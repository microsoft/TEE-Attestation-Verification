// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use didx509::ValidationTime;
use std::time::{Duration, UNIX_EPOCH};

#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test;

#[derive(Debug)]
enum Expected {
    Valid,
    Did(&'static str),
    Certificate(&'static str),
    Cose(&'static str),
    Signature,
}

struct Case {
    name: String,
    endorsement: Vec<u8>,
    trusted: String,
    expected: Expected,
}

impl Case {
    fn assert_result(&self, result: &Result<CborValue<'_>, AciError>) {
        match (&self.expected, result) {
            (Expected::Valid, Ok(_)) | (Expected::Signature, Err(AciError::Signature(_))) => {}
            (Expected::Did(expected), Err(AciError::DidX509(actual)))
            | (Expected::Certificate(expected), Err(AciError::Certificate(actual)))
            | (Expected::Cose(expected), Err(AciError::Cose(actual))) => {
                assert!(
                    actual.contains(*expected),
                    "{}: expected {expected:?}, got {actual:?}",
                    self.name
                );
            }
            _ => panic!(
                "{}: expected {:?}, got {result:?}",
                self.name, self.expected
            ),
        }
    }
}

fn regression_cases(fixture: CaciFixture) -> Vec<Case> {
    let original = reference_info_fixture(fixture);
    let parsed = CborValue::parse_nondet(&original).unwrap();
    let header = endorsement_protected_header(&parsed);
    let prefix = TRUSTED_ACI_DIDX509.split_once("::").unwrap().0;
    let matching = format!("{TRUSTED_ACI_DIDX509}::subject:O:Microsoft%20Corporation");
    let wrong_ca = TRUSTED_ACI_DIDX509.replacen("I__", "A__", 1);
    let mut cases = vec![
        Case {
            name: format!("{} wrong trusted CA fingerprint", fixture.name),
            endorsement: original.clone(),
            trusted: wrong_ca.clone(),
            expected: Expected::Did("trusted DID: CA fingerprint does not match"),
        },
        Case {
            name: format!("{} deployed signature", fixture.name),
            endorsement: original.clone(),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Valid,
        },
        Case {
            name: format!("{} different satisfied trusted predicates", fixture.name),
            endorsement: original.clone(),
            trusted: matching.clone(),
            expected: Expected::Valid,
        },
        Case {
            name: format!(
                "{} modified valid issuer still needs signature",
                fixture.name
            ),
            endorsement: mutate_header(&parsed, |header| {
                *issuer_mut(header, fixture) = CborValue::text(matching.clone());
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Signature,
        },
    ];

    for (suffix, message) in [
        (
            "::subject:CN:NotTheEndorsementSigner",
            "certificate subject",
        ),
        ("::eku:1.2.3.4.5.6.7.8.9", "certificate extended key usage"),
        ("::san:dns:not-the-signer.invalid", "certificate dns SAN"),
    ] {
        let did = format!("{prefix}{suffix}");
        cases.push(Case {
            name: format!("{} trusted predicate {suffix}", fixture.name),
            endorsement: original.clone(),
            trusted: did.clone(),
            expected: Expected::Did(message),
        });
        cases.push(Case {
            name: format!("{} issuer predicate {suffix}", fixture.name),
            endorsement: mutate_header(&parsed, |header| {
                *issuer_mut(header, fixture) = CborValue::text(did.clone());
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Did(message),
        });
    }

    for suffix in [
        "",
        "::",
        "::eku:not-an-oid",
        "::subject:CN:%GG",
        "::unknown:value",
        "::san:uri:https://example.com",
        "::eku:1.3.6.1.4.1.311.76.59.1.2::",
        "::eku:1.3.6.1.4.1.311.76.59.1.2#%",
    ] {
        let did = format!("{prefix}{suffix}");
        cases.push(Case {
            name: format!("{} malformed trusted suffix {suffix:?}", fixture.name),
            endorsement: original.clone(),
            trusted: did.clone(),
            expected: Expected::Did("trusted DID: invalid did:x509 identifier:"),
        });
        cases.push(Case {
            name: format!("{} malformed issuer suffix {suffix:?}", fixture.name),
            endorsement: mutate_header(&parsed, |header| {
                *issuer_mut(header, fixture) = CborValue::text(did.clone());
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Did("issuer DID: invalid did:x509 identifier:"),
        });
    }

    for issuer in [
        "not-a-did",
        &TRUSTED_ACI_DIDX509.replacen(":0:", ":1:", 1),
        &wrong_ca,
    ] {
        cases.push(Case {
            name: format!("{} unlinked issuer {issuer}", fixture.name),
            endorsement: mutate_header(&parsed, |header| {
                *issuer_mut(header, fixture) = CborValue::text(issuer.to_owned());
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Did("issuer DID prefix"),
        });
    }

    let chain =
        parse::parse_x5chain(header.map_at_int(cose::COSE_HEADER_X5CHAIN).unwrap()).unwrap();
    assert!(chain.len() > 2, "fixture includes an intermediate");
    let mut reversed = chain.clone();
    reversed.reverse();
    let mut duplicate = chain.clone();
    duplicate.insert(1, chain[0].clone());
    let mut trailing_der = chain.clone();
    trailing_der[0].push(0);
    for (name, chain_value, expected) in [
        (
            "empty chain",
            CborValue::Array(vec![]),
            Expected::Cose("x5chain array must contain at least two certificates"),
        ),
        (
            "empty DER",
            CborValue::bytes(Vec::<u8>::new()),
            Expected::Certificate("invalid certificate input:"),
        ),
        (
            "invalid DER",
            CborValue::bytes(vec![1, 2, 3]),
            Expected::Certificate("invalid certificate input:"),
        ),
        (
            "leaf only",
            CborValue::bytes(chain[0].clone()),
            Expected::Certificate("invalid certificate chain:"),
        ),
        (
            "reversed chain",
            chain_value(reversed),
            Expected::Certificate("invalid certificate chain:"),
        ),
        (
            "duplicate leaf",
            chain_value(duplicate),
            Expected::Certificate("invalid certificate chain:"),
        ),
        (
            "missing intermediates",
            chain_value(vec![chain[0].clone(), chain.last().unwrap().clone()]),
            Expected::Certificate("invalid certificate chain:"),
        ),
        (
            "DER trailing data",
            chain_value(trailing_der),
            Expected::Certificate("invalid certificate input:"),
        ),
    ] {
        cases.push(Case {
            name: format!("{} {name}", fixture.name),
            endorsement: mutate_header(&parsed, |header| {
                *map_value_mut(header, CborValue::Int(cose::COSE_HEADER_X5CHAIN)) = chain_value;
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected,
        });
    }

    for seconds in [0, 4_102_444_800] {
        cases.push(Case {
            name: format!("{} certificate invalid at {seconds}", fixture.name),
            endorsement: mutate_header(&parsed, |header| {
                *time_mut(header, fixture) = tagged_time(seconds);
            }),
            trusted: TRUSTED_ACI_DIDX509.into(),
            expected: Expected::Certificate("invalid certificate chain:"),
        });
    }
    cases
}

#[cfg(sync_crypto)]
#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
fn uvm_did_regressions_sync() {
    for fixture in fixture_cases() {
        for case in regression_cases(fixture) {
            case.assert_result(&crate::synchronous::verify_uvm_endorsement(
                &case.endorsement,
                &case.trusted,
            ));
        }
    }
}

#[cfg(async_crypto)]
#[cfg_attr(not(target_family = "wasm"), tokio::test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
async fn uvm_did_regressions_async() {
    for fixture in fixture_cases() {
        for case in regression_cases(fixture) {
            let result =
                crate::asynchronous::verify_uvm_endorsement(&case.endorsement, &case.trusted).await;
            case.assert_result(&result);
            #[cfg(sync_crypto)]
            {
                let sync =
                    crate::synchronous::verify_uvm_endorsement(&case.endorsement, &case.trusted);
                assert_eq!(
                    result.as_ref().map(|_| ()).map_err(ToString::to_string),
                    sync.as_ref().map(|_| ()).map_err(ToString::to_string),
                    "{}",
                    case.name
                );
            }
        }
    }
}

#[cfg_attr(not(target_family = "wasm"), test)]
#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
fn protected_signing_time_semantics() {
    let seconds = 1_700_000_000;
    let expected = ValidationTime::At(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds as u64))
            .unwrap(),
    );
    for fixture in fixture_cases() {
        let original = reference_info_fixture(fixture);
        let parsed = CborValue::parse_nondet(&original).unwrap();
        let mut header = endorsement_protected_header(&parsed);
        *time_mut(&mut header, fixture) = tagged_time(seconds);
        assert_eq!(uvm::issuer_and_time(&header).unwrap().1, expected);

        *time_mut(&mut header, fixture) = CborValue::Int(seconds);
        let untagged = uvm::issuer_and_time(&header);
        if fixture.name == LEGACY_FIXTURE.name {
            assert!(matches!(untagged, Err(AciError::Cose(_))));
        } else {
            assert_eq!(untagged.unwrap().1, expected);
        }

        for invalid in [
            tagged_time(-1),
            CborValue::Int(-1),
            CborValue::text("1700000000"),
            CborValue::Tagged {
                tag: 0,
                payload: Box::new(CborValue::Int(seconds)),
            },
            CborValue::Tagged {
                tag: 1,
                payload: Box::new(CborValue::text("1700000000")),
            },
        ] {
            *time_mut(&mut header, fixture) = invalid;
            assert!(matches!(
                uvm::issuer_and_time(&header),
                Err(AciError::Cose(_))
            ));
        }
        let (claims, key) = time_claims_mut(&mut header, fixture);
        map_entries_mut(claims).retain(|(entry_key, _)| entry_key != &key);
        assert_eq!(
            uvm::issuer_and_time(&header).unwrap().1,
            ValidationTime::Now
        );
    }
}

fn mutate_header(
    endorsement: &CborValue<'_>,
    mutate: impl FnOnce(&mut CborValue<'static>),
) -> Vec<u8> {
    let mut endorsement = endorsement.clone().into_owned();
    let mut header = endorsement_protected_header(&endorsement);
    mutate(&mut header);
    // Keep the deployed signature. Mutated protected bytes must never authenticate.
    sign1_items_mut(&mut endorsement)[0] = CborValue::bytes(header.to_bytes_det().unwrap());
    endorsement.to_bytes_det().unwrap()
}

fn chain_value(chain: Vec<Vec<u8>>) -> CborValue<'static> {
    CborValue::Array(chain.into_iter().map(CborValue::bytes).collect())
}

fn issuer_mut<'a>(
    header: &'a mut CborValue<'static>,
    fixture: CaciFixture,
) -> &'a mut CborValue<'static> {
    if fixture.name == LEGACY_FIXTURE.name {
        map_value_mut(header, CborValue::text("iss"))
    } else {
        let claims = map_value_mut(header, CborValue::Int(cose::COSE_HEADER_CWT_CLAIMS));
        map_value_mut(claims, CborValue::Int(cose::CWT_CLAIMS_ISSUER))
    }
}

fn time_claims_mut<'a>(
    header: &'a mut CborValue<'static>,
    fixture: CaciFixture,
) -> (&'a mut CborValue<'static>, CborValue<'static>) {
    if fixture.name == LEGACY_FIXTURE.name {
        (header, CborValue::text("signingtime"))
    } else {
        (
            map_value_mut(header, CborValue::Int(cose::COSE_HEADER_CWT_CLAIMS)),
            CborValue::Int(cose::CWT_CLAIMS_IAT),
        )
    }
}

fn time_mut<'a>(
    header: &'a mut CborValue<'static>,
    fixture: CaciFixture,
) -> &'a mut CborValue<'static> {
    let (claims, key) = time_claims_mut(header, fixture);
    map_value_mut(claims, key)
}

fn tagged_time(seconds: i64) -> CborValue<'static> {
    CborValue::Tagged {
        tag: 1,
        payload: Box::new(CborValue::Int(seconds)),
    }
}

fn map_entries_mut<'a>(
    map: &'a mut CborValue<'static>,
) -> &'a mut Vec<(CborValue<'static>, CborValue<'static>)> {
    match map {
        CborValue::Map(entries) => entries,
        other => panic!("expected map, got {other:?}"),
    }
}

fn map_value_mut<'a>(
    map: &'a mut CborValue<'static>,
    key: CborValue<'static>,
) -> &'a mut CborValue<'static> {
    map_entries_mut(map)
        .iter_mut()
        .find(|(entry_key, _)| entry_key == &key)
        .map(|(_, value)| value)
        .expect("fixture claim is present")
}
