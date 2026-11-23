// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal did:x509 support: `did:x509:0:sha256:<root fingerprint>::eku:<oid>`.
//!
//! This is a deliberate subset of
//! <https://github.com/microsoft/did-x509/blob/main/specification.md>. Other
//! fingerprint algorithms, other predicates, multiple predicates,
//! fingerprints of intermediate CA certificates, and OIDs with a DER
//! subidentifier wider than 128 bits are rejected.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
use crypto::CertificateBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::base64::base64_encode_no_padding;

const DID_PREFIX: &str = "did:x509:0:sha256:";
const SUPPORTED_SYNTAX: &str = "expected did:x509:0:sha256:<fingerprint>::eku:<oid>";
/// RFC 5280 section 4.2.1.12: id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }.
const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";
/// Length of an unpadded base64url SHA-256 digest.
const SHA256_FINGERPRINT_LEN: usize = 43;
const DER_SEQUENCE: u8 = 0x30;
const DER_OID: u8 = 0x06;

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = verify_didx509_eku(trusted_didx509, issuer, leaf)?;
    let root = root_certificate(x5chain)?;
    let digest = <crypto::Crypto as CryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, root)
        .map_err(fingerprint_error)?;
    verify_didx509_fingerprint(&trusted, &digest)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
    leaf: &crypto::Certificate,
) -> Result<(), AciError> {
    let trusted = verify_didx509_eku(trusted_didx509, issuer, leaf)?;
    let root = root_certificate(x5chain)?;
    let digest =
        <crypto::Crypto as AsyncCryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, root)
            .await
            .map_err(fingerprint_error)?;
    verify_didx509_fingerprint(&trusted, &digest)
}

/// did:x509 pins a CA certificate, so the chain needs an entry after the leaf.
fn root_certificate(x5chain: &[Vec<u8>]) -> Result<&[u8], AciError> {
    match x5chain {
        [_leaf, .., root] => Ok(root),
        _ => Err(AciError::DidX509(
            "x5chain must contain a CA certificate after the signing certificate".to_string(),
        )),
    }
}

/// Checks everything except the root fingerprint, which needs a digest and so
/// differs between the sync and async backends.
pub(crate) fn verify_didx509_eku<'a>(
    trusted_didx509: &'a str,
    issuer: &str,
    leaf: &crypto::Certificate,
) -> Result<ParsedDidX509<'a>, AciError> {
    let trusted = parse_didx509(trusted_didx509)?;
    if issuer != trusted_didx509 {
        return Err(AciError::DidX509(format!(
            "issuer DID {issuer} does not match trusted DID {trusted_didx509}"
        )));
    }

    let extended_key_usage =
        crypto::Crypto::get_extension_value_by_oid(leaf, EXTENDED_KEY_USAGE_OID)
            .map_err(|e| AciError::Certificate(e.to_string()))?
            .ok_or_else(|| {
                AciError::DidX509("x5chain leaf certificate has no extended key usage".to_string())
            })?;
    let has_eku =
        extended_key_usage_contains(&extended_key_usage, &trusted.eku).ok_or_else(|| {
            AciError::Certificate(
                "x5chain leaf certificate has a malformed extended key usage".to_string(),
            )
        })?;
    if !has_eku {
        return Err(AciError::DidX509(format!(
            "x5chain leaf certificate does not have the extended key usage required by trusted DID {trusted_didx509}"
        )));
    }

    Ok(trusted)
}

fn verify_didx509_fingerprint(trusted: &ParsedDidX509<'_>, digest: &[u8]) -> Result<(), AciError> {
    if base64_encode_no_padding(digest) != trusted.fingerprint {
        return Err(AciError::DidX509(format!(
            "x5chain root certificate fingerprint does not match trusted DID {}",
            trusted.raw
        )));
    }

    Ok(())
}

fn fingerprint_error(e: impl std::fmt::Display) -> AciError {
    AciError::DidX509(format!(
        "failed to compute DID x509 SHA-256 fingerprint: {e}"
    ))
}

pub(crate) struct ParsedDidX509<'a> {
    fingerprint: &'a str,
    /// DER contents octets of the `eku` predicate's OBJECT IDENTIFIER.
    eku: Vec<u8>,
    raw: &'a str,
}

pub(crate) fn parse_didx509(did: &str) -> Result<ParsedDidX509<'_>, AciError> {
    let syntax_error = || AciError::DidX509(SUPPORTED_SYNTAX.to_string());

    let rest = did.strip_prefix(DID_PREFIX).ok_or_else(syntax_error)?;
    let (fingerprint, predicate) = rest.split_once("::").ok_or_else(syntax_error)?;
    let is_base64url = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    if fingerprint.len() != SHA256_FINGERPRINT_LEN || !fingerprint.bytes().all(is_base64url) {
        return Err(syntax_error());
    }
    let eku = predicate
        .strip_prefix("eku:")
        .and_then(encode_oid)
        .ok_or_else(syntax_error)?;

    Ok(ParsedDidX509 {
        fingerprint,
        eku,
        raw: did,
    })
}

/// Encodes a dotted-decimal OID as the contents octets of a DER OBJECT
/// IDENTIFIER (X.690 section 8.19), or `None` if it is not a canonical OID or
/// has a subidentifier wider than 128 bits.
fn encode_oid(oid: &str) -> Option<Vec<u8>> {
    let mut arcs = oid.split('.').map(|arc| {
        let canonical = arc == "0" || !arc.starts_with('0');
        let digits = !arc.is_empty() && arc.bytes().all(|b| b.is_ascii_digit());
        (canonical && digits)
            .then(|| arc.parse::<u128>().ok())
            .flatten()
    });
    let first = arcs.next()??;
    let second = arcs.next()??;
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    let first_subidentifier = (first * 40).checked_add(second);

    let mut encoded = Vec::new();
    for subidentifier in std::iter::once(first_subidentifier).chain(arcs) {
        let subidentifier = subidentifier?;
        let groups = (u128::BITS - subidentifier.leading_zeros())
            .max(1)
            .div_ceil(7);
        for group in (0..groups).rev() {
            let continuation = if group > 0 { 0x80 } else { 0 };
            encoded.push((subidentifier >> (7 * group)) as u8 & 0x7f | continuation);
        }
    }
    Some(encoded)
}

/// Returns whether a DER `ExtKeyUsageSyntax` (`SEQUENCE OF OBJECT IDENTIFIER`)
/// contains an OID with the given contents octets, or `None` if it is malformed.
fn extended_key_usage_contains(extended_key_usage: &[u8], oid: &[u8]) -> Option<bool> {
    let (mut key_purposes, trailing) = der_tlv(extended_key_usage, DER_SEQUENCE)?;
    if !trailing.is_empty() || key_purposes.is_empty() {
        return None;
    }

    let mut found = false;
    while !key_purposes.is_empty() {
        let (key_purpose, rest) = der_tlv(key_purposes, DER_OID)?;
        if !is_der_oid(key_purpose) {
            return None;
        }
        found |= key_purpose == oid;
        key_purposes = rest;
    }
    Some(found)
}

/// Returns whether `contents` are the contents octets of a DER OBJECT
/// IDENTIFIER: a non-empty run of complete, minimally encoded subidentifiers.
fn is_der_oid(contents: &[u8]) -> bool {
    let mut starts_subidentifier = true;
    for &octet in contents {
        if starts_subidentifier && octet == 0x80 {
            return false;
        }
        starts_subidentifier = octet & 0x80 == 0;
    }
    starts_subidentifier && !contents.is_empty()
}

/// Splits a DER value with the given tag off the front of `input`, returning
/// its contents and the remaining input.
fn der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&actual_tag, input) = input.split_first()?;
    let (&length, input) = input.split_first()?;
    if actual_tag != tag {
        return None;
    }

    let (length, input) = if length < 0x80 {
        (usize::from(length), input)
    } else {
        // Long form: the low bits count the big-endian length octets that follow.
        let (length_octets, input) = input.split_at_checked(usize::from(length & 0x7f))?;
        if length_octets.is_empty() || length_octets.len() > size_of::<u32>() {
            return None;
        }
        let length = length_octets
            .iter()
            .fold(0, |length, &octet| length << 8 | usize::from(octet));
        // DER requires the shortest encoding of the length.
        if length < 0x80 || length_octets[0] == 0 {
            return None;
        }
        (length, input)
    };
    input.split_at_checked(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    const FINGERPRINT: &str = "I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s";
    // 1.3.6.1.4.1.311.76.59.1.2
    const EKU_DER: [u8; 11] = [
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4c, 0x3b, 0x01, 0x02,
    ];

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn encode_oid_matches_der_contents_octets() {
        assert_eq!(encode_oid("1.3.6.1.4.1.311.76.59.1.2").unwrap(), EKU_DER);
        assert_eq!(encode_oid("0.0").unwrap(), [0x00]);
        assert_eq!(encode_oid("1.39").unwrap(), [0x4f]);
        // X.690 section 8.19.5 example: {joint-iso-itu-t 100 3}.
        assert_eq!(encode_oid("2.100.3").unwrap(), [0x81, 0x34, 0x03]);
        assert_eq!(encode_oid("2.999").unwrap(), [0x88, 0x37]);
        // Arcs up to 128 bits cover UUID-based OIDs (X.667).
        let mut widest = vec![0x2a, 0x83];
        widest.extend_from_slice(&[0xff; 17]);
        widest.push(0x7f);
        assert_eq!(
            encode_oid("1.2.340282366920938463463374607431768211455").unwrap(),
            widest
        );
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn encode_oid_rejects_non_canonical_and_oversized_oids() {
        for oid in [
            "",
            "1",
            "1.",
            ".1",
            "1..2",
            "3.1",
            "1.40",
            "01.3",
            "1.03",
            "1.+3",
            "1.3 ",
            "1.a",
            "1.2.340282366920938463463374607431768211456",
            "2.340282366920938463463374607431768211455",
        ] {
            assert_eq!(encode_oid(oid), None, "{oid:?}");
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn parse_didx509_accepts_single_eku_predicate() {
        let did = format!("did:x509:0:sha256:{FINGERPRINT}::eku:1.3.6.1.4.1.311.76.59.1.2");
        let parsed = parse_didx509(&did).unwrap();
        assert_eq!(parsed.fingerprint, FINGERPRINT);
        assert_eq!(parsed.eku, EKU_DER);
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn parse_didx509_rejects_unsupported_dids() {
        for did in [
            "not-a-did".to_string(),
            format!("did:x509:0:sha256:{FINGERPRINT}"),
            format!("did:x509:0:sha256:{FINGERPRINT}::"),
            format!("did:x509:0:sha256:{FINGERPRINT}::eku:"),
            format!("did:x509:0:sha256:{FINGERPRINT}::eku:01.3"),
            format!("did:x509:0:sha256:{FINGERPRINT}::eku:1.3::eku:1.4"),
            format!("did:x509:0:sha256:{FINGERPRINT}::eku:1.3::subject:CN:x"),
            format!("did:x509:0:sha256:{FINGERPRINT}::subject:CN:x"),
            format!("did:x509:0:sha256:{FINGERPRINT}::san:dns:example.com"),
            format!("did:x509:0:sha256:{FINGERPRINT}:::eku:1.3"),
            format!("did:x509:0:sha256:{FINGERPRINT}=::eku:1.3"),
            "did:x509:0:sha256:::eku:1.3".to_string(),
            format!("did:x509:0:sha256:{}::eku:1.3", &FINGERPRINT[1..]),
            format!("did:x509:0:sha384:{FINGERPRINT}::eku:1.3"),
            format!("did:x509:1:sha256:{FINGERPRINT}::eku:1.3"),
            format!("DID:x509:0:sha256:{FINGERPRINT}::eku:1.3"),
        ] {
            match parse_didx509(&did) {
                Err(AciError::DidX509(actual)) => assert_eq!(actual, SUPPORTED_SYNTAX, "{did}"),
                _ => panic!("expected DidX509 error for {did}"),
            }
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn extended_key_usage_contains_matches_whole_oids() {
        // SEQUENCE { OID 1.3.6.1.4.1.311.76.59.1.1, OID 1.3.6.1.4.1.311.76.59.1.2 }
        let mut other = EKU_DER;
        other[10] = 0x01;
        let mut eku = vec![DER_SEQUENCE, 26, DER_OID, 11];
        eku.extend_from_slice(&other);
        eku.extend_from_slice(&[DER_OID, 11]);
        eku.extend_from_slice(&EKU_DER);

        assert_eq!(extended_key_usage_contains(&eku, &EKU_DER), Some(true));
        assert_eq!(extended_key_usage_contains(&eku, &other), Some(true));
        // A prefix or suffix of a listed OID is not a match.
        assert_eq!(
            extended_key_usage_contains(&eku, &EKU_DER[..10]),
            Some(false)
        );
        assert_eq!(
            extended_key_usage_contains(&eku, &EKU_DER[1..]),
            Some(false)
        );

        // Long-form lengths are accepted where DER requires them.
        let mut long_form = vec![DER_SEQUENCE, 0x81, 130];
        for _ in 0..9 {
            long_form.extend_from_slice(&[DER_OID, 11]);
            long_form.extend_from_slice(&other);
        }
        long_form.extend_from_slice(&[DER_OID, 11]);
        long_form.extend_from_slice(&EKU_DER);
        assert_eq!(
            extended_key_usage_contains(&long_form, &EKU_DER),
            Some(true)
        );
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn extended_key_usage_contains_rejects_malformed_der() {
        let malformed: [&[u8]; 15] = [
            &[],
            &[DER_SEQUENCE],
            // Empty SEQUENCE: ExtKeyUsageSyntax has at least one element.
            &[DER_SEQUENCE, 0],
            // Not a SEQUENCE.
            &[0x31, 3, DER_OID, 1, 0x2a],
            // Element is not an OBJECT IDENTIFIER.
            &[DER_SEQUENCE, 3, 0x04, 1, 0x2a],
            // Trailing bytes after the SEQUENCE.
            &[DER_SEQUENCE, 3, DER_OID, 1, 0x2a, 0x00],
            // SEQUENCE longer than the input.
            &[DER_SEQUENCE, 4, DER_OID, 1, 0x2a],
            // OID longer than the SEQUENCE.
            &[DER_SEQUENCE, 3, DER_OID, 2, 0x2a],
            // Indefinite length.
            &[DER_SEQUENCE, 0x80, DER_OID, 1, 0x2a, 0x00, 0x00],
            // Length of the length exceeds four octets.
            &[DER_SEQUENCE, 0x85, 0, 0, 0, 0, 3, DER_OID, 1, 0x2a],
            // Long-form length where the short form fits.
            &[DER_SEQUENCE, 0x81, 3, DER_OID, 1, 0x2a],
            // Empty OID after the matching one.
            &[DER_SEQUENCE, 5, DER_OID, 1, 0x2a, DER_OID, 0],
            // OID whose last subidentifier is unterminated.
            &[DER_SEQUENCE, 6, DER_OID, 1, 0x2a, DER_OID, 1, 0xaa],
            // OID with a padded subidentifier.
            &[DER_SEQUENCE, 7, DER_OID, 1, 0x2a, DER_OID, 2, 0x80, 0x01],
            &[
                DER_SEQUENCE,
                8,
                DER_OID,
                1,
                0x2a,
                DER_OID,
                3,
                0x2a,
                0x80,
                0x01,
            ],
        ];
        for der in malformed {
            assert_eq!(extended_key_usage_contains(der, &[0x2a]), None, "{der:x?}");
        }
    }
}
