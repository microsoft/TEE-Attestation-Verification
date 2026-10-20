// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use maybe_async_attr::maybe_async;
use std::time::{Duration, UNIX_EPOCH};
use tee_attestation_verification_didx509::{Jwk, PolicyConfig, ValidationError, ValidationTime};

#[maybe_async(
    sync: {
        use tee_attestation_verification_crypto::CryptoBackend;
        use tee_attestation_verification_didx509::validation_sync::{
            resolve_pem, resolve_x509chain, validate_pem, validate_x509chain,
        };
    },
    async: {
        use tee_attestation_verification_crypto::AsyncCryptoBackend;
        use tee_attestation_verification_didx509::validation_async::{
            resolve_pem, resolve_x509chain, validate_pem, validate_x509chain,
        };
    },
)]
mod cases {
    use super::*;
    use tee_attestation_verification_crypto::{
        base64::base64_encode_no_padding, CertificateBackend, Crypto, DigestAlgorithm,
    };

    #[maybe_async_fn]
    pub fn key_types() {
        let timestamp: u64 =
            serde_json::from_str(include_str!("../fixtures/keys/validation-time.json")).unwrap();
        for (name, pem, curve, width) in [
            ("rsa", include_str!("../fixtures/keys/rsa.pem"), "", 0),
            (
                "p256",
                include_str!("../fixtures/keys/p256.pem"),
                "P-256",
                43,
            ),
            (
                "p384-sha256",
                include_str!("../fixtures/keys/p384-sha256.pem"),
                "P-384",
                64,
            ),
            (
                "p521",
                include_str!("../fixtures/keys/p521.pem"),
                "P-521",
                88,
            ),
        ] {
            let certs = Crypto::from_pem_chain(pem.as_bytes()).unwrap();
            let der = Crypto::to_der(certs.last().unwrap()).unwrap();
            let fingerprint = base64_encode_no_padding(
                &mb_await!(Crypto::digest(DigestAlgorithm::Sha256, &der)).unwrap(),
            );
            let did = format!("did:x509:0:sha256:{fingerprint}::subject:CN:Fixture%20Leaf");
            let document = mb_await!(resolve_pem(
                &did,
                pem,
                ValidationTime::At(UNIX_EPOCH + Duration::from_secs(timestamp)),
                PolicyConfig::default()
            ))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            match document.verification_method.public_key_jwk {
                Jwk::Rsa { n, e } if name == "rsa" => {
                    assert_eq!(e, "AQAB");
                    assert_eq!(n.len(), 342);
                }

                Jwk::Ec { crv, x, y } if name != "rsa" => {
                    assert_eq!(crv, curve);
                    assert_eq!(x.len(), width);
                    assert_eq!(y.len(), width);
                }
                key => panic!("{name}: unexpected {key:?}"),
            }
            assert_eq!(document.authentication, vec![format!("{did}#0")]);
            assert_eq!(document.key_agreement, vec![format!("{did}#0")]);
        }
    }

    #[maybe_async_fn]
    pub fn validation_does_not_require_a_supported_jwk() {
        let pem = include_str!("../fixtures/keys/ed25519-leaf.pem");
        let timestamp: u64 = serde_json::from_str(include_str!(
            "../fixtures/keys/ed25519-validation-time.json"
        ))
        .unwrap();
        let certificates = Crypto::from_pem_chain(pem.as_bytes()).unwrap();
        let anchor = Crypto::to_der(certificates.last().unwrap()).unwrap();
        let fingerprint = base64_encode_no_padding(
            &mb_await!(Crypto::digest(DigestAlgorithm::Sha256, &anchor)).unwrap(),
        );
        let did = format!("did:x509:0:sha256:{fingerprint}::subject:CN:Fixture%20Leaf");
        let time = ValidationTime::At(UNIX_EPOCH + Duration::from_secs(timestamp));
        mb_await!(validate_pem(&did, pem, time, PolicyConfig::default())).unwrap();
        assert!(matches!(
            mb_await!(resolve_pem(&did, pem, time, PolicyConfig::default())),
            Err(ValidationError::InvalidKey { .. })
        ));
    }

    #[maybe_async_fn]
    pub fn leaf_key_usage_controls_resolution_not_validation() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../fixtures/upstream/did-x509/test-vectors.json"
        ))
        .unwrap();
        let times: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/upstream/did-x509/validation-times.json"
        ))
        .unwrap();
        for id in [
            "key-agreement-only-leaf",
            "leaf-key-usage-must-support-did-operations",
            "root-ca",
        ] {
            let vector = vectors.iter().find(|vector| vector["id"] == id).unwrap();
            let chain = vector["input"]["chain"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",");
            let did = vector["input"]["did"].as_str().unwrap();
            let time =
                ValidationTime::At(UNIX_EPOCH + Duration::from_secs(times[id].as_u64().unwrap()));
            mb_await!(validate_x509chain(
                did,
                &chain,
                time,
                PolicyConfig::default()
            ))
            .unwrap_or_else(|error| panic!("{id}: {error}"));
            let result = mb_await!(resolve_x509chain(
                did,
                &chain,
                time,
                PolicyConfig::default()
            ));
            if let Some(expected) = vector["output"].get("document") {
                let document = result.unwrap_or_else(|error| panic!("{id}: {error}"));
                let actual: serde_json::Value = serde_json::from_str(&document.to_json()).unwrap();
                assert_eq!(&actual, expected, "{id}");
            } else {
                assert!(
                    matches!(result, Err(ValidationError::InvalidKey { .. })),
                    "{id}: {result:?}"
                );
            }
        }
    }

    #[maybe_async_fn]
    pub fn intermediate_trust_anchor() {
        let pem = include_str!("../fixtures/deployed/containerplat/chain.pem");
        let certificates = Crypto::from_pem_chain(pem.as_bytes()).unwrap();
        let anchor_der = Crypto::to_der(&certificates[1]).unwrap();
        let fingerprint = base64_encode_no_padding(
            &mb_await!(Crypto::digest(DigestAlgorithm::Sha256, &anchor_der)).unwrap(),
        );
        let did = format!("did:x509:0:sha256:{fingerprint}::eku:1.3.6.1.4.1.311.76.59.1.2");
        let partial = [
            Crypto::to_pem(&certificates[0]).unwrap(),
            Crypto::to_pem(&certificates[1]).unwrap(),
        ]
        .join("\n");
        mb_await!(resolve_pem(
            &did,
            &partial,
            ValidationTime::At(UNIX_EPOCH + Duration::from_secs(1761595353)),
            PolicyConfig::default()
        ))
        .unwrap();
    }

    #[maybe_async_fn]
    pub fn production_regressions() {
        let times: serde_json::Value = serde_json::from_str(include_str!(
            "../fixtures/upstream/didx509cpp/validation-times.json"
        ))
        .unwrap();
        for (filename, pem, fingerprint, predicate, accepted) in [
            (
                "utf8-subject.pem",
                include_str!("../fixtures/upstream/didx509cpp/utf8-subject.pem"),
                "gq-05smrC6JilYZzYHrr7SOs3V_y_I4K6JMW3arCL2I",
                "subject:O:caf%C3%A9%20Ltd",
                true,
            ),
            (
                "utf8-subject.pem",
                include_str!("../fixtures/upstream/didx509cpp/utf8-subject.pem"),
                "gq-05smrC6JilYZzYHrr7SOs3V_y_I4K6JMW3arCL2I",
                "subject:O:caf%C3%A9",
                false,
            ),
            (
                "wildcard-dns-san.pem",
                include_str!("../fixtures/upstream/didx509cpp/wildcard-dns-san.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:dns:evil.example.com",
                false,
            ),
            (
                "wildcard-dns-san.pem",
                include_str!("../fixtures/upstream/didx509cpp/wildcard-dns-san.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:dns:%2A.example.com",
                true,
            ),
            (
                "uri-san-embedded-nul.pem",
                include_str!("../fixtures/upstream/didx509cpp/uri-san-embedded-nul.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:uri:https%3A%2F%2Ftrusted.example",
                false,
            ),
            (
                "uri-san-embedded-nul.pem",
                include_str!("../fixtures/upstream/didx509cpp/uri-san-embedded-nul.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:uri:https%3A%2F%2Ftrusted.example%00.attacker.test",
                true,
            ),
            (
                "san-subject-fallback.pem",
                include_str!("../fixtures/upstream/didx509cpp/san-subject-fallback.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:dns:fallback.example.com",
                false,
            ),
            (
                "san-subject-fallback.pem",
                include_str!("../fixtures/upstream/didx509cpp/san-subject-fallback.pem"),
                "oytZAcT4RmC4rlV3x0AUg--_inU_2btxHHVxVbDDcG8",
                "san:uri:https%3A%2F%2Fexample.com%2Fanchor",
                true,
            ),
            (
                "ec-leading-zero.pem",
                include_str!("../fixtures/upstream/didx509cpp/ec-leading-zero.pem"),
                "SGI1ucfnPQ6_Rx2YIurUyv75tHSapBv2_aiXaGtxP8w",
                "subject:CN:didx509cpp%20EC%20Test%20Leaf",
                true,
            ),
        ] {
            let did = format!("did:x509:0:sha256:{fingerprint}::{predicate}");
            let time = ValidationTime::At(
                UNIX_EPOCH + Duration::from_secs(times[filename].as_u64().unwrap()),
            );
            let result = mb_await!(resolve_pem(&did, pem, time, PolicyConfig::default()));
            if accepted {
                let document =
                    result.unwrap_or_else(|error| panic!("{filename}, {predicate}: {error}"));
                if filename == "ec-leading-zero.pem" {
                    assert!(
                        matches!(document.verification_method.public_key_jwk, Jwk::Ec { x, y, .. }
                        if x.len() == 43 && y.len() == 43 && x.starts_with('A'))
                    );
                }
            } else {
                assert!(
                    matches!(
                        result,
                        Err(tee_attestation_verification_didx509::ValidationError::PredicateMismatch { .. })
                    ),
                    "{filename}, {predicate}: {result:?}"
                );
            }
        }
    }
}

#[cfg(sync_crypto)]
#[test]
fn synchronous_key_types_and_production_regressions() {
    cases_sync::key_types();
    cases_sync::validation_does_not_require_a_supported_jwk();
    cases_sync::leaf_key_usage_controls_resolution_not_validation();
    cases_sync::production_regressions();
    cases_sync::intermediate_trust_anchor();
}

#[cfg(all(async_crypto, target_arch = "wasm32"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn webcrypto_key_types_and_production_regressions() {
    cases_async::key_types().await;
    cases_async::validation_does_not_require_a_supported_jwk().await;
    cases_async::leaf_key_usage_controls_resolution_not_validation().await;
    cases_async::production_regressions().await;
    cases_async::intermediate_trust_anchor().await;
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
#[test]
fn asynchronous_key_types_and_production_regressions() {
    use std::task::{Context, Poll, Waker};
    let mut future = std::pin::pin!(async {
        cases_async::key_types().await;
        cases_async::validation_does_not_require_a_supported_jwk().await;
        cases_async::leaf_key_usage_controls_resolution_not_validation().await;
        cases_async::production_regressions().await;
        cases_async::intermediate_trust_anchor().await;
    });
    assert!(matches!(
        std::future::Future::poll(future.as_mut(), &mut Context::from_waker(Waker::noop())),
        Poll::Ready(())
    ));
}
