// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use maybe_async_attr::maybe_async;
use std::time::{Duration, UNIX_EPOCH};
use tee_attestation_verification_didx509::{PolicyConfig, ValidationError, ValidationTime};

#[maybe_async(
    sync: {
        use tee_attestation_verification_didx509::validation_sync as api;
    },
    async: {
        use tee_attestation_verification_didx509::validation_async as api;
    },
)]
mod cases {
    use super::*;
    use tee_attestation_verification_crypto::{CertificateBackend, Crypto};

    const DID: &str = "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
    const PEM: &str = include_str!("../fixtures/deployed/containerplat/chain.pem");

    #[maybe_async_fn]
    pub fn full_rfc5280_is_rejected_by_every_entry_point() {
        let policy = PolicyConfig {
            rfc5280_validation: true,
        };
        let time = ValidationTime::Now;
        let errors = [
            mb_await!(api::validate_pem("", "", time, policy)).unwrap_err(),
            mb_await!(api::validate_der("", &[], time, policy)).unwrap_err(),
            mb_await!(api::validate_x509chain("", "", time, policy)).unwrap_err(),
            mb_await!(api::resolve_pem("", "", time, policy)).unwrap_err(),
            mb_await!(api::resolve_der("", &[], time, policy)).unwrap_err(),
            mb_await!(api::resolve_x509chain("", "", time, policy)).unwrap_err(),
            mb_await!(api::resolve_jwk_pem("", "", time, policy)).unwrap_err(),
        ];
        for error in errors {
            assert!(matches!(error, ValidationError::UnsupportedPolicy { .. }));
            assert_eq!(
                error.to_string(),
                "unsupported validation policy: full RFC 5280 validation is not implemented"
            );
        }
    }

    #[maybe_async_fn]
    pub fn default_preserves_signature_time_and_predicate_checks() {
        let policy = PolicyConfig::default();
        assert!(!policy.rfc5280_validation);
        let time = ValidationTime::At(UNIX_EPOCH + Duration::from_secs(1761595353));
        mb_await!(api::validate_pem(DID, PEM, time, policy)).unwrap();
        assert!(matches!(
            mb_await!(api::validate_pem(
                DID,
                PEM,
                ValidationTime::At(UNIX_EPOCH),
                policy
            )),
            Err(ValidationError::InvalidChain { .. })
        ));
        let mismatch = format!("{DID}::subject:CN:NotTheLeaf");
        assert!(matches!(
            mb_await!(api::validate_pem(&mismatch, PEM, time, policy)),
            Err(ValidationError::PredicateMismatch { .. })
        ));

        let certificates = Crypto::from_pem_chain(PEM.as_bytes()).unwrap();
        let mut der: Vec<_> = certificates
            .iter()
            .map(|cert| Crypto::to_der(cert).unwrap())
            .collect();
        // The final DER byte is in the signature, not the signed certificate body.
        *der[0].last_mut().unwrap() ^= 1;
        let chain: Vec<_> = der.iter().map(Vec::as_slice).collect();
        assert!(matches!(
            mb_await!(api::validate_der(DID, &chain, time, policy)),
            Err(ValidationError::InvalidChain { .. })
        ));
    }
}

#[cfg(sync_crypto)]
#[test]
fn synchronous_policy_configuration() {
    cases_sync::full_rfc5280_is_rejected_by_every_entry_point();
    cases_sync::default_preserves_signature_time_and_predicate_checks();
}

#[cfg(all(async_crypto, target_arch = "wasm32"))]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn webcrypto_policy_configuration() {
    cases_async::full_rfc5280_is_rejected_by_every_entry_point().await;
    cases_async::default_preserves_signature_time_and_predicate_checks().await;
}

#[cfg(all(async_crypto, not(target_arch = "wasm32")))]
#[test]
fn asynchronous_policy_configuration() {
    use std::task::{Context, Poll, Waker};
    let mut future = std::pin::pin!(async {
        cases_async::full_rfc5280_is_rejected_by_every_entry_point().await;
        cases_async::default_preserves_signature_time_and_predicate_checks().await;
    });
    assert!(matches!(
        std::future::Future::poll(future.as_mut(), &mut Context::from_waker(Waker::noop())),
        Poll::Ready(())
    ));
}
