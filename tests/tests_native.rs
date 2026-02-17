// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Once;

mod common;

static INIT: Once = Once::new();

pub fn init_logger() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .is_test(true)
            .init();
    });
}

/// Online verification tests (async, fetches certs from AMD KDS)
mod online {
    use super::*;

    #[tokio::test]
    async fn test_verify_milan_attestation() {
        init_logger();
        let result = common::verify_milan_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_genoa_attestation() {
        init_logger();
        let result = common::verify_genoa_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_verify_turin_attestation() {
        init_logger();
        let result = common::verify_turin_attestation()
            .await
            .expect("Verification call failed");

        assert!(
            result.is_valid,
            "Verification should pass: {:?}",
            result.errors
        );
    }
}

/// Offline verification tests (sync, uses pinned ARKs)
mod offline {
    use super::*;
    use tee_attestation_verification_lib::snp::verify::SevVerificationError;

    #[test]
    fn test_verify_milan_attestation() {
        init_logger();
        common::verify_with_snp_verify(common::MILAN_ATTESTATION, common::MILAN_ASK, common::MILAN_VCEK)
            .expect("snp::verify::verify_attestation should pass for Milan fixtures");
    }

    #[test]
    fn test_verify_genoa_attestation() {
        init_logger();
        common::verify_with_snp_verify(common::GENOA_ATTESTATION, common::GENOA_ASK, common::GENOA_VCEK)
            .expect("snp::verify::verify_attestation should pass for Genoa fixtures");
    }

    #[test]
    fn test_verify_turin_attestation() {
        init_logger();
        common::verify_with_snp_verify(common::TURIN_ATTESTATION, common::TURIN_ASK, common::TURIN_VCEK)
            .expect("snp::verify::verify_attestation should pass for Turin fixtures");
    }

    #[test]
    fn test_verify_milan_attestation_rejects_wrong_generation_certs() {
        init_logger();
        let result = common::verify_with_snp_verify(
            common::MILAN_ATTESTATION,
            common::GENOA_ASK,
            common::GENOA_VCEK,
        );

        assert!(matches!(
            &result,
            Err(SevVerificationError::CertificateChainError(_))
        ),
        "Expected CertificateChainError for mismatched ASK/VCEK certs, got: {:?}",
        result
        );
    }
}
