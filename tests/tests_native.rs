// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(target_arch = "wasm32"))]

mod common;

/// Online verification tests (async, fetches certs from AMD KDS)
mod online {
    use super::*;

    #[tokio::test]
    async fn test_verify_milan_attestation() {
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

    #[test]
    fn test_verify_milan_attestation() {
        let result =
            common::verify_milan_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_genoa_attestation() {
        let result =
            common::verify_genoa_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_turin_attestation() {
        let result =
            common::verify_turin_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }
}
