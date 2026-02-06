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

    #[test]
    fn test_verify_milan_attestation() {
        init_logger();
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
        init_logger();
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
        init_logger();
        let result =
            common::verify_turin_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }
}
