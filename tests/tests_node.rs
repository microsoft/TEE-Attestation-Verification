// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "wasm32")]

mod common;

use wasm_bindgen_test::wasm_bindgen_test;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_node_experimental);

/// Online verification tests (async, fetches certs from AMD KDS)
mod online {
    use super::*;

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
    fn test_verify_milan_attestation() {
        let result =
            common::verify_milan_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[wasm_bindgen_test]
    fn test_verify_genoa_attestation() {
        let result =
            common::verify_genoa_attestation_offline().expect("Offline verification call failed");

        assert!(
            result.is_valid,
            "Offline verification should pass: {:?}",
            result.errors
        );
    }

    #[wasm_bindgen_test]
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
