// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Once;
use wasm_bindgen_test::wasm_bindgen_test;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_node_experimental);

static INIT: Once = Once::new();

fn init_logger() {
    INIT.call_once(|| {
        console_error_panic_hook::set_once();
        // Default to Info, can be overridden at compile time with RUST_LOG env var
        let level = option_env!("RUST_LOG")
            .and_then(|s| s.parse().ok())
            .unwrap_or(log::Level::Info);
        wasm_logger::init(wasm_logger::Config::new(level));
    });
}

/// Online verification tests (async, fetches certs from AMD KDS)
mod online {
    use super::*;

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
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

    #[wasm_bindgen_test]
    fn test_suite() {
        init_logger();
        common::verify_attestation_suite();
    }
}
