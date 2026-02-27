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

#[cfg(feature = "online")]
mod online {
    use super::*;

    #[tokio::test]
    async fn test_verify_milan_attestation() {
        init_logger();
        common::verify_milan_attestation()
            .await
            .expect("Verification call failed");
    }

    #[tokio::test]
    async fn test_verify_genoa_attestation() {
        init_logger();
        common::verify_genoa_attestation()
            .await
            .expect("Verification call failed");
    }

    #[tokio::test]
    async fn test_verify_turin_attestation() {
        init_logger();
        common::verify_turin_attestation()
            .await
            .expect("Verification call failed");
    }
}

/// Offline verification tests (sync, uses pinned ARKs)
mod offline {
    use super::*;

    #[test]
    fn test_suite() {
        init_logger();
        common::test_verify_attestation_suite();
    }
}
