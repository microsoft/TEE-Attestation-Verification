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

#[cfg(async_crypto)]
mod r#async {
    use super::*;

    #[tokio::test]
    async fn test_suite() {
        init_logger();
        common::test_verify_attestation_suite_async().await;
    }

}

#[cfg(sync_crypto)]
mod sync {
    use super::*;

    #[test]
    fn test_suite() {
        init_logger();
        common::test_verify_attestation_suite();
    }
}
