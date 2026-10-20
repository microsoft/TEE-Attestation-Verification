// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(sync_crypto)");
    println!("cargo:rustc-check-cfg=cfg(async_crypto)");

    let sync_crypto = std::env::var("DEP_TAV_CRYPTO_SYNC_CRYPTO").unwrap_or_default();
    let async_crypto = std::env::var("DEP_TAV_CRYPTO_ASYNC_CRYPTO").unwrap_or_default();

    if sync_crypto == "true" {
        println!("cargo:rustc-cfg=sync_crypto");
    }
    if async_crypto == "true" {
        println!("cargo:rustc-cfg=async_crypto");
    }
}
