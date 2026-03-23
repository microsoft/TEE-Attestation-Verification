fn main() {
    println!("cargo:rustc-check-cfg=cfg(sync_crypto)");
    println!("cargo:rustc-check-cfg=cfg(async_crypto)");
    println!("cargo:rustc-check-cfg=cfg(crypto_provider, values(\"crypto_openssl\", \"crypto_pure_rust\"))");

    let has_openssl = std::env::var_os("CARGO_FEATURE_CRYPTO_OPENSSL").is_some();
    let has_pure_rust = std::env::var_os("CARGO_FEATURE_CRYPTO_PURE_RUST").is_some();

    let crypto_provider = if has_pure_rust {
        Some("crypto_pure_rust")
    } else if has_openssl {
        Some("crypto_openssl")
    } else {
        None
    };

    if let Some(crypto_provider) = crypto_provider {
        println!("cargo:rustc-cfg=sync_crypto");
        println!("cargo:rustc-cfg=async_crypto");
        println!("cargo:rustc-cfg=crypto_provider=\"{crypto_provider}\"");
    }
}
