# Changelog

## 0.1.0

- Initial development release of the TEE attestation verification library.
- Supports native Rust consumers with the `crypto_openssl` and `crypto_pure_rust` backends.
- Supports WebAssembly consumers with the `crypto_webcrypto` and `crypto_pure_rust` backends and generated `wasm-pack` wrapper output.
- Rust consumers use tagged git dependencies with `tav-<crate-version>` tags.
- WASM consumers can use the GitHub release tarball containing the generated WebCrypto `pkg/` bundle.
