# TEE-Attestation-Verification

A minimal-external-dependencies, portable and safe library for verifying a TEE attestation and its collateral, and returning to the caller the authenticated claims.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Built for `wasm32-unknown-unknown` target with no external dependencies
- **Azure Linux 3.0 compatible**: Built for Azure Linux 3.0, with `rust-openssl` as the sole dependency.

## Usage

```rust
use sev_verification::verify_attestation;

let result = verify_attestation(attestation_bytes).await?;

if result.is_valid {
    println!("Attestation verified successfully!");
} else {
    println!("Verification failed: {:?}", result.errors);
}
```

## Building

Build for WebAssembly:

```bash
cargo build --target wasm32-unknown-unknown --release
```

Use the low TCB variant in another project:
```toml
tee-attestation-verification = { default-features = false, features = ["crypto_openssl"], ...}
```

## SEV-SNP Verification Process

- **Certificate Validation**: Verifies the certificate chain from the ARK through the ASK to the VCEK, and the ARK against a root-of-trust
- **Signature Validation**: Validates the attestation report signature was signed by the VCEK
- **TCB Verification**: Confirm that the TCB values in the attestation report match the VCEK's x509v3 extensions.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft’s Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
