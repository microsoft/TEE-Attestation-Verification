# verification-lib

A WASM-compatible Rust library for AMD SEV-SNP attestation verification.

## Overview

This library provides cryptographic verification of AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation reports. It's designed to run in WebAssembly environments where it uses pure-Rust cryptography implementations and minimal TCB environments where it uses the system's OpenSSL.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Built for `wasm32-unknown-unknown` target with no native dependencies
- **Low TCB**: Feature flags for `crypto-openssl` in comparison to `crypto-pure-rust` and useful but unnecessary dependencies such as `serde`

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

Include the low TCB variant in another project:
```toml
verification-lib = { default-features = false, features = ["crypto_openssl"], ...}
```

## Verification Process

The library performs the following verification steps:

1. **Processor Identification**: Determines the processor model from the attestation report
2. **Certificate Fetching**: Retrieves ARK (AMD Root Key), ASK (AMD SEV Key), and VCEK (Versioned Chip Endorsement Key) from KDS
3. **Certificate Chain Validation**: Verifies ARK is self-signed, ASK is signed by ARK, and VCEK is signed by ASK
4. **Signature Verification**: Validates the attestation report signature using the VCEK public key
5. **TCB Verification**: Confirms Trusted Computing Base (TCB) values in the report match the VCEK certificate extensions

## Contributing

Contributions welcome! Priority areas include:
- Support for Genoa, Turin, and other AMD processor models
- Additional attestation verification types (e.g., TDX)
- Testing collateral

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft’s Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
