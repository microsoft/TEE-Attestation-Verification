# TEE-Attestation-Verification

A minimal-external-dependencies, portable and safe library for verifying a TEE attestation and its collateral, and returning to the caller the authenticated claims.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Build for `wasm32` with a WebCrypto backend
- **Azure Linux 3.0 compatible**: Build for Azure Linux 3.0, with `rust-openssl` as the sole dependency.

## Usage

Add the library to your `Cargo.toml` with a native crypto backend:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-0.1.0", features = ["crypto_openssl"] }
```

Then verify an attestation report with the synchronous `snp::verify::sync` API:

```rust
use tee_attestation_verification_lib::snp::verify::{sync, ChainVerification};
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)?;
let vcek = certificate_from_pem(vcek_pem)?;
let ask = certificate_from_pem(ask_pem)?;

sync::verify_attestation(
    &attestation_report,
    &vcek,
    &ChainVerification::WithPinnedArk { ask: &ask },
)?;
```

## Wasm

Release tags use the `tav-<crate-version>` format.

Releases include a WASM and JS wrapper tarball for direct consumption. The tarball contains the generated `wasm-pack` `pkg/` output for the WebCrypto backend.

### Consuming a release tarball

Download the matching GitHub release asset for your chosen `tav-<crate-version>` tag.

### Building from source

Build the library for `wasm32` with the WebCrypto backend:

```bash
wasm-pack build --target web --no-default-features --features "crypto_webcrypto"
```

For a plain Cargo build targeting `wasm32-unknown-unknown`:

```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features "crypto_webcrypto"
```

## SEV-SNP Verification Process

- **Certificate Validation**: Verifies the certificate chain from the ARK through the ASK to the VCEK, and the ARK against a root-of-trust
- **Signature Validation**: Validates the attestation report signature was signed by the VCEK
- **TCB Verification**: Confirm that the TCB values in the attestation report match the VCEK's x509v3 extensions.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft’s Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
