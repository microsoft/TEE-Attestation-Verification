# TEE Attestation Verification

Portable Rust libraries and demos for verifying trusted execution environment
attestations.

The workspace currently focuses on AMD SEV-SNP attestation reports: parsing the
report, verifying AMD certificate collateral, verifying the report signature,
and returning authenticated report claims to callers.

## Workspace layout

| Path | Package | Purpose |
|---|---|---|
| `crypto/` | `tee-attestation-verification-crypto` | Backend abstraction for certificate handling, certificate-chain verification, and signature verification. |
| `cose/` | `tee-attestation-verification-cose` | COSE signing and verification helpers backed by OpenSSL. |
| `attestation/` | `tee-attestation-verification-lib` | Public attestation verification APIs, SEV-SNP report types, KDS support, C ABI, and WASM bindings. |
| `demos/web-verify-kernel/` | n/a | Browser demo that exercises the WASM attestation bindings. |

Read the crate-specific docs for API details:

- [`attestation/README.md`](attestation/README.md)
- [`crypto/README.md`](crypto/README.md)
- [`demos/web-verify-kernel/README.md`](demos/web-verify-kernel/README.md)

## Crypto backend selection

At least one target-compatible backend must be enabled:

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native | yes | yes | Native OpenSSL-backed verification. |
| `crypto_webcrypto` | WASM | no | yes | Browser/Node WebCrypto-backed verification. |
| `crypto_pure_rust` | Native, WASM | yes | yes | Portable RustCrypto-backed verification. |

The attestation crate forwards these backend features to the crypto crate. Its
default features defer to the crypto crate's defaults, while callers can disable
defaults and choose a backend explicitly.

## Quick start

```toml
[dependencies]
tee-attestation-verification-lib = { version = "1.0.1", features = ["crypto_pure_rust"] }
```

```rust
use tee_attestation_verification_lib::snp::verify::{sync, ChainVerification};
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

let report = AttestationReport::read_from_bytes(attestation_report_bytes)?;
let vcek = certificate_from_pem(vcek_pem)?;
let ask = certificate_from_pem(ask_pem)?;

sync::verify_attestation(&report, &vcek, &ChainVerification::WithPinnedArk { ask: &ask })?;
```

Enable `kds` to fetch AMD certificate collateral automatically:

```toml
[dependencies]
tee-attestation-verification-lib = { version = "1.0.1", features = ["crypto_pure_rust", "kds"] }
```

## Publishing

The attestation crate depends on the crypto crate with both a local `path` and a
crates.io `version`, so local workspace builds use `../crypto` and published
builds resolve from crates.io. Publish `tee-attestation-verification-crypto`
before `tee-attestation-verification-lib`.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
