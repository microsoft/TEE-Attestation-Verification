# TEE Attestation Verification

Portable Rust libraries and demos for verifying trusted execution environment
attestations.

The workspace currently focuses on AMD SEV-SNP attestation reports: parsing the
report, verifying AMD certificate collateral, verifying the report signature,
and returning authenticated report claims to callers.

## Workspace layout

| Path | Package | Purpose |
|---|---|---|
| `cbor/` | `tee-attestation-verification-cbor` | CBOR values over deterministic and non-deterministic EverCBOR. |
| `crypto/` | `tee-attestation-verification-crypto` | Backend abstraction for certificate handling, certificate-chain verification, and signature verification. |
| `didx509/` | `tee-attestation-verification-didx509` | did:x509 validation and resolution using the workspace crypto crate. |
| `didx509/maybe-async/` | `tee-attestation-verification-maybe-async` | Proc macro sharing the DID validator's synchronous and asynchronous implementation. |
| `cose/` | `tee-attestation-verification-cose` | COSE_Sign1 verification helpers. |
| `caci/` | `tee-attestation-verification-caci` | CACI UVM endorsement verification against SEV-SNP attestations and DID x509 roots of trust. |
| `attestation/` | `tee-attestation-verification-lib` | Public attestation verification APIs, SEV-SNP report types, and KDS support. |
| `ffi/` | `tee-attestation-verification-ffi` | Native C ABI, WebAssembly bindings, and a Linux x64 .NET binding and NuGet package for the Rust domain crates. |
| `demos/web-verify-kernel/` | n/a | Browser demo verifying an SNP attestation using the WASM bindings. |
| `demos/caci-attestation-verify/` | n/a | Browser demo verifying an SNP CACI attestation using the WASM bindings. |

Read the crate-specific docs for API details:

- [`attestation/README.md`](attestation/README.md)
- [`caci/README.md`](caci/README.md)
- [`cose/README.md`](cose/README.md)
- [`crypto/README.md`](crypto/README.md)
- [`didx509/README.md`](didx509/README.md)
- [`ffi/README.md`](ffi/README.md)

## Component dependencies

Arrows point from each dependency to the workspace crates that directly depend on it.

```mermaid
flowchart LR
    attestation["attestation (SNP)"]
    caci[caci]
    cbor[cbor]
    cose[cose]
    crypto[crypto]
    didx509[didx509]
    ffi[ffi]

    crypto --> attestation
    attestation --> caci
    cose --> caci
    crypto --> caci
    crypto --> didx509
    cbor --> cose
    crypto --> cose
    attestation --> ffi
    caci --> ffi
    cose --> ffi
    crypto --> ffi
```

## Crypto backend selection

The default feature set enables every backend selector. The build selects the
target-compatible backend:

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native non-Windows | yes | yes | Native OpenSSL-backed verification. |
| `crypto_webcrypto` | WASM | no | yes | Browser/Node WebCrypto-backed verification. |
| `crypto_windows` | Windows | yes | yes | Windows CNG and Crypt32-backed verification. |

Use explicit backend features with `--no-default-features` for backend-specific
testing.

The did:x509 crate validates certificate predicates and resolves DID Documents.
Full RFC 5280 processing is not implemented. See the
[DID validator's policy and backend limitations](didx509/README.md) before relying
on draft conformance.

## Quick start

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X" }
```

```rust
use tee_attestation_verification_lib::snp::verify::{sync as tav, ChainVerification};
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

let report = AttestationReport::read_from_bytes(attestation_report_bytes)?;
let vcek = certificate_from_pem(vcek_pem)?;
let ask = certificate_from_pem(ask_pem)?;

tav::verify_attestation(&report, &vcek, &ChainVerification::WithPinnedArk { ask: &ask })?;
```

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
