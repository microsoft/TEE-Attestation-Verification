# TEE Attestation Verification Crypto

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across native and WebCrypto backends.

## Backends

The default `crypto_compliant` feature selects a target-compatible backend and
activates only that target's backend dependencies.
The feature selects an implementation. Deployment configuration determines
whether that implementation meets a specific compliance standard.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_compliant` | Native and WASM | target-dependent | yes | Selects Windows CNG on Windows, WebCrypto on WASM, and OpenSSL on other native targets. |
| `crypto_openssl` | Native non-Windows | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_windows` | Windows | yes | yes | Uses Windows CNG for primitive verification and Crypt32 for certificate-chain verification. |

Use `--no-default-features` with an explicit backend feature to override the
default. Windows targets require `crypto_windows`. Other native targets use
`crypto_openssl`, and WASM targets use `crypto_webcrypto`.

## Scope

This crate is intentionally limited to just what is required to verify SNP attestations, and in the future UVM endorsements.
This narrow scope ensures we don't need to implement generic cryptographic primitives.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.