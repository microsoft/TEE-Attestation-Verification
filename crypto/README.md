# TEE Attestation Verification Crypto

Rather than implementing any cryptographic primitives, this crate dispatches these to one of several backends.
It narrowly exposes a unified surface for signature verification and certificate chain verification across native and WebCrypto backends.

## Backends

The default feature set enables every backend selector. `build.rs` chooses the
target-compatible backend, and Cargo activates only that target's dependencies.

| Feature | Platforms | sync | async | Notes |
|---|---|---:|---:|---|
| `crypto_openssl` | Native non-Windows | yes | yes | Uses OpenSSL for native certificate-chain verification and primitive verification. |
| `crypto_webcrypto` | WASM | no | yes | Uses `globalThis.crypto.subtle` for primitive verification and the shared X.509 path validator. |
| `crypto_windows` | Windows | yes | yes | Uses Windows CNG for primitive verification and Crypt32 for certificate-chain verification. |

Use `--no-default-features` with an explicit backend feature to test or restrict
the selected backend. Windows targets require `crypto_windows`. Other native
targets use `crypto_openssl`, and WASM targets use `crypto_webcrypto`.

## Scope

This crate provides signature verification, certificate-chain verification, and
certificate metadata decoding for attestation consumers. It does not implement
generic cryptographic primitives.

## Certificate metadata

`CertificateBackend` provides `certificate_details` and
`public_key_components`. The returned types belong to this
crate and do not expose backend-specific types.

`certificate_details` returns subject attributes grouped by relative
distinguished name (RDN), subject alternative names, and extended key usage OIDs.
It preserves repeated attributes, Unicode, and embedded NUL bytes. An absent
extension returns `None`. A present but empty extension returns an empty vector.
Malformed metadata returns an error, not an absent value.

`public_key_components` returns unsigned big-endian RSA modulus and exponent
bytes, or fixed-width EC coordinates for P-256, P-384, and P-521. EC keys must use
named curves and uncompressed points. Component extraction does not enforce key
strength or check whether an EC point lies on its curve.

`CertificateBackend::key_usage` exposes `key_cert_sign`, `digital_signature`,
and `key_agreement`. A malformed queried KeyUsage extension
returns an error.

OpenSSL and Windows decode metadata through native APIs. Neither backend
includes `x509-cert`, `pkcs1`, `der`, or `spki` in its production dependency
graphs. Only WebCrypto uses the private `x509-cert` metadata decoder. Raw
extension lookup by OID remains available.

OpenSSL metadata decoding rejects empty RDN groups because OpenSSL does not
preserve their structure. Entirely empty subject names remain supported.
Windows metadata decoding rejects high-tag-number encodings inside opaque ASN.1
values, such as custom `otherName` payloads.

Decoded metadata does not imply trust. Certificate paths must be verified separately.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.