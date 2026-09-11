# TEE-Attestation-Verification

A minimal-external-dependencies, portable and safe library for verifying a TEE attestation and its collateral, and returning to the caller the authenticated claims.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **WASM-Compatible**: Build for `wasm32` with a WebCrypto backend
- **Azure Linux 3.0 compatible**: Build for Azure Linux 3.0, with `rust-openssl` as the sole dependency.

## Crypto Backends

The default feature set enables every backend selector. The build selects the
target-compatible backend.

| Feature | Platforms | sync | async | Dependencies |
|---|---|---|---|---|
| `crypto_openssl` | Native non-Windows | ✓ | ✓ | OpenSSL |
| `crypto_webcrypto` | WASM only | | ✓ | WebCrypto API |
| `crypto_windows` | Windows | ✓ | ✓ | Windows CNG and Crypt32 |

## Optional Features

| Feature | Description |
|---|---|
| `kds` | Enables automatic certificate fetching from AMD's Key Distribution Service. Uses `curl`/`tokio` on native, `globalThis.fetch` on WASM. |

## Usage

Add the library to your `Cargo.toml`:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X" }
```

### Offline verification (caller provides certificates)

Parse the attestation report from its raw 1184-byte binary representation and verify with the synchronous API:

```rust
use tee_attestation_verification_lib::snp::verify::{sync as tav, ChainVerification};
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)?;
let vcek = certificate_from_pem(vcek_pem)?;
let ask = certificate_from_pem(ask_pem)?;

tav::verify_attestation(
    &attestation_report,
    &vcek,
    &ChainVerification::WithPinnedArk { ask: &ask },
)?;
```

### KDS verification (automatic certificate fetching)

Enable the `kds` feature to let the library fetch certificates from AMD's KDS:

```toml
[dependencies]
tee-attestation-verification-lib = { git = "https://github.com/microsoft/TEE-Attestation-Verification", tag = "tav-X.X.X", features = ["kds"] }
```

```rust
use tee_attestation_verification_lib::{AttestationReport, SevVerifier};
use zerocopy::FromBytes;

let attestation_report = AttestationReport::read_from_bytes(attestation_bytes)?;

let mut verifier = SevVerifier::new().await?;
verifier.verify_attestation(&attestation_report).await?;
```

## What verification checks

A successful `verify_attestation` call establishes that the report bytes were signed by the VCEK of an AMD processor whose identity and firmware levels match that VCEK. It does not establish that the report is fresh, that the guest is one you accept, or that the guest is configured the way you require. Those checks stay with the caller. See [What the caller must check](#what-the-caller-must-check).

`snp::verify::sync::verify_attestation` and `snp::verify::asynchronous::verify_attestation` run these checks in order and return the first failure as a `VerificationError`:

1. **Processor generation.** `cpuid_fam_id` and `cpuid_mod_id` must select Milan, Genoa, or Turin (`Generation::from_family_and_model`). Anything else fails with `UnsupportedProcessor`.
2. **Certificate chain**, as selected by `ChainVerification`:
   - `WithPinnedArk { ask }` verifies ASK and VCEK against the ARK compiled into the crate for that generation (`src/pinned_arks/*.pem`).
   - `WithProvidedArk { ask, ark }` first requires the provided ARK to have the same issuer name and public key as the pinned ARK and a valid self-signature, then verifies ASK and VCEK against it.
   - `Skip` performs no chain verification. The VCEK is trusted as given. Use this only when you have already verified the VCEK yourself.

   Chain verification checks each signature, RFC 5280 path rules (issuer and subject names, basic constraints, key usage, and rejection of unhandled critical extensions), and each certificate's validity period. The `crypto_openssl` backend delegates this to OpenSSL's `X509_verify_cert` with `PARTIAL_CHAIN`. The `crypto_windows` and `crypto_webcrypto` backends use the checks in `crypto/src/x509_policy.rs`.
3. **Signing key.** The report's `SIGNING_KEY` flag must be VCEK. VLEK, `None`, and reserved values fail with `SignatureVerificationError`.
4. **Report signature.** `signature_algo` must be `0x0001` (ECDSA P-384 with SHA-384). The signature over bytes `0x000..0x2A0` must verify with the VCEK public key.
5. **TCB and hardware ID.** Each component of `reported_tcb` (boot loader, TEE, SNP firmware, microcode, and FMC on Turin) must equal the corresponding VCEK extension, and the VCEK hardware ID extension must equal `chip_id`. Extension values are accepted only in the exact encodings AMD issues. A missing extension fails.

### Time and revocation

The `attestation` crate always passes `unix_time: None` to `verify_chain`. Each crypto backend then evaluates certificate validity periods at the machine's current clock: OpenSSL uses the store default, `crypto_windows` uses `SystemTime::now()`, and `crypto_webcrypto` uses `Date.now()`. A wrong local clock therefore changes the outcome. The public verification APIs do not accept an explicit verification time.

No backend checks certificate revocation. There is no CRL or OCSP lookup and no hook to plug one in. If AMD revokes an ASK or VCEK, this library still accepts it.

## What the caller must check

Verification authenticates the report. It does not authorize the guest. The library reads the following fields but does not compare them to any expected value. Decide what each must be for your deployment and check it after `verify_attestation` returns `Ok`:

- `report_data`: bind it to your nonce, challenge, or public-key digest. Without this, a valid report can be replayed.
- `measurement`, `host_data`, `id_key_digest`, `author_key_digest`, `family_id`, and `image_id`: identify the guest image and who launched it.
- `policy()` (debug, SMT, migration agent, and ABI minimums), `vmpl`, `platform_info`, and `guest_svn`: guest and platform configuration.
- `platform_version`, `committed_tcb`, and `launch_tcb`: the library checks only `reported_tcb` against the VCEK. Whether those TCB levels are new enough is a deployment decision.
- `version`: the library parses every 1184-byte buffer as a version 3 layout and does not reject other report versions.

Parsing with `AttestationReport::try_read_from_bytes` checks only the buffer length and field layout. Callers of the C or WASM bindings should also read the ownership and lifetime rules in [`ffi/include/tav/snp.h`](../ffi/include/tav/snp.h).

## Trust model

With `WithPinnedArk` or `WithProvidedArk`, trust ends at the AMD root keys compiled into this crate. Updating those roots requires a new release.

With `SevVerifier` (`kds` feature), the library downloads the ARK, ASK, and VCEK from `https://kdsintf.amd.com` and verifies the ASK and VCEK against the downloaded ARK. It does not compare the downloaded ARK to the pinned one. Trust in that path rests on TLS to `kdsintf.amd.com` as configured by `curl` on native or the browser on WASM. A `SevVerifier` keeps downloaded certificates in memory for its lifetime and does not refetch them. Removal of KDS support from this crate is planned.

## Docs
Docs are available locally by running:
- `cargo doc` for native docs
- `cargo doc --target wasm32-unknown-unknown` for WASM builds

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
