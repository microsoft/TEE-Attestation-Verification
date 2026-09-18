# TAV did:x509

Rust validation and resolution of [`did:x509` identifiers](https://github.com/microsoft/did-x509).
TAV owns certificate parsing and cryptographic verification. The library implements
DID grammar, certificate predicates, fingerprints, JWKs, and DID Documents.

## Status

`tee-attestation-verification-didx509` is a member of the
[TAV workspace](https://github.com/microsoft/TEE-Attestation-Verification).
It uses the sibling [`crypto`](../crypto) crate.
The DID crate and its shared [`maybe-async`](maybe-async) proc macro use version
`1.0.8`, Rust 1.85, edition 2021, and the MIT license. Both dependencies use local
paths with registry versions. No Git dependency, patch, or vendored TAV checkout
is needed.

Full RFC 5280 path validation is not implemented. The
[did:x509 draft requires it](fixtures/upstream/did-x509/specification.md#did-resolution),
so this crate does not claim full draft conformance or general-purpose
production readiness. Matching the pinned C++ implementation does not establish
conformance: both currently accept some chains that certificate-policy processing
should reject. `PolicyConfig` makes this limitation explicit but does not fix it.

## Use

From another TAV workspace crate:

```toml
[dependencies]
tee-attestation-verification-didx509 = { version = "1.0.8", path = "../didx509" }
```

```rust
use tee_attestation_verification_didx509::{
	validation_sync, PolicyConfig, ValidationError, ValidationTime,
};

fn resolve(did: &str, chain_pem: &str) -> Result<String, ValidationError> {
	let document = validation_sync::resolve_pem(
		did, chain_pem, ValidationTime::Now, PolicyConfig::default(),
	)?;
	Ok(document.to_json())
}
```

The matching async API is `validation_async`; await the same operations.
Both namespaces come from one `maybe_async` implementation. Parsing and predicate
evaluation are shared synchronous code.

All validation and resolution functions take a `PolicyConfig` as their final
argument. Its only option is `rfc5280_validation`, which defaults to `false`.
The default preserves existing certificate-signature, path, validity-time,
extension, fingerprint, and DID-predicate checks. It does not claim full RFC 5280
processing, including certificate-policy constraints. Setting the option to `true`
currently returns `ValidationError::UnsupportedPolicy` on every backend, before
processing the DID or certificates.

| Input | Validate | Resolve |
|---|---|---|
| Certificate-only PEM, leaf first | `validate_pem` | `resolve_pem` |
| Individual DER slices, `&[&[u8]]`, leaf first | `validate_der` | `resolve_der` |
| Spec `x509chain`: comma-separated base64url DER | `validate_x509chain` | `resolve_x509chain` |

`resolve_jwk_pem` returns only the validated leaf JWK. Resolution supports RSA and
EC P-256/P-384/P-521 public keys. Key Usage controls `authentication`,
`assertionMethod`, and `keyAgreement`. A present Key Usage with neither relevant
bit fails resolution. Validation alone does not require a supported JWK key.

All inputs require at least two certificates. The last certificate is the supplied
trust anchor, which may be an intermediate CA. The fingerprint must identify a
non-leaf certificate in the exact verified path. Extra, reordered, substituted,
and trailing certificate data are rejected.

Use `ValidationTime::At(SystemTime)` for historical validation. The caller must
establish whether a claimed signing time is trustworthy; this crate does not
authenticate timestamps. There is no skip-time mode. The anchor's validity is
checked too.

Validation proves that a certificate chain satisfies a DID. It does **not** decide
whether that DID is authorized. Keep caller allowlists, endorsement signature
checks, revocation, and other application policy outside this library.

## Backends

Defaults follow TAV's target selection: OpenSSL on non-Windows native targets,
Windows Crypt32/CNG on Windows, and WebCrypto on WASM. Explicit features are
`crypto_openssl`, `crypto_windows`, and `crypto_webcrypto`. Pure-Rust crypto is no
longer supported by current TAV.

Windows and WebCrypto retain TAV's conservative path-policy subset. They reject
name constraints, policy mappings, policy constraints, `inhibitAnyPolicy`, and
critical certificate policies. They accept noncritical certificate policies
without processing a policy tree. OpenSSL performs its own path validation, but
the current adapter does not enable full certificate-policy processing. No backend
accepts a critical Fulcio issuer extension.

## Dependencies and ownership

The DID crate writes its fixed JWK and DID Document JSON schemas directly, with
shared escaping for all string fields. `serde_json` is a dev-dependency for reading
the conformance corpus and comparing serialized output. Production serialization
requires no JSON dependency. `scripts/check.sh dependencies` checks the DID
crate's normal dependency graph across all targets and fails if
`serde_json` appears. It excludes dev-dependencies.
The same command checks DID production dependencies on both native backends
and rejects `x509-cert`, `pkcs1`, `der`, or `spki`. It uses the
`x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` targets regardless of the
host.

Base64 encoding and exact-path validation use TAV crypto.
`CertificateBackend::certificate_details` and
`CertificateBackend::public_key_components` expose metadata on every backend.
OpenSSL and Windows extract metadata
through native APIs without `x509-cert` or `pkcs1`. Only WebCrypto uses TAV's
private parser to decode backend DER. The public accessor types contain
neutral attributes, SAN variants, OID strings, and key components, not parser
types.

DID validation checks structural metadata and predicates without extracting a
supported JWK. Only resolution calls `public_key_components` and applies the
leaf's digital-signature and key-agreement usage bits. Fulcio issuer values
remain raw extension bytes from `get_extension_value_by_oid`.

The dependency alias `maybe-async-attr` refers to
`tee-attestation-verification-maybe-async` in `maybe-async/`.
The macro retains the source module depth and relative-path semantics.

## Compatibility and development

Pinned sources and file hashes live in `fixtures/upstream/*/source.json`.
The specification is pinned at `471c7ca`; the production C++ implementation at
`f754568`. Fixtures include the upstream resolution corpus and C++ regressions
for UTF-8, exact SAN matching, embedded NULs, and zero-prefixed EC coordinates.
Upstream licenses and the historical `SOURCE` import record remain with the
fixtures.

Intentional differences are explicit in `tests/resolution.rs`:

- The upstream vector that rejects an unrelated IP SAN is accepted. An IP SAN
  cannot satisfy a DID predicate but does not invalidate an unrelated subject
  predicate.
- Windows/WebCrypto reject the two positive corpus cases requiring unsupported
  name-constraint or critical certificate-policy processing.
- Upstream vectors omit time validation. Their local validation times are derived
  from the common validity interval of each chain; validity is not disabled.

Grammar is strict: version `0`, canonical fingerprints, nonempty percent-encoded
UTF-8 predicate values, no `S` alias, and no repeated subject OIDs. Fragments are
accepted and removed from the resolved document ID; paths and queries are rejected.
Name decoding supports UTF8String, PrintableString, IA5String, BMPString, and ASCII
TeletexString. Other encodings and x400Address SANs fail closed. OpenSSL rejects
empty RDN groups because its decoder loses them; an entirely empty subject remains
supported. Windows rejects high-tag-number encodings inside opaque ASN.1 values,
such as custom `otherName` payloads. Resolution does not support compressed EC
points or key families other than RSA/named NIST EC.

```sh
# From the TAV workspace root:
bash didx509/scripts/check.sh native
bash didx509/scripts/check.sh dependencies

# From didx509/:
bash scripts/check.sh native
bash scripts/check.sh wasm                 # requires wasm-pack and Node with WebCrypto
bash scripts/check.sh dependencies         # no production serde_json
bash scripts/check.sh differential 200 7   # fuzz against didx509cpp: iterations, seed
python3 scripts/import-fixtures.py          # requires OpenSSL; refresh pinned upstream files
python3 scripts/generate-key-fixtures.py    # regenerate local public certificate fixtures
python3 scripts/generate-key-fixtures.py --unsupported-key-only  # only the validation-only Ed25519 fixture
```

`check.sh` changes to the crate directory before invoking tools. Native checks
select only the DID and macro packages in one Cargo invocation, not the
whole workspace. Native and WASM
checks use the root workspace lockfile. WASM runs
`wasm-pack test --node --locked --no-default-features --features crypto_webcrypto`
from `didx509/`. Builds default to half the available CPUs through
`CARGO_BUILD_JOBS`; an explicit value is retained.

### Parity with didx509cpp

This is a compatibility comparison with one pinned implementation, not normative
proof of RFC 5280 or did:x509 draft conformance.

`fuzz/differential/fuzz.py` generates a signed chain and a matching DID. Both
resolvers must accept this parent case and return identical public JWKs before any
mutation runs. The driver then keeps the pair or applies one mutation, such as a
wrong fingerprint, changed predicate value, reordered chain, or expired leaf.
Each mutation has explicit expected outcomes in `EXPECTED_OUTCOMES`. Repeating a
satisfied subject predicate remains valid. Every accepted result must retain the
parent's key.

The only allowed divergence is a fragment: the pinned C++ must reject it, while
Rust must accept it with the unchanged parent key. Crashes, timeouts, malformed
oracle output, unexpected acceptance or rejection, and key mismatches all fail.
Failures save the parent, the mutated case, and the expected outcomes under
`fuzz/differential/failures/<seed>-<index>/`. Run
`python3 -B fuzz/differential/fuzz.py --replay <dir>` to repeat those assertions.
Replay still uses the current time, so an old saved certificate can expire.

`check.sh differential` first runs the driver's regression tests using Python's
standard library. Run them without building either oracle:

```sh
python3 -B -m unittest discover -s fuzz/differential -p 'test_*.py'
```

The Rust oracle in `fuzz/differential` is a separate workspace, excluded from the
TAV workspace. It depends on this DID crate and the root `crypto/` crate by local
path, with no Git patch. Builds use `--locked` with the oracle's own checked-in
`Cargo.lock`, without touching TAV's root lockfile.
Both oracle binaries and the hash-checked pinned C++ header
stay under `fuzz/differential/target/`. The driver resolves build paths relative
to its own file, so it also runs from the workspace root:

```sh
python3 -B didx509/fuzz/differential/fuzz.py --iterations 200 --seed 7
```

Replay paths are relative to the invoking directory. The seed fixes generator
choices, not certificate bytes: OpenSSL generates fresh keys and certificate
timestamps on each run. The fuzzer needs `g++`,
`pkg-config`, OpenSSL headers, and an `openssl` CLI of 3.4 or later.

DID Document JSON is not compared: this crate emits the current
`https://www.w3.org/ns/cid/v1` shape and the pinned C++ emits the older
`JsonWebKey2020` shape.

Fixture generators never retain private keys. Regeneration changes local
certificates and their recorded validation time. The Ed25519 leaf fixture uses
an RSA CA so its chain can validate on each backend even though resolution does
not support its public-key family. JSON member order is not a
canonicalization contract. Errors retain inputs for diagnostics; avoid logging
`Debug` output when certificate identity data must remain private.
