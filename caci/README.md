# CACI verification

`tee-attestation-verification-caci` verifies ACI/UVM endorsement COSE blobs
against a verified SEV-SNP attestation report and a caller-pinned `did:x509`
root of trust.

## UVM identity validation

CACI uses [`tee-attestation-verification-didx509`](../didx509/) to validate the
caller-trusted DID and the COSE protected issuer DID against the exact supplied
`x5chain`, ordered leaf first and trust anchor last. Validation includes each
DID's predicates, not just its fingerprint. Both DIDs must have the same prefix
through the CA fingerprint. Their predicates can differ if the same certificates
satisfy both. The COSE signature must verify with that chain's leaf public key.

Certificate validity uses the legacy protected `signingtime` or protected CWT
`iat`. Legacy time must be a CBOR tag 1 non-negative integer. CWT time also
accepts an untagged non-negative integer. Missing time selects the current time.
CACI converts supplied time with checked `UNIX_EPOCH` addition and rejects
out-of-range values.

These times are signer claims, authenticated only when the COSE signature
verifies. They are not independent timestamp proof, freshness guarantees, or
evidence that the key was uncompromised at the claimed time.

CACI uses `PolicyConfig::default()`, with `rfc5280_validation: false`. This retains
the DID crate's certificate-signature, exact-path, validity-time, extension,
fingerprint, and predicate checks. Full RFC 5280 processing, including
certificate-policy constraints, is not implemented. Enabling that option in
the DID crate currently returns an unsupported-policy error.

Certificate parsing, path, and validity failures return `AciError::Certificate`.
DID syntax, issuer linkage, fingerprint, and predicate failures return
`AciError::DidX509`. These categories preserve the corresponding FFI error codes.

The default and explicit `crypto_openssl`, `crypto_windows`, and
`crypto_webcrypto` features select the same backend for CACI and DID validation.
Synchronous and asynchronous staged APIs remain available according to backend
capabilities. AMD attestation verification is unchanged.

## Usage

We establish trust in an ACI container using the following relying-party-policy:
- The hardware attestation has a trust chain rooted in AMD
- The UVM endorsements have a trust chain rooted in a trusted did:x509
- The hardware attestation's measurement is the endorsed UVM measurement
- The security policy digest (`attestation.host_data`) is trusted
- The UVM feed, UVM SVN, and SNP TCB version meet the relying party's policy
- The verified `attestation.report_data` is returned for caller-specific key
  release or encryption

The API of this library tries to expose this process to the user.

```rust
use tee_attestation_verification_caci::{snp, synchronous as tav};

let report = tav::verify_attestation(
    attestation_report_bytes,
    amd_endorsements,
)?;
let trusted_didx509 =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
let caci_uvm_endorsement = tav::verify_uvm_endorsement(
    aci_cose_sign1,
    trusted_didx509,
)?;
let minimum_tcb: Vec<(snp::Cpuid, snp::report::TcbVersionRaw)> =
    vec![(container_cpuid, minimum_tcb_version)];
let verified_report_data = tav::verify_caci_attestation(
    report,
    minimum_tcb,
    vec![trusted_caci_execution_policy], // SHA-256 digest of the loaded security policy.
    &caci_uvm_endorsement,
    "ContainerPlat-AMD-UVM",
    minimum_uvm_svn,
)?;
```
