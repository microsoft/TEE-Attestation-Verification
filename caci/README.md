# CACI verification

`tee-attestation-verification-caci` verifies ACI/UVM endorsement COSE blobs
against a verified SEV-SNP attestation report and a caller-pinned `did:x509`
root of trust.

## Usage

We establish trust in an ACI container using the following relying-party-policy:
- The hardware attestation has a trust chain rooted in AMD
- The UVM endorsements have a trust chain rooted in a trusted did:x509
- The hardware attestation's measurement is the endorsed UVM measurement
- The security policy digest (`attestation.host_data`) is trusted
- The UVM feed, UVM SVN, and SNP TCB version meet the relying party's policy
- The verified `attestation.report_data` is returned for caller-specific key
  release or encryption

Authenticate the SNP report and each signed endorsement separately, then
pass the verified artifacts to the CACI policy check.

```rust
use tee_attestation_verification_caci::{synchronous as tav, EndorsementPolicy};

let report = tav::verify_attestation(attestation_report_bytes, amd_endorsements)?;
let uvm_policy = EndorsementPolicy {
    trusted_iss: trusted_uvm_iss,
    expected_sub: "ContainerPlat-AMD-UVM",
    minimum_svn: minimum_uvm_svn,
};
let tcb_policy = EndorsementPolicy {
    trusted_iss: trusted_tcb_iss,
    expected_sub: trusted_tcb_sub,
    minimum_svn: minimum_tcb_endorsement_svn,
};
let uvm = tav::verify_uvm_endorsement(uvm_cose_sign1, &uvm_policy)?;
let tcb = tav::verify_tcb_endorsement(tcb_cose_sign1, &tcb_policy)?;
let verified_report_data = tav::verify_caci_attestation(
    report,
    &tcb,
    vec![trusted_caci_execution_policy], // SHA-256 digest of the loaded security policy.
    &uvm,
)?;
```

The `asynchronous` module exposes the same stages with async functions.
Each endorsement has its own policy. The signed `iss` must exactly match the
configured `did:x509`, and the signing leaf must contain the EKU(s) required by
that DID. Only `eku` DID policy clauses are supported. The verifier checks the
signed CWT `sub` and `svn`; for legacy UVM endorsements it uses the signed
`feed` and numeric guest SVN instead. Bound untrusted input before parsing.

## Signed TCB info

`verify_tcb_endorsement` accepts COSE_Sign1 bytes with protected content type
`application/vnd.tcb-reference-info.v1+cose`. The manifest's signed SVN is
independent of the per-CPU TCB watermarks in its payload. The CACI policy
check rejects a report if its CPU generation has no watermark or its
reported TCB is below an applicable watermark. Future TEE entries are ignored
within the library's CBOR limits. The verifier does not check SCITT receipts
or maintain rollback state; configure the minimum acceptable endorsement SVN.

The existing C, C++, C#, and WASM bindings still use the caller-supplied TCB
minima and root-pinned UVM flow. The equivalent Rust compatibility calls are
`verify_uvm_endorsement_with_root_pin` and
`verify_caci_attestation_with_minimum_tcb`.
