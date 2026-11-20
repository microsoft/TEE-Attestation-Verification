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

`verify_uvm_endorsement` parses the endorsement before anything authenticates
it, and its size is unchecked: bound untrusted input before calling.

## Signed TCB info

`synchronous::verify_tcb_info` (or `asynchronous::verify_tcb_info` with an async
crypto backend) accepts COSE_Sign1 bytes with protected content type
`application/vnd.tcb-reference-info.v1+cose`. It verifies the signature and
embedded certificate chain against a caller-pinned `did:x509` root before
decoding the manifest payload.

```rust
let watermarks = tav::verify_tcb_info(tcb_info_cose, trusted_tcb_info_didx509)?;
let minimum_tcb: Vec<_> = watermarks
    .into_iter()
    .map(|entry| (entry.cpuid, entry.tcb))
    .collect();
```

The verifier returns AMD SEV-SNP entries only. An absent or empty SNP section
returns an empty list; if your policy requires SNP watermarks, reject an empty
list before using it as `minimum_tcb`. Future TEE entries are ignored after CBOR
decoding within the library's usual CBOR limits. The verifier does not check
SCITT receipts or prevent manifest rollback. Pin the TCB signer's root
independently of the input and bound untrusted input size before calling.
