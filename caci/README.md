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
    caci_uvm_endorsement,
    "ContainerPlat-AMD-UVM",
    minimum_uvm_svn,
)?;
```

## WASM

Release tags use the `tav-<crate-version>` format.

Releases include `tav-caci-<version>.tar.gz`, a WASM and JS wrapper tarball
for direct consumption. Download and extract the matching GitHub release asset
for your chosen tag into a directory served by your application:

```sh
mkdir -p public/vendor/tav-caci
tar -xzf tav-caci-<version>.tar.gz --strip-components=1 -C public/vendor/tav-caci
```

Keep the generated `.js` and `.wasm` files together. By default, the JS wrapper
loads `tee_attestation_verification_caci_bg.wasm` next to itself using
`import.meta.url`.

Import the generated JS wrapper from your application code:

```js
import init, {
  split_pem_bundle,
  verify_snp_attestation_with_cert_chain_async,
  verify_caci_attestation,
  verify_uvm_endorsement_async,
} from "/vendor/tav-caci/tee_attestation_verification_caci.js";

await init();
```
