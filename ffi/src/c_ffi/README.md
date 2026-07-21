# C ABI

Native C ABI for SNP, COSE, and CACI verification. Headers live under
`ffi/include/tav/`; each header's usage summary documents its own surface in
more detail (`snp.h`, `cose.h`, `caci.h`, `utils.h`).

All public functions return `NULL` on success or an owned `TavError*` on
failure. Inspect failures with `tav_error_code`/`tav_error_message`, then free
them with `tav_error_free`. Owned handle out-parameters are reset to `NULL`
before any fallible work and set only on success.

If an entry point's implementation panics (e.g. on a bug triggered by
malformed input), the panic is caught at the FFI boundary and reported as a
`TAV_ERROR_PANIC` error instead of aborting the host process.

## Building and linking

```sh
cargo build --manifest-path ffi/Cargo.toml --no-default-features --features crypto_openssl
```

That produces `libtee_attestation_verification_ffi.{a,so}` under
`target/debug/` (or `crypto_pure_rust` for the portable backend). Link against
it and include `ffi/include/tav/`. See `ffi/tests/c-consumer/CMakeLists.txt`
for a worked CMake setup, including static linking.

## CBOR handle ownership

`tav_cbor_value_from_bytes` returns an owned root. The original CBOR child
accessors (`tav_cbor_value_array_at`, the map and tag accessors, and
`tav_validate_cose_sign1`) continue to return borrowed `const TavCborValue *`
handles. Their released signatures and ownership contract are unchanged:
callers must not free them, and they become invalid when their owning ancestor
is freed.

Consumers that need an independent lifetime can pass any live root or borrowed
view to `tav_cbor_value_to_owned`. It returns a mutable `TavCborValue *` handle
for the same value and shares the immutable parsed document through reference
counting; it does not clone a subtree or serialize and reparse it. The input
must remain valid through the call. Free every returned handle with the
null-safe `tav_cbor_value_free`; the new handle remains valid after every
ancestor handle is freed:

```c
TavCborValue *root = NULL;
const TavCborValue *borrowed_child = NULL;
TavCborValue *owned_child = NULL;
tav_cbor_value_from_bytes(cbor, cbor_len, &root);
tav_cbor_value_array_at(root, 0, &borrowed_child);
tav_cbor_value_to_owned(borrowed_child, &owned_child);

tav_cbor_value_free(root); /* owned_child remains valid */
TavCborKind kind = tav_cbor_value_kind(owned_child);
tav_cbor_value_free(owned_child);
```

Byte and text pointers are still borrowed from the handle passed to their
accessor. When that handle is independently owned, those pointers remain valid
until the handle is freed.

## SNP verification

```c
TavSnpAttestationReport *report = NULL;
TavError *error = tav_verify_snp_attestation(
    report_bytes, report_len,
    ark_pem, ark_pem_len,
    ask_pem, ask_pem_len,
    vcek_pem, vcek_pem_len,
    &report);
if (error != NULL) { /* inspect, then tav_error_free(error); */ }

const uint8_t *measurement = NULL;
size_t measurement_len = 0;
tav_snp_attestation_report_measurement(report, &measurement, &measurement_len);

tav_snp_attestation_report_free(report);
```

## CACI verification

CACI verification is staged: verify the SNP attestation and the UVM
endorsement independently, then check the relying-party policy over both
verified handles.

```c
TavSnpAttestationReport *attestation = NULL;
tav_verify_snp_attestation(report_bytes, report_len, ark_pem, ark_pem_len,
                            ask_pem, ask_pem_len, vcek_pem, vcek_pem_len,
                            &attestation);

TavCborValue *uvm = NULL;
tav_verify_caci_uvm_endorsement(uvm_bytes, uvm_len, trusted_didx509,
                                 trusted_didx509_len, &uvm);

TavByteBuffer *report_data = NULL;
TavError *error = tav_verify_caci_attestation(
    attestation,
    minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count,
    trusted_policy_digests, trusted_policy_digest_count,
    uvm, uvm_feed, uvm_feed_len, minimum_svn,
    &report_data);

tav_cbor_value_free(uvm);
tav_snp_attestation_report_free(attestation);
```

`report_data` is the verified 64-byte SNP `REPORT_DATA`; read it with
`tav_byte_buffer_data`/`tav_byte_buffer_len` and release it with
`tav_byte_buffer_free`. See `ffi/tests/c-consumer/caci.cpp` for the failure
modes and full error handling.
