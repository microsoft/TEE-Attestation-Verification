#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tav/cose.h"
#include "tav/tee.h"

#define TAV_CACI_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for staged Confidential ACI attestation verification.
 *
 * Ownership and lifetime:
 * - Use tav_verify_snp_attestation from tav/tee.h to verify the SNP report and
 *   obtain an owned TavSnpAttestationReport.
 * - tav_verify_caci_uvm_endorsement returns an owned TAVCborValue containing
 *   the verified UVM COSE/CBOR document. Inspect it with the CBOR accessors in
 *   tav/cose.h and release it with tav_cbor_value_free.
 * - tav_verify_caci_attestation writes owned bytes to a
 *   TavByteBuffer. Release them with tav_byte_buffer_free.
 * - Freeing NULL owned handles and empty byte buffers is a no-op.
 * - Owned handle out-parameters (TAVCborValue **) must point to a writable slot
 *   that contains NULL on entry. If the out-parameter is NULL, or the slot is
 *   non-NULL, the call returns TAV_ERROR_INVALID_ARGUMENT and does not overwrite
 *   the slot, so an existing handle is never leaked. On success the slot is set
 *   to an owned handle. Byte-buffer out-parameters (TavByteBuffer *) are
 *   write-only: the buffer is reset to { NULL, 0 } before any fallible work.
 *
 * All public functions return NULL on success or an owned TavError on
 * failure unless documented otherwise. Inspect errors with
 * tav_error_code/tav_error_message, then free them with tav_error_free.
 */

typedef enum TavCaciSize {
    TAV_CACI_HOST_DATA_LEN = 32,
    TAV_CACI_REPORT_DATA_LEN = 64,
    TAV_CACI_TCB_VERSION_LEN = 8,
} TavCaciSize;

/*
 * Verify an ACI/UVM endorsement COSE blob against a caller-pinned did:x509 root.
 *
 * trusted_didx509 is a UTF-8 byte slice and does not need to be NUL-terminated.
 * out_uvm_endorsement must point to a writable handle slot that contains NULL on
 * entry; a NULL out-parameter or non-NULL slot returns
 * TAV_ERROR_INVALID_ARGUMENT without overwriting an existing handle.
 */
TAV_CACI_API TavError *tav_verify_caci_uvm_endorsement(
    const uint8_t *uvm_endorsement,
    size_t uvm_endorsement_len,
    const char *trusted_didx509,
    size_t trusted_didx509_len,
    TAVCborValue **out_uvm_endorsement);

/*
 * Verify the relying-party CACI policy over staged verified artifacts.
 *
 * The minimum TCB policy is passed as two parallel arrays of minimum_tcb_count
 * entries: minimum_tcb_cpuids holds one uint32_t CPUID per entry, and
 * minimum_tcb_values holds minimum_tcb_count contiguous TAV_CACI_TCB_VERSION_LEN
 * byte TCB values. Both pointers may be NULL only when minimum_tcb_count is zero.
 *
 * trusted_policy_digests points to trusted_policy_digest_count contiguous
 * TAV_CACI_HOST_DATA_LEN-byte SHA-256 policy digests. At least one digest is
 * required. uvm_feed is a UTF-8 byte slice and does not need to be
 * NUL-terminated.
 */
TAV_CACI_API TavError *tav_verify_caci_attestation(
    const TavSnpAttestationReport *attestation,
    const uint32_t *minimum_tcb_cpuids,
    const uint8_t *minimum_tcb_values,
    size_t minimum_tcb_count,
    const uint8_t *trusted_policy_digests,
    size_t trusted_policy_digest_count,
    const TAVCborValue *uvm_endorsement,
    const char *uvm_feed,
    size_t uvm_feed_len,
    uint64_t minimum_svn,
    TavByteBuffer *out_report_data);

#ifdef __cplusplus
}
#endif
