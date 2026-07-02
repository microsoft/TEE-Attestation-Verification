#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tav/cose.h"
#include "tav/tav.h"

#define TAV_CACI_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for staged Confidential ACI attestation verification.
 *
 * Ownership and lifetime:
 * - Use tav_snp_verify_attestation from tav/tav.h to verify the SNP report and
 *   obtain an owned TAVSnpAttestationReport.
 * - tav_verify_caci_uvm_endorsement returns an owned TAVCborValue containing
 *   the verified UVM COSE/CBOR document. Inspect it with the CBOR accessors in
 *   tav/cose.h and release it with tav_cbor_value_free.
 * - tav_verify_caci_attestation writes owned bytes to a TAVCaciByteBuffer.
 *   Release them with tav_caci_byte_buffer_free.
 * - Freeing NULL owned handles and empty byte buffers is a no-op.
 * - Owned handle out-parameters (TAVCborValue **) must point to a writable slot
 *   that contains NULL on entry. If the out-parameter is NULL, or the slot is
 *   non-NULL, the call returns TAV_CACI_ERROR_INVALID_ARGUMENT and does not
 *   overwrite the slot, so an existing handle is never leaked. On success the
 *   slot is set to an owned handle. Byte-buffer out-parameters
 *   (TAVCaciByteBuffer *) are write-only: the buffer is reset to { NULL, 0 }
 *   before any fallible work.
 *
 * All public functions return NULL on success or an owned TAVCaciError on
 * failure unless documented otherwise. Inspect errors with
 * tav_caci_error_code/tav_caci_error_message, then free them with
 * tav_caci_error_free.
 */

typedef enum TAVCaciSize {
    TAV_CACI_HOST_DATA_LEN = 32,
    TAV_CACI_REPORT_DATA_LEN = 64,
    TAV_CACI_TCB_VERSION_LEN = 8,
} TAVCaciSize;

/*
 * Error codes returned by tav_caci_error_code. Codes 101-105 mirror the wrapped
 * SNP verification failures; 301-306 are CACI-policy specific.
 */
typedef enum TAVCaciErrorCode {
    TAV_CACI_ERROR_OK = 0,
    TAV_CACI_ERROR_INVALID_ARGUMENT = 1,
    TAV_CACI_ERROR_ERROR_CODE_IS_NULL = 2,

    TAV_CACI_ERROR_UNSUPPORTED_PROCESSOR = 101,
    TAV_CACI_ERROR_INVALID_ROOT_CERTIFICATE = 102,
    TAV_CACI_ERROR_CERTIFICATE_CHAIN_ERROR = 103,
    TAV_CACI_ERROR_SIGNATURE_VERIFICATION_ERROR = 104,
    TAV_CACI_ERROR_TCB_VERIFICATION_ERROR = 105,

    TAV_CACI_ERROR_COSE = 301,
    TAV_CACI_ERROR_CERTIFICATE = 302,
    TAV_CACI_ERROR_DID_X509 = 303,
    TAV_CACI_ERROR_SIGNATURE = 304,
    TAV_CACI_ERROR_MEASUREMENT = 305,
    TAV_CACI_ERROR_POLICY = 306,
} TAVCaciErrorCode;

typedef struct TAVCaciError TAVCaciError;

/*
 * Owned byte buffer returned by tav_verify_caci_attestation. data points to a
 * library-owned allocation of len bytes. Release it with
 * tav_caci_byte_buffer_free, which frees the allocation and resets the buffer
 * to { data = NULL, len = 0 }. Freeing a NULL or empty buffer is a no-op.
 */
typedef struct TAVCaciByteBuffer {
    uint8_t *data;
    size_t len;
} TAVCaciByteBuffer;

/*
 * Verify an ACI/UVM endorsement COSE blob against a caller-pinned did:x509 root.
 *
 * trusted_didx509 is a UTF-8 byte slice and does not need to be NUL-terminated.
 * out_uvm_endorsement must point to a writable handle slot that contains NULL on
 * entry; a NULL out-parameter or non-NULL slot returns
 * TAV_CACI_ERROR_INVALID_ARGUMENT without overwriting an existing handle.
 */
TAV_CACI_API TAVCaciError *tav_verify_caci_uvm_endorsement(
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
TAV_CACI_API TAVCaciError *tav_verify_caci_attestation(
    const TAVSnpAttestationReport *attestation,
    const uint32_t *minimum_tcb_cpuids,
    const uint8_t *minimum_tcb_values,
    size_t minimum_tcb_count,
    const uint8_t *trusted_policy_digests,
    size_t trusted_policy_digest_count,
    const TAVCborValue *uvm_endorsement,
    const char *uvm_feed,
    size_t uvm_feed_len,
    uint64_t minimum_svn,
    TAVCaciByteBuffer *out_report_data);

/* Error accessors. NULL error pointers return defensive diagnostics. */
TAV_CACI_API TAVCaciErrorCode tav_caci_error_code(const TAVCaciError *error);
TAV_CACI_API const char *tav_caci_error_message(const TAVCaciError *error);
TAV_CACI_API void tav_caci_error_free(TAVCaciError *error);

TAV_CACI_API void tav_caci_byte_buffer_free(TAVCaciByteBuffer *bytes);

#ifdef __cplusplus
}
#endif
