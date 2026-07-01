#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Shared C ABI error codes.
 *
 * These values are mirrored by ffi-utils::TavErrorCode. Keep all public C ABI
 * error accessors returning this single type.
 */
typedef enum TavErrorCode {
    TAV_ERROR_OK = 0,
    TAV_ERROR_INVALID_ARGUMENT = 1,
    TAV_ERROR_ERROR_IS_NULL = 2,

    TAV_ERROR_UNSUPPORTED_PROCESSOR = 101,
    TAV_ERROR_INVALID_ROOT_CERTIFICATE = 102,
    TAV_ERROR_CERTIFICATE_CHAIN_ERROR = 103,
    TAV_ERROR_SIGNATURE_VERIFICATION_ERROR = 104,
    TAV_ERROR_TCB_VERIFICATION_ERROR = 105,

    TAV_ERROR_CBOR = 201,
    TAV_ERROR_UNEXPECTED_TYPE = 202,
    TAV_ERROR_UNSUPPORTED_ALGORITHM = 203,
    TAV_ERROR_KEY_IMPORT = 204,
    TAV_ERROR_VERIFICATION = 205,

    TAV_ERROR_CACI_COSE = 301,
    TAV_ERROR_CACI_CERTIFICATE = 302,
    TAV_ERROR_CACI_DID_X509 = 303,
    TAV_ERROR_CACI_SIGNATURE = 304,
    TAV_ERROR_CACI_MEASUREMENT = 305,
    TAV_ERROR_CACI_POLICY = 306,
} TavErrorCode;

typedef struct TavError TavError;

TavErrorCode tav_error_code(const TavError *error);
const char *tav_error_message(const TavError *error);
void tav_error_free(TavError *error);

/*
 * Owned byte buffer returned by public C ABI functions.
 *
 * data points to a library-owned allocation of len bytes. Release it with
 * tav_byte_buffer_free, which frees the allocation and resets the buffer to
 * { data = NULL, len = 0 }. Freeing a NULL buffer or an empty buffer is a no-op.
 */
typedef struct TavByteBuffer {
    uint8_t *data;
    size_t len;
} TavByteBuffer;

void tav_byte_buffer_free(TavByteBuffer *bytes);
