#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tav/utils.h"

#define TAV_COSE_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for CBOR parsing/navigation and COSE_Sign1 verification.
 *
 * Ownership and lifetime:
 * - tav_cbor_value_from_bytes returns an owned TAVCborValue. Release it with
 *   tav_cbor_value_free.
 * - CBOR child accessors, including array/map/tag accessors, return borrowed
 *   handles. Borrowed handles must not be freed and remain valid only while the
 *   ancestor owned TAVCborValue remains alive.
 * - Byte/text accessors return borrowed views. The returned data remains valid
 *   only while the owning or ancestor TAVCborValue remains alive.
 * - tav_cbor_value_to_bytes writes owned bytes to a TavByteBuffer. Release
 *   it with tav_byte_buffer_free.
 * - Freeing NULL owned handles is a no-op.
 * - Owned out-parameters are write-only: pass a non-NULL pointer to a handle
 *   slot. The slot is set to NULL before any fallible work and set to an owned
 *   handle only on success.
 */

typedef enum TAVCborKind {
    TAV_CBOR_KIND_INT = 1,
    TAV_CBOR_KIND_SIMPLE = 2,
    TAV_CBOR_KIND_BYTES = 3,
    TAV_CBOR_KIND_TEXT = 4,
    TAV_CBOR_KIND_ARRAY = 5,
    TAV_CBOR_KIND_MAP = 6,
    TAV_CBOR_KIND_TAGGED = 7,
} TAVCborKind;

typedef enum TAVCoseAlgorithm {
    TAV_COSE_ALG_ES256 = -7,
    TAV_COSE_ALG_ES384 = -35,
    TAV_COSE_ALG_ES512 = -36,
    TAV_COSE_ALG_PS256 = -37,
    TAV_COSE_ALG_PS384 = -38,
    TAV_COSE_ALG_PS512 = -39,
} TAVCoseAlgorithm;

typedef enum TAVCoseTag {
    TAV_COSE_TAG_SIGN1 = 18,
} TAVCoseTag;

typedef enum TAVCoseSign1Field {
    TAV_COSE_SIGN1_PROTECTED = 0,
    TAV_COSE_SIGN1_UNPROTECTED = 1,
    TAV_COSE_SIGN1_PAYLOAD = 2,
    TAV_COSE_SIGN1_SIGNATURE = 3,
} TAVCoseSign1Field;

typedef enum TAVCoseHeaderLabel {
    TAV_COSE_HEADER_ALG = 1,
    TAV_COSE_HEADER_CWT_CLAIMS = 15,
    TAV_COSE_HEADER_X5CHAIN = 33,
    TAV_COSE_HEADER_CONTENT_TYPE = 3,
    TAV_COSE_HEADER_PREIMAGE_CONTENT_TYPE = 259,
} TAVCoseHeaderLabel;

typedef enum TAVCwtClaim {
    TAV_CWT_CLAIMS_ISSUER = 1,
    TAV_CWT_CLAIMS_SUBJECT = 2,
    TAV_CWT_CLAIMS_IAT = 6,
} TAVCwtClaim;

typedef struct TAVCborValue TAVCborValue;

TAV_COSE_API TavError *tav_cbor_value_from_bytes(
    const uint8_t *bytes,
    size_t len,
    TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_to_bytes(
    const TAVCborValue *value,
    TavByteBuffer *out_bytes);

/* value must be a valid, non-NULL TAVCborValue handle. */
TAV_COSE_API TAVCborKind tav_cbor_value_kind(const TAVCborValue *value);

TAV_COSE_API TavError *tav_cbor_value_int(
    const TAVCborValue *value,
    int64_t *out);

TAV_COSE_API TavError *tav_cbor_value_simple(
    const TAVCborValue *value,
    uint8_t *out);

TAV_COSE_API TavError *tav_cbor_value_bytes(
    const TAVCborValue *value,
    const uint8_t **data,
    size_t *len);

TAV_COSE_API TavError *tav_cbor_value_text(
    const TAVCborValue *value,
    const char **text,
    size_t *len);

TAV_COSE_API TavError *tav_cbor_value_tag(
    const TAVCborValue *value,
    uint64_t *out);

TAV_COSE_API TavError *tav_cbor_value_tagged_payload(
    const TAVCborValue *value,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_len(
    const TAVCborValue *value,
    size_t *out);

TAV_COSE_API TavError *tav_cbor_value_array_at(
    const TAVCborValue *value,
    size_t index,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at_int(
    const TAVCborValue *value,
    int64_t key,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at_text(
    const TAVCborValue *value,
    const char *key,
    size_t key_len,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_at(
    const TAVCborValue *value,
    const TAVCborValue *key,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_cbor_value_map_has_int_key(
    const TAVCborValue *value,
    int64_t key,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_has_text_key(
    const TAVCborValue *value,
    const char *key,
    size_t key_len,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_has_key(
    const TAVCborValue *value,
    const TAVCborValue *key,
    bool *out);

TAV_COSE_API TavError *tav_cbor_value_map_entry_at(
    const TAVCborValue *value,
    size_t index,
    const TAVCborValue **out_key,
    const TAVCborValue **out_value);

TAV_COSE_API TavError *tav_validate_cose_sign1(
    const TAVCborValue *value,
    const TAVCborValue **out_sign1);

TAV_COSE_API void tav_cbor_value_free(TAVCborValue *value);

TAV_COSE_API TavError *tav_verify_cose_sign1_embedded(
    const TAVCborValue *sign1,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

TAV_COSE_API TavError *tav_verify_cose_sign1_detached(
    const TAVCborValue *sign1,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *spki_der,
    size_t spki_der_len,
    int32_t cose_alg);

#ifdef __cplusplus
}
#endif
