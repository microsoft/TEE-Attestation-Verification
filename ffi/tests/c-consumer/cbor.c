// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <tav/cbor.h>
#include <tav/cose.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        abort(); \
    } \
} while (0)

static void expect(TavError* error, TavErrorCode code)
{
    if (code == TAV_ERROR_OK) {
        CHECK(error == NULL);
    } else {
        CHECK(error != NULL);
        CHECK(tav_error_code(error) == code);
        CHECK(strlen(tav_error_message(error)) > 0);
    }
    tav_error_free(error);
}

static void expect_bytes(const TavByteBuffer* buffer, const uint8_t* bytes, size_t len)
{
    CHECK(buffer != NULL);
    CHECK(tav_byte_buffer_len(buffer) == len);
    CHECK(memcmp(tav_byte_buffer_data(buffer), bytes, len) == 0);
}

static void scalars_and_copies(void)
{
    TavCborHandle* value = NULL;
    int64_t integer = 0;
    uint8_t simple = 0;
    expect(tav_cbor_make_signed(INT64_MIN, &value), TAV_ERROR_OK);
    CHECK(tav_cbor_kind(value) == TAV_CBOR_HANDLE_KIND_SIGNED);
    expect(tav_cbor_as_signed(value, &integer), TAV_ERROR_OK);
    CHECK(integer == INT64_MIN);
    expect(tav_cbor_as_simple(value, &simple), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(simple == 0);
    tav_cbor_free(value);

    expect(tav_cbor_make_simple(22, &value), TAV_ERROR_OK);
    CHECK(tav_cbor_kind(value) == TAV_CBOR_HANDLE_KIND_SIMPLE);
    expect(tav_cbor_as_simple(value, &simple), TAV_ERROR_OK);
    CHECK(simple == 22);
    tav_cbor_free(value);
    expect(tav_cbor_make_simple(24, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL);

    const uint8_t payload[] = {1, 2, 3};
    const uint8_t* bytes = NULL;
    size_t len = 0;
    expect(tav_cbor_make_bytes(payload, sizeof(payload), &value), TAV_ERROR_OK);
    CHECK(tav_cbor_kind(value) == TAV_CBOR_HANDLE_KIND_BYTES);
    expect(tav_cbor_as_bytes(value, &bytes, &len), TAV_ERROR_OK);
    CHECK(bytes == payload && len == sizeof(payload));
    TavCborHandle* shallow = NULL;
    TavCborHandle* deep = NULL;
    expect(tav_cbor_shallow_copy(value, &shallow), TAV_ERROR_OK);
    expect(tav_cbor_deep_copy(value, &deep), TAV_ERROR_OK);
    tav_cbor_free(value);
    expect(tav_cbor_as_bytes(shallow, &bytes, &len), TAV_ERROR_OK);
    CHECK(bytes == payload && len == sizeof(payload));
    expect(tav_cbor_as_bytes(deep, &bytes, &len), TAV_ERROR_OK);
    CHECK(bytes != payload && len == sizeof(payload));
    CHECK(memcmp(bytes, payload, len) == 0);
    tav_cbor_free(shallow);
    tav_cbor_free(deep);

    const char text[] = "hi";
    const char* string = NULL;
    expect(tav_cbor_make_string(text, 2, &value), TAV_ERROR_OK);
    CHECK(tav_cbor_kind(value) == TAV_CBOR_HANDLE_KIND_STRING);
    expect(tav_cbor_as_string(value, &string, &len), TAV_ERROR_OK);
    CHECK(string == text && len == 2);
    tav_cbor_free(value);
    expect(tav_cbor_make_string("\xff", 1, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL);
    expect(tav_cbor_make_bytes(NULL, 0, &value), TAV_ERROR_OK);
    expect(tav_cbor_as_bytes(value, &bytes, &len), TAV_ERROR_OK);
    CHECK(len == 0);
    tav_cbor_free(value);
}

static void containers_and_navigation(void)
{
    TavCborHandle* items[2] = {NULL, NULL};
    TavCborHandle* array = NULL;
    expect(tav_cbor_make_signed(1, &items[0]), TAV_ERROR_OK);
    expect(tav_cbor_make_signed(2, &items[1]), TAV_ERROR_OK);
    expect(tav_cbor_make_array(items, 2, &array), TAV_ERROR_OK);
    CHECK(items[0] == NULL && items[1] == NULL);
    CHECK(tav_cbor_kind(array) == TAV_CBOR_HANDLE_KIND_ARRAY);
    size_t size = 0;
    expect(tav_cbor_size(array, &size), TAV_ERROR_OK);
    CHECK(size == 2);
    TavCborHandle* child = NULL;
    expect(tav_cbor_array_at(array, 2, &child), TAV_ERROR_CBOR_OUT_OF_BOUND);
    CHECK(child == NULL);
    expect(tav_cbor_array_at(array, 1, &child), TAV_ERROR_OK);
    tav_cbor_free(array);
    int64_t integer = 0;
    expect(tav_cbor_as_signed(child, &integer), TAV_ERROR_OK);
    CHECK(integer == 2);

    TavCborHandle* tagged = NULL;
    expect(tav_cbor_make_tagged(18, &child, &tagged), TAV_ERROR_OK);
    CHECK(child == NULL);
    CHECK(tav_cbor_kind(tagged) == TAV_CBOR_HANDLE_KIND_TAGGED);
    uint64_t tag = 0;
    expect(tav_cbor_as_tag(tagged, &tag), TAV_ERROR_OK);
    CHECK(tag == 18);
    expect(tav_cbor_tag_at(tagged, 19, &child), TAV_ERROR_CBOR_KEY_NOT_FOUND);
    CHECK(child == NULL);
    expect(tav_cbor_tag_at(tagged, 18, &child), TAV_ERROR_OK);
    tav_cbor_free(tagged);
    expect(tav_cbor_as_signed(child, &integer), TAV_ERROR_OK);
    CHECK(integer == 2);
    tav_cbor_free(child);

    TavCborHandle* pairs[2] = {NULL, NULL};
    TavCborHandle* map = NULL;
    TavCborHandle* key = NULL;
    expect(tav_cbor_make_signed(7, &pairs[0]), TAV_ERROR_OK);
    expect(tav_cbor_make_signed(9, &pairs[1]), TAV_ERROR_OK);
    expect(tav_cbor_make_map(pairs, 1, &map), TAV_ERROR_OK);
    CHECK(pairs[0] == NULL && pairs[1] == NULL);
    CHECK(tav_cbor_kind(map) == TAV_CBOR_HANDLE_KIND_MAP);
    expect(tav_cbor_size(map, &size), TAV_ERROR_OK);
    CHECK(size == 1);
    expect(tav_cbor_map_key_at(map, 0, &key), TAV_ERROR_OK);
    expect(tav_cbor_as_signed(key, &integer), TAV_ERROR_OK);
    CHECK(integer == 7);
    expect(tav_cbor_map_at(map, key, &child), TAV_ERROR_OK);
    expect(tav_cbor_as_signed(child, &integer), TAV_ERROR_OK);
    CHECK(integer == 9);
    tav_cbor_free(child);
    expect(tav_cbor_map_value_at(map, 0, &child), TAV_ERROR_OK);
    expect(tav_cbor_as_signed(child, &integer), TAV_ERROR_OK);
    CHECK(integer == 9);
    tav_cbor_free(child);
    expect(tav_cbor_map_key_at(map, 1, &child), TAV_ERROR_CBOR_OUT_OF_BOUND);
    CHECK(child == NULL);
    expect(tav_cbor_map_value_at(map, 1, &child), TAV_ERROR_CBOR_OUT_OF_BOUND);
    CHECK(child == NULL);
    tav_cbor_free(key);
    expect(tav_cbor_make_signed(8, &key), TAV_ERROR_OK);
    expect(tav_cbor_map_at(map, key, &child), TAV_ERROR_CBOR_KEY_NOT_FOUND);
    CHECK(child == NULL);
    tav_cbor_free(key);
    tav_cbor_free(map);
}

static void parsing_and_serialization(void)
{
    typedef TavError* (*Parser)(const uint8_t*, size_t, size_t, TavCborHandle**);
    typedef TavError* (*Encoder)(const TavCborHandle*, size_t, TavByteBuffer**);
    const Parser parsers[] = {tav_cbor_nondet_parse, tav_cbor_det_parse};
    const Encoder encoders[] = {tav_cbor_nondet_serialize, tav_cbor_det_serialize};
    const uint8_t document[] = {0x81, 0x42, 1, 2};
    for (size_t i = 0; i < 2; ++i) {
        TavCborHandle* value = NULL;
        TavCborHandle* child = NULL;
        TavByteBuffer* encoded = NULL;
        expect(parsers[i](document, sizeof(document), TAV_CBOR_MAX_DEPTH, &value), TAV_ERROR_OK);
        expect(tav_cbor_array_at(value, 0, &child), TAV_ERROR_OK);
        const uint8_t* bytes = NULL;
        size_t len = 0;
        expect(tav_cbor_as_bytes(child, &bytes, &len), TAV_ERROR_OK);
        CHECK(bytes == document + 2 && len == 2);
        expect(encoders[i](value, TAV_CBOR_MAX_DEPTH, &encoded), TAV_ERROR_OK);
        expect_bytes(encoded, document, sizeof(document));
        tav_cbor_free(value);
        tav_cbor_free(child);
        expect_bytes(encoded, document, sizeof(document));
        tav_byte_buffer_free(encoded);
        expect(encoders[i](NULL, 16, &encoded), TAV_ERROR_CBOR_ENCODE_FAILED);
        CHECK(encoded == NULL);
        expect(encoders[i](NULL, 16, NULL), TAV_ERROR_INVALID_ARGUMENT);
        expect(parsers[i](document, sizeof(document), 0, &value), TAV_ERROR_CBOR_DECODE_FAILED);
        CHECK(value == NULL);
        expect(parsers[i](NULL, 1, 16, &value), TAV_ERROR_CBOR_DECODE_FAILED);
        CHECK(value == NULL);
        expect(parsers[i](document, sizeof(document), 16, NULL), TAV_ERROR_INVALID_ARGUMENT);
    }
    /* Deterministic parsing rejects an unnecessarily long integer encoding. */
    const uint8_t noncanonical[] = {0x18, 0x01};
    TavCborHandle* value = NULL;
    expect(tav_cbor_det_parse(noncanonical, 2, 16, &value), TAV_ERROR_CBOR_DECODE_FAILED);
    CHECK(value == NULL);
    expect(tav_cbor_nondet_parse(noncanonical, 2, 16, &value), TAV_ERROR_OK);
    tav_cbor_free(value);
}

static void nulls_and_rejected_batches(void)
{
    CHECK(tav_cbor_kind(NULL) == TAV_CBOR_HANDLE_KIND_INVALID);
    tav_cbor_free(NULL);
    tav_byte_buffer_free(NULL);
    tav_error_free(NULL);
    TavCborHandle* value = NULL;
    expect(tav_cbor_make_signed(1, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_simple(22, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_bytes(NULL, 0, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_string(NULL, 0, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_shallow_copy(NULL, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL);
    expect(tav_cbor_deep_copy(NULL, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL);
    expect(tav_cbor_shallow_copy(NULL, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_deep_copy(NULL, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_bytes(NULL, 1, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    expect(tav_cbor_make_string(NULL, 1, &value), TAV_ERROR_CBOR_ENCODE_FAILED);

    TavCborHandle* input = NULL;
    expect(tav_cbor_make_signed(1, &input), TAV_ERROR_OK);
    TavCborHandle* duplicates[] = {input, input};
    expect(tav_cbor_make_array(duplicates, 2, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL && duplicates[0] == input && duplicates[1] == input);
    expect(tav_cbor_make_map(duplicates, 1, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL && duplicates[0] == input && duplicates[1] == input);
    expect(tav_cbor_make_array(&input, 1, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_map(duplicates, 1, NULL), TAV_ERROR_INVALID_ARGUMENT);
    expect(tav_cbor_make_tagged(1, &input, NULL), TAV_ERROR_INVALID_ARGUMENT);
    CHECK(input != NULL);
    expect(tav_cbor_make_tagged(1, NULL, &value), TAV_ERROR_CBOR_ENCODE_FAILED);
    CHECK(value == NULL);

    expect(tav_cbor_as_signed(input, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_as_simple(input, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_as_bytes(input, NULL, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_as_string(input, NULL, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_as_tag(input, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_size(input, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_array_at(input, 0, &value), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(value == NULL);
    expect(tav_cbor_map_at(input, input, &value), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(value == NULL);
    expect(tav_cbor_tag_at(input, 1, &value), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(value == NULL);
    expect(tav_cbor_map_key_at(input, 0, &value), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(value == NULL);
    expect(tav_cbor_map_value_at(input, 0, &value), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(value == NULL);
    expect(tav_cbor_array_at(input, 0, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_map_at(input, input, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_tag_at(input, 1, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_map_key_at(input, 0, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    expect(tav_cbor_map_value_at(input, 0, NULL), TAV_ERROR_CBOR_TYPE_MISMATCH);
    tav_cbor_free(input);
}

static void cose_interoperability(void)
{
    const uint8_t input[] = {0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x40};
    TavCborHandle* root = NULL;
    TavCborHandle* sign1 = NULL;
    TavCborHandle* payload = NULL;
    size_t size = 0;
    expect(tav_cbor_nondet_parse(input, sizeof(input), 64, &root), TAV_ERROR_OK);
    expect(tav_validate_cose_sign1(root, &sign1), TAV_ERROR_OK);
    tav_cbor_free(root);
    expect(tav_cbor_size(sign1, &size), TAV_ERROR_OK);
    CHECK(size == 4);
    expect(tav_cbor_array_at(sign1, 2, &payload), TAV_ERROR_OK);
    tav_cbor_free(sign1);
    const uint8_t* data = NULL;
    expect(tav_cbor_as_bytes(payload, &data, &size), TAV_ERROR_OK);
    CHECK(size == 0);
    tav_cbor_free(payload);
}

int main(void)
{
    scalars_and_copies();
    containers_and_navigation();
    parsing_and_serialization();
    nulls_and_rejected_batches();
    cose_interoperability();
    return 0;
}
