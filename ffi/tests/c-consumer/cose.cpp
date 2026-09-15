// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "support.h"

#include <cstring>

namespace {

// COSE P-256 verification-only vector, mirrored from the Rust and managed tests.
const std::vector<uint8_t> kPhdr = {0xa1, 0x01, 0x26};
const std::string kPayload = "verification-only COSE vector";
const std::vector<uint8_t> kSpki = {
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
    3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
    177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
    85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
    167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
    205};
const std::vector<uint8_t> kSig = {
    90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
    248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
    210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
    103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151};

void put_bstr(std::vector<uint8_t> &out, const uint8_t *data, size_t len) {
    if (len < 24) {
        out.push_back(static_cast<uint8_t>(0x40 | len));
    } else {
        out.push_back(0x58);
        out.push_back(static_cast<uint8_t>(len));
    }
    out.insert(out.end(), data, data + len);
}

std::vector<uint8_t> build_sign1(bool embedded_payload) {
    std::vector<uint8_t> env = {0xd2, 0x84};
    put_bstr(env, kPhdr.data(), kPhdr.size());
    env.push_back(0xa0);
    if (embedded_payload) {
        put_bstr(env, reinterpret_cast<const uint8_t *>(kPayload.data()), kPayload.size());
    } else {
        env.push_back(0xf6);
    }
    put_bstr(env, kSig.data(), kSig.size());
    return env;
}

struct CborHandle {
    TavCborHandle *value = nullptr;
    CborHandle() = default;
    CborHandle(const CborHandle &) = delete;
    CborHandle &operator=(const CborHandle &) = delete;
    ~CborHandle() { tav_cbor_free(value); }
    TavCborHandle **out() {
        tav_cbor_free(value);
        value = nullptr;
        return &value;
    }
};

void check_error(TavError *error, TavErrorCode code) {
    REQUIRE(error != nullptr);
    CHECK(tav_error_code(error) == code);
    CHECK(std::strlen(tav_error_message(error)) > 0);
    tav_error_free(error);
}

} // namespace

TEST_CASE("cbor: map keys compare independently of entry order") {
    const uint8_t encoded[] = {0xa1, 0xa2, 1, 2, 3, 4, 7};
    const uint8_t reordered[] = {0xa2, 3, 4, 1, 2};
    CborHandle root, key, found;
    REQUIRE(tav_cbor_nondet_parse(encoded, sizeof(encoded), 64, root.out()) == nullptr);
    REQUIRE(tav_cbor_nondet_parse(reordered, sizeof(reordered), 64, key.out()) == nullptr);
    REQUIRE(tav_cbor_map_at(root.value, key.value, found.out()) == nullptr);
    root.out();
    int64_t number = 0;
    REQUIRE(tav_cbor_as_signed(found.value, &number) == nullptr);
    CHECK(number == 7);
}

TEST_CASE("cbor: deep copies own input and projected views survive parents") {
    std::vector<uint8_t> input = {0x81, 0x42, 0xaa, 0xbb};
    CborHandle borrowed, owned, borrowed_child, owned_child;
    REQUIRE(tav_cbor_nondet_parse(input.data(), input.size(), 64, borrowed.out()) == nullptr);
    REQUIRE(tav_cbor_deep_copy(borrowed.value, owned.out()) == nullptr);
    REQUIRE(tav_cbor_array_at(borrowed.value, 0, borrowed_child.out()) == nullptr);
    REQUIRE(tav_cbor_array_at(owned.value, 0, owned_child.out()) == nullptr);
    const uint8_t *data = nullptr;
    size_t len = 0;
    REQUIRE(tav_cbor_as_bytes(borrowed_child.value, &data, &len) == nullptr);
    CHECK(data == input.data() + 2);
    CHECK(len == 2);
    borrowed.out();
    borrowed_child.out();
    input.assign(input.size(), 0);
    owned.out();
    REQUIRE(tav_cbor_as_bytes(owned_child.value, &data, &len) == nullptr);
    CHECK(len == 2);
    CHECK(data[0] == 0xaa);
    CHECK(data[1] == 0xbb);
}

TEST_CASE("cbor: nested array projections outlive parent handles") {
    const uint8_t input[] = {0x82, 0x01, 0x81, 0x18, 0x2a};
    CborHandle root, scalar, array, nested;
    REQUIRE(tav_cbor_nondet_parse(input, sizeof(input), 64, root.out()) == nullptr);
    REQUIRE(tav_cbor_array_at(root.value, 0, scalar.out()) == nullptr);
    REQUIRE(tav_cbor_array_at(root.value, 1, array.out()) == nullptr);
    REQUIRE(tav_cbor_array_at(array.value, 0, nested.out()) == nullptr);
    CHECK(tav_cbor_kind(scalar.value) == TAV_CBOR_HANDLE_KIND_SIGNED);
    size_t len = 0;
    REQUIRE(tav_cbor_size(root.value, &len) == nullptr);
    CHECK(len == 2);
    root.out();
    array.out();
    int64_t number = 0;
    REQUIRE(tav_cbor_as_signed(scalar.value, &number) == nullptr);
    CHECK(number == 1);
    REQUIRE(tav_cbor_as_signed(nested.value, &number) == nullptr);
    CHECK(number == 42);
    tav_cbor_free(nullptr);
}

TEST_CASE("cbor: map lookup supports constructed and projected keys") {
    const uint8_t input[] = {0xa3, 1, 0x63, 'o', 'n', 'e', 0x63, 'k', 'e', 'y',
                             0x18, 0x2a, 0x41, 0xaa, 0xf5};
    CborHandle root, key, value;
    REQUIRE(tav_cbor_nondet_parse(input, sizeof(input), 64, root.out()) == nullptr);
    size_t len = 0;
    REQUIRE(tav_cbor_size(root.value, &len) == nullptr);
    CHECK(len == 3);
    REQUIRE(tav_cbor_make_signed(1, key.out()) == nullptr);
    REQUIRE(tav_cbor_map_at(root.value, key.value, value.out()) == nullptr);
    const char *text = nullptr;
    REQUIRE(tav_cbor_as_string(value.value, &text, &len) == nullptr);
    CHECK(std::string(text, len) == "one");
    REQUIRE(tav_cbor_make_string("key", 3, key.out()) == nullptr);
    REQUIRE(tav_cbor_map_at(root.value, key.value, value.out()) == nullptr);
    int64_t number = 0;
    REQUIRE(tav_cbor_as_signed(value.value, &number) == nullptr);
    CHECK(number == 42);
    const uint8_t key_data[] = {0xaa};
    REQUIRE(tav_cbor_make_bytes(key_data, sizeof(key_data), key.out()) == nullptr);
    REQUIRE(tav_cbor_map_at(root.value, key.value, value.out()) == nullptr);
    CHECK(tav_cbor_kind(value.value) == TAV_CBOR_HANDLE_KIND_SIMPLE);
    uint8_t simple = 0;
    REQUIRE(tav_cbor_as_simple(value.value, &simple) == nullptr);
    CHECK(simple == 21);
    REQUIRE(tav_cbor_map_key_at(root.value, 0, key.out()) == nullptr);
    REQUIRE(tav_cbor_map_value_at(root.value, 0, value.out()) == nullptr);
    REQUIRE(tav_cbor_as_signed(key.value, &number) == nullptr);
    CHECK(number == 1);
    REQUIRE(tav_cbor_as_string(value.value, &text, &len) == nullptr);
    CHECK(std::string(text, len) == "one");
    REQUIRE(tav_cbor_make_signed(2, key.out()) == nullptr);
    check_error(tav_cbor_map_at(root.value, key.value, value.out()), TAV_ERROR_CBOR_KEY_NOT_FOUND);
    CHECK(value.value == nullptr);
    REQUIRE(tav_cbor_make_string("nope", 4, key.out()) == nullptr);
    check_error(tav_cbor_map_at(root.value, key.value, value.out()), TAV_ERROR_CBOR_KEY_NOT_FOUND);
    CHECK(value.value == nullptr);
    check_error(tav_cbor_map_key_at(root.value, 99, key.out()), TAV_ERROR_CBOR_OUT_OF_BOUND);
    check_error(tav_cbor_map_value_at(root.value, 99, value.out()), TAV_ERROR_CBOR_OUT_OF_BOUND);
    CHECK(key.value == nullptr);
    CHECK(value.value == nullptr);
}

TEST_CASE("cbor: failed reads preserve scalars and borrowed views but clear owned slots") {
    CborHandle value;
    REQUIRE(tav_cbor_make_signed(1, value.out()) == nullptr);
    int64_t scalar = INT64_MAX;
    check_error(tav_cbor_as_signed(nullptr, &scalar), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(scalar == INT64_MAX);
    check_error(tav_cbor_as_signed(value.value, nullptr), TAV_ERROR_CBOR_TYPE_MISMATCH);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(0x1);
    const char *text = reinterpret_cast<const char *>(0x1);
    size_t len = SIZE_MAX;
    check_error(tav_cbor_as_bytes(value.value, &bytes, &len), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(bytes == reinterpret_cast<const uint8_t *>(0x1));
    CHECK(len == SIZE_MAX);
    check_error(tav_cbor_as_string(value.value, &text, &len), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(text == reinterpret_cast<const char *>(0x1));
    CHECK(len == SIZE_MAX);
    check_error(tav_cbor_size(value.value, &len), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(len == SIZE_MAX);
    uint8_t simple = 0xff;
    check_error(tav_cbor_as_simple(value.value, &simple), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(simple == 0xff);
    uint64_t tag = 7;
    check_error(tav_cbor_as_tag(value.value, &tag), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(tag == 7);
    TavCborHandle *out = value.value;
    check_error(tav_cbor_array_at(value.value, 0, &out), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(out == nullptr);
    out = value.value;
    check_error(tav_cbor_map_key_at(value.value, 0, &out), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(out == nullptr);
    out = value.value;
    check_error(tav_cbor_map_value_at(value.value, 0, &out), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(out == nullptr);
    check_error(tav_cbor_tag_at(value.value, 18, &out), TAV_ERROR_CBOR_TYPE_MISMATCH);
    CHECK(out == nullptr);
    check_error(tav_cbor_nondet_parse(nullptr, 0, 64, &out), TAV_ERROR_CBOR_DECODE_FAILED);
    CHECK(out == nullptr);
    check_error(tav_cbor_nondet_parse(nullptr, 1, 64, &out), TAV_ERROR_CBOR_DECODE_FAILED);
    const uint8_t trailing[] = {1, 2};
    check_error(tav_cbor_nondet_parse(trailing, sizeof(trailing), 64, &out), TAV_ERROR_CBOR_DECODE_FAILED);
    CHECK(out == nullptr);
}

TEST_CASE("cbor: parsing and owned serialization enforce the requested depth") {
    for (size_t depth : {64u, 65u}) {
        std::vector<uint8_t> input(depth, 0x81);
        input.push_back(0);
        CborHandle root;
        TavError *error = tav_cbor_nondet_parse(input.data(), input.size(), 64, root.out());
        if (depth == 64) {
            REQUIRE(error == nullptr);
        } else {
            check_error(error, TAV_ERROR_CBOR_DECODE_FAILED);
            CHECK(root.value == nullptr);
        }
        REQUIRE(tav_cbor_nondet_parse(input.data(), input.size(), 65, root.out()) == nullptr);
        TavByteBuffer *bytes = reinterpret_cast<TavByteBuffer *>(0x1);
        error = tav_cbor_det_serialize(root.value, 64, &bytes);
        if (depth == 64) {
            REQUIRE(error == nullptr);
            CHECK(tav_byte_buffer_len(bytes) == input.size());
            CHECK(std::memcmp(tav_byte_buffer_data(bytes), input.data(), input.size()) == 0);
        } else {
            check_error(error, TAV_ERROR_CBOR_ENCODE_FAILED);
            CHECK(bytes == nullptr);
        }
        tav_byte_buffer_free(bytes);
        REQUIRE(tav_cbor_det_serialize(root.value, 65, &bytes) == nullptr);
        CHECK(tav_byte_buffer_len(bytes) == input.size());
        CHECK(std::memcmp(tav_byte_buffer_data(bytes), input.data(), input.size()) == 0);
        tav_byte_buffer_free(bytes);
    }
}

TEST_CASE("cose: tag projection and validation preserve independently owned views") {
    const auto env = build_sign1(true);
    CborHandle root, payload, sign1;
    REQUIRE(tav_cbor_nondet_parse(env.data(), env.size(), 64, root.out()) == nullptr);
    uint64_t tag = 0;
    REQUIRE(tav_cbor_as_tag(root.value, &tag) == nullptr);
    CHECK(tag == TAV_COSE_TAG_SIGN1);
    REQUIRE(tav_cbor_tag_at(root.value, tag, payload.out()) == nullptr);
    size_t len = 0;
    REQUIRE(tav_cbor_size(payload.value, &len) == nullptr);
    CHECK(len == 4);
    REQUIRE(tav_validate_cose_sign1(root.value, sign1.out()) == nullptr);
    CHECK(tav_cbor_kind(sign1.value) == TAV_CBOR_HANDLE_KIND_ARRAY);
    root.out();
    payload.out();
    REQUIRE(tav_verify_cose_sign1_embedded(sign1.value, kSpki.data(), kSpki.size(),
                                          TAV_COSE_ALG_ES256) == nullptr);
}

TEST_CASE("cose: deep-copied validated values no longer borrow input") {
    auto env = build_sign1(true);
    CborHandle borrowed, owned, sign1;
    REQUIRE(tav_cbor_nondet_parse(env.data(), env.size(), 64, borrowed.out()) == nullptr);
    REQUIRE(tav_cbor_deep_copy(borrowed.value, owned.out()) == nullptr);
    borrowed.out();
    env.assign(env.size(), 0);
    REQUIRE(tav_validate_cose_sign1(owned.value, sign1.out()) == nullptr);
    owned.out();
    REQUIRE(tav_verify_cose_sign1_embedded(sign1.value, kSpki.data(), kSpki.size(),
                                          TAV_COSE_ALG_ES256) == nullptr);
}

TEST_CASE("cose: embedded verification rejects tampered signatures") {
    auto env = build_sign1(true);
    env.back() ^= 0xff;
    CborHandle root, sign1;
    REQUIRE(tav_cbor_nondet_parse(env.data(), env.size(), 64, root.out()) == nullptr);
    REQUIRE(tav_validate_cose_sign1(root.value, sign1.out()) == nullptr);
    check_error(tav_verify_cose_sign1_embedded(sign1.value, kSpki.data(), kSpki.size(),
                                              TAV_COSE_ALG_ES256), TAV_ERROR_COSE_VERIFICATION);
}

TEST_CASE("cose: detached verification requires a nil payload") {
    for (bool embedded : {true, false}) {
        const auto env = build_sign1(embedded);
        CborHandle root, sign1;
        REQUIRE(tav_cbor_nondet_parse(env.data(), env.size(), 64, root.out()) == nullptr);
        REQUIRE(tav_validate_cose_sign1(root.value, sign1.out()) == nullptr);
        TavError *error = tav_verify_cose_sign1_detached(
            sign1.value, reinterpret_cast<const uint8_t *>(kPayload.data()), kPayload.size(),
            kSpki.data(), kSpki.size(), TAV_COSE_ALG_ES256);
        if (embedded) {
            REQUIRE(error != nullptr);
            CHECK(std::string(tav_error_message(error)).find("requires nil COSE payload") != std::string::npos);
            check_error(error, TAV_ERROR_COSE_UNEXPECTED_TYPE);
        } else {
            REQUIRE(error == nullptr);
            check_error(tav_verify_cose_sign1_embedded(sign1.value, kSpki.data(), kSpki.size(),
                                                      TAV_COSE_ALG_ES256), TAV_ERROR_COSE_UNEXPECTED_TYPE);
        }
    }
}

TEST_CASE("cose: validation resets output on null and malformed inputs") {
    CborHandle value;
    REQUIRE(tav_cbor_make_signed(1, value.out()) == nullptr);
    TavCborHandle *out = value.value;
    check_error(tav_validate_cose_sign1(nullptr, &out), TAV_ERROR_INVALID_ARGUMENT);
    CHECK(out == nullptr);
    out = value.value;
    check_error(tav_validate_cose_sign1(value.value, &out), TAV_ERROR_COSE_CBOR);
    CHECK(out == nullptr);
    check_error(tav_validate_cose_sign1(value.value, nullptr), TAV_ERROR_INVALID_ARGUMENT);
}
