// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../c-consumer/support.h"

#include <tav/cbor.hpp>
#include <tav/cose.h>
#include <tav/snp.hpp>
#include <tav/byte_buffer.hpp>
#include <tav/errors.hpp>

#include <memory>
#include <type_traits>

namespace {

template <typename Make, typename Read, typename HasValue>
void check_handle_moves(Make make, Read read, HasValue has_value) {
    using T = decltype(make(1));
    static_assert(!std::is_copy_constructible_v<T>);
    static_assert(!std::is_copy_assignable_v<T>);
    static_assert(std::is_nothrow_move_constructible_v<T>);
    static_assert(std::is_nothrow_move_assignable_v<T>);

    auto source = make(1);
    REQUIRE(has_value(source));
    auto& alias = source;
    CHECK(&(source = std::move(alias)) == &source);
    REQUIRE(has_value(source));
    CHECK(read(source) == 1);

    auto moved = std::move(source);
    CHECK_FALSE(has_value(source));
    REQUIRE(has_value(moved));
    CHECK(read(moved) == 1);

    auto destination = make(2);
    CHECK(read(destination) == 2);
    CHECK(&(destination = std::move(moved)) == &destination);
    CHECK_FALSE(has_value(moved));
    REQUIRE(has_value(destination));
    CHECK(read(destination) == 1);

    // Moving from an empty source clears an occupied destination.
    destination = std::move(source);
    CHECK_FALSE(has_value(source));
    CHECK_FALSE(has_value(destination));
    auto empty = std::move(source);
    CHECK_FALSE(has_value(source));
    CHECK_FALSE(has_value(empty));
    CHECK(&(source = std::move(alias)) == &source);
    CHECK_FALSE(has_value(source));

    {
        auto replacement = make(3);
        source = std::move(replacement);
        CHECK_FALSE(has_value(replacement));
    }
    REQUIRE(has_value(source));
    CHECK(read(source) == 3);
}

template <typename E, typename Code, typename ReadCode>
void check_error_moves(Code first, Code second, ReadCode read_code) {
    static_assert(std::is_move_constructible_v<E>);
    static_assert(std::is_move_assignable_v<E>);
    E source(first, "first error");
    auto& alias = source;
    CHECK(&(source = std::move(alias)) == &source);
    CHECK(read_code(source) == first);
    // The standard library controls the moved-from runtime_error message.
    // Reassign before testing its contents.
    source = E(first, "first error");
    E moved(std::move(source));
    CHECK(read_code(moved) == first);
    CHECK(std::string(moved.what()) == "first error");

    E destination(second, "second error");
    destination = std::move(moved);
    CHECK(read_code(destination) == first);
    CHECK(std::string(destination.what()) == "first error");
    source = E(second, "reused error");
    CHECK(read_code(source) == second);
    CHECK(std::string(source.what()) == "reused error");
}

} // namespace

TEST_CASE("C++ moves: Report") {
    check_handle_moves(
        [](uint8_t version) {
            auto bytes = tav_test::read_file(
                "attestation/tests/test_data/milan_attestation_report.bin");
            bytes[0] = version;
            return tav::snp::Report::from_unverified_bytes(bytes);
        },
        [](const tav::snp::Report& report) { return report.version(); },
        [](const tav::snp::Report& report) { return !report.empty(); });
}

TEST_CASE("C++ moves: ByteBuffer") {
    check_handle_moves(
        [](uint8_t byte) {
            TavCborHandle* raw = nullptr;
            tav::check(tav_cbor_make_signed(byte, &raw));
            std::unique_ptr<TavCborHandle, decltype(&tav_cbor_free)> value(
                raw, tav_cbor_free);
            TavByteBuffer* buffer = nullptr;
            tav::check(tav_cbor_det_serialize(value.get(), TAV_CBOR_MAX_DEPTH, &buffer));
            return tav::ByteBuffer::adopt(buffer);
        },
        [](const tav::ByteBuffer& buffer) {
            REQUIRE(buffer.bytes().size() == 1);
            return buffer.bytes()[0];
        },
        [](const tav::ByteBuffer& buffer) { return buffer.has_value(); });
}

TEST_CASE("C++ moves: CBOR Value") {
    check_handle_moves(
        [](int value) { return tav::cbor::make_signed(value); },
        [](const tav::cbor::Value& value) { return value.as_signed(); },
        [](const tav::cbor::Value& value) { return !value.empty(); });
}

TEST_CASE("ByteBuffer: no handle has no value and exposes an empty span") {
    const tav::ByteBuffer buffer;
    CHECK_FALSE(buffer.has_value());
    CHECK(buffer.bytes().empty());
    const auto adopted = tav::ByteBuffer::adopt(nullptr);
    CHECK_FALSE(adopted.has_value());
    CHECK(adopted.bytes().empty());
}

TEST_CASE("C++ moves: Exception") {
    check_error_moves<tav::Exception>(
        tav::ErrorCode::IS_NULL, tav::ErrorCode::INVALID_ARGUMENT,
        [](const tav::Exception& error) { return error.code(); });
}
