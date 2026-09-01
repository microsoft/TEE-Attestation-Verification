// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the CBOR C ABI, driven through the shipped C++ wrapper,
// one round trip per CBOR type.

#include "doctest.h"

#include <tav/cbor.hpp>

#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace tav::cbor;

// Non-copyable ownership is what keeps one value from being consumed twice,
// and only the factories can manufacture a Value from a handle.
static_assert(!std::is_copy_constructible_v<Value>);
static_assert(!std::is_copy_assignable_v<Value>);
static_assert(std::is_move_constructible_v<Value>);
static_assert(std::is_move_assignable_v<Value>);
static_assert(!std::is_constructible_v<Value, TavCborHandle*>);

namespace {

std::vector<uint8_t> vec(std::span<const uint8_t> data)
{
    return {data.begin(), data.end()};
}

} // namespace

TEST_CASE("cbor handle: signed round trips")
{
    for (int64_t value : {int64_t{0}, int64_t{1}, int64_t{-1}, INT64_MIN, INT64_MAX})
    {
        const Value built = make_signed(value);
        const std::vector<uint8_t> encoded = built.det_serialize();
        const Value parsed = nondet_parse(encoded);
        CHECK(parsed.kind() == Kind::SIGNED);
        CHECK(parsed.as_signed() == value);
    }
}

TEST_CASE("cbor handle: simple round trips")
{
    const Value built = make_simple(22); // null
    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0xf6});

    const Value parsed = nondet_parse(encoded);
    CHECK(parsed.kind() == Kind::SIMPLE);
    CHECK(parsed.as_simple() == 22);
}

TEST_CASE("cbor handle: bytes round trip")
{
    const std::vector<uint8_t> payload = {1, 2, 3};
    const Value built = make_bytes(payload);
    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0x43, 1, 2, 3});

    const Value parsed = nondet_parse(encoded);
    CHECK(parsed.kind() == Kind::BYTES);
    CHECK(vec(parsed.as_bytes()) == payload);
}

TEST_CASE("cbor handle: string round trips")
{
    const std::string payload = "hi";
    const Value built = make_string(payload);
    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0x62, 0x68, 0x69});

    const Value parsed = nondet_parse(encoded);
    CHECK(parsed.kind() == Kind::STRING);
    CHECK(parsed.as_string() == "hi");
}

TEST_CASE("cbor handle: array round trips")
{
    const std::string text = "hi";
    std::vector<Value> items;
    items.push_back(make_signed(1));
    items.push_back(make_string(text));
    const Value built = make_array(std::move(items));

    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0x82, 0x01, 0x62, 0x68, 0x69});

    const Value parsed = nondet_parse(encoded);
    const Value& root = parsed;
    CHECK(root.kind() == Kind::ARRAY);
    REQUIRE(root.size() == 2);
    CHECK(root.array_at(0).as_signed() == 1);
    const Value text_value = root.array_at(1);
    CHECK(text_value.as_string() == "hi");
}

TEST_CASE("cbor handle: map round trips, det sorts keys, and lookup is by key")
{
    const std::string b = "b";
    const std::string a = "a";
    std::vector<MapItem> entries;
    entries.emplace_back(make_string(b), make_signed(2));
    entries.emplace_back(make_string(a), make_signed(1));
    const Value built = make_map(std::move(entries));

    // Entry order is preserved as given...
    CHECK(built.nondet_serialize() ==
          std::vector<uint8_t>{0xa2, 0x61, 0x62, 0x02, 0x61, 0x61, 0x01});
    // ...and sorted into canonical order for deterministic encoding.
    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02});

    const Value parsed = nondet_parse(encoded);
    const Value& root = parsed;
    CHECK(root.kind() == Kind::MAP);
    REQUIRE(root.size() == 2);

    // Lookup by key, as ValueImpl::map_at does.
    const Value key_a = make_string(a);
    CHECK(root.map_at(key_a).as_signed() == 1);

    // Enumeration, for callers that walk.
    const Value second_key = root.map_key_at(1);
    CHECK(second_key.as_string() == "b");
    CHECK(root.map_value_at(1).as_signed() == 2);
}

TEST_CASE("cbor handle: tagged round trips and tag_at checks the tag")
{
    const std::vector<uint8_t> payload = {0x2a};
    const Value built = make_tagged(18, make_bytes(payload));
    const std::vector<uint8_t> encoded = built.det_serialize();
    CHECK(encoded == std::vector<uint8_t>{0xd2, 0x41, 0x2a});

    const Value parsed = nondet_parse(encoded);
    const Value& root = parsed;
    CHECK(root.kind() == Kind::TAGGED);
    const Value tagged_payload = root.tag_at(18);
    CHECK(vec(tagged_payload.as_bytes()) == payload);
}

TEST_CASE("cbor handle: payloads are borrowed, not copied")
{
    // The payload read back is the caller's own address, which a copy could
    // not be. Mutating a borrowed buffer would be undefined, so identity is
    // the safe proof.
    const std::vector<uint8_t> buffer = {1, 2, 3};
    const Value built = make_bytes(buffer);
    CHECK(built.as_bytes().data() == buffer.data());

    // The same holds for a parsed document: its payload points into the input.
    const std::vector<uint8_t> document = {0x43, 1, 2, 3};
    const Value parsed = nondet_parse(document);
    CHECK(parsed.as_bytes().data() == document.data() + 1);
    CHECK(vec(parsed.as_bytes()) == std::vector<uint8_t>{1, 2, 3});
}

TEST_CASE("cbor handle: det_parse accepts a canonical encoding and round trips")
{
    std::vector<MapItem> entries;
    entries.emplace_back(make_signed(2), make_string("two"));
    entries.emplace_back(make_signed(1), make_string("one"));
    const Value built = make_map(std::move(entries));
    const std::vector<uint8_t> encoded = built.det_serialize();

    const Value parsed = det_parse(encoded);
    const Value& root = parsed;
    CHECK(root.kind() == Kind::MAP);
    CHECK(root.size() == 2);

    const Value one = make_signed(1);
    const Value found = root.map_at(one);
    CHECK(found.as_string() == "one");
    CHECK(parsed.det_serialize() == encoded);
}

TEST_CASE("cbor handle: errors carry the ABI status")
{
    const std::vector<uint8_t> document = {0x81, 0x01}; // [1]
    const Value parsed = nondet_parse(document);
    const Value& root = parsed;

    CHECK_THROWS_AS((void)root.array_at(5), CborError);
    try
    {
        (void)root.array_at(5);
    }
    catch (const CborError& e)
    {
        CHECK(e.error_code() == Error::OUT_OF_BOUND);
    }

    try
    {
        (void)root.as_signed(); // an array is not a signed value
        FAIL("expected a CborError");
    }
    catch (const CborError& e)
    {
        CHECK(e.error_code() == Error::TYPE_MISMATCH);
    }

    try
    {
        (void)root.tag_at(18); // not tagged at all
        FAIL("expected a CborError");
    }
    catch (const CborError& e)
    {
        CHECK(e.error_code() == Error::TYPE_MISMATCH);
    }

    // A non-canonical encoding: 1 in a two-byte head. Only det_parse rejects
    // it, and the canonical spelling of the same value is accepted.
    const std::vector<uint8_t> non_canonical = {0x18, 0x01};
    const std::vector<uint8_t> canonical = {0x01};
    CHECK_NOTHROW(nondet_parse(non_canonical));

    const Value canonical_parsed = det_parse(canonical);
    CHECK(canonical_parsed.as_signed() == 1);

    try
    {
        (void)det_parse(non_canonical);
        FAIL("expected a CborError");
    }
    catch (const CborError& e)
    {
        CHECK(e.error_code() == Error::DECODE_FAILED);
    }
}

TEST_CASE("cbor handle: a container empties the values it consumes")
{
    std::vector<Value> items;
    items.push_back(make_signed(1));
    const Value array = make_array(std::move(items));

    // The array took the handle, so the caller's variable is left empty.
    CHECK(items[0].empty());
    CHECK(array.det_serialize() == std::vector<uint8_t>{0x81, 0x01});
}

TEST_CASE("cbor handle: an empty value cannot be placed in a container")
{
    std::vector<Value> items;
    items.push_back(make_signed(1));
    items.emplace_back();

    // The ABI rejects the complete batch, then the wrapper releases the
    // handles it had taken from the source values.
    CHECK_THROWS_AS(make_array(std::move(items)), CborError);
}

TEST_CASE("cbor handle: navigation returns an independently owned value")
{
    Value child;
    {
        const std::vector<uint8_t> document = {0x81, 0x18, 0x2a}; // [42]
        const Value parsed = nondet_parse(document);
        child = parsed.array_at(0);
    }

    CHECK(child.as_signed() == 42);
}

TEST_CASE("cbor handle: a projected value can be consumed by a builder")
{
    const std::vector<uint8_t> document = {0x81, 0x18, 0x2a}; // [42]
    const Value parsed = nondet_parse(document);
    Value child = parsed.array_at(0);

    std::vector<Value> fields;
    fields.push_back(std::move(child));
    const Value rebuilt = make_array(std::move(fields));

    CHECK(child.empty());
    CHECK(rebuilt.det_serialize() == document);
    CHECK(parsed.det_serialize() == document);
}

TEST_CASE("cbor handle: a nested document survives build, serialize, parse and walk")
{
    const std::vector<uint8_t> phdr = {0xa1, 0x01, 0x26};
    const std::vector<uint8_t> payload = {0x2a};
    const std::vector<uint8_t> signature = {0xff};

    std::vector<Value> items;
    items.push_back(make_bytes(phdr));
    items.push_back(make_map({}));
    items.push_back(make_bytes(payload));
    items.push_back(make_bytes(signature));
    const Value sign1 = make_tagged(18, make_array(std::move(items)));

    const std::vector<uint8_t> encoded = sign1.det_serialize();
    const Value parsed = nondet_parse(encoded);
    const Value body = parsed.tag_at(18);
    REQUIRE(body.size() == 4);
    const Value parsed_phdr = body.array_at(0);
    CHECK(vec(parsed_phdr.as_bytes()) == phdr);
    CHECK(body.array_at(1).size() == 0);
    const Value parsed_payload = body.array_at(2);
    CHECK(vec(parsed_payload.as_bytes()) == payload);
    const Value parsed_signature = body.array_at(3);
    CHECK(vec(parsed_signature.as_bytes()) == signature);
}

TEST_CASE("cbor handle: decode and encode failures are distinguishable")
{
    const std::vector<uint8_t> non_canonical = {0x18, 0x01};
    CHECK_THROWS_AS((void)det_parse(non_canonical), DecodeError);

    const std::vector<uint8_t> document = {0x81, 0x01}; // [1]
    const Value parsed = nondet_parse(document);
    CHECK_THROWS_AS((void)parsed.as_signed(), DecodeError);

    // Nesting deeper than the serializer is allowed to walk.
    std::vector<Value> inner;
    inner.push_back(make_signed(1));
    std::vector<Value> outer;
    outer.push_back(make_array(std::move(inner)));
    const Value nested = make_array(std::move(outer));
    CHECK_THROWS_AS((void)nested.det_serialize(1), EncodeError);

    // Both remain catchable as the common base.
    CHECK_THROWS_AS((void)det_parse(non_canonical), CborError);
}

TEST_CASE("cbor handle: invalid UTF-8 fails string construction")
{
    const char invalid[] = {static_cast<char>(0xff)};
    CHECK_THROWS_AS(
      (void)make_string(std::string_view(invalid, 1)), EncodeError);
}

TEST_CASE("cbor handle: simple values convert to and from booleans")
{
    CHECK(simple_to_boolean(SimpleValue::True));
    CHECK_FALSE(simple_to_boolean(SimpleValue::False));
    CHECK_THROWS_AS((void)simple_to_boolean(SimpleValue::Null), DecodeError);
    CHECK_THROWS_AS(
      (void)simple_to_boolean(SimpleValue::Undefined), DecodeError);
    CHECK(boolean_to_simple(true) == SimpleValue::True);
    CHECK(boolean_to_simple(false) == SimpleValue::False);

    // SimpleValue feeds make_simple directly.
    const Value null_value = make_simple(SimpleValue::Null);
    CHECK(null_value.as_simple() == SimpleValue::Null);
    CHECK(null_value.det_serialize() == std::vector<uint8_t>{0xf6});
}

TEST_CASE("cbor handle: reserved simple values cannot be built")
{
    for (uint8_t value = 24; value <= 31; ++value)
    {
        CHECK_THROWS_AS((void)make_simple(value), EncodeError);
    }

    // The neighbours on both sides still build and serialize.
    const Value below = make_simple(23);
    const Value above = make_simple(32);
    CHECK(below.det_serialize() == std::vector<uint8_t>{0xf7});
    CHECK(above.det_serialize() == std::vector<uint8_t>{0xf8, 0x20});
}

TEST_CASE("cbor handle: rethrow_with_msg prefixes decode errors only")
{
    const std::vector<uint8_t> document = {0x81, 0x01}; // [1]
    const Value parsed = nondet_parse(document);

    // The value is returned untouched when nothing throws.
    const Value item =
      rethrow_with_msg([&] { return parsed.array_at(0); }, "reading");
    CHECK(item.as_signed() == 1);

    try
    {
        (void)rethrow_with_msg(
          [&] { return parsed.array_at(9); }, "reading item");
        FAIL("expected a DecodeError");
    }
    catch (const DecodeError& e)
    {
        CHECK(e.error_code() == Error::OUT_OF_BOUND);
        CHECK(std::string(e.what()).starts_with("reading item: "));
    }

    // Without a message the original error passes through unchanged.
    try
    {
        (void)rethrow_with_msg([&] { return parsed.array_at(9); });
        FAIL("expected a DecodeError");
    }
    catch (const DecodeError& e)
    {
        CHECK(e.error_code() == Error::OUT_OF_BOUND);
        CHECK(std::string(e.what()) == "array_at");
    }
}

TEST_CASE("cbor handle: map lookup by key round trips")
{
    // a3 01 63 6f6e65 02 63 74776f 03 65 7468726565
    const std::vector<uint8_t> document = {
      0xa3,
      0x01,
      0x63,
      'o',
      'n',
      'e',
      0x02,
      0x63,
      't',
      'w',
      'o',
      0x03,
      0x65,
      't',
      'h',
      'r',
      'e',
      'e'};
    const Value parsed = nondet_parse(document);
    const Value& root = parsed;

    REQUIRE(root.size() == 3);
    const Value one = make_signed(1);
    const Value two = make_signed(2);
    const Value three = make_signed(3);
    const Value found_one = root.map_at(one);
    const Value found_two = root.map_at(two);
    const Value found_three = root.map_at(three);
    CHECK(found_one.as_string() == "one");
    CHECK(found_two.as_string() == "two");
    CHECK(found_three.as_string() == "three");

    CHECK(parsed.nondet_serialize() == document);
}

TEST_CASE("cbor handle: shallow_copy shares payload buffers, deep_copy does not")
{
    const std::vector<uint8_t> payload = {0xaa, 0xbb};
    const Value source = make_bytes(payload);

    const Value shared = shallow_copy(source);
    const Value detached = deep_copy(source);

    // Same bytes either way.
    CHECK(vec(shared.as_bytes()) == payload);
    CHECK(vec(detached.as_bytes()) == payload);

    // The shallow copy points at the caller's buffer; the deep copy does not.
    CHECK(shared.as_bytes().data() == payload.data());
    CHECK(detached.as_bytes().data() != payload.data());

    // Both are values in their own right, so both outlive the source value.
    CHECK(shared.det_serialize() == detached.det_serialize());
}

TEST_CASE("cbor handle: deep_copy outlives the buffer it was taken from")
{
    Value detached;
    {
        const std::vector<uint8_t> document = {0x43, 0x01, 0x02, 0x03};
        const Value parsed = nondet_parse(document);
        detached = deep_copy(parsed);
        // parsed and document both die here.
    }
    CHECK(detached.det_serialize() == std::vector<uint8_t>{0x43, 0x01, 0x02, 0x03});
}

TEST_CASE("cbor handle: copying reproduces every kind")
{
    const std::vector<uint8_t> raw = {0xde, 0xad};
    std::vector<MapItem> entries;
    entries.emplace_back(make_string("k"), make_bytes(raw));

    std::vector<Value> items;
    items.push_back(make_signed(-7));
    items.push_back(make_simple(SimpleValue::Null));
    items.push_back(make_map(std::move(entries)));
    const auto EPOCH_DATE_TIME = 1;
    const Value source =
      make_tagged(EPOCH_DATE_TIME, make_array(std::move(items)));
    const std::vector<uint8_t> expected = source.det_serialize();

    CHECK(shallow_copy(source).det_serialize() == expected);
    CHECK(deep_copy(source).det_serialize() == expected);
}

TEST_CASE("cbor handle: an empty value cannot be copied")
{
    const Value empty;
    CHECK_THROWS_AS((void)shallow_copy(empty), EncodeError);
    CHECK_THROWS_AS((void)deep_copy(empty), EncodeError);
}

TEST_CASE("cbor handle: rebuilding a map with one entry replaced")
{
    // The pattern that replaces in-place mutation of a parsed document.
    std::vector<MapItem> original;
    original.emplace_back(make_signed(1), make_string("keep"));
    original.emplace_back(make_signed(2), make_string("replace"));
    const Value source = make_map(std::move(original));

    const Value& map = source;
    std::vector<MapItem> rebuilt;
    rebuilt.reserve(map.size());
    for (size_t i = 0; i < map.size(); ++i)
    {
        const Value key = map.map_key_at(i);
        const bool hit = key.kind() == Kind::SIGNED && key.as_signed() == 2;
        rebuilt.emplace_back(
          shallow_copy(key), hit ? make_signed(0) : shallow_copy(map.map_value_at(i)));
    }
    const Value edited = make_map(std::move(rebuilt));

    const Value one = make_signed(1);
    const Value two = make_signed(2);
    CHECK(edited.map_at(one).as_string() == "keep");
    CHECK(edited.map_at(two).as_signed() == 0);
    // The source is untouched.
    CHECK(source.map_at(two).as_string() == "replace");
}

TEST_CASE("cbor handle: rebuilding an array with one element replaced")
{
    // The pattern that replaces in-place mutation of a parsed document.
    std::vector<Value> original;
    original.push_back(make_string("keep"));
    original.push_back(make_string("replace"));
    original.push_back(make_string("keep too"));
    const Value source = make_array(std::move(original));

    const Value& array = source;
    std::vector<Value> rebuilt;
    rebuilt.reserve(array.size());
    for (size_t i = 0; i < array.size(); ++i)
    {
        rebuilt.push_back(i == 1 ? make_signed(0) : shallow_copy(array.array_at(i)));
    }
    const Value edited = make_array(std::move(rebuilt));

    const Value& result = edited;
    REQUIRE(result.size() == 3);
    CHECK(result.array_at(0).as_string() == "keep");
    CHECK(result.array_at(1).as_signed() == 0);
    CHECK(result.array_at(2).as_string() == "keep too");
    // The source is untouched.
    CHECK(source.array_at(1).as_string() == "replace");
}

TEST_CASE("cbor handle: shallow_copy keeps an owned payload owned")
{
    // Cloning a value whose payload it owns must copy that payload, or the
    // the copy would point into the source once the source is gone.
    Value copied;
    {
        const std::vector<uint8_t> buffer = {0xaa, 0xbb, 0xcc};
        const Value borrowing = make_bytes(buffer);
        const Value source = deep_copy(borrowing);
        copied = shallow_copy(source);
        CHECK(copied.as_bytes().data() != source.as_bytes().data());
    }
    CHECK(vec(copied.as_bytes()) == std::vector<uint8_t>{0xaa, 0xbb, 0xcc});
}

TEST_CASE("cbor handle: shallow_copy keeps a borrowed payload borrowed")
{
    const std::vector<uint8_t> buffer = {0x01, 0x02};
    const Value source = make_bytes(buffer);
    const Value copied = shallow_copy(source);

    // Shared with the caller's buffer, so nothing was duplicated.
    CHECK(copied.as_bytes().data() == buffer.data());
}

TEST_CASE("cbor handle: serialization stops one level past the depth ceiling")
{
    auto nest = [](size_t levels) {
        Value v = make_signed(1);
        for (size_t i = 0; i < levels; ++i)
        {
            std::vector<Value> outer;
            outer.push_back(std::move(v));
            v = make_array(std::move(outer));
        }
        return v;
    };

    const Value at_ceiling = nest(MAX_DEPTH);
    CHECK_NOTHROW((void)at_ceiling.det_serialize());
    CHECK_NOTHROW((void)deep_copy(at_ceiling));

    const Value past_ceiling = nest(MAX_DEPTH + 1);
    CHECK_THROWS_AS((void)past_ceiling.det_serialize(), EncodeError);

    // Copying carries no depth limit of its own, so it still succeeds.
    CHECK_NOTHROW((void)deep_copy(past_ceiling));
    CHECK_NOTHROW((void)shallow_copy(past_ceiling));
}

TEST_CASE("cbor handle: every key a map holds can be looked up")
{
    const std::vector<uint8_t> bytes_key = {0x01};
    std::vector<MapItem> entries;
    entries.emplace_back(make_signed(1), make_string("by int"));
    entries.emplace_back(make_string("k"), make_string("by text"));
    entries.emplace_back(make_bytes(bytes_key), make_string("by bytes"));
    entries.emplace_back(make_simple(SimpleValue::Null), make_string("by simple"));
    const Value map = make_map(std::move(entries));

    const Value& root = map;
    REQUIRE(root.size() == 4);
    for (size_t i = 0; i < root.size(); ++i)
    {
        // The key the map hands back always finds its own entry.
        const Value key = root.map_key_at(i);
        const Value found = root.map_at(key);
        const Value enumerated = root.map_value_at(i);
        CHECK(found.as_string() == enumerated.as_string());
    }
}

TEST_CASE("cbor handle: a container cannot be a map key")
{
    std::vector<MapItem> entries;
    entries.emplace_back(make_array({}), make_signed(7));
    CHECK_THROWS_AS(make_map(std::move(entries)), EncodeError);

    std::vector<MapItem> tagged;
    tagged.emplace_back(make_tagged(18, make_signed(1)), make_signed(7));
    CHECK_THROWS_AS(make_map(std::move(tagged)), EncodeError);

    // Parsing applies the same rule, so no map reachable through this API
    // holds a key map_at would refuse.
    CHECK_THROWS_AS(
      (void)nondet_parse(std::vector<uint8_t>{0xa1, 0x81, 0x01, 0x02}),
      DecodeError); // {[1]: 2}
    CHECK_THROWS_AS(
      (void)det_parse(std::vector<uint8_t>{0xa1, 0x81, 0x01, 0x02}),
      DecodeError);

    // Nested below the root, so the whole tree is checked.
    CHECK_THROWS_AS(
      (void)nondet_parse(std::vector<uint8_t>{0x81, 0xa1, 0x81, 0x01, 0x02}),
      DecodeError); // [{[1]: 2}]
}

TEST_CASE("cbor handle: duplicate map keys cannot be serialized")
{
    std::vector<MapItem> integers;
    integers.emplace_back(make_signed(1), make_signed(10));
    integers.emplace_back(make_signed(1), make_signed(20));
    const Value map = make_map(std::move(integers));

    CHECK(integers[0].first.empty());
    CHECK(integers[0].second.empty());
    CHECK(integers[1].first.empty());
    CHECK(integers[1].second.empty());
    CHECK(map.size() == 2);
    CHECK_THROWS_AS((void)map.nondet_serialize(), EncodeError);
    CHECK_THROWS_AS((void)map.det_serialize(), EncodeError);
    CHECK(map.size() == 2);
}

TEST_CASE("cbor handle: every key of a parsed map can be looked up")
{
    std::vector<MapItem> entries;
    entries.emplace_back(make_signed(1), make_string("one"));
    entries.emplace_back(make_string("two"), make_signed(2));
    const Value built = make_map(std::move(entries));

    const std::vector<uint8_t> encoded = built.det_serialize();
    const Value parsed = det_parse(encoded);
    const Value& root = parsed;

    // Enumeration and lookup agree: whatever map_key_at hands back, map_at
    // accepts.
    for (size_t i = 0; i < root.size(); ++i)
    {
        const Value key = root.map_key_at(i);
        CHECK_NOTHROW((void)root.map_at(key));
    }
}

TEST_CASE("cbor handle: as_tag reads the tag a tagged value carries")
{
    const Value tagged = make_tagged(18, make_signed(7));
    CHECK(tagged.as_tag() == 18);
    // The tag is needed to reach the payload, which tag_at only checks.
    CHECK(tagged.tag_at(tagged.as_tag()).as_signed() == 7);

    // Anything else is a mismatch rather than a silent zero.
    const Value untagged = make_signed(1);
    CHECK_THROWS_AS((void)untagged.as_tag(), DecodeError);
}

TEST_CASE("cbor handle: moving transfers the handle and releases the target's own")
{
    Value source = make_signed(42);

    const Value moved = std::move(source);
    CHECK(source.empty());
    CHECK(moved.det_serialize() == std::vector<uint8_t>{0x18, 0x2a});

    // Move assignment releases whatever the target already held.
    Value target = make_signed(1);
    Value replacement = make_signed(2);
    target = std::move(replacement);
    CHECK(replacement.empty());
    CHECK(target.det_serialize() == std::vector<uint8_t>{0x02});

    // Assigning a value to itself must not free it.
    Value* alias = &target;
    target = std::move(*alias);
    CHECK_FALSE(target.empty());
    CHECK(target.det_serialize() == std::vector<uint8_t>{0x02});
}

TEST_CASE("cbor handle: empty containers round trip")
{
    CHECK(make_array({}).det_serialize() == std::vector<uint8_t>{0x80});
    CHECK(make_map({}).det_serialize() == std::vector<uint8_t>{0xa0});

    const Value array = make_array({});
    const Value map = make_map({});
    CHECK(array.size() == 0);
    CHECK(map.size() == 0);
}
