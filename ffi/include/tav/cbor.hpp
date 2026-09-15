// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// RAII wrapper over the public CBOR C ABI in <tav/cbor.h>.
//
// Handle ownership:
// - Every Value is independently owned and releases its handle on destruction.
//   Navigation returns another Value that keeps the same immutable document
//   alive. Value cannot be copied, so one handle is never consumed twice.
// - Container builders consume the values passed to them, leaving each source
//   empty(). A consumed Value must not be used again.
//
// Payload ownership:
// - Scalars are copied. Byte and text payloads are borrowed: a buffer passed
//   to make_bytes, make_string, or a parse call must outlive every Value and
//   every Value derived from it, and must not be modified meanwhile. Spans and
//   views returned by as_bytes and as_string must not outlive their payload
//   storage.
//
// Failures throw tav::Exception with the C ABI's tav::ErrorCode and message.
//
// Nesting:
// - MAX_DEPTH limits parsing and serialization, not builders. Callers must
//   bound the depth they build. Copying, materializing, or destroying an
//   extremely deep Value can exhaust the process stack and abort.

#include <tav/cbor.h>
#include <tav/byte_buffer.hpp>
#include <tav/errors.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tav::cbor
{
/// Ceiling on nesting depth for parsing and serialization.
constexpr size_t MAX_DEPTH = TAV_CBOR_MAX_DEPTH;

/// Value kinds. INVALID is reported for an empty Value.
enum class Kind : int
{
    INVALID = TAV_CBOR_HANDLE_KIND_INVALID,
    SIGNED = TAV_CBOR_HANDLE_KIND_SIGNED,
    BYTES = TAV_CBOR_HANDLE_KIND_BYTES,
    STRING = TAV_CBOR_HANDLE_KIND_STRING,
    ARRAY = TAV_CBOR_HANDLE_KIND_ARRAY,
    MAP = TAV_CBOR_HANDLE_KIND_MAP,
    TAGGED = TAV_CBOR_HANDLE_KIND_TAGGED,
    SIMPLE = TAV_CBOR_HANDLE_KIND_SIMPLE,
};

/// https://www.iana.org/assignments/cbor-simple-values/cbor-simple-values.xhtml
enum SimpleValue : uint8_t
{
    False = 20,
    True = 21,
    Null = 22,
    Undefined = 23,
};

inline bool simple_to_boolean(uint8_t value)
{
    switch (value)
    {
        case SimpleValue::False:
            return false;
        case SimpleValue::True:
            return true;
        default:
            throw tav::Exception(
              tav::ErrorCode::CBOR_TYPE_MISMATCH, "Simple value cannot be matched to boolean");
    }
}

inline SimpleValue boolean_to_simple(bool value)
{
    return value ? SimpleValue::True : SimpleValue::False;
}

class Value;
using MapItem = std::pair<Value, Value>;

Value make_signed(int64_t value);
Value make_simple(uint8_t value);
Value make_bytes(std::span<const uint8_t> data);
Value make_string(std::string_view data);
Value make_array(std::vector<Value>&& items);
Value make_map(std::vector<MapItem>&& entries);
Value make_tagged(uint64_t tag, Value&& payload);
Value shallow_copy(const Value& value);
Value deep_copy(const Value& value);
Value nondet_parse(std::span<const uint8_t> raw, size_t max_depth);
Value det_parse(std::span<const uint8_t> raw, size_t max_depth);

/// An owning value. Moving transfers the handle and empties the source.
class Value
{
public:
    Value() = default;
    Value(const Value&) = delete;
    Value& operator=(const Value&) = delete;

    Value(Value&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    Value& operator=(Value&& other) noexcept
    {
        if (this != &other)
        {
            tav_cbor_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~Value()
    {
        tav_cbor_free(handle_);
    }

    /// True once the handle has been consumed or moved out.
    [[nodiscard]] bool empty() const
    {
        return handle_ == nullptr;
    }

    [[nodiscard]] Kind kind() const
    {
        return static_cast<Kind>(tav_cbor_kind(handle_));
    }

    [[nodiscard]] int64_t as_signed() const
    {
        int64_t out = 0;
        tav::check(tav_cbor_as_signed(handle_, &out));
        return out;
    }

    [[nodiscard]] uint8_t as_simple() const
    {
        uint8_t out = 0;
        tav::check(tav_cbor_as_simple(handle_, &out));
        return out;
    }

    /// Returns a non-owning view of the payload.
    [[nodiscard]] std::span<const uint8_t> as_bytes() const
    {
        const uint8_t* data = nullptr;
        size_t len = 0;
        tav::check(tav_cbor_as_bytes(handle_, &data, &len));
        return {data, len};
    }

    /// Returns a non-owning view of the payload.
    [[nodiscard]] std::string_view as_string() const
    {
        const char* data = nullptr;
        size_t len = 0;
        tav::check(tav_cbor_as_string(handle_, &data, &len));
        return {data, len};
    }

    [[nodiscard]] uint64_t as_tag() const
    {
        uint64_t out = 0;
        tav::check(tav_cbor_as_tag(handle_, &out));
        return out;
    }

    /// Array or map entry count.
    [[nodiscard]] size_t size() const
    {
        size_t out = 0;
        tav::check(tav_cbor_size(handle_, &out));
        return out;
    }

    [[nodiscard]] Value array_at(size_t index) const
    {
        TavCborHandle* out = nullptr;
        tav::check(tav_cbor_array_at(handle_, index, &out));
        return adopt(out, "array_at");
    }

    [[nodiscard]] Value map_at(const Value& key) const
    {
        TavCborHandle* out = nullptr;
        tav::check(tav_cbor_map_at(handle_, key.handle_, &out));
        return adopt(out, "map_at");
    }

    [[nodiscard]] Value tag_at(uint64_t tag) const
    {
        TavCborHandle* out = nullptr;
        tav::check(tav_cbor_tag_at(handle_, tag, &out));
        return adopt(out, "tag_at");
    }

    [[nodiscard]] Value map_key_at(size_t index) const
    {
        TavCborHandle* out = nullptr;
        tav::check(tav_cbor_map_key_at(handle_, index, &out));
        return adopt(out, "map_key_at");
    }

    [[nodiscard]] Value map_value_at(size_t index) const
    {
        TavCborHandle* out = nullptr;
        tav::check(tav_cbor_map_value_at(handle_, index, &out));
        return adopt(out, "map_value_at");
    }

    [[nodiscard]] std::vector<uint8_t> nondet_serialize(
      size_t max_depth = MAX_DEPTH) const
    {
        return encode(tav_cbor_nondet_serialize, max_depth);
    }

    /// Deterministic encoding.
    [[nodiscard]] std::vector<uint8_t> det_serialize(size_t max_depth = MAX_DEPTH) const
    {
        return encode(tav_cbor_det_serialize, max_depth);
    }

private:
    // Only these may mint an owning value from a raw handle, so no two
    // values can name the same one.
    friend Value make_signed(int64_t);
    friend Value make_simple(uint8_t);
    friend Value make_bytes(std::span<const uint8_t>);
    friend Value make_string(std::string_view);
    friend Value make_array(std::vector<Value>&&);
    friend Value make_map(std::vector<MapItem>&&);
    friend Value make_tagged(uint64_t, Value&&);
    friend Value shallow_copy(const Value&);
    friend Value deep_copy(const Value&);
    friend Value nondet_parse(std::span<const uint8_t>, size_t);
    friend Value det_parse(std::span<const uint8_t>, size_t);

    /// Holds handles being handed to a container constructor.
    ///
    /// The constructor nulls what it consumes and returns what it does not,
    /// so the destructor frees exactly the handles still owned here.
    class Batch
    {
    public:
        Batch() = default;
        Batch(const Batch&) = delete;
        Batch& operator=(const Batch&) = delete;
        Batch(Batch&&) = delete;
        Batch& operator=(Batch&&) = delete;

        ~Batch()
        {
            for (TavCborHandle* handle : handles_)
            {
                tav_cbor_free(handle);
            }
        }

        void reserve(size_t n)
        {
            handles_.reserve(n);
        }

        void add(Value&& value)
        {
            handles_.push_back(std::exchange(*value.slot(), nullptr));
        }

        TavCborHandle** data()
        {
            return handles_.data();
        }

        [[nodiscard]] size_t size() const
        {
            return handles_.size();
        }

        std::vector<TavCborHandle*> handles_;
    };

    static Value adopt(TavCborHandle* handle, const char* what)
    {
        if (handle == nullptr)
        {
            throw tav::Exception(tav::ErrorCode::CBOR_ENCODE_FAILED, what);
        }
        return Value(handle);
    }

    template<class Builder>
    static Value construct(Builder builder, const char* what)
    {
        TavCborHandle* out = nullptr;
        tav::check(builder(&out));
        return adopt(out, what);
    }

    using Encoder =
      TavError* (*)(const TavCborHandle*, size_t, TavByteBuffer**);
    using Parser =
      TavError* (*)(const uint8_t*, size_t, size_t, TavCborHandle**);

    static Value parse_with(Parser parser, std::span<const uint8_t> raw, size_t max_depth)
    {
        TavCborHandle* out = nullptr;
        tav::check(parser(raw.data(), raw.size(), max_depth, &out));
        return Value::adopt(out, "parse");
    }

    explicit Value(TavCborHandle* handle) : handle_(handle) {}

    TavCborHandle** slot()
    {
        return &handle_;
    }

    [[nodiscard]] std::vector<uint8_t> encode(Encoder encoder, size_t max_depth) const
    {
        TavByteBuffer* out = nullptr;
        TavError* error = encoder(handle_, max_depth, &out);
        const auto buffer = tav::ByteBuffer::adopt(out);
        tav::check(error);
        const auto bytes = buffer.bytes();
        return {bytes.begin(), bytes.end()};
    }

    TavCborHandle* handle_ = nullptr;
};

inline Value make_signed(int64_t value)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_make_signed(value, out); }, "make_signed");
}

inline Value make_simple(uint8_t value)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_make_simple(value, out); }, "make_simple");
}

/// Borrows data, which must outlive the returned value.
inline Value make_bytes(std::span<const uint8_t> data)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_make_bytes(data.data(), data.size(), out); },
      "make_bytes");
}

/// Borrows data, which must outlive the returned value and be valid UTF-8.
inline Value make_string(std::string_view data)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_make_string(data.data(), data.size(), out); },
      "make_string");
}

inline Value make_array(std::vector<Value>&& items)
{
    Value::Batch batch;
    batch.reserve(items.size());
    for (Value& item : items)
    {
        batch.add(std::move(item));
    }
    return Value::construct(
      [&](auto out) { return tav_cbor_make_array(batch.data(), batch.size(), out); },
      "make_array");
}

/// Keys may be any supported CBOR value and must be unique. Duplicate keys are
/// unsupported: construction may succeed, but serialization throws tav::Exception.
inline Value make_map(std::vector<MapItem>&& entries)
{
    const size_t pair_count = entries.size();
    Value::Batch batch;
    batch.reserve(pair_count * 2);
    for (MapItem& entry : entries)
    {
        batch.add(std::move(entry.first));
        batch.add(std::move(entry.second));
    }
    return Value::construct(
      [&](auto out) { return tav_cbor_make_map(batch.data(), pair_count, out); },
      "make_map");
}

inline Value make_tagged(uint64_t tag, Value&& payload)
{
    Value::Batch batch;
    batch.reserve(1);
    batch.add(std::move(payload));
    return Value::construct(
      [&](auto out) { return tav_cbor_make_tagged(tag, batch.data(), out); },
      "make_tagged");
}

/// Borrows raw, which must outlive the returned value.
///
/// Map keys use RFC 8949 equivalence, including order-independent map comparison.
inline Value nondet_parse(std::span<const uint8_t> raw, size_t max_depth = MAX_DEPTH)
{
    return Value::parse_with(tav_cbor_nondet_parse, raw, max_depth);
}

/// Borrows raw, and requires deterministic encoding.
inline Value det_parse(std::span<const uint8_t> raw, size_t max_depth = MAX_DEPTH)
{
    return Value::parse_with(tav_cbor_det_parse, raw, max_depth);
}

/// Copy a value, keeping the payload ownership the source had.
///
/// The structure is duplicated. A payload the source borrows is borrowed
/// again from the same buffer, so that buffer must outlive the result; a
/// payload the source owns is copied. The source value itself need not
/// outlive the result.
inline Value shallow_copy(const Value& value)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_shallow_copy(value.handle_, out); }, "shallow_copy");
}

/// Copy a value, copying every payload, so the result borrows nothing.
///
/// Do not keep a view obtained from a temporary result:
/// `auto text = deep_copy(value).as_string();` leaves `text` dangling.
inline Value deep_copy(const Value& value)
{
    return Value::construct(
      [&](auto out) { return tav_cbor_deep_copy(value.handle_, out); }, "deep_copy");
}

/// Run f, prefixing msg onto any tav::Exception while preserving its code.
decltype(auto) rethrow_with_msg(auto&& f, std::string_view msg = {})
{
    try
    {
        return f();
    }
    catch (const tav::Exception& err)
    {
        if (msg.empty())
        {
            throw;
        }
        throw tav::Exception(
          err.code(), std::string(msg) + ": " + err.what());
    }
}
}
