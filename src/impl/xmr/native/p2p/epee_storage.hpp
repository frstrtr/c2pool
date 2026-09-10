// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/epee_storage.hpp
//
// Wave 1, component C1a: the epee PORTABLE STORAGE codec -- the binary
// key/value format that carries every levin message body on the Monero wire.
//
// Ground truth (read verbatim, monerod master, 2026-09-10):
//   contrib/epee/include/storages/portable_storage_base.h     -- tags, marks
//   contrib/epee/include/storages/portable_storage_to_bin.h   -- the encoder
//   contrib/epee/include/storages/portable_storage_from_bin.h -- the decoder
//   contrib/epee/include/serialization/keyvalue_serialization.h
//   contrib/epee/include/serialization/keyvalue_serialization_overloads.h
//
// Five facts from that reading shape this file, and every one of them is a
// place where an independently invented implementation would have been wrong:
//
//   1. A section is a std::map<std::string, storage_entry>, so monerod emits
//      entries in LEXICOGRAPHIC KEY ORDER -- not in the order the KV map
//      declares them. Byte-parity against a captured frame is impossible
//      unless the encoder sorts. write_storage() sorts.
//   2. KV_SERIALIZE_OPT OMITS the field on store when it equals its default.
//      That is why levin_messages.hpp writes `rpc_port` only when non-zero and
//      `dandelionpp_fluff` only when false: the omission is the wire format,
//      not an optimisation.
//   3. Empty STL containers are not written at all
//      (serialize_stl_container_t_val: `if(!container.size()) return true;`),
//      and the loader's failure to find them is DISCARDED by KV_SERIALIZE
//      (the macro ignores the return value), so an absent container simply
//      means "empty" -- it is not a parse error at either end.
//   4. The size-mark varint is not the CryptoNote LEB128 varint used inside
//      block and transaction blobs. Two varints, two codecs; the other one
//      lives in native/consensus/xmr_blob_reader.hpp and is never mixed in.
//   5. epee's own decoder is where the peer's bytes get to choose how much we
//      allocate. Its guards (array count <= remaining/min_element_bytes,
//      duplicate keys rejected, string length <= remaining) are mirrored here
//      exactly, and then tightened: recursion depth 8 instead of 100, and a
//      hard ceiling on entries, objects, strings and array elements.
//
// This header is PURE CODEC: no socket, no thread, no connection state.
// STL only. Header-only.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace c2pool::xmr::native::epee {

// --- format constants --------------------------------------------------------
inline constexpr std::uint32_t SIGNATURE_A = 0x01011101u;
inline constexpr std::uint32_t SIGNATURE_B = 0x01020101u;  // "bender's nightmare"
inline constexpr std::uint8_t  FORMAT_VER  = 1;
inline constexpr std::size_t   STORAGE_HEADER_SIZE = 9;    // 4 + 4 + 1

// Size-mark varint. The low two bits of the first byte select the width; the
// value is the remaining bits, little-endian, shifted down by two.
inline constexpr std::uint8_t SIZE_MARK_MASK  = 0x03;
inline constexpr std::uint8_t SIZE_MARK_BYTE  = 0;
inline constexpr std::uint8_t SIZE_MARK_WORD  = 1;
inline constexpr std::uint8_t SIZE_MARK_DWORD = 2;
inline constexpr std::uint8_t SIZE_MARK_INT64 = 3;

// Largest value the 8-byte form can carry (62 bits).
inline constexpr std::uint64_t VARINT_MAX = 0x3FFFFFFFFFFFFFFFull;

enum class Type : std::uint8_t {
    Int64  = 1,
    Int32  = 2,
    Int16  = 3,
    Int8   = 4,
    Uint64 = 5,
    Uint32 = 6,
    Uint16 = 7,
    Uint8  = 8,
    Double = 9,
    String = 10,
    Bool   = 11,
    Object = 12,
    Array  = 13,
};

inline constexpr std::uint8_t FLAG_ARRAY = 0x80;

inline const char* to_string(Type t) noexcept {
    switch (t) {
        case Type::Int64:  return "Int64";
        case Type::Int32:  return "Int32";
        case Type::Int16:  return "Int16";
        case Type::Int8:   return "Int8";
        case Type::Uint64: return "Uint64";
        case Type::Uint32: return "Uint32";
        case Type::Uint16: return "Uint16";
        case Type::Uint8:  return "Uint8";
        case Type::Double: return "Double";
        case Type::String: return "String";
        case Type::Bool:   return "Bool";
        case Type::Object: return "Object";
        case Type::Array:  return "Array";
    }
    return "?";
}

inline constexpr bool is_known_type(std::uint8_t tag) noexcept {
    return tag >= 1 && tag <= 13;
}

inline constexpr bool is_integer_type(Type t) noexcept {
    switch (t) {
        case Type::Int64: case Type::Int32: case Type::Int16: case Type::Int8:
        case Type::Uint64: case Type::Uint32: case Type::Uint16: case Type::Uint8:
        case Type::Bool:
            return true;
        default:
            return false;
    }
}

inline constexpr bool is_signed_type(Type t) noexcept {
    return t == Type::Int64 || t == Type::Int32 || t == Type::Int16 || t == Type::Int8;
}

// Bytes an element of this type occupies AT MINIMUM. Mirrors epee's
// ps_min_bytes<T>::strict, including the two non-obvious ones: a STRING is 2
// (one varint byte plus at least one payload byte is not required -- epee
// simply pins 2), and an OBJECT is 1 (an empty section is one varint byte).
inline constexpr std::size_t min_element_bytes(Type t) noexcept {
    switch (t) {
        case Type::Int64:  case Type::Uint64: case Type::Double: return 8;
        case Type::Int32:  case Type::Uint32:                    return 4;
        case Type::Int16:  case Type::Uint16:                    return 2;
        case Type::Int8:   case Type::Uint8:  case Type::Bool:   return 1;
        case Type::String:                                       return 2;
        case Type::Object:                                       return 1;
        case Type::Array:                                        return 1;
    }
    return 1;
}

// Fixed on-wire width of a scalar type, or 0 for the variable-length ones.
inline constexpr std::size_t scalar_width(Type t) noexcept {
    switch (t) {
        case Type::Int64:  case Type::Uint64: case Type::Double: return 8;
        case Type::Int32:  case Type::Uint32:                    return 4;
        case Type::Int16:  case Type::Uint16:                    return 2;
        case Type::Int8:   case Type::Uint8:  case Type::Bool:   return 1;
        default:                                                 return 0;
    }
}

// --- errors ------------------------------------------------------------------
enum class StorageError : std::uint8_t {
    None = 0,
    Truncated,            // ran out of input
    BadSignature,         // the 9-byte storage header is not epee's
    BadVersion,
    BadTypeTag,           // a type byte outside 1..13
    NestedArray,          // SERIALIZE_TYPE_ARRAY: epee cannot load it either
    EmptyName,            // a zero-length key; monerod rejects on both sides
    NameTooLong,          // >= 255 bytes; monerod asserts on store
    DuplicateKey,
    DepthExceeded,
    TooManyEntries,
    TooManyObjects,
    TooManyStrings,
    StringTooLong,
    ArrayTooLarge,
    BoolOutOfRange,       // epee rejects any bool byte above 1
    VarintTooLarge,       // above the 62-bit ceiling, on the write side
    TrailingBytes,        // the body has more bytes than the storage consumed
    NotASection,          // the root, or a value used as one, is not an Object
    WrongValueKind,       // builder misuse: array element type mismatch, etc.
};

inline const char* to_string(StorageError e) noexcept {
    switch (e) {
        case StorageError::None:           return "None";
        case StorageError::Truncated:      return "Truncated";
        case StorageError::BadSignature:   return "BadSignature";
        case StorageError::BadVersion:     return "BadVersion";
        case StorageError::BadTypeTag:     return "BadTypeTag";
        case StorageError::NestedArray:    return "NestedArray";
        case StorageError::EmptyName:      return "EmptyName";
        case StorageError::NameTooLong:    return "NameTooLong";
        case StorageError::DuplicateKey:   return "DuplicateKey";
        case StorageError::DepthExceeded:  return "DepthExceeded";
        case StorageError::TooManyEntries: return "TooManyEntries";
        case StorageError::TooManyObjects: return "TooManyObjects";
        case StorageError::TooManyStrings: return "TooManyStrings";
        case StorageError::StringTooLong:  return "StringTooLong";
        case StorageError::ArrayTooLarge:  return "ArrayTooLarge";
        case StorageError::BoolOutOfRange: return "BoolOutOfRange";
        case StorageError::VarintTooLarge: return "VarintTooLarge";
        case StorageError::TrailingBytes:  return "TrailingBytes";
        case StorageError::NotASection:    return "NotASection";
        case StorageError::WrongValueKind: return "WrongValueKind";
    }
    return "?";
}

// --- decoder limits ----------------------------------------------------------
// monerod bounds recursion at 100 and leaves objects/fields/strings unbounded
// unless a caller sets them. Nothing in the P2P protocol nests deeper than 4,
// so 8 is generous; the rest are the plan's numbers (design section 1.2).
struct Limits {
    std::size_t max_depth          = 8;
    std::size_t max_entries        = 4096;      // total keys in the whole message
    std::size_t max_objects        = 4096;      // total sections
    std::size_t max_strings        = 262144;    // 2004 carries one string per tx
    std::size_t max_array_elements = 262144;    // 2010: a 4 MB hash blob is one string,
                                                // but 2004's block array is real
    std::size_t max_string_bytes   = 64u * 1024u * 1024u;
    bool        allow_trailing     = false;     // a levin body IS the storage
};

// --- the value tree ----------------------------------------------------------
// One node type for every epee shape. `is_array` turns any of them into a
// homogeneous array whose elements live in `arr` (each element carries the same
// `type` with `is_array == false`).
//
// std::vector of an incomplete type is well-defined since C++17, which is what
// lets Value hold its own children and its Entry list.
struct Entry;

class Value {
public:
    Type type     = Type::Object;
    bool is_array = false;

    // Integer and bool scalars live here as raw two's-complement bits; `type`
    // says how wide they are and whether they are signed. Keeping one field
    // (instead of a union per width) is what makes the lenient integer reads
    // below a range check rather than a nest of casts.
    std::uint64_t u = 0;
    double        d = 0.0;

    std::vector<std::uint8_t> str;   // String
    std::vector<Entry>        obj;   // Object
    std::vector<Value>        arr;   // any type, when is_array

    Value() = default;

    bool is_object() const noexcept { return type == Type::Object && !is_array; }
    bool is_string() const noexcept { return type == Type::String && !is_array; }
    bool is_scalar() const noexcept { return !is_array && scalar_width(type) != 0; }

    // Sign-extended view of an integer scalar.
    std::int64_t as_int64() const noexcept {
        switch (type) {
            case Type::Int8:  return static_cast<std::int8_t>(u & 0xffu);
            case Type::Int16: return static_cast<std::int16_t>(u & 0xffffu);
            case Type::Int32: return static_cast<std::int32_t>(u & 0xffffffffu);
            case Type::Int64: return static_cast<std::int64_t>(u);
            default:          return static_cast<std::int64_t>(u);
        }
    }
};

struct Entry {
    std::string name;
    Value       value;
};

// --- builders ----------------------------------------------------------------
inline Value v_u64(std::uint64_t x) { Value v; v.type = Type::Uint64; v.u = x; return v; }
inline Value v_u32(std::uint32_t x) { Value v; v.type = Type::Uint32; v.u = x; return v; }
inline Value v_u16(std::uint16_t x) { Value v; v.type = Type::Uint16; v.u = x; return v; }
inline Value v_u8 (std::uint8_t  x) { Value v; v.type = Type::Uint8;  v.u = x; return v; }
inline Value v_i64(std::int64_t  x) { Value v; v.type = Type::Int64;  v.u = static_cast<std::uint64_t>(x); return v; }
inline Value v_i32(std::int32_t  x) { Value v; v.type = Type::Int32;  v.u = static_cast<std::uint32_t>(x); return v; }
inline Value v_i16(std::int16_t  x) { Value v; v.type = Type::Int16;  v.u = static_cast<std::uint16_t>(x); return v; }
inline Value v_i8 (std::int8_t   x) { Value v; v.type = Type::Int8;   v.u = static_cast<std::uint8_t>(x);  return v; }
inline Value v_bool(bool x)         { Value v; v.type = Type::Bool;   v.u = x ? 1u : 0u; return v; }
inline Value v_double(double x)     { Value v; v.type = Type::Double; v.d = x; return v; }

inline Value v_blob(std::vector<std::uint8_t> bytes) {
    Value v; v.type = Type::String; v.str = std::move(bytes); return v;
}
inline Value v_str(std::string_view s) {
    Value v; v.type = Type::String;
    v.str.assign(reinterpret_cast<const std::uint8_t*>(s.data()),
                 reinterpret_cast<const std::uint8_t*>(s.data()) + s.size());
    return v;
}
inline Value v_object(std::vector<Entry> entries) {
    Value v; v.type = Type::Object; v.obj = std::move(entries); return v;
}
// `elem` is the element type tag written on the wire; every element in `values`
// must already carry it. An EMPTY array is representable here, but note fact 3
// above: monerod never emits one, and levin_messages.hpp omits the key instead.
inline Value v_array(Type elem, std::vector<Value> values) {
    Value v; v.type = elem; v.is_array = true; v.arr = std::move(values); return v;
}

// --- section lookup ----------------------------------------------------------
inline const Value* find(const Value& section, std::string_view name) noexcept {
    if (!section.is_object()) return nullptr;
    for (const Entry& e : section.obj) {
        if (e.name.size() == name.size()
            && std::memcmp(e.name.data(), name.data(), name.size()) == 0) {
            return &e.value;
        }
    }
    return nullptr;
}

// Lenient integer reads, in epee's spirit (its decoder converts between widths
// on load) but fail-closed where epee truncates: a value that does not fit the
// requested width is a REJECT, not a silent wrap. An honest peer writes the
// declared width, so the only sender that trips this is one trying to make our
// number differ from what it sent.
inline bool get_uint(const Value& section, std::string_view name, std::uint64_t& out) noexcept {
    const Value* v = find(section, name);
    if (!v || !v->is_scalar() || !is_integer_type(v->type)) return false;
    if (is_signed_type(v->type) && v->as_int64() < 0) return false;
    out = v->u;
    return true;
}

template <typename T>
inline bool get_uint_as(const Value& section, std::string_view name, T& out) noexcept {
    std::uint64_t raw = 0;
    if (!get_uint(section, name, raw)) return false;
    if (raw > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) return false;
    out = static_cast<T>(raw);
    return true;
}

inline bool get_int(const Value& section, std::string_view name, std::int64_t& out) noexcept {
    const Value* v = find(section, name);
    if (!v || !v->is_scalar() || !is_integer_type(v->type)) return false;
    out = v->as_int64();
    return true;
}

inline bool get_bool(const Value& section, std::string_view name, bool& out) noexcept {
    const Value* v = find(section, name);
    if (!v || !v->is_scalar() || !is_integer_type(v->type)) return false;
    out = (v->u != 0);
    return true;
}

inline const std::vector<std::uint8_t>* get_blob(const Value& section,
                                                 std::string_view name) noexcept {
    const Value* v = find(section, name);
    return (v && v->is_string()) ? &v->str : nullptr;
}

inline const Value* get_object(const Value& section, std::string_view name) noexcept {
    const Value* v = find(section, name);
    return (v && v->is_object()) ? v : nullptr;
}

// An array of `elem`. Returns nullptr when the key is absent or is not an array
// of that element type. Absent means EMPTY at the message layer (fact 3).
inline const Value* get_array(const Value& section, std::string_view name, Type elem) noexcept {
    const Value* v = find(section, name);
    return (v && v->is_array && v->type == elem) ? v : nullptr;
}

// --- varint ------------------------------------------------------------------
inline bool write_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    if (v <= 63) {
        out.push_back(static_cast<std::uint8_t>((v << 2) | SIZE_MARK_BYTE));
        return true;
    }
    if (v <= 16383) {
        const std::uint16_t packed = static_cast<std::uint16_t>((v << 2) | SIZE_MARK_WORD);
        out.push_back(static_cast<std::uint8_t>(packed & 0xff));
        out.push_back(static_cast<std::uint8_t>((packed >> 8) & 0xff));
        return true;
    }
    if (v <= 1073741823) {
        const std::uint32_t packed = static_cast<std::uint32_t>((v << 2) | SIZE_MARK_DWORD);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((packed >> (8 * i)) & 0xff));
        return true;
    }
    if (v > VARINT_MAX) return false;
    const std::uint64_t packed = (v << 2) | SIZE_MARK_INT64;
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((packed >> (8 * i)) & 0xff));
    return true;
}

// Byte width the encoder would use for `v` (0 when unencodable). Exposed so the
// message layer can size buffers and so the KAT can pin the mark boundaries.
inline constexpr std::size_t varint_width(std::uint64_t v) noexcept {
    if (v <= 63)         return 1;
    if (v <= 16383)      return 2;
    if (v <= 1073741823) return 4;
    if (v <= VARINT_MAX) return 8;
    return 0;
}

// --- the encoder -------------------------------------------------------------
namespace detail {

inline bool write_section_body(const Value& section,
                               std::vector<std::uint8_t>& out,
                               std::size_t depth,
                               const Limits& limits,
                               StorageError& err);

inline bool write_value(const Value& v,
                        std::vector<std::uint8_t>& out,
                        std::size_t depth,
                        const Limits& limits,
                        StorageError& err) {
    const std::uint8_t tag = static_cast<std::uint8_t>(v.type);
    if (!is_known_type(tag)) { err = StorageError::BadTypeTag; return false; }
    if (v.type == Type::Array) { err = StorageError::NestedArray; return false; }

    if (v.is_array) {
        out.push_back(static_cast<std::uint8_t>(tag | FLAG_ARRAY));
        if (!write_varint(out, v.arr.size())) { err = StorageError::VarintTooLarge; return false; }
        for (const Value& e : v.arr) {
            if (e.is_array || e.type != v.type) { err = StorageError::WrongValueKind; return false; }
            // Elements are written WITHOUT a type byte: the array's own tag
            // typed all of them.
            if (v.type == Type::String) {
                if (!write_varint(out, e.str.size())) { err = StorageError::VarintTooLarge; return false; }
                out.insert(out.end(), e.str.begin(), e.str.end());
            } else if (v.type == Type::Object) {
                if (!write_section_body(e, out, depth + 1, limits, err)) return false;
            } else if (v.type == Type::Double) {
                std::uint64_t bits = 0;
                double dv = e.d;
                std::memcpy(&bits, &dv, sizeof(bits));
                for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff));
            } else {
                const std::size_t w = scalar_width(v.type);
                for (std::size_t i = 0; i < w; ++i)
                    out.push_back(static_cast<std::uint8_t>((e.u >> (8 * i)) & 0xff));
            }
        }
        return true;
    }

    out.push_back(tag);
    if (v.type == Type::String) {
        if (!write_varint(out, v.str.size())) { err = StorageError::VarintTooLarge; return false; }
        out.insert(out.end(), v.str.begin(), v.str.end());
        return true;
    }
    if (v.type == Type::Object) {
        return write_section_body(v, out, depth + 1, limits, err);
    }
    if (v.type == Type::Double) {
        std::uint64_t bits = 0;
        double dv = v.d;
        std::memcpy(&bits, &dv, sizeof(bits));
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((bits >> (8 * i)) & 0xff));
        return true;
    }
    const std::size_t w = scalar_width(v.type);
    for (std::size_t i = 0; i < w; ++i)
        out.push_back(static_cast<std::uint8_t>((v.u >> (8 * i)) & 0xff));
    return true;
}

inline bool write_section_body(const Value& section,
                               std::vector<std::uint8_t>& out,
                               std::size_t depth,
                               const Limits& limits,
                               StorageError& err) {
    if (!section.is_object()) { err = StorageError::NotASection; return false; }
    if (depth > limits.max_depth) { err = StorageError::DepthExceeded; return false; }

    // Fact 1: monerod's section is a std::map, so the wire order is the sorted
    // key order. Sorting a copy of the index keeps the caller's Value untouched.
    std::vector<const Entry*> ordered;
    ordered.reserve(section.obj.size());
    for (const Entry& e : section.obj) ordered.push_back(&e);
    std::sort(ordered.begin(), ordered.end(),
              [](const Entry* a, const Entry* b) { return a->name < b->name; });

    for (std::size_t i = 0; i < ordered.size(); ++i) {
        if (ordered[i]->name.empty())      { err = StorageError::EmptyName;   return false; }
        if (ordered[i]->name.size() > 254) { err = StorageError::NameTooLong; return false; }
        if (i > 0 && ordered[i]->name == ordered[i - 1]->name) {
            err = StorageError::DuplicateKey;
            return false;
        }
    }

    if (!write_varint(out, ordered.size())) { err = StorageError::VarintTooLarge; return false; }
    for (const Entry* e : ordered) {
        out.push_back(static_cast<std::uint8_t>(e->name.size()));
        out.insert(out.end(), e->name.begin(), e->name.end());
        if (!write_value(e->value, out, depth, limits, err)) return false;
    }
    return true;
}

} // namespace detail

// Serialises `root` (which must be an Object) as a complete portable-storage
// body: the 9-byte header followed by the root section.
inline bool write_storage(const Value& root,
                          std::vector<std::uint8_t>& out,
                          StorageError& err,
                          const Limits& limits = Limits{}) {
    err = StorageError::None;
    if (!root.is_object()) { err = StorageError::NotASection; return false; }

    const std::size_t start = out.size();
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((SIGNATURE_A >> (8 * i)) & 0xff));
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((SIGNATURE_B >> (8 * i)) & 0xff));
    out.push_back(FORMAT_VER);

    if (!detail::write_section_body(root, out, 1, limits, err)) {
        out.resize(start);
        return false;
    }
    return true;
}

inline std::vector<std::uint8_t> write_storage_or_empty(const Value& root) {
    std::vector<std::uint8_t> out;
    StorageError err = StorageError::None;
    if (!write_storage(root, out, err)) out.clear();
    return out;
}

// --- the decoder -------------------------------------------------------------
// Everything a peer sends reaches this function first, so it is written the way
// the blob reader next door is: every read bounds-checked, no throwing path, the
// cursor never past the end, and no allocation sized on a peer's word alone.
class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size, const Limits& limits) noexcept
        : data_(data), size_(data ? size : 0), limits_(limits) {}

    std::size_t  offset()    const noexcept { return pos_; }
    std::size_t  remaining() const noexcept { return size_ - pos_; }
    StorageError error()     const noexcept { return err_; }

    bool fail(StorageError e) noexcept {
        if (err_ == StorageError::None) err_ = e;
        return false;
    }

    bool read_bytes(void* dst, std::size_t n) noexcept {
        if (err_ != StorageError::None) return false;
        if (remaining() < n) return fail(StorageError::Truncated);
        if (n) std::memcpy(dst, data_ + pos_, n);
        pos_ += n;
        return true;
    }

    bool read_byte(std::uint8_t& out) noexcept { return read_bytes(&out, 1); }

    bool read_varint(std::uint64_t& out) noexcept {
        if (err_ != StorageError::None) return false;
        if (remaining() < 1) return fail(StorageError::Truncated);
        const std::uint8_t mark = data_[pos_] & SIZE_MARK_MASK;
        std::size_t width = 0;
        switch (mark) {
            case SIZE_MARK_BYTE:  width = 1; break;
            case SIZE_MARK_WORD:  width = 2; break;
            case SIZE_MARK_DWORD: width = 4; break;
            default:              width = 8; break;   // SIZE_MARK_INT64
        }
        if (remaining() < width) return fail(StorageError::Truncated);
        std::uint64_t raw = 0;
        for (std::size_t i = 0; i < width; ++i)
            raw |= static_cast<std::uint64_t>(data_[pos_ + i]) << (8 * i);
        pos_ += width;
        // epee accepts a non-minimal encoding (a 4-byte form holding 7, say);
        // no monerod ever emits one, but rejecting would make us stricter than
        // the network, so it is accepted and simply decoded.
        out = raw >> 2;
        return true;
    }

    bool read_section(Value& out, std::size_t depth) noexcept {
        if (err_ != StorageError::None) return false;
        if (depth > limits_.max_depth) return fail(StorageError::DepthExceeded);
        if (objects_ >= limits_.max_objects) return fail(StorageError::TooManyObjects);
        ++objects_;

        std::uint64_t count = 0;
        if (!read_varint(count)) return false;
        // An entry costs at least 3 bytes (1 name length + 1 name + 1 type), so
        // a count larger than a third of what is left cannot be honest.
        if (count > remaining() / 3) return fail(StorageError::Truncated);
        if (count > limits_.max_entries - entries_) return fail(StorageError::TooManyEntries);
        entries_ += static_cast<std::size_t>(count);

        out = Value{};
        out.type = Type::Object;
        out.obj.reserve(static_cast<std::size_t>(count));

        for (std::uint64_t i = 0; i < count; ++i) {
            std::uint8_t name_len = 0;
            if (!read_byte(name_len)) return false;
            if (name_len == 0) return fail(StorageError::EmptyName);
            if (remaining() < name_len) return fail(StorageError::Truncated);

            Entry e;
            e.name.assign(reinterpret_cast<const char*>(data_ + pos_), name_len);
            pos_ += name_len;

            for (const Entry& seen : out.obj) {
                if (seen.name == e.name) return fail(StorageError::DuplicateKey);
            }
            if (!read_entry_value(e.value, depth)) return false;
            out.obj.push_back(std::move(e));
        }
        return true;
    }

private:
    bool read_scalar(Type t, Value& out) noexcept {
        const std::size_t w = scalar_width(t);
        std::uint8_t buf[8] = {0};
        if (!read_bytes(buf, w)) return false;
        out = Value{};
        out.type = t;
        if (t == Type::Double) {
            std::uint64_t bits = 0;
            for (std::size_t i = 0; i < 8; ++i) bits |= static_cast<std::uint64_t>(buf[i]) << (8 * i);
            double dv = 0.0;
            std::memcpy(&dv, &bits, sizeof(dv));
            out.d = dv;
            return true;
        }
        std::uint64_t raw = 0;
        for (std::size_t i = 0; i < w; ++i) raw |= static_cast<std::uint64_t>(buf[i]) << (8 * i);
        if (t == Type::Bool && raw > 1) return fail(StorageError::BoolOutOfRange);
        out.u = raw;
        return true;
    }

    bool read_string(Value& out) noexcept {
        if (strings_ >= limits_.max_strings) return fail(StorageError::TooManyStrings);
        ++strings_;
        std::uint64_t len = 0;
        if (!read_varint(len)) return false;
        if (len > limits_.max_string_bytes) return fail(StorageError::StringTooLong);
        if (len > remaining()) return fail(StorageError::Truncated);
        out = Value{};
        out.type = Type::String;
        out.str.assign(data_ + pos_, data_ + pos_ + static_cast<std::size_t>(len));
        pos_ += static_cast<std::size_t>(len);
        return true;
    }

    bool read_typed(Type t, Value& out, std::size_t depth) noexcept {
        if (t == Type::Object) return read_section(out, depth + 1);
        if (t == Type::String) return read_string(out);
        if (t == Type::Array)  return fail(StorageError::NestedArray);
        return read_scalar(t, out);
    }

    bool read_array(Type elem, Value& out, std::size_t depth) noexcept {
        // epee reaches this for SERIALIZE_TYPE_ARRAY|FLAG too, and then throws
        // "Reading array entry is not supported" from read(array_entry&). We
        // reject earlier and by name.
        if (elem == Type::Array) return fail(StorageError::NestedArray);

        std::uint64_t count = 0;
        if (!read_varint(count)) return false;
        // epee's own pre-allocation guard, verbatim: an array cannot claim more
        // elements than the remaining bytes could possibly hold.
        if (count > remaining() / min_element_bytes(elem)) return fail(StorageError::Truncated);
        if (count > limits_.max_array_elements) return fail(StorageError::ArrayTooLarge);

        out = Value{};
        out.type     = elem;
        out.is_array = true;
        // Reserve in a bounded chunk rather than on the peer's number: a 4 MB
        // frame may legitimately declare a six-figure element count, and
        // reserving for it up front is the allocation this whole class exists
        // to refuse. The vector grows as elements actually arrive.
        out.arr.reserve(static_cast<std::size_t>(count < 4096 ? count : 4096));
        for (std::uint64_t i = 0; i < count; ++i) {
            Value element;
            if (!read_typed(elem, element, depth)) return false;
            out.arr.push_back(std::move(element));
        }
        return true;
    }

    bool read_entry_value(Value& out, std::size_t depth) noexcept {
        std::uint8_t tag = 0;
        if (!read_byte(tag)) return false;
        const bool arr = (tag & FLAG_ARRAY) != 0;
        const std::uint8_t base = static_cast<std::uint8_t>(tag & ~FLAG_ARRAY);
        if (!is_known_type(base)) return fail(StorageError::BadTypeTag);
        const Type t = static_cast<Type>(base);
        if (arr) return read_array(t, out, depth);
        if (t == Type::Array) {
            // A bare tag 13 means "an array entry follows"; epee then requires
            // the ARRAY flag on the next byte and ends up in the unsupported
            // read(array_entry&). Nothing in the P2P protocol uses it.
            return fail(StorageError::NestedArray);
        }
        return read_typed(t, out, depth);
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t         size_ = 0;
    std::size_t         pos_  = 0;
    Limits              limits_{};
    StorageError        err_  = StorageError::None;
    std::size_t         entries_ = 0;
    std::size_t         objects_ = 0;
    std::size_t         strings_ = 0;
};

// Parses a complete portable-storage body into `root`. `consumed`, when given,
// receives the number of bytes the storage occupied (useful when a caller
// deliberately allows trailing bytes).
inline bool read_storage(const std::uint8_t* data,
                         std::size_t         size,
                         Value&              root,
                         StorageError&       err,
                         const Limits&       limits   = Limits{},
                         std::size_t*        consumed = nullptr) {
    err = StorageError::None;
    if (!data || size < STORAGE_HEADER_SIZE) { err = StorageError::Truncated; return false; }

    std::uint32_t sig_a = 0, sig_b = 0;
    for (int i = 3; i >= 0; --i) sig_a = (sig_a << 8) | data[static_cast<std::size_t>(i)];
    for (int i = 3; i >= 0; --i) sig_b = (sig_b << 8) | data[4 + static_cast<std::size_t>(i)];
    if (sig_a != SIGNATURE_A || sig_b != SIGNATURE_B) { err = StorageError::BadSignature; return false; }
    if (data[8] != FORMAT_VER) { err = StorageError::BadVersion; return false; }

    Reader r(data + STORAGE_HEADER_SIZE, size - STORAGE_HEADER_SIZE, limits);
    Value parsed;
    if (!r.read_section(parsed, 1)) { err = r.error(); return false; }
    if (!limits.allow_trailing && r.remaining() != 0) { err = StorageError::TrailingBytes; return false; }

    if (consumed) *consumed = STORAGE_HEADER_SIZE + r.offset();
    root = std::move(parsed);
    return true;
}

inline bool read_storage(const std::vector<std::uint8_t>& body,
                         Value&                           root,
                         StorageError&                    err,
                         const Limits&                    limits = Limits{}) {
    return read_storage(body.data(), body.size(), root, err, limits, nullptr);
}

} // namespace c2pool::xmr::native::epee
