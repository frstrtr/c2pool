// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_epee_storage_kat.cpp
//
// K-C1-2 (first half): the epee portable-storage codec.
//
// The goldens are DERIVED from the format rules in
// contrib/epee/include/storages/portable_storage_{base,to_bin,from_bin}.h --
// the size-mark varint, the type tags, the section layout -- not captured from
// a running daemon, so they check the encoder rather than photograph it. Byte
// parity against real monerod frames is owed as U5 and belongs to the C6 rig.
//
// The two facts most likely to be got wrong by an independent implementation
// have their own sections below: sections are emitted in SORTED key order
// (monerod's section is a std::map), and every bound the decoder enforces is
// one a peer would otherwise choose for us.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/epee_storage.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace E = c2pool::xmr::native::epee;
using namespace c2pool::xmr::native::kat;

// The 9-byte storage header: SIGNATURE_A, SIGNATURE_B, FORMAT_VER, all
// little-endian. 0x01011101 -> 01 11 01 01; 0x01020101 -> 01 01 02 01.
static const char* STORAGE_HEADER_HEX = "0111010101010201 01";

static std::vector<std::uint8_t> body(const std::string& section_hex) {
    return from_hex(std::string(STORAGE_HEADER_HEX) + section_hex);
}

// ---------------------------------------------------------------------------
// 1. The size-mark varint. Two bits of width selector in the low bits, the
//    value in the rest, little-endian. This is NOT the CryptoNote LEB128
//    varint that lives in consensus/xmr_blob_reader.hpp.
static void test_varint() {
    struct Row { std::uint64_t value; const char* hex; const char* why; };
    const Row rows[] = {
        {0,          "00",               "zero is one byte with mark 0"},
        {1,          "04",               "1 << 2"},
        {63,         "fc",               "63 is the last one-byte value"},
        {64,         "0101",             "64 needs the word form: (64<<2)|1 = 0x0101"},
        {16383,      "fdff",             "16383 is the last two-byte value"},
        {16384,      "02000100",         "16384 takes the dword form"},
        {1073741823, "feffffff",         "1073741823 is the last four-byte value"},
        {1073741824, "0300000001000000", "and one more needs the int64 form: (v<<2)|3 = 0x100000003"},
        {E::VARINT_MAX, "ffffffffffffffff", "the 62-bit ceiling packs to all ones"},
    };
    for (const Row& r : rows) {
        std::vector<std::uint8_t> out;
        checkf(E::write_varint(out, r.value), "varint %llu encodes", (unsigned long long)r.value);
        check_bytes(out, from_hex(r.hex), r.why);
        checkf(E::varint_width(r.value) == out.size(), "varint_width agrees for %llu",
               (unsigned long long)r.value);

        E::Reader rd(out.data(), out.size(), E::Limits{});
        std::uint64_t back = 0;
        checkf(rd.read_varint(back) && back == r.value, "varint %llu round trips",
               (unsigned long long)r.value);
    }

    std::vector<std::uint8_t> over;
    check(!E::write_varint(over, E::VARINT_MAX + 1), "a value above 62 bits is unencodable");
    check(E::varint_width(E::VARINT_MAX + 1) == 0, "and varint_width says so");

    // epee accepts a non-minimal encoding, so we do too: rejecting would make
    // us stricter than the network for no security gain.
    const std::vector<std::uint8_t> non_minimal = from_hex("1e000000");   // dword form holding 7
    E::Reader rd(non_minimal.data(), non_minimal.size(), E::Limits{});
    std::uint64_t v = 0;
    check(rd.read_varint(v) && v == 7, "a non-minimal varint decodes to its value");

    // Truncation is caught, not read past.
    const std::vector<std::uint8_t> cut = from_hex("01");   // claims the word form, one byte given
    E::Reader rd2(cut.data(), cut.size(), E::Limits{});
    check(!rd2.read_varint(v) && rd2.error() == E::StorageError::Truncated,
          "a truncated varint is refused");
}

// ---------------------------------------------------------------------------
// 2. The storage header and the empty section.
static void test_header_and_empty() {
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;
    check(E::write_storage(E::v_object({}), out, err), "an empty root section encodes");
    check_bytes(out, body("00"), "empty storage is the 9-byte header plus varint(0)");

    E::Value root;
    check(E::read_storage(out, root, err), "and parses back");
    check(root.is_object() && root.obj.empty(), "as an empty section");

    std::vector<std::uint8_t> bad = out;
    bad[5] ^= 0xff;
    check(!E::read_storage(bad, root, err) && err == E::StorageError::BadSignature,
          "a wrong signature is refused");
    bad = out;
    bad[8] = 2;
    check(!E::read_storage(bad, root, err) && err == E::StorageError::BadVersion,
          "format version 2 is refused");
    std::vector<std::uint8_t> short_body = from_hex("011101010101");
    check(!E::read_storage(short_body, root, err) && err == E::StorageError::Truncated,
          "a body shorter than the header is refused");
}

// ---------------------------------------------------------------------------
// 3. Type tags, one entry per scalar kind.
static void test_type_matrix() {
    struct Row { const char* name; E::Value v; const char* value_hex; };
    const Row rows[] = {
        {"a", E::v_i64(-2),          "01 feffffffffffffff"},
        {"a", E::v_i32(-2),          "02 feffffff"},
        {"a", E::v_i16(-2),          "03 feff"},
        {"a", E::v_i8(-2),           "04 fe"},
        {"a", E::v_u64(0x0102030405060708ull), "05 0807060504030201"},
        {"a", E::v_u32(0x01020304u), "06 04030201"},
        {"a", E::v_u16(0x0102),      "07 0201"},
        {"a", E::v_u8(0x7f),         "08 7f"},
        {"a", E::v_bool(true),       "0b 01"},
        {"a", E::v_bool(false),      "0b 00"},
        {"a", E::v_str("hi"),        "0a 08 6869"},
        {"a", E::v_object({}),       "0c 00"},
    };
    for (const Row& r : rows) {
        std::vector<std::uint8_t> out;
        E::StorageError err = E::StorageError::None;
        check(E::write_storage(E::v_object({{r.name, r.v}}), out, err), "typed entry encodes");
        // one entry, name length 1, the name, then the value
        check_bytes(out, body(std::string("04 01 61 ") + r.value_hex), E::to_string(r.v.type));

        E::Value root;
        check(E::read_storage(out, root, err), "typed entry parses");
        const E::Value* got = E::find(root, "a");
        checkf(got != nullptr && got->type == r.v.type && got->is_array == r.v.is_array,
               "type %s survives", E::to_string(r.v.type));
        if (got && E::is_integer_type(r.v.type)) {
            checkf(got->u == r.v.u, "value bits survive for %s", E::to_string(r.v.type));
            checkf(got->as_int64() == r.v.as_int64(), "sign extension agrees for %s",
                   E::to_string(r.v.type));
        }
    }

    // Doubles never appear in the P2P protocol, but the decoder must not choke
    // on one, and the bit pattern must survive.
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;
    check(E::write_storage(E::v_object({{"d", E::v_double(-0.5)}}), out, err), "a double encodes");
    E::Value root;
    check(E::read_storage(out, root, err) && E::find(root, "d")->d == -0.5, "and round trips");
}

// ---------------------------------------------------------------------------
// 4. SORTED KEY ORDER. monerod's section is a std::map<std::string, ...>, so
//    the wire order is lexicographic no matter what order the KV map declares.
//    An encoder that preserved declaration order would produce frames a daemon
//    still parses -- and would never be byte-identical to a capture, which is
//    exactly the parity check C6 is built to run.
static void test_sorted_keys() {
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;
    // Inserted b, a, c -- must come out a, b, c.
    check(E::write_storage(E::v_object({
              {"b", E::v_u8(2)},
              {"a", E::v_u8(1)},
              {"c", E::v_u8(3)},
          }), out, err),
          "a three-key section encodes");
    check_bytes(out, body("0c 01 61 08 01 01 62 08 02 01 63 08 03"),
                "entries are emitted in sorted key order, not insertion order");

    // Prefix ordering: the shorter key sorts first, which is what puts
    // cumulative_difficulty before cumulative_difficulty_top64 on the wire.
    check(std::string("cumulative_difficulty") < std::string("cumulative_difficulty_top64"),
          "a prefix sorts before its extension");
    check(std::string("cumulative_difficulty_top64") < std::string("current_height"),
          "and cumulative_* sorts before current_height");
}

// ---------------------------------------------------------------------------
// 5. Arrays: the type byte carries FLAG_ARRAY, then a count, then packed
//    elements with NO per-element type byte.
static void test_arrays() {
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;

    check(E::write_storage(E::v_object({
              {"n", E::v_array(E::Type::Uint64, {E::v_u64(1), E::v_u64(2)})},
          }), out, err),
          "a uint64 array encodes");
    check_bytes(out, body("04 01 6e 85 08 0100000000000000 0200000000000000"),
                "uint64 array: tag 0x85, varint(2), two packed words");

    out.clear();
    check(E::write_storage(E::v_object({
              {"s", E::v_array(E::Type::String, {E::v_str("ab"), E::v_str("")})},
          }), out, err),
          "a string array encodes");
    check_bytes(out, body("04 01 73 8a 08 08 6162 00"),
                "string array: each element is its own length-prefixed blob");

    out.clear();
    check(E::write_storage(E::v_object({
              {"o", E::v_array(E::Type::Object, {E::v_object({{"x", E::v_u8(7)}}), E::v_object({})})},
          }), out, err),
          "an object array encodes");
    check_bytes(out, body("04 01 6f 8c 08 04 01 78 08 07 00"),
                "object array: each element is a bare section body");

    E::Value root;
    check(E::read_storage(out, root, err), "the object array parses");
    const E::Value* arr = E::get_array(root, "o", E::Type::Object);
    check(arr != nullptr && arr->arr.size() == 2, "with two elements");
    if (arr && arr->arr.size() == 2) {
        std::uint8_t x = 0;
        check(E::get_uint_as(arr->arr[0], "x", x) && x == 7, "and the nested field reads back");
        check(arr->arr[1].obj.empty(), "the empty element stays empty");
    }
    check(E::get_array(root, "o", E::Type::String) == nullptr,
          "asking for the wrong element type does not silently succeed");
}

// ---------------------------------------------------------------------------
// 6. Nesting and the depth bound.
static void test_nesting_depth() {
    // Build a chain of n nested objects and check where the decoder stops.
    auto nested_body = [](std::size_t levels) {
        E::Value v = E::v_object({});
        for (std::size_t i = 0; i < levels; ++i) v = E::v_object({{"n", v}});
        return v;
    };

    E::Limits limits;               // max_depth 8
    for (std::size_t levels : {0u, 3u, 7u}) {
        std::vector<std::uint8_t> out;
        E::StorageError err = E::StorageError::None;
        checkf(E::write_storage(nested_body(levels), out, err), "%zu nested levels encode", levels);
        E::Value root;
        checkf(E::read_storage(out.data(), out.size(), root, err, limits),
               "%zu nested levels parse (err %s)", levels, E::to_string(err));
    }

    // Nine sections deep is one past the root-plus-eight budget.
    std::vector<std::uint8_t> deep;
    E::StorageError err = E::StorageError::None;
    E::Limits generous;
    generous.max_depth = 64;
    check(E::write_storage(nested_body(12), deep, err, generous), "twelve levels encode under a generous limit");
    E::Value root;
    check(!E::read_storage(deep.data(), deep.size(), root, err, limits)
              && err == E::StorageError::DepthExceeded,
          "twelve levels are refused at the default depth of 8");

    // The encoder is bounded too: it will not emit what it would refuse to read.
    std::vector<std::uint8_t> out;
    check(!E::write_storage(nested_body(12), out, err) && err == E::StorageError::DepthExceeded,
          "and the encoder refuses to build it in the first place");
    check(out.empty(), "a failed encode leaves no partial bytes behind");
}

// ---------------------------------------------------------------------------
// 7. Every decoder bound. Each of these is a place where a peer would
//    otherwise choose how much we allocate or how deep we recurse.
static void test_decoder_bounds() {
    E::Value root;
    E::StorageError err = E::StorageError::None;
    const E::Limits limits;

    // Duplicate keys: monerod rejects them on load (lower_bound + compare).
    std::vector<std::uint8_t> dup = body("08 01 61 08 01 01 61 08 02");
    check(!E::read_storage(dup.data(), dup.size(), root, err, limits)
              && err == E::StorageError::DuplicateKey,
          "a duplicate key is refused");

    // A zero-length name: "Section name is missing" in epee.
    std::vector<std::uint8_t> empty_name = body("04 00 08 01");
    check(!E::read_storage(empty_name.data(), empty_name.size(), root, err, limits)
              && err == E::StorageError::EmptyName,
          "a zero-length key is refused");

    // A string claiming more bytes than remain.
    std::vector<std::uint8_t> long_string = body("04 01 61 0a fc");   // len 63, nothing follows
    check(!E::read_storage(long_string.data(), long_string.size(), root, err, limits)
              && err == E::StorageError::Truncated,
          "a string longer than the body is refused before any allocation");

    // An array claiming 2^30 uint64 elements in a body of a few bytes: epee's
    // own guard is count <= remaining / min_element_bytes, mirrored here.
    std::vector<std::uint8_t> huge_array = body("04 01 61 85 feffffff");
    check(!E::read_storage(huge_array.data(), huge_array.size(), root, err, limits)
              && err == E::StorageError::Truncated,
          "an array count the body cannot afford is refused");

    // An array of EMPTY strings, at the end of the body. epee pins
    // ps_min_bytes<std::string>::strict at 2, but an empty string element is
    // one byte (a zero varint), so four of them at the tail of a body fail the
    // guard: 4 <= 4/2 is false. We mirror that REFUSAL deliberately. monerod's
    // own decoder throws on exactly this frame, which means such a frame cannot
    // travel the network in the first place; being laxer than the reference
    // decoder would buy nothing and would put us out of step with every peer.
    std::vector<std::uint8_t> empty_strings = body("04 01 61 8a 10 00 00 00 00");
    check(!E::read_storage(empty_strings.data(), empty_strings.size(), root, err, limits)
              && err == E::StorageError::Truncated,
          "an array of empty strings is refused exactly as monerod refuses it");
    // The same array with one payload byte per element is fine, which is what
    // every real message carries.
    std::vector<std::uint8_t> one_byte_strings = body("04 01 61 8a 08 04 41 04 42");
    check(E::read_storage(one_byte_strings.data(), one_byte_strings.size(), root, err, limits),
          "and the same array with non-empty elements parses");

    // A section claiming more entries than three bytes each could fill.
    std::vector<std::uint8_t> huge_section = body("feffffff");
    check(!E::read_storage(huge_section.data(), huge_section.size(), root, err, limits)
              && err == E::StorageError::Truncated,
          "an entry count the body cannot afford is refused");

    // epee rejects any bool byte above 1 outright.
    std::vector<std::uint8_t> bad_bool = body("04 01 61 0b 02");
    check(!E::read_storage(bad_bool.data(), bad_bool.size(), root, err, limits)
              && err == E::StorageError::BoolOutOfRange,
          "a bool byte of 2 is refused, exactly as epee does");

    // An unknown type tag.
    std::vector<std::uint8_t> bad_tag = body("04 01 61 0f 00");
    check(!E::read_storage(bad_tag.data(), bad_tag.size(), root, err, limits)
              && err == E::StorageError::BadTypeTag,
          "type tag 15 does not exist");

    // SERIALIZE_TYPE_ARRAY. epee's own loader throws "Reading array entry is
    // not supported" when it reaches one; nothing in the protocol uses it.
    std::vector<std::uint8_t> nested_array = body("04 01 61 8d 04");
    check(!E::read_storage(nested_array.data(), nested_array.size(), root, err, limits)
              && err == E::StorageError::NestedArray,
          "an array of arrays is refused by name");

    // Trailing bytes: a levin body IS the storage, so anything after it is a
    // framing error rather than padding.
    std::vector<std::uint8_t> trailing = body("00 ff");
    check(!E::read_storage(trailing.data(), trailing.size(), root, err, limits)
              && err == E::StorageError::TrailingBytes,
          "trailing bytes are refused");
    E::Limits allow = limits;
    allow.allow_trailing = true;
    std::size_t consumed = 0;
    check(E::read_storage(trailing.data(), trailing.size(), root, err, allow, &consumed)
              && consumed == trailing.size() - 1,
          "and reported exactly when a caller opts in");

    // The entry ceiling.
    E::Limits tight = limits;
    tight.max_entries = 2;
    std::vector<std::uint8_t> three = body("0c 01 61 08 01 01 62 08 02 01 63 08 03");
    check(!E::read_storage(three.data(), three.size(), root, err, tight)
              && err == E::StorageError::TooManyEntries,
          "the total entry ceiling is enforced");
}

// ---------------------------------------------------------------------------
// 8. Encoder-side refusals. The encoder will not produce a frame the decoder
//    would reject, which is what keeps a bug on our side from becoming a ban.
static void test_encoder_refusals() {
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;

    check(!E::write_storage(E::v_object({{"a", E::v_u8(1)}, {"a", E::v_u8(2)}}), out, err)
              && err == E::StorageError::DuplicateKey,
          "a duplicate key is refused on encode too");

    err = E::StorageError::None;
    check(!E::write_storage(E::v_object({{"", E::v_u8(1)}}), out, err)
              && err == E::StorageError::EmptyName,
          "an empty key is refused on encode");

    err = E::StorageError::None;
    check(!E::write_storage(E::v_object({{std::string(255, 'x'), E::v_u8(1)}}), out, err)
              && err == E::StorageError::NameTooLong,
          "a 255-byte key does not fit the length byte monerod asserts on");

    err = E::StorageError::None;
    check(E::write_storage(E::v_object({{std::string(254, 'x'), E::v_u8(1)}}), out, err),
          "254 bytes is the longest key that does");

    err = E::StorageError::None;
    check(!E::write_storage(E::v_u8(1), out, err) && err == E::StorageError::NotASection,
          "the root must be a section");

    // An array whose elements do not carry its own element type is a builder
    // bug; it is caught rather than silently written as garbage.
    err = E::StorageError::None;
    E::Value mixed = E::v_array(E::Type::Uint64, {E::v_u64(1), E::v_u8(2)});
    check(!E::write_storage(E::v_object({{"a", mixed}}), out, err)
              && err == E::StorageError::WrongValueKind,
          "a heterogeneous array is refused");
}

// ---------------------------------------------------------------------------
// 9. Lenient integer reads, fail-closed on range.
static void test_integer_reads() {
    std::vector<std::uint8_t> out;
    E::StorageError err = E::StorageError::None;
    check(E::write_storage(E::v_object({
              {"small", E::v_u16(300)},
              {"big",   E::v_u64(70000)},
              {"neg",   E::v_i32(-1)},
              {"flag",  E::v_bool(true)},
          }), out, err),
          "the mixed-width section encodes");
    E::Value root;
    check(E::read_storage(out, root, err), "and parses");

    // epee converts between widths on read; so do we, when the value fits.
    std::uint64_t wide = 0;
    check(E::get_uint(root, "small", wide) && wide == 300, "a u16 reads as a u64");
    std::uint32_t narrow = 0;
    check(E::get_uint_as(root, "big", narrow) && narrow == 70000, "a u64 that fits reads as a u32");

    // Where epee truncates, we refuse: an honest peer writes the declared
    // width, so the only sender that trips this is one trying to make our
    // number differ from the one it sent.
    std::uint16_t too_small = 0;
    check(!E::get_uint_as(root, "big", too_small), "a u64 that does not fit a u16 is refused");

    std::uint64_t as_unsigned = 0;
    check(!E::get_uint(root, "neg", as_unsigned), "a negative value never reads as unsigned");
    std::int64_t signed_out = 0;
    check(E::get_int(root, "neg", signed_out) && signed_out == -1, "but reads as a signed value");

    bool flag = false;
    check(E::get_bool(root, "flag", flag) && flag, "a bool reads back");
    check(!E::get_bool(root, "absent", flag), "an absent key does not touch the output");
    check(E::get_blob(root, "small") == nullptr, "an integer is not a blob");
    check(E::find(root, "nope") == nullptr, "a missing key is a null lookup");
}

int main() {
    test_varint();
    test_header_and_empty();
    test_type_matrix();
    test_sorted_keys();
    test_arrays();
    test_nesting_depth();
    test_decoder_bounds();
    test_encoder_refusals();
    test_integer_reads();
    return report("xmr_epee_storage_kat");
}
