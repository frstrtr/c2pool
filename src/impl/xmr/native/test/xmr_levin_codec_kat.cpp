// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_levin_codec_kat.cpp
//
// K-C1-1: the 33-byte levin bucket header.
//
// The goldens here are derived from the field layout in
// contrib/epee/include/net/levin_base.h (packed struct, little-endian) rather
// than captured, so they are an independent check on the encoder rather than a
// photograph of its output. A real monerod capture is owed as U5 and belongs to
// the C6 parity rig; what this KAT pins is everything provable offline:
// byte layout, the frame classification table, and the inbound size caps.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "impl/xmr/native/p2p/levin_codec.hpp"
#include "xmr_p2p_kat_util.hpp"

using namespace c2pool::xmr::native::levin;
using namespace c2pool::xmr::native::kat;

// ---------------------------------------------------------------------------
// 1. Byte layout.
static void test_header_goldens() {
    // A NOTIFY_NEW_FLUFFY_BLOCK notification with a 5-byte body.
    //   signature            01 21 01 01 01 01 01 01   (0x0101010101012101 LE)
    //   cb = 5               05 00 00 00 00 00 00 00
    //   have_to_return_data  00
    //   command = 2008       d8 07 00 00
    //   return_code = 0      00 00 00 00
    //   flags = REQUEST      01 00 00 00
    //   protocol_version = 1 01 00 00 00
    const std::vector<std::uint8_t> body{0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const std::vector<std::uint8_t> want = from_hex(
        "0121010101010101"
        "0500000000000000"
        "00"
        "d8070000"
        "00000000"
        "01000000"
        "01000000"
        "aabbccddee");
    check_bytes(make_notify(CMD_NEW_FLUFFY_BLOCK, body), want, "2008 notify frame golden");

    // The same command as an INVOKE differs only in the have_to_return_data
    // byte -- there is no request id anywhere in the header, which is why
    // responses can only be matched by arrival order.
    const std::vector<std::uint8_t> invoke = make_invoke(CMD_HANDSHAKE, {});
    checkf(invoke.size() == HEADER_SIZE, "empty invoke is exactly a header, got %zu", invoke.size());
    check(invoke[16] == 1, "invoke sets have_to_return_data");
    check(from_hex("e9030000") == std::vector<std::uint8_t>(invoke.begin() + 17, invoke.begin() + 21),
          "1001 encodes little-endian in the command field");

    // A response carries the flag and a return code, and never asks for one.
    const std::vector<std::uint8_t> resp = make_response(CMD_TIMED_SYNC, {}, RC_ERROR_FORMAT);
    check(resp[16] == 0, "response never sets have_to_return_data");
    check(get_u32_le(resp.data() + 25) == PACKET_RESPONSE, "response sets the RESPONSE flag");
    check(static_cast<std::int32_t>(get_u32_le(resp.data() + 21)) == RC_ERROR_FORMAT,
          "LEVIN_ERROR_FORMAT survives the round trip as -7");
}

// ---------------------------------------------------------------------------
// 2. Round trip over every flag combination that can appear.
static void test_round_trip() {
    HeaderPolicy p;
    p.handshaked      = true;
    p.accept_fragments = true;

    const std::uint32_t flag_sets[] = {
        PACKET_REQUEST,
        PACKET_RESPONSE,
        PACKET_REQUEST | PACKET_RESPONSE,
        PACKET_BEGIN,
        PACKET_END,
        PACKET_BEGIN | PACKET_END,
        0,
    };
    for (std::uint32_t flags : flag_sets) {
        for (bool expect : {false, true}) {
            BucketHead h;
            h.cb                  = 1234;
            h.have_to_return_data = expect;
            h.command             = CMD_RESPONSE_CHAIN_ENTRY;
            h.return_code         = -4;
            h.flags               = flags;

            std::vector<std::uint8_t> bytes;
            write_header(h, bytes);
            checkf(bytes.size() == HEADER_SIZE, "header is 33 bytes for flags %u", flags);

            BucketHead back;
            HeaderError err = HeaderError::None;
            const bool ok = read_header(bytes.data(), bytes.size(), p, back, err);
            checkf(ok, "round trip parses for flags %u: %s", flags, to_string(err));
            if (!ok) continue;
            checkf(back.cb == h.cb && back.command == h.command
                       && back.return_code == h.return_code && back.flags == h.flags
                       && back.have_to_return_data == h.have_to_return_data
                       && back.protocol_version == PROTOCOL_VER_1,
                   "every field survives for flags %u", flags);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Frame classification, exactly as levin_protocol_handler_async.h dispatches.
static void test_classification() {
    struct Row { std::uint32_t flags; bool expect_response; FrameClass want; const char* why; };
    const Row rows[] = {
        {PACKET_REQUEST,                 false, FrameClass::Notify,         "REQUEST without a return is a notification"},
        {PACKET_REQUEST,                 true,  FrameClass::Invoke,         "REQUEST with a return is an invoke"},
        {PACKET_RESPONSE,                false, FrameClass::Response,       "RESPONSE answers the oldest invoke"},
        {PACKET_REQUEST | PACKET_RESPONSE, true, FrameClass::Response,      "RESPONSE wins when both bits are set"},
        {PACKET_BEGIN | PACKET_END,      false, FrameClass::Noise,          "BEGIN|END is white noise and is skipped"},
        {PACKET_BEGIN,                   false, FrameClass::FragmentBegin,  "BEGIN alone opens a fragment run"},
        {PACKET_END,                     false, FrameClass::FragmentEnd,    "END alone closes a fragment run"},
        {0,                              false, FrameClass::FragmentMiddle, "neither bit is a middle fragment"},
    };
    for (const Row& r : rows) {
        BucketHead h;
        h.flags = r.flags;
        h.have_to_return_data = r.expect_response;
        checkf(classify(h) == r.want, "%s (got %s)", r.why, frame_class_name(classify(h)));
    }
}

// ---------------------------------------------------------------------------
// 4. The inbound cap table (R-CAPS).
static void test_caps() {
    // monerod's own numbers where we adopt them.
    check(max_body_bytes(CMD_HANDSHAKE,  true) == 64u * 1024u,  "1001 cap is 64 KiB");
    check(max_body_bytes(CMD_TIMED_SYNC, true) == 64u * 1024u,  "1002 cap is 64 KiB");
    check(max_body_bytes(CMD_PING,       true) == 4096,         "1003 cap is 4 KiB");
    check(max_body_bytes(CMD_RESPONSE_CHAIN_ENTRY, true) == 4u * 1024u * 1024u, "2007 cap is 4 MiB");
    check(max_body_bytes(CMD_NEW_FLUFFY_BLOCK,     true) == 4u * 1024u * 1024u, "2008 cap is 4 MiB");

    // Ours, deliberately below monerod's, because a pool never legitimately
    // receives a 100 MB frame.
    check(max_body_bytes(CMD_NEW_TRANSACTIONS, true) < 128u * 1024u * 1024u,
          "2002 is capped far below monerod's 128 MB");
    check(max_body_bytes(CMD_RESPONSE_GET_OBJECTS, true) < 128u * 1024u * 1024u,
          "2004 is capped far below monerod's 128 MB");
    check(max_body_bytes(CMD_REQUEST_GET_OBJECTS, true) == 4096,
          "2003 is 100 ids of 32 bytes plus a little, not monerod's 2 MB");

    // Unknown commands are refused outright: 1004..1006 are unsupported by
    // modern daemons too, so nothing legitimate is lost.
    check(max_body_bytes(1004, true) == 0, "1004 is not a command we speak");
    check(max_body_bytes(2005, true) == 0, "2005 does not exist");
    check(max_body_bytes(9999, true) == 0, "an invented command is refused");

    // Pre-handshake, the packet ceiling clamps everything.
    check(max_body_bytes(CMD_RESPONSE_CHAIN_ENTRY, false) == MONEROD_INITIAL_MAX_PACKET_SIZE,
          "pre-handshake the 256 KiB ceiling clamps a 4 MiB command");
    check(max_body_bytes(CMD_PING, false) == 4096,
          "the smaller of the two always wins");

    check(command_allowed_pre_handshake(CMD_HANDSHAKE), "the handshake itself is legal early");
    check(command_allowed_pre_handshake(CMD_REQUEST_SUPPORT_FLAGS),
          "a peer may ask for support flags before we finish");
    check(!command_allowed_pre_handshake(CMD_NEW_FLUFFY_BLOCK),
          "a block push before the handshake is not");
}

// ---------------------------------------------------------------------------
// 5. Every rejection path. A malformed header closes the socket; the reader
//    never rescans for a signature, so each of these must be detected on the
//    first 33 bytes.
static void test_rejections() {
    HeaderPolicy p;
    p.handshaked = true;

    BucketHead out;
    HeaderError err = HeaderError::None;

    std::vector<std::uint8_t> frame = make_notify(CMD_NEW_FLUFFY_BLOCK, {});
    check(read_header(frame.data(), frame.size(), p, out, err), "the control frame parses");

    check(!read_header(frame.data(), HEADER_SIZE - 1, p, out, err) && err == HeaderError::ShortBuffer,
          "32 bytes is not a header");

    std::vector<std::uint8_t> bad_sig = frame;
    bad_sig[0] ^= 0xff;
    check(!read_header(bad_sig.data(), bad_sig.size(), p, out, err) && err == HeaderError::BadSignature,
          "a wrong signature is fatal");

    std::vector<std::uint8_t> bad_ver = frame;
    bad_ver[29] = 2;
    check(!read_header(bad_ver.data(), bad_ver.size(), p, out, err) && err == HeaderError::BadProtocolVersion,
          "protocol version 2 is refused under the strict policy");
    HeaderPolicy lenient = p;
    lenient.strict_protocol_version = false;
    check(read_header(bad_ver.data(), bad_ver.size(), lenient, out, err),
          "and accepted when the policy says so");

    std::vector<std::uint8_t> huge = frame;
    huge[8] = 0xff; huge[9] = 0xff; huge[10] = 0xff;   // cb = 16 MiB - 1
    check(!read_header(huge.data(), huge.size(), p, out, err) && err == HeaderError::BodyTooLarge,
          "a 2008 body above 4 MiB is refused before a single body byte is read");

    std::vector<std::uint8_t> unknown = make_notify(1005, {});
    check(!read_header(unknown.data(), unknown.size(), p, out, err) && err == HeaderError::UnsupportedCommand,
          "an unsupported command is refused");

    // Fragments exist only for the tor/i2p white-noise feature. On a clearnet
    // TCP link they are either a bug or an attempt to make us buffer forever.
    std::vector<std::uint8_t> fragment = make_frame(CMD_NEW_FLUFFY_BLOCK, {}, PACKET_BEGIN, RC_OK, false);
    check(!read_header(fragment.data(), fragment.size(), p, out, err)
              && err == HeaderError::FragmentOnClearnet,
          "a fragment on clearnet is refused");
    HeaderPolicy frag_ok = p;
    frag_ok.accept_fragments = true;
    check(read_header(fragment.data(), fragment.size(), frag_ok, out, err),
          "and accepted only when a caller opts in");

    // Pre-handshake, a relay push is refused even though its cap is generous.
    HeaderPolicy fresh;
    fresh.handshaked = false;
    check(!read_header(frame.data(), frame.size(), fresh, out, err)
              && err == HeaderError::UnsupportedCommand,
          "2008 before the handshake is refused");
    std::vector<std::uint8_t> hs = make_response(CMD_HANDSHAKE, {});
    check(read_header(hs.data(), hs.size(), fresh, out, err),
          "the handshake response is the frame we expect first");
}

// ---------------------------------------------------------------------------
// 6. The little-endian helpers, since every field above depends on them.
static void test_le_helpers() {
    std::vector<std::uint8_t> v;
    put_u16_le(v, 0x1234);
    put_u32_le(v, 0x89abcdefu);
    put_u64_le(v, 0x0123456789abcdefull);
    check_bytes(v, from_hex("3412 efcdab89 efcdab8967452301"), "little-endian writers");
    check(get_u16_le(v.data()) == 0x1234, "u16 reads back");
    check(get_u32_le(v.data() + 2) == 0x89abcdefu, "u32 reads back");
    check(get_u64_le(v.data() + 6) == 0x0123456789abcdefull, "u64 reads back");
}

int main() {
    test_header_goldens();
    test_round_trip();
    test_classification();
    test_caps();
    test_rejections();
    test_le_helpers();
    return report("xmr_levin_codec_kat");
}
