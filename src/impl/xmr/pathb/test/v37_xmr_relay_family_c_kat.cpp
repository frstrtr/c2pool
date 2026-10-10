// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_relay_family_c_kat.cpp
// Family C and FB_RECEIPTS v3 (pathb_relay_wire.hpp):
//   (1) FH = u8 opcode | u8 frame version | u32 chain_id LE (6 B); the frame
//       version of every opcode: 0x40, 0x41, 0x53 = 0x02; 0x50-0x52, 0x54,
//       0x55, 0x43 / 0x44, 0x48 / 0x49, 0x4c / 0x4d = 0x01; a frame with
//       another version, opcode or chain_id refused;
//   (2) FC_CARRIER: FH | carrier body; above the frame buffer (P-11): DROP;
//   (3) FC_GETCARRIER: FH | u8 n | n x id | u8 want_bodies; n 1..17 round
//       trip, n = 18 and n = 0 refused (encoder and decoder), want_bodies 2
//       refused, trailing and truncated refused;
//   (4) FC_GETHEADERS: FH | from | stop | u16 max, 72 B;
//   (5) FC_HEADERS at frame version 0x02: FH | u64 first_pos | u16 n | n x
//       header, first_pos at bytes 6..13 and n at 14..15; header = u8 ver |
//       own body | u8 n_carried | u128 cum_work_claim; round trip; a frame at
//       version 0x01 refused; n_carried above R_MAX refused; packing stops at
//       the frame bytes;
//   (6) FB_RECEIPTS at frame version 0x02: FH | u8 n | n x v3 body; n 1..17,
//       n = 18 refused; a version-0x01 frame refused; a body above the
//       receipt buffer (P-10) or a frame above P-11: DROP.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_relay_wire.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint32_t kChain = 0x0102ABCDu;
const pb::LaneParams kP = pb::kRuledLaneParams;

std::uint64_t le(const std::vector<std::uint8_t>& f, std::size_t at, std::size_t width) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i) v |= std::uint64_t{f[at + i]} << (8 * i);
    return v;
}

bool fh_is(const std::vector<std::uint8_t>& f, std::uint8_t op, std::uint8_t ver) {
    return f.size() >= 6 && f[0] == op && f[1] == ver && le(f, 2, 4) == kChain;
}

pb::RelayBuffers buffers() { return pb::relay_buffers_default(16, 300000, kP.r_max).value(); }

void frame_versions() {
    for (std::uint8_t op : {pb::kOpFbHello, pb::kOpFbReceipts, pb::kOpFcHeaders})
        check(pb::frame_version_of(op) == 0x02, "(1) frame version 0x02 for opcode " + std::to_string(op));
    for (std::uint8_t op : {pb::kOpFcCarrier, pb::kOpFcGetCarrier, pb::kOpFcGetHeaders, pb::kOpFcGetBuckets, pb::kOpFcBuckets,
                            pb::kOpFbGetCtx, pb::kOpFbCtx, pb::kOpFbPing, pb::kOpFbPong, pb::kOpFbGetAddr, pb::kOpFbAddr})
        check(pb::frame_version_of(op) == 0x01, "(1) frame version 0x01 for opcode " + std::to_string(op));
    check(!pb::frame_version_of(0x42) && !pb::frame_version_of(0x45) && !pb::frame_version_of(0x56),
          "(1) no frame version for an opcode outside the table (0x42, 0x45, 0x56)");
    check(pb::kFrameHeaderBytes == 6, "(1) FH = 6 B");
}

void fc_carrier() {
    pb::CarrierBodyV3 c;
    c.own = make_body(2, false, 0x30);
    c.carried = {make_body(1, true, 0x40), make_body(0, false, 0x50)};
    const std::optional<std::vector<std::uint8_t>> f = pb::encode_fc_carrier(kChain, c, kP.r_max);
    check(f && fh_is(*f, 0x50, 0x01), "(2) FC_CARRIER FH 0x50 | 0x01 | chain_id");
    std::vector<std::uint8_t> body;
    pb::encode_carrier_body_v3(c, kP.r_max, body);
    check(f && std::vector<std::uint8_t>(f->begin() + 6, f->end()) == body, "(2) FC_CARRIER body = the carrier body");
    const pb::RelayBuffers b = buffers();
    check(f && pb::check_fc_carrier(*f, kChain, b).ok(), "(2) FC_CARRIER FH accepted");
    check(f && pb::check_fc_carrier(*f, kChain + 1, b).error == pb::FrameWireError::ChainId, "(2) another chain_id refused");
    std::vector<std::uint8_t> v2 = *f;
    v2[1] = 0x02;
    check(pb::check_fc_carrier(v2, kChain, b).error == pb::FrameWireError::Version, "(2) FC_CARRIER at version 0x02 refused");
    std::vector<std::uint8_t> big(b.frame + 1, 0);
    big[0] = 0x50;
    big[1] = 0x01;
    check(pb::check_fc_carrier(big, kChain, b).error == pb::FrameWireError::OverBuffer, "(2) above the frame buffer (P-11): DROP");
    pb::CarrierBodyV3 over = c;
    for (int i = 0; i < 15; ++i) over.carried.push_back(make_body(0, false, static_cast<std::uint8_t>(0x60 + i)));
    check(!pb::encode_fc_carrier(kChain, over, kP.r_max), "(2) a carrier with 17 carried bodies does not encode");
}

void fc_getcarrier() {
    pb::GetCarrier q;
    q.chain_id = kChain;
    for (std::uint8_t i = 0; i < 17; ++i) q.ids.push_back(seq32(i));
    q.want_bodies = true;
    const std::optional<std::vector<std::uint8_t>> f = pb::encode_fc_getcarrier(q, kP);
    check(f && fh_is(*f, 0x51, 0x01) && f->size() == 6 + 1 + 17 * 32 + 1 && (*f)[6] == 17 && f->back() == 1,
          "(3) FC_GETCARRIER n = 17: FH | 17 | ids | 1");
    pb::GetCarrier d;
    check(f && pb::decode_fc_getcarrier(*f, kChain, kP, d).ok() && d == q, "(3) n = 17 round trip");
    pb::GetCarrier q18 = q;
    q18.ids.push_back(seq32(0x99));
    check(!pb::encode_fc_getcarrier(q18, kP), "(3) n = 18 does not encode");
    std::vector<std::uint8_t> b18 = *f;
    b18[6] = 18;
    const pb::Hash32 extra = seq32(0x99);
    b18.insert(b18.end() - 1, extra.begin(), extra.end());
    check(pb::decode_fc_getcarrier(b18, kChain, kP, d).error == pb::FrameWireError::Count, "(3) n = 18 refused");
    std::vector<std::uint8_t> b0 = {0x51, 0x01, 0xCD, 0xAB, 0x02, 0x01, 0x00, 0x00};
    check(pb::decode_fc_getcarrier(b0, kChain, kP, d).error == pb::FrameWireError::Count, "(3) n = 0 refused");
    std::vector<std::uint8_t> bad = *f;
    bad.back() = 2;
    check(pb::decode_fc_getcarrier(bad, kChain, kP, d).error == pb::FrameWireError::Flag, "(3) want_bodies 2 refused");
    std::vector<std::uint8_t> tr = *f;
    tr.push_back(0);
    check(pb::decode_fc_getcarrier(tr, kChain, kP, d).error == pb::FrameWireError::Trailing, "(3) trailing byte refused");
    std::vector<std::uint8_t> cut(f->begin(), f->end() - 1);
    check(pb::decode_fc_getcarrier(cut, kChain, kP, d).error == pb::FrameWireError::Truncated, "(3) truncated refused");
    std::vector<std::uint8_t> v2 = *f;
    v2[1] = 0x02;
    check(pb::decode_fc_getcarrier(v2, kChain, kP, d).error == pb::FrameWireError::Version, "(3) version 0x02 refused");
}

void fc_getheaders() {
    pb::GetHeaders q{kChain, seq32(0x10), seq32(0x20), 1152};
    const std::vector<std::uint8_t> f = pb::encode_fc_getheaders(q);
    check(fh_is(f, 0x52, 0x01) && f.size() == 72 && le(f, 70, 2) == 1152, "(4) FC_GETHEADERS: FH | from | stop | u16 max (72 B)");
    pb::GetHeaders d;
    check(pb::decode_fc_getheaders(f, kChain, d).ok() && d == q, "(4) round trip");
    std::vector<std::uint8_t> tr = f;
    tr.push_back(1);
    check(pb::decode_fc_getheaders(tr, kChain, d).error == pb::FrameWireError::Trailing, "(4) trailing refused");
    check(pb::decode_fc_getheaders(std::vector<std::uint8_t>(f.begin(), f.end() - 1), kChain, d).error
                  == pb::FrameWireError::Truncated,
          "(4) truncated refused");
}

pb::CarrierHeader header(std::uint8_t seed, std::uint8_t n_carried, std::uint64_t work) {
    pb::CarrierHeader h;
    h.own = make_body(1, false, seed);
    h.n_carried = n_carried;
    h.cum_work_claim = ::c2pool::xmr::native::U128{work, 7};
    return h;
}

void fc_headers() {
    pb::HeadersReply r;
    r.chain_id = kChain;
    r.first_pos = 0x0123456789ABCDEFull;
    r.headers = {header(0x11, 0, 100), header(0x22, 16, 200), header(0x33, 3, 300)};
    std::size_t packed = 0;
    const std::optional<std::vector<std::uint8_t>> f = pb::encode_fc_headers(r, 1u << 20, &packed);
    check(f && packed == 3 && fh_is(*f, 0x53, 0x02), "(5) FC_HEADERS FH 0x53 | 0x02 | chain_id");
    check(f && le(*f, 6, 8) == 0x0123456789ABCDEFull, "(5) u64 first_pos is the first field (bytes 6..13)");
    check(f && le(*f, 14, 2) == 3, "(5) u16 n follows first_pos (bytes 14..15), next to its list");
    std::vector<std::uint8_t> h0 = *pb::header_bytes(r.headers[0]);
    check(f && std::equal(h0.begin(), h0.end(), f->begin() + 16), "(5) the first header at byte 16");
    const std::vector<std::uint8_t> own0 = enc(r.headers[0].own);
    check(h0.size() == 1 + own0.size() + 1 + 16 && h0.front() == pb::kCarrierBodyVersion
                  && std::equal(own0.begin(), own0.end(), h0.begin() + 1) && h0[1 + own0.size()] == 0
                  && le(h0, 2 + own0.size(), 8) == 100 && le(h0, 10 + own0.size(), 8) == 7,
          "(5) header = u8 ver 3 | own body | u8 n_carried | u128 cum_work_claim (LE)");
    pb::HeadersReply d;
    check(f && pb::decode_fc_headers(*f, kChain, 1u << 20, kP, d).ok() && d == r, "(5) round trip");
    std::vector<std::uint8_t> v1 = *f;
    v1[1] = 0x01;
    check(pb::decode_fc_headers(v1, kChain, 1u << 20, kP, d).error == pb::FrameWireError::Version,
          "(5) FC_HEADERS at frame version 0x01 refused");
    pb::HeadersReply over = r;
    over.headers[1].n_carried = 17;
    const std::optional<std::vector<std::uint8_t>> fo = pb::encode_fc_headers(over, 1u << 20);
    check(fo && pb::decode_fc_headers(*fo, kChain, 1u << 20, kP, d).body_error == pb::WireError::CarriedCount,
          "(5) a header with n_carried 17 > R_MAX refused");
    const std::size_t one = 16 + h0.size();
    std::size_t p1 = 0;
    const std::optional<std::vector<std::uint8_t>> small = pb::encode_fc_headers(r, one, &p1);
    check(small && p1 == 1 && le(*small, 14, 2) == 1 && small->size() == one, "(5) packing stops at the frame bytes");
    check(f && pb::decode_fc_headers(*f, kChain, f->size() - 1, kP, d).error == pb::FrameWireError::OverBuffer,
          "(5) a frame above its buffer: DROP");
    std::vector<std::uint8_t> tr = *f;
    tr.push_back(0);
    check(pb::decode_fc_headers(tr, kChain, 1u << 20, kP, d).error == pb::FrameWireError::Trailing, "(5) trailing refused");
    // an empty reply: n = 0, first_pos kept
    pb::HeadersReply e;
    e.chain_id = kChain;
    e.first_pos = 5;
    const std::optional<std::vector<std::uint8_t>> fe = pb::encode_fc_headers(e, 1u << 20);
    check(fe && fe->size() == 16 && pb::decode_fc_headers(*fe, kChain, 1u << 20, kP, d).ok() && d.headers.empty()
                  && d.first_pos == 5,
          "(5) n = 0: 16 bytes");
}

void fb_receipts() {
    std::vector<pb::ReceiptBodyV3> bodies;
    for (std::uint8_t i = 0; i < 17; ++i) bodies.push_back(make_body(i % 3, i % 2 == 0, static_cast<std::uint8_t>(0x10 + i)));
    const std::optional<std::vector<std::uint8_t>> f = pb::encode_fb_receipts(kChain, bodies, kP);
    check(f && fh_is(*f, 0x41, 0x02) && (*f)[6] == 17, "(6) FB_RECEIPTS FH 0x41 | 0x02 | chain_id | n 17");
    const pb::RelayBuffers b = buffers();
    pb::ReceiptsFrame d;
    bool same = f && pb::decode_fb_receipts(*f, kChain, b, kP, d).ok() && d.bodies.size() == 17;
    for (std::size_t i = 0; same && i < 17; ++i) same = d.bodies[i] == enc(bodies[i]);
    check(same, "(6) 17 bodies round trip, each its own bytes (no length prefix)");
    std::vector<pb::ReceiptBodyV3> b18 = bodies;
    b18.push_back(make_body(0, false, 0x77));
    check(!pb::encode_fb_receipts(kChain, b18, kP), "(6) n = 18 does not encode");
    std::vector<std::uint8_t> f18 = *f;
    f18[6] = 18;
    const std::vector<std::uint8_t> extra = enc(make_body(0, false, 0x77));
    f18.insert(f18.end(), extra.begin(), extra.end());
    check(pb::decode_fb_receipts(f18, kChain, b, kP, d).error == pb::FrameWireError::Count, "(6) n = 18 refused");
    std::vector<std::uint8_t> v1 = *f;
    v1[1] = 0x01;
    check(pb::decode_fb_receipts(v1, kChain, b, kP, d).error == pb::FrameWireError::Version,
          "(6) FB_RECEIPTS at version 0x01 (v2 bodies) refused");
    pb::RelayBuffers tight = b;
    tight.receipt = enc(bodies[0]).size() - 1;
    check(pb::decode_fb_receipts(*f, kChain, tight, kP, d).error == pb::FrameWireError::OverBuffer,
          "(6) a body above the receipt buffer (P-10): DROP");
    pb::RelayBuffers small = b;
    small.frame = f->size() - 1;
    check(pb::decode_fb_receipts(*f, kChain, small, kP, d).error == pb::FrameWireError::OverBuffer,
          "(6) a frame above the frame buffer (P-11): DROP");
    std::vector<std::uint8_t> cut(f->begin(), f->end() - 1);
    check(pb::decode_fb_receipts(cut, kChain, b, kP, d).error == pb::FrameWireError::Body, "(6) a truncated body refused");
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_relay_family_c_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) fn();
    };
    run("versions", frame_versions);
    run("carrier", fc_carrier);
    run("getcarrier", fc_getcarrier);
    run("getheaders", fc_getheaders);
    run("headers", fc_headers);
    run("receipts", fb_receipts);
    return finish("v37_xmr_relay_family_c_kat");
}
