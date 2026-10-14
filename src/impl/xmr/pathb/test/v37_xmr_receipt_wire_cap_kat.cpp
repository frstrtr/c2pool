// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_receipt_wire_cap_kat.cpp
// The size verdict of a receipt and a carrier frame (pathb_header_rules.hpp,
// S2.3 #1a / #1b / #9, K18), with the strike counter:
//   (1) a body of RECEIPT_MAX(D) for its D (399 + 32 D at p = 0) admitted;
//       one byte longer or shorter than the field sum STRIKE; blob_len > 78
//       STRIKE;
//   (2) D != floor(log2(n_tx + 1 + X)) at hf 16 and 17 (X 0 / 2) STRIKE;
//       n_tx above floor(2 Z(P_r) / w_min) STRIKE; a body above
//       RECEIPT_CAP(hf, P_r) (possible only with an n_tx that already fails)
//       STRIKE, and the cap judged on its own STRIKE;
//   (3) a body longer than the receipt I/O buffer and a frame longer than the
//       frame I/O buffer are DROPPED: the strike counter stays 0;
//   (4) FRAME_CAP = 6 + 2 + 17 x 913 = 15,529 (hf 16) / 14,441 (hf 17); a
//       frame above it STRIKE; the largest consensus carrier body + FH equals
//       FRAME_CAP exactly (no length prefixes);
//   (5) the default I/O buffers 945 / 16,073 (hf 16) and 881 / 14,985 (hf 17);
//       check_relay_buffers refuses a start-up that lowers them; the relay and
//       admission budgets are one formula;
//   (6) FH = 6 against the relay frame header (kFbReceiptsHeader = FH + 1,
//       kCtxHeader = FH + 36, FB_GETCTX bytes opcode | kFbVersion | chain_id LE);
//   (7) a body with D = D_max(hf, P_view) + 1 and p = 0 passes the codec and is
//       judged by #9 on its own P_r; the D_max boundary: two nodes with D_max
//       14 / 15 and a D 15 body valid by its own P_r: neither DROPS it, neither
//       STRIKES, the same chain-data verdict on both.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_header_rules.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace relay = ::c2pool::v37n::xmr::relay;

namespace {

std::uint64_t g_strikes = 0;  // the invalid-object budget tokens charged so far

std::optional<pb::AdmitVerdict> tally(std::optional<pb::AdmitVerdict> v) {
    if (v) g_strikes += pb::strike_tokens(*v);
    return v;
}

// #1a / #1b of a body against a receipt buffer.
std::optional<pb::AdmitVerdict> wire(const std::vector<std::uint8_t>& b, std::uint64_t buffer) {
    pb::ReceiptBodyV3 r;
    return tally(pb::wire_verdict(pb::decode_receipt_body_v3(b.data(), b.size(), pb::ReceiptLimits{buffer}, r)));
}

// #9 of a decoded body on its own P_r.
std::optional<pb::AdmitVerdict> row9(const pb::ReceiptBodyV3& r, std::uint64_t len, const pb::HeaderInputs& in) {
    return tally(pb::header_fields_verdict(pb::header_fields(r, len, in)));
}

// A body whose header passes the header rules at hf with no median (major hf,
// voting hf).
pb::ReceiptBodyV3 at_hf(pb::ReceiptBodyV3 r, std::uint8_t hf) {
    r.blob.major = hf;
    r.blob.minor = hf;
    return r;
}

}  // namespace

int main() {
    std::printf("v37_xmr_receipt_wire_cap_kat\n");
    const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
    const pb::RelayBuffers buf16 = pb::relay_buffers_default(16, 0, r_max).value_or(pb::RelayBuffers{});
    const pb::RelayBuffers buf17 = pb::relay_buffers_default(17, 0, r_max).value_or(pb::RelayBuffers{});
    const pb::HeaderInputs in16{16, std::nullopt, 300000, 300000};

    // (1) #1b: the field sum
    {
        std::uint64_t before = g_strikes;
        for (std::size_t d : {0u, 2u, 8u, 14u}) {
            const std::vector<std::uint8_t> full = enc(make_max_body(d, true));
            const std::vector<std::uint8_t> nofee = enc(make_max_body(d, false));
            check(full.size() == pb::receipt_max(d) && !wire(full, buf16.receipt).has_value(),
                  "RECEIPT_MAX(" + std::to_string(d) + ") body admitted by #1b");
            check(nofee.size() == 399 + 32 * d && !wire(nofee, buf16.receipt).has_value(),
                  "399 + 32 D body at p = 0 admitted by #1b (D " + std::to_string(d) + ")");
        }
        check(g_strikes == before, "no token for valid bodies");
        const std::vector<std::uint8_t> body = enc(make_body(2, false, 9));
        std::vector<std::uint8_t> longer = body;
        longer.push_back(0);
        const std::vector<std::uint8_t> shorter(body.begin(), body.end() - 1);
        check(wire(longer, buf16.receipt) == pb::AdmitVerdict::Strike, "one byte longer than the field sum STRIKE");
        check(wire(shorter, buf16.receipt) == pb::AdmitVerdict::Strike, "one byte shorter than the field sum STRIKE");
        std::vector<std::uint8_t> bl = body;
        bl[0] = 79;
        check(wire(bl, buf16.receipt) == pb::AdmitVerdict::Strike, "blob_len 79 STRIKE");
        check(g_strikes == before + 3, "three strikes charged");
    }

    // (2) #9: the D rule, the n_tx rule, the cap
    {
        const std::uint64_t before = g_strikes;
        pb::ReceiptBodyV3 r16 = at_hf(make_body(2, false, 4), 16);
        r16.blob.tx_count = 6;  // D 2 at hf 16
        check(!row9(r16, enc(r16).size(), in16).has_value(), "hf 16: tx_count 6, D 2 admitted by #9");
        pb::ReceiptBodyV3 bad16 = r16;
        bad16.branch.push_back(seq32(0x90));
        check(row9(bad16, enc(bad16).size(), in16) == pb::AdmitVerdict::Strike, "hf 16: tx_count 6, D 3 STRIKE");
        const pb::HeaderInputs in17{17, std::nullopt, 625000, 625000};
        pb::ReceiptBodyV3 r17 = at_hf(make_body(3, false, 4), 17);
        r17.blob.tx_count = 6;  // D 3 at hf 17 (X 2)
        check(!row9(r17, enc(r17).size(), in17).has_value(), "hf 17: tx_count 6, D 3 admitted (X 2)");
        pb::ReceiptBodyV3 bad17 = r17;
        bad17.branch.pop_back();
        check(row9(bad17, enc(bad17).size(), in17) == pb::AdmitVerdict::Strike, "hf 17: tx_count 6, D 2 STRIKE");
        pb::ReceiptBodyV3 n411 = at_hf(make_body(8, false, 4), 16);
        n411.blob.tx_count = 412;  // 411 transactions + the miner tx, D 8
        check(!row9(n411, enc(n411).size(), in16).has_value(), "Z 300,000: n_tx 411 admitted");
        pb::ReceiptBodyV3 n412 = n411;
        n412.blob.tx_count = 413;
        check(row9(n412, enc(n412).size(), in16) == pb::AdmitVerdict::Strike, "Z 300,000: n_tx 412 STRIKE");
        // a body above RECEIPT_CAP at its own P_r: only with an n_tx that already fails
        pb::ReceiptBodyV3 big = at_hf(make_max_body(15, true), 16);
        big.blob.tx_count = 32768;  // D 15
        const std::uint64_t big_len = enc(big).size();
        check(big_len == 945 && !pb::within_receipt_cap(16, 300000, big_len), "a 945 B D 15 body is above the cap at Z_lt 300,000");
        check(pb::header_fields(big, big_len, in16) == pb::HeaderFault::TxCount
                      && row9(big, big_len, in16) == pb::AdmitVerdict::Strike,
              "above RECEIPT_CAP: its n_tx already fails, STRIKE");
        const pb::HeaderInputs cap_only{16, std::nullopt, 24000000, 300000};
        check(pb::header_fields(big, big_len, cap_only) == pb::HeaderFault::OverCap
                      && row9(big, big_len, cap_only) == pb::AdmitVerdict::Strike,
              "the cap judged on its own at Z_lt 300,000: STRIKE");
        check(g_strikes == before + 5, "five strikes charged by #9");
    }

    // (3) DROP: no verdict, no token
    {
        const std::uint64_t before = g_strikes;
        std::vector<std::uint8_t> over = enc(make_max_body(15, true));
        check(over.size() == buf16.receipt && !wire(over, buf16.receipt).has_value(),
              "a body of the receipt buffer (945 B) passes the codec");
        over.push_back(0);
        check(wire(over, buf16.receipt) == pb::AdmitVerdict::Drop, "receipt buffer + 1 byte DROPPED");
        check(tally(pb::frame_size_verdict(buf16.frame + 1, buf16.frame, pb::frame_cap(913, r_max)))
                      == pb::AdmitVerdict::Drop,
              "frame buffer + 1 byte DROPPED");
        check(tally(pb::frame_size_verdict(buf16.frame + 100000, buf16.frame, pb::frame_cap(913, r_max)))
                      == pb::AdmitVerdict::Drop,
              "a far larger frame DROPPED");
        check(g_strikes == before, "DROP charges no token: the strike counter stays 0");
        check(pb::strike_tokens(pb::AdmitVerdict::Drop) == 0 && pb::strike_tokens(pb::AdmitVerdict::Defer) == 0
                      && pb::strike_tokens(pb::AdmitVerdict::Refuse) == 0
                      && pb::strike_tokens(pb::AdmitVerdict::Duplicate) == 0,
              "DROP, DEFER, REFUSE and DUPLICATE cost no token");
    }

    // (4) FRAME_CAP
    {
        const std::uint64_t before = g_strikes;
        const std::uint64_t cap16 = pb::frame_cap(pb::receipt_cap(16, 0).value_or(0), r_max);
        const std::uint64_t cap17 = pb::frame_cap(pb::receipt_cap(17, 0).value_or(0), r_max);
        check(cap16 == 15529 && cap16 == 6 + 2 + 17 * 913, "FRAME_CAP = 6 + 2 + 17 x 913 = 15,529 (hf 16)");
        check(cap17 == 14441 && cap17 == 6 + 2 + 17 * 849, "FRAME_CAP = 6 + 2 + 17 x 849 = 14,441 (hf 17)");
        pb::CarrierBodyV3 c;
        c.own = make_max_body(14, true);
        for (std::uint64_t i = 0; i < r_max; ++i) c.carried.push_back(make_max_body(14, true));
        std::vector<std::uint8_t> body;
        check(pb::encode_carrier_body_v3(c, r_max, body) == pb::WireError::None, "the largest consensus carrier encodes");
        const std::uint64_t frame = pb::kFrameHeaderBytes + body.size();
        check(frame == cap16 && body.size() == pb::carrier_body_size(913, r_max),
              "largest consensus carrier body + FH = FRAME_CAP exactly (no length prefixes)");
        check(!tally(pb::frame_size_verdict(frame, buf16.frame, cap16)).has_value(), "a frame of FRAME_CAP admitted");
        check(tally(pb::frame_size_verdict(frame + 1, buf16.frame, cap16)) == pb::AdmitVerdict::Strike,
              "a frame of FRAME_CAP + 1 STRIKE");
        check(tally(pb::frame_size_verdict(buf16.frame, buf16.frame, cap16)) == pb::AdmitVerdict::Strike,
              "a frame of the frame buffer, above FRAME_CAP: STRIKE (not a drop)");
        check(g_strikes == before + 2, "two strikes charged by the frame cap");
    }

    // (5) I/O buffers and the one budget
    {
        check(buf16.receipt == 945 && buf16.frame == 16073, "default buffers hf 16: 945 / 16,073");
        check(buf17.receipt == 881 && buf17.frame == 14985, "default buffers hf 17: 881 / 14,985");
        check(pb::check_relay_buffers(16, 0, r_max, buf16) == pb::BufferCheck::Ok, "defaults pass check_relay_buffers");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{944, 16073}) == pb::BufferCheck::ReceiptBelowMinimum,
              "a lowered receipt buffer refused at start-up");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{945, 16072}) == pb::BufferCheck::FrameBelowMinimum,
              "a lowered frame buffer refused at start-up");
        check(pb::check_relay_buffers(17, 0, r_max, pb::RelayBuffers{880, 14985}) == pb::BufferCheck::ReceiptBelowMinimum,
              "a lowered hf 17 receipt buffer refused at start-up");
        static_assert(pb::per_receipt_budget(16, 0, 16).value() == pb::fb_receipt_budget(16, 0, 16).value());
        static_assert(pb::per_receipt_budget(17, 0, 16).value() == pb::fb_receipt_budget(17, 0, 16).value());
        check(pb::per_receipt_budget(16, 0, r_max) == std::optional<std::uint64_t>(buf16.receipt),
              "relay and admission budgets: one formula = the receipt buffer");
    }

    // (6) FH = 6 against the relay frame header
    {
        check(pb::kFrameHeaderBytes == 6, "FH = 6");
        check(relay::kFbReceiptsHeader == pb::kFrameHeaderBytes + 1, "kFbReceiptsHeader = FH + 1");
        check(relay::kCtxHeader == pb::kFrameHeaderBytes + 36, "kCtxHeader = FH + 36");
        const std::vector<std::uint8_t> f = relay::encode_getctx(0x0a0b0c0du, std::vector<relay::bytes32>(1));
        check(f.size() > pb::kFrameHeaderBytes && f[0] == relay::FB_GETCTX && f[1] == relay::kFbVersion && f[2] == 0x0d
                      && f[3] == 0x0c && f[4] == 0x0b && f[5] == 0x0a,
              "FB_GETCTX bytes: opcode | kFbVersion | chain_id LE");
    }

    // (7) the one-level margin and the D_max boundary
    {
        const std::uint64_t before = g_strikes;
        const std::uint64_t dmax = pb::d_max(16, 0).value_or(0);
        pb::ReceiptBodyV3 d15 = at_hf(make_max_body(dmax + 1, false), 16);
        d15.blob.tx_count = 32768;  // floor(log2(32,768)) = 15
        const std::vector<std::uint8_t> e = enc(d15);
        check(!wire(e, buf16.receipt).has_value(), "D = D_max(view) + 1 at p = 0 passes the codec (the margin)");
        check(row9(d15, e.size(), in16) == pb::AdmitVerdict::Strike, "... and is judged by #9 on its own P_r");
        // two nodes: Z_lt 300,000 (D_max 14) and 478,071 (D_max 15)
        const pb::RelayBuffers buf_a = pb::relay_buffers_default(16, 300000, r_max).value_or(pb::RelayBuffers{});
        const pb::RelayBuffers buf_b = pb::relay_buffers_default(16, 478071, r_max).value_or(pb::RelayBuffers{});
        check(pb::d_max(16, 300000) == std::optional<std::uint64_t>(14) && pb::d_max(16, 478071) == std::optional<std::uint64_t>(15),
              "two node views: D_max 14 and 15");
        pb::ReceiptBodyV3 b15 = at_hf(make_max_body(15, true), 16);
        b15.blob.tx_count = 32768;
        const std::vector<std::uint8_t> e15 = enc(b15);
        const pb::HeaderInputs own_pr{16, std::nullopt, 24000000, 478071};  // the receipt's own P_r
        const std::uint64_t mid = g_strikes;
        const std::optional<pb::AdmitVerdict> wa = wire(e15, buf_a.receipt);
        const std::optional<pb::AdmitVerdict> wb = wire(e15, buf_b.receipt);
        check(!wa.has_value() && !wb.has_value(), "neither node DROPS the D 15 body");
        const std::optional<pb::AdmitVerdict> va = row9(b15, e15.size(), own_pr);
        const std::optional<pb::AdmitVerdict> vb = row9(b15, e15.size(), own_pr);
        check(!va.has_value() && va == vb, "the same #9 verdict on both nodes: admitted");
        check(g_strikes == mid, "neither node issues a STRIKE");
        check(g_strikes == before + 1, "one strike in this section (the margin body on a D_max 14 P_r)");
    }

    return finish("v37_xmr_receipt_wire_cap_kat");
}
