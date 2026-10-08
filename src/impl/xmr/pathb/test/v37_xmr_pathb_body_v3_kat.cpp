// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_body_v3_kat.cpp
// Receipt body v3 and carrier body v3 codecs:
//   (1) RECEIPT_MAX(D) = 465 + 32 D (721 / 913 / 977 at D 8 / 14 / 16;
//       399 + 32 D without owner_ref); the largest body encodes to exactly
//       RECEIPT_MAX(D);
//   (2) I/O buffer, consensus cap and size rules: the receipt buffer is
//       RECEIPT_MAX(D_max + 1) = 945 at v16 (881 at v17): a body of 945 B
//       accepted by the codec, one byte more dropped without a verdict
//       (OverCap); the consensus cap RECEIPT_CAP = RECEIPT_MAX(D_max) = 913 at
//       the receipt's own P_r: 913 B within, 914 B and the D 15 body above it
//       (strike) at Z_lt 300,000; D_max boundary: two nodes with D_max 14 / 15
//       and a body of D 15 valid for its P_r -> neither drops it, both judge
//       the size rules and the cap at P_r the same; check_relay_buffers
//       refuses a receipt buffer of 944 / a frame buffer of 16,072 and accepts
//       the defaults and raised values;
//       D != floor(log2(tx_count + X)) refused at v16 and v17 (X 0 / 2);
//       tx_count - 1 above floor(2 Z / w_min) refused; blob_len 79 / 71 refused;
//   (3) hashing blob: field wider than declared refused (both directions),
//       non-canonical varint refused, blob_len not matching the fields refused;
//   (4) round trip over generated bodies (give_author_bp in 0..10000 - p);
//       encode(decode(b)) == b;
//   (5) every truncation refused; mutation pass: an accepted mutant
//       re-encodes to the same bytes;
//   (6) carrier body: 0 and R_MAX carried round trip; R_MAX + 1 refused by
//       encoder and decoder (before allocation); version != 3 refused; the
//       largest carrier body at the buffer equals carrier_body_buffer
//       (2 + 17 x 945), one byte more refused;
//       trailing bytes refused; counts above the remaining bytes refused
//       without allocation;
//   (7) carrier frame: FH = 6 (u8 opcode | u8 frame version | u32 chain_id),
//       the header of the relay frames in xmr_relay_wire.hpp (FB_RECEIPTS
//       header = FH + count byte, FB_CTX header = FH + id + length, FB_GETCTX
//       bytes); frame buffer = FH + 2 + 17 x 945 = 16,073 (14,985 at v17);
//       consensus FRAME_CAP = FH + 2 + 17 x 913 = 15,529 (14,441 at v17);
//       kFbMaxReceiptsPerFrame = 1 + R_MAX = 17 (the S2 relay literal 8 is
//       superseded);
//   (8) one budget (X-6): PER_RECEIPT_BUDGET (admission) == kFbReceiptBudget
//       (relay) == the receipt I/O buffer P-10 = 945 (v16) / 881 (v17), and
//       PER_LANE_BUDGET = R_MAX x P-10; the S2 engine sizes them apart
//       (relay 1024, admission 768).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace relay = ::c2pool::v37n::xmr::relay;

namespace {

// Decode with a receipt buffer of RECEIPT_MAX(buffer_depth).
pb::WireError dec(const std::vector<std::uint8_t>& b, std::uint64_t buffer_depth, pb::ReceiptBodyV3* out = nullptr) {
    pb::ReceiptBodyV3 r;
    pb::WireError e =
            pb::decode_receipt_body_v3(b.data(), b.size(), pb::ReceiptLimits{pb::receipt_max(buffer_depth)}, r);
    if (out) *out = r;
    return e;
}

pb::WireError dec_carrier(const std::vector<std::uint8_t>& b, const pb::CarrierLimits& lim,
                          pb::CarrierBodyV3* out = nullptr) {
    pb::CarrierBodyV3 c;
    pb::WireError e = pb::decode_carrier_body_v3(b.data(), b.size(), lim, c);
    if (out) *out = c;
    return e;
}

// Encoded hashing blob with the given raw varint bytes for timestamp (others minimal).
std::vector<std::uint8_t> body_with_raw_timestamp(const pb::ReceiptBodyV3& base, const std::vector<std::uint8_t>& ts) {
    std::vector<std::uint8_t> e = enc(base);
    const std::size_t old_len = e[0];
    std::vector<std::uint8_t> blob;
    blob.push_back(static_cast<std::uint8_t>(base.blob.major));
    blob.push_back(static_cast<std::uint8_t>(base.blob.minor));
    blob.insert(blob.end(), ts.begin(), ts.end());
    // prev_id, nonce, tree_root, tx_count from the original encoding
    const std::size_t ts_len = pb::varint_len(base.blob.timestamp);
    blob.insert(blob.end(), e.begin() + 1 + 2 + static_cast<std::ptrdiff_t>(ts_len),
                e.begin() + 1 + static_cast<std::ptrdiff_t>(old_len));
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>(blob.size()));
    out.insert(out.end(), blob.begin(), blob.end());
    out.insert(out.end(), e.begin() + 1 + static_cast<std::ptrdiff_t>(old_len), e.end());
    return out;
}

}  // namespace

int main() {
    std::printf("v37_xmr_pathb_body_v3_kat\n");

    // (1) RECEIPT_MAX
    check(pb::kHashingBlobMaxBytes == 78, "hashing blob max 78 B");
    check(pb::kHashingHeaderMaxBytes == 43, "HDR_max 43 B");
    check(pb::kReceiptFixedMaxBytes == 465, "RECEIPT_MAX(0) = 465");
    check(pb::receipt_max(8) == 721, "RECEIPT_MAX(8) = 721");
    check(pb::receipt_max(14) == 913, "RECEIPT_MAX(14) = 913");
    check(pb::receipt_max(16) == 977, "RECEIPT_MAX(16) = 977");
    for (std::size_t d : {0u, 1u, 8u, 12u, 14u, 16u}) {
        const std::vector<std::uint8_t> full = enc(make_max_body(d, true));
        const std::vector<std::uint8_t> nofee = enc(make_max_body(d, false));
        check(full.size() == pb::receipt_max(d), "largest body at D " + std::to_string(d) + " = RECEIPT_MAX(D)");
        check(nofee.size() == 399 + 32 * d, "largest body without owner_ref at D " + std::to_string(d) + " = 399 + 32 D");
        check(full[0] == 78, "largest hashing blob 78 B at D " + std::to_string(d));
    }

    // (2) I/O buffer and consensus cap at D_max(16, today) = 14
    const std::uint64_t dmax = pb::d_max(16, 0).value_or(0);
    check(dmax == 14, "D_max(v16, zone) = 14");
    const pb::RelayBuffers buf16 = pb::relay_buffers_default(16, 0, pb::kRuledLaneParams.r_max).value_or(pb::RelayBuffers{});
    const pb::RelayBuffers buf17 = pb::relay_buffers_default(17, 0, pb::kRuledLaneParams.r_max).value_or(pb::RelayBuffers{});
    check(buf16.receipt == 945 && buf16.frame == 16073, "buffers v16: RECEIPT_MAX(15) = 945, 6 + 2 + 17 x 945 = 16,073");
    check(buf17.receipt == 881 && buf17.frame == 14985, "buffers v17: RECEIPT_MAX(13) = 881, 6 + 2 + 17 x 881 = 14,985");
    check(pb::receipt_cap(16, 0) == std::optional<std::uint64_t>(913) && pb::receipt_cap(17, 0) == std::optional<std::uint64_t>(849),
          "consensus RECEIPT_CAP 913 (v16) / 849 (v17)");
    {
        const pb::ReceiptLimits lim = pb::receipt_limits(buf16);
        pb::ReceiptBodyV3 got;
        const std::vector<std::uint8_t> at_buf = enc(make_max_body(dmax + 1, true));
        check(at_buf.size() == 945, "largest D 15 body is 945 B");
        check(pb::decode_receipt_body_v3(at_buf.data(), at_buf.size(), lim, got) == pb::WireError::None,
              "body of the receipt buffer (945 B) accepted by the codec");
        std::vector<std::uint8_t> plus1 = at_buf;
        plus1.push_back(0);
        check(pb::decode_receipt_body_v3(plus1.data(), plus1.size(), lim, got) == pb::WireError::OverCap
                      && pb::wire_drop_without_verdict(pb::WireError::OverCap),
              "receipt buffer + 1 byte dropped without a verdict");
        const std::vector<std::uint8_t> d16 = enc(make_max_body(dmax + 2, false));
        check(d16.size() <= pb::receipt_max(dmax + 1) && dec(d16, dmax + 1) == pb::WireError::None,
              "a D 16 body without owner_ref inside the buffer: accepted by the codec");

        // consensus cap at the receipt's own P_r
        const std::vector<std::uint8_t> at_cap = enc(make_max_body(dmax, true));
        check(at_cap.size() == 913, "body at RECEIPT_MAX(D_max) is 913 B");
        check(pb::within_receipt_cap(16, 300000, at_cap.size()) && !pb::within_receipt_cap(16, 300000, at_cap.size() + 1),
              "RECEIPT_CAP at P_r (Z_lt 300,000): 913 B within, 914 B above (strike)");
        check(!pb::within_receipt_cap(16, 300000, at_buf.size()) && pb::within_receipt_cap(16, 478071, at_buf.size()),
              "the 945 B D 15 body: above the cap at Z_lt 300,000, within it at Z_lt 478,071");
        check(!pb::within_receipt_cap(16, UINT64_MAX, 1), "Z_lt outside the domain: not within the cap");
        check(pb::within_receipt_cap(17, 0, 849) && !pb::within_receipt_cap(17, 0, 850), "v17: RECEIPT_CAP 849");

        const std::vector<std::uint8_t> small = enc(make_body(2, false, 9));
        std::vector<std::uint8_t> small_plus = small;
        small_plus.push_back(0);
        check(dec(small_plus, dmax + 1) == pb::WireError::Trailing, "trailing byte refused");

        // D_max boundary: nodes with Z_lt 300,000 (D_max 14) and 478,071 (D_max 15)
        const std::uint64_t dmax_a = pb::d_max(16, 300000).value_or(0);
        const std::uint64_t dmax_b = pb::d_max(16, 478071).value_or(0);
        check(dmax_a == 14 && dmax_b == 15, "two nodes: D_max 14 and 15");
        const pb::RelayBuffers buf_a =
                pb::relay_buffers_default(16, 300000, pb::kRuledLaneParams.r_max).value_or(pb::RelayBuffers{});
        const pb::RelayBuffers buf_b =
                pb::relay_buffers_default(16, 478071, pb::kRuledLaneParams.r_max).value_or(pb::RelayBuffers{});
        check(buf_a.receipt == 945 && buf_b.receipt == 977, "their buffers: 945 and 977");
        pb::ReceiptBodyV3 d15 = make_max_body(15, true);
        d15.blob.tx_count = 32768;  // floor(log2(32,768)) = 15
        const std::uint64_t z_pr = 24000000;
        const std::uint64_t z_lt_pr = 478071;
        const std::vector<std::uint8_t> e15 = enc(d15);
        check(e15.size() == pb::receipt_max(15), "D 15 body of RECEIPT_MAX(15)");
        const pb::WireError va = pb::decode_receipt_body_v3(e15.data(), e15.size(), pb::receipt_limits(buf_a), got);
        const pb::WireError vb = pb::decode_receipt_body_v3(e15.data(), e15.size(), pb::receipt_limits(buf_b), got);
        check(va == pb::WireError::None && vb == pb::WireError::None, "neither node drops the D 15 body");
        check(pb::receipt_size_rules(16, z_pr, d15.blob.tx_count, d15.branch.size()) == pb::SizeRule::Ok
                      && pb::within_receipt_cap(16, z_lt_pr, e15.size()),
              "size rules and the cap on the receipt's own P_r: the same verdict on both nodes");

        // start-up check
        const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
        check(pb::check_relay_buffers(16, 0, r_max, buf16) == pb::BufferCheck::Ok, "defaults pass check_relay_buffers");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{944, 16073}) == pb::BufferCheck::ReceiptBelowMinimum,
              "receipt buffer 944 refused");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{945, 16072}) == pb::BufferCheck::FrameBelowMinimum,
              "frame buffer 16,072 refused");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{913, 15529}) == pb::BufferCheck::ReceiptBelowMinimum,
              "buffers at the consensus caps (913 / 15,529) refused");
        check(pb::check_relay_buffers(16, 0, r_max, pb::RelayBuffers{2000, 40000}) == pb::BufferCheck::Ok,
              "raised buffers accepted");
        check(pb::check_relay_buffers(16, 478071, r_max, buf16) == pb::BufferCheck::ReceiptBelowMinimum,
              "re-run after the view moves to D_max 15: the old 945 B buffer refused");
        check(pb::check_relay_buffers(17, 0, r_max, buf17) == pb::BufferCheck::Ok, "v17 defaults pass");
        check(pb::check_relay_buffers(16, UINT64_MAX, r_max, buf16) == pb::BufferCheck::ViewOutOfDomain,
              "view outside the domain refused");

        // size rules
        check(pb::receipt_size_rules(16, 300000, 6, 2) == pb::SizeRule::Ok, "v16: tx_count 6 -> D 2");
        check(pb::receipt_size_rules(16, 300000, 6, 3) == pb::SizeRule::Depth, "v16: tx_count 6, D 3 refused");
        check(pb::receipt_size_rules(17, 625000, 6, 2) == pb::SizeRule::Depth, "v17: tx_count 6, D 2 refused (X 2)");
        check(pb::receipt_size_rules(17, 625000, 6, 3) == pb::SizeRule::Ok, "v17: tx_count 6 -> D 3");
        check(pb::receipt_size_rules(16, 300000, 1, 0) == pb::SizeRule::Ok, "v16: miner tx only -> D 0");
        check(pb::receipt_size_rules(17, 625000, 1, 1) == pb::SizeRule::Ok, "v17: miner tx only -> D 1");
        check(pb::receipt_size_rules(16, 300000, 0, 0) == pb::SizeRule::TxCount, "tx_count 0 refused");
        check(pb::receipt_size_rules(16, 300000, 412, 8) == pb::SizeRule::Ok, "Z 300,000: 411 transactions accepted");
        check(pb::receipt_size_rules(16, 300000, 413, 8) == pb::SizeRule::TxCount, "Z 300,000: 412 transactions refused");
        check(pb::receipt_size_rules(16, UINT64_MAX, 1, 0) == pb::SizeRule::TxCount, "Z outside the u64 domain refused");

        std::vector<std::uint8_t> b = small;
        b[0] = 79;
        check(dec(b, dmax + 1) == pb::WireError::BlobLength, "blob_len 79 refused");
        b[0] = 71;
        check(dec(b, dmax + 1) == pb::WireError::BlobLength, "blob_len 71 refused");
        b[0] = static_cast<std::uint8_t>(small[0] - 1);
        check(dec(b, dmax + 1) != pb::WireError::None, "blob_len one short of the fields refused");
        b[0] = static_cast<std::uint8_t>(small[0] + 1);
        check(dec(b, dmax + 1) != pb::WireError::None, "blob_len one over the fields refused");
    }

    // (3) hashing blob field widths and varints
    {
        pb::ReceiptBodyV3 base = make_body(1, false, 4);
        std::vector<std::uint8_t> sink;
        pb::ReceiptBodyV3 wide = base;
        wide.blob.timestamp = 1ull << 35;  // 6 B varint
        check(pb::encode_receipt_body_v3(wide, sink) == pb::WireError::Unencodable && sink.empty(),
              "encoder refuses a 6-byte timestamp");
        wide = base;
        wide.blob.major = 128;  // 2 B varint
        check(pb::encode_receipt_body_v3(wide, sink) == pb::WireError::Unencodable, "encoder refuses a 2-byte major");
        wide = base;
        wide.blob.tx_count = 1ull << 21;  // 4 B varint
        check(pb::encode_receipt_body_v3(wide, sink) == pb::WireError::Unencodable, "encoder refuses a 4-byte tx_count");
        wide = base;
        wide.branch.resize(256);
        check(pb::encode_receipt_body_v3(wide, sink) == pb::WireError::Unencodable, "encoder refuses depth 256");

        // 6-byte timestamp varint on the wire
        const std::vector<std::uint8_t> ts6 = {0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
        check(dec(body_with_raw_timestamp(base, ts6), 1) == pb::WireError::BlobField, "6-byte timestamp varint refused");
        // non-canonical 5-byte encoding of a small timestamp
        const std::vector<std::uint8_t> ts_nc = {0x81, 0x80, 0x80, 0x80, 0x00};
        check(dec(body_with_raw_timestamp(base, ts_nc), 1) == pb::WireError::BlobField,
              "non-canonical timestamp varint refused");
        // canonical 5-byte timestamp
        const std::vector<std::uint8_t> ts5 = {0x81, 0x80, 0x80, 0x80, 0x01};
        pb::ReceiptBodyV3 got;
        check(dec(body_with_raw_timestamp(base, ts5), 1, &got) == pb::WireError::None
                      && got.blob.timestamp == (1ull + (1ull << 28)),
              "canonical 5-byte timestamp varint accepted");
    }

    // (4) round trip over generated bodies
    {
        Rng rng(0x5eed);
        bool all_ok = true;
        for (int i = 0; i < 400; ++i) {
            const std::size_t depth = rng.below(17);
            const bool owner = rng.below(2) != 0;
            pb::ReceiptBodyV3 b = make_body(depth, owner, static_cast<std::uint8_t>(rng.below(256)));
            b.blob.major = rng.below(128);
            b.blob.minor = rng.below(128);
            b.blob.timestamp = rng.below(1ull << 35);
            b.blob.tx_count = rng.below(1ull << 21);
            b.reward_total = rng.next();
            if (owner) b.side.fee_rate_bp = static_cast<std::uint16_t>(1 + rng.below(10000));
            b.side.give_author_bp = static_cast<std::uint16_t>(rng.below(10001u - b.side.fee_rate_bp));  // 0..10000 - p
            const std::vector<std::uint8_t> e = enc(b);
            pb::ReceiptBodyV3 back;
            if (e.empty() || dec(e, 16, &back) != pb::WireError::None || !(back == b) || enc(back) != e)
                all_ok = false;
        }
        check(all_ok, "400 generated bodies: decode(encode(x)) == x and encode(decode(b)) == b");
    }

    // (5) truncation and mutation
    {
        const std::vector<std::uint8_t> e = enc(make_body(5, true, 21));
        bool trunc_ok = true;
        for (std::size_t n = 0; n < e.size(); ++n) {
            std::vector<std::uint8_t> t(e.begin(), e.begin() + static_cast<std::ptrdiff_t>(n));
            if (dec(t, 16) == pb::WireError::None) trunc_ok = false;
        }
        check(trunc_ok, "every truncation of a receipt body refused");

        Rng rng(0xfeed);
        bool canonical = true;
        int accepted = 0;
        for (int i = 0; i < 20000; ++i) {
            std::vector<std::uint8_t> m = e;
            const int flips = 1 + static_cast<int>(rng.below(3));
            for (int f = 0; f < flips; ++f) m[rng.below(m.size())] ^= static_cast<std::uint8_t>(1 + rng.below(255));
            pb::ReceiptBodyV3 got;
            if (dec(m, 16, &got) == pb::WireError::None) {
                ++accepted;
                if (enc(got) != m) canonical = false;
            }
        }
        check(canonical, "every accepted mutant re-encodes to its own bytes (" + std::to_string(accepted) + " accepted)");
    }

    // (6) carrier body
    {
        const pb::CarrierLimits lim = pb::carrier_limits(buf16, pb::kRuledLaneParams.r_max);
        check(pb::carrier_body_buffer(lim) == 1 + 945 + 1 + 16 * 945, "carrier_body_buffer = 2 + 17 x 945");

        pb::CarrierBodyV3 c0;
        c0.own = make_body(3, true, 1);
        std::vector<std::uint8_t> e0;
        check(pb::encode_carrier_body_v3(c0, lim.r_max, e0) == pb::WireError::None, "carrier with 0 carried encodes");
        check(e0[0] == 3, "carrier body version byte 3");
        pb::CarrierBodyV3 back;
        check(dec_carrier(e0, lim, &back) == pb::WireError::None && back == c0, "carrier with 0 carried round trip");

        pb::CarrierBodyV3 cmax;
        cmax.own = make_max_body(dmax + 1, true);
        for (std::uint64_t i = 0; i < lim.r_max; ++i) cmax.carried.push_back(make_max_body(dmax + 1, true));
        std::vector<std::uint8_t> emax;
        check(pb::encode_carrier_body_v3(cmax, lim.r_max, emax) == pb::WireError::None, "carrier with R_MAX carried encodes");
        check(emax.size() == pb::carrier_body_buffer(lim), "largest carrier body equals carrier_body_buffer");
        check(dec_carrier(emax, lim, &back) == pb::WireError::None && back == cmax, "carrier with R_MAX carried round trip");
        std::vector<std::uint8_t> emax1 = emax;
        emax1.push_back(0);
        check(dec_carrier(emax1, lim) == pb::WireError::OverCap, "carrier body cap + 1 byte refused");

        pb::CarrierBodyV3 c17 = c0;
        for (std::uint64_t i = 0; i <= lim.r_max; ++i) c17.carried.push_back(make_body(1, false, static_cast<std::uint8_t>(i)));
        std::vector<std::uint8_t> sink;
        check(pb::encode_carrier_body_v3(c17, lim.r_max, sink) == pb::WireError::CarriedCount && sink.empty(),
              "encoder refuses R_MAX + 1 carried");

        // n_carried byte = R_MAX + 1 and 255 on the wire, nothing after it
        const std::vector<std::uint8_t> own = enc(c0.own);
        for (std::uint8_t n : {static_cast<std::uint8_t>(lim.r_max + 1), static_cast<std::uint8_t>(255)}) {
            std::vector<std::uint8_t> w;
            w.push_back(3);
            w.insert(w.end(), own.begin(), own.end());
            w.push_back(n);
            check(dec_carrier(w, lim) == pb::WireError::CarriedCount,
                  "n_carried " + std::to_string(n) + " refused before allocation");
        }

        std::vector<std::uint8_t> bad = e0;
        bad[0] = 2;
        check(dec_carrier(bad, lim) == pb::WireError::Version, "carrier body version 2 refused");
        bad = e0;
        bad.push_back(7);
        check(dec_carrier(bad, lim) == pb::WireError::Trailing, "carrier body trailing byte refused");

        // n_carried = 2 with one body present
        std::vector<std::uint8_t> w;
        w.push_back(3);
        w.insert(w.end(), own.begin(), own.end());
        w.push_back(2);
        w.insert(w.end(), own.begin(), own.end());
        check(dec_carrier(w, lim) == pb::WireError::Truncated, "n_carried above the bodies present refused");

        // depth 255 announced with no branch bytes, buffer RECEIPT_MAX(255): refused before allocation
        std::vector<std::uint8_t> d255 = enc(make_body(0, false, 6));
        const std::size_t depth_off = 1 + d255[0] + pb::kExtraNonceBytes;
        d255[depth_off] = 255;
        d255.resize(depth_off + 1);
        check(dec(d255, 255) == pb::WireError::Truncated, "depth 255 without branch bytes refused before allocation");

        bool trunc_ok = true;
        for (std::size_t n = 0; n < emax.size(); n += 7) {
            std::vector<std::uint8_t> t(emax.begin(), emax.begin() + static_cast<std::ptrdiff_t>(n));
            if (dec_carrier(t, lim) == pb::WireError::None) trunc_ok = false;
        }
        check(trunc_ok, "truncations of the largest carrier body refused");
    }

    // (7) carrier frame
    {
        check(pb::kFrameHeaderBytes == 6, "FH = opcode 1 + frame version 1 + chain_id 4 = 6");
        check(pb::kFrameOpcodeBytes == sizeof(relay::FB_RECEIPTS) && pb::kFrameVersionBytes == sizeof(relay::kFbVersion)
                      && pb::kFrameChainIdBytes == sizeof(relay::u32),
              "FH fields have the widths of the relay opcode, frame version and chain_id");
        check(relay::kFbReceiptsHeader == pb::kFrameHeaderBytes + pb::kU8Bytes, "relay FB_RECEIPTS header = FH + count byte");
        check(relay::kCtxHeader == pb::kFrameHeaderBytes + pb::kHashBytes + pb::kU32Bytes,
              "relay FB_CTX header = FH + id + length");
        const relay::u32 chain = 0x0a0b0c0du;
        const std::vector<std::uint8_t> f = relay::encode_getctx(chain, std::vector<relay::bytes32>(1));
        check(f.size() == pb::kFrameHeaderBytes + pb::kU8Bytes + pb::kHashBytes, "relay FB_GETCTX frame = FH + count + id");
        check(f.size() > pb::kFrameHeaderBytes && f[0] == relay::FB_GETCTX && f[1] == relay::kFbVersion && f[2] == 0x0d
                      && f[3] == 0x0c && f[4] == 0x0b && f[5] == 0x0a,
              "relay frame bytes: opcode | frame version | chain_id little-endian");

        const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
        const pb::CarrierLimits lim = pb::carrier_limits(buf16, r_max);
        check(pb::frame_buffer(lim) == pb::kFrameHeaderBytes + pb::carrier_body_buffer(lim),
              "frame buffer = FH + carrier_body_buffer");
        check(pb::frame_buffer(lim) == 16073 && pb::frame_buffer(lim) == buf16.frame,
              "frame buffer = 6 + 2 + 17 x 945 = 16,073 at D_max 14, R_MAX 16");
        check(pb::frame_buffer(pb::carrier_limits(buf17, r_max)) == 14985, "frame buffer = 6 + 2 + 17 x 881 = 14,985 at v17");
        check(pb::frame_cap(913, r_max) == 15529, "consensus FRAME_CAP = 6 + 2 + 17 x 913 = 15,529");
        check(pb::frame_cap(849, r_max) == 14441, "consensus FRAME_CAP = 6 + 2 + 17 x 849 = 14,441 at v17");

        // kFbMaxReceiptsPerFrame: a carrier frame holds the carrier + R_MAX carried
        // = 1 + R_MAX = 17 (the S2 relay literal 8 is superseded; v2.4).
        check(pb::max_receipts_per_frame(r_max) == 17 && pb::kFbMaxReceiptsPerFrame == 17,
              "kFbMaxReceiptsPerFrame = 1 + R_MAX = 17 (8 -> 17)");
        check(relay::kFbMaxReceiptsPerFrame == 8, "the S2 relay literal kFbMaxReceiptsPerFrame is 8 (superseded)");
        check(pb::carrier_body_size(945, r_max) == 2 + pb::max_receipts_per_frame(r_max) * 945,
              "carrier body = 2 + kFbMaxReceiptsPerFrame x receipt");
    }

    // (8) one budget (X-6): the relay verify budget and the admission budget are
    // the same receipt I/O buffer P-10; PER_LANE_BUDGET = R_MAX x P-10.
    {
        const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
        check(pb::per_receipt_budget(16, 0, r_max) == std::optional<std::uint64_t>(945)
                      && pb::per_receipt_budget(16, 0, r_max) == pb::fb_receipt_budget(16, 0, r_max),
              "one budget: PER_RECEIPT_BUDGET == kFbReceiptBudget == P-10 = 945 (v16)");
        check(pb::per_receipt_budget(17, 0, r_max) == std::optional<std::uint64_t>(881)
                      && pb::per_receipt_budget(17, 0, r_max) == pb::fb_receipt_budget(17, 0, r_max),
              "one budget at v17: 881");
        check(pb::per_receipt_budget(16, 0, r_max) == std::optional<std::uint64_t>(buf16.receipt)
                      && pb::per_receipt_budget(17, 0, r_max) == std::optional<std::uint64_t>(buf17.receipt),
              "the one budget equals the configured receipt buffer P-10");
        check(pb::per_lane_budget(16, 0, r_max) == std::optional<std::uint64_t>(r_max * 945)
                      && pb::per_lane_budget(17, 0, r_max) == std::optional<std::uint64_t>(r_max * 881),
              "PER_LANE_BUDGET = R_MAX x P-10 = 15,120 (v16) / 14,096 (v17)");
        check(pb::per_receipt_budget(16, UINT64_MAX, r_max) == std::nullopt,
              "a view outside the domain yields no budget");
        // the S2 engine sizes the two apart: relay 1024, admission 768.
        check(relay::kFbReceiptBudget == 1024, "the S2 relay budget literal is 1024 (superseded)");
    }

    return finish("v37_xmr_pathb_body_v3_kat");
}
