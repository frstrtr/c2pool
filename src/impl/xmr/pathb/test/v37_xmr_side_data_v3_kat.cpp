// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_side_data_v3_kat.cpp
// side_data_v3 (241 B), mm_root and the receipts_root fold:
//   (1) field offsets 0/1/33/35/37/69/77/109/141/173/205/207/239, size 241;
//       rules_epoch u16 at 33, ballot u16 at 35;
//   (2) golden bytes and golden mm_root (gen_pathb_golden.py, independent
//       Keccak-256), Keccak-256 of the empty input;
//   (3) round trip; every truncation refused; 242 bytes refused;
//   (4) version != 3, p > 10000, give_author_bp > 10000, owner identity
//       zero/non-zero against p: refused by the decoder and the encoder;
//       S2.3 #2 p + give_author_bp <= 10000: 10000 + 1 and 5001 + 5000 refused
//       (ShareSum) by the side data and receipt body decoders and encoders, no
//       mm_root; 9990 + 10 and 10000 + 0 accepted; p 10001 is FeeRateRange;
//   (5) in the receipt body: payee kind XMR_SUB refused, owner_ref with p = 0
//       refused, owner_ref missing with p > 0 refused, ref len != 64 refused,
//       a key that does not decompress refused (decoder and encoder);
//   (6) identity binding of the refs to side_data;
//   (7) ratchet state S: 134 B, offsets 0/2/34/66/98/130, little-endian;
//       golden S, rs_root and receipts_root (gen_pathb_golden.py, hashlib
//       sha256d): S after three carriers of d 18,180 with ballots 0 ->
//       rs_root 33c0bf81..., receipts_root (carried_root 0) 9c6c4c42...;
//       rs_step: with ballots 0 only `all` moves; at x = (k + 1) L - 1 the
//       window level is appended and the sums reset; level 1 at
//       4 y1 = 3 all, level 2 at 4 y2 >= 3 all, 0 below and when all = 0;
//       the own flag does not count; W_R = 4 at L 34,881 / GRACE 120,960,
//       W_R 5 refused; the carrier fold check: Match on the verifier's S,
//       Strike on a flipped bit, another position's S, or carried_root != 0.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>
#include <vector>

#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

const char* kGoldenSideHex =
        "030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020304404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f0102030405060708606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c"
        "7d7e7fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1"
        "d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff02012122232425"
        "262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f400a00";
const char* kGoldenMmRootHex = "3bd720d5af12ee5c69da51ced2d3f97e8c3e1f7e745c9c9dc155e40a1fec8428";
const char* kKeccakEmptyHex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

// Ratchet state vectors (gen_pathb_golden.py).
const char* kS1StateHex =
        "00001112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f300cd5000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000";
const char* kS1RsRootHex = "33c0bf81942281b70e7a5aff7a18e509ab663453f85ebc3e2e73d5d7c5c83a96";
const char* kS1ReceiptsRootHex = "9c6c4c423ea279867e47120c92c2d67d2bac5c3ff052e3dfaf5e8a7c7294bf55";
const char* kS1ReceiptsRootCarriedHex = "87c18a7ac805e94f74e788592ee79cfd26daefe8fb788f7ce772b898cce0f510";
const char* kFullStateHex =
        "0201202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01000000000000000200000000000000030000"
        "000000000004000000000000000500000000000000060000000000000007000000000000000800000000000000090000000000000"
        "00a000000000000000b000000000000000c0000000000000000010201";
const char* kFullRsRootHex = "fd2c09ddf9aa4c0011494994d6c4fc2d329e09c578663ed4ca295041fa2aa552";

pb::RsWork limbs(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d) {
    pb::RsWork w;
    w.v = {a, b, c, d};
    return w;
}

pb::RatchetState step(const pb::RatchetParams& p, const pb::RatchetState& s, std::uint64_t x,
                      std::vector<pb::RatchetPlacement> placed) {
    return pb::rs_step(p, s, x, placed);
}

pb::WireError dec_side(const std::vector<std::uint8_t>& b) {
    pb::SideDataV3 s;
    return pb::decode_side_data_v3(b.data(), b.size(), s);
}

// Decode with a receipt buffer of RECEIPT_MAX(buffer_depth).
pb::WireError dec_body(const std::vector<std::uint8_t>& b, std::uint64_t buffer_depth) {
    pb::ReceiptBodyV3 r;
    return pb::decode_receipt_body_v3(b.data(), b.size(), pb::ReceiptLimits{pb::receipt_max(buffer_depth)}, r);
}

// Offset of payee_ref in an encoded body.
std::size_t payee_ref_offset(const std::vector<std::uint8_t>& enc_body, std::size_t depth) {
    return 1 + enc_body[0] + pb::kExtraNonceBytes + 1 + depth * pb::kHashBytes + pb::side_v3::kSize;
}

}  // namespace

int main() {
    std::printf("v37_xmr_side_data_v3_kat\n");

    // (1) layout
    check(pb::side_v3::kVersionOff == 0, "version at 0");
    check(pb::side_v3::kPoolIdOff == 1, "pool_id at 1");
    check(pb::side_v3::kRulesEpochOff == 33, "rules_epoch at 33");
    check(pb::side_v3::kBallotOff == 35, "ballot at 35");
    check(pb::side_v3::kPayeeOff == 37, "payee at 37");
    check(pb::side_v3::kTOriginOff == 69, "t_origin at 69");
    check(pb::side_v3::kTipOff == 77, "tip at 77");
    check(pb::side_v3::kReceiptsRootOff == 109, "receipts_root at 109");
    check(pb::side_v3::kWindowRootOff == 141, "window_root at 141");
    check(pb::side_v3::kMmrRootOff == 173, "mmr_root at 173");
    check(pb::side_v3::kFeeRateOff == 205, "fee_rate at 205");
    check(pb::side_v3::kOwnerOff == 207, "owner at 207");
    check(pb::side_v3::kGiveAuthorOff == 239, "give_author_bp at 239");
    check(pb::side_v3::kSize == 241, "side_data_v3 is 241 B");
    static_assert(std::is_same_v<decltype(pb::SideDataV3::rules_epoch), std::uint16_t>
                          && std::is_same_v<decltype(pb::SideDataV3::ballot), std::uint16_t>,
                  "rules_epoch and ballot are u16");

    // (2) golden bytes and mm_root
    const pb::SideDataV3 g = golden_side();
    std::vector<std::uint8_t> gb;
    check(pb::encode_side_data_v3(g, gb) == pb::WireError::None, "golden side data encodes");
    check(gb.size() == 241, "golden side data encodes to 241 B");
    check(hex(gb.data(), gb.size()) == kGoldenSideHex, "golden side data bytes");
    const std::optional<pb::Hash32> mm = pb::mm_root_of(g);
    check(mm.has_value() && hex(mm->data(), mm->size()) == kGoldenMmRootHex, "golden mm_root");
    {
        const ::xmr::coin::Hash256 e = ::xmr::coin::keccak256(nullptr, 0);
        check(hex(e.data(), 32) == kKeccakEmptyHex, "keccak256 of the empty input (Keccak, not SHA3)");
    }
    check(gb[pb::side_v3::kRulesEpochOff] == 0x01 && gb[pb::side_v3::kRulesEpochOff + 1] == 0x02,
          "rules_epoch u16 little-endian");
    check(gb[pb::side_v3::kBallotOff] == 0x03 && gb[pb::side_v3::kBallotOff + 1] == 0x04, "ballot u16 little-endian");
    check(gb[pb::side_v3::kTOriginOff] == 0x01 && gb[pb::side_v3::kTOriginOff + 7] == 0x08,
          "t_origin little-endian");
    check(gb[pb::side_v3::kFeeRateOff] == 0x02 && gb[pb::side_v3::kFeeRateOff + 1] == 0x01, "fee_rate little-endian");
    check(gb[pb::side_v3::kGiveAuthorOff] == 10 && gb[pb::side_v3::kGiveAuthorOff + 1] == 0, "give_author_bp = 10");

    // (3) round trip, truncation, oversize
    {
        pb::SideDataV3 back;
        check(pb::decode_side_data_v3(gb.data(), gb.size(), back) == pb::WireError::None && back == g,
              "side data round trip");
        bool all_refused = true;
        for (std::size_t n = 0; n < gb.size(); ++n) {
            std::vector<std::uint8_t> t(gb.begin(), gb.begin() + static_cast<std::ptrdiff_t>(n));
            if (dec_side(t) != pb::WireError::Truncated) all_refused = false;
        }
        check(all_refused, "every truncation of side data refused (Truncated)");
        std::vector<std::uint8_t> longer = gb;
        longer.push_back(0);
        check(dec_side(longer) == pb::WireError::OverCap, "242 B side data refused");
    }

    // (4) field rules
    {
        std::vector<std::uint8_t> b = gb;
        b[pb::side_v3::kVersionOff] = 2;
        check(dec_side(b) == pb::WireError::Version, "version 2 refused");
        b[pb::side_v3::kVersionOff] = 4;
        check(dec_side(b) == pb::WireError::Version, "version 4 refused");

        b = gb;  // p = 10001
        b[pb::side_v3::kFeeRateOff] = 0x11;
        b[pb::side_v3::kFeeRateOff + 1] = 0x27;
        check(dec_side(b) == pb::WireError::FeeRateRange, "fee_rate 10001 refused");
        b[pb::side_v3::kFeeRateOff] = 0x10;  // p = 10000, give_author_bp 10
        check(dec_side(b) == pb::WireError::ShareSum, "fee_rate 10000 + give_author_bp 10 refused (ShareSum)");
        b[pb::side_v3::kGiveAuthorOff] = 0;  // p = 10000, give_author_bp 0
        check(dec_side(b) == pb::WireError::None, "fee_rate 10000 accepted");

        b = gb;  // give_author_bp = 10001
        b[pb::side_v3::kGiveAuthorOff] = 0x11;
        b[pb::side_v3::kGiveAuthorOff + 1] = 0x27;
        check(dec_side(b) == pb::WireError::GiveAuthorRange, "give_author_bp 10001 refused");
        b[pb::side_v3::kGiveAuthorOff] = 0;
        b[pb::side_v3::kGiveAuthorOff + 1] = 0;
        check(dec_side(b) == pb::WireError::None, "give_author_bp 0 accepted");

        b = gb;  // p = 0 with a non-zero owner
        b[pb::side_v3::kFeeRateOff] = 0;
        b[pb::side_v3::kFeeRateOff + 1] = 0;
        check(dec_side(b) == pb::WireError::OwnerIdentity, "p = 0 with an owner identity refused");
        for (std::size_t i = 0; i < pb::kHashBytes; ++i) b[pb::side_v3::kOwnerOff + i] = 0;
        check(dec_side(b) == pb::WireError::None, "p = 0 with a zero owner accepted");

        b = gb;  // p > 0 with a zero owner
        for (std::size_t i = 0; i < pb::kHashBytes; ++i) b[pb::side_v3::kOwnerOff + i] = 0;
        check(dec_side(b) == pb::WireError::OwnerIdentity, "p > 0 with a zero owner refused");

        pb::SideDataV3 s = g;
        std::vector<std::uint8_t> sink;
        s.version = 2;
        check(pb::encode_side_data_v3(s, sink) == pb::WireError::Version && sink.empty(), "encoder refuses version 2");
        s = g;
        s.fee_rate_bp = 10001;
        check(pb::encode_side_data_v3(s, sink) == pb::WireError::FeeRateRange && sink.empty(),
              "encoder refuses p 10001");
        s = g;
        s.owner = pb::Hash32{};
        check(pb::encode_side_data_v3(s, sink) == pb::WireError::OwnerIdentity && sink.empty(),
              "encoder refuses p > 0 with a zero owner");
    }

    // (4b) S2.3 #2: p + give_author_bp <= 10000 (decoder, encoder, mm_root_of,
    // receipt body). 10000 exactly is valid (miner weight 0).
    {
        struct Sum {
            std::uint16_t p;
            std::uint16_t ga;
            bool valid;
        };
        for (const Sum c : {Sum{10000, 1, false}, Sum{5001, 5000, false}, Sum{9990, 10, true}, Sum{10000, 0, true}}) {
            const std::string tag = "p " + std::to_string(c.p) + " + give_author_bp " + std::to_string(c.ga);
            const pb::WireError want = c.valid ? pb::WireError::None : pb::WireError::ShareSum;
            std::vector<std::uint8_t> b = gb;
            b[pb::side_v3::kFeeRateOff] = static_cast<std::uint8_t>(c.p & 0xff);
            b[pb::side_v3::kFeeRateOff + 1] = static_cast<std::uint8_t>(c.p >> 8);
            b[pb::side_v3::kGiveAuthorOff] = static_cast<std::uint8_t>(c.ga & 0xff);
            b[pb::side_v3::kGiveAuthorOff + 1] = static_cast<std::uint8_t>(c.ga >> 8);
            check(dec_side(b) == want, tag + (c.valid ? ": decoder accepts" : ": decoder refuses (ShareSum)"));
            pb::SideDataV3 s = g;
            s.fee_rate_bp = c.p;
            s.give_author_bp = c.ga;
            std::vector<std::uint8_t> sink;
            const pb::WireError e = pb::encode_side_data_v3(s, sink);
            check(c.valid ? (e == pb::WireError::None && sink == b) : (e == pb::WireError::ShareSum && sink.empty()),
                  tag + (c.valid ? ": encoder writes the same bytes" : ": encoder refuses (ShareSum)"));
            check(pb::mm_root_of(s).has_value() == c.valid,
                  tag + (c.valid ? ": mm_root_of builds" : ": mm_root_of builds nothing"));
            pb::ReceiptBodyV3 body = make_body(3, true, 0x5a);
            std::vector<std::uint8_t> eb = enc(body);
            if (eb.empty()) {
                check(false, tag + ": the base receipt body encodes");
                continue;
            }
            const std::size_t so = payee_ref_offset(eb, 3) - pb::side_v3::kSize;
            eb[so + pb::side_v3::kFeeRateOff] = static_cast<std::uint8_t>(c.p & 0xff);
            eb[so + pb::side_v3::kFeeRateOff + 1] = static_cast<std::uint8_t>(c.p >> 8);
            eb[so + pb::side_v3::kGiveAuthorOff] = static_cast<std::uint8_t>(c.ga & 0xff);
            eb[so + pb::side_v3::kGiveAuthorOff + 1] = static_cast<std::uint8_t>(c.ga >> 8);
            check(dec_body(eb, 3) == want,
                  tag + (c.valid ? ": receipt body decoder accepts" : ": receipt body decoder refuses (ShareSum)"));
            body.side.fee_rate_bp = c.p;
            body.side.give_author_bp = c.ga;
            sink.clear();
            check((pb::encode_receipt_body_v3(body, sink) == want) && (sink.empty() != c.valid),
                  tag + (c.valid ? ": receipt body encoder accepts" : ": receipt body encoder refuses (ShareSum)"));
        }
        // the per-field range rules come first: p 10001 + give_author_bp 0 is FeeRateRange.
        pb::SideDataV3 s = g;
        s.fee_rate_bp = 10001;
        s.give_author_bp = 0;
        std::vector<std::uint8_t> sink;
        check(pb::encode_side_data_v3(s, sink) == pb::WireError::FeeRateRange, "p 10001 + give_author_bp 0: FeeRateRange");
    }

    // (5) refs in the receipt body
    {
        const std::size_t depth = 3;
        pb::ReceiptBodyV3 with_owner = make_body(depth, true, 1);
        pb::ReceiptBodyV3 no_owner = make_body(depth, false, 2);
        std::vector<std::uint8_t> eo = enc(with_owner);
        std::vector<std::uint8_t> en = enc(no_owner);
        check(dec_body(eo, depth) == pb::WireError::None, "body with owner_ref accepted");
        check(dec_body(en, depth) == pb::WireError::None, "body without owner_ref accepted");

        std::vector<std::uint8_t> b = en;
        const std::size_t pr = payee_ref_offset(en, depth);
        check(b[pr] == 0x10, "payee_ref kind byte is XMR_STD (0x10)");
        b[pr] = static_cast<std::uint8_t>(::v37::xmr::XMR_SUB);
        check(dec_body(b, depth) == pb::WireError::PayeeRefKind, "payee XMR_SUB refused");
        b = en;
        b[pr + 1] = 63;
        check(dec_body(b, depth) == pb::WireError::PayeeRefLength, "payee_ref len 63 refused");

        // owner_ref inserted with p = 0
        b = en;
        std::vector<std::uint8_t> extra_ref;
        extra_ref.push_back(0x10);
        extra_ref.push_back(64);
        for (int i = 0; i < 64; ++i) extra_ref.push_back(static_cast<std::uint8_t>(i));
        b.insert(b.end() - static_cast<std::ptrdiff_t>(pb::kU64Bytes), extra_ref.begin(), extra_ref.end());
        check(dec_body(b, depth) != pb::WireError::None, "owner_ref with p = 0 refused");

        // owner_ref removed with p > 0
        b = eo;
        const std::size_t orf = payee_ref_offset(eo, depth) + pb::kKeyRefBytes;
        b.erase(b.begin() + static_cast<std::ptrdiff_t>(orf),
                b.begin() + static_cast<std::ptrdiff_t>(orf + pb::kKeyRefBytes));
        check(dec_body(b, depth) != pb::WireError::None, "owner_ref missing with p > 0 refused");

        b = eo;
        b[orf] = static_cast<std::uint8_t>(::v37::xmr::XMR_SUB);
        check(dec_body(b, depth) == pb::WireError::OwnerRefKind, "owner XMR_SUB refused");
        b = eo;
        b[orf + 1] = 65;
        check(dec_body(b, depth) == pb::WireError::OwnerRefLength, "owner_ref len 65 refused");

        pb::ReceiptBodyV3 bad = with_owner;
        bad.owner.reset();
        std::vector<std::uint8_t> sink;
        check(pb::encode_receipt_body_v3(bad, sink) == pb::WireError::OwnerIdentity && sink.empty(),
              "encoder refuses p > 0 without owner_ref");
        bad = no_owner;
        bad.owner = key_ref(5);
        check(pb::encode_receipt_body_v3(bad, sink) == pb::WireError::OwnerIdentity && sink.empty(),
              "encoder refuses owner_ref with p = 0");

        // key points
        const pb::Hash32 bad_pt = non_point();
        check(!pb::point_decompresses(bad_pt) && pb::point_decompresses(with_owner.payee.spend),
              "a non-point encoding found; fixture keys decompress");
        b = eo;
        const std::size_t pr_o = payee_ref_offset(eo, depth);
        for (std::size_t i = 0; i < pb::kHashBytes; ++i) b[pr_o + 2 + i] = bad_pt[i];
        check(dec_body(b, depth) == pb::WireError::PayeeRefPoint, "payee spend key not a point refused");
        b = eo;
        for (std::size_t i = 0; i < pb::kHashBytes; ++i) b[orf + 2 + pb::kHashBytes + i] = bad_pt[i];
        check(dec_body(b, depth) == pb::WireError::OwnerRefPoint, "owner view key not a point refused");
        bad = with_owner;
        bad.payee.view = bad_pt;
        check(pb::encode_receipt_body_v3(bad, sink) == pb::WireError::PayeeRefPoint && sink.empty(),
              "encoder refuses a payee key that is not a point");
        bad = with_owner;
        bad.owner->spend = bad_pt;
        check(pb::encode_receipt_body_v3(bad, sink) == pb::WireError::OwnerRefPoint && sink.empty(),
              "encoder refuses an owner key that is not a point");

        // (6) identity binding
        check(pb::identities_bound(with_owner), "payee and owner identities bound");
        check(pb::identities_bound(no_owner), "payee identity bound, no owner");
        pb::ReceiptBodyV3 unbound = with_owner;
        unbound.side.payee[0] ^= 1;
        check(!pb::identities_bound(unbound), "payee identity mismatch detected");
        unbound = with_owner;
        unbound.side.owner[5] ^= 1;
        check(!pb::identities_bound(unbound), "owner identity mismatch detected");
    }

    // (7) ratchet state and the receipts_root fold
    {
        check(pb::rs_layout::kEpochCurOff == 0 && pb::rs_layout::kRulesCurOff == 2 && pb::rs_layout::kAllOff == 34
                      && pb::rs_layout::kY1Off == 66 && pb::rs_layout::kY2Off == 98 && pb::rs_layout::kLevelsOff == 130,
              "S offsets 0 / 2 / 34 / 66 / 98 / 130");
        check(pb::rs_layout::kSize == 134, "S is 134 B");

        const pb::RatchetParams rp = pb::kRuledRatchetParams;
        check(rp.window == 34881 && rp.grace == 120960, "K30 L 34,881, GRACE 120,960");
        check(pb::ratchet_kept_windows(rp) == 4 && pb::ratchet_params_valid(rp), "W_R = floor(120,959 / 34,881) + 1 = 4");
        check(!pb::ratchet_params_valid(pb::RatchetParams{5, 21}) && pb::ratchet_params_valid(pb::RatchetParams{5, 20}),
              "W_R 5 refused, W_R 4 accepted (L 5, GRACE 21 / 20)");
        check(!pb::ratchet_params_valid(pb::RatchetParams{0, 20}), "L 0 refused");

        // golden S after three carriers of d 18,180, ballots 0
        const pb::RatchetState g0 = pb::genesis_ratchet_state(seq32(0x11));
        check(g0.epoch_cur == 0 && g0.rules_cur == seq32(0x11) && g0.all.is_zero() && g0.y1.is_zero()
                      && g0.y2.is_zero() && g0.levels == std::array<std::uint8_t, 4>{},
              "genesis S: epoch 0, rules_cur = genesis digest, sums and levels 0");
        pb::RatchetState s = g0;
        for (std::uint64_t x = 1; x <= 3; ++x) s = step(rp, s, x, {pb::RatchetPlacement{18180, 0}});
        check(s.all == pb::RsWork(3 * 18180) && s.y1.is_zero() && s.y2.is_zero() && s.epoch_cur == 0
                      && s.rules_cur == seq32(0x11) && s.levels == std::array<std::uint8_t, 4>{},
              "ballots 0: only `all` moves (54,540)");
        const pb::RatchetStateBytes sb = pb::encode_ratchet_state(s);
        check(hex(sb.data(), sb.size()) == kS1StateHex, "golden S bytes");
        const pb::Hash32 rs = pb::rs_root(s);
        check(hex(rs.data(), rs.size()) == kS1RsRootHex, "golden rs_root = sha256d(\"c2pool-v37-rs1\" || S)");
        const pb::Hash32 rr = pb::carrier_receipts_root(pb::kNoCarriedRoot, s);
        check(hex(rr.data(), rr.size()) == kS1ReceiptsRootHex,
              "golden receipts_root = sha256d(\"c2pool-v37-carry\" || 0 || rs_root)");
        check(pb::receipts_root_fold(pb::kNoCarriedRoot, rs) == rr, "fold of carried_root 0 with rs_root");
        const pb::Hash32 rc = pb::carrier_receipts_root(seq32(0x30), s);
        check(hex(rc.data(), rc.size()) == kS1ReceiptsRootCarriedHex, "golden fold with a non-zero carried_root");

        // every field of S in the bytes
        pb::RatchetState full;
        full.epoch_cur = 0x0102;
        full.rules_cur = seq32(0x20);
        full.all = limbs(1, 2, 3, 4);
        full.y1 = limbs(5, 6, 7, 8);
        full.y2 = limbs(9, 10, 11, 12);
        full.levels = {0, 1, 2, 1};
        const pb::RatchetStateBytes fb = pb::encode_ratchet_state(full);
        check(hex(fb.data(), fb.size()) == kFullStateHex, "S bytes: u16 and U256 limbs little-endian, levels oldest first");
        const pb::Hash32 frs = pb::rs_root(full);
        check(hex(frs.data(), frs.size()) == kFullRsRootHex, "golden rs_root of a state with every field set");

        // the carrier fold check
        check(pb::check_carrier_fold(rr, pb::kNoCarriedRoot, s) == pb::FoldVerdict::Match, "fold over the verifier's S: match");
        pb::Hash32 flipped = rr;
        flipped[31] ^= 1;
        check(pb::check_carrier_fold(flipped, pb::kNoCarriedRoot, s) == pb::FoldVerdict::Strike, "a flipped bit: strike");
        const pb::RatchetState s2 = step(rp, s, 4, {pb::RatchetPlacement{18180, 0}});
        check(pb::check_carrier_fold(rr, pb::kNoCarriedRoot, s2) == pb::FoldVerdict::Strike,
              "a fold over another position's S: strike");
        check(pb::check_carrier_fold(rr, seq32(0x30), s) == pb::FoldVerdict::Strike
                      && pb::check_carrier_fold(rc, pb::kNoCarriedRoot, s) == pb::FoldVerdict::Strike,
              "carried_root other than the carrier's: strike");
        pb::RatchetState other_rules = s;
        other_rules.rules_cur[0] ^= 1;
        check(pb::check_carrier_fold(rr, pb::kNoCarriedRoot, other_rules) == pb::FoldVerdict::Strike,
              "another rules_cur: strike");

        // ballot encoding
        check(pb::ballot_epoch(0x8002) == 2 && pb::ballot_own(0x8002) && !pb::ballot_own(0x0002)
                      && pb::make_ballot(2, true) == 0x8002 && pb::make_ballot(0x7fff, false) == 0x7fff,
              "ballot = own flag bit 15 | epoch_no bits 0..14");

        // rs_step at a window end (L 5, GRACE 20: windows [0, 5), [5, 10), ...)
        const pb::RatchetParams small{5, 20};
        check(pb::ratchet_window_end(small, 4) && pb::ratchet_window_end(small, 9) && !pb::ratchet_window_end(small, 5)
                      && !pb::ratchet_window_end(small, 0),
              "window ends at x = (k + 1) L - 1");
        pb::RatchetState w = pb::genesis_ratchet_state(seq32(0x11));
        w = step(small, w, 1, {pb::RatchetPlacement{100, pb::make_ballot(1, false)}});
        w = step(small, w, 2, {pb::RatchetPlacement{100, pb::make_ballot(2, false)}});
        w = step(small, w, 3, {pb::RatchetPlacement{100, pb::make_ballot(2, true)}});
        check(w.all == pb::RsWork(300) && w.y1 == pb::RsWork(300) && w.y2 == pb::RsWork(200),
              "ballot epoch 1 counts in y1, epoch 2 in y1 and y2, the own flag does not count");
        w = step(small, w, 4, {pb::RatchetPlacement{100, 0}});
        check(w.levels == std::array<std::uint8_t, 4>{0, 0, 0, 1} && w.all.is_zero() && w.y1.is_zero() && w.y2.is_zero(),
              "4 y1 = 3 all (1,200): level 1 appended, sums reset");
        for (std::uint64_t x = 5; x <= 9; ++x) w = step(small, w, x, {});
        check(w.levels == std::array<std::uint8_t, 4>{0, 0, 1, 0}, "a window without work: level 0");
        for (std::uint64_t x = 10; x <= 14; ++x)
            w = step(small, w, x, {pb::RatchetPlacement{100, x == 10 ? std::uint16_t{0} : pb::make_ballot(3, false)}});
        check(w.levels == std::array<std::uint8_t, 4>{0, 1, 0, 2}, "4 y2 >= 3 all (1,600 >= 1,500): level 2");
        for (std::uint64_t x = 15; x <= 19; ++x)
            w = step(small, w, x, {pb::RatchetPlacement{100, x <= 16 ? std::uint16_t{0} : pb::make_ballot(1, false)}});
        check(w.levels == std::array<std::uint8_t, 4>{1, 0, 2, 0}, "4 y1 < 3 all (1,200 < 1,500): level 0");
        for (std::uint64_t x = 20; x <= 24; ++x) w = step(small, w, x, {pb::RatchetPlacement{100, 0}});
        check(w.levels == std::array<std::uint8_t, 4>{0, 2, 0, 0} && w.epoch_cur == 0 && w.rules_cur == seq32(0x11),
              "ballots 0: level 0; the oldest level drops; epoch_cur and rules_cur unchanged");
        pb::RatchetState dead = pb::genesis_ratchet_state(seq32(0x11));
        for (std::uint64_t x = 0; x <= 4; ++x) dead = step(small, dead, x, {pb::RatchetPlacement{0, pb::make_ballot(1, false)}});
        check(dead.levels.back() == pb::kLevelNone, "work 0 (dead receipts) only: all = 0, level 0");
    }

    return finish("v37_xmr_side_data_v3_kat");
}
