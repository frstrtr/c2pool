// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_side_data_v3_kat.cpp
// side_data_v3 (273 B) and mm_root:
//   (1) field offsets 0/1/33/37/69/77/109/141/173/205/237/239/271, size 273;
//   (2) golden bytes and golden mm_root (gen_pathb_golden.py, independent
//       Keccak-256), Keccak-256 of the empty input;
//   (3) round trip; every truncation refused; 274 bytes refused;
//   (4) version != 3, p > 10000, give_author_bp > 10000, owner identity
//       zero/non-zero against p: refused by the decoder and the encoder;
//   (5) in the receipt body: payee kind XMR_SUB refused, owner_ref with p = 0
//       refused, owner_ref missing with p > 0 refused, ref len != 64 refused,
//       a key that does not decompress refused (decoder and encoder);
//   (6) identity binding of the refs to side_data.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

const char* kGoldenSideHex =
        "030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020304404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f0102030405060708606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c"
        "7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1"
        "b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"
        "e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff02012122232425262728292a2b2c2d2e2f303132333435363738393a"
        "3b3c3d3e3f400a00";
const char* kGoldenMmRootHex = "fde5247627bfe5b7e6b51608bacbc9d9e20feb65c915320f89d9e069762f8d65";
const char* kKeccakEmptyHex = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

pb::WireError dec_side(const std::vector<std::uint8_t>& b) {
    pb::SideDataV3 s;
    return pb::decode_side_data_v3(b.data(), b.size(), s);
}

pb::WireError dec_body(const std::vector<std::uint8_t>& b, std::uint64_t cap_depth) {
    pb::ReceiptBodyV3 r;
    return pb::decode_receipt_body_v3(b.data(), b.size(), pb::ReceiptLimits{cap_depth}, r);
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
    check(pb::side_v3::kPayeeOff == 37, "payee at 37");
    check(pb::side_v3::kTOriginOff == 69, "t_origin at 69");
    check(pb::side_v3::kTipOff == 77, "tip at 77");
    check(pb::side_v3::kPrevOwnShareOff == 109, "prev_own_share at 109");
    check(pb::side_v3::kReceiptsRootOff == 141, "receipts_root at 141");
    check(pb::side_v3::kWindowRootOff == 173, "window_root at 173");
    check(pb::side_v3::kMmrRootOff == 205, "mmr_root at 205");
    check(pb::side_v3::kFeeRateOff == 237, "fee_rate at 237");
    check(pb::side_v3::kOwnerOff == 239, "owner at 239");
    check(pb::side_v3::kGiveAuthorOff == 271, "give_author_bp at 271");
    check(pb::side_v3::kSize == 273, "side_data_v3 is 273 B");

    // (2) golden bytes and mm_root
    const pb::SideDataV3 g = golden_side();
    std::vector<std::uint8_t> gb;
    check(pb::encode_side_data_v3(g, gb) == pb::WireError::None, "golden side data encodes");
    check(gb.size() == 273, "golden side data encodes to 273 B");
    check(hex(gb.data(), gb.size()) == kGoldenSideHex, "golden side data bytes");
    const std::optional<pb::Hash32> mm = pb::mm_root_of(g);
    check(mm.has_value() && hex(mm->data(), mm->size()) == kGoldenMmRootHex, "golden mm_root");
    {
        const ::xmr::coin::Hash256 e = ::xmr::coin::keccak256(nullptr, 0);
        check(hex(e.data(), 32) == kKeccakEmptyHex, "keccak256 of the empty input (Keccak, not SHA3)");
    }
    check(gb[pb::side_v3::kRulesEpochOff] == 0x01 && gb[pb::side_v3::kRulesEpochOff + 3] == 0x04,
          "rules_epoch little-endian");
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
        check(dec_side(longer) == pb::WireError::OverCap, "274 B side data refused");
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
        b[pb::side_v3::kFeeRateOff] = 0x10;  // p = 10000
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

    return finish("v37_xmr_side_data_v3_kat");
}
