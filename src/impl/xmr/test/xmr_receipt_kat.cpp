// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_receipt_kat.cpp  --  the Path B receipt (v3 body) KAT.
//
//   KAT-1  REAL Monero mainnet block 3000000 (ground truth: monerod get_block,
//          src/impl/xmr/test/x0-kat-3000000.json, values inlined below):
//          miner_tx_prefix_hash(prefix) == H(prefix); miner_tx_hash == the
//          block's miner tx hash; the tree fold tree_root_fold(tx hash, branch)
//          == the root inside the RandomX-hashed blob; the 76-byte hashing blob
//          decodes (tx_count 38) and re-encodes byte-exact; a flipped branch
//          byte no longer reproduces the root.
//   KAT-2  a v3 receipt body through the S2.3 order (admit_receipt):
//          (a) admitted PENDING, RandomX called last, once;
//          (b) the same receipt placed on the best chain -> DUPLICATE row 22,
//              no RandomX;
//          (c) h(r) - h(tip) > Fresh -> REFUSE row 20, no RandomX;
//          (d) t_origin changed in the body -> STRIKE row 25, no RandomX;
//          (e) credit = work(t_origin): the placement's work is
//              t_origin = d_at(tip), whatever the PoW achieves (a zero hash);
//              an off-consensus t_origin (the body built consistently on it)
//              -> STRIKE row 25, no RandomX;
//          (f) RandomX false -> BAN row 29 (RandomX called, last);
//          the v3 body round-trips (encode / decode) and its id is
//          keccak256(hashing blob).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/pathb/test/pathb_kat_admit.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
using pb::AdmitVerdict;
using pb::RowId;

namespace {

std::vector<std::uint8_t> unhex_v(const std::string& s) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>((hex_nibble(s[i]) << 4) | hex_nibble(s[i + 1])));
    return out;
}

namespace kat3000000 {
const std::string HASHING_BLOB =
        "1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd5b4b5347"
        "bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d910f53d9a8b167a24e"
        "7bdf0626";
const std::string PREFIX_BLOB =
        "02fc8db70101ffc08db7010180bde2a1c911031f214b304e74e9fe437ccd1f62b4777b20"
        "4dea7afdf844420dc5214971ef8d6cf334017543af4f79becc9e3d8701bfc6c405696a52"
        "d60332692703faad3475e0a8cfe402110000007147a42756000000000000000000";
const std::string H_PREFIX = "18b7efb2ab347082fc161ff480b0554dbf94de87251e676d8b67d7f5d9173b24";
const std::string MINER_TX_HASH = "7f88a52afdab303ddb9d444cb5b53adb5a12c63a82e898a9d2db9f76dd1127f6";
const std::string TREE_ROOT = "3cc88694451e92299e5283b2c51985e5c0d31b8d910f53d9a8b167a24e7bdf06";
const char* BRANCH[5] = {
        "e4516854a5984eaf5f8750ac7af41d1e0b2c602a2297a673001e8c0af88eba11",
        "160b280159f52461dcb661e49f30cae2a7f235acbdd68a8d002183b2358ed144",
        "03330ad5f7bee104763d8c19b207d52d4323d86a888229790801934c177629d3",
        "2244a793730a85480efc9301dde5045088ee4d8b61e4849ccf757ab8a99d5f44",
        "3d5a1ba12f721187cf632d75f220ee7c412420572fe6aca17cce1eecb569e93d",
};
}  // namespace kat3000000

void kat1_real_block() {
    using namespace kat3000000;
    std::printf("[KAT-1] REAL Monero mainnet block 3000000\n");
    const std::vector<std::uint8_t> prefix = unhex_v(PREFIX_BLOB);
    check(prefix.size() == 105, "KAT-1 prefix length 105");
    const pb::Hash32 hp = pb::miner_tx_prefix_hash(prefix);
    check(hex32(hp) == H_PREFIX, "KAT-1 miner_tx_prefix_hash(prefix) == monerod get_transaction_prefix_hash");
    const pb::Hash32 tx = pb::miner_tx_hash(hp);
    check(hex32(tx) == MINER_TX_HASH, "KAT-1 miner_tx_hash == monerod get_block");
    std::vector<pb::Hash32> branch;
    for (const char* b : BRANCH) branch.push_back(h32(b));
    const pb::Hash32 root = pb::tree_root_fold(tx, branch);
    check(hex32(root) == TREE_ROOT, "KAT-1 tree_root_fold(miner tx hash, branch) == the block's tree root");

    const std::vector<std::uint8_t> blob = unhex_v(HASHING_BLOB);
    check(blob.size() == 76, "KAT-1 hashing blob length 76");
    pb::BlobReader r(blob.data(), blob.size());
    pb::HashingBlob hb;
    check(pb::detail::read_hashing_blob(r, blob.size(), hb) == pb::WireError::None, "KAT-1 the hashing blob decodes");
    check(hex32(hb.tree_root) == TREE_ROOT && hb.tx_count == 38 && hb.major == 16 && hb.minor == 16,
          "KAT-1 the blob carries the folded root, tx_count 38, version 16 / 16");
    std::vector<std::uint8_t> again;
    pb::encode_hashing_blob(hb, again);
    check(again == blob, "KAT-1 the blob re-encodes byte-exact");
    check(pb::receipt_id(hb) == pb::keccak256_hash(blob), "KAT-1 receipt_id == keccak256(hashing blob)");

    std::vector<pb::Hash32> bad = branch;
    bad[2][0] ^= 0x01;
    check(pb::tree_root_fold(tx, bad) != root, "KAT-1 a flipped branch byte no longer reproduces the root");
}

const std::uint64_t kJ0 = pb::admit_j0(pb::kRuledLaneParams);

std::vector<pb::Hash32> chain_of(KatNode& n, std::uint64_t count) {
    std::vector<pb::Hash32> out;
    pb::Hash32 prev = n.tree.best().id;
    const std::uint64_t base = n.node(prev).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const pb::CarrierBodyV3 c = carrier_on(n, prev, h_pos(base + i), {}, (base + i) % 4, 1 + base + i);
        const Admitted a = admit_place(n, c);
        if (!a.placed) {
            check(false, "chain: carrier not placed at " + std::to_string(base + i) + ": " + desc(a.r));
            break;
        }
        prev = pb::receipt_id(c.own);
        out.push_back(prev);
    }
    return out;
}

bool is(const pb::AdmitResult& r, AdmitVerdict v, RowId row) { return r.verdict == v && r.row == row; }

void kat2_v3_order() {
    std::printf("[KAT-2] a v3 receipt body through the S2.3 order\n");
    KatNet net;
    KatNode n(net, kJ0);
    std::vector<pb::Hash32> chain = chain_of(n, 12);
    if (chain.empty()) return;
    const pb::Hash32 tip = chain.back();
    const std::uint64_t ht = h_pos(13);

    const pb::ReceiptBodyV3 r = body_on(n, tip, ht, 1, 8001);
    const std::vector<std::uint8_t> bytes = bytes_of(r);
    pb::ReceiptBodyV3 dec;
    check(pb::decode_receipt_body_v3(bytes.data(), bytes.size(), pb::ReceiptLimits{n.buffers.receipt}, dec) ==
                          pb::WireError::None &&
                  dec == r,
          "KAT-2 the v3 body round-trips");
    std::vector<std::uint8_t> hb;
    pb::encode_hashing_blob(r.blob, hb);
    check(pb::receipt_id(r) == pb::keccak256_hash(hb), "KAT-2 the receipt id is keccak256(hashing blob)");

    // (a)
    std::uint64_t rx = n.rx_calls;
    const pb::AdmitResult a = pb::admit_receipt(n.env(), bytes, pb::Role::Pending);
    check(is(a, AdmitVerdict::AdmitPending, RowId::R30) && a.randomx_called && n.rx_calls == rx + 1,
          "KAT-2 (a) admitted PENDING, RandomX called once, last: " + desc(a));
    // (e) credit = work(t_origin), not the achieved difficulty (the stub's hash meets any d)
    const std::uint64_t d_at = n.tree.next_difficulty(tip).value_or(0);
    check(d_at > 0 && r.side.t_origin == d_at && a.store_placements.size() == 1 && a.store_placements[0].work == d_at,
          "KAT-2 (e) the placement's work is t_origin = d_at(tip) = " + std::to_string(d_at));
    // (b) the same receipt carried by the next carrier on the best chain -> DUPLICATE
    {
        const pb::CarrierBodyV3 c = carrier_on(n, tip, h_pos(13), {r}, 2, 8101);
        const Admitted p = admit_place(n, c);
        check(p.placed, "KAT-2 (b) a carrier carrying the receipt is placed: " + desc(p.r));
        rx = n.rx_calls;
        const pb::AdmitResult b = pb::admit_receipt(n.env(), bytes, pb::Role::Pending);
        check(is(b, AdmitVerdict::Duplicate, RowId::R22) && n.rx_calls == rx && !b.randomx_called,
              "KAT-2 (b) the replayed receipt -> DUPLICATE row 22, no RandomX: " + desc(b));
        if (p.placed) chain.push_back(pb::receipt_id(c.own));
    }
    const pb::Hash32 tip2 = chain.back();
    const std::uint64_t ht2 = h_pos(14);
    // (c) beyond Fresh
    {
        const pb::ReceiptBodyV3 late = body_on(n, tip2, ht2 + pb::kRuledLaneParams.fresh_max + 1, 3, 8201);
        rx = n.rx_calls;
        const pb::AdmitResult c = pb::admit_receipt(n.env(), bytes_of(late), pb::Role::Pending);
        check(is(c, AdmitVerdict::Refuse, RowId::R20) && n.rx_calls == rx,
              "KAT-2 (c) h(r) - h(tip) > Fresh -> REFUSE row 20, no RandomX: " + desc(c));
    }
    // (d) t_origin changed in a committed body
    {
        pb::ReceiptBodyV3 t = body_on(n, tip2, ht2, 4, 8301);
        t.side.t_origin += 1;
        rx = n.rx_calls;
        const pb::AdmitResult d = pb::admit_receipt(n.env(), bytes_of(t), pb::Role::Pending);
        check(is(d, AdmitVerdict::Strike, RowId::R25) && n.rx_calls == rx,
              "KAT-2 (d) t_origin changed -> STRIKE row 25, no RandomX: " + desc(d));
    }
    // (e) an off-consensus t_origin, the body built consistently on it
    {
        const pb::ReceiptBodyV3 off =
                body_on(n, tip2, ht2, 5, 8401, {}, [](pb::ReceiptBodyV3& b) { b.side.t_origin = b.side.t_origin * 3 + 7; });
        rx = n.rx_calls;
        const pb::AdmitResult e = pb::admit_receipt(n.env(), bytes_of(off), pb::Role::Pending);
        check(is(e, AdmitVerdict::Strike, RowId::R25) && n.rx_calls == rx,
              "KAT-2 (e) an off-consensus t_origin -> STRIKE row 25, no RandomX: " + desc(e));
    }
    // (f) RandomX false
    {
        const pb::ReceiptBodyV3 f = body_on(n, tip2, ht2, 6, 8501);
        n.bad_pow.insert(pb::receipt_id(f));
        rx = n.rx_calls;
        const pb::AdmitResult x = pb::admit_receipt(n.env(), bytes_of(f), pb::Role::Pending);
        check(is(x, AdmitVerdict::Ban, RowId::R29) && x.randomx_called && n.rx_calls == rx + 1,
              "KAT-2 (f) RandomX false -> BAN row 29, RandomX called last: " + desc(x));
    }
}

}  // namespace

int main() {
    std::printf("=== xmr_receipt_kat: the Path B receipt ===\n");
    kat1_real_block();
    kat2_v3_order();
    return finish("xmr_receipt_kat");
}
