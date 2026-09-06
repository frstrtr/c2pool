// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/receipt/test/xmr_receipt_kat.cpp  --  X4 receipt-envelope KAT.
//
// Two KATs, RandomX CI-gated throughout (no 256-MiB cache, no heavy hash):
//
//   KAT-1  REAL Monero mainnet block 3000000. Build the coinbase opening from the
//          real miner_tx prefix, verify_crypto_opening() end-to-end, and confirm
//          the Keccak-midstate opening reproduces  H(prefix) -> miner_tx_hash ->
//          tree_root == the root inside the RandomX-signed hashing blob. Ground
//          truth = monerod get_block, carried in
//          src/impl/xmr/test/x0-kat-3000000.json (values inlined below, cited).
//
//   KAT-2  SYNTHETIC v37 receipt (real X1 coinbase serializer + a v37 tx_extra
//          0x03 leaf committing info_digest). Runs the FULL keyed_heavy W2
//          admission ORDER and proves: (a) a clean receipt is accepted with
//          RandomX CI-gated (SkippedCIGated); (b) a replayed receipt dies at
//          stage 1 (Dedup) with RandomX NEVER reached; (c) an expired receipt
//          dies at stage 2 (Expiry), RandomX NEVER reached; (d) a tampered
//          T_origin breaks the binding at stage 3 (Structural); (e) an
//          off-consensus T_origin dies at stage 4 (R1Target); (f) with a stub
//          hasher wired, stage 5 (RandomX) runs LAST and its verdict is honoured.
//
// Build (light, single TU, uses X1's already-vendored primitives; no cmake):
//   g++ -std=c++20 -O1 \
//     -I <c2pool>/src/impl/xmr/coin \
//     -I <c2pool>/src/impl/xmr/receipt \
//     xmr_receipt_kat.cpp \
//     xmr_receipt_verify.cpp \
//     <c2pool>/src/impl/xmr/coin/xmr_blob.cpp \
//     <c2pool>/src/impl/xmr/coin/vendor/{keccak,hash,tree-hash}.c \
//     -o /tmp/xmr_receipt_kat && /tmp/xmr_receipt_kat
// ---------------------------------------------------------------------------
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#include "xmr_receipt.hpp"
#include "xmr_admission.hpp"
#include "xmr_receipt_verify.hpp"
#include "xmr_blob.hpp"           // X1 coinbase serializer for KAT-2

using namespace v37::xmr;
namespace vf = v37::xmr::verify;

// ------------------------------ hex helpers --------------------------------
static std::vector<u8> unhex(const std::string& s) {
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<u8> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<u8>((nyb(s[i]) << 4) | nyb(s[i + 1])));
    return out;
}
static bytes32 unhex32(const std::string& s) {
    auto v = unhex(s);
    bytes32 b{};
    for (int i = 0; i < 32 && i < (int)v.size(); ++i) b[i] = v[i];
    return b;
}
static std::string hex(const bytes32& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (u8 c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 15]); }
    return s;
}
static void put_varint(std::vector<u8>& b, u64 v) {
    while (v >= 0x80) { b.push_back(static_cast<u8>(v) | 0x80); v >>= 7; }
    b.push_back(static_cast<u8>(v));
}

// ------------------- REAL block 3000000 KAT vectors ------------------------
// Source: src/impl/xmr/test/x0-kat-3000000.json (monerod get_block, X0 leg).
namespace kat3000000 {
const std::string HASHING_BLOB =
  "1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd5b4b5347"
  "bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d910f53d9a8b167a24e"
  "7bdf0626";
const std::string PREFIX_BLOB =
  "02fc8db70101ffc08db7010180bde2a1c911031f214b304e74e9fe437ccd1f62b4777b20"
  "4dea7afdf844420dc5214971ef8d6cf334017543af4f79becc9e3d8701bfc6c405696a52"
  "d60332692703faad3475e0a8cfe402110000007147a42756000000000000000000";
const std::size_t EXTRA_START = 53;    // extra_start_in_prefix
const std::string H_PREFIX =
  "18b7efb2ab347082fc161ff480b0554dbf94de87251e676d8b67d7f5d9173b24";
const std::string MINER_TX_HASH =
  "7f88a52afdab303ddb9d444cb5b53adb5a12c63a82e898a9d2db9f76dd1127f6";
const std::string TREE_ROOT =
  "3cc88694451e92299e5283b2c51985e5c0d31b8d910f53d9a8b167a24e7bdf06";
const std::uint8_t DEPTH = 5;          // tree_branch_leaf0.depth (n_tx=38 -> clean 32)
const std::uint32_t PATH_BITS = 0;     // path_bits "00000" (leaf 0 is always left)
const char* BRANCH[5] = {
  "e4516854a5984eaf5f8750ac7af41d1e0b2c602a2297a673001e8c0af88eba11",
  "160b280159f52461dcb661e49f30cae2a7f235acbdd68a8d002183b2358ed144",
  "03330ad5f7bee104763d8c19b207d52d4323d86a888229790801934c177629d3",
  "2244a793730a85480efc9301dde5045088ee4d8b61e4849ccf757ab8a99d5f44",
  "3d5a1ba12f721187cf632d75f220ee7c412420572fe6aca17cce1eecb569e93d",
};
} // namespace kat3000000

static int g_pass = 0, g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) { std::printf("  PASS  %s\n", name); ++g_pass; } \
    else      { std::printf("  FAIL  %s\n", name); ++g_fail; } } while (0)

// ===========================================================================
// KAT-1: real block 3000000 -- Keccak-midstate opening reproduces tx->root.
// ===========================================================================
static void kat1_real_block() {
    using namespace kat3000000;
    std::printf("[KAT-1] REAL Monero mainnet block 3000000 (RandomX CI-gated)\n");

    MoneroReceipt r;
    r.hashing_blob.bytes = unhex(HASHING_BLOB);
    CHECK("hashing_blob length == 76", r.hashing_blob.size() == 76);

    // build the coinbase opening from the real miner_tx prefix at the extra boundary
    std::vector<u8> prefix = unhex(PREFIX_BLOB);
    CHECK("prefix length == 105", prefix.size() == 105);
    bool bok = vf::build_coinbase_opening(prefix, EXTRA_START, r.coinbase_opening);
    CHECK("build_coinbase_opening ok", bok);
    // block 3000000: 0 complete 136-blocks before boundary => midstate all-zero,
    // prefix_tail == the 53-byte head, tx_extra == the 52 opened bytes.
    bool tail_is_head = r.coinbase_opening.prefix_tail.size() == EXTRA_START;
    bool extra_is_52  = r.coinbase_opening.tx_extra.size() == 105 - EXTRA_START;
    CHECK("opening: prefix_tail == 53-byte head", tail_is_head);
    CHECK("opening: tx_extra == 52 opened bytes", extra_is_52);

    // (i) the midstate resume reproduces H(prefix)
    bytes32 h_prefix{};
    bool rok = vf::resume_prefix_hash(r.coinbase_opening, h_prefix);
    CHECK("resume_prefix_hash ok", rok);
    CHECK("H(prefix) == monerod get_transaction_prefix_hash", hex(h_prefix) == H_PREFIX);

    // fill the tree branch from the real proof
    r.tree_branch.depth     = DEPTH;
    r.tree_branch.path_bits = PATH_BITS;
    for (int i = 0; i < DEPTH; ++i) r.tree_branch.path.push_back(unhex32(BRANCH[i]));

    // (ii) verify_crypto_opening: resume -> tx hash -> tree branch -> root match
    OpenedCommitment oc;
    std::string why;
    bool vok = vf::verify_crypto_opening(r, oc, &why);
    CHECK("verify_crypto_opening ok (RandomX CI-gated)", vok);
    if (!vok) std::printf("        why: %s\n", why.c_str());

    // (iii) the recovered leaf-0 tx hash and root match monerod ground truth
    CHECK("miner_tx_hash == monerod get_block", hex(oc.miner_tx_hash) == MINER_TX_HASH);
    CHECK("recovered tree_root == monerod tree_root", hex(oc.tree_root) == TREE_ROOT);

    // (iv) and that root IS the one embedded in the RandomX-signed hashing blob
    vf::ParsedBlob pb;
    bool pok = vf::parse_hashing_blob(r.hashing_blob, pb);
    CHECK("parse_hashing_blob ok", pok);
    CHECK("blob-embedded tree_root == recovered tree_root", hex(pb.tree_root) == TREE_ROOT);
    CHECK("blob n_tx == 38", pb.n_tx == 38);

    // (v) tamper: flip one branch byte -> root no longer reproduces -> reject
    MoneroReceipt bad = r;
    bad.tree_branch.path[2][0] ^= 0x01;
    OpenedCommitment oc2;
    bool vbad = vf::verify_crypto_opening(bad, oc2, nullptr);
    CHECK("tampered branch is rejected", !vbad);

    std::printf("        opening chain reproduced: H(prefix)=%s...\n", H_PREFIX.substr(0,16).c_str());
    std::printf("                                  tx_hash =%s...\n", MINER_TX_HASH.substr(0,16).c_str());
    std::printf("                                  root    =%s...\n", TREE_ROOT.substr(0,16).c_str());
}

// ===========================================================================
// KAT-2: synthetic v37 receipt -- full keyed_heavy admission ORDER.
// ===========================================================================
static ::xmr::coin::PublicKey mk_key(u8 seed) {
    ::xmr::coin::PublicKey k;
    for (int i = 0; i < 32; ++i) k.data()[i] = static_cast<u8>(seed + i);
    return k;
}
static bytes32 mk_id(u8 seed) {
    bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<u8>(0xA0 ^ (seed + i)); return b;
}

static bool build_synth_receipt(const ReceiptSideData& sd, MoneroReceipt& out) {
    // real X1 coinbase serializer: one payee, height 3000000
    const std::uint64_t height = 3000000;
    const std::uint64_t amount = 600000000000ULL;   // ~0.6 XMR
    ::xmr::coin::PublicKey key = mk_key(0x40);
    ::xmr::coin::ViewTag vt; vt.tag = 0x11;
    std::vector<u8> head =
        ::xmr::coin::write_coinbase_prefix_head(height, &amount, &key, &vt, 1);

    // v37 tx_extra: 0x01 pubkey || 0x02 nonce(4) || 0x03 MM{depth0, mm_leaf}
    const bytes32 info    = vf::side_data_digest(sd);
    const bytes32 mm_leaf = vf::mm_commitment_leaf(sd.chain_id, info);
    std::vector<u8> extra;
    extra.push_back(0x01);
    for (int i = 0; i < 32; ++i) extra.push_back(static_cast<u8>(0x70 + i));   // tx pubkey R
    extra.push_back(0x02); put_varint(extra, 4);
    for (int i = 0; i < 4; ++i) extra.push_back(static_cast<u8>(i));            // nonce
    extra.push_back(0x03);
    { std::vector<u8> inner; put_varint(inner, 0);                              // depth
      inner.insert(inner.end(), mm_leaf.begin(), mm_leaf.end());               // root
      put_varint(extra, inner.size());
      extra.insert(extra.end(), inner.begin(), inner.end()); }

    // prefix = head || varint(len(extra)) || extra
    std::vector<u8> prefix = head;
    put_varint(prefix, extra.size());
    const std::size_t extra_start = prefix.size();
    prefix.insert(prefix.end(), extra.begin(), extra.end());

    vf::BuildInputs in;
    in.major = 16; in.minor = 16; in.timestamp = 1697813342;
    in.prev_id = mk_id(0x01); in.nonce = 0xdeadbeef;
    in.prefix_bytes = prefix; in.extra_start = extra_start;
    in.side_data = sd;                       // other_leaves empty => n_tx == 1
    in.seed_policy = SeedRefPolicy::DerivedFromBin;
    std::string why;
    bool ok = vf::build_v37_receipt(in, out, &why);
    if (!ok) std::printf("        build_v37_receipt failed: %s\n", why.c_str());
    return ok;
}

static void kat2_admission_order() {
    std::printf("[KAT-2] synthetic v37 receipt -- keyed_heavy admission ORDER\n");

    const u32 CHAIN = 0x584d5200u;                 // 'XMR\0' lane id (arbitrary)
    const bytes32 IDENT = mk_id(0x11);             // miner's payout identity == carrier
    const Difficulty T_ORIGIN{100000, 0};          // p2pool-class share target

    ReceiptSideData sd;
    sd.t_origin = T_ORIGIN;
    sd.payout_identity = IDENT;
    sd.chain_id = CHAIN;
    // prev_own_share display-only, left zero

    MoneroReceipt r;
    bool bok = build_synth_receipt(sd, r);
    CHECK("build synthetic v37 receipt", bok);
    CHECK("receipt within per-receipt byte budget",
          r.wire_size() <= budget::PER_RECEIPT_BUDGET);
    std::printf("        receipt wire_size = %zu B (cap %zu)\n",
                r.wire_size(), (std::size_t)budget::PER_RECEIPT_BUDGET);

    LaneKeyedHeavy lp;                              // r_max=2, n_ctx=2
    const u64 RECEIPT_BIN = 3000000;
    const u64 CARRIER_BIN = 3000001;               // 1 bin ahead, within n_ctx=2

    // ----- base config: index oracles wired; RandomX null => CI-gated -----
    vf::VerifyConfig cfg;
    cfg.bin_of = [&](const HashingBlob&, u64& b) { b = RECEIPT_BIN; return true; };
    cfg.consensus_difficulty = [&](u64, Difficulty& d) { d = T_ORIGIN; return true; };
    cfg.seed_for_bin = [&](u64, const SeedRef&, bytes32& s) { s = bytes32{}; return true; };
    cfg.seen = [&](const bytes32&) { return false; };
    // cfg.rx_check left null => stage 5 CI-gated

    // (a) clean receipt -> accepted, RandomX CI-gated
    {
        OpenedCommitment oc;
        AdmitOutcome o = vf::verify_receipt(r, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
        CHECK("(a) clean receipt accepted", o.ok && o.stage == AdmitStage::Accepted);
        CHECK("(a) RandomX CI-gated (SkippedCIGated)",
              o.randomx == RandomXStatus::SkippedCIGated);
        CHECK("(a) opened T_origin == committed side data", oc.t_origin == T_ORIGIN);
        CHECK("(a) opened payout identity bound", oc.payout_identity == IDENT);
        CHECK("(a) opened chain_id bound", oc.chain_id == CHAIN);
    }

    // (b) replayed receipt -> killed at stage 1 (Dedup); RandomX NEVER reached
    {
        vf::VerifyConfig c2 = cfg;
        c2.seen = [&](const bytes32&) { return true; };     // dedup hit
        OpenedCommitment oc;
        AdmitOutcome o = vf::verify_receipt(r, IDENT, CARRIER_BIN, CHAIN, lp, c2, oc);
        CHECK("(b) replay rejected at Dedup", !o.ok && o.stage == AdmitStage::Dedup);
        CHECK("(b) replay never touched RandomX", o.randomx == RandomXStatus::NotReached);
    }

    // (c) expired receipt (bin too old) -> killed at stage 2 (Expiry), no RandomX
    {
        OpenedCommitment oc;
        // carrier is 5 bins ahead; n_ctx = 2 => expired
        AdmitOutcome o = vf::verify_receipt(r, IDENT, RECEIPT_BIN + 5, CHAIN, lp, cfg, oc);
        CHECK("(c) expired rejected at Expiry", !o.ok && o.stage == AdmitStage::Expiry);
        CHECK("(c) expired never touched RandomX", o.randomx == RandomXStatus::NotReached);
    }

    // (d) tampered T_origin in the preimage -> info_digest changes -> the 0x03 MM
    //     leaf no longer matches -> killed at stage 3 (Structural), no RandomX
    {
        MoneroReceipt bad = r;
        bad.side_data->t_origin = Difficulty{999999, 0};    // preimage lie
        // (info_digest is NOT recomputed => info_digest != keccak256(side_data))
        OpenedCommitment oc;
        AdmitOutcome o = vf::verify_receipt(bad, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
        CHECK("(d) tampered T_origin rejected at Structural",
              !o.ok && o.stage == AdmitStage::Structural);
        CHECK("(d) tampered T_origin never touched RandomX",
              o.randomx == RandomXStatus::NotReached);
    }

    // (e) off-consensus T_origin: consistent preimage (rebuild) but consensus
    //     pins a different target -> killed at stage 4 (R1Target), no RandomX
    {
        ReceiptSideData sd2 = sd;
        sd2.t_origin = Difficulty{424242, 0};               // internally consistent...
        MoneroReceipt r2;
        bool ok2 = build_synth_receipt(sd2, r2);
        CHECK("(e) build off-consensus receipt", ok2);
        OpenedCommitment oc;
        // consensus still pins T_ORIGIN=100000, receipt says 424242
        AdmitOutcome o = vf::verify_receipt(r2, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
        CHECK("(e) off-consensus T_origin rejected at R1Target",
              !o.ok && o.stage == AdmitStage::R1Target);
        CHECK("(e) off-consensus never touched RandomX",
              o.randomx == RandomXStatus::NotReached);
    }

    // (f) with a stub hasher wired, stage 5 runs LAST and its verdict is honoured.
    {
        vf::VerifyConfig cpass = cfg;
        cpass.rx_check = [&](const bytes32&, const HashingBlob&, const Difficulty&,
                             bytes32& pow) { pow = bytes32{}; return true; };  // PoW meets target
        OpenedCommitment oc;
        AdmitOutcome o = vf::verify_receipt(r, IDENT, CARRIER_BIN, CHAIN, lp, cpass, oc);
        CHECK("(f) stub-PoW pass: accepted with RandomX Ran (last)",
              o.ok && o.stage == AdmitStage::Accepted && o.randomx == RandomXStatus::Ran);

        vf::VerifyConfig cfail = cfg;
        cfail.rx_check = [&](const bytes32&, const HashingBlob&, const Difficulty&,
                             bytes32&) { return false; };                      // PoW below target
        AdmitOutcome o2 = vf::verify_receipt(r, IDENT, CARRIER_BIN, CHAIN, lp, cfail, oc);
        CHECK("(f) stub-PoW fail: rejected at RandomX (only heavy reject)",
              !o2.ok && o2.stage == AdmitStage::RandomX && o2.randomx == RandomXStatus::Ran);
    }

    // path dispatch sanity
    CHECK("keyed_heavy dispatches to RandomX-last path",
          verify_path_for(PowVerifyClass::keyed_heavy) == VerifyPath::FamilyB_RandomXLast);
    CHECK("stateless_cheap keeps Family-A PoW-first path",
          verify_path_for(PowVerifyClass::stateless_cheap) == VerifyPath::FamilyA_PoWFirst);
}

int main() {
    std::printf("=== X4 MoneroReceipt envelope KAT (X1 primitives; RandomX CI-gated) ===\n");
    kat1_real_block();
    kat2_admission_order();
    std::printf("=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
