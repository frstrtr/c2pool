// SPDX-License-Identifier: MIT
//
// DASH S8 stratum job-notify round-trip contract KAT.
//
// Pins the second half of the get_work() -> stratum wire contract: the
// mining.notify merkle_branch. #630 (test_dash_stratum_binding) proved the
// extranonce2 (nonce64) coinbase-slot geometry; this leaf proves that the
// merkle_branch our server ships in mining.notify, when a miner folds its
// extranonce2-substituted coinbase through it (leaf index 0), reproduces the
// EXACT header merkle_root -- closing the loop:
//
//     get_work() --> [coinb1][extranonce2 slot][coinb2] + merkle_branch
//                 --> miner substitutes extranonce2, hashes coinbase
//                 --> folds branch (index 0) --> header merkle_root
//
// Oracle (frstrtr/p2pool-dash @9a0a609):
//   p2pool/work.py:474   header['merkle_root'] == check_merkle_link(
//                            hash256(new_packed_gentx), merkle_link)
//   p2pool/work.py:493   merkle_link = calculate_merkle_link(hashes, index)
//   p2pool/dash/data.py:189 calculate_merkle_link  (branch producer, index 0)
//   p2pool/dash/data.py:216 check_merkle_link       (miner-side fold)
//   p2pool/dash/data.py:180 merkle_hash             (full-tree root)
//
// merkle_record_type.pack(left,right) == left||right (32B internal LE each);
// hash256 == sha256d. For coinbase leaf index 0, every fold step places the
// running hash on the LEFT: cur = sha256d(cur || sibling).
//
// This binds the REAL landed producer dash::coinbase::merkle_branches_raw()
// (src/impl/dash/coinbase_builder.hpp) -- the exact code mining.notify uses.
// The miner-side fold + full-tree root are mirrored locally (the miner is
// cpuminer, not our code) and cross-checked THREE ways: (a) real branch folds
// to the locally-recomputed full root, (b) both equal externally-computed
// golden sha256d anchors (independent Python hashlib, NOT the oracle code),
// (c) round-trip is exercised across distinct extranonce2 values so the #630
// slot demonstrably propagates into the block-header merkle_root.
//
// Fenced: test/ + build.yml allowlist only. Non-consensus, socket-free,
// node-free -- pure synthetic CoinbaseLayout, no live node / RPC / P2P.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // merkle_branches_raw, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // HexStr
#include <core/uint256.hpp>

using dash::coinbase::merkle_branches_raw;
using dash::coinbase::sha256d;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// ── Synthetic fixtures ───────────────────────────────────────────────────────
// Same 40-byte coinbase as #630: bytes[i] = i, with the 8-byte nonce64 slot at
// [28,36) zeroed (nonce64_offset = 40 - locktime(4) - nonce64(8) = 28).
constexpr size_t kNonceOffset = 28;

// Build the coinbase bytes with `e2` (8 bytes) substituted into the nonce64 slot.
std::vector<unsigned char> build_coinbase(std::span<const unsigned char> e2) {
    std::vector<unsigned char> cb(40);
    for (size_t i = 0; i < 40; ++i) cb[i] = static_cast<unsigned char>(i);
    for (size_t i = kNonceOffset; i < kNonceOffset + EXTRANONCE2_SIZE; ++i) cb[i] = 0;
    std::memcpy(cb.data() + kNonceOffset, e2.data(), EXTRANONCE2_SIZE);
    return cb;
}

uint256 coinbase_hash(std::span<const unsigned char> e2) {
    auto cb = build_coinbase(e2);
    return sha256d(std::span<const unsigned char>(cb.data(), cb.size()));
}

// A 32-byte internal-order hash filled with a single byte (order-independent).
uint256 fill_hash(unsigned char b) {
    return uint256(std::vector<unsigned char>(32, b));
}

// sha256d(left || right), 32B internal LE each -- mirrors merkle_record_type.pack.
uint256 node(const uint256& l, const uint256& r) {
    std::vector<unsigned char> buf(64);
    auto lc = l.GetChars();
    auto rc = r.GetChars();
    std::memcpy(buf.data(),      lc.data(), 32);
    std::memcpy(buf.data() + 32, rc.data(), 32);
    return sha256d(std::span<const unsigned char>(buf.data(), buf.size()));
}

// Full merkle root (mirror of oracle dash_data.merkle_hash: duplicate-last on odd).
uint256 merkle_root_full(std::vector<uint256> leaves) {
    if (leaves.empty()) return uint256();
    while (leaves.size() > 1) {
        if (leaves.size() % 2 == 1) leaves.push_back(leaves.back());
        std::vector<uint256> next;
        next.reserve(leaves.size() / 2);
        for (size_t i = 0; i + 1 < leaves.size(); i += 2)
            next.push_back(node(leaves[i], leaves[i + 1]));
        leaves.swap(next);
    }
    return leaves[0];
}

// Miner-side fold for coinbase leaf index 0: running hash always on the LEFT
// (mirror of oracle check_merkle_link with index == 0).
uint256 fold_index0(const uint256& tip, const std::vector<uint256>& branch) {
    uint256 cur = tip;
    for (const auto& sib : branch) cur = node(cur, sib);
    return cur;
}

// Deliberately-wrong orientation (running hash on the RIGHT) -- for the guard
// that the LE-orientation the server encodes actually matters.
uint256 fold_wrongside(const uint256& tip, const std::vector<uint256>& branch) {
    uint256 cur = tip;
    for (const auto& sib : branch) cur = node(sib, cur);
    return cur;
}

const std::vector<unsigned char> E2_ZERO(8, 0x00);
const std::vector<unsigned char> E2_A{0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8};
const std::vector<unsigned char> E2_B{0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8};

// Independently-computed golden anchors (Python hashlib sha256d, NOT oracle
// code). Display (GetHex) form. Four-leaf tree: [coinbase, 0x11.., 0x22.., 0x33..].
const char* GOLD_BRANCH1  = "a3b916608afe957e34063e2253d49027536edf473f62d82891974f94fca5c569";
const char* GOLD_CBHASH_Z = "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab";
const char* GOLD_ROOT_Z   = "26f79b540fe6f2ac6fc52f37e5af5b33a61f33216bc4ec394635b24235850ea0";
const char* GOLD_CBHASH_A = "22a146527ac0731341d026480042a55cee0bdb804043b570af24feb9e76f2c8b";
const char* GOLD_ROOT_A   = "4b2d0948edb39954294fd28ca3926a78f0e56990c69d4fd7530a80a40491198e";
const char* GOLD_CBHASH_B = "04c8f4793537be307eaa2166642accc8265add0a59ccf4d01525f0ec54c6237a";
const char* GOLD_ROOT_B   = "72f7c45d5d6c65fd77053fec86d20d918681b92aba88c87f5aaa5bf7ab3a8230";

// Four-leaf tx set: coinbase placeholder at [0] + three sibling tx hashes.
std::vector<uint256> leaves_with(const uint256& cb) {
    return { cb, fill_hash(0x11), fill_hash(0x22), fill_hash(0x33) };
}

} // namespace

// (1) Producer geometry: a 4-leaf tree yields a 2-element merkle_branch, and
//     the placeholder value at [0] does not affect the branch (only siblings).
TEST(DashStratumNotifyRoundtrip, BranchDepthAndPlaceholderIndependence) {
    auto a = merkle_branches_raw(leaves_with(coinbase_hash(E2_ZERO)));
    auto b = merkle_branches_raw(leaves_with(coinbase_hash(E2_A)));
    ASSERT_EQ(a.size(), 2u);              // ceil(log2(4)) siblings
    EXPECT_EQ(a, b);                      // branch is coinbase-value-independent
    EXPECT_EQ(a[0].GetHex(), std::string(64, '1'));  // first sibling == 0x11..
    EXPECT_EQ(a[1].GetHex(), GOLD_BRANCH1);
}

// (2) Round-trip core (oracle work.py:474): folding the real notify branch over
//     the coinbase hash (index 0) reproduces the full-tree merkle_root exactly.
TEST(DashStratumNotifyRoundtrip, BranchFoldsToFullRoot) {
    uint256 cb = coinbase_hash(E2_ZERO);
    auto branch = merkle_branches_raw(leaves_with(cb));
    uint256 folded = fold_index0(cb, branch);
    uint256 full   = merkle_root_full(leaves_with(cb));
    EXPECT_EQ(folded, full);
    EXPECT_EQ(folded.GetHex(), GOLD_ROOT_Z);
}

// (3) Extranonce2 binds into the header root: distinct extranonce2 -> distinct
//     coinbase hash -> distinct folded merkle_root under the SAME branch. This
//     propagates #630's slot binding all the way into the block-header field.
TEST(DashStratumNotifyRoundtrip, Extranonce2BindsIntoMerkleRoot) {
    uint256 cbZ = coinbase_hash(E2_ZERO);
    uint256 cbA = coinbase_hash(E2_A);
    uint256 cbB = coinbase_hash(E2_B);
    // Branch is the same regardless of coinbase value (asserted in test 1); use it.
    auto branch = merkle_branches_raw(leaves_with(cbZ));

    uint256 rZ = fold_index0(cbZ, branch);
    uint256 rA = fold_index0(cbA, branch);
    uint256 rB = fold_index0(cbB, branch);

    // injective: three distinct extranonce2 -> three distinct roots
    EXPECT_NE(rZ, rA);
    EXPECT_NE(rZ, rB);
    EXPECT_NE(rA, rB);

    // each folded root equals both its full-tree recomputation and its golden.
    EXPECT_EQ(rA, merkle_root_full(leaves_with(cbA)));
    EXPECT_EQ(rB, merkle_root_full(leaves_with(cbB)));
    EXPECT_EQ(rA.GetHex(), GOLD_ROOT_A);
    EXPECT_EQ(rB.GetHex(), GOLD_ROOT_B);
}

// (4) Zero nonce is the identity element into the root as well: the E2_ZERO
//     coinbase reproduces the baseline root (complements #630 ZeroNonceIsIdentity).
TEST(DashStratumNotifyRoundtrip, ZeroNonceRootIsBaseline) {
    uint256 cb = coinbase_hash(E2_ZERO);
    EXPECT_EQ(cb.GetHex(), GOLD_CBHASH_Z);
    auto branch = merkle_branches_raw(leaves_with(cb));
    EXPECT_EQ(fold_index0(cb, branch).GetHex(), GOLD_ROOT_Z);
}

// (5) Solo-coinbase (single-tx block, oracle work.py:124/357 empty branch):
//     merkle_branches_raw returns an empty branch and the root IS the coinbase
//     hash -- the fold degenerates to the identity.
TEST(DashStratumNotifyRoundtrip, SoloCoinbaseEmptyBranch) {
    uint256 cb = coinbase_hash(E2_ZERO);
    auto branch = merkle_branches_raw({cb});          // one leaf -> empty branch
    EXPECT_TRUE(branch.empty());
    EXPECT_EQ(fold_index0(cb, branch), cb);
    EXPECT_EQ(merkle_root_full({cb}), cb);
}

// (6) Orientation guard: index-0 binding puts the running hash on the LEFT. The
//     opposite orientation yields a different root -- pinning the exact byte
//     order (the merkle_branches_hex LE-vs-display trap documented in-source).
TEST(DashStratumNotifyRoundtrip, FoldOrientationIndex0IsLeft) {
    uint256 cb = coinbase_hash(E2_A);
    auto branch = merkle_branches_raw(leaves_with(cb));
    EXPECT_EQ(fold_index0(cb, branch).GetHex(), GOLD_ROOT_A);
    EXPECT_NE(fold_index0(cb, branch), fold_wrongside(cb, branch));
}

// (7) Golden byte-parity anchors (independent Python sha256d). Non-circular:
//     these hex values were computed outside both the oracle and this code.
TEST(DashStratumNotifyRoundtrip, GoldenAnchors) {
    EXPECT_EQ(coinbase_hash(E2_ZERO).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(coinbase_hash(E2_A).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(coinbase_hash(E2_B).GetHex(),    GOLD_CBHASH_B);
    EXPECT_EQ(merkle_branches_raw(leaves_with(coinbase_hash(E2_ZERO)))[1].GetHex(), GOLD_BRANCH1);
}
