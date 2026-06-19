// ---------------------------------------------------------------------------
// nmc::coin::aux_merkle_root KAT (P1 — AuxPow merkle-proof walk).
//
// Pins the merge-mining merkle-branch walk that AuxPow::check_proof() (still a
// P-DEFER stub) will consume for step-1 (chain-merkle-root) and step-3 (parent
// tx-merkle-root). The walk is a byte-faithful port of legacy
// libcoind/data.cpp check_merkle_link() — the same SSOT btc uses — so these
// KATs lock the consensus-relevant ordering:
//   * empty branch        => root == leaf (identity);
//   * index bit i selects whether branch[i] is the LEFT or RIGHT sibling at
//     depth i, folded with double-SHA256 of the 64-byte concatenation;
//   * an index that does not fit in branch.size() bits is rejected.
//
// Expected roots are derived INDEPENDENTLY here via core::Hash on the explicit
// concatenation (not by calling aux_merkle_root), so a side-swap or fold bug in
// the walk is caught rather than mirrored. Self-derived => no fixture file.
//
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY (this is
// an independent NMC-local re-derivation, fence #4). MUST appear in BOTH
// test/CMakeLists.txt AND the build.yml --target allowlist or it becomes a
// NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/header_chain.hpp"

namespace {

using nmc::coin::aux_merkle_root;
using nmc::coin::AuxPow;

// Build a uint256 whose first byte is `b` (rest zero) — distinct, legible leaves.
static uint256 leaf_of(unsigned char b)
{
    uint256 u;
    u.SetNull();
    *(u.begin()) = b;
    return u;
}

// Independent reference combine: double-SHA256 of l||r, mirroring the legacy
// merkle node hash but computed here WITHOUT touching aux_merkle_root.
static uint256 combine(const uint256& l, const uint256& r)
{
    PackStream ps;
    ps << l;
    ps << r;
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
    return Hash(sp);
}

TEST(NmcAuxMerkle, EmptyBranchIsIdentity)
{
    uint256 leaf = leaf_of(0x11);
    EXPECT_EQ(aux_merkle_root(leaf, {}, 0), leaf);
    // index is ignored when there is no branch to walk.
    EXPECT_EQ(aux_merkle_root(leaf, {}, 12345u), leaf);
}

TEST(NmcAuxMerkle, SingleStepIndexZeroLeafOnLeft)
{
    uint256 leaf = leaf_of(0x11);
    uint256 sib  = leaf_of(0x22);
    // index bit 0 == 0  => leaf is LEFT, sibling RIGHT.
    EXPECT_EQ(aux_merkle_root(leaf, {sib}, 0), combine(leaf, sib));
}

TEST(NmcAuxMerkle, SingleStepIndexOneLeafOnRight)
{
    uint256 leaf = leaf_of(0x11);
    uint256 sib  = leaf_of(0x22);
    // index bit 0 == 1  => sibling LEFT, leaf RIGHT.
    EXPECT_EQ(aux_merkle_root(leaf, {sib}, 1), combine(sib, leaf));
}

TEST(NmcAuxMerkle, TwoStepFoldRespectsPerLevelIndexBits)
{
    uint256 leaf = leaf_of(0x11);
    uint256 b0   = leaf_of(0x22);
    uint256 b1   = leaf_of(0x33);
    // index = 0b10: level0 bit=0 (leaf left), level1 bit=1 (accum right).
    uint256 lvl0 = combine(leaf, b0);
    uint256 want = combine(b1, lvl0);
    EXPECT_EQ(aux_merkle_root(leaf, {b0, b1}, 0b10u), want);
}

TEST(NmcAuxMerkle, IndexTooLargeForBranchThrows)
{
    uint256 leaf = leaf_of(0x11);
    uint256 sib  = leaf_of(0x22);
    // one-element branch admits indices 0..1; 2 overflows the implied tree.
    EXPECT_THROW(aux_merkle_root(leaf, {sib}, 2u), std::invalid_argument);
}


// ---------------------------------------------------------------------------
// P1b: AuxPow::check_proof chain-merkle leg (step 1) wiring.
//
// check_proof() now reconstructs the merged-mining merkle root from the aux
// block hash through chain_merkle_branch/index via aux_merkle_root(). Steps 2
// (MM-marker commitment), 3 (parent-coinbase tx-merkle leg) and 4 (parent PoW)
// are NOT built, so a structurally-consistent walk returns INCOMPLETE — never
// VALID. A malformed slot index (negative, or wider than the branch depth)
// returns INVALID. These KATs pin exactly that boundary so the leg can never
// silently regress into asserting VALID before the rest of the proof exists.
// ---------------------------------------------------------------------------

TEST(NmcAuxCheckProof, ChainLegStructurallyValidIsIncomplete)
{
    AuxPow ap;
    ap.chain_merkle_branch = {leaf_of(0xbe)};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(leaf_of(0x01), /*expected_chain_id=*/1),
              AuxPow::CheckResult::INCOMPLETE);
}

TEST(NmcAuxCheckProof, EmptyChainBranchIsIncompleteNeverValid)
{
    AuxPow ap;  // empty branch, index 0 => identity walk, still not provable
    EXPECT_EQ(ap.check_proof(leaf_of(0x07), 1),
              AuxPow::CheckResult::INCOMPLETE);
    EXPECT_NE(ap.check_proof(leaf_of(0x07), 1),
              AuxPow::CheckResult::VALID);
}

TEST(NmcAuxCheckProof, NegativeChainIndexIsInvalid)
{
    AuxPow ap;
    ap.chain_merkle_branch = {leaf_of(0x0a)};
    ap.chain_merkle_index = -1;
    EXPECT_EQ(ap.check_proof(leaf_of(0x02), 1),
              AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxCheckProof, ChainIndexTooWideForDepthIsInvalid)
{
    AuxPow ap;
    ap.chain_merkle_branch = {leaf_of(0x0a)};  // depth 1 => max index 1
    ap.chain_merkle_index = 2;
    EXPECT_EQ(ap.check_proof(leaf_of(0x02), 1),
              AuxPow::CheckResult::INVALID);
}

} // namespace
