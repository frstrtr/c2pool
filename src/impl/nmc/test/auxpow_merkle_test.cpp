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

#include <algorithm>
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

// ---------------------------------------------------------------------------
// P1c: AuxPow::check_proof parent-coinbase tx-merkle leg (step 3) wiring.
//
// step 3 reconstructs the parent block's transaction merkle root from the
// WITNESS-STRIPPED parent coinbase txid through parent_coinbase_branch/index
// via aux_merkle_root(), and (once a parent header is present) requires it to
// equal parent_header.m_merkle_root. The load-bearing test asserts the exact
// byte serialization of the txid: it is hashed over the LEGACY (no-witness)
// layout -- txid, NOT wtxid -- so a coinbase carrying the BIP141 segwit
// reserved value still hashes witness-stripped. The legacy preimage is
// re-derived here field-by-field WITHOUT calling SerializeTransaction's
// witness/marker path, so a stray marker/flag byte is caught, not mirrored.
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY.
// ---------------------------------------------------------------------------

using nmc::coin::MutableTransaction;
using nmc::coin::TxIn;
using nmc::coin::TxOut;
using nmc::coin::parent_coinbase_txid;

// A minimal parent (BTC) coinbase carrying the BIP141 witness reserved value
// (single 32-byte zero stack item) -- exactly what a real segwit coinbase
// carries, so the txid path is forced to strip a present witness.
static MutableTransaction make_parent_coinbase()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffffu;
    static const unsigned char sig[] = {0x03, 0x4e, 0x4d, 0x43};  // arbitrary scriptSig
    in.scriptSig = OPScript(sig, sig + sizeof(sig));
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    return tx;
}

// Independent legacy (no-witness) txid: lay out version|vin|vout|locktime via
// PackStream directly (the TxIn serializer writes prevout+scriptSig+sequence,
// NO witness) and double-SHA256 it -- never touching parent_coinbase_txid's
// SerializeTransaction path.
static uint256 legacy_txid(const MutableTransaction& tx)
{
    PackStream ref;
    ref << tx.version;
    ref << tx.vin;
    ref << tx.vout;
    ref << tx.locktime;
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref.data()), ref.size());
    return Hash(sp);
}

TEST(NmcAuxParentCoinbase, TxidIsWitnessStrippedLegacyHashNotWtxid)
{
    auto cb = make_parent_coinbase();
    ASSERT_TRUE(cb.HasWitness());  // a real BTC coinbase carries the reserved value

    // (a) txid is hashed over the independently-laid-out legacy serialization.
    EXPECT_EQ(parent_coinbase_txid(cb), legacy_txid(cb));

    // (b) txid != wtxid: the with-witness hash differs precisely because the
    //     witness is present and the txid path must strip it.
    auto wpacked = pack(nmc::coin::TX_WITH_WITNESS(cb));
    uint256 wtxid = Hash(wpacked.get_span());
    EXPECT_NE(parent_coinbase_txid(cb), wtxid);
}

TEST(NmcAuxCheckProof, ParentLegReconstructingHeaderMerkleIsIncomplete)
{
    AuxPow ap;
    ap.parent_coinbase = make_parent_coinbase();
    uint256 cbid = parent_coinbase_txid(ap.parent_coinbase);
    uint256 sib  = leaf_of(0x55);
    ap.parent_coinbase_branch = {sib};
    ap.parent_coinbase_index  = 0;            // bit0=0 => coinbase LEFT
    // parent header commits the reconstructed tx-merkle-root; mark it non-null.
    ap.parent_header.m_merkle_root = combine(cbid, sib);
    ap.parent_header.m_bits = 1;              // non-null so the equality gate fires
    // chain leg left at defaults (empty branch, index 0) => passes step 1.
    EXPECT_EQ(ap.check_proof(leaf_of(0x01), 1),
              AuxPow::CheckResult::INCOMPLETE);
}

TEST(NmcAuxCheckProof, ParentLegNotReconstructingHeaderMerkleIsInvalid)
{
    AuxPow ap;
    ap.parent_coinbase = make_parent_coinbase();
    ap.parent_coinbase_branch = {leaf_of(0x55)};
    ap.parent_coinbase_index  = 0;
    ap.parent_header.m_merkle_root = leaf_of(0x99);  // deliberately wrong root
    ap.parent_header.m_bits = 1;                     // non-null => equality gate fires
    EXPECT_EQ(ap.check_proof(leaf_of(0x01), 1),
              AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxCheckProof, NegativeParentCoinbaseIndexIsInvalid)
{
    AuxPow ap;
    ap.parent_coinbase = make_parent_coinbase();
    ap.parent_coinbase_branch = {leaf_of(0x55)};
    ap.parent_coinbase_index  = -1;
    EXPECT_EQ(ap.check_proof(leaf_of(0x01), 1),
              AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxCheckProof, ParentCoinbaseIndexTooWideForDepthIsInvalid)
{
    AuxPow ap;
    ap.parent_coinbase = make_parent_coinbase();
    ap.parent_coinbase_branch = {leaf_of(0x55)};  // depth 1 => max index 1
    ap.parent_coinbase_index  = 2;
    EXPECT_EQ(ap.check_proof(leaf_of(0x01), 1),
              AuxPow::CheckResult::INVALID);
}


// ---------------------------------------------------------------------------
// P1c-step2: AuxPow::check_proof MM-marker commitment + chain_id/slot binding.
//
// step 2 confirms the chain-merkle root reconstructed in step 1 is the one
// committed inside the parent coinbase's merged-mining marker (pchMergedMiningHeader
// = fa be 6d 6d), that the marker's tree size == 2^height, and that the chain
// occupies the slot aux_expected_index(nonce, chain_id, height) demands. A
// coinbase with NO marker leaves the proof INCOMPLETE (staged: nothing to
// assert, mirrors the null-parent-header gate). A marker present but committing
// a different root / wrong size / wrong slot, or a duplicated marker, is INVALID.
// The proof never reaches VALID — step 4 (parent PoW) is still unbuilt.
//
// aux_expected_index is pinned against values computed OFFLINE (not by calling
// the production helper), so an LCG-constant/typo in the port is caught. The
// committed root is laid out here by hand (magic|reversed-root|LE size|LE nonce)
// without touching scan_mm_commitment, so a scan/parse bug is caught not mirrored.
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY.
// ---------------------------------------------------------------------------

using nmc::coin::scan_mm_commitment;
using nmc::coin::aux_expected_index;
using nmc::coin::MMScan;

static const unsigned char MM_MAGIC[4] = {0xfa, 0xbe, 'm', 'm'};

static void put_le32(std::vector<unsigned char>& v, uint32_t x)
{
    v.push_back(static_cast<unsigned char>( x        & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 8)  & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 24) & 0xff));
}

// The chain-merkle root as committed: reversed (big-endian display) byte order,
// derived here without touching scan_mm_commitment.
static std::vector<unsigned char> root_reversed(uint256 r)
{
    const unsigned char* p = reinterpret_cast<const unsigned char*>(r.begin());
    std::vector<unsigned char> v(p, p + uint256::BYTES);
    std::reverse(v.begin(), v.end());
    return v;
}

// [dummy coinbase-height prefix][magic][reversed root][LE size][LE nonce].
static std::vector<unsigned char> mm_script(const std::vector<unsigned char>& reversed_root,
                                            uint32_t size, uint32_t nonce)
{
    std::vector<unsigned char> s = {0x03, 0x11, 0x22, 0x33};  // arbitrary prefix
    s.insert(s.end(), MM_MAGIC, MM_MAGIC + 4);
    s.insert(s.end(), reversed_root.begin(), reversed_root.end());
    put_le32(s, size);
    put_le32(s, nonce);
    return s;
}

static MutableTransaction coinbase_with_script(const std::vector<unsigned char>& script)
{
    MutableTransaction tx;
    tx.version = 1; tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffffu;
    in.scriptSig = OPScript(script.data(), script.data() + script.size());
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut out; out.value = 5000000000LL; tx.vout.push_back(out);
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    return tx;
}

TEST(NmcAuxExpectedIndex, MatchesPinnedOfflineReference)
{
    // values computed offline via the LCG (1103515245 / 12345), chain_id = 1.
    EXPECT_EQ(aux_expected_index(0,     1, 3), 3u);
    EXPECT_EQ(aux_expected_index(1,     1, 3), 4u);
    EXPECT_EQ(aux_expected_index(7,     1, 3), 2u);
    EXPECT_EQ(aux_expected_index(0,     1, 1), 1u);
    EXPECT_EQ(aux_expected_index(1,     1, 1), 0u);
    EXPECT_EQ(aux_expected_index(12345, 1, 4), 12u);
}

TEST(NmcAuxStep2, ScanReturnsMatchAbsentMismatch)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);          // index bit0=0 => leaf left
    unsigned h = 1; int32_t cid = 1; uint32_t nonce = 1; uint32_t index = 0;  // slot 0

    auto good = mm_script(root_reversed(root), 1u << h, nonce);
    EXPECT_EQ(scan_mm_commitment(good, root, h, cid, index), MMScan::MATCH);

    std::vector<unsigned char> nomagic = {0x03, 0x11, 0x22, 0x33};
    EXPECT_EQ(scan_mm_commitment(nomagic, root, h, cid, index), MMScan::ABSENT);

    auto badroot = mm_script(root_reversed(leaf_of(0x99)), 1u << h, nonce);
    EXPECT_EQ(scan_mm_commitment(badroot, root, h, cid, index), MMScan::MISMATCH);
}

TEST(NmcAuxStep2, ValidCommitmentIsIncompleteNeverValid)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    auto script = mm_script(root_reversed(root), /*size=*/2, /*nonce=*/1);  // slot 0

    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    // parent_header null => step 3 equality skipped; step 2 MATCH; step 4 unbuilt.
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INCOMPLETE);
    EXPECT_NE(ap.check_proof(aux, 1), AuxPow::CheckResult::VALID);
}

TEST(NmcAuxStep2, WrongCommittedRootIsInvalid)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    auto script = mm_script(root_reversed(leaf_of(0x99)), 2, 1);  // commits wrong root
    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxStep2, WrongTreeSizeIsInvalid)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    auto script = mm_script(root_reversed(root), /*size=*/4, /*nonce=*/1);  // h=1 wants 2
    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxStep2, WrongDeterministicSlotIsInvalid)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);          // correct root for index 0
    // nonce 0 => expected slot 1 (pinned) != chain_merkle_index 0 => binding fails;
    // root + size are correct so only the slot check rejects this.
    auto script = mm_script(root_reversed(root), 2, /*nonce=*/0);
    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxStep2, DuplicateMergedMiningHeaderIsInvalid)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    auto script = mm_script(root_reversed(root), 2, 1);
    script.insert(script.end(), MM_MAGIC, MM_MAGIC + 4);  // a second, illegal header
    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxStep2, NoMarkerLeavesProofIncomplete)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    std::vector<unsigned char> nomagic = {0x03, 0x4e, 0x4d, 0x43};  // no MM magic
    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(nomagic);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = 0;
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INCOMPLETE);
}

} // namespace
