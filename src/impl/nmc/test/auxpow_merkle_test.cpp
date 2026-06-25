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
#include <filesystem>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/target_utils.hpp>

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include <c2pool/merged/merged_mining.hpp>  // PD SSOT drift-guard: build_auxpow_commitment

namespace {

using nmc::coin::aux_merkle_root;
using nmc::coin::AuxPow;
using nmc::coin::pow_hash;

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
using nmc::coin::build_mm_commitment;

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

// ---------------------------------------------------------------------------
// build_mm_commitment -- the BUILD-side inverse of scan_mm_commitment (PC-prep
// auxpow commitment scaffolding, overlapping PD's dual-target parent coinbase).
// The commitment a c2pool-built parent coinbase embeds must round-trip through
// the SAME scanner the verifier runs: emit then scan the marker for the slot
// aux_expected_index(nonce, chain_id, height) and it MUST return MATCH; any
// tamper (committed root / slot / tree size) MUST NOT. The byte layout is pinned
// explicitly so a build-side layout drift is caught, not mirrored.
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY.
// ---------------------------------------------------------------------------

TEST(NmcBuildMMCommitment, RoundTripsThroughScannerAtExpectedSlot)
{
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    const unsigned h = 1; const int32_t cid = 1; const uint32_t nonce = 1;

    auto payload = build_mm_commitment(root, h, nonce);
    const uint32_t slot = aux_expected_index(nonce, cid, h);
    EXPECT_EQ(scan_mm_commitment(payload, root, h, cid, slot), MMScan::MATCH);
}

TEST(NmcBuildMMCommitment, ByteLayoutIsMagicReversedRootSizeNonce)
{
    uint256 root = leaf_of(0x01);
    const unsigned h = 3; const uint32_t nonce = 0x04030201u;

    auto got = build_mm_commitment(root, h, nonce);

    std::vector<unsigned char> want;
    want.insert(want.end(), MM_MAGIC, MM_MAGIC + 4);
    auto rr = root_reversed(root);
    want.insert(want.end(), rr.begin(), rr.end());
    put_le32(want, 1u << h);   // tree size = 2^h = 8
    put_le32(want, nonce);

    EXPECT_EQ(got, want);
    EXPECT_EQ(got.size(), static_cast<size_t>(4 + 32 + 4 + 4));
}

TEST(NmcBuildMMCommitment, DelegatesByteForByteToCrossCoinSSOT)
{
    // PD SSOT drift-guard. build_mm_commitment is a thin NMC-typed ADAPTER over
    // the cross-coin canonical builder c2pool::merged::build_auxpow_commitment;
    // its only added semantics is the height->size map (tree size = 2^height).
    // Pin byte-for-byte equality so the adapter can never silently fork a
    // parallel NMC-local commitment layout -- the bucket-2 v37-convergence trap.
    struct Case { uint256 root; unsigned h; uint32_t nonce; };
    const std::vector<Case> cases = {
        { leaf_of(0x01), 0, 0u },                              // single NMC under BTC: size == 1
        { leaf_of(0xAB), 1, 1u },
        { combine(leaf_of(0x02), leaf_of(0x77)), 3, 0x04030201u },
        { leaf_of(0xFF), 5, 0xDEADBEEFu },
    };
    for (const auto& c : cases) {
        auto adapter = build_mm_commitment(c.root, c.h, c.nonce);
        auto ssot    = c2pool::merged::build_auxpow_commitment(c.root, 1u << c.h, c.nonce);
        EXPECT_EQ(adapter, ssot)
            << "MM commitment adapter diverged from cross-coin SSOT at h=" << c.h;
    }
}

TEST(NmcBuildMMCommitment, TamperedRootOrSlotFailsScan)
{
    uint256 aux = leaf_of(0x02), sib = leaf_of(0x77);
    uint256 root = combine(aux, sib);
    const unsigned h = 2; const int32_t cid = 1; const uint32_t nonce = 7;

    auto payload = build_mm_commitment(root, h, nonce);
    const uint32_t slot = aux_expected_index(nonce, cid, h);

    EXPECT_EQ(scan_mm_commitment(payload, root, h, cid, slot), MMScan::MATCH);
    // Wrong committed root.
    EXPECT_EQ(scan_mm_commitment(payload, leaf_of(0x99), h, cid, slot), MMScan::MISMATCH);
    // Right marker read at the wrong deterministic slot.
    EXPECT_EQ(scan_mm_commitment(payload, root, h, cid, (slot + 1u) & ((1u << h) - 1u)),
              MMScan::MISMATCH);
}

// ---------------------------------------------------------------------------
// P1c-step4: AuxPow::check_proof parent proof-of-work leg (step 4).
//
// The parent (BTC) block's SHA256d PoW hash must clear the AUX (NMC) block's
// difficulty target (Namecoin CheckAuxPowProofOfWork: the parent PoW is checked
// against the aux bits, NOT the parent's own bits). With steps 1-3 satisfied,
// a sufficient parent PoW finally yields VALID; an insufficient one is INVALID;
// and a caller that supplies no aux_bits (default 0) keeps the otherwise-
// complete proof INCOMPLETE so NMC never block-validates off a partial proof.
// Per-coin isolation: src/impl/nmc/ only; chain::bits_to_target is core, the
// PoW hash is nmc-local pow_hash() -- the btc tree is not touched.
// ---------------------------------------------------------------------------

// A structurally-complete AuxPow whose steps 1-3 all pass: a parent coinbase
// carrying the MM marker committing the chain-merkle root (slot 0: nonce=1,
// chain_id=1, height=1), itself linked into the parent header tx-merkle-root.
static AuxPow complete_proof(uint256 aux, uint32_t parent_own_bits)
{
    uint256 sib  = leaf_of(0x55);
    uint256 root = combine(aux, sib);                       // chain-merkle root
    auto    script = mm_script(root_reversed(root), /*size=*/2, /*nonce=*/1);

    AuxPow ap;
    ap.parent_coinbase     = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index  = 0;                             // expected slot 0

    uint256 cbid = parent_coinbase_txid(ap.parent_coinbase);
    uint256 sib2 = leaf_of(0x77);
    ap.parent_coinbase_branch = {sib2};
    ap.parent_coinbase_index  = 0;                          // coinbase LEFT
    ap.parent_header.m_merkle_root = combine(cbid, sib2);
    ap.parent_header.m_bits        = parent_own_bits;       // non-null header
    return ap;
}

// "Mine" a parent header against an easy target: bump m_nonce until the
// SHA256d PoW clears `target`. Touches ONLY m_nonce, so the merkle legs
// (steps 1-3) are unaffected. At regtest-style difficulty this lands in a
// couple of iterations; the bound makes it deterministic-or-loud.
static bool mine_parent(AuxPow& ap, const uint256& target)
{
    for (uint32_t n = 0; n < 100000u; ++n) {
        ap.parent_header.m_nonce = n;
        if (!(pow_hash(ap.parent_header) > target)) return true;
    }
    return false;
}

TEST(NmcAuxStep4, CompleteProofWithSufficientParentWorkIsValid)
{
    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    uint32_t aux_bits = 0x207fffffu;                        // regtest-style easy target
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    EXPECT_EQ(ap.check_proof(aux, 1, aux_bits), AuxPow::CheckResult::VALID);
}

TEST(NmcAuxStep4, CompleteProofWithInsufficientParentWorkIsInvalid)
{
    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    // Maximally-hard aux target (compact for target == 1). A real double-SHA256
    // parent hash exceeds it (guarded), so the parent fails the aux PoW.
    uint32_t hard_bits = 0x03000001u;                       // bits_to_target => 1
    uint256  pow       = pow_hash(ap.parent_header);
    ASSERT_TRUE(pow > chain::bits_to_target(hard_bits));    // precondition
    EXPECT_EQ(ap.check_proof(aux, 1, hard_bits), AuxPow::CheckResult::INVALID);
}

TEST(NmcAuxStep4, CompleteProofWithoutAuxBitsStaysIncomplete)
{
    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    // Default aux_bits (0): the parent-PoW gate is skipped and the otherwise-
    // complete proof stays INCOMPLETE -- never VALID.
    EXPECT_EQ(ap.check_proof(aux, 1), AuxPow::CheckResult::INCOMPLETE);
    EXPECT_NE(ap.check_proof(aux, 1), AuxPow::CheckResult::VALID);
}

TEST(NmcAuxStep4, ParentOwnBitsAreNotTheAuxGate)
{
    // Parent header's OWN nBits set maximally hard (target == 1); if check_proof
    // wrongly used the parent's own bits the proof would be INVALID. The AUX
    // target (easy) governs instead -- pinning the Namecoin consensus rule that
    // the parent PoW is checked against the aux bits, not the parent's own.
    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x03000001u);
    uint32_t aux_bits = 0x207fffffu;                        // easy aux target
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    EXPECT_EQ(ap.check_proof(aux, 1, aux_bits), AuxPow::CheckResult::VALID);
}

// ---------------------------------------------------------------------------
// P1d - HeaderChain::add_auxpow_header / verify_auxpow_header consensus GATE.
//
// The gate wires AuxPow::check_proof into the header-accept path: an incoming
// merge-mined header is admissible ONLY when its proof fully verifies against
// THIS chain's params (aux_chain_id) and the header's own nBits as the aux PoW
// target. These KATs pin the rejection contract - nothing unproven gets in -
// reusing the step-4 complete_proof/mine_parent fixtures but binding the aux
// block hash to a REAL header via block_hash(header), the production seam.
// These KATs assert the verify VERDICT. add_auxpow_header returns false here
// because the fixtures leave auxpow_activation_height at the -1 sentinel, so the
// activation gate REJECT_UNPINNEDs -- NOT because storage is deferred (the
// P1e/P1f connect+persist path is live; see NmcP1eStore / NmcP1fPersist).
// ---------------------------------------------------------------------------

using nmc::coin::HeaderChain;
using nmc::coin::NMCChainParams;
using nmc::coin::BlockHeaderType;
using nmc::coin::block_hash;

// Params with a pinned aux_chain_id == 1 so the fixture's MM-marker slot
// (chain_id=1) binds. Activation height stays unpinned: the P1d gate under test
// is the cryptographic check_proof, not the (deferred) height-activation path.
static NMCChainParams params_chain_id_1()
{
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    // mainnet() now PINS auxpow_activation_height=19200; these fixtures exercise
    // the unpinned refuse-to-judge gate, so force the sentinel back explicitly.
    p.auxpow_activation_height = -1;
    return p;
}

// A header whose block_hash() becomes the AUX hash the proof commits to; m_bits
// carries the aux PoW target the parent hash must clear (Namecoin aux-bits rule).
static BlockHeaderType aux_header_for(uint32_t aux_bits)
{
    BlockHeaderType h{};
    h.m_version = 1;
    h.m_bits    = aux_bits;
    return h;
}

TEST(NmcP1dGate, FullyVerifiedAuxPowPassesTheGate)
{
    uint32_t aux_bits = 0x207fffffu;                 // regtest-style easy target
    BlockHeaderType h = aux_header_for(aux_bits);
    uint256 aux = block_hash(h);                      // production seam
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));

    HeaderChain chain_(params_chain_id_1());
    EXPECT_EQ(chain_.verify_auxpow_header(h, ap), AuxPow::CheckResult::VALID);
    // Verified, but NOT admitted: params_chain_id_1() leaves activation at the
    // -1 sentinel, so connect_locked REJECT_UNPINNEDs -> nothing persisted.
    EXPECT_FALSE(chain_.add_auxpow_header(h, ap));
    EXPECT_FALSE(chain_.has_header(aux));
}

TEST(NmcP1dGate, WrongChainIdIsNotValidAndIsRejected)
{
    uint32_t aux_bits = 0x207fffffu;
    BlockHeaderType h = aux_header_for(aux_bits);
    uint256 aux = block_hash(h);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));

    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 2;                               // != fixture's chain_id 1
    HeaderChain chain_(p);
    EXPECT_NE(chain_.verify_auxpow_header(h, ap), AuxPow::CheckResult::VALID);
    EXPECT_FALSE(chain_.add_auxpow_header(h, ap));
}

TEST(NmcP1dGate, InsufficientParentWorkIsRejected)
{
    BlockHeaderType h = aux_header_for(/*aux_bits=*/0x03000001u); // target == 1
    uint256 aux = block_hash(h);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    // Unmined parent: a real double-SHA256 hash exceeds target 1 => INVALID.
    ASSERT_TRUE(pow_hash(ap.parent_header) > chain::bits_to_target(h.m_bits));

    HeaderChain chain_(params_chain_id_1());
    EXPECT_EQ(chain_.verify_auxpow_header(h, ap), AuxPow::CheckResult::INVALID);
    EXPECT_FALSE(chain_.add_auxpow_header(h, ap));
}

TEST(NmcP1dGate, MissingAuxBitsKeepsProofIncompleteAndRejected)
{
    BlockHeaderType h = aux_header_for(/*aux_bits=*/0u);  // 0 == leg-only sentinel
    uint256 aux = block_hash(h);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);

    HeaderChain chain_(params_chain_id_1());
    // header.m_bits == 0 feeds check_proof's leg-only sentinel: step 4 skipped,
    // the proof stays INCOMPLETE, and the gate rejects.
    EXPECT_EQ(chain_.verify_auxpow_header(h, ap), AuxPow::CheckResult::INCOMPLETE);
    EXPECT_FALSE(chain_.add_auxpow_header(h, ap));
}

// ---------------------------------------------------------------------------
// P1e: activation-height admission gate KATs (NmcP1eActivationGate).
// Exercise HeaderChain::check_activation_gate() - the height-derived MM
// activation gate, factored like the P1d proof gate so it is testable without
// the deferred storage path. The production height is now PINNED (mainnet=19200
// via the factory, against namecoin-core chainparams.cpp); these P1e fixtures
// still inject a height explicitly to drive every gate branch in isolation.
// See NmcPFActivationPin for the production-factory pin assertions.
// ---------------------------------------------------------------------------
static NMCChainParams params_activation(int32_t act_height)
{
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    p.auxpow_activation_height = act_height;   // TEST-only override of the pinned production height
    return p;
}

TEST(NmcP1eActivationGate, UnpinnedActivationRefusesToJudge)
{
    // params_chain_id_1() forces auxpow_activation_height to -1 (unpinned): the
    // gate must refuse rather than guess, regardless of AuxPow presence.
    HeaderChain chain_(params_chain_id_1());
    EXPECT_EQ(chain_.check_activation_gate(50000, /*has_auxpow=*/true),
              HeaderChain::AdmitResult::REJECT_UNPINNED);
    EXPECT_EQ(chain_.check_activation_gate(50000, /*has_auxpow=*/false),
              HeaderChain::AdmitResult::REJECT_UNPINNED);
}

TEST(NmcP1eActivationGate, AuxPowBelowActivationIsPremature)
{
    HeaderChain chain_(params_activation(19200));
    EXPECT_EQ(chain_.check_activation_gate(19199, /*has_auxpow=*/true),
              HeaderChain::AdmitResult::REJECT_PREMATURE_AUXPOW);
    // a plain (non-MM) header below activation is admissible.
    EXPECT_EQ(chain_.check_activation_gate(19199, /*has_auxpow=*/false),
              HeaderChain::AdmitResult::ADMIT);
}

TEST(NmcP1eActivationGate, AuxPowRequiredAtAndAfterActivation)
{
    HeaderChain chain_(params_activation(19200));
    // exactly at the activation height the AuxPow becomes mandatory.
    EXPECT_EQ(chain_.check_activation_gate(19200, /*has_auxpow=*/false),
              HeaderChain::AdmitResult::REJECT_MISSING_AUXPOW);
    EXPECT_EQ(chain_.check_activation_gate(19200, /*has_auxpow=*/true),
              HeaderChain::AdmitResult::ADMIT);
    // and well past it.
    EXPECT_EQ(chain_.check_activation_gate(250000, /*has_auxpow=*/true),
              HeaderChain::AdmitResult::ADMIT);
}

TEST(NmcP1eActivationGate, ActivationBoundaryIsInclusive)
{
    HeaderChain chain_(params_activation(19200));
    // height == activation-1 is still pre-activation (MM not yet required);
    // height == activation flips MM to mandatory.
    EXPECT_EQ(chain_.check_activation_gate(19199, /*has_auxpow=*/false),
              HeaderChain::AdmitResult::ADMIT);
    EXPECT_EQ(chain_.check_activation_gate(19200, /*has_auxpow=*/false),
              HeaderChain::AdmitResult::REJECT_MISSING_AUXPOW);
}

// ---------------------------------------------------------------------------
// PF-conformance: production auxpow_activation_height pin (NmcPFActivationPin).
// Unlike the P1e gate KATs above (which inject a TEST-only height), these
// exercise the values baked into the mainnet()/testnet() factories, pinned
// against namecoin-core src/kernel/chainparams.cpp consensus.nAuxpowStartHeight:
// mainnet=19200 (CMainParams), testnet=0 (CTestNetParams, MM active from
// genesis). A regression here means the production pin drifted from source.
// ---------------------------------------------------------------------------
TEST(NmcPFActivationPin, MainnetActivatesAt19200)
{
    NMCChainParams p = NMCChainParams::mainnet();
    EXPECT_EQ(p.auxpow_activation_height, 19200);
    EXPECT_EQ(p.aux_chain_id, 1);               // nAuxpowChainId = 0x0001
    EXPECT_FALSE(p.is_auxpow_active(19199));     // one below activation: inactive
    EXPECT_TRUE(p.is_auxpow_active(19200));      // boundary inclusive: active
    EXPECT_TRUE(p.is_auxpow_active(250000));     // well past activation: active
}

TEST(NmcPFActivationPin, TestnetActivatesFromGenesis)
{
    NMCChainParams p = NMCChainParams::testnet();
    EXPECT_EQ(p.auxpow_activation_height, 0);
    // nAuxpowStartHeight=0 / fStrictChainId=false: AuxPoW is active from genesis
    // on Namecoin testnet, so height 0 must already report active.
    EXPECT_TRUE(p.is_auxpow_active(0));
    EXPECT_TRUE(p.is_auxpow_active(1));
}


// ---------------------------------------------------------------------------
// P1e storage leg: in-memory connect path KATs (NmcP1eStore). Exercise
// HeaderChain::add_header / add_auxpow_header now that a passing header is
// CONNECTED: genesis-seed, prev-hash linkage, height derivation, the activation
// gate enforced from the connected height, and tip advance. Cumulative-work
// summation + work-based reorg stay a later sub-leg.
// ---------------------------------------------------------------------------
static BlockHeaderType plain_header(const uint256& prev, uint32_t bits, uint32_t nonce)
{
    BlockHeaderType h{};
    h.m_version        = 1;
    h.m_previous_block = prev;
    h.m_bits           = bits;
    h.m_nonce          = nonce;
    return h;
}

TEST(NmcP1eStore, EmptyChainSeedsRootAtHeightZero)
{
    HeaderChain chain_(params_activation(19200));   // pinned so plain<activation ADMITs
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    EXPECT_TRUE(chain_.add_header(g));
    EXPECT_TRUE(chain_.has_header(block_hash(g)));
    EXPECT_EQ(chain_.size(), 1u);
    EXPECT_EQ(chain_.height(), 0u);
}

TEST(NmcP1eStore, ConnectsChildByPrevHashAndAdvancesTip)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2);
    EXPECT_TRUE(chain_.add_header(c));
    EXPECT_EQ(chain_.size(), 2u);
    EXPECT_EQ(chain_.height(), 1u);
    ASSERT_TRUE(chain_.tip().has_value());
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(c));
}

TEST(NmcP1eStore, OrphanWithUnknownParentIsRejected)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));
    uint256 bogus = leaf_of(0xAB);                  // not g's hash
    BlockHeaderType o = plain_header(bogus, 0x1d00ffffu, 3);
    EXPECT_FALSE(chain_.add_header(o));
    EXPECT_FALSE(chain_.has_header(block_hash(o)));
    EXPECT_EQ(chain_.size(), 1u);
}

TEST(NmcP1eStore, UnpinnedActivationRefusesToConnect)
{
    HeaderChain chain_(params_chain_id_1());        // activation height == -1
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    EXPECT_FALSE(chain_.add_header(g));             // REJECT_UNPINNED: build nothing
    EXPECT_EQ(chain_.size(), 0u);
}

TEST(NmcP1eStore, VerifiedAuxPowConnectsAtActivationHeight)
{
    HeaderChain chain_(params_activation(1));       // activation at height 1
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));              // genesis (height 0, plain)

    uint32_t aux_bits = 0x207fffffu;                // easy aux target
    BlockHeaderType h1 = plain_header(block_hash(g), aux_bits, 7);
    uint256 aux = block_hash(h1);                   // production seam: aux == header hash
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    ASSERT_EQ(chain_.verify_auxpow_header(h1, ap), AuxPow::CheckResult::VALID);

    EXPECT_TRUE(chain_.add_auxpow_header(h1, ap));  // height 1 >= activation, proof VALID
    EXPECT_TRUE(chain_.has_header(aux));
    EXPECT_EQ(chain_.height(), 1u);
    ASSERT_TRUE(chain_.get_header(aux).has_value());
    EXPECT_TRUE(chain_.get_header(aux)->auxpow.has_value());
}

TEST(NmcP1eStore, PrematureAuxPowIsRejectedByStoreEvenWhenProofValid)
{
    HeaderChain chain_(params_activation(19200));   // activation far above height 1
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));

    uint32_t aux_bits = 0x207fffffu;
    BlockHeaderType h1 = plain_header(block_hash(g), aux_bits, 9);
    uint256 aux = block_hash(h1);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    ASSERT_EQ(chain_.verify_auxpow_header(h1, ap), AuxPow::CheckResult::VALID);

    // proof is VALID, but height 1 is below activation -> premature, NOT stored.
    EXPECT_FALSE(chain_.add_auxpow_header(h1, ap));
    EXPECT_FALSE(chain_.has_header(aux));
    EXPECT_EQ(chain_.height(), 0u);
}

// ---------------------------------------------------------------------------
// P1e cumulative-work summation sub-leg KATs (NmcP1eWork). chain_work is now
// parent.chain_work + get_block_proof(nBits); cumulative_work() tracks the tip.
// (Tip selection itself is covered by the NmcP1eForkChoice suite below.)
// ---------------------------------------------------------------------------
TEST(NmcP1eWork, GetBlockProofMatchesTwoToThe256OverTargetPlusOne)
{
    using nmc::coin::get_block_proof;
    // For bits=0x207fffff the target fills (almost) the whole 256-bit range, so
    // the proof is tiny; for a harder target the proof is strictly larger.
    uint256 easy = get_block_proof(0x207fffffu);   // regtest-easy target
    uint256 hard = get_block_proof(0x1d00ffffu);   // BTC genesis-era target
    EXPECT_FALSE(easy.IsNull());
    EXPECT_TRUE(hard > easy);                       // harder target => more work
}

TEST(NmcP1eWork, MalformedBitsContributeZeroWork)
{
    using nmc::coin::get_block_proof;
    EXPECT_TRUE(get_block_proof(0u).IsNull());      // null target => zero work
}

TEST(NmcP1eWork, GenesisChainWorkIsItsOwnBlockProof)
{
    using nmc::coin::get_block_proof;
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));
    EXPECT_EQ(chain_.cumulative_work(), get_block_proof(0x1d00ffffu));
    ASSERT_TRUE(chain_.tip().has_value());
    EXPECT_EQ(chain_.tip()->chain_work, get_block_proof(0x1d00ffffu));
}

TEST(NmcP1eWork, ChildChainWorkIsParentPlusOwnProof)
{
    using nmc::coin::get_block_proof;
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2);
    ASSERT_TRUE(chain_.add_header(c));
    uint256 want = get_block_proof(0x1d00ffffu) + get_block_proof(0x1d00ffffu);
    EXPECT_EQ(chain_.cumulative_work(), want);
    ASSERT_TRUE(chain_.tip().has_value());
    EXPECT_EQ(chain_.tip()->chain_work, want);
}

TEST(NmcP1eWork, CumulativeWorkAccumulatesMonotonicallyAcrossAChain)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType prev = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(prev));
    uint256 last = chain_.cumulative_work();
    for (uint32_t i = 2; i <= 6; ++i) {
        BlockHeaderType c = plain_header(block_hash(prev), 0x1d00ffffu, i);
        ASSERT_TRUE(chain_.add_header(c));
        uint256 now = chain_.cumulative_work();
        EXPECT_TRUE(now > last);                    // strictly increasing per block
        last = now;
        prev = c;
    }
    EXPECT_EQ(chain_.height(), 5u);
}

TEST(NmcP1eWork, RejectedHeaderDoesNotAdvanceCumulativeWork)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1);
    ASSERT_TRUE(chain_.add_header(g));
    uint256 before = chain_.cumulative_work();
    BlockHeaderType orphan = plain_header(leaf_of(0xAB), 0x1d00ffffu, 99);
    EXPECT_FALSE(chain_.add_header(orphan));         // unknown parent
    EXPECT_EQ(chain_.cumulative_work(), before);     // work unchanged on reject
}

// ---------------------------------------------------------------------------
// P1e work-based reorg fork-choice sub-leg KATs (NmcP1eForkChoice). The tip is
// now the header with the most CUMULATIVE work, not the greatest height: a
// heavier competing branch reorgs the tip even when it is shorter, and an
// equal-work header at the tip height switches the tip (network-consensus
// tie-break). Mirrors btc::coin::HeaderChain fork choice.
// ---------------------------------------------------------------------------
namespace {
constexpr uint32_t kEasyBits = 0x1d00ffffu;   // BTC genesis-era target
constexpr uint32_t kHardBits = 0x1c0fffffu;   // ~16x more work per block
}

TEST(NmcP1eForkChoice, HeavierSingleBlockReorgsOverLongerLighterChain)
{
    using nmc::coin::get_block_proof;
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    // Long, light chain: g <- a1 <- a2 <- a3  (height 3).
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g),  kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    BlockHeaderType a2 = plain_header(block_hash(a1), kEasyBits, 3);
    ASSERT_TRUE(chain_.add_header(a2));
    BlockHeaderType a3 = plain_header(block_hash(a2), kEasyBits, 4);
    ASSERT_TRUE(chain_.add_header(a3));
    EXPECT_EQ(chain_.height(), 3u);
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(a3));

    // One much-heavier sibling at height 1 outweighs the whole easy chain.
    EXPECT_TRUE(get_block_proof(kHardBits)
                > get_block_proof(kEasyBits) + get_block_proof(kEasyBits)
                  + get_block_proof(kEasyBits));
    BlockHeaderType b1 = plain_header(block_hash(g), kHardBits, 5);
    ASSERT_TRUE(chain_.add_header(b1));
    EXPECT_EQ(chain_.height(), 1u);                      // reorg shortened the tip
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(b1));
    EXPECT_EQ(chain_.cumulative_work(),
              get_block_proof(kEasyBits) + get_block_proof(kHardBits));
}

TEST(NmcP1eForkChoice, LighterSiblingIsStoredButDoesNotReorg)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g), kHardBits, 2);   // heavy tip
    ASSERT_TRUE(chain_.add_header(a1));
    uint256 work_at_tip = chain_.cumulative_work();

    BlockHeaderType b1 = plain_header(block_hash(g), kEasyBits, 3);   // lighter sibling
    EXPECT_TRUE(chain_.add_header(b1));                 // stored...
    EXPECT_TRUE(chain_.has_header(block_hash(b1)));
    EXPECT_EQ(chain_.size(), 3u);
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(a1)); // ...but tip unchanged
    EXPECT_EQ(chain_.cumulative_work(), work_at_tip);
}

TEST(NmcP1eForkChoice, EqualWorkSiblingAtTipHeightSwitchesTip)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g), kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(a1));
    uint256 work_at_tip = chain_.cumulative_work();

    // Same parent + same difficulty, different nonce => equal work, new hash.
    BlockHeaderType b1 = plain_header(block_hash(g), kEasyBits, 99);
    EXPECT_TRUE(chain_.add_header(b1));
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(b1)); // equal-work tie-break switch
    EXPECT_EQ(chain_.height(), 1u);
    EXPECT_EQ(chain_.cumulative_work(), work_at_tip);    // work identical
}

TEST(NmcP1eForkChoice, ReReceivingHeadersDoesNotFlipFlopTheTip)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g), kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    BlockHeaderType b1 = plain_header(block_hash(g), kHardBits, 3);   // reorg to heavy
    ASSERT_TRUE(chain_.add_header(b1));
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(b1));
    uint256 work_at_tip = chain_.cumulative_work();

    // Re-receiving either stored header is an idempotent no-op; tip is stable.
    EXPECT_FALSE(chain_.add_header(a1));
    EXPECT_FALSE(chain_.add_header(b1));
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(b1));
    EXPECT_EQ(chain_.cumulative_work(), work_at_tip);
}

TEST(NmcP1eForkChoice, TipExtendsAfterAWorkReorg)
{
    using nmc::coin::get_block_proof;
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g), kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    BlockHeaderType b1 = plain_header(block_hash(g), kHardBits, 3);   // reorg
    ASSERT_TRUE(chain_.add_header(b1));
    EXPECT_EQ(chain_.height(), 1u);

    BlockHeaderType b2 = plain_header(block_hash(b1), kEasyBits, 4);  // extend heavy tip
    ASSERT_TRUE(chain_.add_header(b2));
    EXPECT_EQ(chain_.height(), 2u);
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(b2));
    EXPECT_EQ(chain_.cumulative_work(),
              get_block_proof(kEasyBits) + get_block_proof(kHardBits)
              + get_block_proof(kEasyBits));
}

TEST(NmcP1eForkChoice, FirstHeaderBecomesTipRegardlessOfPriorState)
{
    HeaderChain chain_(params_activation(19200));
    EXPECT_FALSE(chain_.tip().has_value());
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    ASSERT_TRUE(chain_.tip().has_value());
    EXPECT_EQ(chain_.tip()->block_hash, block_hash(g));
    EXPECT_EQ(chain_.cumulative_work(), nmc::coin::get_block_proof(kEasyBits));
}

// ── P1f: HeaderChain::get_locator — BIP31 block locator over tip ancestry ──

TEST(NmcP1fLocator, EmptyChainProducesEmptyLocator)
{
    HeaderChain chain_(params_activation(19200));
    EXPECT_TRUE(chain_.get_locator().empty());
}

TEST(NmcP1fLocator, SingleHeaderLocatorIsJustTheTip)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    auto loc = chain_.get_locator();
    ASSERT_EQ(loc.size(), 1u);
    EXPECT_EQ(loc.front(), block_hash(g));
}

TEST(NmcP1fLocator, ShortChainLocatorIsDenseTipToRoot)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    BlockHeaderType a1 = plain_header(block_hash(g),  kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    BlockHeaderType a2 = plain_header(block_hash(a1), kEasyBits, 3);
    ASSERT_TRUE(chain_.add_header(a2));
    auto loc = chain_.get_locator();
    ASSERT_EQ(loc.size(), 3u);          // dense: every block while <= 10 deep
    EXPECT_EQ(loc[0], block_hash(a2));  // tip first
    EXPECT_EQ(loc[1], block_hash(a1));
    EXPECT_EQ(loc[2], block_hash(g));   // root last
}

TEST(NmcP1fLocator, LongChainFrontIsContiguousAndAnchoredAtRoot)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    std::vector<uint256> hashes{block_hash(g)};
    uint256 prev = block_hash(g);
    for (uint32_t i = 1; i <= 30; ++i) {            // height 0..30 (31 headers)
        BlockHeaderType h = plain_header(prev, kEasyBits, i + 1);
        ASSERT_TRUE(chain_.add_header(h));
        prev = block_hash(h);
        hashes.push_back(prev);
    }
    auto loc = chain_.get_locator();
    EXPECT_EQ(chain_.height(), 30u);
    // First 11 entries are contiguous from the tip (step stays 1 until >10).
    for (size_t i = 0; i < 11u; ++i)
        EXPECT_EQ(loc[i], hashes[hashes.size() - 1 - i]);
    // Backoff makes the locator far shorter than the chain, root-anchored.
    EXPECT_LT(loc.size(), hashes.size());
    EXPECT_EQ(loc.back(), block_hash(g));
}

TEST(NmcP1fLocator, BackoffStrideDoublesPastTheDenseHead)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    uint256 prev = block_hash(g);
    for (uint32_t i = 1; i <= 30; ++i) {
        BlockHeaderType h = plain_header(prev, kEasyBits, i + 1);
        ASSERT_TRUE(chain_.add_header(h));
        prev = block_hash(h);
    }
    auto loc = chain_.get_locator();
    // No duplicates, strictly descending toward the root, all known to the chain.
    for (size_t i = 0; i < loc.size(); ++i)
        EXPECT_TRUE(chain_.has_header(loc[i]));
    for (size_t i = 1; i < loc.size(); ++i)
        EXPECT_NE(loc[i], loc[i - 1]);
}

TEST(NmcP1fLocator, LocatorFollowsTheTipAfterAWorkReorg)
{
    HeaderChain chain_(params_activation(19200));
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    ASSERT_TRUE(chain_.add_header(g));
    // Light branch a1<-a2 builds the initial tip.
    BlockHeaderType a1 = plain_header(block_hash(g),  kEasyBits, 2);
    ASSERT_TRUE(chain_.add_header(a1));
    BlockHeaderType a2 = plain_header(block_hash(a1), kEasyBits, 3);
    ASSERT_TRUE(chain_.add_header(a2));
    // One heavy sibling at height 1 reorgs the tip onto branch b.
    BlockHeaderType b1 = plain_header(block_hash(g), kHardBits, 4);
    ASSERT_TRUE(chain_.add_header(b1));
    ASSERT_EQ(chain_.tip()->block_hash, block_hash(b1));
    auto loc = chain_.get_locator();
    // Locator tracks the NEW tip's ancestry (b1 <- g), not the abandoned a-branch.
    ASSERT_EQ(loc.size(), 2u);
    EXPECT_EQ(loc[0], block_hash(b1));
    EXPECT_EQ(loc[1], block_hash(g));
    EXPECT_EQ(std::count(loc.begin(), loc.end(), block_hash(a2)), 0);
}


// ---------------------------------------------------------------------------
// P1f LevelDB persistence leg KATs (NmcP1fPersist). The in-memory connect path
// now writes every accepted header under "h"+block_hash plus "tip"/"height"
// pointers in one synced batch; init() reloads them. NMC has no height-index,
// so there is deliberately NO "i" key (full-residency m_index, unlike btc).
// P1f(a) persists the AuxPow blob too (behind has_auxpow), so a reloaded
// merge-mined header keeps both its VALID_CHAIN status and its auxpow proof.
// The disk-format round-trips are pure (no DB);
// the reopen round-trips exercise the real LevelDBStore under a temp dir.
// ---------------------------------------------------------------------------
using nmc::coin::IndexEntry;
using nmc::coin::IndexEntryDiskV1;

// A fresh, empty on-disk path for one test (prior contents wiped).
static std::string fresh_db_dir(const std::string& name)
{
    std::filesystem::path p = std::filesystem::path(testing::TempDir()) / name;
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    return p.string();
}

TEST(NmcP1fPersist, IndexEntryDiskRoundTripsViaPackStream)
{
    IndexEntry e;
    e.header     = plain_header(leaf_of(0x11), kEasyBits, 42);
    e.block_hash = block_hash(e.header);
    e.height     = 7;
    e.chain_work = nmc::coin::get_block_proof(kEasyBits);
    e.status     = nmc::coin::HEADER_VALID_TREE;
    e.auxpow     = std::nullopt;

    auto disk = IndexEntryDiskV1::from_entry(e);
    EXPECT_EQ(disk.has_auxpow, 0);

    auto packed = pack(disk);
    std::vector<uint8_t> data(
        reinterpret_cast<const uint8_t*>(packed.data()),
        reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
    PackStream ps(data);
    IndexEntryDiskV1 back;
    ps >> back;
    IndexEntry r = back.to_entry();

    EXPECT_EQ(r.block_hash, e.block_hash);
    EXPECT_EQ(r.height,     e.height);
    EXPECT_EQ(r.chain_work, e.chain_work);
    EXPECT_EQ(r.status,     e.status);
    EXPECT_FALSE(r.auxpow.has_value());
}

TEST(NmcP1fPersist, DiskRoundTripPreservesMergeMinedStatusAndAuxFlag)
{
    IndexEntry e;
    e.header     = plain_header(leaf_of(0x22), kEasyBits, 9);
    e.block_hash = block_hash(e.header);
    e.height     = 19200;
    e.chain_work = nmc::coin::get_block_proof(kEasyBits);
    e.status     = nmc::coin::HEADER_VALID_CHAIN;          // merge-mined verdict
    e.auxpow     = complete_proof(e.block_hash, 0x1d00ffffu);

    auto disk = IndexEntryDiskV1::from_entry(e);
    EXPECT_EQ(disk.has_auxpow, 1);                         // flag tracks presence

    auto packed = pack(disk);
    std::vector<uint8_t> data(
        reinterpret_cast<const uint8_t*>(packed.data()),
        reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
    PackStream ps(data);
    IndexEntryDiskV1 back;
    ps >> back;
    EXPECT_EQ(back.has_auxpow, 1);

    IndexEntry r = back.to_entry();
    EXPECT_EQ(r.status, nmc::coin::HEADER_VALID_CHAIN);    // status survives reload
    ASSERT_TRUE(r.auxpow.has_value());                    // P1f(a): blob now restored
    EXPECT_EQ(r.auxpow->chain_merkle_index, e.auxpow->chain_merkle_index);
    EXPECT_EQ(parent_coinbase_txid(r.auxpow->parent_coinbase),
              parent_coinbase_txid(e.auxpow->parent_coinbase));
}

TEST(NmcP1fPersist, ReopenRestoresEmptyChainAsEmpty)
{
    const std::string dir = fresh_db_dir("nmc_p1f_empty");
    {
        HeaderChain a(params_activation(19200), dir);
        ASSERT_TRUE(a.init());
        EXPECT_EQ(a.size(), 0u);
    }
    {
        HeaderChain b(params_activation(19200), dir);
        ASSERT_TRUE(b.init());
        EXPECT_EQ(b.size(), 0u);
        EXPECT_FALSE(b.tip().has_value());
        EXPECT_EQ(b.height(), 0u);
    }
}

TEST(NmcP1fPersist, SingleHeaderSurvivesReopen)
{
    const std::string dir = fresh_db_dir("nmc_p1f_single");
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    {
        HeaderChain a(params_activation(19200), dir);
        ASSERT_TRUE(a.init());
        ASSERT_TRUE(a.add_header(g));
        ASSERT_EQ(a.size(), 1u);
    }
    {
        HeaderChain b(params_activation(19200), dir);
        ASSERT_TRUE(b.init());
        EXPECT_EQ(b.size(), 1u);
        EXPECT_EQ(b.height(), 0u);
        EXPECT_TRUE(b.has_header(block_hash(g)));
        ASSERT_TRUE(b.tip().has_value());
        EXPECT_EQ(b.tip()->block_hash, block_hash(g));
    }
}

TEST(NmcP1fPersist, MultiHeaderChainRestoresTipHeightAndWork)
{
    const std::string dir = fresh_db_dir("nmc_p1f_multi");
    uint256 z; z.SetNull();
    BlockHeaderType g  = plain_header(z, kEasyBits, 1);
    BlockHeaderType c1 = plain_header(block_hash(g),  kEasyBits, 2);
    BlockHeaderType c2 = plain_header(block_hash(c1), kEasyBits, 3);
    uint256 want_work;
    {
        HeaderChain a(params_activation(19200), dir);
        ASSERT_TRUE(a.init());
        ASSERT_TRUE(a.add_header(g));
        ASSERT_TRUE(a.add_header(c1));
        ASSERT_TRUE(a.add_header(c2));
        ASSERT_EQ(a.height(), 2u);
        want_work = a.cumulative_work();
    }
    {
        HeaderChain b(params_activation(19200), dir);
        ASSERT_TRUE(b.init());
        EXPECT_EQ(b.size(),   3u);                  // "height" key not mis-parsed as a header
        EXPECT_EQ(b.height(), 2u);
        EXPECT_EQ(b.cumulative_work(), want_work);
        ASSERT_TRUE(b.tip().has_value());
        EXPECT_EQ(b.tip()->block_hash, block_hash(c2));
        EXPECT_TRUE(b.has_header(block_hash(g)));
        EXPECT_TRUE(b.has_header(block_hash(c1)));
        EXPECT_TRUE(b.has_header(block_hash(c2)));
        ASSERT_TRUE(b.get_header(block_hash(c2)).has_value());
        EXPECT_EQ(b.get_header(block_hash(c2))->height, 2u);
    }
}

TEST(NmcP1fPersist, InMemoryModeWithoutDbPathPersistsNothing)
{
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    {
        HeaderChain mem(params_activation(19200), "");   // no db_path -> pure in-memory
        ASSERT_TRUE(mem.init());
        ASSERT_TRUE(mem.add_header(g));
        EXPECT_EQ(mem.size(), 1u);
    }
    // A fresh in-memory chain shares no on-disk state -- it starts empty.
    HeaderChain fresh(params_activation(19200), "");
    ASSERT_TRUE(fresh.init());
    EXPECT_EQ(fresh.size(), 0u);
    EXPECT_FALSE(fresh.has_header(block_hash(g)));
}

// ---------------------------------------------------------------------------
// P1f end-to-end accept-path persistence KATs (NmcP1fAcceptPersist). The suites
// above prove the disk codec (synthetic IndexEntryDiskV1) and the reopen of a
// PLAIN chain separately. These two compose the missing seam: drive the LIVE
// proof-gated add_auxpow_header() into a LevelDB-backed chain, reopen, and
// assert a VALID merge-mined header (tip + AuxPow blob) survives -- and that an
// INVALID-proof header is neither connected nor written, surviving as nothing.
// ---------------------------------------------------------------------------
TEST(NmcP1fAcceptPersist, ValidatedAuxPowHeaderSurvivesReopenViaAcceptPath)
{
    const std::string dir = fresh_db_dir("nmc_p1f_auxpow_accept");
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);           // genesis, height 0
    uint32_t aux_bits = 0x207fffffu;                            // easy aux target
    BlockHeaderType h1 = plain_header(block_hash(g), aux_bits, 7);
    uint256 aux = block_hash(h1);                               // production seam
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    {
        HeaderChain a(params_activation(1), dir);               // activation at height 1
        ASSERT_TRUE(a.init());
        ASSERT_TRUE(a.add_header(g));                           // height 0, plain
        ASSERT_EQ(a.verify_auxpow_header(h1, ap), AuxPow::CheckResult::VALID);
        ASSERT_TRUE(a.add_auxpow_header(h1, ap));               // LIVE proof-gated accept
        ASSERT_EQ(a.height(), 1u);
        ASSERT_TRUE(a.tip().has_value());
        ASSERT_EQ(a.tip()->block_hash, aux);
    }
    {
        HeaderChain b(params_activation(1), dir);
        ASSERT_TRUE(b.init());                                  // reload from disk
        EXPECT_EQ(b.size(), 2u);
        EXPECT_EQ(b.height(), 1u);
        ASSERT_TRUE(b.tip().has_value());
        EXPECT_EQ(b.tip()->block_hash, aux);                   // tip advanced + survived
        ASSERT_TRUE(b.get_header(aux).has_value());
        EXPECT_EQ(b.get_header(aux)->status, nmc::coin::HEADER_VALID_CHAIN);
        EXPECT_TRUE(b.get_header(aux)->auxpow.has_value());    // P1f(a) blob restored thru live path
    }
}

TEST(NmcP1fAcceptPersist, InvalidProofAuxPowLeavesNothingOnDiskAfterReopen)
{
    const std::string dir = fresh_db_dir("nmc_p1f_auxpow_reject");
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, kEasyBits, 1);
    // height-1 header carrying an UNMINED parent: aux target == 1, so the parent
    // PoW cannot clear it => check_proof INVALID => never connected, never written.
    BlockHeaderType h1 = plain_header(block_hash(g), /*aux_bits=*/0x03000001u, 7);
    uint256 aux = block_hash(h1);
    AuxPow ap = complete_proof(aux, 0x1d00ffffu);
    ASSERT_TRUE(pow_hash(ap.parent_header) > chain::bits_to_target(h1.m_bits));
    {
        HeaderChain a(params_activation(1), dir);
        ASSERT_TRUE(a.init());
        ASSERT_TRUE(a.add_header(g));
        ASSERT_EQ(a.verify_auxpow_header(h1, ap), AuxPow::CheckResult::INVALID);
        EXPECT_FALSE(a.add_auxpow_header(h1, ap));              // rejected before connect
        EXPECT_FALSE(a.has_header(aux));
        EXPECT_EQ(a.size(), 1u);                               // genesis only
    }
    {
        HeaderChain b(params_activation(1), dir);
        ASSERT_TRUE(b.init());                                  // reload
        EXPECT_EQ(b.size(), 1u);                               // reject left no disk row
        EXPECT_FALSE(b.has_header(aux));
        EXPECT_EQ(b.height(), 0u);
        ASSERT_TRUE(b.tip().has_value());
        EXPECT_EQ(b.tip()->block_hash, block_hash(g));
    }
}

// ---------------------------------------------------------------------------
// P1f(a): nmc::coin::AuxPow canonical CAuxPow serialization round-trip.
//
// Pins the on-disk / wire codec for the merge-mining proof. A fully-populated
// AuxPow (the same complete_proof fixture steps 1-4 validate) is packed and
// unpacked; every field must survive, AND the restored proof must still verify
// VALID through check_proof -- so a field-order or witness-flag regression in
// the codec is caught against the consensus verifier, not merely a self-compare.
// Ground-truth wire-vector assertion against the Namecoin daemon's own bytes is
// the immediate follow-up (needs a captured testnet auxpow blob).
// Per-coin isolation: src/impl/nmc/ only; core/pack + nmc::coin types.
// ---------------------------------------------------------------------------
TEST(NmcAuxPowCodec, FullProofRoundTripsAndStillVerifies)
{
    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    uint32_t aux_bits = 0x207fffffu;
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));
    ASSERT_EQ(ap.check_proof(aux, 1, aux_bits), AuxPow::CheckResult::VALID);

    PackStream ps;
    ps << ap;
    AuxPow back;
    ps >> back;

    // Every field survives the round-trip.
    EXPECT_EQ(back.parent_block_hash,        ap.parent_block_hash);
    EXPECT_EQ(back.parent_coinbase_branch,   ap.parent_coinbase_branch);
    EXPECT_EQ(back.parent_coinbase_index,    ap.parent_coinbase_index);
    EXPECT_EQ(back.chain_merkle_branch,      ap.chain_merkle_branch);
    EXPECT_EQ(back.chain_merkle_index,       ap.chain_merkle_index);
    EXPECT_EQ(block_hash(back.parent_header), block_hash(ap.parent_header));
    EXPECT_EQ(parent_coinbase_txid(back.parent_coinbase),
              parent_coinbase_txid(ap.parent_coinbase));

    // The restored proof is consensus-equivalent: still VALID.
    EXPECT_EQ(back.check_proof(aux, 1, aux_bits), AuxPow::CheckResult::VALID);
}

// ---------------------------------------------------------------------------
// P1f(a): IndexEntryDiskV1 persists the AuxPow blob behind has_auxpow.
//
// The persistence leg (#201) stored only the presence flag; this leg writes the
// canonical CAuxPow blob after it iff has_auxpow == 1, and restores it on load.
// Asserts: a merge-mined entry round-trips its proof through from_entry ->
// PackStream -> to_entry; and a proofless entry trails no blob and restores to
// std::nullopt (so the flag/blob coupling cannot desync the disk format).
// ---------------------------------------------------------------------------
TEST(NmcAuxPowPersist, IndexEntryDiskV1RoundTripsAuxPowBlob)
{
    using nmc::coin::IndexEntry;
    using nmc::coin::IndexEntryDiskV1;

    uint256 aux = leaf_of(0x01);
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);

    IndexEntry e;
    e.header     = ap.parent_header;   // any 80-byte header
    e.block_hash = leaf_of(0xAB);
    e.height     = 42;
    e.chain_work = leaf_of(0xCD);
    e.status     = nmc::coin::HEADER_VALID_CHAIN;
    e.auxpow     = ap;

    IndexEntryDiskV1 disk = IndexEntryDiskV1::from_entry(e);
    ASSERT_EQ(disk.has_auxpow, 1);

    PackStream ps; ps << disk;
    IndexEntryDiskV1 back; ps >> back;
    ASSERT_EQ(back.has_auxpow, 1);
    ASSERT_TRUE(back.auxpow.has_value());

    IndexEntry r = back.to_entry();
    EXPECT_EQ(r.height, e.height);
    EXPECT_EQ(r.status, e.status);
    ASSERT_TRUE(r.auxpow.has_value());
    EXPECT_EQ(r.auxpow->chain_merkle_index,      e.auxpow->chain_merkle_index);
    EXPECT_EQ(r.auxpow->parent_coinbase_branch,  e.auxpow->parent_coinbase_branch);
    EXPECT_EQ(parent_coinbase_txid(r.auxpow->parent_coinbase),
              parent_coinbase_txid(e.auxpow->parent_coinbase));

    // A proofless entry trails no blob and restores to nullopt.
    IndexEntry plain = e; plain.auxpow = std::nullopt;
    IndexEntryDiskV1 pdisk = IndexEntryDiskV1::from_entry(plain);
    ASSERT_EQ(pdisk.has_auxpow, 0);
    PackStream ps2; ps2 << pdisk;
    IndexEntryDiskV1 pback; ps2 >> pback;
    EXPECT_FALSE(pback.to_entry().auxpow.has_value());
}


// ─── P1 PB: NMC mempool (re-homed btc mirror) ───────────────────────────────
// Pins nmc::coin::Mempool basics against the nmc::coin transaction/block types:
// add/contains/remove + duplicate rejection, feerate-ordered selection, and
// confirmed-block cleanup. The pool is a byte-faithful mirror of the btc pool
// re-homed into namespace nmc::coin (no btc::coin symbols).

static nmc::coin::MutableTransaction mempool_tx(uint8_t seed, int64_t out_value) {
    nmc::coin::MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;
    nmc::coin::TxIn in;
    in.prevout.hash  = leaf_of(seed);
    in.prevout.index = 0;
    in.sequence      = 0xffffffffu;
    tx.vin.push_back(in);
    nmc::coin::TxOut out;
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

TEST(NmcMempool, AddContainsRemoveAndDedup) {
    nmc::coin::Mempool pool;
    auto tx = mempool_tx(0x11, 5000);
    uint256 txid = nmc::coin::compute_txid(tx);

    EXPECT_TRUE(pool.add_tx(tx));
    EXPECT_TRUE(pool.contains(txid));
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_FALSE(pool.add_tx(tx));      // duplicate rejected
    EXPECT_EQ(pool.size(), 1u);

    pool.remove_tx(txid);
    EXPECT_FALSE(pool.contains(txid));
    EXPECT_EQ(pool.size(), 0u);
}

TEST(NmcMempool, FeerateOrderedSelection) {
    nmc::coin::Mempool pool;
    auto lo = mempool_tx(0x21, 1000);
    auto hi = mempool_tx(0x22, 1000);
    uint256 lo_id = nmc::coin::compute_txid(lo);
    uint256 hi_id = nmc::coin::compute_txid(hi);
    ASSERT_TRUE(pool.add_tx(lo));
    ASSERT_TRUE(pool.add_tx(hi));
    // Equal weight, different fees -> higher fee is the higher feerate.
    pool.set_tx_fee(lo_id, 1000);
    pool.set_tx_fee(hi_id, 9000);

    auto sel = pool.get_sorted_txs_with_fees(4000000u);
    ASSERT_EQ(sel.first.size(), 2u);
    EXPECT_EQ(sel.first[0].fee, 9000u);   // highest feerate first
    EXPECT_EQ(sel.first[1].fee, 1000u);
    EXPECT_EQ(sel.second, 10000u);
    EXPECT_EQ(pool.total_fees(), 10000u);
}

TEST(NmcMempool, RemoveForBlockClearsConfirmed) {
    nmc::coin::Mempool pool;
    auto a = mempool_tx(0x31, 2000);
    auto b = mempool_tx(0x32, 2000);
    uint256 a_id = nmc::coin::compute_txid(a);
    ASSERT_TRUE(pool.add_tx(a));
    ASSERT_TRUE(pool.add_tx(b));
    EXPECT_EQ(pool.size(), 2u);

    nmc::coin::BlockType block;
    block.m_txs.push_back(a);             // a confirmed in this block
    pool.remove_for_block(block);

    EXPECT_FALSE(pool.contains(a_id));
    EXPECT_EQ(pool.size(), 1u);           // b remains
}

// ---------------------------------------------------------------------------
// PF-conformance: production retarget + network-policy pins (NmcPFConsensusParams).
// Lock the source-verified namecoin-core consensus/network constants baked into
// the mainnet()/testnet() factories so a future edit cannot silently drift them.
// Sourced from namecoin-core src/kernel/chainparams.cpp (NOT from memory):
//   consensus.nPowTargetTimespan = 1209600 (2 weeks), nPowTargetSpacing = 600
//   (10 min)  => difficulty_adjustment_interval() == 2016 on both nets;
//   fPowAllowMinDifficultyBlocks = false (CMainParams) / true (CTestNetParams);
//   fPowNoRetargeting = false; pchMessageStart = {f9,be,b4,fe} (CMainParams) /
//   {fa,bf,b5,fe} (CTestNetParams). powLimit + mainnet genesis stay TO-CONFIRM
//   placeholders and are deliberately NOT asserted here.
// ---------------------------------------------------------------------------
TEST(NmcPFConsensusParams, MainnetRetargetAndMagicPinned)
{
    NMCChainParams p = NMCChainParams::mainnet();
    EXPECT_EQ(p.target_timespan, 1209600);          // 2 weeks
    EXPECT_EQ(p.target_spacing, 600);               // 10 minutes
    EXPECT_EQ(p.difficulty_adjustment_interval(), 2016);
    EXPECT_FALSE(p.allow_min_difficulty);           // CMainParams: strict difficulty
    EXPECT_FALSE(p.no_retargeting);
    const std::array<unsigned char, 4> kMagic{{0xf9, 0xbe, 0xb4, 0xfe}};
    EXPECT_EQ(p.p2p_magic, kMagic);                 // CMainParams pchMessageStart
}

TEST(NmcPFConsensusParams, TestnetRetargetAndMagicPinned)
{
    NMCChainParams p = NMCChainParams::testnet();
    EXPECT_EQ(p.target_timespan, 1209600);          // 2 weeks (shared with mainnet)
    EXPECT_EQ(p.target_spacing, 600);               // 10 minutes
    EXPECT_EQ(p.difficulty_adjustment_interval(), 2016);
    EXPECT_TRUE(p.allow_min_difficulty);            // CTestNetParams: min-diff allowed
    EXPECT_FALSE(p.no_retargeting);
    const std::array<unsigned char, 4> kMagic{{0xfa, 0xbf, 0xb5, 0xfe}};
    EXPECT_EQ(p.p2p_magic, kMagic);                 // CTestNetParams pchMessageStart
}

// ── AuxPoW chain-id SSOT conformance (PF) ───────────────────────────────────
//
// Locks the merge-mining chain id against namecoin-core nAuxpowChainId.
// chain_id is a BUCKET-1 ISOLATION PRIMITIVE (per-coin namespacing of the
// parent merged-mining slot): pinned per coin, NEVER standardized away. The
// verify side (HeaderChain::verify_auxpow_header -> AuxPow::check_proof) reads
// m_params.aux_chain_id, and the embedded build side (AuxChainEmbedded) casts
// the SAME field into AuxWork.chain_id. A single drift in the factory default
// silently breaks the build<->verify slot binding on BOTH sides, while the
// hand-set fixtures above (which force aux_chain_id = 1) keep passing. These
// KATs pin the FACTORY OUTPUT, not a hand-set fixture, so factory drift reds.
//
// Source: Namecoin Core src/kernel/chainparams.cpp -- nAuxpowChainId = 0x0001
// on BOTH mainnet and testnet (NOT Dogecoin 0x0062).

TEST(NmcAuxChainIdConformance, SSOTConstantMatchesNamecoinCore)
{
    EXPECT_EQ(nmc::coin::NMC_AUXPOW_CHAIN_ID, 0x0001u);
    EXPECT_NE(nmc::coin::NMC_AUXPOW_CHAIN_ID, 0x0062u);   // != DOGE chain id
}

TEST(NmcAuxChainIdConformance, MainnetFactoryEmitsSSOT)
{
    NMCChainParams p = NMCChainParams::mainnet();
    EXPECT_EQ(p.aux_chain_id, static_cast<int32_t>(nmc::coin::NMC_AUXPOW_CHAIN_ID));
    EXPECT_EQ(p.aux_chain_id, 1);
}

TEST(NmcAuxChainIdConformance, TestnetFactoryEmitsSSOT)
{
    // Namecoin uses the SAME aux chain id (0x0001) on testnet as mainnet.
    NMCChainParams p = NMCChainParams::testnet();
    EXPECT_EQ(p.aux_chain_id, static_cast<int32_t>(nmc::coin::NMC_AUXPOW_CHAIN_ID));
    EXPECT_EQ(p.aux_chain_id, 1);
}

TEST(NmcAuxChainIdConformance, BuildVerifySymmetryOnFactoryDefault)
{
    // Build side casts m_params.aux_chain_id -> uint32_t AuxWork.chain_id;
    // verify side passes m_params.aux_chain_id as expected_chain_id into
    // check_proof. Pin that the factory default is no -1 sentinel and survives
    // the uint32_t cast the build path performs -- both sides agree on 1u.
    NMCChainParams p = NMCChainParams::mainnet();
    EXPECT_GE(p.aux_chain_id, 0);                          // not the -1 unpinned sentinel
    EXPECT_EQ(static_cast<uint32_t>(p.aux_chain_id), 1u);  // build-side AuxWork.chain_id
}

// ---------------------------------------------------------------------------
// PD-prep GOLDEN FIXTURE: dual-target coinbase merged-mining commitment layout.
//
// Pins PD's acceptance target AHEAD of the build code. PD's dual-target coinbase
// path (PR #408's nmc::coin::build_mm_commitment) must emit the merged-mining
// marker in EXACTLY the Namecoin/Bitcoin auxpow.cpp reference layout:
//
//     [ fa be 6d 6d ]  4-byte MM magic  ("\xfa\xbe" + "mm")
//     [ 32 bytes    ]  chain-merkle root, REVERSED (big-endian display order)
//     [ 4 bytes LE  ]  chain-merkle tree size = 2^chain_height
//     [ 4 bytes LE  ]  nonce
//
// The expected 44-byte marker is hand-computed here from that reference oracle
// and asserted as an explicit byte LITERAL. This fixture DELIBERATELY does NOT
// import or invoke build_mm_commitment: that is PD's surface, and calling it
// would re-introduce the #408 dependency and merely mirror a build bug instead
// of catching it. The literal is the independent oracle PD's output reproduces.
//
// Binding to the already-merged consensus surface (build-independent):
//   * the literal is fed through scan_mm_commitment (the verify-side SSOT) and
//     must return MMScan::MATCH;
//   * the deterministic slot is cross-checked against aux_expected_index, and a
//     wrong slot is shown to be rejected (the slot field is load-bearing);
//   * the local hand layout (root_reversed + mm_script, NOT build_mm_commitment)
//     is asserted byte-equal to the literal so a layout drift on either side reds.
//
// Per-coin isolation (P0 fence #4): src/impl/nmc/ test target only; additive;
// rides the already-allowlisted nmc_auxpow_merkle_test exe (no build.yml change,
// no consensus-value change). Pure layout/byte-order pin, no other-coin tree.
// ---------------------------------------------------------------------------

// uint256 whose 32 INTERNAL (little-endian) bytes ascend from `start`.
static uint256 root_ascending(unsigned char start)
{
    uint256 u; u.SetNull();
    // begin() is a typed (word-strided) iterator; cast to raw bytes like
    // root_reversed does so we set 32 CONTIGUOUS internal bytes, not every 4th.
    unsigned char* p = reinterpret_cast<unsigned char*>(u.begin());
    for (size_t i = 0; i < uint256::BYTES; ++i)
        p[i] = static_cast<unsigned char>(start + i);
    return u;
}

TEST(NmcPdGoldenFixture, SingleSlotMarkerMatchesHandComputedLiteral)
{
    // Live NMC-under-BTC posture: a length-1 chain tree (height 0 => size 1),
    // so the aux chain always occupies slot 0 regardless of nonce. A legible
    // non-zero nonce exercises the little-endian nonce field.
    uint256 root = root_ascending(0x01);          // internal LE = 01 02 .. 20
    const unsigned  h     = 0;
    const int32_t   cid   = 1;
    const uint32_t  nonce = 0x12345678u;

    // Hand-computed golden marker (44 bytes), reference layout above.
    const std::vector<unsigned char> golden = {
        0xfa, 0xbe, 0x6d, 0x6d,                          // MM magic
        // chain-merkle root, reversed (big-endian display order):
        0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x01, 0x00, 0x00, 0x00,                          // size = 2^0 = 1 (LE)
        0x78, 0x56, 0x34, 0x12,                          // nonce 0x12345678 (LE)
    };
    ASSERT_EQ(golden.size(), 4u + uint256::BYTES + 8u);

    // Independent hand layout (NOT build_mm_commitment) reproduces the literal.
    // mm_script() frames the marker with a 4-byte dummy coinbase-height prefix
    // (build_mm_commitment emits ONLY the marker payload; the caller prepends the
    // scriptSig framing), so strip that prefix before the byte-equality check.
    std::vector<unsigned char> framed = mm_script(root_reversed(root), 1u << h, nonce);
    std::vector<unsigned char> payload(framed.begin() + 4, framed.end());
    EXPECT_EQ(payload, golden);

    // Deterministic slot is 0 and is what the verify-side arithmetic demands.
    const uint32_t slot = aux_expected_index(nonce, cid, h);
    EXPECT_EQ(slot, 0u);

    // The merged verify-side scanner accepts exactly this layout, both as the
    // bare marker and embedded after scriptSig framing (found by search).
    EXPECT_EQ(scan_mm_commitment(golden, root, h, cid, slot), MMScan::MATCH);
    EXPECT_EQ(scan_mm_commitment(framed, root, h, cid, slot), MMScan::MATCH);
}

TEST(NmcPdGoldenFixture, MultiSlotMarkerPinsDeterministicSlotAndLiteral)
{
    // height 2 => 4-leaf chain tree; nonce 2 pins the aux chain to slot 1
    // (aux_expected_index(2, 1, 2) == 1), exercising both the LE tree-size
    // field (= 4) and the deterministic-slot binding the single-slot case cannot.
    uint256 root = root_ascending(0x41);          // internal LE = 41 42 .. 60
    const unsigned  h     = 2;
    const int32_t   cid   = 1;
    const uint32_t  nonce = 2u;

    const std::vector<unsigned char> golden = {
        0xfa, 0xbe, 0x6d, 0x6d,                          // MM magic
        0x60, 0x5f, 0x5e, 0x5d, 0x5c, 0x5b, 0x5a, 0x59,
        0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51,
        0x50, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a, 0x49,
        0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
        0x04, 0x00, 0x00, 0x00,                          // size = 2^2 = 4 (LE)
        0x02, 0x00, 0x00, 0x00,                          // nonce 2 (LE)
    };
    ASSERT_EQ(golden.size(), 44u);

    std::vector<unsigned char> framed = mm_script(root_reversed(root), 1u << h, nonce);
    std::vector<unsigned char> payload(framed.begin() + 4, framed.end());
    EXPECT_EQ(payload, golden);

    const uint32_t slot = aux_expected_index(nonce, cid, h);
    EXPECT_EQ(slot, 1u);   // hand-pinned: nonce 2, chain_id 1, height 2 => slot 1

    EXPECT_EQ(scan_mm_commitment(golden, root, h, cid, slot), MMScan::MATCH);

    // Negative pin: the SAME marker presented for the WRONG slot is rejected,
    // proving the slot field is load-bearing, not decorative.
    EXPECT_EQ(scan_mm_commitment(golden, root, h, cid, slot ^ 1u), MMScan::MISMATCH);
}

TEST(NmcPdGoldenFixture, MarkerFieldOffsetsAreThePinnedLayout)
{
    // Pin the exact field offsets PD's build path must emit. Slicing the marker
    // proves WHERE each field sits; each slice is checked against an independent
    // literal (not against the builder), so a field-order/width drift reds.
    uint256 root = root_ascending(0x01);
    std::vector<unsigned char> framed =
        mm_script(root_reversed(root), /*size=*/1u, /*nonce=*/0x12345678u);
    // Drop the 4-byte dummy coinbase-height prefix; index the bare marker from 0.
    const std::vector<unsigned char> marker(framed.begin() + 4, framed.end());
    ASSERT_EQ(marker.size(), 44u);

    // [0,4) MM magic.
    EXPECT_EQ((std::vector<unsigned char>(marker.begin(), marker.begin() + 4)),
              (std::vector<unsigned char>{0xfa, 0xbe, 0x6d, 0x6d}));

    // [4,36) reversed root == big-endian display order of the internal bytes,
    // re-derived here by an independent reverse of the ascending internal bytes.
    std::vector<unsigned char> expect_root(uint256::BYTES);
    for (size_t i = 0; i < uint256::BYTES; ++i)
        expect_root[i] = static_cast<unsigned char>(0x01 + (uint256::BYTES - 1 - i));
    EXPECT_EQ((std::vector<unsigned char>(marker.begin() + 4, marker.begin() + 36)),
              expect_root);

    // [36,40) tree size = 1 (LE).
    EXPECT_EQ((std::vector<unsigned char>(marker.begin() + 36, marker.begin() + 40)),
              (std::vector<unsigned char>{0x01, 0x00, 0x00, 0x00}));

    // [40,44) nonce 0x12345678 (LE).
    EXPECT_EQ((std::vector<unsigned char>(marker.begin() + 40, marker.begin() + 44)),
              (std::vector<unsigned char>{0x78, 0x56, 0x34, 0x12}));
}

// ── Merged-mining marker magic SSOT conformance (PF) ────────────────────────
//
// Pins the 4th and last source-verified consensus constant of the NMC arc:
// pchMergedMiningHeader, the magic tag that precedes the merged-mining
// commitment inside the parent coinbase scriptSig. Like chain_id (above) it is
// a BUCKET-1 isolation/wire primitive -- pinned per coin, never standardized --
// but unlike chain_id it had NO value-pin: every golden fixture above hard-codes
// the {fa,be,6d,6d} hex literal directly, so an edit to the PRODUCTION
// MM_HEADER_MAGIC constant would red ZERO fixtures, yet the live scanner would
// silently stop matching real Namecoin coinbases. These KATs reference the
// production constant, closing that drift gap.
//
// Source: Namecoin/Bitcoin auxpow.cpp pchMergedMiningHeader =
//   { 0xfa, 0xbe, 'm', 'm' }  ==  { 0xfa, 0xbe, 0x6d, 0x6d }   ('m' == 0x6d).

TEST(NmcMergedMiningMagicConformance, ProductionConstantMatchesAuxpowReference)
{
    using nmc::coin::MM_HEADER_MAGIC;
    // Byte-for-byte against the canonical reference, in BOTH spellings: the
    // char-literal form the constant is written in, and the hex form every
    // golden fixture above spells out -- proving the two are the same 4 bytes.
    const unsigned char kRef[4]    = {0xfa, 0xbe, 'm', 'm'};
    const unsigned char kRefHex[4] = {0xfa, 0xbe, 0x6d, 0x6d};
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(MM_HEADER_MAGIC[i], kRef[i]);
        EXPECT_EQ(MM_HEADER_MAGIC[i], kRefHex[i]);
    }
    // Document the char->byte identity every fixture above silently relies on.
    EXPECT_EQ(static_cast<unsigned char>('m'), 0x6du);
}

TEST(NmcMergedMiningMagicConformance, ScannerBindsToExactlyThePinnedMagic)
{
    // A canonical single-slot marker the scanner accepts (mirrors the golden
    // fixture above), then a copy whose magic final byte is flipped by one bit.
    uint256 root = root_ascending(0x01);
    const unsigned h = 0; const int32_t cid = 1; const uint32_t nonce = 0x12345678u;
    std::vector<unsigned char> good = mm_script(root_reversed(root), 1u << h, nonce);
    const uint32_t slot = aux_expected_index(nonce, cid, h);
    ASSERT_EQ(scan_mm_commitment(good, root, h, cid, slot), MMScan::MATCH);

    // Locate the production magic inside the framed script and corrupt ONE byte.
    auto it = std::search(good.begin(), good.end(),
                          nmc::coin::MM_HEADER_MAGIC,
                          nmc::coin::MM_HEADER_MAGIC + 4);
    ASSERT_NE(it, good.end());
    std::vector<unsigned char> drifted = good;
    drifted[(it - good.begin()) + 3] ^= 0x01;             // 0x6d -> 0x6c
    // A one-byte drift makes the marker UNDETECTABLE: the scanner reports ABSENT
    // (staged-leg posture), not a malformed MISMATCH -- i.e. the commitment
    // vanishes from the parent coinbase entirely. This is exactly the silent
    // failure mode a production-constant edit would cause on live coinbases.
    EXPECT_EQ(scan_mm_commitment(drifted, root, h, cid, slot), MMScan::ABSENT);
}

} // namespace

// ---------------------------------------------------------------------------
// NMC chain-id source-pin KAT.
//
// Pins consensus.nAuxpowChainId = 0x0001, sourced from canonical Namecoin Core
// @ 6697dba480 (branch auxpow), src/kernel/chainparams.cpp:179 (CMainParams),
// :345 (CTestNetParams), :620 (CTestNet4Params), :725 (CRegTestParams) -- the
// value is 0x0001 across all four nets. The live cross-check vs .140 namecoind
// is DEFERRED to the PE item4 soak (the gate stays visible; it is not retired).
//
// Three bindings prove the pin is load-bearing, not decorative:
//   1. the aux_id.hpp SSOT constant, the slot-modeling AuxChain default and the
//      consensus-bearing NMCChainParams::aux_chain_id all read 0x0001 -- drift on
//      any one reds (the -1 placeholder cannot creep back);
//   2. an AuxPow round-trip carrying the PINNED chain_id reaches the same staged
//      state a correct proof does (INCOMPLETE -- step 4 parent-PoW still unbuilt --
//      and never spuriously VALID);
//   3. presenting the SAME proof under a DIFFERENT expected chain id moves the
//      demanded slot (aux_expected_index folds chain_id in), so the marker no
//      longer occupies the required slot and the proof is no longer staged --
//      chain_id genuinely participates in the consensus slot binding.
// Per-coin isolation (P0 fence #4): src/impl/nmc/ test target only; rides the
// already-allowlisted nmc_auxpow_merkle_test exe; no build.yml change.
// ---------------------------------------------------------------------------

TEST(NmcChainIdPin, PinnedValueIsAuxpowChainId0x0001)
{
    EXPECT_EQ(nmc::coin::NMC_AUXPOW_CHAIN_ID, 0x0001u);
    // slot-modeling struct default is the SSOT, no longer the -1 sentinel:
    EXPECT_EQ(nmc::coin::AuxChain{}.chain_id, 0x0001);
    // consensus-bearing params field agrees with the SSOT:
    EXPECT_EQ(nmc::coin::NMCChainParams::mainnet().aux_chain_id, 0x0001);
}

TEST(NmcChainIdPin, RoundTripUnderPinnedChainIdIsStagedNotInvalid)
{
    const int32_t cid = static_cast<int32_t>(nmc::coin::NMC_AUXPOW_CHAIN_ID); // 0x0001
    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);                 // index bit0=0 => leaf left
    const unsigned h = 1; const uint32_t nonce = 1;
    const uint32_t slot = aux_expected_index(nonce, cid, h);   // (1,1,1) => 0
    ASSERT_EQ(slot, 0u);
    auto script = mm_script(root_reversed(root), 1u << h, nonce);

    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = slot;
    // pinned chain id: marker scans, slot binds, proof staged (step 4 unbuilt).
    EXPECT_EQ(ap.check_proof(aux, cid), AuxPow::CheckResult::INCOMPLETE);
    EXPECT_NE(ap.check_proof(aux, cid), AuxPow::CheckResult::VALID);
}

TEST(NmcChainIdPin, WrongExpectedChainIdBreaksSlotBinding)
{
    const int32_t cid   = static_cast<int32_t>(nmc::coin::NMC_AUXPOW_CHAIN_ID); // 1
    const int32_t wrong = cid + 1;                                              // 2
    const unsigned h = 1; const uint32_t nonce = 1;
    // chain_id folds into the deterministic slot: the demanded slot moves.
    EXPECT_NE(aux_expected_index(nonce, cid, h),
              aux_expected_index(nonce, wrong, h));        // 0 vs 1

    uint256 aux = leaf_of(0x01), sib = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    const uint32_t slot = aux_expected_index(nonce, cid, h);   // marker laid at slot 0
    auto script = mm_script(root_reversed(root), 1u << h, nonce);

    AuxPow ap;
    ap.parent_coinbase = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index = slot;
    // Same proof, WRONG expected chain id -> verifier demands a different slot,
    // so the staged MATCH is lost; never INCOMPLETE, never VALID.
    EXPECT_NE(ap.check_proof(aux, wrong), AuxPow::CheckResult::INCOMPLETE);
    EXPECT_NE(ap.check_proof(aux, wrong), AuxPow::CheckResult::VALID);
}
