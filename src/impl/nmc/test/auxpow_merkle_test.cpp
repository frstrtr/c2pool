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
#include <core/target_utils.hpp>

#include "../coin/header_chain.hpp"

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
// Storage stays P0-DEFER, so a verified header is not persisted yet (add
// returns false on both arms); the assertion is on the verify verdict.
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
    // Storage is still P0-DEFER, so even a verified header is not persisted yet.
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
// the deferred storage path. The production activation height stays the -1
// sentinel; these fixtures pin a TEST-only height (19200, the historically
// cited NMC mainnet value) purely to drive the gate - no consensus promotion.
// ---------------------------------------------------------------------------
static NMCChainParams params_activation(int32_t act_height)
{
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    p.auxpow_activation_height = act_height;   // TEST-only pin; production stays -1
    return p;
}

TEST(NmcP1eActivationGate, UnpinnedActivationRefusesToJudge)
{
    // mainnet() leaves auxpow_activation_height at -1: the gate must refuse
    // rather than guess, regardless of whether the header carries an AuxPow.
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
// Fork-choice stays height-proxy (work-based reorg is a still-later sub-leg).
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

} // namespace
