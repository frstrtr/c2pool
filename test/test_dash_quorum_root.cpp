// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-TEMPLATE step 4c — Dash merkleRootQuorums computation leaf unit tests
///
/// Exercises the vendored CalcCbTxMerkleRootQuorums mirror:
///
///   - src/impl/dash/coin/quorum_root.hpp
///
/// This is the quorum-root leaf that sits between the LLMQ
/// quorum-tail verification leaf (#321) and the embedded_gbt main: it
/// pins how the in-memory QuorumManager active set is reduced to the
/// CbTx `merkleRootQuorums` field that a built block template must carry
/// for a Dash node to accept the coinbase special-tx payload.
///
/// KATs pinned here (all self-contained, bit-exact against the library
/// SHA256d primitive):
///   - llmq_uses_rotation() flags exactly the mainnet rotated types
///     (5 = LLMQ_60_75, 6 = LLMQ_25_67) and nothing else.
///   - hash_commitment() == SHA256d(pack(CFinalCommitment)) for a fully
///     specified non-indexed commitment, frozen against a wire-byte
///     golden so a pack/serialize drift surfaces.
///   - merkle_pair_hash() / compute_merkle_root_local() match the
///     standard Bitcoin/Dash duplicate-last-on-odd SHA256d merkle:
///     empty -> ZERO, singleton -> itself, pair, odd-triple.
///   - compute_merkle_root_quorums() includes EVERY non-rotated active
///     entry, applies the rotated latest-per-quorumIndex dedup (older
///     same-index entries are dropped from the set), and the final root
///     is the lexicographically-sorted SHA256d merkle over that set.
///     Cross-checked against an independent reference that re-derives the
///     included set by hand and against frozen root goldens.
///
/// SCOPE NOTE (honest): the end-to-end "active set built from a live
/// Dash mnlistdiff reproduces the on-chain cbTx.merkleRootQuorums of a
/// real block" cross-check is explicitly NOT claimed here — that needs
/// the full mnlistdiff bootstrap and is deferred to Phase L, exactly as
/// the #321 quorum-tail leaf deferred BLS verification. The block
/// fixtures carry the on-chain merkleRootQuorums for that future check.

#include <gtest/gtest.h>

#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

using dash::coin::QuorumManager;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::llmq_uses_rotation;
using dash::coin::hash_commitment;
using dash::coin::merkle_pair_hash;
using dash::coin::compute_merkle_root_local;
using dash::coin::compute_merkle_root_quorums;

namespace {

// Hex of a uint256 in display order (reversed bytes), to keep frozen
// goldens human-comparable with dashcore/explorer output.
std::string to_hex_rev(const uint256& h)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 31; i >= 0; --i) {
        s.push_back(k[h.data()[i] >> 4]);
        s.push_back(k[h.data()[i] & 0xf]);
    }
    return s;
}

// Independent SHA256d over an arbitrary byte span (does not go through
// quorum_root.hpp) — the reference oracle for the merkle KATs.
uint256 sha256d(std::span<const unsigned char> in)
{
    uint256 out;
    CHash256()
        .Write(in)
        .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

uint256 hash256_concat(const uint256& a, const uint256& b)
{
    std::array<unsigned char, 64> buf{};
    std::memcpy(buf.data(), a.data(), 32);
    std::memcpy(buf.data() + 32, b.data(), 32);
    return sha256d(std::span<const unsigned char>(buf.data(), 64));
}

uint256 hash_of_byte(unsigned char b)
{
    return sha256d(std::span<const unsigned char>(&b, 1));
}

// Build a fully-specified non-indexed (v1) commitment with caller-chosen
// llmqType / quorumHash / quorumIndex so the active-set tests can
// distinguish entries by their serialized bytes.
CFinalCommitment make_commitment(uint8_t llmqType, unsigned char hash_seed,
                                 int16_t quorumIndex)
{
    CFinalCommitment c;
    c.nVersion = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType = llmqType;
    for (int i = 0; i < 32; ++i) c.quorumHash.data()[i] = hash_seed;
    c.quorumIndex = quorumIndex;       // carried in memory even for v1
    c.signers.assign(8, false);
    c.validMembers.assign(8, true);
    // quorumPublicKey / quorumSig / membersSig left zero-initialized.
    return c;
}

QuorumManager::Entry make_entry(uint8_t llmqType, unsigned char hash_seed,
                                int16_t quorumIndex, uint32_t mining_height)
{
    QuorumManager::Entry e;
    e.commitment = make_commitment(llmqType, hash_seed, quorumIndex);
    e.key = QuorumManager::ActiveKey{llmqType, e.commitment.quorumHash};
    e.mining_height = mining_height;
    return e;
}

// Reference re-implementation of the SET selected by
// compute_merkle_root_quorums: every non-rotated entry, plus the
// latest-mining-height entry per (rotated type, quorumIndex). Returns
// the lexicographically-sorted commitment hashes — the leaves that feed
// the merkle root. Deliberately independent of the per-type pre-sort in
// quorum_root.hpp (which the final lexicographic sort makes irrelevant
// to the root), so this pins the SET-selection consensus behavior.
std::vector<uint256> reference_leaves(const QuorumManager& q)
{
    std::vector<const QuorumManager::Entry*> selected;
    // non-rotated: all.
    for (const auto& e : q.active_entries()) {
        if (!llmq_uses_rotation(e.key.llmqType)) selected.push_back(&e);
    }
    // rotated: latest mining_height per (type, quorumIndex).
    std::vector<const QuorumManager::Entry*> rotated;
    for (const auto& e : q.active_entries()) {
        if (llmq_uses_rotation(e.key.llmqType)) rotated.push_back(&e);
    }
    for (auto* ep : rotated) {
        bool superseded = false;
        for (auto* other : rotated) {
            if (other == ep) continue;
            if (other->key.llmqType == ep->key.llmqType
                && other->commitment.quorumIndex == ep->commitment.quorumIndex
                && other->mining_height > ep->mining_height) {
                superseded = true;
                break;
            }
        }
        if (!superseded) selected.push_back(ep);
    }
    std::vector<uint256> leaves;
    for (auto* ep : selected) leaves.push_back(hash_commitment(ep->commitment));
    std::sort(leaves.begin(), leaves.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });
    return leaves;
}

} // namespace

// ---------------------------------------------------------------------
// llmq_uses_rotation
// ---------------------------------------------------------------------

TEST(DashQuorumRootKat, RotationFlagsMatchMainnet)
{
    EXPECT_FALSE(llmq_uses_rotation(CFinalCommitment::LLMQ_50_60));   // 1
    EXPECT_FALSE(llmq_uses_rotation(CFinalCommitment::LLMQ_400_60));  // 2
    EXPECT_FALSE(llmq_uses_rotation(CFinalCommitment::LLMQ_400_85));  // 3
    EXPECT_FALSE(llmq_uses_rotation(CFinalCommitment::LLMQ_100_67));  // 4
    EXPECT_TRUE(llmq_uses_rotation(CFinalCommitment::LLMQ_60_75));    // 5
    EXPECT_TRUE(llmq_uses_rotation(CFinalCommitment::LLMQ_25_67));    // 6
    EXPECT_FALSE(llmq_uses_rotation(CFinalCommitment::LLMQ_NONE));    // 0xff
    EXPECT_FALSE(llmq_uses_rotation(0));
    EXPECT_FALSE(llmq_uses_rotation(7));
}

// ---------------------------------------------------------------------
// hash_commitment — bit-exact vs an independent SHA256d(pack(c))
// ---------------------------------------------------------------------

TEST(DashQuorumRootKat, HashCommitmentMatchesSerializeHash)
{
    CFinalCommitment c = make_commitment(CFinalCommitment::LLMQ_50_60,
                                         /*hash_seed*/ 0xab, /*qi*/ 0);

    auto stream = ::pack(c);
    auto sp = stream.get_span();
    uint256 expected = sha256d(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()), sp.size()));

    EXPECT_EQ(hash_commitment(c), expected);

    // Frozen wire-byte golden (display/reversed hex). A change here means
    // CFinalCommitment serialization drifted — review before re-pinning.
    EXPECT_EQ(to_hex_rev(hash_commitment(c)),
              "484866e842b8b7567d91c64a0b25c2d7e856f0320fc292c2cf7825aca6e4ade4");
}

// ---------------------------------------------------------------------
// merkle primitives
// ---------------------------------------------------------------------

TEST(DashQuorumRootKat, MerkleEmptyIsZero)
{
    EXPECT_EQ(compute_merkle_root_local({}), uint256::ZERO);
}

TEST(DashQuorumRootKat, MerkleSingletonIsItself)
{
    uint256 a = hash_of_byte(0x01);
    EXPECT_EQ(compute_merkle_root_local({a}), a);
}

TEST(DashQuorumRootKat, MerklePairMatchesConcatHash)
{
    uint256 a = hash_of_byte(0x01);
    uint256 b = hash_of_byte(0x02);
    EXPECT_EQ(merkle_pair_hash(a, b), hash256_concat(a, b));
    EXPECT_EQ(compute_merkle_root_local({a, b}), hash256_concat(a, b));
}

TEST(DashQuorumRootKat, MerkleOddTripleDuplicatesLast)
{
    uint256 a = hash_of_byte(0x01);
    uint256 b = hash_of_byte(0x02);
    uint256 c = hash_of_byte(0x03);
    // level1: H(a,b), H(c,c) ; root: H(H(a,b), H(c,c))
    uint256 ab = hash256_concat(a, b);
    uint256 cc = hash256_concat(c, c);
    EXPECT_EQ(compute_merkle_root_local({a, b, c}), hash256_concat(ab, cc));
}

// ---------------------------------------------------------------------
// compute_merkle_root_quorums — set selection + ordering
// ---------------------------------------------------------------------

TEST(DashQuorumRootKat, EmptyManagerRootIsZero)
{
    QuorumManager q;
    EXPECT_EQ(compute_merkle_root_quorums(q), uint256::ZERO);
}

TEST(DashQuorumRootKat, NonRotatedIncludesAllEntriesSorted)
{
    QuorumManager q;
    std::vector<QuorumManager::Entry> active;
    active.push_back(make_entry(CFinalCommitment::LLMQ_50_60,  0x11, 0, 100));
    active.push_back(make_entry(CFinalCommitment::LLMQ_400_60, 0x22, 0, 90));
    active.push_back(make_entry(CFinalCommitment::LLMQ_100_67, 0x33, 0, 110));
    q.replace_state(std::move(active), {});

    EXPECT_EQ(compute_merkle_root_quorums(q),
              compute_merkle_root_local(reference_leaves(q)));
    // All three included -> root is non-zero and depends on the set.
    EXPECT_NE(compute_merkle_root_quorums(q), uint256::ZERO);
}

TEST(DashQuorumRootKat, RotatedDedupKeepsLatestPerIndex)
{
    // Two rotated (type 5) entries share quorumIndex 0; the older one
    // (mining_height 50) must be dropped, the newer (80) kept. A third
    // at quorumIndex 1 is independent and kept.
    QuorumManager q;
    std::vector<QuorumManager::Entry> active;
    active.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xaa, /*qi*/0, 50));
    active.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xbb, /*qi*/0, 80));
    active.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xcc, /*qi*/1, 70));
    q.replace_state(std::move(active), {});

    auto leaves = reference_leaves(q);
    EXPECT_EQ(leaves.size(), 2u);   // older qi=0 dropped
    EXPECT_EQ(compute_merkle_root_quorums(q),
              compute_merkle_root_local(leaves));

    // The dropped older entry must NOT influence the root: a manager
    // holding only {newer qi=0, qi=1} yields the same root.
    QuorumManager q2;
    std::vector<QuorumManager::Entry> active2;
    active2.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xbb, 0, 80));
    active2.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xcc, 1, 70));
    q2.replace_state(std::move(active2), {});
    EXPECT_EQ(compute_merkle_root_quorums(q), compute_merkle_root_quorums(q2));
}

TEST(DashQuorumRootKat, AddingDistinctIndexChangesRoot)
{
    QuorumManager q;
    std::vector<QuorumManager::Entry> a1;
    a1.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xbb, 0, 80));
    q.replace_state(std::move(a1), {});
    uint256 before = compute_merkle_root_quorums(q);

    QuorumManager q2;
    std::vector<QuorumManager::Entry> a2;
    a2.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xbb, 0, 80));
    a2.push_back(make_entry(CFinalCommitment::LLMQ_60_75, 0xcc, 1, 70));
    q2.replace_state(std::move(a2), {});
    EXPECT_NE(before, compute_merkle_root_quorums(q2));
}

TEST(DashQuorumRootKat, MixedRotatedAndNonRotatedFrozenGolden)
{
    QuorumManager q;
    std::vector<QuorumManager::Entry> active;
    active.push_back(make_entry(CFinalCommitment::LLMQ_50_60,  0x11, 0, 100));
    active.push_back(make_entry(CFinalCommitment::LLMQ_400_85, 0x22, 0, 95));
    active.push_back(make_entry(CFinalCommitment::LLMQ_60_75,  0xaa, 0, 50));  // dropped
    active.push_back(make_entry(CFinalCommitment::LLMQ_60_75,  0xbb, 0, 80));  // kept
    active.push_back(make_entry(CFinalCommitment::LLMQ_25_67,  0xcc, 3, 70));
    q.replace_state(std::move(active), {});

    auto leaves = reference_leaves(q);
    EXPECT_EQ(leaves.size(), 4u);   // 2 non-rotated + 2 rotated (one deduped)
    uint256 root = compute_merkle_root_quorums(q);
    EXPECT_EQ(root, compute_merkle_root_local(leaves));

    // Frozen golden (display/reversed hex). Drift => set-selection or
    // serialization changed; re-pin only after verifying intentional.
    EXPECT_EQ(to_hex_rev(root),
              "2cc59f74a7c40646968dafddcfba9759bc66a327c83695b304984f84dbeb0c37");
}