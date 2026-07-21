// SPDX-License-Identifier: AGPL-3.0-or-later
/// FROM-WIRE merkle-root parity: raw mnlistdiff -> our SML/quorum objects ->
/// our merkle roots vs the roots a REAL dashd committed in its CbTx.
///
/// review finding H-5 follow-through. The CbTx byte-parity KAT
/// (test_dash_embedded_cbtx_byte_parity.cpp) proved our wire codec + field
/// assembly reproduce dashd's CbTx byte-identically, but it TRANSPLANTED the two
/// merkle roots from dashd. This suite COMPUTES them from the raw wire:
///
///   raw `mnlistdiff` P2P bytes  (dashd testnet, captured over the P2P socket)
///     --[vendor CSimplifiedMNListDiff deserialize]-->  diff
///     --[apply_diff into an empty SML]--------------->  full SML @ 1518412
///     --[CSimplifiedMNList::CalcMerkleRoot]---------->  merkleRootMNList
///     --[parse_quorum_tail + QuorumManager::apply]--->  active quorum set
///     --[compute_merkle_root_quorums]---------------->  merkleRootQuorums
///
/// and compares to the roots dashd put in the block-1518413 GBT CbTx.
///
/// RESULT (block 1518412, testnet) — BOTH roots match dashd byte-for-byte:
///   * merkleRootMNList  — raw mnlistdiff -> our SML -> our root == dashd's.
///   * merkleRootQuorums — raw mnlistdiff -> our quorum set -> our root ==
///     dashd's. The fix: hash EVERY active commitment (all 109, incl. rotated
///     ring members — no per-index dedup, no mining-height ordering), sort the
///     leaf hashes (memcmp), merkle. Because dashcore also sorts the leaf hashes
///     as the final step, the SET is all that matters and the root is fully
///     wire-derivable (no block-body qc ingest). A prior revision dedup'd
///     rotated types by quorumIndex, dropping ring-member leaves — that diverged.
///
/// Fixtures (verbatim, NOT c2pool output):
///   test/fixtures/dash_testnet_mnlistdiff_1518412.bin  — the `mnlistdiff`
///     message PAYLOAD (checksum-verified on capture) off a synced testnet node.
///   test/fixtures/dash_testnet_gbt_1518413.json        — dashd's GBT roots.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::apply_diff;
using dash::coin::vendor::QuorumTail;
using dash::coin::vendor::parse_quorum_tail;
using dash::coin::QuorumManager;
using dash::coin::compute_merkle_root_quorums;
using dash::coin::hash_commitment;

// dashd's committed roots for block 1518413 (== block 1518412 CbTx / protx diff).
static const char* kExpMnListRoot =
    "6bbc07fd07c1ef0deb0e1c547d1047bb008d80186a742a54702506c41639d48f";
static const char* kExpQuorumRoot =
    "1901c17202846e585a92ee7b858f5716a5a3c33d0afae06f245ae07e7bff1dfb";

static std::vector<unsigned char> read_fixture() {
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_mnlistdiff_1518412.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

static CSimplifiedMNListDiff parse_wire() {
    auto bytes = read_fixture();
    EXPECT_EQ(bytes.size(), 97639u) << "fixture length regression";
    ::PackStream in(bytes);
    CSimplifiedMNListDiff diff;
    in >> diff;
    EXPECT_EQ(in.cursor_size(), 0u)
        << "trailing bytes after mnlistdiff deserialize — wire-layout drift";
    return diff;
}

// ════════════════════════════════════════════════════════════════════════
// merkleRootMNList: full SML from wire -> CalcMerkleRoot == dashd's root.
// PROVEN: the SML axis is byte-identical to dashd end-to-end from the wire.
// ════════════════════════════════════════════════════════════════════════
TEST(DashMnlistdiffRootParity, MerkleRootMNListFromWireMatchesDashd) {
    CSimplifiedMNListDiff diff = parse_wire();
    ASSERT_EQ(diff.baseBlockHash, uint256::ZERO) << "capture must be a full snapshot";

    CSimplifiedMNList sml;                       // empty base
    auto r = apply_diff(sml, diff);
    EXPECT_EQ(r.deleted, 0u) << "full snapshot deletes nothing";
    EXPECT_GT(sml.size(), 300u) << "expected the full testnet DMN set (~375)";

    const uint256 root = sml.CalcMerkleRoot();
    EXPECT_EQ(root.GetHex(), std::string(kExpMnListRoot))
        << "SML CalcMerkleRoot from wire must equal dashd's committed merkleRootMNList";
}

// ════════════════════════════════════════════════════════════════════════
// Quorum SET and LEAF hash are byte-exact from wire — the invariants the
// merkleRootQuorums parity rests on:
//   - the active quorum set is exactly dashd's (109; per-type 24/4/1/24/32/24,
//     matching `protx diff 1 1518412`; includes all rotated ring members);
//   - the leaf hash is byte-exact: pack(commitment) reproduces the wire bytes
//     verbatim, so SHA256d(pack(commitment)) == dashd's ::SerializeHash(qc).
// ════════════════════════════════════════════════════════════════════════
TEST(DashMnlistdiffRootParity, QuorumSetAndLeavesAreByteExactFromWire) {
    CSimplifiedMNListDiff diff = parse_wire();
    ASSERT_FALSE(diff.quorum_tail.empty());

    QuorumTail tail;
    ASSERT_TRUE(parse_quorum_tail(diff.quorum_tail, tail));
    ASSERT_EQ(tail.newQuorums.size(), 109u) << "dashd protx diff reports 109 newQuorums";

    std::map<uint8_t, int> per_type;
    for (const auto& q : tail.newQuorums) per_type[q.llmqType]++;
    EXPECT_EQ(per_type[1], 24);
    EXPECT_EQ(per_type[2], 4);
    EXPECT_EQ(per_type[3], 1);
    EXPECT_EQ(per_type[4], 24);
    EXPECT_EQ(per_type[5], 32);
    EXPECT_EQ(per_type[6], 24);

    // Leaf byte-exactness: pack(commitment) must appear verbatim in the wire tail.
    const auto& c0 = tail.newQuorums.front();
    auto st = ::pack(c0);
    auto sp = st.get_span();
    std::vector<unsigned char> packed(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    auto it = std::search(diff.quorum_tail.begin(), diff.quorum_tail.end(),
                          packed.begin(), packed.end());
    EXPECT_NE(it, diff.quorum_tail.end())
        << "commitment serialization must round-trip the wire bytes exactly "
           "(=> the leaf hash equals dashd's SerializeHash)";
}

// ════════════════════════════════════════════════════════════════════════
// merkleRootQuorums: active quorum set from wire -> compute == dashd's root.
// The daemonless quorum path is now byte-identical to dashd end-to-end.
// ════════════════════════════════════════════════════════════════════════
// The mnlistdiff's embedded cbTx carries the credit-pool seed for its OWN
// blockHash (both a full snapshot and an incremental) — the seed source the
// maintainer must key by cbTx nHeight, not just diff.blockHash. Pins that the
// incremental diff advances the seed to the tip (not one behind).
TEST(DashMnlistdiffRootParity, DiffCbTxCarriesSeedForItsOwnBlock) {
    // Full snapshot @ 1518412.
    CSimplifiedMNListDiff diff = parse_wire();
    ASSERT_EQ(diff.cbTx.type, 5);
    dash::coin::vendor::CCbTx cb;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(diff.cbTx.extra_payload, cb));
    EXPECT_EQ(cb.nHeight, 1518412);
    EXPECT_EQ(cb.creditPoolBalance, 33957998621814LL);

    // Incremental (base=1518667, blockHash=1518669): the cbTx is the TIP's,
    // nHeight == the diff's blockHash height, creditPool == creditPool(1518669).
    const std::string ipath =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_mnlistdiff_incremental_1518669.bin";
    std::ifstream f(ipath, std::ios::binary);
    std::vector<unsigned char> ibytes{std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>()};
    ::PackStream in(ibytes);
    CSimplifiedMNListDiff idiff; in >> idiff;
    ASSERT_EQ(idiff.cbTx.type, 5);
    dash::coin::vendor::CCbTx icb;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(idiff.cbTx.extra_payload, icb));
    EXPECT_EQ(icb.nHeight, 1518669);
    EXPECT_EQ(icb.creditPoolBalance, 33975697944616LL);
}

TEST(DashMnlistdiffRootParity, MerkleRootQuorumsFromWireMatchesDashd) {
    CSimplifiedMNListDiff diff = parse_wire();
    QuorumTail tail;
    ASSERT_TRUE(parse_quorum_tail(diff.quorum_tail, tail));
    QuorumManager qmgr;
    qmgr.apply(tail);
    EXPECT_EQ(qmgr.active_count(), 109u) << "full active quorum set (incl. rotated ring members)";
    const uint256 qroot = compute_merkle_root_quorums(qmgr);
    EXPECT_EQ(qroot.GetHex(), std::string(kExpQuorumRoot))
        << "compute_merkle_root_quorums from wire must equal dashd's merkleRootQuorums";
}
