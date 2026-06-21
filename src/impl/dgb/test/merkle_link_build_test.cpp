// ---------------------------------------------------------------------------
// merkle_link_build_test.cpp -- pins coin/merkle_link_build.hpp
// calculate_merkle_link() as the exact inverse of check_merkle_link().
//
// The won-block multi-tx gap: a reconstructed block's merkle root is recomputed
// from the gentx hash up the share's m_merkle_link, while other_txs fill the
// body. For a tx-bearing won block to ACCEPT at the daemon, the link MUST encode
// the branch for that exact tx set. This KAT proves the builder produces a link
// that replays (via the SAME combine the production check_merkle_link uses) to
// the full-tree BlockMerkleRoot, across coinbase-only, even, and odd
// (duplicate-last) tx counts -- so the rebuilt forced-won block roots correctly.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/dgb/coin/merkle_link_build.hpp>
#include <impl/dgb/share_check.hpp>   // dgb::check_merkle_link (the PRODUCTION verifier)
#include <impl/dgb/share_types.hpp>

using dgb::MerkleLink;
using dgb::coin::calculate_merkle_link;
using dgb::coin::merkle_combine;

namespace
{

// A deterministic, distinct uint256 per leaf (no RNG -- byte-stable KAT input).
uint256 leaf(uint32_t i)
{
    uint256 h;
    auto* p = reinterpret_cast<unsigned char*>(h.data());
    p[0] = static_cast<unsigned char>(0xA0 + i);
    p[1] = static_cast<unsigned char>(i * 7 + 1);
    p[31] = static_cast<unsigned char>(i + 1);
    return h;
}

// Independent reference: Bitcoin's BlockMerkleRoot (duplicate-last on odd),
// over the SAME merkle_combine primitive -- the root node B computes.
uint256 reference_merkle_root(std::vector<uint256> level)
{
    if (level.empty()) return uint256{};
    while (level.size() > 1)
    {
        if (level.size() & 1u) level.push_back(level.back());
        std::vector<uint256> next;
        for (std::size_t k = 0; k + 1 < level.size(); k += 2)
            next.push_back(merkle_combine(level[k], level[k + 1]));
        level = std::move(next);
    }
    return level.front();
}

// The production verifier's walk, re-stated here to keep the KAT self-contained
// (byte-identical to share_check.hpp check_merkle_link's loop). Proves the
// branch the builder emits replays to the root through that exact convention.
uint256 replay_merkle_link(const uint256& tip, const MerkleLink& link)
{
    uint256 cur = tip;
    for (std::size_t i = 0; i < link.m_branch.size(); ++i)
        cur = ((link.m_index >> i) & 1u)
                  ? merkle_combine(link.m_branch[i], cur)
                  : merkle_combine(cur, link.m_branch[i]);
    return cur;
}

std::vector<uint256> leaves(uint32_t n)
{
    std::vector<uint256> v;
    v.reserve(n);
    for (uint32_t i = 0; i < n; ++i) v.push_back(leaf(i));
    return v;
}

} // namespace

// Coinbase-only: empty branch, root == the single leaf (a valid coinbase-only
// won block -- the template-capture MISS contract).
TEST(MerkleLinkBuild, SingleLeafEmptyBranch)
{
    auto txs = leaves(1);
    auto link = calculate_merkle_link(txs, 0);
    EXPECT_TRUE(link.m_branch.empty());
    EXPECT_EQ(link.m_index, 0u);
    EXPECT_EQ(replay_merkle_link(txs[0], link), txs[0]);
    EXPECT_EQ(replay_merkle_link(txs[0], link), reference_merkle_root(txs));
}

// Coinbase index 0 round-trips to the full-tree root across even AND odd
// (duplicate-last) counts -- the multi-tx won-block shape.
TEST(MerkleLinkBuild, CoinbaseIndexRoundTripsRoot)
{
    for (uint32_t n : {2u, 3u, 4u, 5u, 7u, 8u, 13u})
    {
        auto txs = leaves(n);
        auto link = calculate_merkle_link(txs, 0);
        EXPECT_EQ(replay_merkle_link(txs[0], link), reference_merkle_root(txs))
            << "coinbase branch failed for n=" << n;
        // ...and through the PRODUCTION verifier the won block is rooted by.
        EXPECT_EQ(dgb::check_merkle_link(txs[0], link), reference_merkle_root(txs))
            << "production check_merkle_link disagreed for n=" << n;
        // branch depth == ceil(log2(n))
        std::size_t depth = 0, sz = n;
        while (sz > 1) { sz = (sz + 1) / 2; ++depth; }
        EXPECT_EQ(link.m_branch.size(), depth) << "branch depth wrong for n=" << n;
    }
}

// Non-zero leaf index also round-trips (general inverse, not just index 0):
// every leaf's branch must reproduce the one shared root.
TEST(MerkleLinkBuild, EveryLeafIndexReproducesSameRoot)
{
    for (uint32_t n : {2u, 3u, 6u, 9u})
    {
        auto txs = leaves(n);
        const uint256 root = reference_merkle_root(txs);
        for (uint32_t idx = 0; idx < n; ++idx)
        {
            auto link = calculate_merkle_link(txs, idx);
            EXPECT_EQ(link.m_index, idx);
            EXPECT_EQ(replay_merkle_link(txs[idx], link), root)
                << "n=" << n << " idx=" << idx;
            EXPECT_EQ(dgb::check_merkle_link(txs[idx], link), root)
                << "production verifier n=" << n << " idx=" << idx;
        }
    }
}

// Fail-closed: empty input and out-of-range index throw rather than emit a
// silently-wrong (daemon-rejected) branch.
TEST(MerkleLinkBuild, FailsClosedOnBadInput)
{
    EXPECT_THROW(calculate_merkle_link({}, 0), std::invalid_argument);
    auto txs = leaves(3);
    EXPECT_THROW(calculate_merkle_link(txs, 3), std::invalid_argument);
}
