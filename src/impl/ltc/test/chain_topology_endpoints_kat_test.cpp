// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT — chain-topology serializable surface backing the four p2pool-parity
// transparency endpoints (/web/heads, /web/tails, /web/verified_heads,
// /web/verified_tails). PR-1 exposes the accessors ONLY; PR-2 hangs the routes
// off them in src/core/web_server.cpp.
//
// This asserts the ShareChain::head_hashes()/tail_hashes() projections against a
// REAL fixture forest — non-empty AND correct membership, not merely non-null:
//
//   raw `chain`    :  R <- a <- b   and   a <- c        (fork off a)
//                     => heads = {b, c} ,  tails = {R}
//   `verified`     :  R <- a <- b                        (subset; borrows a,b)
//                     => heads = {b}    ,  tails = {R}
//
// `verified` borrows the SAME raw share pointers `chain` owns (production
// ownership shape: chain owns, verified is a borrowing view — see the
// ShareTracker dtor's verified.clear_unowned()), so there is no leak and no
// double free. R is the never-added missing-parent anchor every fork descends
// from; it is the correct tail key, exactly as p2pool's tracker.tails reports.
#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

// Distinct, order-stable fixture hashes (numeric value = sort order).
const uint256 R = uint256(0x100);  // root anchor, never added -> the tail key
const uint256 A = uint256(0x001);
const uint256 B = uint256(0x002);
const uint256 C = uint256(0x003);

ltc::MergedMiningShare* mk(const uint256& hash, const uint256& prev) {
    auto* sh = new ltc::MergedMiningShare();
    sh->m_hash = hash;
    sh->m_prev_hash = prev;
    sh->m_desired_version = 36;
    sh->m_bits = 0x1e0fffff;
    sh->m_max_bits = 0x1e0fffff;
    return sh;
}

std::vector<uint256> sorted(std::vector<uint256> v) {
    std::sort(v.begin(), v.end());
    return v;
}

bool has(const std::vector<uint256>& v, const uint256& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

}  // namespace

TEST(LtcChainTopologyEndpoints, HeadsTailsVerifiedMembership) {
    ltc::ShareTracker t;

    // chain OWNS all three raw shares.
    auto* sa = mk(A, R);
    auto* sb = mk(B, A);
    auto* sc = mk(C, A);
    t.chain.add(sa);
    t.chain.add(sb);
    t.chain.add(sc);

    // verified BORROWS the same sa/sb pointers (subset R<-a<-b).
    t.verified.add(sa);
    t.verified.add(sb);

    // --- raw heads: exactly the two tips {B, C} ---
    const auto heads = t.chain.head_hashes();
    EXPECT_EQ(heads.size(), 2u);
    EXPECT_EQ(sorted(heads), (std::vector<uint256>{B, C}));
    EXPECT_TRUE(has(heads, B));
    EXPECT_TRUE(has(heads, C));
    EXPECT_FALSE(has(heads, A));  // interior share is not a head
    EXPECT_FALSE(has(heads, R));  // anchor is not a head

    // --- raw tails: exactly the single anchor {R} ---
    const auto tails = t.chain.tail_hashes();
    EXPECT_EQ(tails.size(), 1u);
    EXPECT_TRUE(has(tails, R));

    // --- verified heads: exactly {B} (C is NOT verified) ---
    const auto vheads = t.verified.head_hashes();
    EXPECT_EQ(vheads.size(), 1u);
    EXPECT_TRUE(has(vheads, B));
    EXPECT_FALSE(has(vheads, C));

    // --- verified tails: exactly {R} ---
    const auto vtails = t.verified.tail_hashes();
    EXPECT_EQ(vtails.size(), 1u);
    EXPECT_TRUE(has(vtails, R));

    // Non-emptiness (the endpoints must never serialize an empty set here).
    EXPECT_FALSE(heads.empty());
    EXPECT_FALSE(tails.empty());
    EXPECT_FALSE(vheads.empty());
    EXPECT_FALSE(vtails.empty());
}
