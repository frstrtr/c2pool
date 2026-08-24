// SPDX-License-Identifier: AGPL-3.0-or-later
/// PR-C3 — ConnectBlock fold-before-publish ordering KAT.
///
/// dashcore's ConnectBlock (validation.cpp) updates the UTXO set + evo state
/// (credit pool, DML, quorums, ChainLocks) from the VALIDATED block body and
/// only THEN makes the new tip visible, so its getblocktemplate never observes
/// a tip at height N with a body-derived axis still at N-1. c2pool's embedded
/// arm advances each axis on its own round trip / local fold, so the seam that
/// publishes the tip to the work source — NodeCoinState::set_tip(), read by
/// DASHWorkSource through select_work() — could be poked with the tip HEADER
/// ahead of the tip BODY's credit-pool fold. That is the intra-node per-tip
/// ordering window measured in issue #1154 (~47-80 ms/tip surviving replay),
/// which surfaces as the creditpool-stale / dmn-stale / payee-stale decline
/// family.
///
/// These cases pin the ported invariant at the seam itself:
///   * DEFAULT OFF — set_tip publishes immediately, byte-identical to master,
///     even with no credit-pool fold (the header-first / RPC-seed / KAT path).
///   * ARMED — set_tip REFUSES to publish a tip whose credit-pool seed is not
///     folded AT that block (fold-before-publish), and the previously
///     published, fully-folded tip is retained (fail-closed, no stale window).
///   * ARMED — once the body folds (set_credit_pool at the tip), the SAME
///     set_tip publishes: the derived state is folded BEFORE the tip goes live.
///   * genesis (prev_height==0) is exempt — no prior block body to fold.
///
/// Reward-safety: the guard only ever REFUSES to advance to a not-yet-folded
/// tip; it never changes any derived value. Off, it is inert.

#include <gtest/gtest.h>

#include <impl/dash/coin/node_coin_state.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>

using dash::coin::NodeCoinState;

namespace {

constexpr uint8_t  ADDR_VER = 76;   // DASH mainnet P2PKH
constexpr uint8_t  P2SH_VER = 16;
constexpr uint32_t BITS     = 0x1a0abcde;
constexpr uint32_t MTP      = 1'700'000'000;

uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

// Publish tip at (height, hash) through the seam the work source reads.
void publish_tip(NodeCoinState& st, uint32_t height, const uint256& hash) {
    st.set_tip(height, hash, BITS, MTP, ADDR_VER, P2SH_VER);
}

// Fold the tip block's body-derived credit-pool seed AT (height, hash) — the
// reward-critical witness that dashd's ConnectBlock advances inside the connect.
void fold_body(NodeCoinState& st, uint32_t height, const uint256& hash) {
    st.set_credit_pool(/*balance=*/123456, hash, static_cast<int32_t>(height));
}

} // namespace

// OFF-equivalence: default flag off, no fold — set_tip publishes immediately,
// exactly as master does. This is what keeps every existing caller (header-
// first, RPC seed, the #673 direct-poke KAT) byte-identical.
TEST(DashConnectBlockOrdering, OffPublishesWithoutFold) {
    NodeCoinState st;
    ASSERT_FALSE(st.connectblock_ordering());

    const uint256 tipH = raw256(0x40);
    publish_tip(st, 2'500'000, tipH);

    EXPECT_TRUE(st.populated());
    EXPECT_EQ(st.published_tip_height(), 2'500'000u);
    EXPECT_EQ(st.published_tip_hash(), tipH);
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 0u);
}

// ARMED: a tip whose body is not yet folded is REFUSED. No serve slot moves
// (populated stays false, prev_height stays 0) — the work source never sees a
// tip ahead of its derived state.
TEST(DashConnectBlockOrdering, ArmedRefusesTipAheadOfFold) {
    NodeCoinState st;
    st.set_connectblock_ordering(true);

    const uint256 tipH = raw256(0x40);
    ASSERT_FALSE(st.credit_pool_folded_at(2'500'000, tipH));

    publish_tip(st, 2'500'000, tipH);

    EXPECT_FALSE(st.populated());
    EXPECT_EQ(st.published_tip_height(), 0u);
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 1u);
}

// ARMED: once the body folds AT the tip, the SAME publish succeeds — the
// derived state is folded BEFORE the tip is published (the ported invariant).
TEST(DashConnectBlockOrdering, ArmedPublishesAfterFold) {
    NodeCoinState st;
    st.set_connectblock_ordering(true);

    const uint256 tipH = raw256(0x40);

    // Pre-fold poke is refused ...
    publish_tip(st, 2'500'000, tipH);
    ASSERT_FALSE(st.populated());
    ASSERT_EQ(st.connectblock_ordering_deferrals(), 1u);

    // ... fold the tip body's credit-pool seed, then publish: now it rides.
    fold_body(st, 2'500'000, tipH);
    ASSERT_TRUE(st.credit_pool_folded_at(2'500'000, tipH));
    publish_tip(st, 2'500'000, tipH);

    EXPECT_TRUE(st.populated());
    EXPECT_EQ(st.published_tip_height(), 2'500'000u);
    EXPECT_EQ(st.published_tip_hash(), tipH);
    // No new deferral on the successful publish.
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 1u);
}

// ARMED: a stale header-tip advance (body of H not folded) is refused while a
// PREVIOUS fully-folded tip (H-1) is already live — the previous tip is
// retained (fail-closed), not clobbered, so the arm keeps serving a tip it can
// stand behind through the propagation window. Promotion resumes once H folds.
TEST(DashConnectBlockOrdering, ArmedRetainsPreviousFoldedTip) {
    NodeCoinState st;
    st.set_connectblock_ordering(true);

    const uint256 tipA = raw256(0x10);   // H-1
    const uint256 tipB = raw256(0x80);   // H

    // Fold + publish H-1.
    fold_body(st, 2'499'999, tipA);
    publish_tip(st, 2'499'999, tipA);
    ASSERT_TRUE(st.populated());
    ASSERT_EQ(st.published_tip_height(), 2'499'999u);

    // Header tip H arrives; its body is not folded yet. Refused, previous
    // tip retained.
    publish_tip(st, 2'500'000, tipB);
    EXPECT_TRUE(st.populated());                 // still live on H-1
    EXPECT_EQ(st.published_tip_height(), 2'499'999u);     // NOT advanced to H
    EXPECT_EQ(st.published_tip_hash(), tipA);
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 1u);

    // H's body folds -> the same advance now publishes.
    fold_body(st, 2'500'000, tipB);
    publish_tip(st, 2'500'000, tipB);
    EXPECT_TRUE(st.populated());
    EXPECT_EQ(st.published_tip_height(), 2'500'000u);
    EXPECT_EQ(st.published_tip_hash(), tipB);
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 1u);
}

// Genesis carve-out: prev_height==0 has no prior block body to fold, so the
// guard is exempt and the publish rides (mirrors the maintainer's ZERO
// carve-outs; prevents a cold-node deadlock).
TEST(DashConnectBlockOrdering, ArmedGenesisExempt) {
    NodeCoinState st;
    st.set_connectblock_ordering(true);

    const uint256 zero = uint256::ZERO;
    publish_tip(st, 0, zero);

    EXPECT_TRUE(st.populated());
    EXPECT_EQ(st.connectblock_ordering_deferrals(), 0u);
}
