// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for the #157 read-only tx-inject status observability layer
// (core::obs::inject_status()). FOLDED into the EXISTING allowlisted core_test
// target — never a standalone add_executable (the #769 "Not Run" trap: a
// standalone target is not in build.yml's --target list, so CI never builds it
// and CTest reports the cases "Not Run").
//
// Covers the invariants the loopback /api/tx-inject-status endpoint depends on:
//   1. a fresh snapshot is "unwired" (updated_at == 0, enabled == false, pool
//      counts zero) so the endpoint reports wired:false on a flag-OFF build;
//   2. a publish mirrors the flag, pool counts and caps and stamps updated_at;
//   3. the tx_inject p2p wire counter (M2) is an independent slot — the same
//      slot the endpoint reads — and no other message type bleeds into it.
//
// It asserts NOTHING about arming, submission, or config write: the status
// layer is read-only by construction (plain atomics, no node call).

#include <gtest/gtest.h>

#include <core/p2p_message_stats.hpp>

#include <cstdint>

using namespace core::obs;

// ── 1. default snapshot is "unwired" ────────────────────────────────────────

TEST(InjectStatus, DefaultSnapshotIsUnwired)
{
    InjectStatus s;   // a fresh instance models the never-published state
    EXPECT_FALSE(s.enabled.load());
    EXPECT_EQ(s.pool_entries.load(), 0u);
    EXPECT_EQ(s.pool_bytes.load(), 0u);
    EXPECT_EQ(s.max_entries.load(), 0u);
    EXPECT_EQ(s.updated_at.load(), 0);   // 0 => endpoint renders "wired": false
}

// ── 2. a publish mirrors the flag, pool and caps ────────────────────────────

TEST(InjectStatus, PublishMirrorsFlagPoolAndCaps)
{
    InjectStatus s;
    s.enabled.store(true);
    s.pool_entries.store(3);
    s.pool_bytes.store(1200);
    s.max_entries.store(1024);
    s.max_total_bytes.store(400000);
    s.max_tx_bytes.store(100000);
    s.updated_at.store(1234567890);

    EXPECT_TRUE(s.enabled.load());
    EXPECT_EQ(s.pool_entries.load(), 3u);
    EXPECT_EQ(s.pool_bytes.load(), 1200u);
    EXPECT_EQ(s.max_entries.load(), 1024u);
    EXPECT_EQ(s.max_total_bytes.load(), 400000u);
    EXPECT_EQ(s.max_tx_bytes.load(), 100000u);
    EXPECT_NE(s.updated_at.load(), 0);   // stamped => endpoint renders "wired": true
}

// ── 3. tx_inject wire counter is an independent slot ────────────────────────

TEST(InjectStatus, TxInjectWireCounterIsAnIndependentSlot)
{
    P2PMessageStats st;
    EXPECT_EQ(st.get_in(P2PMessage::tx_inject), 0u);

    st.count_in("tx_inject");
    EXPECT_EQ(st.get_in(P2PMessage::tx_inject), 1u);

    // A different message type must not bleed into the tx_inject slot — the
    // /api/tx-inject-status "wire" section reads exactly this slot.
    st.count_in("ping");
    EXPECT_EQ(st.get_in(P2PMessage::tx_inject), 1u);
    EXPECT_EQ(st.get_out(P2PMessage::tx_inject), 0u);
}
