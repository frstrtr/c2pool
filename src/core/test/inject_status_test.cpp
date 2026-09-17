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

// ── 4. M3 counters + caps round-trip (Slice 2) ──────────────────────────────
//
// The /api/tx-inject-status endpoint's `rate_limit` and `sandbox` objects read
// EXACTLY these atomics (build_tx_inject_status_json in http_session.cpp).
// NodeCoinState publishes them; here we store the M3 rate-limiter / sandbox
// refusal tallies, window occupancy and caps directly into a snapshot and read
// them back — the same store→load the node's publish and the endpoint's render
// perform — proving every field exists, is an independent slot, and mirrors
// faithfully. A default snapshot leaves them all zero (the "dormant" state the
// endpoint renders as null), asserted first.

TEST(InjectStatus, PublishMirrorsM3CountersAndCaps)
{
    InjectStatus s;

    // Dormant default: every M3 slot is zero (endpoint renders rate_limit/sandbox
    // null while updated_at == 0, never 0-as-"unknown").
    EXPECT_EQ(s.rl_local_count_refused.load(), 0u);
    EXPECT_EQ(s.rl_peer_bytes_refused.load(), 0u);
    EXPECT_EQ(s.rl_max_per_window.load(), 0u);
    EXPECT_EQ(s.sb_refused_total.load(), 0u);
    EXPECT_EQ(s.sb_max_inputs.load(), 0u);

    // Rate-limiter refusal tallies (per scope × verdict), window occupancy, caps.
    s.rl_local_count_refused.store(3);
    s.rl_local_bytes_refused.store(1);
    s.rl_peer_count_refused.store(7);
    s.rl_peer_bytes_refused.store(2);
    s.rl_local_in_window.store(11);
    s.rl_peer_in_window.store(13);
    s.rl_local_bytes_in_window.store(4096);
    s.rl_peer_bytes_in_window.store(8192);
    s.rl_max_per_window.store(200);
    s.rl_max_bytes_per_window.store(8u * 1024u * 1024u);
    s.rl_window_sec.store(60);

    // Sandbox refusal tallies (per verdict + running total) and caps.
    s.sb_refused_total.store(5);
    s.sb_refused_inputs.store(1);
    s.sb_refused_outputs.store(1);
    s.sb_refused_scriptsig.store(1);
    s.sb_refused_total_scriptsig.store(1);
    s.sb_refused_sigops.store(1);
    s.sb_max_inputs.store(1000);
    s.sb_max_outputs.store(1000);
    s.sb_max_scriptsig.store(10000);
    s.sb_max_total_scriptsig.store(100000);
    s.sb_max_sigops.store(4000);

    // Read back exactly what the endpoint's rate_limit.{local,peers,caps} reads.
    EXPECT_EQ(s.rl_local_count_refused.load(), 3u);
    EXPECT_EQ(s.rl_local_bytes_refused.load(), 1u);
    EXPECT_EQ(s.rl_peer_count_refused.load(), 7u);
    EXPECT_EQ(s.rl_peer_bytes_refused.load(), 2u);
    EXPECT_EQ(s.rl_local_in_window.load(), 11u);
    EXPECT_EQ(s.rl_peer_in_window.load(), 13u);
    EXPECT_EQ(s.rl_local_bytes_in_window.load(), 4096u);
    EXPECT_EQ(s.rl_peer_bytes_in_window.load(), 8192u);
    EXPECT_EQ(s.rl_max_per_window.load(), 200u);
    EXPECT_EQ(s.rl_max_bytes_per_window.load(), 8u * 1024u * 1024u);
    EXPECT_EQ(s.rl_window_sec.load(), 60u);

    // Read back exactly what the endpoint's sandbox.{refused,caps} reads. The
    // by-cause tallies sum to the running total (each verdict bumped once here).
    EXPECT_EQ(s.sb_refused_total.load(), 5u);
    EXPECT_EQ(s.sb_refused_inputs.load(), 1u);
    EXPECT_EQ(s.sb_refused_outputs.load(), 1u);
    EXPECT_EQ(s.sb_refused_scriptsig.load(), 1u);
    EXPECT_EQ(s.sb_refused_total_scriptsig.load(), 1u);
    EXPECT_EQ(s.sb_refused_sigops.load(), 1u);
    EXPECT_EQ(s.sb_refused_inputs.load() + s.sb_refused_outputs.load()
              + s.sb_refused_scriptsig.load() + s.sb_refused_total_scriptsig.load()
              + s.sb_refused_sigops.load(), s.sb_refused_total.load());
    EXPECT_EQ(s.sb_max_inputs.load(), 1000u);
    EXPECT_EQ(s.sb_max_outputs.load(), 1000u);
    EXPECT_EQ(s.sb_max_scriptsig.load(), 10000u);
    EXPECT_EQ(s.sb_max_total_scriptsig.load(), 100000u);
    EXPECT_EQ(s.sb_max_sigops.load(), 4000u);
}
