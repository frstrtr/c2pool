// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin submit-flood gate KATs — pin the two c2pool-side amplifiers of the
// .234 submitblock cs_main wedge (2026-09-20..22):
//   (a) Send() must not re-send a DELIVERED submitblock after a read timeout;
//   (b) the stratum connect path and the won-block dispatch must collapse onto
//       ONE delivered submitblock per block.
//
// A deterministic fake daemon counts every submitblock body it receives; the
// transport model below walks the same attempt loop as NodeRPC::Send(). No
// sockets, no timers. Rides the already-allowlisted btc_share_test executable.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "../coin/submit_flood_gate.hpp"

using btc::coin::RpcFailure;
using btc::coin::SubmitDedupe;
using btc::coin::rpc_may_resend;
using Verdict = SubmitDedupe::Verdict;

namespace {

// bitcoind whose submitblock holds cs_main past our 30s read deadline.
struct WedgedDaemon {
    bool wedged      = true;  // every delivered request outlives the read timeout
    int  drop_writes = 0;     // first N writes hit a dead socket (stale keep-alive)
    int  delivered   = 0;     // submitblock bodies that reached bitcoind
    int  writes      = 0;
};

// Mirror of NodeRPC::Send()'s two-attempt loop. Returns the response body, or
// nullopt when the call failed (NodeRPC then surfaces an exception).
std::optional<std::string> send_model(WedgedDaemon& d, bool non_idempotent)
{
    for (int attempt = 0; attempt < 2; ++attempt) {
        ++d.writes;
        if (d.writes <= d.drop_writes) {
            if (attempt == 0 && rpc_may_resend(RpcFailure::Write, non_idempotent))
                continue;
            return std::nullopt;
        }
        ++d.delivered;
        if (d.wedged) {
            if (attempt == 0 && rpc_may_resend(RpcFailure::Read, non_idempotent))
                continue;
            return std::nullopt;
        }
        return std::string("null");
    }
    return std::nullopt;
}

// Mirror of NodeRPC::submit_block_hex()'s dedupe wrapper.
bool submit_model(WedgedDaemon& d, SubmitDedupe& dedupe, const std::string& block_hex)
{
    const auto key = SubmitDedupe::key_of(block_hex);
    if (auto prior = dedupe.lookup(key))
        return SubmitDedupe::reached(*prior);
    const int before = d.delivered;
    auto body = send_model(d, /*non_idempotent=*/true);
    if (!body) {
        if (d.delivered > before)
            dedupe.record(key, Verdict::DeliveredUnknown);
        return false;
    }
    dedupe.record(key, Verdict::Accepted);
    return true;
}

std::string block_hex(char fill)
{
    // 80-byte header (160 hex) + a body tail that differs from the header.
    return std::string(160, fill) + "01" + std::string(64, 'e');
}

} // namespace

// --- (a) resend policy matrix ---------------------------------------------

TEST(SubmitFloodGate, IdempotentCallsKeepLegacyRetryOnce)
{
    EXPECT_TRUE(rpc_may_resend(RpcFailure::Write, false));
    EXPECT_TRUE(rpc_may_resend(RpcFailure::Read, false));
    EXPECT_TRUE(rpc_may_resend(RpcFailure::EmptyNon200, false));
}

TEST(SubmitFloodGate, SubmitblockResentOnlyWhenNeverDelivered)
{
    EXPECT_TRUE(rpc_may_resend(RpcFailure::Write, true));
    EXPECT_FALSE(rpc_may_resend(RpcFailure::Read, true));
    EXPECT_FALSE(rpc_may_resend(RpcFailure::EmptyNon200, true));
}

TEST(SubmitFloodGate, ReadTimeoutDeliversSubmitblockExactlyOnce)
{
    WedgedDaemon d;
    EXPECT_FALSE(send_model(d, /*non_idempotent=*/true).has_value());
    EXPECT_EQ(d.delivered, 1);   // pre-fix: 2 (resend after the 30s read timeout)
}

TEST(SubmitFloodGate, StaleKeepAliveWriteFailStillRetries)
{
    WedgedDaemon d;
    d.wedged = false;
    d.drop_writes = 1;
    auto body = send_model(d, /*non_idempotent=*/true);
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ(*body, "null");
    EXPECT_EQ(d.delivered, 1);
    EXPECT_EQ(d.writes, 2);
}

// --- (b) per-block dedupe -------------------------------------------------

TEST(SubmitFloodGate, TwoCallersCollapseToOneDeliveredSubmit)
{
    // Stratum connect path + won-block dispatch submit the same block while
    // bitcoind is wedged. Pre-fix worst case: 2 callers x 2 attempts = 4.
    WedgedDaemon d;
    SubmitDedupe dedupe;
    const auto hex = block_hex('a');
    EXPECT_FALSE(submit_model(d, dedupe, hex));   // stratum: delivered, response lost
    EXPECT_TRUE(submit_model(d, dedupe, hex));    // dispatch: deduped, reports reached
    EXPECT_EQ(d.delivered, 1);
    EXPECT_EQ(dedupe.lookup(SubmitDedupe::key_of(hex)), Verdict::DeliveredUnknown);
}

TEST(SubmitFloodGate, UndeliveredSubmitIsNotDeduped)
{
    // Both of the first caller's writes fail: nothing reached bitcoind, so the
    // second caller must still get to deliver the block.
    WedgedDaemon d;
    d.wedged = false;
    d.drop_writes = 2;
    SubmitDedupe dedupe;
    const auto hex = block_hex('b');
    EXPECT_FALSE(submit_model(d, dedupe, hex));
    EXPECT_EQ(d.delivered, 0);
    EXPECT_FALSE(dedupe.lookup(SubmitDedupe::key_of(hex)).has_value());
    EXPECT_TRUE(submit_model(d, dedupe, hex));
    EXPECT_EQ(d.delivered, 1);
}

TEST(SubmitFloodGate, DedupeReplaysPriorVerdict)
{
    SubmitDedupe dedupe;
    const auto ok  = SubmitDedupe::key_of(block_hex('c'));
    const auto bad = SubmitDedupe::key_of(block_hex('d'));
    dedupe.record(ok, Verdict::Accepted);
    dedupe.record(bad, Verdict::Rejected);
    EXPECT_TRUE(SubmitDedupe::reached(*dedupe.lookup(ok)));
    EXPECT_FALSE(SubmitDedupe::reached(*dedupe.lookup(bad)));
    EXPECT_TRUE(SubmitDedupe::reached(Verdict::DeliveredUnknown));
}

TEST(SubmitFloodGate, LaterVerdictSupersedesDeliveredUnknown)
{
    SubmitDedupe dedupe;
    const auto key = SubmitDedupe::key_of(block_hex('e'));
    dedupe.record(key, Verdict::DeliveredUnknown);
    dedupe.record(key, Verdict::Accepted);
    EXPECT_EQ(dedupe.lookup(key), Verdict::Accepted);
    EXPECT_EQ(dedupe.size(), 1u);
}

TEST(SubmitFloodGate, KeyIsTheHeaderNotTheBody)
{
    // Same header with a different body tail is the same block (same hash).
    const std::string header(160, 'f');
    EXPECT_EQ(SubmitDedupe::key_of(header + "01aa"), SubmitDedupe::key_of(header + "02bb"));
    EXPECT_NE(SubmitDedupe::key_of(block_hex('1')), SubmitDedupe::key_of(block_hex('2')));
}

TEST(SubmitFloodGate, WindowIsBoundedFifo)
{
    SubmitDedupe dedupe;
    const std::string fills = "0123456789abcdefgh";   // kCapacity + 2 distinct blocks
    for (char c : fills)
        dedupe.record(SubmitDedupe::key_of(block_hex(c)), Verdict::Accepted);
    EXPECT_EQ(dedupe.size(), SubmitDedupe::kCapacity);
    EXPECT_FALSE(dedupe.lookup(SubmitDedupe::key_of(block_hex('0'))).has_value());
    EXPECT_FALSE(dedupe.lookup(SubmitDedupe::key_of(block_hex('1'))).has_value());
    EXPECT_TRUE(dedupe.lookup(SubmitDedupe::key_of(block_hex('h'))).has_value());
}
