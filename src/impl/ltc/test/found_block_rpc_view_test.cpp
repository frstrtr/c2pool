// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The found-block verdict on an LTC parent block in RPC mode
// (--no-embedded-ltc): ltc::coin::found_block::rpc_parent_verdict over
// litecoind's best chain (getblockcount, getblockhash, getblockheader), wired
// by main_ltc.cpp into MiningInterface::set_block_verify_fn (> 0 confirmed,
// < 0 orphaned, 0 pending).
//
// Before this, RPC mode wired no parent verifier at all: every LTC row on
// /recent_blocks stayed pending for the life of the node (G3b L3 on VM220,
// 2026-11-24: 1213/1213 rows pending while the node logged an orphan). The
// rule is the embedded node's (found_block_verify_test.cpp). Here the
// litecoind side is pinned: what it answers, its RPC errors, and a daemon
// that is down.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <impl/ltc/coin/found_block_rpc_view.hpp>

namespace {

using ltc::coin::found_block::RpcLookups;
using ltc::coin::found_block::rpc_parent_verdict;

uint256 h_of(const std::string& tag)
{
    uint256 h;
    h.SetHex(tag);
    return h;
}

/// A litecoind stand-in: the best chain by height and every block it knows
/// (any branch). It throws as jsonrpccxx does on an RPC error: -5 "Block not
/// found", -8 "Block height out of range". `down` throws on every call.
struct FakeLitecoind {
    std::map<uint32_t, uint256> best;
    std::map<uint256, uint32_t> known;
    bool down = false;
    int calls_getblockcount = 0;

    void grow(uint32_t from, uint32_t to)
    {
        for (uint32_t h = from; h <= to; ++h) {
            best[h] = h_of("b" + std::to_string(h));
            known[best[h]] = h;
        }
    }
    RpcLookups lookups()
    {
        RpcLookups r;
        r.getblockcount = [this]() -> nlohmann::json {
            ++calls_getblockcount;
            if (down)
                throw std::runtime_error("connection refused");
            return best.empty() ? -1 : static_cast<int64_t>(best.rbegin()->first);
        };
        r.getblockhash = [this](uint32_t h) -> nlohmann::json {
            if (down)
                throw std::runtime_error("connection refused");
            auto it = best.find(h);
            if (it == best.end())
                throw std::runtime_error("-8 Block height out of range");
            return it->second.GetHex();
        };
        r.getblockheader = [this](const uint256& hh) -> nlohmann::json {
            if (down)
                throw std::runtime_error("connection refused");
            auto it = known.find(hh);
            if (it == known.end())
                throw std::runtime_error("-5 Block not found");
            auto in_best = best.find(it->second);
            const bool on_best = in_best != best.end() && in_best->second == hh;
            return nlohmann::json{
                {"hash", hh.GetHex()},
                {"height", it->second},
                {"confirmations", on_best ? static_cast<int64_t>(best.rbegin()->first - it->second + 1) : -1}};
        };
        return r;
    }
};

} // namespace

// Our block is on litecoind's best chain: pending until 6 deep, then
// confirmed with its confirmations.
TEST(LtcFoundBlockRpcVerdict, BestChainBlockConfirmsSixDeep)
{
    FakeLitecoind d;
    d.grow(100, 107);
    const uint256 ours = d.best[105];
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, 105), 0) << "3 deep: pending";
    d.grow(108, 110);
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, 105), 6) << "6 deep: confirmed";
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, std::nullopt), 6)
        << "height from getblockheader when the record has none";
}

// The G3b L3 case: our block lost a race. litecoind knows its header on a
// side branch (confirmations -1); another block holds the height. Never
// confirmed. Orphaned once the best chain is 6 deep from it.
TEST(LtcFoundBlockRpcVerdict, SideBranchBlockIsOrphanedNotConfirmed)
{
    FakeLitecoind d;
    d.grow(100, 106);
    const uint256 ours = h_of("a105");
    d.known[ours] = 105;
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, 105), 0) << "2 deep: a sibling race can still go our way";
    d.grow(107, 110);
    EXPECT_LT(rpc_parent_verdict(d.lookups(), ours, 105), 0) << "6 deep, another block at 105: orphaned";
    EXPECT_LT(rpc_parent_verdict(d.lookups(), ours, std::nullopt), 0)
        << "a side-branch header still gives its height";
}

// litecoind never saw our block (-5 on getblockheader): orphaned once the
// best chain is 6 deep from the record's height. With no height anywhere it
// cannot be judged, so it stays pending.
TEST(LtcFoundBlockRpcVerdict, UnknownBlockOrphanedByRecordHeight)
{
    FakeLitecoind d;
    d.grow(100, 107);
    const uint256 ours = h_of("c105");
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, 105), 0) << "3 deep: pending";
    d.grow(108, 110);
    EXPECT_LT(rpc_parent_verdict(d.lookups(), ours, 105), 0) << "6 deep, never seen: orphaned";
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, std::nullopt), 0) << "no height: pending";
}

// The chain has not reached the record's height (-8 on getblockhash): pending.
TEST(LtcFoundBlockRpcVerdict, HeightAboveTipIsPending)
{
    FakeLitecoind d;
    d.grow(100, 104);
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), h_of("d200"), 200), 0);
}

// An answering daemon is not a confirmation, and a daemon that is down
// gives no verdict either way: pending, never confirmed or orphaned.
TEST(LtcFoundBlockRpcVerdict, DaemonDownIsPending)
{
    FakeLitecoind d;
    d.grow(100, 120);
    const uint256 ours = d.best[105];
    d.down = true;
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), ours, 105), 0);
    EXPECT_EQ(rpc_parent_verdict(d.lookups(), h_of("e105"), 105), 0);
    RpcLookups none;  // no calls bound at all
    EXPECT_EQ(rpc_parent_verdict(none, ours, 105), 0);
}

// One verdict reads one tip: getblockcount is asked once per verdict, so a
// block arriving mid-verdict cannot mix two tips.
TEST(LtcFoundBlockRpcVerdict, TipReadOncePerVerdict)
{
    FakeLitecoind d;
    d.grow(100, 110);
    rpc_parent_verdict(d.lookups(), d.best[105], 105);
    EXPECT_EQ(d.calls_getblockcount, 1);
}
