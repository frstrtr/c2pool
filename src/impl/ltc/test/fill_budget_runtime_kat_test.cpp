// SPDX-License-Identifier: AGPL-3.0-or-later
// G2 fill-budget RUNTIME KATs: the EmbeddedCoinNode-owned LTC bucket.
// grant (one per work event) -> settle (share FOUND, exact template bytes)
// -> lazy reset on a parent-block change -> ramp climbs back above the
// 50 kB floor. Offline, deterministic (injected clock). Folded into the
// allowlisted share_test target (the #769 trap -- no new executable).

#include <gtest/gtest.h>

#include "../coin/fill_budget_runtime.hpp"

#include <core/web_server.hpp>   // core::MiningInterface::compute_merkle_branches

#include <btclibs/util/strencodings.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using ltc::coin::coinbase_merkle_branch;
using ltc::coin::LEGACY_NEWTX_CAP;
using ltc::coin::LTC_FILL_BURST;
using ltc::coin::ParentFillBudget;

namespace {

struct FakeClock {
    double t = 0.0;
    void advance(double dt) { t += dt; }
};

uint256 h(uint8_t b)
{
    uint256 u;
    std::memset(u.begin(), b, 32);
    return u;
}

// What the share-creation hook receives: core's hex branches parsed back
// into uint256 exactly as web_server.cpp fills ShareCreationParams.
std::vector<uint256> core_branch(const std::vector<uint256>& txs)
{
    std::vector<std::string> hex;
    for (const auto& t : txs)
        hex.push_back(t.GetHex());
    std::vector<uint256> out;
    for (const auto& b : core::MiningInterface::compute_merkle_branches(hex)) {
        uint256 u;
        auto bytes = ParseHex(b);
        if (bytes.size() == 32)
            std::memcpy(u.begin(), bytes.data(), 32);
        out.push_back(u);
    }
    return out;
}

} // namespace

// The settle key must equal what the job hands back at share-found time.
TEST(G2FillBudgetRuntime, BranchKeyEqualsCoreShareParams)
{
    for (size_t n : {0u, 1u, 2u, 3u, 4u, 5u, 7u, 8u, 13u}) {
        std::vector<uint256> txs;
        for (size_t i = 0; i < n; ++i)
            txs.push_back(Hash(h(static_cast<uint8_t>(i + 1)), h(0xA5)));
        EXPECT_EQ(coinbase_merkle_branch(txs), core_branch(txs)) << "n=" << n;
    }
    EXPECT_EQ(coinbase_merkle_branch({h(1), h(2), h(3)}),
              (std::vector<uint256>{h(1), Hash(h(2), h(3))}));
}

// The integrator-specified sequence: grant, settle, reset across a parent
// change, and the ramp climbing back above the floor after the block.
TEST(G2FillBudgetRuntime, GrantSettleResetRampClimbsAboveFloor)
{
    FakeClock c;
    auto pb = ParentFillBudget::ltc([&c] { return c.t; });
    const std::vector<uint256> tx_x{h(1), h(2)}, tx_y{h(3)}, tx_z{h(4), h(5), h(6)};

    // Boot on parent A: bucket full, ramp complete -> burst, no reset.
    EXPECT_EQ(pb.begin_work(h(0xA0)), LTC_FILL_BURST);
    pb.record(tx_x, 120000);

    // Share FOUND on that template: exact bytes debited.
    auto s = pb.settle_found(coinbase_merkle_branch(tx_x));
    EXPECT_TRUE(s.matched);
    EXPECT_EQ(s.bytes, 120000u);
    EXPECT_DOUBLE_EQ(pb.tokens(), 130000.0);

    // Same parent, next work event: no reset, grant = remaining tokens.
    EXPECT_EQ(pb.begin_work(h(0xA0)), 130000);

    // Parent changes (block found): refill to burst, ramp restarts at floor.
    EXPECT_EQ(pb.begin_work(h(0xB0)), LEGACY_NEWTX_CAP);
    EXPECT_EQ(pb.shares_since_reset(), 0);
    EXPECT_DOUBLE_EQ(pb.tokens(), 250000.0);
    pb.record(tx_y, 50000);
    EXPECT_TRUE(pb.settle_found(coinbase_merkle_branch(tx_y)).matched);

    // One share after the block: ABOVE the floor (cap 100 kB, tokens 200 kB).
    EXPECT_EQ(pb.begin_work(h(0xB0)), 100000);
    pb.record(tx_z, 100000);
    pb.settle_found(coinbase_merkle_branch(tx_z));
    EXPECT_EQ(pb.current_cap(), 150000);

    // Tokens (100 kB) now bind below the cap; 15 s refill (99990 B) lifts
    // the grant to the 150 kB cap.
    EXPECT_EQ(pb.begin_work(h(0xB0)), 100000);
    c.advance(15);
    EXPECT_EQ(pb.begin_work(h(0xB0)), 150000);

    // Two more found shares complete the ramp back to burst.
    for (int i = 0; i < 2; ++i) {
        pb.record({h(static_cast<uint8_t>(0x10 + i))}, 0);
        pb.settle_found(coinbase_merkle_branch({h(static_cast<uint8_t>(0x10 + i))}));
    }
    EXPECT_EQ(pb.current_cap(), LTC_FILL_BURST);
}

// Why grant and settle ship together: grant alone pins the floor forever.
TEST(G2FillBudgetRuntime, GrantWithoutSettleSticksAtFloor)
{
    FakeClock c;
    auto pb = ParentFillBudget::ltc([&c] { return c.t; });
    pb.begin_work(h(0xA0));
    EXPECT_EQ(pb.begin_work(h(0xB0)), LEGACY_NEWTX_CAP);   // block reset
    for (int i = 0; i < 50; ++i) {
        c.advance(150);
        EXPECT_EQ(pb.begin_work(h(0xB0)), LEGACY_NEWTX_CAP);
    }
    pb.record({h(7)}, 1000);
    pb.settle_found(coinbase_merkle_branch({h(7)}));
    EXPECT_GT(pb.begin_work(h(0xB0)), LEGACY_NEWTX_CAP);
}

// A share on a template no longer in the recent ring debits the held grant
// (upper bound, never an under-debit) and still advances the ramp.
TEST(G2FillBudgetRuntime, UnknownTemplateSettlesHeldGrant)
{
    FakeClock c;
    auto pb = ParentFillBudget::ltc([&c] { return c.t; });
    pb.begin_work(h(0xA0));
    pb.begin_work(h(0xB0));                                 // grant = 50 kB
    pb.record({h(1)}, 1000);
    auto s = pb.settle_found(coinbase_merkle_branch({h(9)}));
    EXPECT_FALSE(s.matched);
    EXPECT_EQ(s.bytes, static_cast<uint64_t>(LEGACY_NEWTX_CAP));
    EXPECT_EQ(pb.shares_since_reset(), 1);
}

TEST(G2FillBudgetRuntime, RecentRingEvictsOldest)
{
    FakeClock c;
    auto pb = ParentFillBudget::ltc([&c] { return c.t; });
    pb.begin_work(h(0xA0));
    for (size_t i = 0; i <= ParentFillBudget::RECENT_TEMPLATES; ++i)
        pb.record({h(static_cast<uint8_t>(i + 1))}, 10 * (i + 1));
    EXPECT_FALSE(pb.settle_found(coinbase_merkle_branch({h(1)})).matched);
    auto s = pb.settle_found(coinbase_merkle_branch({h(2)}));
    EXPECT_TRUE(s.matched);
    EXPECT_EQ(s.bytes, 20u);
}
