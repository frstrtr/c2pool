// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Share version 3601: a share re-wrapped under the other type number.
//
// A 3601 share is the V36 share's bytes under another type number, and
// neither the share hash nor its coinbase commits to the type. A 3601-typed
// copy of a share timestamped before the flag day (or a V36-typed copy of
// one after it) must never reach the tracker: its dedup by hash would keep
// the bad copy, which fails the share check and takes the honest children
// (and the peers relaying them) with it. Pinned here on the real
// ltc::NodeImpl::processing_shares_phase2 and share_check:
//   - the share handlers' filter (drop_misfit_share) drops a share whose
//     type number does not fit its timestamp, in both directions, and the
//     honest copy is then admitted and verifies with its children;
//   - a copy that reaches phase 2 anyway (as a duplicate by hash) does not
//     replace the relay bytes of the share the tracker holds;
//   - the same check guards a share read back from LevelDB.
// Both with the flag day not scheduled (the release default) and scheduled.
#include <gtest/gtest.h>

#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

struct TestNode : public ltc::NodeImpl
{
    TestNode() : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_think_running.store(true);   // run_think's first early return (no io_context)
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    using ltc::NodeImpl::drop_misfit_share;
    using ltc::NodeImpl::m_raw_share_cache;
    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::processing_shares_phase2;
};

constexpr uint32_t kBits = 0x1e0fffff;

template <class S>
S* mk(uint64_t id, const uint256& prev, uint32_t ts)
{
    auto* s = new S(uint256(id), prev);
    s->m_bits = kBits;
    s->m_max_bits = kBits;
    s->m_absheight = 1;
    s->m_timestamp = ts;
    s->m_desired_version = 36;
    s->m_donation = 50;
    s->m_pubkey_hash.SetHex("00000000000000000000000000000000000000a1");
    return s;
}

template <class S>
ltc::ShareType var_of(S* s)
{
    ltc::ShareType v;
    v = s;
    return v;
}

// To phase 2 as the shares / sharereply handlers hand a batch over: the
// loaded share and its wire RawShare (type number + bytes). `filtered`: through
// the handlers' filter first. Returns false when the filter dropped it.
bool deliver(TestNode& node, ltc::ShareType v, const NetService& from, bool filtered = true)
{
    if (filtered) {
        std::string why;
        if (node.drop_misfit_share(v, why))
            return false;
    }
    chain::RawShare raw(v.version(), pack(v));
    ltc::HandleSharesData d;
    d.add(v, {}, raw);
    node.processing_shares_phase2(d, from);
    return true;
}

std::string check_msg(ltc::ShareTracker& tr, ltc::ShareType& v)
{
    const auto params = ltc::make_coin_params(true);
    std::string m;
    v.invoke([&](auto* obj) {
        try {
            ltc::share_check(*obj, obj->m_hash, uint256(), tr, params);
        } catch (const std::exception& e) {
            m = e.what();
        }
    });
    return m;
}

bool flag_day_failure(const std::string& m)
{
    return m.find("flag day") != std::string::npos || m.find("3601") != std::string::npos;
}

class Rewrap : public ::testing::TestWithParam<bool> {
protected:
    void SetUp() override
    {
        was_testnet_ = ltc::PoolConfig::is_testnet;
        ltc::PoolConfig::is_testnet = true;
        now_ = static_cast<uint32_t>(std::time(nullptr));
        // false: the release default (not scheduled); true: one day ahead.
        if (GetParam())
            ltc::PoolConfig::v3601_activation_time_override = now_ + 86400;
    }
    void TearDown() override
    {
        ltc::PoolConfig::v3601_activation_time_override.reset();
        ltc::PoolConfig::is_testnet = was_testnet_;
    }
    bool was_testnet_{false};
    uint32_t now_{0};
};

} // namespace

// A peer delivers the 3601-typed copy of an honest V36 share before the
// honest copy arrives: dropped by the handlers' filter; the honest copy and
// its child are admitted and pass the flag-day and switch steps.
TEST_P(Rewrap, A3601CopyOfAPreFlagDayShareIsDroppedBeforeTheTracker)
{
    TestNode node;
    const NetService attacker("10.0.0.66", 9326), honest("10.0.0.7", 9326);
    const uint256 P(0x100), H(0x101), C(0x102);
    ASSERT_TRUE(deliver(node, var_of(mk<ltc::MergedMiningShare>(0x100, uint256(), now_ - 300)), honest));
    ASSERT_TRUE(node.m_tracker.chain.contains(P));

    std::unique_ptr<ltc::MergedMiningShare> honest_h(mk<ltc::MergedMiningShare>(0x101, P, now_ - 200));
    auto rv = var_of(new ltc::MergedMiningShareV3601(*honest_h));
    EXPECT_NE(ltc::received_share_flag_day_problem(rv), "");
    EXPECT_FALSE(deliver(node, rv, attacker)) << "the handlers drop the 3601-typed copy";
    EXPECT_FALSE(node.m_tracker.chain.contains(H));

    ASSERT_TRUE(deliver(node, var_of(new ltc::MergedMiningShare(*honest_h)), honest));
    ASSERT_TRUE(node.m_tracker.chain.contains(H));
    EXPECT_EQ(node.m_tracker.chain.get_share(H).version(), 36);
    {
        auto& hv = node.m_tracker.chain.get_share(H);
        const auto m = check_msg(node.m_tracker, hv);
        EXPECT_FALSE(flag_day_failure(m)) << m;
    }
    ASSERT_TRUE(deliver(node, var_of(mk<ltc::MergedMiningShare>(0x102, H, now_ - 190)), honest));
    {
        auto& cv = node.m_tracker.chain.get_share(C);
        const auto m = check_msg(node.m_tracker, cv);
        EXPECT_FALSE(flag_day_failure(m)) << m;
    }
}

// A copy that reaches phase 2 anyway, as a duplicate by hash, does not
// replace the relay bytes of the V36 share the tracker holds.
TEST_P(Rewrap, ADuplicateCopyDoesNotReplaceTheRelayBytes)
{
    TestNode node;
    const NetService attacker("10.0.0.66", 9326), honest("10.0.0.7", 9326);
    const uint256 H(0x201);
    std::unique_ptr<ltc::MergedMiningShare> honest_h(mk<ltc::MergedMiningShare>(0x201, uint256(), now_ - 200));
    ASSERT_TRUE(deliver(node, var_of(new ltc::MergedMiningShare(*honest_h)), honest));
    ASSERT_EQ(node.m_raw_share_cache.count(H), 1u);
    EXPECT_EQ(node.m_raw_share_cache.at(H).type, 36u);

    deliver(node, var_of(new ltc::MergedMiningShareV3601(*honest_h)), attacker, /*filtered=*/false);
    EXPECT_EQ(node.m_tracker.chain.get_share(H).version(), 36);
    EXPECT_EQ(node.m_raw_share_cache.at(H).type, 36u) << "the relay bytes stay the held share's";
}

// The other direction: a V36-typed copy of a share after the flag day.
TEST(RewrapPastTheFlagDay, AV36CopyPastTheFlagDayIsDroppedBeforeTheTracker)
{
    ltc::PoolConfig::v3601_activation_time_override = 1700000000u;
    TestNode node;
    std::unique_ptr<ltc::MergedMiningShareV3601> s(mk<ltc::MergedMiningShareV3601>(0x301, uint256(), 1700000100u));
    EXPECT_FALSE(deliver(node, var_of(new ltc::MergedMiningShare(*s)), NetService("10.0.0.66", 9326)));
    EXPECT_FALSE(node.m_tracker.chain.contains(uint256(0x301)));
    // the 3601 share itself is admitted
    EXPECT_TRUE(deliver(node, var_of(new ltc::MergedMiningShareV3601(*s)), NetService("10.0.0.7", 9326)));
    EXPECT_TRUE(node.m_tracker.chain.contains(uint256(0x301)));
    ltc::PoolConfig::v3601_activation_time_override.reset();
}

// The LevelDB load path uses the same check (node.cpp load_persisted_shares).
TEST(RewrapPastTheFlagDay, StoredShareCheck)
{
    ltc::PoolConfig::v3601_activation_time_override = 1700000000u;
    auto early3601 = var_of(mk<ltc::MergedMiningShareV3601>(1, uint256(), 1699999999u));
    auto late36 = var_of(mk<ltc::MergedMiningShare>(2, uint256(), 1700000000u));
    auto ok36 = var_of(mk<ltc::MergedMiningShare>(3, uint256(), 1699999999u));
    auto ok3601 = var_of(mk<ltc::MergedMiningShareV3601>(4, uint256(), 1700000000u));
    EXPECT_NE(ltc::received_share_flag_day_problem(early3601), "");
    EXPECT_NE(ltc::received_share_flag_day_problem(late36), "");
    EXPECT_EQ(ltc::received_share_flag_day_problem(ok36), "");
    EXPECT_EQ(ltc::received_share_flag_day_problem(ok3601), "");
    for (auto* v : {&early3601, &late36, &ok36, &ok3601}) v->destroy();
    ltc::PoolConfig::v3601_activation_time_override.reset();
}

INSTANTIATE_TEST_SUITE_P(FlagDay, Rewrap, ::testing::Values(false, true),
                         [](const auto& i) { return i.param ? std::string("Scheduled") : std::string("NotScheduled"); });
