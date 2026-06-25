/// Phase S8 — WonBlockRelay <-> DashBroadcaster binding KATs.
///
/// Exercises src/impl/dash/block_relay_binding.hpp — the adapter that pulls the
/// broadcaster's LIVE slot keys and feeds them to the won-block planner, with NO
/// socket and NO live dashd:
///
///   (a) bind_fanout      — announce against a pool of N discovered+live slots
///                          fans the inv out to exactly those N pool keys, in
///                          deterministic (sorted) order; the block records.
///   (b) excludes_dead    — when the liveness predicate flips every slot dead,
///                          the live view (and thus the fan-out) drops to zero
///                          even though the slots still occupy the pool.
///   (c) empty_pool_record— with an empty pool the block is STILL recorded
///                          (relay.knows == true, pending == 1, fanout == 0):
///                          recording is decoupled from fan-out.
///   (d) reply_passthru   — plan_getdata_reply routes a getdata back to its slot
///                          and serves the announced block.
///   (e) live_fanout_obs  — live_fanout() reports the recipient count WITHOUT
///                          recording anything (relay.pending stays 0).
///
/// SCOPE NOTE (honest): pure adapter over opaque "host:port" slot keys driven by
/// the injected liveness predicate. No socket opened, no io_context driven, no
/// hash recomputed; a block is served only if announced. The live plan -> socket
/// write + dashd submitblock arm is the operator-gated broadcaster_full concern
/// and is not claimed here.

#include <gtest/gtest.h>

#include <impl/dash/block_relay_binding.hpp>
#include <impl/dash/block_relay_plan.hpp>
#include <impl/dash/block_relay.hpp>
#include <impl/dash/broadcaster.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace dash;
using nlohmann::json;
using dash::coin::BlockType;
using dash::coin::p2p::message_getdata;
using dash::coin::p2p::inventory_type;

namespace {

constexpr uint16_t kCanonicalPort = 19999;
constexpr char     kPrimaryHost[] = "10.9.9.9";

std::unique_ptr<Config> make_config()
{
    auto cfg = std::make_unique<Config>("dash-s8-binding-kat");
    cfg->coin()->m_p2p.address =
        NetService{std::string{"127.0.0.1"}, std::to_string(kCanonicalPort)};
    return cfg;
}

// Bare-NodeP2P factory (no socket); liveness governed by the injected predicate.
struct StubFactory {
    boost::asio::io_context* ioc;
    DashBroadcaster::Slot operator()(const NetService& /*addr*/)
    {
        return std::make_unique<dash::coin::p2p::NodeP2P>(ioc);
    }
};

DashBroadcaster make_bcast(boost::asio::io_context& ioc, Config* cfg,
                           bool* all_live, size_t max_peers)
{
    DashBroadcaster b{&ioc, cfg, NetService{std::string{kPrimaryHost},
                                            std::to_string(kCanonicalPort)},
                      max_peers};
    b.set_slot_factory(StubFactory{&ioc});
    b.set_live_predicate(
        [all_live](const dash::coin::p2p::NodeP2P&) { return *all_live; });
    return b;
}

json peer(const std::string& addr)
{
    json p = json::object(); p["addr"] = addr; return p;
}

uint256 hash_seq(uint8_t base)
{
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    uint256 h; std::memcpy(h.data(), p.data(), 32); return h;
}

BlockType make_block(uint8_t seed)
{
    BlockType b;
    b.m_version        = 0x20000000u | seed;
    b.m_previous_block = hash_seq(0x10 + seed);
    b.m_merkle_root    = hash_seq(0x50 + seed);
    b.m_timestamp      = 0x5f5e1000u + seed;
    b.m_bits           = 0x1d00ffffu;
    b.m_nonce          = 0xdeadbeefu - seed;
    return b;
}

inventory_type inv_block(const uint256& h)
{
    return inventory_type(inventory_type::block, h);
}

std::unique_ptr<RawMessage> make_getdata(std::vector<inventory_type> reqs)
{
    return message_getdata::make_raw(std::move(reqs));
}

} // namespace

// (a) bind_fanout: announce reaches every live discovered slot, in pool order ──
TEST(DashRelayBinding, AnnounceFansOutToLivePool)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("1.1.1.1:19999"));
    peers.push_back(peer("2.2.2.2:19999"));
    peers.push_back(peer("3.3.3.3:19999"));
    ASSERT_EQ(pool.discover(peers), 3u);
    ASSERT_EQ(pool.live_slot_keys().size(), 3u);

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);

    const uint256 h = hash_seq(0x20);
    AnnouncePlan plan = binding.plan_announce(h, make_block(4));

    EXPECT_TRUE(relay.knows(h));
    ASSERT_NE(plan.inv, nullptr);
    EXPECT_EQ(plan.inv->m_command, "inv");
    ASSERT_EQ(plan.fanout(), 3u);
    // std::map ordering of the pool keys is deterministic.
    EXPECT_EQ(plan.slots[0], "1.1.1.1:19999");
    EXPECT_EQ(plan.slots[1], "2.2.2.2:19999");
    EXPECT_EQ(plan.slots[2], "3.3.3.3:19999");
}

// (b) excludes_dead: liveness predicate gates the fan-out, not slot occupancy ──
TEST(DashRelayBinding, DeadSlotsDropOutOfFanout)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("1.1.1.1:19999"));
    peers.push_back(peer("2.2.2.2:19999"));
    ASSERT_EQ(pool.discover(peers), 2u);
    ASSERT_EQ(pool.live_slot_keys().size(), 2u);

    // Connections collapse: every slot now fails the liveness predicate.
    all_live = false;
    EXPECT_EQ(pool.live_slot_keys().size(), 0u);
    EXPECT_EQ(pool.slot_count(), 2u);  // still occupy the pool until pruned

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);

    AnnouncePlan plan = binding.plan_announce(hash_seq(0x30), make_block(1));
    EXPECT_TRUE(relay.knows(hash_seq(0x30)));  // recorded regardless
    EXPECT_EQ(plan.fanout(), 0u);              // but nobody live to fan out to
}

// (c) empty_pool_record: empty pool still records the won block ────────────────
TEST(DashRelayBinding, EmptyPoolStillRecords)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);

    const uint256 h = hash_seq(0x40);
    AnnouncePlan plan = binding.plan_announce(h, make_block(2));

    EXPECT_EQ(plan.fanout(), 0u);
    EXPECT_TRUE(relay.knows(h));
    EXPECT_EQ(relay.pending(), 1u);
    ASSERT_NE(plan.inv, nullptr);  // the inv frame exists even with no recipients
}

// (d) reply_passthru: getdata routed back to its slot, serves announced block ──
TEST(DashRelayBinding, GetDataReplyRoutesToSlot)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);
    json peers = json::array();
    peers.push_back(peer("7.7.7.7:19999"));
    ASSERT_EQ(pool.discover(peers), 1u);

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);

    const uint256 h = hash_seq(0x55);
    binding.plan_announce(h, make_block(3));   // record it first

    auto gd = make_getdata({inv_block(h)});
    ReplyPlan reply = binding.plan_getdata_reply("7.7.7.7:19999", *gd);

    EXPECT_EQ(reply.slot, "7.7.7.7:19999");
    EXPECT_EQ(reply.served(), 1u);
    EXPECT_FALSE(reply.has_misses());

    // an unknown hash from the same slot serves nothing and notfounds.
    ReplyPlan miss = binding.plan_getdata_reply("7.7.7.7:19999",
                                                *make_getdata({inv_block(hash_seq(0x99))}));
    EXPECT_EQ(miss.slot, "7.7.7.7:19999");
    EXPECT_EQ(miss.served(), 0u);
    EXPECT_TRUE(miss.has_misses());
}

// (e) live_fanout_obs: observer reports recipients without recording ──────────
TEST(DashRelayBinding, LiveFanoutObserverDoesNotRecord)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);
    json peers = json::array();
    peers.push_back(peer("8.8.8.8:19999"));
    peers.push_back(peer("9.9.9.9:19999"));
    ASSERT_EQ(pool.discover(peers), 2u);

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);

    EXPECT_EQ(binding.live_fanout(), 2u);
    EXPECT_EQ(relay.pending(), 0u);  // nothing recorded by the observer
}
