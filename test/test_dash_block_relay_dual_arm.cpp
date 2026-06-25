/// Phase S8 — WonBlock dual-arm delivery plan + reached-network verdict KATs.
///
/// Exercises src/impl/dash/block_relay_dual_arm.hpp — the pure planner that
/// decides which of the two delivery arms (embedded-P2P inv fan-out, dashd
/// submitblock fallback) a won block is armed on, and the static verdict
/// evaluator that decides whether the block reached the network once the
/// keystone has driven both arms. NO socket, NO live dashd:
///
///   (a) both_arms        — live pool + raw bytes -> P2P arm armed (fans out to
///                          the live slots) AND submitblock arm armed; bytes are
///                          carried verbatim; the block records.
///   (b) submitblock_only — empty pool but raw bytes present -> P2P arm DISARMED
///                          (fanout 0) while the submitblock arm STILL carries
///                          it; the block still records.
///   (c) p2p_only         — live pool but no raw bytes -> P2P arm armed, submit-
///                          block arm disarmed.
///   (d) dead_end_records — neither arm armed -> any_armed()==false, yet the
///                          block is STILL recorded (recording is decoupled from
///                          delivery, so a later peer can getdata it).
///   (e) verdict_logic    — evaluate(): reached via P2P acks alone, via submit-
///                          block alone, and NOT reached when both arms fail.
///
/// SCOPE NOTE (honest): pure decision over an opaque caller-supplied raw-block
/// blob and the broadcaster's live-slot view. No socket opened, no io_context
/// driven, no RPC issued, no hash recomputed. The live plan -> socket write, the
/// dashd submitblock RPC, and collecting the real per-arm results are the
/// operator-gated broadcaster_full concern and are not claimed here.

#include <gtest/gtest.h>

#include <impl/dash/block_relay_dual_arm.hpp>
#include <impl/dash/block_relay_binding.hpp>
#include <impl/dash/block_relay_plan.hpp>
#include <impl/dash/block_relay.hpp>
#include <impl/dash/broadcaster.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace dash;
using nlohmann::json;
using dash::coin::BlockType;

namespace {

constexpr uint16_t kCanonicalPort = 19999;
constexpr char     kPrimaryHost[] = "10.9.9.9";

std::unique_ptr<Config> make_config()
{
    auto cfg = std::make_unique<Config>("dash-s8-dualarm-kat");
    cfg->coin()->m_p2p.address =
        NetService{std::string{"127.0.0.1"}, std::to_string(kCanonicalPort)};
    return cfg;
}

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

// A stand-in for the won block's raw serialized bytes captured for submission.
std::vector<unsigned char> raw_bytes(uint8_t seed, size_t n = 80)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = static_cast<unsigned char>(seed + i);
    return v;
}

} // namespace

// (a) both_arms ────────────────────────────────────────────────────────────────
TEST(DashDualArm, BothArmsArmedWithLivePoolAndBytes)
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

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);
    DualArmPlanner dual(binding);

    const uint256 h = hash_seq(0x20);
    const std::vector<unsigned char> bytes = raw_bytes(0xA0);
    DualArmPlan plan = dual.plan(h, make_block(4),
                                 std::span<const unsigned char>(bytes));

    EXPECT_TRUE(relay.knows(h));
    EXPECT_TRUE(plan.p2p_armed);
    EXPECT_TRUE(plan.submitblock_armed);
    EXPECT_TRUE(plan.any_armed());
    EXPECT_EQ(plan.p2p.fanout(), 3u);
    ASSERT_NE(plan.p2p.inv, nullptr);
    // Raw bytes carried verbatim into the submitblock arm.
    ASSERT_EQ(plan.submitblock_bytes.size(), bytes.size());
    EXPECT_EQ(plan.submitblock_bytes, bytes);
}

// (b) submitblock_only ─────────────────────────────────────────────────────────
TEST(DashDualArm, SubmitblockOnlyAtZeroLiveSlots)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);
    // No discover() -> empty live pool.

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);
    DualArmPlanner dual(binding);

    const uint256 h = hash_seq(0x40);
    const std::vector<unsigned char> bytes = raw_bytes(0xB0);
    DualArmPlan plan = dual.plan(h, make_block(2),
                                 std::span<const unsigned char>(bytes));

    EXPECT_FALSE(plan.p2p_armed);          // nobody live to fan out to
    EXPECT_EQ(plan.p2p.fanout(), 0u);
    EXPECT_TRUE(plan.submitblock_armed);   // dashd arm still carries it
    EXPECT_TRUE(plan.any_armed());
    EXPECT_TRUE(relay.knows(h));           // recorded regardless
    EXPECT_EQ(relay.pending(), 1u);
}

// (c) p2p_only ─────────────────────────────────────────────────────────────────
TEST(DashDualArm, P2POnlyWhenNoRawBytes)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);
    json peers = json::array();
    peers.push_back(peer("5.5.5.5:19999"));
    ASSERT_EQ(pool.discover(peers), 1u);

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);
    DualArmPlanner dual(binding);

    const uint256 h = hash_seq(0x60);
    DualArmPlan plan = dual.plan(h, make_block(5),
                                 std::span<const unsigned char>());  // no bytes

    EXPECT_TRUE(plan.p2p_armed);
    EXPECT_EQ(plan.p2p.fanout(), 1u);
    EXPECT_FALSE(plan.submitblock_armed);
    EXPECT_TRUE(plan.submitblock_bytes.empty());
    EXPECT_TRUE(plan.any_armed());
}

// (d) dead_end_records ─────────────────────────────────────────────────────────
TEST(DashDualArm, DeadEndStillRecords)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    bool all_live = true;
    DashBroadcaster pool = make_bcast(ioc, cfg.get(), &all_live, /*max_peers*/4);
    // empty pool + no bytes.

    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    WonBlockRelayBinding binding(pool, planner);
    DualArmPlanner dual(binding);

    const uint256 h = hash_seq(0x70);
    DualArmPlan plan = dual.plan(h, make_block(6),
                                 std::span<const unsigned char>());

    EXPECT_FALSE(plan.p2p_armed);
    EXPECT_FALSE(plan.submitblock_armed);
    EXPECT_FALSE(plan.any_armed());        // dead end: no path to network...
    EXPECT_TRUE(relay.knows(h));           // ...but the block is still recorded
    EXPECT_EQ(relay.pending(), 1u);
}

// (e) verdict_logic ────────────────────────────────────────────────────────────
TEST(DashDualArm, VerdictReachedViaEitherArm)
{
    // P2P alone suffices.
    DeliveryVerdict v1 = DualArmPlanner::evaluate(/*p2p_acks*/2, /*sb_ok*/false);
    EXPECT_TRUE(v1.reached_network());
    EXPECT_EQ(v1.p2p_acks, 2u);
    EXPECT_FALSE(v1.submitblock_ok);

    // submitblock alone suffices (zero live peers).
    DeliveryVerdict v2 = DualArmPlanner::evaluate(0, true);
    EXPECT_TRUE(v2.reached_network());
    EXPECT_EQ(v2.p2p_acks, 0u);
    EXPECT_TRUE(v2.submitblock_ok);

    // both arms suceeding still reaches.
    DeliveryVerdict v3 = DualArmPlanner::evaluate(3, true);
    EXPECT_TRUE(v3.reached_network());
}

TEST(DashDualArm, VerdictNotReachedWhenBothFail)
{
    DeliveryVerdict v = DualArmPlanner::evaluate(/*p2p_acks*/0, /*sb_ok*/false);
    EXPECT_FALSE(v.reached_network());
    EXPECT_EQ(v.p2p_acks, 0u);
    EXPECT_FALSE(v.submitblock_ok);
}
