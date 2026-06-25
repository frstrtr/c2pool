/// Phase S8 — DashBroadcasterFull won-block KEYSTONE KATs (dual-path #83).
///
/// Exercises src/impl/dash/broadcaster_full.hpp — the keystone that routes a
/// WON block to the network over BOTH arms of the dual-path gate:
///
///   ARM A — embedded P2P fan-out (DashBroadcaster::submit_block_raw_all)
///   ARM B — submitblock RPC fallback (dashd authoritative; never removed)
///
/// The gate the integrator verifies: won-block-reaches-network must be proven
/// on EACH arm INDEPENDENTLY (not a single path exercised, no hollow pass). So:
///
///   (1) EmbeddedArmReachesEachLivePeer — N live slots, NO rpc arm: on_block_found
///       fans the EXACT block bytes to every live peer; reached_network() true.
///   (2) EmbeddedArmSkipsDeadPeers      — fan-out hits only LIVE slots.
///   (3) RpcArmReachesNetworkAlone      — ZERO live peers, rpc arm wired:
///       on_block_found relays via submitblock with correct hex; true.
///   (4) RpcArmAcceptReject             — rpc_submitted tracks dashd's accept/reject.
///   (5) DualArmBothFireIndependently   — N live peers AND rpc wired: BOTH arms
///       fire (peers_reached==N AND rpc_submitted) — neither suppresses the other.
///   (6) NoArmIsNotReached              — zero peers AND no rpc: reached_network()
///       false (a won block with no network path must NOT silently pass).
///   (7) HexEncodingMatchesDashd        — to_hex() byte-parity for submitblock.
///
/// Sockets are never opened: the slot factory builds bare NodeP2P, liveness is
/// injected, the per-slot submit and the RPC submit are injected capturing fns.

#include <gtest/gtest.h>

#include <stdexcept>

#include <impl/dash/broadcaster_full.hpp>
#include <impl/dash/broadcaster.hpp>
#include <impl/dash/config.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <string>
#include <vector>

using namespace dash;
using nlohmann::json;

namespace {

constexpr uint16_t kCanonicalPort = 19999;
constexpr char     kPrimaryHost[] = "10.9.9.9";

std::unique_ptr<Config> make_config()
{
    auto cfg = std::make_unique<Config>("dash-s8-broadcaster-full-kat");
    cfg->coin()->m_p2p.address =
        NetService{std::string{"127.0.0.1"}, std::to_string(kCanonicalPort)};
    return cfg;
}

json peer(const std::string& addr)
{
    json p = json::object();
    p["addr"] = addr;
    return p;
}

// Build a leaf broadcaster with a bare-NodeP2P factory and an injected liveness
// predicate, then populate it with `live` live slots + `dead` dead slots via a
// discovery pass. Returns the populated leaf.
struct PoolEnv {
    boost::asio::io_context ioc;
    std::unique_ptr<Config> cfg{make_config()};
    bool all_live{true};
    std::unique_ptr<DashBroadcaster> pool;

    explicit PoolEnv(size_t max_peers = 16)
    {
        pool = std::make_unique<DashBroadcaster>(
            &ioc, cfg.get(),
            NetService{std::string{kPrimaryHost}, std::to_string(kCanonicalPort)},
            max_peers);
        pool->set_slot_factory([this](const NetService&) {
            return std::make_unique<dash::coin::p2p::NodeP2P>(&ioc);
        });
        pool->set_live_predicate(
            [this](const dash::coin::p2p::NodeP2P&) { return all_live; });
    }

    // Dial N peers (all live by construction).
    void dial(size_t n)
    {
        json peers = json::array();
        for (size_t i = 0; i < n; ++i)
            peers.push_back(peer("10.0.0." + std::to_string(i + 1) + ":19999"));
        size_t got = pool->discover(peers);
        ASSERT_EQ(got, n);
    }
};

const std::vector<unsigned char> kBlock = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02};

} // namespace

// (1) Embedded arm alone reaches EVERY live peer with the exact bytes.
TEST(DashBroadcasterFull, EmbeddedArmReachesEachLivePeer)
{
    PoolEnv env;
    env.dial(3);

    DashBroadcasterFull full{env.pool.get()};

    // Capture every per-slot submit (proves fan-out actually delivered bytes).
    size_t calls = 0;
    std::vector<unsigned char> captured;
    full.set_peer_submit([&](dash::coin::p2p::NodeP2P&,
                             std::span<const unsigned char> b) {
        ++calls;
        captured.assign(b.begin(), b.end());  // same bytes each call
    });

    ASSERT_FALSE(full.has_rpc_arm());  // embedded arm in isolation

    auto out = full.on_block_found(kBlock);

    EXPECT_EQ(out.peers_reached, 3u);
    EXPECT_EQ(calls, 3u);
    EXPECT_EQ(captured, kBlock);        // exact bytes reached the wire
    EXPECT_FALSE(out.rpc_attempted);
    EXPECT_TRUE(out.reached_network()); // won block reached network via P2P
}

// (2) Embedded arm fans out to LIVE slots only.
TEST(DashBroadcasterFull, EmbeddedArmSkipsDeadPeers)
{
    PoolEnv env;
    env.dial(2);

    DashBroadcasterFull full{env.pool.get()};
    size_t calls = 0;
    full.set_peer_submit(
        [&](dash::coin::p2p::NodeP2P&, std::span<const unsigned char>) { ++calls; });

    env.all_live = false;  // every slot now reads dead

    auto out = full.on_block_found(kBlock);
    EXPECT_EQ(out.peers_reached, 0u);
    EXPECT_EQ(calls, 0u);
    EXPECT_FALSE(out.reached_network());  // no live peer, no rpc -> not relayed
}

// (3) RPC fallback alone (zero live peers) reaches the network.
TEST(DashBroadcasterFull, RpcArmReachesNetworkAlone)
{
    PoolEnv env;  // NO peers dialed -> embedded arm is cold

    DashBroadcasterFull full{env.pool.get()};

    std::string seen_hex;
    full.set_rpc_submit([&](const std::string& hex) {
        seen_hex = hex;
        return true;  // dashd accepted
    });

    ASSERT_TRUE(full.has_rpc_arm());

    auto out = full.on_block_found(kBlock);

    EXPECT_EQ(out.peers_reached, 0u);            // embedded arm empty
    EXPECT_TRUE(out.rpc_attempted);
    EXPECT_TRUE(out.rpc_submitted);
    EXPECT_EQ(seen_hex, "deadbeef0102");          // correct submitblock payload
    EXPECT_TRUE(out.reached_network());           // won block reached via dashd
}

// (4) RPC arm propagates dashd's accept/reject verdict.
TEST(DashBroadcasterFull, RpcArmAcceptReject)
{
    PoolEnv env;
    DashBroadcasterFull full{env.pool.get()};

    full.set_rpc_submit([&](const std::string&) { return false; });  // dashd rejected
    auto out = full.on_block_found(kBlock);
    EXPECT_TRUE(out.rpc_attempted);
    EXPECT_FALSE(out.rpc_submitted);
    EXPECT_FALSE(out.reached_network());  // rejected + no peers -> not relayed
}

// (5) Dual-arm: BOTH arms fire independently; neither suppresses the other.
TEST(DashBroadcasterFull, DualArmBothFireIndependently)
{
    PoolEnv env;
    env.dial(4);

    DashBroadcasterFull full{env.pool.get()};
    size_t peer_calls = 0;
    bool   rpc_called = false;
    full.set_peer_submit(
        [&](dash::coin::p2p::NodeP2P&, std::span<const unsigned char>) { ++peer_calls; });
    full.set_rpc_submit([&](const std::string& hex) {
        rpc_called = true;
        EXPECT_EQ(hex, "deadbeef0102");
        return true;
    });

    auto out = full.on_block_found(kBlock);

    EXPECT_EQ(out.peers_reached, 4u);   // ARM A fired to all live peers
    EXPECT_EQ(peer_calls, 4u);
    EXPECT_TRUE(out.rpc_submitted);      // ARM B fired too (not gated on empty pool)
    EXPECT_TRUE(rpc_called);
    EXPECT_TRUE(out.reached_network());
}

// (6) No path at all: a won block with no live peers and no RPC is NOT reached.
TEST(DashBroadcasterFull, NoArmIsNotReached)
{
    PoolEnv env;  // no peers
    DashBroadcasterFull full{env.pool.get()};
    ASSERT_FALSE(full.has_rpc_arm());

    auto out = full.on_block_found(kBlock);
    EXPECT_EQ(out.peers_reached, 0u);
    EXPECT_FALSE(out.rpc_attempted);
    EXPECT_FALSE(out.reached_network());  // gate must NOT silently pass
}

// (7) to_hex byte-parity for the submitblock payload.
TEST(DashBroadcasterFull, HexEncodingMatchesDashd)
{
    std::vector<unsigned char> b = {0x00, 0x0f, 0xff, 0x10, 0xa5};
    EXPECT_EQ(DashBroadcasterFull::to_hex(b), "000fff10a5");
    EXPECT_EQ(DashBroadcasterFull::to_hex({}), "");
}

// (8) ARM-A LEG GUARD: a throwing embedded P2P fan-out must NOT prevent the
//     ARM B submitblock RPC fallback — the won block still reaches the network
//     via dashd, peers_reached stays 0 (the fan-out never completed),
//     reached_network() is true (NOT silent-dropped), and on_block_found does
//     NOT propagate the throw. Mirror of NMC #468 / DGB #469 / BCH #471.
TEST(DashBroadcasterFull, ThrowingEmbeddedArmStillFiresRpcFallback)
{
    PoolEnv env;
    env.dial(3);

    DashBroadcasterFull full{env.pool.get()};
    full.set_peer_submit([&](dash::coin::p2p::NodeP2P&,
                             std::span<const unsigned char>) {
        throw std::runtime_error("embedded peer socket reset mid-fanout");
    });
    bool rpc_called = false;
    full.set_rpc_submit([&](const std::string& hex) {
        rpc_called = true;
        EXPECT_EQ(hex, "deadbeef0102");
        return true;  // dashd accepted
    });

    DashBroadcasterFull::Outcome out;
    EXPECT_NO_THROW(out = full.on_block_found(kBlock));
    EXPECT_EQ(out.peers_reached, 0u);   // ARM A threw -> never counted reached
    EXPECT_TRUE(out.rpc_attempted);
    EXPECT_TRUE(out.rpc_submitted);     // ARM B safety net STILL fired
    EXPECT_TRUE(rpc_called);
    EXPECT_TRUE(out.reached_network()); // won block was NOT silent-dropped
}

// (9) ARM-B LEG GUARD: a throwing submitblock RPC sink must not propagate and
//     must not mask an ARM A win already recorded — rpc_submitted stays false,
//     the P2P win stands (peers_reached==N, reached_network() true).
TEST(DashBroadcasterFull, ThrowingRpcDoesNotMaskEmbeddedWin)
{
    PoolEnv env;
    env.dial(2);

    DashBroadcasterFull full{env.pool.get()};
    size_t peer_calls = 0;
    full.set_peer_submit(
        [&](dash::coin::p2p::NodeP2P&, std::span<const unsigned char>) { ++peer_calls; });
    full.set_rpc_submit([&](const std::string&) -> bool {
        throw std::runtime_error("submitblock client socket reset");
    });

    DashBroadcasterFull::Outcome out;
    EXPECT_NO_THROW(out = full.on_block_found(kBlock));
    EXPECT_EQ(out.peers_reached, 2u);   // ARM A win stands
    EXPECT_EQ(peer_calls, 2u);
    EXPECT_TRUE(out.rpc_attempted);
    EXPECT_FALSE(out.rpc_submitted);    // ARM B threw -> treated as no-ack
    EXPECT_TRUE(out.reached_network()); // P2P win not masked
}
