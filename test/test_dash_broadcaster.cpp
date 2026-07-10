// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase S8 — DashBroadcaster peer-pool + discovery scaffold KATs.
///
/// Exercises src/impl/dash/broadcaster.hpp — the PURE peer-pool + discovery +
/// fan-out scaffold one rung above the socket-node:
///
///     p2p_connection -> p2p_node -> [broadcaster] -> broadcaster_full
///
/// What is PINNED here is the real, deterministic, socket-free contract the
/// broadcaster_full keystone builds on. Every test injects the slot factory and
/// the liveness predicate so NO socket is opened and NO live node is required:
///
///   (a) parse_host_port — plain "host:port", bracketed "[v6]:port",
///       "::ffff:" v4-mapped stripping, and rejection of malformed/bad-port.
///   (b) select_candidates — canonical-port filter, primary-host exclude,
///       dedupe vs existing slots, dedupe within batch, backoff skip, and the
///       max_peers cap (live + selected <= max).
///   (c) discover — creates a slot per candidate via the injected factory and
///       reuses freed capacity after prune.
///   (d) prune_dead — removes non-live slots and arms a backoff for each.
///   (e) live_count — counts only slots the injected predicate marks live.
///   (f) peer_info_json_all — merges the primary array with per-slot arrays.
///   (g) submit_block_raw_all — fan-out scaffold invokes the injected per-slot
///       hook on LIVE slots only (NO real block submit in this leaf).
///
/// SCOPE NOTE (honest): the slot factory produces bare NodeP2P objects (no
/// socket attached) and liveness is driven through the injected predicate, so
/// these KATs pin the selection/pool/fan-out logic in isolation against the
/// real dash::Config / NetService / NodeP2P types. The live dashd handshake,
/// getpeerinfo RPC tick, and the real block-submit fan-out are broadcaster_full
/// concerns and are intentionally not exercised here.

#include <gtest/gtest.h>

#include <impl/dash/broadcaster.hpp>
#include <impl/dash/config.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace dash;
using nlohmann::json;

namespace {

// Canonical p2p port the broadcaster filters to (testnet3, 19999 is mainnet).
constexpr uint16_t kCanonicalPort = 19999;
constexpr char     kPrimaryHost[] = "10.9.9.9";

// Build a config whose coin p2p address carries the canonical port the
// candidate selection filters against.
std::unique_ptr<Config> make_config()
{
    auto cfg = std::make_unique<Config>("dash-s8-broadcaster-kat");
    cfg->coin()->m_p2p.address =
        NetService{std::string{"127.0.0.1"}, std::to_string(kCanonicalPort)};
    return cfg;
}

// A factory that records every address it was asked to dial and produces a bare
// NodeP2P (no socket). Liveness of produced slots is governed entirely by the
// injected predicate below, so nothing touches a socket.
struct StubFactory {
    boost::asio::io_context* ioc;
    std::vector<std::string>* dialed;
    DashBroadcaster::Slot operator()(const NetService& addr)
    {
        dialed->push_back(addr.address() + ":" + std::to_string(addr.port()));
        return std::make_unique<dash::coin::p2p::NodeP2P>(ioc);
    }
};

// Helper to wire a broadcaster with the stub factory + a controllable liveness
// predicate (default: everything created is "live").
DashBroadcaster make_bcast(boost::asio::io_context& ioc,
                           Config* cfg,
                           std::vector<std::string>& dialed,
                           bool* all_live,
                           size_t max_peers)
{
    DashBroadcaster b{&ioc, cfg, NetService{std::string{kPrimaryHost},
                                            std::to_string(kCanonicalPort)},
                      max_peers};
    b.set_slot_factory(StubFactory{&ioc, &dialed});
    b.set_live_predicate(
        [all_live](const dash::coin::p2p::NodeP2P&) { return *all_live; });
    return b;
}

json peer(const std::string& addr)
{
    json p = json::object();
    p["addr"] = addr;
    return p;
}

} // namespace

// (a) parse_host_port — all variants.
TEST(DashBroadcaster, ParseHostPortVariants)
{
    // plain host:port
    auto a = DashBroadcaster::parse_host_port("1.2.3.4:19999");
    ASSERT_TRUE(a.valid);
    EXPECT_EQ(a.host, "1.2.3.4");
    EXPECT_EQ(a.port, 19999);

    // bracketed IPv6
    auto b = DashBroadcaster::parse_host_port("[2001:db8::1]:19999");
    ASSERT_TRUE(b.valid);
    EXPECT_EQ(b.host, "2001:db8::1");
    EXPECT_EQ(b.port, 19999);

    // v4-mapped prefix stripped (bracketed form, as dashd emits)
    auto c = DashBroadcaster::parse_host_port("[::ffff:5.6.7.8]:19999");
    ASSERT_TRUE(c.valid);
    EXPECT_EQ(c.host, "5.6.7.8");
    EXPECT_EQ(c.port, 19999);

    // rejections
    EXPECT_FALSE(DashBroadcaster::parse_host_port("").valid);
    EXPECT_FALSE(DashBroadcaster::parse_host_port("nohostport").valid);
    EXPECT_FALSE(DashBroadcaster::parse_host_port("1.2.3.4:abc").valid);
    EXPECT_FALSE(DashBroadcaster::parse_host_port("1.2.3.4:0").valid);
    EXPECT_FALSE(DashBroadcaster::parse_host_port("1.2.3.4:70000").valid);
    EXPECT_FALSE(DashBroadcaster::parse_host_port("[2001:db8::1]").valid);   // no port
    EXPECT_FALSE(DashBroadcaster::parse_host_port("[2001:db8::1]9999").valid); // missing colon
}

// (b) select_candidates — port filter, primary exclude, dedupe, cap.
TEST(DashBroadcaster, SelectCandidatesFilterAndCap)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/2);

    json peers = json::array();
    peers.push_back(peer("1.1.1.1:19999"));                 // good
    peers.push_back(peer("2.2.2.2:8888"));                  // wrong port -> skip
    peers.push_back(std::string{kPrimaryHost} + ":19999");  // not an object form below
    peers.push_back(peer(std::string{kPrimaryHost} + ":19999")); // primary -> skip
    peers.push_back(peer("[::ffff:3.3.3.3]:19999"));        // good (v4-mapped)
    peers.push_back(peer("4.4.4.4:19999"));                 // good but over cap=2
    peers.push_back(peer("1.1.1.1:19999"));                 // dup of first -> skip
    peers.push_back(peer("garbage"));                       // malformed -> skip
    peers.push_back(7);                                     // non-object -> skip

    auto cands = b.select_candidates(peers);
    ASSERT_EQ(cands.size(), 2u);  // capped at max_peers
    EXPECT_EQ(cands[0].address(), "1.1.1.1");
    EXPECT_EQ(cands[1].address(), "3.3.3.3");  // v4-mapped stripped
}

// (b cont) backoff skip is respected by selection.
TEST(DashBroadcaster, SelectCandidatesBackoffSkip)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = false;  // produced slots considered dead -> pruned -> backoff
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/8);

    // First discover dials these; since predicate says dead, prune arms backoff.
    json peers = json::array();
    peers.push_back(peer("5.5.5.5:19999"));
    peers.push_back(peer("6.6.6.6:19999"));

    EXPECT_EQ(b.discover(peers), 2u);   // both dialed (factory always yields)
    EXPECT_EQ(b.prune_dead(), 2u);      // both dead -> pruned + backoff armed
    EXPECT_TRUE(b.is_backed_off("5.5.5.5:19999"));
    EXPECT_TRUE(b.is_backed_off("6.6.6.6:19999"));

    // Now selection must skip both (still backed off).
    auto cands = b.select_candidates(peers);
    EXPECT_TRUE(cands.empty());
}

// (c) discover creates slots via the injected factory.
TEST(DashBroadcaster, DiscoverCreatesSlots)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("7.7.7.7:19999"));
    peers.push_back(peer("8.8.8.8:19999"));

    EXPECT_EQ(b.discover(peers), 2u);
    EXPECT_EQ(b.slot_count(), 2u);
    EXPECT_TRUE(b.has_slot("7.7.7.7:19999"));
    EXPECT_TRUE(b.has_slot("8.8.8.8:19999"));
    ASSERT_EQ(dialed.size(), 2u);

    // Re-discover with the same peers -> dedupe vs existing slots, no new dials.
    EXPECT_EQ(b.discover(peers), 0u);
    EXPECT_EQ(b.slot_count(), 2u);
    EXPECT_EQ(dialed.size(), 2u);
}

// (d) prune_dead removes non-live slots and arms backoff; (e) live_count.
TEST(DashBroadcaster, PruneDeadAndLiveCount)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("9.9.9.1:19999"));
    peers.push_back(peer("9.9.9.2:19999"));
    EXPECT_EQ(b.discover(peers), 2u);
    EXPECT_EQ(b.live_count(), 2u);  // predicate says live

    // Flip predicate to dead -> live_count drops, prune removes both.
    all_live = false;
    EXPECT_EQ(b.live_count(), 0u);
    EXPECT_EQ(b.prune_dead(), 2u);
    EXPECT_EQ(b.slot_count(), 0u);
    EXPECT_TRUE(b.is_backed_off("9.9.9.1:19999"));
    EXPECT_TRUE(b.is_backed_off("9.9.9.2:19999"));
}

// (e cont) capacity cap accounts for existing live slots.
TEST(DashBroadcaster, MaxPeersAccountsForLiveSlots)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/3);

    json first = json::array();
    first.push_back(peer("1.0.0.1:19999"));
    first.push_back(peer("1.0.0.2:19999"));
    EXPECT_EQ(b.discover(first), 2u);
    EXPECT_EQ(b.live_count(), 2u);

    // Now offer 3 more; only 1 fits (2 live + 1 = max 3).
    json more = json::array();
    more.push_back(peer("1.0.0.3:19999"));
    more.push_back(peer("1.0.0.4:19999"));
    more.push_back(peer("1.0.0.5:19999"));
    EXPECT_EQ(b.discover(more), 1u);
    EXPECT_EQ(b.slot_count(), 3u);
}

// (f) peer_info_json_all merges primary + per-slot arrays.
TEST(DashBroadcaster, PeerInfoAggregation)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("2.0.0.1:19999"));
    peers.push_back(peer("2.0.0.2:19999"));
    EXPECT_EQ(b.discover(peers), 2u);

    json primary = json::array();
    primary.push_back(json{{"addr", "primary-A"}});
    primary.push_back(json{{"addr", "primary-B"}});

    // Per-slot json source: each slot contributes a single-element array.
    int counter = 0;
    auto slot_json = [&counter](const dash::coin::p2p::NodeP2P&) {
        json a = json::array();
        a.push_back(json{{"slot", counter++}});
        return a;
    };

    auto all = b.peer_info_json_all(primary, slot_json);
    ASSERT_TRUE(all.is_array());
    EXPECT_EQ(all.size(), 4u);  // 2 primary + 2 slot

    // Without a slot-json source, only the primary array passes through.
    auto primary_only = b.peer_info_json_all(primary);
    EXPECT_EQ(primary_only.size(), 2u);
}

// (g) submit_block_raw_all fan-out scaffold — hook fires on LIVE slots only.
TEST(DashBroadcaster, FanOutHookOnLiveSlotsOnly)
{
    boost::asio::io_context ioc;
    auto cfg = make_config();
    std::vector<std::string> dialed;
    bool all_live = true;
    auto b = make_bcast(ioc, cfg.get(), dialed, &all_live, /*max_peers*/8);

    json peers = json::array();
    peers.push_back(peer("3.0.0.1:19999"));
    peers.push_back(peer("3.0.0.2:19999"));
    EXPECT_EQ(b.discover(peers), 2u);

    int hook_calls = 0;
    std::vector<unsigned char> observed;
    b.set_fan_out_hook(
        [&](dash::coin::p2p::NodeP2P&, std::span<const unsigned char> bytes) {
            ++hook_calls;
            observed.assign(bytes.begin(), bytes.end());
        });

    std::vector<unsigned char> block = {0xde, 0xad, 0xbe, 0xef};
    EXPECT_EQ(b.submit_block_raw_all(block), 2u);  // 2 live slots
    EXPECT_EQ(hook_calls, 2);
    ASSERT_EQ(observed.size(), 4u);
    EXPECT_EQ(observed[0], 0xde);

    // Mark all dead -> no live slots -> hook not invoked.
    all_live = false;
    hook_calls = 0;
    EXPECT_EQ(b.submit_block_raw_all(block), 0u);
    EXPECT_EQ(hook_calls, 0);
}