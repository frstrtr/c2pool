// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH embedded coin-network P2P client — MULTI-PEER POOL KATs
///
/// Exercises the pool added to src/impl/dash/coin/p2p_client.hpp. The point of
/// the pool is NOT bandwidth: a DKG final commitment (qfcommit) and a ChainLock
/// (clsig) are each announced EXACTLY ONCE by inv and served only by their own
/// digest, so an announcement we did not witness is an object we can never
/// fetch. Holding one peer made "we didn't hear it, therefore it is null" a
/// guess; holding N peers makes it evidence. Every KAT below pins a property
/// that guess-to-evidence conversion depends on:
///
///   (A) CONCURRENCY — N peers are held at once and all reach handshake, with
///       N DISTINCT addresses. (The bug this replaces: 9h of logs showing 3
///       distinct addresses because one connection rotated through a plan.)
///
///   (B) PER-PEER STATE ISOLATION — the liveness policy, ping nonce, handshake
///       tracker and unhandled-command set are per connection. A pong from peer
///       A must NOT close peer B's outstanding ping; if it could, a dead peer
///       would be held "alive" indefinitely by its healthy neighbours and the
///       pool would silently degrade to fewer real witnesses than it reports.
///
///   (C) INDEPENDENT REAPING — a peer that goes silent matures ITS OWN
///       unanswered-ping deadline and is dropped, while the others stay
///       connected and keep delivering messages.
///
///   (D) FAN-IN COLLAPSE — the same inv now arrives from several peers; exactly
///       ONE getdata is issued, not N.
///
///   (E) THE DEDUP SET IS BOUNDED — proven by eviction, both bounds, not
///       asserted in a comment. This node runs for weeks; an unbounded
///       (type, hash) set is a leak that only shows up in production.
///
///   (F) REFILL — losing a peer does not stop the node; the pool re-dials from
///       the scored candidate set and does not re-dial peers it already holds.
///
///   (G) WON-BLOCK RELAY POLICY — broadcast to every handshaked peer. Money
///       path: duplicate submission of a found block is a non-event, a missed
///       submission is a lost block with no retry.
///
/// SCOPE NOTE (honest): as with the sibling single-peer TU, the transport is
/// direct handle() delivery rather than live TCP — everything ABOVE the socket
/// (demux by peer address, per-peer state, liveness, primary election, dedup,
/// broadcast) is the real code. Reliable qfcommit acquisition itself is
/// UNPROVEN until a soak observes it on a live wire; these KATs pin the
/// mechanism, not the outcome.
///
/// This TU compiles into the EXISTING allowlisted test_dash_p2p_node target
/// (fourth source; no new test target, no workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_client.hpp>
#include <impl/dash/coin/govsync_status.hpp>   // R5 coverage wiring proof
#include <impl/dash/config.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes (wire-magic bytes)

#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>

using dash::coin::p2p::CoinClient;
using dash::coin::p2p::InvDedup;
using dash::coin::p2p::PeerSession;

namespace {

namespace p2p = dash::coin::p2p;

// ── Multi-peer rig ────────────────────────────────────────────────────────
//
// attach_peer_for_test() stands a session up with a synthetic endpoint and a
// null socket, the way Factory does on a live connect. The explicit address is
// what makes a MULTI-peer rig possible at all: socketless peers would otherwise
// all key to the same ":0" and the demux would be untestable.
struct PoolRig
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::Config config;
    CoinClient<dash::Config> client;

    PoolRig()
        : config("dash-coin-p2p-pool-kat")
        , client(&ioc, &coin_state, &config, "COIN-P2P-POOL-KAT")
    {
        config.coin()->m_p2p.prefix = ParseHexBytes("cee2caff");   // testnet magic
    }

    // ── simulated clock ──────────────────────────────────────────────────
    // Same rationale as the sibling single-peer TU: every deadline in the
    // client is a comparison against its now_sec(), so the liveness tests drive
    // SIMULATED seconds and assert on exact decisions. No wall clock means no
    // race with a sanitizer-slowed runner, and the SHIPPED 120s/1200s constants
    // become free to assert against.
    int64_t fake_now{1'000'000};
    void use_fake_clock() { client.set_now_fn([this]{ return fake_now; }); }

    /// One simulated second at a time, running the pool tick on each — the
    /// cadence the real repeating timer produces. `on_second` stands in for the
    /// peers' replies.
    void run_seconds(int64_t seconds,
                     const std::function<void(int64_t)>& on_second = nullptr)
    {
        for (int64_t i = 0; i < seconds; ++i)
        {
            ++fake_now;
            client.tick_for_test();
            if (on_second) on_second(fake_now);
        }
    }

    static NetService peer_addr(int n)
    {
        // RFC 5737 TEST-NET-1 literals: never resolvable, never routable, and
        // parsed without touching DNS.
        return NetService{"192.0.2." + std::to_string(n), 19999};
    }
    static std::string peer_key(int n) { return peer_addr(n).to_string(); }

    void attach(int n) { client.attach_peer_for_test(peer_addr(n)); }

    void deliver(int n, std::unique_ptr<RawMessage> rmsg)
    {
        client.handle(std::move(rmsg), peer_addr(n));
    }

    std::unique_ptr<RawMessage> version_msg(uint32_t height,
                                            const std::string& subver = "/Dash Core:21.1.0/",
                                            uint64_t services = 1)
    {
        return p2p::message_version::make_raw(
            70230, services, /*timestamp=*/1234567890ull,
            addr_t{services, NetService{"127.0.0.1", 19999}},
            addr_t{services, NetService{"127.0.0.1", 19999}},
            /*nonce=*/0x1122334455667788ull, subver, height);
    }

    /// Full attach + version/verack for peer n.
    void handshake(int n, uint32_t height = 1000)
    {
        attach(n);
        deliver(n, version_msg(height));
        deliver(n, p2p::message_verack::make_raw());
    }

    /// Full attach + version/verack for peer n advertising a SPECIFIC service
    /// bitfield — the CanServeBlocks convergence KATs stand up mixed
    /// archival(NODE_NETWORK) / pruned(NODE_NETWORK_LIMITED) pools this way.
    void handshake_services(int n, uint64_t services, uint32_t height = 1000)
    {
        attach(n);
        deliver(n, version_msg(height, "/Dash Core:21.1.0/", services));
        deliver(n, p2p::message_verack::make_raw());
    }

    static std::unique_ptr<RawMessage> block_notfound(const uint256& h)
    {
        return p2p::message_notfound::make_raw(std::vector<p2p::inventory_type>{
            p2p::inventory_type(p2p::inventory_type::block, h)});
    }

    const PeerSession* session(int n) const
    {
        return client.peer_session(peer_key(n));
    }

    static std::unique_ptr<RawMessage> qfcommit_inv(const uint256& h)
    {
        return p2p::message_inv::make_raw(std::vector<p2p::inventory_type>{
            p2p::inventory_type(p2p::inventory_type::quorum_final_commitment, h)});
    }
    static std::unique_ptr<RawMessage> block_inv(const uint256& h)
    {
        return p2p::message_inv::make_raw(std::vector<p2p::inventory_type>{
            p2p::inventory_type(p2p::inventory_type::block, h)});
    }
};

uint256 hash_n(uint32_t n)
{
    uint256 h;
    // Distinct, deterministic, and cheap — the dedup key only needs distinctness.
    auto* p = reinterpret_cast<unsigned char*>(&h);
    p[0] = static_cast<unsigned char>(n & 0xff);
    p[1] = static_cast<unsigned char>((n >> 8) & 0xff);
    p[2] = static_cast<unsigned char>((n >> 16) & 0xff);
    p[3] = static_cast<unsigned char>((n >> 24) & 0xff);
    return h;
}

// ══════════════════════════════════════════════════════════════════════════
// (A) CONCURRENCY — N peers at once, all handshaked, N distinct addresses
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, eight_peers_connect_concurrently_and_all_handshake)
{
    PoolRig rig;
    rig.client.set_max_peers(8);
    ASSERT_EQ(rig.client.max_peers(), 8u);

    for (int i = 1; i <= 8; ++i)
        rig.handshake(i, /*height=*/1000u + static_cast<uint32_t>(i));

    EXPECT_EQ(rig.client.connected_peer_count(), 8u)
        << "the pool did not hold eight concurrent peers";
    EXPECT_EQ(rig.client.handshaked_peer_count(), 8u)
        << "not every peer reached version/verack";
    EXPECT_EQ(rig.client.distinct_peer_addresses(), 8u)
        << "eight connections but fewer distinct addresses — the exact failure "
           "the single-connection dial rotation produced unnoticed";
    EXPECT_TRUE(rig.client.is_connected());
    EXPECT_TRUE(rig.client.is_handshake_complete());

    // Exactly one primary, and it is the FIRST peer to have handshaked — the
    // request/response legs must have exactly one carrier.
    EXPECT_EQ(rig.client.peer_key(), PoolRig::peer_key(1));
    int primaries = 0;
    for (int i = 1; i <= 8; ++i)
        if (rig.session(i) && rig.session(i)->primary) ++primaries;
    EXPECT_EQ(primaries, 1);
}

TEST(DashCoinP2PPool, pool_is_hard_capped_and_refuses_duplicate_addresses)
{
    PoolRig rig;
    // Over-cap request is clamped, never honoured.
    rig.client.set_max_peers(9999);
    EXPECT_EQ(rig.client.max_peers(),
              CoinClient<dash::Config>::POOL_PEERS_HARD_CAP);

    rig.client.set_max_peers(3);
    for (int i = 1; i <= 6; ++i) rig.handshake(i);
    EXPECT_EQ(rig.client.connected_peer_count(), 3u)
        << "the pool grew past its configured target";

    // The same endpoint twice must not burn a second slot: one node cannot
    // witness an announcement twice, and a duplicate key breaks the demux.
    PoolRig rig2;
    rig2.client.set_max_peers(4);
    rig2.handshake(1);
    rig2.attach(1);
    EXPECT_EQ(rig2.client.connected_peer_count(), 1u);
    EXPECT_EQ(rig2.client.distinct_peer_addresses(), 1u);
}

TEST(DashCoinP2PPool, peer_metadata_is_per_peer_not_shared)
{
    PoolRig rig;
    rig.client.set_max_peers(4);
    rig.attach(1);
    rig.deliver(1, rig.version_msg(1500000, "/Dash Core:21.1.0/"));
    rig.deliver(1, p2p::message_verack::make_raw());
    rig.attach(2);
    rig.deliver(2, rig.version_msg(1400000, "/Dash Core:22.0.0/"));
    rig.deliver(2, p2p::message_verack::make_raw());

    ASSERT_NE(rig.session(1), nullptr);
    ASSERT_NE(rig.session(2), nullptr);
    EXPECT_EQ(rig.session(1)->subver, "/Dash Core:21.1.0/");
    EXPECT_EQ(rig.session(2)->subver, "/Dash Core:22.0.0/")
        << "peer 2's version message overwrote peer 1's metadata (or vice versa)";
    EXPECT_EQ(rig.session(1)->start_height, 1500000u);
    EXPECT_EQ(rig.session(2)->start_height, 1400000u);

    // The pool's advertised best height is MONOTONE: peer 2 is behind, and a
    // lagging member must not walk the sync-progress target backwards.
    EXPECT_EQ(rig.client.best_peer_height(), 1500000u);
    // The single-peer accessors describe the PRIMARY, which is peer 1.
    EXPECT_EQ(rig.client.peer_start_height(), 1500000u);
    EXPECT_EQ(rig.client.peer_subver(), "/Dash Core:21.1.0/");
}

TEST(DashCoinP2PPool, unhandled_command_set_is_per_peer)
{
    // dashd pushes commands outside our Handler set. The first occurrence per
    // (peer, command) is WARNed, the rest are silent. Per-peer, because a
    // shared set would let the first peer's vocabulary mask every later peer's
    // — and the interesting signal is "THIS peer speaks something we don't".
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);

    rig.deliver(1, std::make_unique<RawMessage>("senddsq", PackStream{}));
    rig.deliver(1, std::make_unique<RawMessage>("senddsq", PackStream{}));
    ASSERT_NE(rig.session(1), nullptr);
    EXPECT_EQ(rig.session(1)->unhandled_seen.size(), 1u);
    ASSERT_NE(rig.session(2), nullptr);
    EXPECT_EQ(rig.session(2)->unhandled_seen.size(), 0u)
        << "peer 1's unhandled-command set leaked into peer 2";

    rig.deliver(2, std::make_unique<RawMessage>("senddsq", PackStream{}));
    EXPECT_EQ(rig.session(2)->unhandled_seen.size(), 1u);
    // Both sessions survive unknown traffic.
    EXPECT_EQ(rig.client.connected_peer_count(), 2u);
}

TEST(DashCoinP2PPool, message_from_an_unattached_peer_is_dropped_not_misattributed)
{
    // The demux keys on the delivering socket's own address (core/socket.cpp
    // tags every message with it). A message from a socket we do not hold must
    // be dropped rather than routed into whichever session happens to be
    // current — misattribution would corrupt that peer's liveness and metadata.
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1, /*height=*/900000);
    ASSERT_NE(rig.session(1), nullptr);
    const uint64_t before = rig.session(1)->msgs_sent;

    rig.deliver(7, rig.version_msg(1234567, "/Impostor/"));   // peer 7 never attached
    EXPECT_EQ(rig.client.connected_peer_count(), 1u);
    EXPECT_EQ(rig.session(1)->subver, "/Dash Core:21.1.0/")
        << "a message from an unattached socket rewrote an attached peer's state";
    EXPECT_EQ(rig.session(1)->msgs_sent, before)
        << "we replied to a peer we do not hold";
}

// ══════════════════════════════════════════════════════════════════════════
// (B) PER-PEER STATE ISOLATION — A's pong must not answer B's ping
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, a_pong_from_one_peer_never_closes_another_peers_ping)
{
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.use_fake_clock();                 // SHIPPED thresholds: 120s / 1200s
    rig.handshake(1);
    rig.handshake(2);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 2u);

    // Advance to the ping interval so the pool tick probes BOTH peers. Neither
    // answers, which is what leaves two outstanding pings to confuse.
    rig.run_seconds(rig.client.ping_interval_sec());

    const PeerSession* p1 = rig.session(1);
    const PeerSession* p2 = rig.session(2);
    ASSERT_NE(p1, nullptr);
    ASSERT_NE(p2, nullptr);
    ASSERT_TRUE(p1->liveness.ping_outstanding()) << "peer 1 was never pinged";
    ASSERT_TRUE(p2->liveness.ping_outstanding()) << "peer 2 was never pinged";
    const uint64_t nonce1 = p1->liveness.ping_nonce();
    const uint64_t nonce2 = p2->liveness.ping_nonce();
    ASSERT_NE(nonce1, nonce2)
        << "both peers were issued the SAME ping nonce — the nonce is shared";

    // Peer 2 answers with PEER 1's nonce. This must satisfy nobody: not peer 1
    // (it did not speak) and not peer 2 (wrong nonce).
    rig.deliver(2, p2p::message_pong::make_raw(nonce1));
    EXPECT_TRUE(p1->liveness.ping_outstanding())
        << "peer 2's pong closed PEER 1's outstanding ping — the nonce is "
           "shared across the pool, so a dead peer can be held alive forever "
           "by a healthy neighbour";
    EXPECT_TRUE(p2->liveness.ping_outstanding())
        << "a wrong-nonce pong closed the ping it did not answer";
    EXPECT_EQ(p2->liveness.pongs_matched(), 0u);

    // Peer 2 now answers correctly: only peer 2's ping closes.
    rig.deliver(2, p2p::message_pong::make_raw(nonce2));
    EXPECT_FALSE(p2->liveness.ping_outstanding());
    EXPECT_EQ(p2->liveness.pongs_matched(), 1u);
    EXPECT_TRUE(p1->liveness.ping_outstanding())
        << "peer 2 answering its own ping also closed peer 1's";
    EXPECT_EQ(p1->liveness.pongs_matched(), 0u);
}

TEST(DashCoinP2PPool, inbound_traffic_to_one_peer_does_not_refresh_another)
{
    // Liveness is evidence about a SPECIFIC peer. If one peer's traffic pushed
    // the whole pool's deadline out, a silent peer would never be reaped for as
    // long as any neighbour was chatty — which is a pool that reports eight
    // witnesses and has one.
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.client.set_keepalive_for_test(/*ping*/60, /*peer_timeout*/600, /*tick*/1);
    rig.handshake(1);
    rig.handshake(2);
    const PeerSession* p1 = rig.session(1);
    const PeerSession* p2 = rig.session(2);
    ASSERT_NE(p1, nullptr);
    ASSERT_NE(p2, nullptr);
    const int64_t p2_before = p2->liveness.last_recv();

    // Hammer peer 1 with inbound traffic.
    for (int i = 0; i < 5; ++i)
        rig.deliver(1, std::make_unique<RawMessage>("senddsq", PackStream{}));

    EXPECT_EQ(p2->liveness.last_recv(), p2_before)
        << "peer 1's inbound traffic refreshed peer 2's liveness deadline";
}

// ══════════════════════════════════════════════════════════════════════════
// (C) INDEPENDENT REAPING — the silent one dies, the others keep delivering
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, silent_peer_is_dropped_while_the_others_keep_delivering)
{
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.use_fake_clock();                 // SHIPPED thresholds: 120s / 1200s
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 3u);
    const int64_t t0 = rig.fake_now;

    std::set<std::string> dropped;
    rig.client.set_on_peer_disconnected(
        [&](const NetService& s){ dropped.insert(s.to_string()); });

    // Peers 1 and 2 answer every ping. Peer 3 says nothing, ever.
    const auto answer_1_and_2 = [&](int64_t){
        for (int n : {1, 2}) {
            const PeerSession* s = rig.session(n);
            if (s && s->liveness.ping_outstanding())
                rig.deliver(n, p2p::message_pong::make_raw(
                    s->liveness.ping_nonce()));
        }
    };

    // One second BEFORE peer 3's own deadline, all three are still held: the
    // silent peer is not reaped early, and the chatty ones have not dragged it
    // along either.
    rig.run_seconds(rig.client.peer_timeout_sec() - 1, answer_1_and_2);
    EXPECT_EQ(rig.client.connected_peer_count(), 3u)
        << "a peer was reaped before its own deadline matured";
    EXPECT_TRUE(dropped.empty());

    // The very next second, peer 3 — and ONLY peer 3 — is gone.
    rig.run_seconds(1, answer_1_and_2);
    ASSERT_EQ(rig.fake_now - t0, rig.client.peer_timeout_sec());
    EXPECT_EQ(dropped.size(), 1u) << "reaping the silent peer took others with it";
    EXPECT_EQ(dropped.count(PoolRig::peer_key(3)), 1u)
        << "the fully silent peer was never reaped";
    EXPECT_EQ(rig.session(3), nullptr);
    // GRACEFUL DEGRADATION: the survivors are untouched and still answerable.
    EXPECT_EQ(rig.client.connected_peer_count(), 2u)
        << "reaping one peer disturbed the others";
    EXPECT_NE(rig.session(1), nullptr);
    EXPECT_NE(rig.session(2), nullptr);
    EXPECT_TRUE(rig.client.is_handshake_complete());
    // EXACT: one ping per PING_INTERVAL_SEC over the window, every one answered.
    const uint64_t expected_pings =
        static_cast<uint64_t>(rig.client.peer_timeout_sec() /
                              rig.client.ping_interval_sec());
    EXPECT_EQ(rig.session(1)->liveness.pings_sent(), expected_pings);
    EXPECT_EQ(rig.session(1)->liveness.pongs_matched(), expected_pings);
    EXPECT_EQ(rig.session(2)->liveness.pongs_matched(), expected_pings);

    // ...and they KEEP DELIVERING: a fresh inv from a survivor is still acted on.
    int fired = 0;
    rig.coin_state.new_block.subscribe([&](uint256){ ++fired; });
    rig.deliver(2, PoolRig::block_inv(hash_n(4242)));
    EXPECT_EQ(fired, 1) << "a survivor's inbound message stopped being dispatched";
}

TEST(DashCoinP2PPool, losing_the_primary_promotes_a_survivor_and_rekicks_sync)
{
    // The primary carries every request/response leg. Losing it must promote a
    // survivor and re-fire the handshake-complete seam — the same re-ask the
    // single-peer client performed on every reconnect. Otherwise the sync legs
    // would go quiet with peers still connected.
    PoolRig rig;
    rig.client.set_max_peers(3);
    int kicks = 0;
    rig.client.set_on_handshake_complete([&]{ ++kicks; });

    rig.handshake(1);
    EXPECT_EQ(kicks, 1);
    rig.handshake(2);
    EXPECT_EQ(kicks, 1) << "a witness peer joining re-kicked the sync legs";
    EXPECT_EQ(rig.client.peer_key(), PoolRig::peer_key(1));

    rig.client.error(std::string("KAT: primary dropped"), PoolRig::peer_addr(1));
    EXPECT_EQ(rig.client.connected_peer_count(), 1u);
    EXPECT_EQ(rig.client.peer_key(), PoolRig::peer_key(2))
        << "the primary was lost and nothing took over the request legs";
    EXPECT_EQ(kicks, 2) << "promotion did not re-kick the sync legs";
    EXPECT_TRUE(rig.client.is_handshake_complete());

    // Losing the LAST peer leaves the node alive and unanswerable, not crashed.
    rig.client.error(std::string("KAT: last peer dropped"), PoolRig::peer_addr(2));
    EXPECT_EQ(rig.client.connected_peer_count(), 0u);
    EXPECT_FALSE(rig.client.is_handshake_complete());
    EXPECT_EQ(rig.client.peer_key(), std::string());
}

TEST(DashCoinP2PPool, error_removes_exactly_one_peer)
{
    PoolRig rig;
    rig.client.set_max_peers(4);
    for (int i = 1; i <= 4; ++i) rig.handshake(i);
    ASSERT_EQ(rig.client.connected_peer_count(), 4u);

    rig.client.error(std::string("KAT: peer 3 blew up"), PoolRig::peer_addr(3));
    EXPECT_EQ(rig.client.connected_peer_count(), 3u);
    EXPECT_EQ(rig.session(3), nullptr);
    for (int i : {1, 2, 4}) EXPECT_NE(rig.session(i), nullptr) << "peer " << i;

    // A double-fire (socket error racing our own teardown) must be a no-op.
    EXPECT_NO_THROW(rig.client.error(std::string("KAT: again"), PoolRig::peer_addr(3)));
    EXPECT_EQ(rig.client.connected_peer_count(), 3u);
    // An error naming a socket we never held must not remove a random peer.
    EXPECT_NO_THROW(rig.client.error(std::string("KAT: stranger"), PoolRig::peer_addr(9)));
    EXPECT_EQ(rig.client.connected_peer_count(), 3u);
}

// ══════════════════════════════════════════════════════════════════════════
// (D) FAN-IN COLLAPSE — one getdata, not N
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, same_qfcommit_inv_from_three_peers_issues_exactly_one_getdata)
{
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 3u);

    const uint64_t before = rig.client.total_msgs_sent();
    const auto d0 = rig.client.inv_dedup().stats();
    const uint256 fqc = hash_n(0xC0FFEE);

    rig.deliver(1, PoolRig::qfcommit_inv(fqc));
    rig.deliver(2, PoolRig::qfcommit_inv(fqc));
    rig.deliver(3, PoolRig::qfcommit_inv(fqc));

    const uint64_t after = rig.client.total_msgs_sent();
    EXPECT_EQ(after - before, 1u)
        << "three announcements of ONE commitment produced " << (after - before)
        << " outbound messages — the fan-in did not collapse";

    const auto d1 = rig.client.inv_dedup().stats();
    EXPECT_EQ(d1.admitted - d0.admitted, 1u);
    EXPECT_EQ(d1.suppressed - d0.suppressed, 2u);

    // The getdata went to the peer that ANNOUNCED it first — it demonstrably
    // holds the object, and its reply routes back to that same session.
    ASSERT_NE(rig.session(1), nullptr);
    ASSERT_NE(rig.session(2), nullptr);
    ASSERT_NE(rig.session(3), nullptr);
    EXPECT_GT(rig.session(1)->msgs_sent, rig.session(2)->msgs_sent);
    EXPECT_EQ(rig.session(2)->msgs_sent, rig.session(3)->msgs_sent);

    // A DIFFERENT commitment is a different key and is still pulled.
    rig.deliver(2, PoolRig::qfcommit_inv(hash_n(0xBEEF)));
    EXPECT_EQ(rig.client.total_msgs_sent() - after, 1u);
}

TEST(DashCoinP2PPool, same_block_inv_from_three_peers_fires_new_block_once)
{
    // Block invs do not take the getdata branch; they fire new_block, which
    // fans into every downstream ingest leg. N peers announcing one block must
    // still be ONE event, or the ingest legs are multiplied by the pool size.
    PoolRig rig;
    rig.client.set_max_peers(3);
    for (int i = 1; i <= 3; ++i) rig.handshake(i);

    int fired = 0;
    rig.coin_state.new_block.subscribe([&](uint256){ ++fired; });
    const uint256 blk = hash_n(777);
    rig.deliver(1, PoolRig::block_inv(blk));
    rig.deliver(2, PoolRig::block_inv(blk));
    rig.deliver(3, PoolRig::block_inv(blk));
    EXPECT_EQ(fired, 1) << "one block announced by three peers fired new_block "
                        << fired << " times";

    rig.deliver(3, PoolRig::block_inv(hash_n(778)));
    EXPECT_EQ(fired, 2) << "a genuinely new block was suppressed";
}

TEST(DashCoinP2PPool, non_actionable_inv_types_do_not_consume_dedup_slots)
{
    // MSG_TX is neither pulled nor block: it must not spend a bounded dedup
    // slot, or a busy mempool would evict the qfcommit/clsig keys we care about.
    PoolRig rig;
    rig.client.set_max_peers(2);
    rig.handshake(1);
    const std::size_t before = rig.client.inv_dedup().size();
    for (uint32_t i = 0; i < 50; ++i)
        rig.deliver(1, p2p::message_inv::make_raw(std::vector<p2p::inventory_type>{
            p2p::inventory_type(p2p::inventory_type::tx, hash_n(9000 + i))}));
    EXPECT_EQ(rig.client.inv_dedup().size(), before);
}

// ══════════════════════════════════════════════════════════════════════════
// (E) THE DEDUP SET IS BOUNDED — eviction PROVEN, both bounds
// ══════════════════════════════════════════════════════════════════════════

TEST(DashInvDedup, first_announcement_admitted_rest_suppressed)
{
    InvDedup d;
    const uint256 h = hash_n(1);
    EXPECT_TRUE(d.admit(21, h, 100));
    EXPECT_FALSE(d.admit(21, h, 100));
    EXPECT_FALSE(d.admit(21, h, 101));
    EXPECT_EQ(d.stats().admitted, 1u);
    EXPECT_EQ(d.stats().suppressed, 2u);
    // The TYPE is part of the key: MSG_CLSIG(29) and MSG_QFCOMMIT(21) with the
    // same digest are different objects.
    EXPECT_TRUE(d.admit(29, h, 101));
    EXPECT_EQ(d.size(), 2u);
}

TEST(DashInvDedup, capacity_bound_evicts_oldest_first_and_size_never_exceeds_it)
{
    InvDedup d;
    d.configure(/*capacity=*/8, /*ttl_sec=*/1000000);   // TTL out of the way

    for (uint32_t i = 0; i < 20; ++i)
    {
        EXPECT_TRUE(d.admit(21, hash_n(i), 1000));
        EXPECT_LE(d.size(), 8u) << "the set exceeded its capacity at i=" << i;
        EXPECT_EQ(d.size(), d.index_size())
            << "the eviction queue and the membership index desynchronised at i="
            << i << " — that gap IS the leak";
    }

    EXPECT_EQ(d.size(), 8u);
    EXPECT_EQ(d.stats().evicted_capacity, 12u);
    EXPECT_EQ(d.stats().evicted_ttl, 0u);

    // The 12 OLDEST are gone (strict FIFO), the 8 newest are still held.
    for (uint32_t i = 0; i < 12; ++i)
        EXPECT_FALSE(d.contains(21, hash_n(i))) << "entry " << i << " survived eviction";
    for (uint32_t i = 12; i < 20; ++i)
        EXPECT_TRUE(d.contains(21, hash_n(i))) << "entry " << i << " was evicted early";

    // ...and an evicted key is genuinely re-admittable (nothing is stranded in
    // the index pretending to be present).
    EXPECT_TRUE(d.admit(21, hash_n(0), 1000));
}

TEST(DashInvDedup, ttl_bound_expires_entries_and_reclaims_them)
{
    InvDedup d;
    d.configure(/*capacity=*/100000, /*ttl_sec=*/10);   // capacity out of the way
    const uint256 h = hash_n(42);

    EXPECT_TRUE(d.admit(21, h, /*now=*/1000));
    EXPECT_FALSE(d.admit(21, h, /*now=*/1005)) << "suppressed inside the TTL";
    EXPECT_EQ(d.size(), 1u);

    // At exactly TTL the entry ages out: reclaimed, and re-admittable.
    EXPECT_TRUE(d.admit(21, h, /*now=*/1010));
    EXPECT_EQ(d.stats().evicted_ttl, 1u);
    EXPECT_EQ(d.size(), 1u);
    EXPECT_EQ(d.size(), d.index_size());

    // A whole generation ages out together, leaving an EMPTY set — the direct
    // proof that a quiet node does not carry yesterday's keys forever.
    InvDedup d2;
    d2.configure(1000, 10);
    for (uint32_t i = 0; i < 500; ++i) d2.admit(21, hash_n(i), 2000);
    EXPECT_EQ(d2.size(), 500u);
    EXPECT_FALSE(d2.admit(29, hash_n(0), 2010) == false);   // forces an expire pass
    EXPECT_EQ(d2.size(), 1u) << "500 aged-out entries were not reclaimed";
    EXPECT_EQ(d2.index_size(), 1u);
    EXPECT_EQ(d2.stats().evicted_ttl, 500u);
}

TEST(DashInvDedup, long_running_arrival_stream_is_bounded_not_a_leak)
{
    // THE PRODUCTION QUESTION, asked directly: this node runs for weeks. Feed
    // it 200k distinct announcements with an out-of-the-way TTL and assert the
    // resident set never exceeds the capacity bound. An unbounded set would
    // grow to 200k here and to millions in production.
    InvDedup d;
    d.configure(/*capacity=*/4096, /*ttl_sec=*/1000000);
    for (uint32_t i = 0; i < 200000; ++i)
    {
        d.admit(21, hash_n(i), 5000);
        if ((i % 5000) == 0)
        {
            ASSERT_LE(d.size(), 4096u) << "unbounded growth at i=" << i;
            ASSERT_EQ(d.size(), d.index_size()) << "index desync at i=" << i;
        }
    }
    EXPECT_EQ(d.size(), 4096u);
    EXPECT_EQ(d.index_size(), 4096u);
    EXPECT_EQ(d.stats().admitted, 200000u);
    EXPECT_EQ(d.stats().evicted_capacity, 200000u - 4096u);
}

TEST(DashInvDedup, capacity_is_floored_at_one_so_dedup_cannot_be_configured_off)
{
    InvDedup d;
    d.configure(/*capacity=*/0, /*ttl_sec=*/600);
    EXPECT_GE(d.capacity(), 1u);
    const uint256 h = hash_n(5);
    EXPECT_TRUE(d.admit(21, h, 10));
    EXPECT_FALSE(d.admit(21, h, 10))
        << "the entry just admitted was immediately evicted — dedup is off";
}

TEST(DashCoinP2PPool, client_dedup_bound_is_configurable_and_enforced_end_to_end)
{
    PoolRig rig;
    rig.client.set_max_peers(2);
    rig.client.configure_inv_dedup(/*capacity=*/16, /*ttl_sec=*/1000000);
    rig.handshake(1);
    for (uint32_t i = 0; i < 200; ++i)
        rig.deliver(1, PoolRig::qfcommit_inv(hash_n(i)));
    EXPECT_EQ(rig.client.inv_dedup().size(), 16u)
        << "the client's dedup set grew past its configured bound";
    EXPECT_EQ(rig.client.inv_dedup().stats().evicted_capacity, 200u - 16u);
}

// ══════════════════════════════════════════════════════════════════════════
// (F) REFILL — the pool re-dials after a loss, and never re-dials what it holds
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, initial_connect_dials_up_to_the_pool_target)
{
    // The io_context is deliberately NOT run: the dials stay in flight, which
    // is exactly what we want to count. (On master the reconnect loop is
    // guarded on holding ZERO peers, so it could only ever have one in flight.)
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.client.connect({PoolRig::peer_addr(1), PoolRig::peer_addr(2),
                        PoolRig::peer_addr(3), PoolRig::peer_addr(4),
                        PoolRig::peer_addr(5)});
    EXPECT_EQ(rig.client.dialing_count(), 3u)
        << "connect() did not open the pool up to its target concurrently";
    EXPECT_EQ(rig.client.connected_peer_count(), 0u);
}

TEST(DashCoinP2PPool, refill_skips_peers_already_held_and_fills_only_the_gap)
{
    PoolRig rig;
    rig.client.set_max_peers(3);
    const std::vector<NetService> plan{
        PoolRig::peer_addr(1), PoolRig::peer_addr(2),
        PoolRig::peer_addr(3), PoolRig::peer_addr(4)};

    rig.client.connect(plan);
    ASSERT_EQ(rig.client.dialing_count(), 3u);
    // The pass starts at the plan's FIRST entry — in the discover posture that
    // is the pinned local dashd, which must not be reachable only after a lap.
    {
        auto d = rig.client.dialing_keys();
        std::set<std::string> s(d.begin(), d.end());
        EXPECT_EQ(s.count(PoolRig::peer_key(1)), 1u)
            << "the first plan entry (pinned node) was skipped by the dial pass";
    }

    // Those three come up (attach clears their in-flight slot).
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);
    EXPECT_EQ(rig.client.connected_peer_count(), 3u);
    EXPECT_EQ(rig.client.dialing_count(), 0u);

    // A full pool must not dial at all.
    rig.client.update_dial_targets(plan);
    EXPECT_EQ(rig.client.dialing_count(), 0u)
        << "a full pool issued a dial";

    // Lose one. GRACEFUL DEGRADATION: node keeps running on the survivors...
    rig.client.error(std::string("KAT: peer 2 lost"), PoolRig::peer_addr(2));
    ASSERT_EQ(rig.client.connected_peer_count(), 2u);
    EXPECT_TRUE(rig.client.is_handshake_complete());

    // ...and the refill closes exactly the one gap, choosing a target we do NOT
    // already hold.
    rig.client.update_dial_targets(plan);
    ASSERT_EQ(rig.client.dialing_count(), 1u)
        << "the pool did not refill after losing a peer";
    const auto dialing = rig.client.dialing_keys();
    ASSERT_EQ(dialing.size(), 1u);
    EXPECT_NE(dialing[0], PoolRig::peer_key(1)) << "re-dialed a peer we hold";
    EXPECT_NE(dialing[0], PoolRig::peer_key(3)) << "re-dialed a peer we hold";
    EXPECT_TRUE(dialing[0] == PoolRig::peer_key(2) ||
                dialing[0] == PoolRig::peer_key(4))
        << "refill dialed something outside the plan: " << dialing[0];
}

TEST(DashCoinP2PPool, empty_connect_arms_without_wedging_and_starts_on_first_seeds)
{
    // Cold start (--coin-p2p-discover, fresh peer-db + DNS unavailable): an
    // empty plan must arm and idle, then dial the moment seeds land.
    PoolRig rig;
    rig.client.set_max_peers(4);
    EXPECT_NO_THROW(rig.client.connect({}));
    EXPECT_EQ(rig.client.connected_peer_count(), 0u);
    EXPECT_EQ(rig.client.dialing_count(), 0u);
    EXPECT_NO_THROW(rig.client.update_dial_targets({}));   // empty refresh: no-op
    EXPECT_EQ(rig.client.dialing_count(), 0u);

    rig.client.update_dial_targets({PoolRig::peer_addr(1), PoolRig::peer_addr(2)});
    EXPECT_EQ(rig.client.dialing_count(), 2u)
        << "seed-discovered targets did not start the cold-start dial";
}

// ══════════════════════════════════════════════════════════════════════════
// (G) WON-BLOCK RELAY POLICY — broadcast to every handshaked peer (money path)
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, won_block_is_broadcast_to_every_handshaked_peer)
{
    PoolRig rig;
    rig.client.set_max_peers(4);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);
    rig.attach(4);                       // connected but NOT handshaked

    std::vector<uint64_t> before;
    for (int i = 1; i <= 4; ++i) before.push_back(rig.session(i)->msgs_sent);

    const std::vector<unsigned char> raw_block(256, 0xAB);
    EXPECT_EQ(rig.client.submit_block_p2p_raw(raw_block), 3u)
        << "the found block did not reach every handshaked peer";

    for (int i = 1; i <= 3; ++i)
        EXPECT_EQ(rig.session(i)->msgs_sent, before[i - 1] + 1)
            << "peer " << i << " did not receive the won block";
    // A peer still mid-handshake cannot be written to meaningfully.
    EXPECT_EQ(rig.session(4)->msgs_sent, before[3]);
}

TEST(DashCoinP2PPool, won_block_with_no_handshaked_peer_reports_zero_not_success)
{
    // The dual-path broadcaster's NEVER-SILENT-DROP contract depends on this
    // count being honest: 0 means the caller MUST fall back to submitblock RPC.
    PoolRig rig;
    rig.client.set_max_peers(2);
    EXPECT_EQ(rig.client.submit_block_p2p_raw({1, 2, 3}), 0u);
    rig.attach(1);                       // socket up, handshake not done
    EXPECT_EQ(rig.client.submit_block_p2p_raw({1, 2, 3}), 0u)
        << "claimed a relay to a peer that has not completed its handshake";
    rig.deliver(1, rig.version_msg(100));
    rig.deliver(1, p2p::message_verack::make_raw());
    EXPECT_EQ(rig.client.submit_block_p2p_raw({1, 2, 3}), 1u);
}

// ── request/response legs stay bound to ONE peer ──────────────────────────

TEST(DashCoinP2PPool, stateful_request_legs_go_to_the_primary_only)
{
    // getmnlistd / getqrinfo / getheaders / mempool are STATEFUL, CURSOR-MATCHED
    // QUESTIONS whose answers must be matched to the peer that was asked (routing
    // class 1): the reply is computed FROM a requester-supplied cursor and applied
    // against the asking session. Fanning them out would mis-route the reply and
    // multiply the stream by the pool size for no extra evidence. (govsync is NOT
    // here — it is a coverage-prime, routing class 3; see
    // govsync_prime_covers_every_handshaked_peer_exactly_once below.)
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);

    std::vector<uint64_t> before;
    for (int i = 1; i <= 3; ++i) before.push_back(rig.session(i)->msgs_sent);

    rig.client.send_getheaders(70230, {}, uint256::ZERO);
    rig.client.send_getmnlistd(uint256::ZERO, uint256::ONE);
    rig.client.send_mempool();

    EXPECT_EQ(rig.session(1)->msgs_sent, before[0] + 3u)
        << "the request legs did not land on the primary";
    EXPECT_EQ(rig.session(2)->msgs_sent, before[1])
        << "a stateful request was fanned out to a witness peer";
    EXPECT_EQ(rig.session(3)->msgs_sent, before[2]);
}

// ── govsync (nProp=0) is a COVERAGE-PRIME: each peer asked EXACTLY once ────────

TEST(DashCoinP2PPool, govsync_prime_covers_every_handshaked_peer_exactly_once)
{
    // govsync(nProp=0) is neither a primary-only stateful question nor a
    // repeat-safe getaddr broadcast: its reply (full object invs) merges into the
    // ONE GovernanceStore regardless of which peer sent it, so multi-peer coverage
    // is the defence against a single peer hiding the winning funding trigger —
    // BUT dashd PUNISHES a repeated full govsync from the same address with
    // Misbehaving(20) (CGovernanceManager::SyncObjects). So the prime must reach
    // every handshaked peer, and reach each one AT MOST ONCE per expiry window.
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);

    std::vector<uint64_t> before;
    for (int i = 1; i <= 3; ++i) before.push_back(rig.session(i)->msgs_sent);

    // First prime: every handshaked peer is asked exactly once; the returned
    // vector is the coverage record (3 distinct keys).
    auto primed1 = rig.client.send_govsync_prime();
    EXPECT_EQ(primed1.size(), 3u) << "the prime did not cover all 3 handshaked peers";
    for (int i = 1; i <= 3; ++i)
        EXPECT_EQ(rig.session(i)->msgs_sent, before[i - 1] + 1u)
            << "peer " << i << " was not primed";

    // Second prime (same expiry window): NOBODY is re-asked — a repeat would earn
    // dashd's Misbehaving(20). Returns empty (no new coverage), no bytes written.
    auto primed2 = rig.client.send_govsync_prime();
    EXPECT_TRUE(primed2.empty()) << "a repeat prime re-asked an already-primed peer "
                                    "(dashd Misbehaving(20) / ban vector)";
    for (int i = 1; i <= 3; ++i)
        EXPECT_EQ(rig.session(i)->msgs_sent, before[i - 1] + 1u)
            << "peer " << i << " was re-primed inside the expiry window";
}

TEST(DashCoinP2PPool, govsync_prime_is_incremental_for_late_handshakes)
{
    // The prime fires from on_handshake_complete: at each new handshake it must
    // write to exactly the ONE newly-handshaked (still-unprimed) peer, never
    // re-touch the peers already primed at earlier handshakes.
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);

    // Prime the first two.
    auto r1 = rig.client.send_govsync_prime();
    EXPECT_EQ(r1.size(), 2u);
    const uint64_t s1 = rig.session(1)->msgs_sent;
    const uint64_t s2 = rig.session(2)->msgs_sent;

    // A third peer completes its handshake; prime again.
    rig.handshake(3);
    const uint64_t s3_before = rig.session(3)->msgs_sent;
    auto r2 = rig.client.send_govsync_prime();

    ASSERT_EQ(r2.size(), 1u) << "the incremental prime touched more than the new peer";
    EXPECT_EQ(r2[0], PoolRig::peer_key(3));
    EXPECT_EQ(rig.session(1)->msgs_sent, s1) << "peer 1 re-primed on a later handshake";
    EXPECT_EQ(rig.session(2)->msgs_sent, s2) << "peer 2 re-primed on a later handshake";
    EXPECT_EQ(rig.session(3)->msgs_sent, s3_before + 1u) << "the new peer was not primed";
}

TEST(DashCoinP2PPool, govsync_prime_reprime_after_expiry)
{
    // The once-only guard is an EXPIRY window (dashd's per-request fulfilled
    // window, ~1h on mainnet), not a permanent latch: once it lapses the peer may
    // be re-asked (dashcore re-syncs governance after its fulfilled request
    // expires). set_govsync_reprime_secs(0) collapses the window so a second call
    // re-primes, proving the TTL semantics rather than a one-shot flag.
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(2);
    rig.client.set_govsync_reprime_secs(0);   // window lapses immediately
    rig.handshake(1);
    rig.handshake(2);

    auto r1 = rig.client.send_govsync_prime();
    EXPECT_EQ(r1.size(), 2u);
    auto r2 = rig.client.send_govsync_prime();
    EXPECT_EQ(r2.size(), 2u) << "a lapsed expiry window did not permit a re-prime";
}

TEST(DashCoinP2PPool, govsync_prime_returned_keys_drive_R5_to_two_peer_completeness)
{
    // THE MACHINE-CHECKED STATEMENT that a single peer can NEVER be the sole
    // governance source: feed the keys RETURNED by the prime across handshakes
    // into the production GovSyncStatus (the R5 completeness predicate the
    // superblock serve path consults). One peer must stay INCOMPLETE; two DISTINCT
    // primed peers must be able to cross the min_peers=2 floor and, after settle +
    // quiescence, flip is_complete() TRUE — exactly the wiring main_dash performs
    // (`for (pk : cp->send_govsync_prime()) maint->note_govsync_requested(pk)`).
    using dash::coin::GovSyncStatus;
    GovSyncStatus gov;                      // defaults: min_peers=2, settle=60, quiesce=30
    const int64_t t0 = 1'000'000;

    PoolRig rig;
    rig.use_fake_clock();
    rig.fake_now = t0;
    rig.client.set_max_peers(2);

    // First peer handshakes and is primed -> record its returned key.
    rig.handshake(1);
    for (const auto& pk : rig.client.send_govsync_prime())
        gov.note_govsync_requested(pk, rig.fake_now);
    EXPECT_EQ(gov.requested_peer_count(), 1u);
    EXPECT_FALSE(gov.is_complete(t0 + 10'000))
        << "a single primed peer must never be a complete governance view";

    // Second DISTINCT peer handshakes later and is primed -> coverage reaches 2.
    rig.fake_now = t0 + 5;
    rig.handshake(2);
    for (const auto& pk : rig.client.send_govsync_prime())
        gov.note_govsync_requested(pk, rig.fake_now);
    EXPECT_EQ(gov.requested_peer_count(), 2u)
        << "two handshakes did not accrue two DISTINCT primed peers";

    // Not settled yet (60s floor since first request).
    EXPECT_FALSE(gov.is_complete(t0 + 30));
    // After the settle floor AND the quiescence window with no new arrivals, the
    // >=2-peer view is COMPLETE — the serve path may now trust the store.
    EXPECT_TRUE(gov.is_complete(t0 + 61 + 30))
        << "a >=2-peer, settled, quiesced governance view was not declared complete";
}

TEST(DashCoinP2PPool, getaddr_is_broadcast_because_discovery_breadth_refills_the_pool)
{
    // An addr reply carries no per-peer matching state, and address breadth is
    // what refills the pool after a loss — so this one leg IS fanned out.
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);

    std::vector<uint64_t> before;
    for (int i = 1; i <= 3; ++i) before.push_back(rig.session(i)->msgs_sent);
    rig.client.send_getaddr();
    for (int i = 1; i <= 3; ++i)
        EXPECT_EQ(rig.session(i)->msgs_sent, before[i - 1] + 1)
            << "peer " << i << " was not asked for addresses";
}

TEST(DashCoinP2PPool, addr_discovery_feed_accepts_records_from_any_pool_peer)
{
    PoolRig rig;
    rig.client.set_max_peers(3);
    std::vector<std::string> discovered;
    rig.client.set_addr_callback([&](const std::vector<NetService>& v){
        for (auto& a : v) discovered.push_back(a.to_string());
    });
    rig.handshake(1);
    rig.handshake(2);

    std::vector<p2p::btc_addr_record_t> recs;
    p2p::btc_addr_record_t rec;
    rec.m_endpoint = NetService{"198.51.100.7", 9999};
    recs.push_back(rec);
    rig.deliver(2, p2p::message_addr::make_raw(recs));
    ASSERT_EQ(discovered.size(), 1u)
        << "a witness peer's addr records were dropped";
    EXPECT_EQ(discovered[0], "198.51.100.7:9999");
}

// ── read-loop preservation, per peer ──────────────────────────────────────

TEST(DashCoinP2PPool, a_throwing_subscriber_costs_one_message_not_the_pool)
{
    // core::Socket re-arms its read only on the line AFTER message_processing(),
    // so an exception escaping handle() leaves that socket open but permanently
    // deaf. With a pool the blast radius question is sharper: it must cost ONE
    // message on ONE peer, never the pool.
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);

    int fired = 0;
    rig.coin_state.new_block.subscribe([&](uint256){
        ++fired;
        throw std::runtime_error("KAT: subscriber blew up");
    });

    EXPECT_NO_THROW(rig.deliver(1, PoolRig::block_inv(hash_n(11))));
    EXPECT_EQ(fired, 1);
    EXPECT_EQ(rig.client.connected_peer_count(), 2u);
    EXPECT_TRUE(rig.client.is_handshake_complete());

    // Both peers are still dispatched afterwards.
    EXPECT_NO_THROW(rig.deliver(2, PoolRig::block_inv(hash_n(12))));
    EXPECT_EQ(fired, 2);
    ASSERT_NE(rig.session(2), nullptr);
    rig.deliver(2, rig.version_msg(1234, "/Dash Core:22.0.0/"));
    EXPECT_EQ(rig.session(2)->subver, "/Dash Core:22.0.0/")
        << "inbound dispatch stopped after a handler threw";
}

// ══════════════════════════════════════════════════════════════════════════
// LOST-BODY WATCHDOG (#1089 208 s tail; same defect class as the #1077
// rotated-pending wedge: a request with no timeout). request_block_tracked's
// getdata unanswered for its per-slot stall window is re-issued from a DIFFERENT
// handshaked peer, rotating on successive attempts; a chronic staller is
// disconnected after BODY_REREQUEST_MAX stalls, each named (`cause=body-rerequest`) —
// killing the 208 s / 600 s inv-TTL tail. FAILS-ON-MASTER: request_block has
// no tracking, no timeout, no re-request at all.
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, lost_tip_body_is_rerequested_from_a_rotated_peer_at_T)
{
    PoolRig rig;
    rig.use_fake_clock();
    for (int i = 1; i <= 3; ++i) rig.handshake(i);

    const uint256 h = hash_n(0xB0D7);
    const uint64_t p1_before = rig.session(1)->msgs_sent;
    const uint64_t p2_before = rig.session(2)->msgs_sent;
    const uint64_t p3_before = rig.session(3)->msgs_sent;

    rig.client.request_block_tracked(h);
    EXPECT_EQ(rig.client.pending_body_count(), 1u);
    // The initial getdata goes to the primary (peer 1), like request_block.
    EXPECT_EQ(rig.session(1)->msgs_sent, p1_before + 1);

    // One second of silence (< the 2 s initial stall window): no re-request.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.body_rerequests_total(), 0u)
        << "re-requested before the initial stall window elapsed";

    // Crossing the window: exactly one re-request, and NOT to the failing peer.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.body_rerequests_total(), 1u)
        << "an unanswered tracked body request must be re-requested at the"
           " dashd stall window (2 s, doubling)";
    EXPECT_EQ(rig.session(1)->msgs_sent, p1_before + 1)
        << "the re-request must rotate OFF the peer that did not answer";
    EXPECT_EQ((rig.session(2)->msgs_sent - p2_before)
                  + (rig.session(3)->msgs_sent - p3_before),
              1u)
        << "exactly one re-request, to one other peer";
    EXPECT_EQ(rig.client.pending_body_count(), 1u) << "still unanswered";
}

// ANTI-WEDGE (dashd mapBlocksInFlight + disconnect-on-stall). The height-967736
// wedge: connected=8/8 but none serves THAT body; master ERASED the slot after
// BODY_REREQUEST_MAX tries and the lane froze forever. dashd never abandons a
// needed block — the slot stays in flight, the per-slot stall window doubles,
// and a chronic staller is DISCONNECTED so the pool churns to a peer that has
// it. FAILS-ON-MASTER: the exhaust branch erased the slot and stopped retrying.
TEST(DashCoinP2PPool, stalled_body_is_never_abandoned_and_evicts_the_staller)
{
    PoolRig rig;
    rig.use_fake_clock();
    for (int i = 1; i <= 2; ++i) rig.handshake(i);

    rig.client.request_block_tracked(hash_n(0xDEAD));

    // Nothing ever answers, for a long time.
    rig.run_seconds(300);

    EXPECT_EQ(rig.client.pending_body_count(), 1u)
        << "ANTI-WEDGE: a stalled slot must NEVER be erased (master released it "
           "after 4 tries and the lane wedged forever)";
    EXPECT_GT(rig.client.body_rerequests_total(), 4u)
        << "re-requests must continue past the old BODY_REREQUEST_MAX cap";
    EXPECT_GE(rig.client.body_stall_evictions(), 1u)
        << "a chronic staller must be disconnected (dashd disconnect-on-stall)";
    EXPECT_EQ(rig.client.connected_peer_count(), 1u)
        << "the staller was churned out; the survivor keeps the slot live — the "
           "pool is not drained to zero over one missing block";
}

// THE REQUIRED RECOVERY KAT. A block whose FIRST-tried peer never serves the
// body is recovered from a SECOND peer, and the tracked cursor advances (the
// slot disarms) — no permanent wedge. Recovery is by ROTATION, before any
// staller eviction, so it is deterministic. FAILS-ON-MASTER: after the cap the
// slot was erased, so a later delivery had nothing to disarm and the reseed
// cursor never advanced.
TEST(DashCoinP2PPool, lost_body_first_peer_stalls_recovers_from_the_second_peer)
{
    PoolRig rig;
    rig.use_fake_clock();
    for (int i = 1; i <= 2; ++i) rig.handshake(i);   // peer 1 is primary

    dash::coin::BlockType blk;
    blk.m_version = 0x20000000;
    blk.m_timestamp = 1'700'000'000u;
    auto packed_hdr =
        pack(static_cast<const dash::coin::BlockHeaderType&>(blk));
    const uint256 bh = dash::crypto::hash_x11(packed_hdr.get_span());

    const uint64_t p1_before = rig.session(1)->msgs_sent;
    const uint64_t p2_before = rig.session(2)->msgs_sent;

    // Initial getdata -> primary (peer 1) = the "first-tried peer".
    rig.client.request_block_tracked(bh);
    ASSERT_EQ(rig.client.pending_body_count(), 1u);
    EXPECT_EQ(rig.session(1)->msgs_sent, p1_before + 1)
        << "the initial body getdata goes to the primary (peer 1)";

    // Peer 1 never serves it. When its stall window (2 s) elapses the watchdog
    // rotates OFF the staller and re-requests from the SECOND peer.
    rig.run_seconds(2);
    EXPECT_GE(rig.client.body_rerequests_total(), 1u);
    EXPECT_EQ(rig.session(2)->msgs_sent, p2_before + 1)
        << "the re-request must rotate to the second peer (peer 1 stalled)";
    EXPECT_EQ(rig.client.pending_body_count(), 1u)
        << "still outstanding — and NOT abandoned";
    ASSERT_EQ(rig.client.connected_peer_count(), 2u)
        << "recovery is by rotation; no eviction after a single stall";

    // Peer 2 serves the body: RECOVERY. The tracked slot disarms — in
    // production the reseed-tail cursor advances here — and no wedge remains.
    rig.deliver(2, p2p::message_block::make_raw(blk));
    EXPECT_EQ(rig.client.pending_body_count(), 0u)
        << "delivery from the rotated-to peer recovers the block; the cursor "
           "advances instead of wedging";

    // And nothing re-requests afterwards.
    const uint64_t total_after = rig.client.body_rerequests_total();
    rig.run_seconds(60);
    EXPECT_EQ(rig.client.body_rerequests_total(), total_after)
        << "a delivered body stops the watchdog";
}

TEST(DashCoinP2PPool, body_arrival_disarms_the_watchdog)
{
    PoolRig rig;
    rig.use_fake_clock();
    for (int i = 1; i <= 2; ++i) rig.handshake(i);

    // A real (if empty-bodied) block whose X11 header hash the handler will
    // compute — track exactly that hash.
    dash::coin::BlockType blk;
    blk.m_version = 0x20000000;
    blk.m_timestamp = 1'700'000'000u;
    auto packed_hdr =
        pack(static_cast<const dash::coin::BlockHeaderType&>(blk));
    const uint256 bh = dash::crypto::hash_x11(packed_hdr.get_span());

    rig.client.request_block_tracked(bh);
    EXPECT_EQ(rig.client.pending_body_count(), 1u);

    // The body arrives — from the OTHER peer, which must disarm it too.
    rig.deliver(2, p2p::message_block::make_raw(blk));
    EXPECT_EQ(rig.client.pending_body_count(), 0u)
        << "receipt from any peer must disarm the watchdog";

    // And no re-request ever fires afterwards.
    rig.run_seconds(60);
    EXPECT_EQ(rig.client.body_rerequests_total(), 0u);
}

// ══════════════════════════════════════════════════════════════════════════
// (H) TIP-BODY ROUTING — the body-fetch getdata goes to the peer that
// ANNOUNCED the block, which holds it by definition, NOT to an arbitrary
// primary. On a WARM node (pool of 8, announcer usually != primary) the block
// body announced by peer B was fetched from primary A; when A was behind or
// wedged it silently never delivered (no notfound), the watchdog rotated
// through a fixed subset that also lacked the block, and body-first serve-tip
// stayed at have_tip=0 forever — the embedded arm never served. The fresh
// soak's sequential catch-up (getheaders->getdata to the primary it was
// syncing from) never exercised the inv-driven announcer!=primary path, which
// is why only the warm hotel node surfaced it.
//
// FAILS-ON-MASTER: request_block writes unconditionally to m_primary, so the
// getdata lands on peer 1 (primary), never on the announcing peer 3.
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, tip_body_getdata_targets_the_announcing_peer_not_the_primary)
{
    PoolRig rig;
    for (int i = 1; i <= 3; ++i) rig.handshake(i);   // peer 1 handshakes first
    ASSERT_TRUE(rig.session(1) && rig.session(1)->primary)
        << "peer 1 must be the primary for this test to isolate the routing";

    const uint256 h = hash_n(0xB0D9);

    // Peer 3 — NOT the primary — announces the new block via inv.
    rig.deliver(3, PoolRig::block_inv(h));

    const uint64_t p1_before = rig.session(1)->msgs_sent;
    const uint64_t p3_before = rig.session(3)->msgs_sent;

    // The tip-follow body pull for that block (what the new_block subscriber
    // fires in production).
    rig.client.request_block_tracked(h);

    EXPECT_EQ(rig.session(3)->msgs_sent, p3_before + 1)
        << "the body getdata must go to the peer that ANNOUNCED the block "
           "(it holds it by definition)";
    EXPECT_EQ(rig.session(1)->msgs_sent, p1_before)
        << "the body getdata must NOT be routed to an arbitrary primary that, "
           "on a warm node, may be behind/wedged and never deliver";
}

// ══════════════════════════════════════════════════════════════════════════
// TASK #138 — a TRACKED request that DIED LOCALLY must (a) say so, and
// (b) still arm the watchdog, which puts the getdata on the wire the moment
// a route exists.
//
// This is the p2p half of the reseed-tail contract. The mn-ckpt lane's
// request ledger only advances on TRUE (ledger honesty, its own tests in
// test_dash_mn_checkpoint.cpp), and the tail of the reseed window is
// requested TRACKED so the wedge shape — no announcer for a historical tip
// body, primary churned out — is owned by service_pending_bodies() instead
// of dying silently. FAILS-ON-MASTER twice over: request_block_tracked
// returned void, and a dead initial send parked the slot for a full
// a full per-slot stall window before the first retry.
// ══════════════════════════════════════════════════════════════════════════

TEST(DashCoinP2PPool, tracked_request_that_died_locally_reports_it_and_recovers_via_watchdog)
{
    PoolRig rig;
    rig.use_fake_clock();

    // No handshaked peer at all: block_source() has neither announcer nor
    // primary — the initial getdata cannot reach anyone.
    const uint256 h = hash_n(0x138);
    EXPECT_FALSE(rig.client.request_block_tracked(h))
        << "#138: a tracked request with no route must SAY so — the caller's"
           " request ledger must not count a getdata no peer heard";
    EXPECT_EQ(rig.client.pending_body_count(), 1u)
        << "the watchdog slot must be armed anyway: the locally-dead request"
           " is exactly the one that needs the retry";
    EXPECT_EQ(rig.client.body_rerequests_total(), 0u);

    // The pool heals. The WATCHDOG — not the caller — must put the getdata on
    // the wire, and immediately: a send that never happened must not have
    // started the 10 s unanswered-clock.
    rig.handshake(1);
    const uint64_t before = rig.session(1)->msgs_sent;
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.body_rerequests_total(), 1u)
        << "the armed slot must be serviced on the first tick after a"
           " handshaked peer exists — not a full stall window later";
    EXPECT_EQ(rig.session(1)->msgs_sent, before + 1)
        << "exactly one getdata, to the peer that now exists";

    // A dead RE-ask (the lane's pump re-driving the same height while the
    // route is down again) must not push the watchdog's own timer out — the
    // slot keeps its cadence. Modelled by asking again for the same hash:
    // peer 1 answers routing now, so this send SUCCEEDS and refreshes.
    EXPECT_TRUE(rig.client.request_block_tracked(h))
        << "with a primary up the tracked re-ask reaches the wire";
    EXPECT_EQ(rig.client.pending_body_count(), 1u)
        << "re-asking an already-tracked hash must not grow the slots";
}

// ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
// DASHD-CUT — the anchor->tip mn-checkpoint BULK fold must fan its block-body
// getdata across the WHOLE handshaked pool and disconnect a stalling peer, the
// way dashd's FindNextBlocksToDownload / mapBlocksInFlight downloads a deep IBD
// window in parallel across peers and drops a staller (BLOCK_STALLING_TIMEOUT).
//
// The wedge these cover (measured on vm905, wf wt1q31gh2, belt+control both
// FROZE at cursor=2513065 applied=64): #1250 seeds the mn-ckpt anchor ~9.5k
// blocks BELOW the header tip, so the ENTIRE fold is the deep-historical
// (no-announcer) regime. On master every such body was routed to a single
// m_primary (block_source fallback) and the fixed PENDING_BODY_CAP=8 evicted
// all but the newest 8 tracked slots — so a slow / churning primary froze the
// fold at the first 64-block window and only that one peer was ever re-asked.
//
// FAILS-ON-MASTER: (1) all getdata funnel at the primary (peers_asked==1),
// (2) the window is evicted to 8 tracked slots (pending_body_count==8 not 64).
// ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

TEST(DashCoinP2PPool, bulk_fold_getdata_fans_out_across_the_whole_pool)
{
    PoolRig rig;
    rig.client.set_max_peers(8);
    for (int i = 1; i <= 8; ++i) rig.handshake(i, /*height=*/2513000u + i);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 8u);

    // Per-peer outbound baseline (the handshake itself sent our version).
    std::vector<uint64_t> base(9, 0);
    for (int i = 1; i <= 8; ++i) base[i] = rig.session(i)->msgs_sent;

    // A full fold window of BURIED blocks — none announced (no inv delivered),
    // exactly the deep anchor->tip regime.
    const uint32_t W = 64;
    for (uint32_t k = 0; k < W; ++k)
        ASSERT_TRUE(rig.client.request_block_tracked(hash_n(500000u + k)))
            << "with 8 handshaked peers every bulk body must reach the wire";

    int peers_asked = 0;
    uint64_t max_on_one = 0, total = 0;
    for (int i = 1; i <= 8; ++i) {
        const uint64_t got = rig.session(i)->msgs_sent - base[i];
        if (got > 0) ++peers_asked;
        if (got > max_on_one) max_on_one = got;
        total += got;
    }
    EXPECT_EQ(total, static_cast<uint64_t>(W))
        << "every window body must reach exactly one peer";
    EXPECT_EQ(peers_asked, 8)
        << "the fold window must fan out across the WHOLE handshaked pool "
           "(dashd FindNextBlocksToDownload), not funnel at m_primary";
    EXPECT_LE(max_on_one, static_cast<uint64_t>(W / 8 + 1))
        << "no peer may carry more than its round-robin share of the window";

    // ...and the full window stays TRACKED by the lost-body watchdog: the
    // in-flight bound is dashd's MAX_BLOCKS_IN_TRANSIT_PER_PEER(16) x 8 peers
    // = 128 >= 64, not the fixed cap of 8 that used to strand the bulk fold.
    EXPECT_EQ(rig.client.pending_body_count(), static_cast<std::size_t>(W))
        << "the whole fold window must stay in service_pending_bodies so a "
           "stalled body is re-requested from another peer, not lost";
}

TEST(DashCoinP2PPool, a_stalling_bulk_peer_is_disconnected_so_the_fold_advances)
{
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(8);
    for (int i = 1; i <= 8; ++i) rig.handshake(i, /*height=*/2513000u + i);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 8u);

    // A fold window that NOBODY ever delivers — every assigned peer stalls the
    // body it was handed. The watchdog must re-request each stalled body from a
    // DIFFERENT peer and, once a peer has chronically stalled, DISCONNECT it
    // (dashd disconnect-on-stall + reassign), so the fold keeps advancing
    // instead of freezing behind one silent peer at the first window.
    const uint32_t W = 64;
    for (uint32_t k = 0; k < W; ++k)
        ASSERT_TRUE(rig.client.request_block_tracked(hash_n(600000u + k)));
    ASSERT_EQ(rig.client.pending_body_count(), static_cast<std::size_t>(W))
        << "the full bulk window is tracked (this assert also fails on master, "
           "where the window is evicted to the fixed cap of 8)";

    const uint64_t rr0 = rig.client.body_rerequests_total();
    rig.run_seconds(600);   // ten minutes of stall service; no peer answers

    EXPECT_GT(rig.client.body_rerequests_total(), rr0)
        << "a stalled bulk window must be re-requested by the watchdog, not "
           "left on one peer forever";
    EXPECT_GE(rig.client.body_stall_evictions(), 1u)
        << "a chronically stalling peer must be disconnected so the pool churns "
           "to a peer that serves the body (dashd disconnect-on-stall)";
    EXPECT_GT(rig.client.handshaked_peer_count(), 0u)
        << "graceful degradation: a stall must never drain the pool to zero";
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// (H) CanServeBlocks CONVERGENCE — dashd net_processing service-flag gate +
//     per-peer download-failure demotion, ported onto the #1253 bulk-fold
//     round-robin. The mn-checkpoint anchor->tip fold must target ONLY peers
//     that advertise they can serve the block (NODE_NETWORK, not pruned-only)
//     and must CONVERGE away from peers that fail to serve (NOTFOUND / stall
//     eviction) so a deep IBD window re-homes onto archival deliverers.
//
//     RED on #1253 (blind round-robin, service-flag-/demotion-blind): a
//     limited-only peer is selected for a deep body it cannot serve, and a
//     peer that keeps answering NOTFOUND keeps being re-asked.
//     GREEN with the port: the pruned peer is never selected, the failing peer
//     is demoted out, and selection converges onto the full-block peers.
// ══════════════════════════════════════════════════════════════════════════

// NODE_NETWORK=0x1, NODE_NETWORK_LIMITED=0x400 (dashd protocol.h).
static constexpr uint64_t SVC_NETWORK        = 0x1;
static constexpr uint64_t SVC_LIMITED        = 0x400;
static constexpr uint64_t SVC_FULL           = 0x1 | 0x400;   // archival: both
static constexpr uint64_t SVC_LIMITED_ONLY   = 0x400;         // pruned

TEST(DashBulkCanServe, limited_only_peer_is_never_selected_for_a_deep_bulk_body)
{
    PoolRig rig;
    // Two archival (full-block) peers and one pruned (limited-only) peer.
    rig.handshake_services(1, SVC_FULL);
    rig.handshake_services(2, SVC_FULL);
    rig.handshake_services(3, SVC_LIMITED_ONLY);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 3u);

    // Announcer-less (deep-historical) body selection, many rounds so a blind
    // round-robin would land on peer 3 repeatedly.
    std::map<std::string, int> hits;
    for (uint32_t k = 0; k < 60; ++k)
        hits[rig.client.select_bulk_peer_key_for_test(hash_n(1000 + k))]++;

    // GREEN: the pruned peer is EXCLUDED entirely; both archival peers serve.
    EXPECT_EQ(hits[PoolRig::peer_key(3)], 0)
        << "a limited-only (pruned) peer must never be asked for ~9.5k-deep "
           "history — dashd IsLimitedPeer gate";
    EXPECT_GT(hits[PoolRig::peer_key(1)], 0);
    EXPECT_GT(hits[PoolRig::peer_key(2)], 0);
    EXPECT_EQ(hits[PoolRig::peer_key(1)] + hits[PoolRig::peer_key(2)], 60);
}

TEST(DashBulkCanServe, notfound_demotes_a_nonserver_and_selection_converges)
{
    PoolRig rig;
    rig.handshake_services(1, SVC_FULL);
    rig.handshake_services(2, SVC_FULL);
    rig.handshake_services(3, SVC_FULL);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 3u);

    // Peer 2 keeps answering NOTFOUND for deep bodies (advertises NODE_NETWORK
    // but does not actually serve buried history — the live-network symptom).
    for (int i = 0; i < 2; ++i)   // BULK_NONSERVER_STRIKE_MAX
        rig.deliver(2, PoolRig::block_notfound(hash_n(7000 + i)));

    EXPECT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(2)))
        << "a peer that repeatedly answers NOTFOUND must be demoted "
           "(dashd per-peer download-failure demotion)";

    // GREEN: selection now CONVERGES onto the two delivering peers; the demoted
    // non-server is never chosen again.
    std::map<std::string, int> hits;
    for (uint32_t k = 0; k < 60; ++k)
        hits[rig.client.select_bulk_peer_key_for_test(hash_n(8000 + k))]++;
    EXPECT_EQ(hits[PoolRig::peer_key(2)], 0);
    EXPECT_GT(hits[PoolRig::peer_key(1)], 0);
    EXPECT_GT(hits[PoolRig::peer_key(3)], 0);
}

TEST(DashBulkCanServe, delivering_a_body_forgives_a_demoted_peer)
{
    PoolRig rig;
    rig.handshake_services(1, SVC_FULL);
    rig.handshake_services(2, SVC_FULL);
    for (int i = 0; i < 2; ++i)
        rig.deliver(2, PoolRig::block_notfound(hash_n(100 + i)));
    ASSERT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(2)));

    // A single clean body delivery from peer 2 clears the strike — it
    // demonstrably serves blocks now (dashd forgives on a satisfied download).
    rig.client.forgive_bulk_nonserver_for_test(PoolRig::peer_key(2));
    EXPECT_FALSE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(2)));
    EXPECT_EQ(rig.client.bulk_nonserver_strikes_for_test(PoolRig::peer_key(2)), 0);
}

TEST(DashBulkCanServe, no_eligible_peer_falls_back_never_wedges_the_selection)
{
    PoolRig rig;
    // Pathological scarcity: EVERY reachable peer is pruned (limited-only).
    // The port must NOT wedge on an empty selection — it falls back to the
    // handshaked pool exactly as #1253 did (non-regression: never worse than
    // the blind rotation on a peer set with no archival deliverer).
    rig.handshake_services(1, SVC_LIMITED_ONLY);
    rig.handshake_services(2, SVC_LIMITED_ONLY);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 2u);

    std::set<std::string> chosen;
    for (uint32_t k = 0; k < 20; ++k)
    {
        std::string key = rig.client.select_bulk_peer_key_for_test(hash_n(200 + k));
        EXPECT_FALSE(key.empty()) << "selection must never return no peer";
        chosen.insert(key);
    }
    // Both limited peers still get used (fallback pass spreads across the pool).
    EXPECT_EQ(chosen.size(), 2u);
}


// ══════════════════════════════════════════════════════════════════════════
// (I) STATEFUL FOLD LEG — getmnlistd rotate-on-stall (dashd sync-peer parity)
//
//     The mn-checkpoint anchor->tip fold requests its per-height masternode
//     snapshot with getmnlistd(ZERO, hash_at(H)). On master (#1253/#1254) that
//     request is pinned to m_primary and, on no reply, tick_pending_fold()
//     RE-ASKS THE SAME PRIMARY. A live cold soak froze 26 min behind ONE slow
//     primary waiting for the deep base->anchor snapshot while 7 other archival
//     peers sat idle (LANE-WATCHDOG waiting_for=fold-mnlist-reply, warn 1..9).
//
//     dashd picks a sync peer for a mnlistdiff and ROTATES to another on stall.
//     send_getmnlistd_rotating() ports that: the fold's snapshot request (and
//     every re-ask) fans out across the eligible CanServeBlocks pool, preferring
//     a carrier OTHER than the last one, so a slow-but-alive primary can no
//     longer wedge the fold. Reply is matched by block hash and only one
//     getmnlistd is ever outstanding, so any carrier's reply satisfies the await.
//
//     RED (pinned path, still used by the LIVE tip follower): send_getmnlistd
//     lands every ask on the primary — asserted below as the contrast.
//     GREEN (fold path): send_getmnlistd_rotating spreads consecutive asks
//     across the archival peers and skips the pruned one.
// ══════════════════════════════════════════════════════════════════════════

TEST(DashStatefulFold, fold_getmnlistd_rotates_across_archival_peers_and_skips_pruned)
{
    PoolRig rig;
    rig.handshake_services(1, SVC_FULL);          // primary (first handshaked)
    rig.handshake_services(2, SVC_FULL);
    rig.handshake_services(3, SVC_FULL);
    rig.handshake_services(4, SVC_LIMITED_ONLY);  // pruned — cannot serve deep
    ASSERT_EQ(rig.client.handshaked_peer_count(), 4u);

    // CONTRAST (the RED behaviour the fix replaces): the PINNED leg — the one
    // the live tip follower still uses — puts every ask on the primary.
    const uint64_t p1_before_pinned = rig.session(1)->msgs_sent;
    for (int i = 0; i < 3; ++i)
        rig.client.send_getmnlistd(uint256::ZERO, hash_n(500 + i));
    EXPECT_EQ(rig.session(1)->msgs_sent, p1_before_pinned + 3u)
        << "the pinned getmnlistd leg must still land on the primary";

    // GREEN: the ROTATING fold leg fans out. Three consecutive asks over three
    // eligible archival peers hit three DISTINCT carriers (preferring a peer
    // other than the last), and the pruned peer is never asked.
    std::vector<uint64_t> before;
    for (int i = 1; i <= 4; ++i) before.push_back(rig.session(i)->msgs_sent);
    for (int i = 0; i < 3; ++i)
        rig.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(9000 + i));

    const uint64_t d1 = rig.session(1)->msgs_sent - before[0];
    const uint64_t d2 = rig.session(2)->msgs_sent - before[1];
    const uint64_t d3 = rig.session(3)->msgs_sent - before[2];
    const uint64_t d4 = rig.session(4)->msgs_sent - before[3];

    EXPECT_EQ(d1 + d2 + d3, 3u) << "all three asks must reach an archival peer";
    EXPECT_EQ(d4, 0u)
        << "a pruned (limited-only) peer must never carry the deep fold "
           "snapshot — it cannot serve ~9.5k-deep history";
    // True fan-out: no single archival peer absorbed all three (the 26-min
    // single-primary freeze the fix exists to prevent). With three eligible
    // peers and last-carrier avoidance, each gets exactly one.
    EXPECT_EQ(d1, 1u);
    EXPECT_EQ(d2, 1u);
    EXPECT_EQ(d3, 1u);
}

TEST(DashStatefulFold, fold_getmnlistd_reask_leaves_the_slow_primary_for_a_neighbour)
{
    PoolRig rig;
    rig.handshake_services(1, SVC_FULL);   // primary
    rig.handshake_services(2, SVC_FULL);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 2u);

    // First ask (fold snapshot) — allowed to pick the primary.
    const std::string first = rig.client.select_stateful_peer_key_for_test();
    EXPECT_FALSE(first.empty());
    // The RE-ask (tick_pending_fold on no reply) must move OFF that carrier so
    // a slow-but-alive primary cannot wedge the fold. On master the re-ask hit
    // the same primary every time; here it rotates to the neighbour.
    const std::string second = rig.client.select_stateful_peer_key_for_test();
    EXPECT_FALSE(second.empty());
    EXPECT_NE(second, first)
        << "the fold re-ask must rotate to a DIFFERENT eligible peer, not "
           "re-hammer the slow primary (dashd rotate-on-stall)";
}

TEST(DashStatefulFold, fold_getmnlistd_never_wedges_when_only_pruned_peers_exist)
{
    PoolRig rig;
    // Pathological: every reachable peer is pruned. The rotating leg must still
    // send (fallback pass), never drop the fold silently — non-regression vs
    // the pinned path, which would also have used the (pruned) primary.
    rig.handshake_services(1, SVC_LIMITED_ONLY);
    rig.handshake_services(2, SVC_LIMITED_ONLY);
    ASSERT_EQ(rig.client.handshaked_peer_count(), 2u);

    std::vector<uint64_t> before{rig.session(1)->msgs_sent,
                                 rig.session(2)->msgs_sent};
    for (int i = 0; i < 4; ++i)
        rig.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(300 + i));
    const uint64_t sent = (rig.session(1)->msgs_sent - before[0])
                        + (rig.session(2)->msgs_sent - before[1]);
    EXPECT_EQ(sent, 4u) << "the fold request must never be dropped even when no "
                           "archival peer exists (fallback to the handshaked pool)";
}

// (STATEFUL-STALL B) THE DIRECT EXPANSION SIGNAL (2026-08-19 ondemand freeze).
// (STATEFUL-STALL A) below demotes the carrier via TWO re-asks landing on the
// SAME peer — which reaches BULK_NONSERVER_STRIKE_MAX only when the pool has a
// SINGLE eligible carrier. On the live ondemand-mnlist freeze the re-asks
// ROTATE across many peers, so no single carrier ever accumulates two strikes
// and the block-body demotion tally stays EMPTY even after 22 minutes frozen.
// The mn-ckpt lane's wall-clock watchdog therefore signals the stall DIRECTLY
// (dashd TipMayBeStale -> SetTryNewOutboundPeer): note_stateful_stall(true)
// raises outbound_behind() with ZERO demoted peers, so the pool dials past its
// base target and rotates onto a peer that will answer. It self-clears the
// moment the leg is served. RED contrast: pre-port, outbound_behind() read
// ONLY the demotion tally, so a rotation-spread getmnlistd stall was invisible
// and the pool stayed frozen at 8.
TEST(DashStatefulFold, a_frozen_bridging_getmnlistd_expands_outbound_directly)
{
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(8);

    std::vector<NetService> plan;
    for (int i = 1; i <= 8; ++i) plan.push_back(PoolRig::peer_addr(i));
    rig.client.connect(plan);
    for (int i = 1; i <= 8; ++i) rig.handshake_services(i, SVC_FULL);
    ASSERT_EQ(rig.client.connected_peer_count(), 8u);

    // Fresh archival candidates the frozen set never reached.
    rig.client.update_dial_targets({PoolRig::peer_addr(9), PoolRig::peer_addr(10)});

    // Healthy AND with NO demoted peer: (STATEFUL-STALL A)'s demotion path
    // cannot be what expands here — the tally is empty.
    EXPECT_FALSE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 8u);

    // The lane's wall-clock watchdog found a bridging getmnlistd frozen and
    // raised the direct stall signal. Expansion engages with ZERO strikes.
    rig.client.note_stateful_stall(true);
    EXPECT_TRUE(rig.client.outbound_behind_for_test())
        << "a frozen ondemand-mnlist must expand the pool WITHOUT waiting for a "
           "carrier to accumulate block-body strikes";
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 10u)
        << "a frozen stateful leg must raise the dial target directly";

    // A pool tick dials the extra fresh archival outbound (dashd extra outbound).
    rig.run_seconds(1);
    EXPECT_GE(rig.client.dialing_count(), 1u)
        << "behind on a frozen stateful leg, the pool must acquire a fresh peer";

    // The (rotated) peer answers => the lane clears the signal => the pool
    // contracts back to its base target (dashd stops opening extras on recovery).
    rig.client.note_stateful_stall(false);
    EXPECT_FALSE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 8u)
        << "once the leg is served the expansion signal must drop, not latch";
}

// (STATEFUL-STALL A) THE EXPANSION HALF, DRIVEN BY A STATEFUL STALL.
// The live A/B (wf w8cr3yepg) proved the acquisition ROTATION fired but the
// effective_max_peers EXPANSION never engaged: the near-tip window was
// dominated by the STATEFUL getmnlistd leg, and "behind" was fed ONLY by the
// block-body demotion tally — blind to a getmnlistd stall. send_getmnlistd_
// reask() closes it: a timeout re-ask strikes the stalled carrier through the
// SAME tally, so outbound_behind() sees the demoted slot-holder, the dial
// target rises (GetExtraFullOutboundCount) and refill dials fresh archival
// peers. RED contrast: the pre-port rotating send never strikes, so the
// identical stall stays invisible and the pool stays frozen at its base size.
TEST(DashStatefulFold, stateful_getmnlistd_stall_expands_outbound_like_a_body_stall)
{
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(8);

    // Come up full: 8 handshaked peers, exactly ONE archival (peer 1); the
    // rest pruned, so the stateful leg can only ride peer 1 — the single-
    // carrier topology the live 26-min freeze happened on.
    std::vector<NetService> plan;
    for (int i = 1; i <= 8; ++i) plan.push_back(PoolRig::peer_addr(i));
    rig.client.connect(plan);
    rig.handshake_services(1, SVC_FULL);
    for (int i = 2; i <= 8; ++i) rig.handshake_services(i, SVC_LIMITED_ONLY);
    ASSERT_EQ(rig.client.connected_peer_count(), 8u);

    // Fresh archival candidates the frozen set never reached.
    rig.client.update_dial_targets({PoolRig::peer_addr(9), PoolRig::peer_addr(10),
                                    PoolRig::peer_addr(11), PoolRig::peer_addr(12)});

    // Healthy to begin with: not behind, base target.
    EXPECT_FALSE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 8u);

    // The fold asks peer 1 (records it as the stateful carrier), then two
    // timeout re-asks go unanswered — each strikes the carrier. Two strikes =
    // BULK_NONSERVER_STRIKE_MAX => demoted.
    rig.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(700));   // first ask
    ASSERT_EQ(rig.client.bulk_nonserver_strikes_for_test(PoolRig::peer_key(1)), 0);
    rig.client.send_getmnlistd_reask(uint256::ZERO, hash_n(700));      // re-ask #1
    rig.client.send_getmnlistd_reask(uint256::ZERO, hash_n(700));      // re-ask #2
    EXPECT_GE(rig.client.bulk_nonserver_strikes_for_test(PoolRig::peer_key(1)), 2);
    ASSERT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(1)))
        << "a chronically-unanswered stateful carrier must demote, exactly like "
           "a chronically-unanswered block-body peer";

    // EXPANSION now engages — the half that never fired in the live run.
    EXPECT_TRUE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 10u)
        << "a stateful-leg stall must raise the dial target, not only a body stall";

    // One pool tick dials the extra fresh archival outbound.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.dialing_count(), 2u)
        << "behind on the stateful leg, the pool must acquire MORE archival peers";
    for (const auto& k : rig.client.dialing_keys())
    {
        bool fresh = k == PoolRig::peer_key(9)  || k == PoolRig::peer_key(10) ||
                     k == PoolRig::peer_key(11) || k == PoolRig::peer_key(12);
        EXPECT_TRUE(fresh) << "extra outbound dialed a non-fresh target: " << k;
    }

    // RED CONTRAST: the pre-port rotating send (no strike) leaves the identical
    // stall invisible — no demotion, no expansion, the frozen pool of the run.
    PoolRig red;
    red.use_fake_clock();
    red.client.set_max_peers(8);
    red.client.connect(plan);
    red.handshake_services(1, SVC_FULL);
    for (int i = 2; i <= 8; ++i) red.handshake_services(i, SVC_LIMITED_ONLY);
    red.client.update_dial_targets({PoolRig::peer_addr(9), PoolRig::peer_addr(10),
                                    PoolRig::peer_addr(11), PoolRig::peer_addr(12)});
    red.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(700));
    red.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(700));
    red.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(700));
    red.run_seconds(5);
    EXPECT_EQ(red.client.bulk_nonserver_strikes_for_test(PoolRig::peer_key(1)), 0)
        << "the plain rotating send must never strike — that is why EXPANSION "
           "never engaged in the live A/B";
    EXPECT_FALSE(red.client.outbound_behind_for_test());
    EXPECT_EQ(red.client.effective_max_peers_for_test(), 8u);
    EXPECT_EQ(red.client.dialing_count(), 0u);
}

// (STATEFUL-STALL B) The re-ask STRIKES the stalled carrier; the plain first-
// ask rotating send never does. This is the reward-safe demote-on-stall the
// tip-follow SmlResyncWatchdog re-request now feeds so a slow/limited primary
// can neither wedge the SML nor stay invisible to the acquisition pump.
TEST(DashStatefulFold, getmnlistd_reask_strikes_the_stalled_carrier)
{
    PoolRig rig;
    rig.handshake_services(1, SVC_FULL);
    rig.handshake_services(2, SVC_FULL);
    rig.handshake_services(3, SVC_FULL);

    const std::string c1 = rig.client.select_stateful_peer_key_for_test();
    ASSERT_FALSE(c1.empty());
    ASSERT_EQ(rig.client.bulk_nonserver_strikes_for_test(c1), 0);

    // A timeout re-ask strikes THAT carrier (it did not answer in time).
    rig.client.send_getmnlistd_reask(uint256::ZERO, hash_n(11));
    EXPECT_EQ(rig.client.bulk_nonserver_strikes_for_test(c1), 1)
        << "the stalled stateful carrier must be struck (dashd disconnect-on-stall)";

    // RED: the first-ask rotating send is not a stall signal and never demotes.
    PoolRig red;
    red.handshake_services(1, SVC_FULL);
    red.handshake_services(2, SVC_FULL);
    const std::string rc = red.client.select_stateful_peer_key_for_test();
    ASSERT_FALSE(rc.empty());
    red.client.send_getmnlistd_rotating(uint256::ZERO, hash_n(12));
    EXPECT_EQ(red.client.bulk_nonserver_strikes_for_test(rc), 0)
        << "a first-ask rotating send must not demote its carrier";
}

// ══════════════════════════════════════════════════════════════════════════
// (H) OUTBOUND ACQUISITION — dashd never stays starved on a full-but-shallow
//     peer set. While it is behind it opens EXTRA full-relay outbound
//     (GetExtraFullOutboundCount) and it DISCONNECTS a peer that holds a
//     download slot without serving (BLOCK_STALLING_TIMEOUT) so the freed slot
//     refills with a FRESH addrman candidate (ThreadOpenConnections) —
//     rotating until every download slot holds an archival peer and the
//     block-download window fills. Our pool used to LATCH: a full pool
//     early-returned from refill_pool() and the bulk lane only DEMOTED a
//     demonstrated non-server (held it off fresh ranges) without ever freeing
//     its slot, so the large addrman bank behind the working set was never
//     re-drawn. These KATs are RED with the pump disabled (byte-identical
//     pre-port frozen full pool) and GREEN with it on (default).
// ══════════════════════════════════════════════════════════════════════════

// (H1) dashd GetExtraFullOutboundCount: a demonstrated deep-body non-server
// occupying a slot means we are BEHIND on archival coverage — the effective
// dial target expands and a full-at-base pool dials MORE fresh candidates to
// reach archival servers beyond the frozen set.
TEST(DashCoinP2PPool, behind_on_archival_coverage_expands_outbound_and_dials_more)
{
    PoolRig rig;
    rig.use_fake_clock();
    rig.client.set_max_peers(8);

    // Come up full: 8 handshaked peers dialed from the plan.
    std::vector<NetService> plan;
    for (int i = 1; i <= 8; ++i) plan.push_back(PoolRig::peer_addr(i));
    rig.client.connect(plan);
    for (int i = 1; i <= 8; ++i) rig.handshake(i);
    ASSERT_EQ(rig.client.connected_peer_count(), 8u);

    // Healthy full pool: base target, NOT behind, and (the pre-#1272 rule that
    // still holds) a full pool does not dial.
    EXPECT_FALSE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 8u);

    // Supply FRESH archival candidates the frozen set never reached.
    rig.client.update_dial_targets({PoolRig::peer_addr(9), PoolRig::peer_addr(10),
                                    PoolRig::peer_addr(11), PoolRig::peer_addr(12)});
    ASSERT_EQ(rig.client.dialing_count(), 0u) << "a healthy full pool must not dial";

    // Peer 1 demonstrates it does not serve deep bodies (two NOTFOUND/stall
    // strikes = BULK_NONSERVER_STRIKE_MAX) — it is now demoted, holding a slot.
    rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(1));
    rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(1));
    ASSERT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(1)));

    // GetExtraFullOutboundCount: behind ⇒ target raised by OUTBOUND_BEHIND_EXTRA.
    EXPECT_TRUE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 10u)
        << "the dial target must expand while behind so we reach MORE peers";

    // One pool tick runs the acquisition pump: 8 held < 10 effective ⇒ dial 2
    // FRESH candidates (no eviction needed — pure extra outbound).
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.dialing_count(), 2u)
        << "behind, a full-at-base pool must dial the extra outbound slots";
    for (const auto& k : rig.client.dialing_keys())
    {
        bool fresh = k == PoolRig::peer_key(9)  || k == PoolRig::peer_key(10) ||
                     k == PoolRig::peer_key(11) || k == PoolRig::peer_key(12);
        EXPECT_TRUE(fresh) << "extra outbound dialed a non-fresh target: " << k;
    }
    EXPECT_EQ(rig.client.outbound_rotations_for_test(), 0u)
        << "the extra-outbound path must NOT evict anyone (no peer disconnected)";

    // RED proof (pump disabled = byte-identical pre-port): frozen full pool.
    PoolRig red;
    red.use_fake_clock();
    red.client.set_outbound_rotate_enabled_for_test(false);
    red.client.set_max_peers(8);
    red.client.connect(plan);
    for (int i = 1; i <= 8; ++i) red.handshake(i);
    red.client.update_dial_targets({PoolRig::peer_addr(9), PoolRig::peer_addr(10),
                                    PoolRig::peer_addr(11), PoolRig::peer_addr(12)});
    red.client.note_bulk_nonserver_for_test(PoolRig::peer_key(1));
    red.client.note_bulk_nonserver_for_test(PoolRig::peer_key(1));
    red.run_seconds(5);
    EXPECT_EQ(red.client.effective_max_peers_for_test(), 8u);
    EXPECT_EQ(red.client.dialing_count(), 0u)
        << "PRE-PORT: a full pool of non-servers never dials more (the frozen pool)";
}

// (H2) dashd BLOCK_STALLING_TIMEOUT + ThreadOpenConnections: when even the
// EXPANDED pool is saturated and still holds demoted non-servers, the worst one
// (most strikes) is disconnected and the freed slot refills from the addrman-fed
// plan with a FRESH candidate. Non-demoted peers are never evicted.
TEST(DashCoinP2PPool, saturated_pool_rotates_worst_nonserver_out_for_a_fresh_dial)
{
    PoolRig rig;
    rig.use_fake_clock();
    // At the hard cap the effective target cannot expand (min(16+2,16)==16), so
    // a full+behind pool takes the EVICT-then-refill branch deterministically.
    rig.client.set_max_peers(16);

    std::vector<NetService> plan;
    for (int i = 1; i <= 16; ++i) plan.push_back(PoolRig::peer_addr(i));
    rig.client.connect(plan);
    for (int i = 1; i <= 16; ++i) rig.handshake(i);
    ASSERT_EQ(rig.client.connected_peer_count(), 16u);

    // A fresh archival candidate the frozen 16-set never reached.
    rig.client.update_dial_targets({PoolRig::peer_addr(17)});

    // Two demoted non-servers; peer 6 is the WORST (3 strikes vs peer 9's 2).
    for (int s = 0; s < 2; ++s) rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(9));
    for (int s = 0; s < 3; ++s) rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(6));
    ASSERT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(6)));
    ASSERT_TRUE(rig.client.bulk_demoted_for_test(PoolRig::peer_key(9)));
    EXPECT_TRUE(rig.client.outbound_behind_for_test());
    EXPECT_EQ(rig.client.effective_max_peers_for_test(), 16u)
        << "at the hard cap there is no room to expand — rotation is the lever";

    // One tick: evict the worst non-server (peer 6) and redial a fresh archival.
    rig.run_seconds(1);
    EXPECT_EQ(rig.client.outbound_rotations_for_test(), 1u);
    EXPECT_EQ(rig.client.connected_peer_count(), 15u)
        << "the demoted slot-holder must be freed";
    EXPECT_EQ(rig.client.peer_session(PoolRig::peer_key(6)), nullptr)
        << "peer 6 (most strikes) must be the one rotated out";
    EXPECT_NE(rig.client.peer_session(PoolRig::peer_key(9)), nullptr)
        << "the LESS-struck non-server must survive this rotation (one at a time)";
    // Non-demoted peers are untouched.
    EXPECT_NE(rig.client.peer_session(PoolRig::peer_key(1)), nullptr);
    // The freed slot refills with the FRESH candidate, not the just-evicted peer.
    ASSERT_EQ(rig.client.dialing_count(), 1u) << "the freed slot must redial";
    EXPECT_EQ(rig.client.dialing_keys().front(), PoolRig::peer_key(17))
        << "refill must draw a fresh candidate, never re-dial the rotated-out peer";

    // RED proof: pump off ⇒ the frozen full pool never rotates.
    PoolRig red;
    red.use_fake_clock();
    red.client.set_outbound_rotate_enabled_for_test(false);
    red.client.set_max_peers(16);
    red.client.connect(plan);
    for (int i = 1; i <= 16; ++i) red.handshake(i);
    red.client.update_dial_targets({PoolRig::peer_addr(17)});
    for (int s = 0; s < 3; ++s) red.client.note_bulk_nonserver_for_test(PoolRig::peer_key(6));
    red.run_seconds(10);
    EXPECT_EQ(red.client.outbound_rotations_for_test(), 0u);
    EXPECT_EQ(red.client.connected_peer_count(), 16u)
        << "PRE-PORT: a full pool of demoted non-servers stays frozen at 16/16";
    EXPECT_EQ(red.client.dialing_count(), 0u);
}

// (H3) GUARDRAILS — the pump is reward-safe connection management: it never
// churns a healthy pool, never disconnects when it cannot replace, and rate-
// limits rotations so a transiently-quiet peer is not thrashed.
TEST(DashCoinP2PPool, archival_rotation_is_bounded_and_never_churns_a_healthy_pool)
{
    // (a) A healthy full pool (no demoted peer) is byte-identical to before:
    // not behind, base target, zero dials, zero rotations across many ticks.
    {
        PoolRig rig;
        rig.use_fake_clock();
        rig.client.set_max_peers(16);
        std::vector<NetService> plan;
        for (int i = 1; i <= 16; ++i) plan.push_back(PoolRig::peer_addr(i));
        rig.client.connect(plan);
        for (int i = 1; i <= 16; ++i) rig.handshake(i);
        rig.client.update_dial_targets({PoolRig::peer_addr(17)});
        rig.run_seconds(30);
        EXPECT_FALSE(rig.client.outbound_behind_for_test());
        EXPECT_EQ(rig.client.effective_max_peers_for_test(), 16u);
        EXPECT_EQ(rig.client.outbound_rotations_for_test(), 0u);
        EXPECT_EQ(rig.client.connected_peer_count(), 16u);
        EXPECT_EQ(rig.client.dialing_count(), 0u)
            << "a healthy full pool must never dial or churn";
    }

    // (b) Full+behind but NO fresh candidate ⇒ HOLD: never disconnect a peer we
    // cannot replace (would only re-dial the same non-server).
    {
        PoolRig rig;
        rig.use_fake_clock();
        rig.client.set_max_peers(16);
        std::vector<NetService> plan;
        for (int i = 1; i <= 16; ++i) plan.push_back(PoolRig::peer_addr(i));
        rig.client.connect(plan);
        for (int i = 1; i <= 16; ++i) rig.handshake(i);
        // Plan holds ONLY addresses we already hold ⇒ no fresh candidate.
        for (int s = 0; s < 3; ++s) rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(6));
        rig.run_seconds(30);
        EXPECT_EQ(rig.client.outbound_rotations_for_test(), 0u)
            << "no fresh candidate ⇒ the pump must NOT disconnect (no thrash)";
        EXPECT_EQ(rig.client.connected_peer_count(), 16u);
    }

    // (c) Rate limit: two demoted non-servers, one fresh candidate. The pump
    // rotates ONE per OUTBOUND_ROTATE_INTERVAL_SEC, not both at once.
    {
        PoolRig rig;
        rig.use_fake_clock();
        rig.client.set_max_peers(16);
        std::vector<NetService> plan;
        for (int i = 1; i <= 16; ++i) plan.push_back(PoolRig::peer_addr(i));
        rig.client.connect(plan);
        for (int i = 1; i <= 16; ++i) rig.handshake(i);
        rig.client.update_dial_targets({PoolRig::peer_addr(17), PoolRig::peer_addr(18)});
        for (int s = 0; s < 3; ++s) rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(6));
        for (int s = 0; s < 3; ++s) rig.client.note_bulk_nonserver_for_test(PoolRig::peer_key(9));
        rig.run_seconds(1);
        EXPECT_EQ(rig.client.outbound_rotations_for_test(), 1u)
            << "only ONE rotation may fire per stall interval";
        // Within the interval, no further rotation even though a 2nd demoted
        // non-server and a 2nd fresh candidate both exist.
        rig.run_seconds(5);
        EXPECT_EQ(rig.client.outbound_rotations_for_test(), 1u)
            << "a second rotation must wait out OUTBOUND_ROTATE_INTERVAL_SEC";
    }
}
