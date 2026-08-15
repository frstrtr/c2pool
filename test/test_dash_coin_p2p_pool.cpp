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
                                            const std::string& subver = "/Dash Core:21.1.0/")
    {
        return p2p::message_version::make_raw(
            70230, /*services=*/1, /*timestamp=*/1234567890ull,
            addr_t{1, NetService{"127.0.0.1", 19999}},
            addr_t{1, NetService{"127.0.0.1", 19999}},
            /*nonce=*/0x1122334455667788ull, subver, height);
    }

    /// Full attach + version/verack for peer n.
    void handshake(int n, uint32_t height = 1000)
    {
        attach(n);
        deliver(n, version_msg(height));
        deliver(n, p2p::message_verack::make_raw());
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
    // getmnlistd / getqrinfo / getheaders / govsync are QUESTIONS whose answers
    // must be matched to the peer that was asked. Fanning them out would
    // multiply an entire mainnet governance stream by the pool size for no
    // extra evidence.
    PoolRig rig;
    rig.client.set_max_peers(3);
    rig.handshake(1);
    rig.handshake(2);
    rig.handshake(3);

    std::vector<uint64_t> before;
    for (int i = 1; i <= 3; ++i) before.push_back(rig.session(i)->msgs_sent);

    rig.client.send_getheaders(70230, {}, uint256::ZERO);
    rig.client.send_getmnlistd(uint256::ZERO, uint256::ONE);
    rig.client.send_govsync();
    rig.client.send_mempool();

    EXPECT_EQ(rig.session(1)->msgs_sent, before[0] + 4u)
        << "the request legs did not land on the primary";
    EXPECT_EQ(rig.session(2)->msgs_sent, before[1])
        << "a stateful request was fanned out to a witness peer";
    EXPECT_EQ(rig.session(3)->msgs_sent, before[2]);
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

} // namespace
