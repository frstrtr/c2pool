// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH embedded coin-network P2P client (E1) — connection-management KATs
///
/// Exercises src/impl/dash/coin/p2p_client.hpp — the OPT-IN outbound dial
/// layer (--coin-p2p-connect) the embedded arm uses to reach a live dashd:
///
///   (a) HandshakeTracker — the extracted version/verack state machine:
///       legal progression, verack-before-version tolerance, stray/duplicate
///       rejection, reset-on-disconnect.
///
///   (b) DialPlan — round-robin rotation over repeatable --coin-p2p-connect
///       targets: single-target plans stay put; multi-target plans rotate on
///       each reconnect attempt so a dead first target cannot wedge redial.
///
///   (b2) PeerLiveness — the extracted ping/pong keepalive policy that
///       replaced the old bare "no inbound message for 100s => drop" rule:
///       a quiet peer is PINGED, any inbound message (pong included) is
///       liveness evidence, our own outbound traffic is NOT, and a drop
///       happens only once a ping has gone unanswered past the (much longer)
///       peer timeout.
///
///   (c) CoinClient handshake drive — the REAL client class fed byte-exact
///       wire messages (message_version / message_verack round-tripped
///       through make_raw -> Handler::parse, the same path live socket bytes
///       take): peer metadata capture, handshake completion, the
///       on_handshake_complete seam, unknown-command tolerance (dashd CoinJoin/
///       governance traffic), and teardown-on-error resetting the session.
///
///   (d) Read-loop preservation — a subscriber that THROWS out of a message
///       handler must not escape handle(). core::Socket re-arms its read only
///       on the line AFTER message_processing(), so an escaping exception
///       leaves the socket open but permanently deaf, and every inv-PUSHED
///       message type (qfcommit, clsig, block invs) is lost for the rest of
///       that connection's life.
///
///   (e) Keepalive over the REAL client + a real io_context (scaled cadence):
///       a peer that answers pings and sends nothing else stays connected far
///       past the retired 100s deadline; a peer that answers nothing is still
///       dropped, but only after the peer timeout.
///
/// SCOPE NOTE (honest): the wire transport here is direct handle() delivery,
/// not a live TCP socket — the live-socket leg is the E1 smoke gate run
/// against a controlled testnet dashd (see PR). Everything above the socket
/// (parse -> dispatch -> state machine -> timers armed) is the real code.
///
/// This TU compiles into the EXISTING allowlisted test_dash_p2p_node target
/// (second source; no new test target, no workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_client.hpp>
#include <impl/dash/config.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes (wire-magic bytes)

#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using dash::coin::p2p::CoinClient;
using dash::coin::p2p::DialPlan;
using dash::coin::p2p::HandshakeTracker;
using dash::coin::p2p::PeerLiveness;

namespace {

using State = HandshakeTracker::State;

// ── (a) HandshakeTracker ──────────────────────────────────────────────────

TEST(DashCoinP2PClient, handshake_tracker_legal_progression)
{
    HandshakeTracker t;
    EXPECT_EQ(t.state(), State::Idle);
    EXPECT_FALSE(t.complete());

    t.on_connected();
    EXPECT_EQ(t.state(), State::Connected);

    EXPECT_TRUE(t.on_version());          // peer version -> we verack
    EXPECT_EQ(t.state(), State::VersionReceived);
    EXPECT_FALSE(t.complete());

    EXPECT_TRUE(t.on_verack());           // peer verack -> session up
    EXPECT_EQ(t.state(), State::Complete);
    EXPECT_TRUE(t.complete());
}

TEST(DashCoinP2PClient, handshake_tracker_verack_before_version_tolerated)
{
    HandshakeTracker t;
    t.on_connected();
    EXPECT_TRUE(t.on_verack());           // eager ack — session still completes
    EXPECT_TRUE(t.complete());
}

TEST(DashCoinP2PClient, handshake_tracker_strays_ignored_while_idle)
{
    HandshakeTracker t;
    EXPECT_FALSE(t.on_version());         // no session — must not fabricate one
    EXPECT_FALSE(t.on_verack());
    EXPECT_EQ(t.state(), State::Idle);
    EXPECT_FALSE(t.complete());
}

TEST(DashCoinP2PClient, handshake_tracker_duplicate_version_not_reacked)
{
    HandshakeTracker t;
    t.on_connected();
    EXPECT_TRUE(t.on_version());
    EXPECT_FALSE(t.on_version());         // duplicate — caller must not re-verack
    EXPECT_TRUE(t.on_verack());
    EXPECT_FALSE(t.on_version());         // post-complete version — ignored
    EXPECT_TRUE(t.complete());
}

TEST(DashCoinP2PClient, handshake_tracker_reset_returns_to_idle)
{
    HandshakeTracker t;
    t.on_connected();
    t.on_version();
    t.on_verack();
    ASSERT_TRUE(t.complete());

    t.reset();                            // disconnect / error path
    EXPECT_EQ(t.state(), State::Idle);
    EXPECT_FALSE(t.complete());
    EXPECT_FALSE(t.on_verack());          // and strays stay ignored again
}

// ── (b) DialPlan ──────────────────────────────────────────────────────────

TEST(DashCoinP2PClient, dial_plan_single_target_stays_put)
{
    DialPlan p;
    p.set_targets({NetService("192.168.86.52", 19999)});
    ASSERT_EQ(p.size(), 1u);
    EXPECT_EQ(p.current().to_string(), "192.168.86.52:19999");
    EXPECT_EQ(p.advance().to_string(), "192.168.86.52:19999");   // rotation is a no-op
    EXPECT_EQ(p.advance().to_string(), "192.168.86.52:19999");
}

TEST(DashCoinP2PClient, dial_plan_multi_target_rotates_round_robin)
{
    DialPlan p;
    p.set_targets({NetService("10.0.0.1", 9999),
                   NetService("10.0.0.2", 9999),
                   NetService("10.0.0.3", 9999)});
    EXPECT_EQ(p.current().to_string(), "10.0.0.1:9999");
    EXPECT_EQ(p.advance().to_string(), "10.0.0.2:9999");
    EXPECT_EQ(p.advance().to_string(), "10.0.0.3:9999");
    EXPECT_EQ(p.advance().to_string(), "10.0.0.1:9999");   // wraps
}

// ── (b2) PeerLiveness keepalive policy ────────────────────────────────────
//
// Production defaults, mirrored from Dash Core net.h, so the KATs below read
// against the same numbers the client ships with.
constexpr time_t kPingInterval = 120;    // Dash Core PING_INTERVAL
constexpr time_t kPeerTimeout  = 1200;   // Dash Core TIMEOUT_INTERVAL
constexpr time_t kRetiredIdleTimeout = 100;  // the rule this replaced (measured)
// The two protocol constants the retired rule sat below. See
// tolerates_silence_past_peer_ping_and_block_interval for why they matter.
constexpr time_t kPeerKeepalivePing = 120;   // the PEER's own ping cadence
constexpr time_t kDashBlockInterval = 150;   // DASH target block spacing

using Action = PeerLiveness::Action;

TEST(DashCoinP2PLiveness, quiet_peer_is_pinged_not_killed)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(/*now=*/0);

    // The window the retired rule used to kill in: still nothing to do.
    EXPECT_EQ(lv.tick(kRetiredIdleTimeout), Action::None);
    EXPECT_EQ(lv.tick(kRetiredIdleTimeout + 1), Action::None);

    // Once the peer has been quiet for the ping interval we PROBE it — we do
    // not conclude anything about it yet.
    EXPECT_EQ(lv.tick(kPingInterval), Action::SendPing);
}

// THE ESSENTIAL PROPERTY (the live defect, stated as a test):
// a peer that completes the handshake and then sends nothing but valid pongs
// must stay connected indefinitely — and in particular far past the retired
// 100s deadline that was killing every hotel peer at 101s.
TEST(DashCoinP2PLiveness, peer_answering_only_pongs_is_never_dropped)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(/*now=*/0);

    uint64_t nonce_seq = 0;
    // Two full peer-timeout windows of a peer that relays NOTHING and only
    // answers our pings. 40 minutes; the old rule killed at 100 seconds.
    for (int64_t now = 1; now <= 2 * kPeerTimeout; ++now)
    {
        const Action a = lv.tick(now);
        ASSERT_NE(a, Action::DropIdle) << "dropped a pong-answering peer at t=" << now;
        ASSERT_NE(a, Action::DropPingTimeout) << "ping-timeout on an answered ping at t=" << now;
        if (a == Action::SendPing)
        {
            const uint64_t nonce = ++nonce_seq;
            lv.note_ping_sent(nonce, now);
            EXPECT_TRUE(lv.ping_outstanding());
            EXPECT_TRUE(lv.on_pong(nonce, now));       // peer answers immediately
            EXPECT_FALSE(lv.ping_outstanding());
        }
    }

    EXPECT_GE(lv.pings_sent(), 2u * kPeerTimeout / kPingInterval - 1);
    EXPECT_EQ(lv.pongs_matched(), lv.pings_sent());
}

TEST(DashCoinP2PLiveness, any_inbound_message_is_liveness_not_just_pong)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(0);

    // An inv-push (a block/tx announcement) is just as good as a pong: it is
    // evidence the peer is alive and talking to us.
    lv.on_inbound(kPingInterval - 1);
    EXPECT_EQ(lv.tick(kPingInterval), Action::None);          // deadline moved
    EXPECT_EQ(lv.tick(kPingInterval * 2 - 2), Action::None);
    EXPECT_EQ(lv.tick(kPingInterval * 2 - 1), Action::SendPing);
}

TEST(DashCoinP2PLiveness, our_own_outbound_traffic_never_pushes_the_deadline)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(0);
    ASSERT_EQ(lv.last_recv(), 0);

    // Sending is not evidence about the PEER. If our own writes reset the
    // clock, a half-open socket looks healthy forever.
    lv.note_ping_sent(/*nonce=*/7, /*now=*/kPingInterval);
    EXPECT_EQ(lv.last_recv(), 0) << "an outbound ping moved the inbound deadline";

    // The inbound deadline therefore still matures measured from t=0, NOT
    // from the moment we sent the ping.
    EXPECT_EQ(lv.tick(kPeerTimeout - 1), Action::None);
    EXPECT_EQ(lv.tick(kPeerTimeout), Action::DropIdle);
}

TEST(DashCoinP2PLiveness, unanswered_ping_drops_only_after_the_peer_timeout)
{
    // Isolate the ping-timeout arm: the peer keeps RELAYING (so the
    // "nothing received at all" arm never matures) but never answers a ping.
    // That is the half-open case only ping/pong can catch.
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(0);

    ASSERT_EQ(lv.tick(kPingInterval), Action::SendPing);
    lv.note_ping_sent(/*nonce=*/42, /*now=*/kPingInterval);

    // A genuinely unresponsive peer IS still dropped — that half of the
    // contract must not regress. It just takes the Core-semantics deadline.
    for (int64_t now = kPingInterval + 1; now < kPingInterval + kPeerTimeout; ++now)
    {
        lv.on_inbound(now);                       // relay traffic keeps flowing
        ASSERT_EQ(lv.tick(now), Action::None) << "dropped early at t=" << now;
    }
    lv.on_inbound(kPingInterval + kPeerTimeout);
    EXPECT_EQ(lv.tick(kPingInterval + kPeerTimeout), Action::DropPingTimeout);
}

// ORDERING RELATION, not a magic number. The three constants that decide
// whether a threshold is meaningful at all:
//
//     our old drop deadline   100 s   (measured, +/-0.1 ms over 6 cycles)
//   < Dash Core ping cadence  120 s   (the peer's own keepalive)
//   < DASH block interval     150 s   (earliest possible block inv)
//
// The old 100 s deadline sat BELOW both, so the peer was never going to speak
// inside our window and every connection died at the identical instant by
// construction. Any replacement must clear both — a 110 s timeout would still
// be broken, and a test hard-coded to "survives 101 s" would have passed it.
TEST(DashCoinP2PLiveness, tolerates_silence_past_peer_ping_and_block_interval)
{
    ASSERT_LT(kRetiredIdleTimeout, kPeerKeepalivePing) << "premise of the defect";
    ASSERT_LT(kPeerKeepalivePing, kDashBlockInterval);

    PeerLiveness lv;   // SHIPPED defaults — no test scaling here on purpose
    lv.start(0);

    // Structural: the drop deadline must clear both protocol constants, so a
    // peer that says nothing until its own keepalive (or until the next block)
    // is never concluded dead first.
    EXPECT_GT(lv.peer_timeout_sec(), kPeerKeepalivePing);
    EXPECT_GT(lv.peer_timeout_sec(), kDashBlockInterval);

    // Behavioural: a peer that handshakes and then stays silent for longer
    // than BOTH must still be connected — and must have been probed by us.
    for (int64_t now = 1; now <= kDashBlockInterval * 2; ++now)
    {
        const Action a = lv.tick(now);
        ASSERT_NE(a, Action::DropIdle) << "dropped at t=" << now
            << "s, before the peer's own " << kPeerKeepalivePing << "s ping";
        ASSERT_NE(a, Action::DropPingTimeout) << "ping-timeout at t=" << now;
        if (a == Action::SendPing)
            lv.note_ping_sent(/*nonce=*/1, now);   // sent; peer has not answered yet
    }
    EXPECT_GE(lv.pings_sent(), 1u)
        << "we must generate our own liveness evidence, not bet on peer chattiness";
}

TEST(DashCoinP2PLiveness, total_silence_drops_at_the_peer_timeout)
{
    // Degenerate config (ping interval >= peer timeout, i.e. we never get to
    // probe): the "nothing at all received" arm must still fire.
    PeerLiveness lv;
    lv.configure(/*ping_interval=*/kPeerTimeout * 2, kPeerTimeout);
    lv.start(0);

    EXPECT_EQ(lv.tick(kPeerTimeout - 1), Action::None);
    EXPECT_EQ(lv.tick(kPeerTimeout), Action::DropIdle);
}

TEST(DashCoinP2PLiveness, stale_or_unsolicited_pong_nonce_answers_nothing)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(0);

    // Unsolicited pong with no ping outstanding: liveness, but answers nothing.
    EXPECT_FALSE(lv.on_pong(/*nonce=*/999, /*now=*/10));
    EXPECT_EQ(lv.last_recv(), 10);

    ASSERT_EQ(lv.tick(10 + kPingInterval), Action::SendPing);
    lv.note_ping_sent(/*nonce=*/1234, 10 + kPingInterval);

    // Replayed old nonce must NOT close the outstanding ping — otherwise a
    // peer could hold a dead link open with a recording.
    EXPECT_FALSE(lv.on_pong(/*nonce=*/999, 10 + kPingInterval + 1));
    EXPECT_TRUE(lv.ping_outstanding());
    EXPECT_EQ(lv.pongs_matched(), 0u);

    EXPECT_TRUE(lv.on_pong(/*nonce=*/1234, 10 + kPingInterval + 2));
    EXPECT_FALSE(lv.ping_outstanding());
    EXPECT_EQ(lv.pongs_matched(), 1u);
}

TEST(DashCoinP2PLiveness, session_restart_clears_the_previous_peer_state)
{
    PeerLiveness lv;
    lv.configure(kPingInterval, kPeerTimeout);
    lv.start(0);
    ASSERT_EQ(lv.tick(kPingInterval), Action::SendPing);
    lv.note_ping_sent(/*nonce=*/5, kPingInterval);
    ASSERT_TRUE(lv.ping_outstanding());

    // Reconnect: the new peer must not inherit the old one's outstanding ping
    // (which would drop it the moment the previous deadline matured).
    lv.start(/*now=*/5000);
    EXPECT_FALSE(lv.ping_outstanding());
    EXPECT_EQ(lv.pings_sent(), 0u);
    EXPECT_EQ(lv.tick(5000 + kRetiredIdleTimeout), Action::None);
}

TEST(DashCoinP2PLiveness, shipped_defaults_are_the_dash_core_values)
{
    PeerLiveness lv;   // default-constructed == the shipped policy
    EXPECT_EQ(lv.ping_interval_sec(), kPingInterval);
    EXPECT_EQ(lv.peer_timeout_sec(), kPeerTimeout);
    EXPECT_GT(lv.peer_timeout_sec(), kRetiredIdleTimeout)
        << "the drop deadline must be far longer than the rule it replaced";
    // 100 < 120 < 150 < ping_interval? no — the ping cadence MAY equal the
    // peer's, but the DROP deadline must clear both by a wide margin.
    EXPECT_GT(lv.peer_timeout_sec(), kDashBlockInterval * 4);
}

// ── (c) CoinClient handshake drive ────────────────────────────────────────

struct ClientRig
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::Config config;
    CoinClient<dash::Config> client;

    ClientRig()
        : config("dash-coin-p2p-client-kat")
        , client(&ioc, &coin_state, &config, "COIN-P2P-KAT")
    {
        config.coin()->m_p2p.prefix = ParseHexBytes("cee2caff");   // testnet magic
    }

    // ── simulated clock ──────────────────────────────────────────────────
    // Every deadline in the client is a comparison against its now_sec(). Wire
    // that to a counter we control so the liveness policy runs in SIMULATED
    // seconds: no wall clock, no io_context, no race with a slow runner. See
    // CoinClient::set_now_fn for why elapsed-milliseconds assertions were
    // removed from this file.
    int64_t fake_now{1'000'000};
    void use_fake_clock() { client.set_now_fn([this]{ return fake_now; }); }

    /// Advance simulated time one second at a time, running the pool tick on
    /// each one — exactly the cadence the real repeating timer produces. A
    /// single jump would NOT be equivalent for the ping cadence, so it is not
    /// used. `on_second` runs after each tick and stands in for the peer.
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

    // Stand the session up the way Factory does on a live connect. A null
    // socket is legal for the Connection leaf (write() no-ops, get_addr()
    // yields the empty NetService) — everything ABOVE the socket is real.
    void wire_connected() { client.connected(nullptr); }

    void deliver(std::unique_ptr<RawMessage> rmsg)
    {
        client.handle(std::move(rmsg), NetService{});
    }

    std::unique_ptr<RawMessage> peer_version(uint32_t proto, uint64_t services,
                                             uint32_t height, const std::string& subver)
    {
        return dash::coin::p2p::message_version::make_raw(
            proto, services, /*timestamp=*/1234567890ull,
            addr_t{services, NetService{"127.0.0.1", 19999}},
            addr_t{services, NetService{"127.0.0.1", 19999}},
            /*nonce=*/0x1122334455667788ull, subver, height);
    }
};

// ── (b') Cold-start empty dial plan (daemonless --coin-p2p-discover) ────────
//
// Regression pin for the discover cold-start wedge: connect() with an EMPTY
// target list (fresh peer-db + DNS unavailable) must NOT early-return into a
// dead state — it arms the reconnect loop and idles, leaving the client
// safely disconnected (no throw, no session) until seed-discovered peers land
// via update_dial_targets(). An empty update is a safe no-op.
TEST(DashCoinP2PClient, empty_connect_arms_without_wedging)
{
    ClientRig rig;
    EXPECT_NO_THROW(rig.client.connect({}));      // empty initial dial plan
    EXPECT_FALSE(rig.client.is_connected());
    EXPECT_FALSE(rig.client.is_handshake_complete());
    EXPECT_NO_THROW(rig.client.update_dial_targets({}));   // empty refresh: no-op
    EXPECT_FALSE(rig.client.is_connected());
}

TEST(DashCoinP2PClient, client_completes_handshake_and_captures_peer_metadata)
{
    ClientRig rig;
    EXPECT_FALSE(rig.client.is_connected());
    EXPECT_FALSE(rig.client.is_handshake_complete());

    bool handshake_fired = false;
    rig.client.set_on_handshake_complete([&]{ handshake_fired = true; });

    uint32_t seen_height = 0;
    rig.client.set_on_peer_height([&](uint32_t h){ seen_height = h; });

    rig.wire_connected();
    EXPECT_TRUE(rig.client.is_connected());
    EXPECT_FALSE(rig.client.is_handshake_complete());

    rig.deliver(rig.peer_version(70230, /*services=*/5, /*height=*/1497944,
                                 "/Dash Core:21.1.0/"));
    EXPECT_FALSE(rig.client.is_handshake_complete());   // verack still pending
    EXPECT_EQ(rig.client.peer_version(), 70230u);
    EXPECT_EQ(rig.client.peer_services(), 5u);
    EXPECT_EQ(rig.client.peer_start_height(), 1497944u);
    EXPECT_EQ(rig.client.peer_subver(), "/Dash Core:21.1.0/");
    EXPECT_EQ(seen_height, 1497944u);

    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    EXPECT_TRUE(rig.client.is_handshake_complete());
    EXPECT_TRUE(handshake_fired);
}

TEST(DashCoinP2PClient, client_ignores_stray_verack_without_session)
{
    ClientRig rig;
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    EXPECT_FALSE(rig.client.is_handshake_complete());
    EXPECT_FALSE(rig.client.is_connected());
}

TEST(DashCoinP2PClient, client_tolerates_unknown_commands)
{
    // dashd pushes CoinJoin/quorum commands outside our Handler set (senddsq,
    // qsendrecsigs, ...); the client must ignore them without tearing the
    // session down. ("spork" no longer qualifies: it is REGISTERED and handled
    // — see test_dash_spork.cpp.)
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    auto senddsq = std::make_unique<RawMessage>("senddsq", PackStream{});
    rig.deliver(std::move(senddsq));                     // must not throw
    EXPECT_TRUE(rig.client.is_handshake_complete());     // session survives
    EXPECT_TRUE(rig.client.is_connected());
}

TEST(DashCoinP2PClient, client_error_tears_session_down_for_redial)
{
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    rig.client.error(std::string("KAT-induced disconnect"), NetService{});
    EXPECT_FALSE(rig.client.is_connected());             // peer dropped
    EXPECT_FALSE(rig.client.is_handshake_complete());    // session reset

    // A fresh connect must renegotiate from scratch (no stale completion).
    rig.wire_connected();
    EXPECT_TRUE(rig.client.is_connected());
    EXPECT_FALSE(rig.client.is_handshake_complete());
}

// ── (d) Read-loop preservation ────────────────────────────────────────────
//
// core::Socket::read_payload is literally:
//
//     message_processing(packet);   // -> CoinClient::handle(rmsg, addr)
//     read();                       // re-arm the read loop
//
// so an exception escaping handle() unwinds PAST read(). The socket stays
// open, error() never fires, the client keeps believing it has a healthy
// peer — and not one further byte is ever processed from that peer. In
// production main_dash's #755 io-handler guard catches the throw at
// ioc.run() and resumes the loop, which is precisely why the damage is
// silent: nothing is logged about the connection, and the only visible
// consequence arrives when this client's own liveness deadline matures on a
// peer it silenced itself.
//
// Message handlers fan out into subscriber code we do not own
// (new_block / new_mnlistdiff / new_qfcommit / new_chainlock ...), so a
// throwing subscriber must cost that message and nothing more.
TEST(DashCoinP2PClient, throwing_subscriber_does_not_escape_handle)
{
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    int fired = 0;
    rig.coin_state.new_block.subscribe([&](uint256){
        ++fired;
        throw std::runtime_error("KAT: subscriber blew up");
    });

    auto block_inv = dash::coin::p2p::message_inv::make_raw(
        std::vector<dash::coin::p2p::inventory_type>{
            dash::coin::p2p::inventory_type(
                dash::coin::p2p::inventory_type::block, uint256::ONE)});

    // The whole point: this must NOT throw out of handle().
    EXPECT_NO_THROW(rig.deliver(std::move(block_inv)));
    EXPECT_EQ(fired, 1);

    // ... and the session must be intact so the read loop keeps going.
    EXPECT_TRUE(rig.client.is_connected());
    EXPECT_TRUE(rig.client.is_handshake_complete());
}

TEST(DashCoinP2PClient, message_after_a_throwing_handler_is_still_processed)
{
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    rig.coin_state.new_block.subscribe([](uint256){
        throw std::runtime_error("KAT: subscriber blew up");
    });
    auto bad = dash::coin::p2p::message_inv::make_raw(
        std::vector<dash::coin::p2p::inventory_type>{
            dash::coin::p2p::inventory_type(
                dash::coin::p2p::inventory_type::block, uint256::ONE)});
    EXPECT_NO_THROW(rig.deliver(std::move(bad)));

    // The NEXT inbound message — in production this is exactly the qfcommit /
    // clsig inv-push we exist to witness — must still be dispatched. A
    // post-handshake version updates the peer metadata unconditionally
    // (the handshake tracker only gates the verack reply), so it is a
    // side-effect we can observe without a socket.
    ASSERT_EQ(rig.client.peer_subver(), "/Dash Core:21.1.0/");
    rig.deliver(rig.peer_version(70230, 1, 101, "/Dash Core:22.0.0/"));
    EXPECT_EQ(rig.client.peer_subver(), "/Dash Core:22.0.0/")
        << "inbound dispatch stopped after a handler threw";
    EXPECT_EQ(rig.client.peer_start_height(), 101u);
    EXPECT_TRUE(rig.client.is_connected());
}

// ── (e) Keepalive over the REAL client, driven by a SIMULATED clock ───────
//
// These drive the real plumbing — pool tick -> PeerLiveness::tick -> send_ping
// / timeout -> error() -> session teardown — through the client's injected time
// source rather than the wall clock.
//
// They previously ran against real time and asserted on elapsed milliseconds.
// That is a race the machine eventually wins: under AddressSanitizer the binary
// runs 2-10x slower and `EXPECT_GE(elapsed, 3000)` failed at 2999 on a loaded
// runner. Widening the tolerance would have moved the flake rather than removed
// it, and would have left a test that cannot distinguish "the deadline logic
// regressed" from "the runner was busy". Driving simulated seconds instead makes
// the assertions EXACT — a ping at T+120, a drop at T+1200 — and lets them be
// made against the SHIPPED constants (PING_INTERVAL_SEC / PEER_TIMEOUT_SEC)
// rather than scaled stand-ins, because simulated hours cost nothing.
TEST(DashCoinP2PClient, quiet_peer_that_answers_pings_survives_indefinitely)
{
    ClientRig rig;
    rig.use_fake_clock();                 // SHIPPED thresholds: 120s / 1200s
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());
    ASSERT_EQ(rig.client.ping_interval_sec(), 120);
    ASSERT_EQ(rig.client.peer_timeout_sec(), 1200);

    // The peer answers every ping with a matching pong through the real inbound
    // path, and sends NOTHING else — the "healthy but quiet at the chain tip"
    // case the retired 100s idle rule used to kill.
    const int64_t SIM_SECONDS = 7200;     // two simulated hours
    rig.run_seconds(SIM_SECONDS, [&](int64_t){
        if (rig.client.is_connected() && rig.client.ping_outstanding())
            rig.deliver(dash::coin::p2p::message_pong::make_raw(
                rig.client.last_ping_nonce()));
    });

    EXPECT_TRUE(rig.client.is_connected())
        << "a peer that answered every ping was dropped";
    EXPECT_TRUE(rig.client.is_handshake_complete());
    // EXACT, not a range: one ping per PING_INTERVAL_SEC, each answered
    // immediately, for the whole window. 7200/120 = 60.
    EXPECT_EQ(rig.client.pings_sent(), 60u);
    EXPECT_EQ(rig.client.pongs_matched(), 60u);
    EXPECT_FALSE(rig.client.ping_outstanding());
}

TEST(DashCoinP2PClient, silent_peer_is_dropped_at_exactly_the_peer_timeout)
{
    // Negative control: lifting the deadline must NOT make us keep dead peers.
    ClientRig rig;
    rig.use_fake_clock();                 // SHIPPED thresholds: 120s / 1200s
    bool dropped = false;
    rig.client.set_on_peer_disconnected([&](const NetService&){ dropped = true; });
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());
    const int64_t t_handshake = rig.fake_now;

    // The peer says nothing, ever. It is PROBED first (we never conclude a peer
    // is dead without asking), then dropped when the silence — not the ping —
    // reaches PEER_TIMEOUT_SEC.
    rig.run_seconds(rig.client.ping_interval_sec());
    EXPECT_EQ(rig.client.pings_sent(), 1u) << "we must probe before concluding";
    EXPECT_TRUE(rig.client.ping_outstanding());
    EXPECT_TRUE(rig.client.is_connected());

    // One second BEFORE the deadline: still held. This is the half of the
    // assertion that a widened tolerance would have destroyed.
    rig.run_seconds(rig.client.peer_timeout_sec() - rig.client.ping_interval_sec() - 1);
    ASSERT_EQ(rig.fake_now - t_handshake, rig.client.peer_timeout_sec() - 1);
    EXPECT_TRUE(rig.client.is_connected())
        << "dropped BEFORE the peer timeout matured";
    EXPECT_FALSE(dropped);

    // The very next second: gone.
    rig.run_seconds(1);
    ASSERT_EQ(rig.fake_now - t_handshake, rig.client.peer_timeout_sec());
    EXPECT_FALSE(rig.client.is_connected()) << "a fully silent peer was never dropped";
    EXPECT_TRUE(dropped);
    EXPECT_EQ(rig.client.pongs_matched(), 0u);
    EXPECT_EQ(rig.client.pings_sent(), 1u);
}

// ── (f) The ONE test that must observe REAL time ──────────────────────────
//
// Everything above is clock-driven and therefore proves the POLICY. None of it
// would notice if ensure_pool_timer() were deleted and the tick never armed at
// all — the tests call tick_for_test() themselves. This is the single
// narrowly-scoped case that closes that gap: a real io_context, a real
// core::Timer, and the question "did the client arm anything?".
//
// It is deliberately a LIVENESS assertion, not a timing one: it waits for the
// first ping to appear and stops the moment it does. A slower machine makes it
// take longer, never makes it fail — the only way it fails is if the tick is
// genuinely never armed. That is why the watchdog is 20s against a 1s cadence
// rather than a tight bound.
TEST(DashCoinP2PClient, pool_tick_timer_is_actually_armed_on_the_io_context)
{
    ClientRig rig;
    rig.client.set_keepalive_for_test(/*ping*/1, /*peer_timeout*/600, /*tick*/1);
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    // Stop as soon as the client pings of its own accord.
    boost::asio::steady_timer poll(rig.ioc);
    std::function<void()> watch = [&]{
        poll.expires_after(std::chrono::milliseconds(50));
        poll.async_wait([&](const boost::system::error_code& ec){
            if (ec) return;
            if (rig.client.pings_sent() > 0) { rig.ioc.stop(); return; }
            watch();
        });
    };
    watch();

    boost::asio::steady_timer watchdog(rig.ioc);
    watchdog.expires_after(std::chrono::seconds(20));   // 20x the cadence
    watchdog.async_wait([&](const boost::system::error_code&){ rig.ioc.stop(); });
    rig.ioc.run();

    EXPECT_GE(rig.client.pings_sent(), 1u)
        << "the pool tick timer was never armed on the io_context — every "
           "clock-driven test above would still pass with the tick deleted";
}

// ── (e) Mempool-ingest completeness — DSTX visibility + body-busy retry ─────
//
// Two mechanisms the daemonless mempool-ingest lane depends on, pinned here:
//
//   1. tx_ingest_status() surfaces the DSTX counters. dashd announces CoinJoin
//      broadcast txs ONLY via inv(MSG_DSTX=16), never MSG_TX, so the whole
//      DSTX class — 17.2 % of mined block txs, ~half the mempool BYTES — is
//      invisible in [MEMPOOL-INGEST] logs unless the counters the client
//      already keeps are printed. An armed DSTX lane is unmeasurable without
//      them.
//
//   2. A tx/dstx inv admitted by InvDedup but skipped because a tip body was
//      in flight is PARKED and re-issued when the body clears — not stranded
//      behind the 600 s InvDedup TTL (which suppresses every re-announcement
//      from every peer, losing the tx until the entry ages out, by which time
//      it is usually already mined).

TEST(DashCoinP2PIngest, dstx_counters_are_visible_in_tx_ingest_status)
{
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, /*services=*/5, /*height=*/2526000,
                                 "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    // Arm the DSTX lane (the --embedded-ingest-dstx runtime opt-in).
    rig.client.set_dstx_pull(true);

    // dashd announces a mixing tx as inv(MSG_DSTX=16) — the inv hash is the
    // plain txid. With no tip body in flight it earns a getdata immediately
    // and the counters the client keeps must move.
    auto dstx_inv = dash::coin::p2p::message_inv::make_raw(
        std::vector<dash::coin::p2p::inventory_type>{
            dash::coin::p2p::inventory_type(
                dash::coin::p2p::inventory_type::dstx, uint256::ONE)});
    rig.deliver(std::move(dstx_inv));

    const std::string status = rig.client.tx_ingest_status();
    // RED on the pre-change code: tx_ingest_status() never prints a dstx
    // field, so the armed lane cannot be measured. GREEN with the instrument.
    EXPECT_NE(status.find("dstx_inv=1"), std::string::npos) << status;
    EXPECT_NE(status.find("dstx_getdata=1"), std::string::npos) << status;
    EXPECT_NE(status.find("dstx_received=0"), std::string::npos) << status;
}

TEST(DashCoinP2PIngest, tx_inv_skipped_while_body_in_flight_is_retried_not_stranded)
{
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, /*services=*/5, /*height=*/2526000,
                                 "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());
    ASSERT_GE(rig.client.handshaked_peer_count(), 1u);

    rig.client.set_tx_pull(true);

    // A tracked tip body is in flight — strict priority means no tx getdata
    // may go out while it is outstanding.
    rig.client.request_block_tracked(uint256::ONE);
    ASSERT_GE(rig.client.pending_body_count(), 1u);

    // A tx inv arrives while the body is outstanding: admitted by InvDedup,
    // then skipped by the tip-body-priority rule.
    const uint256 txid = uint256(static_cast<uint64_t>(0xAAull));
    auto tx_inv = dash::coin::p2p::message_inv::make_raw(
        std::vector<dash::coin::p2p::inventory_type>{
            dash::coin::p2p::inventory_type(
                dash::coin::p2p::inventory_type::tx, txid)});
    rig.deliver(std::move(tx_inv));

    // Skipped: nothing in flight yet, and the announcement was parked.
    EXPECT_EQ(rig.client.tx_pull_inflight(), 0u);
    EXPECT_EQ(rig.client.tx_pull_sent_count(), 0u);
    EXPECT_EQ(rig.client.tx_pull_skipped_busy_count(), 1u);
    EXPECT_EQ(rig.client.tx_retry_busy_count(), 1u);

    // The tip body lands — pending bodies clear. The next pool tick must
    // re-issue the parked getdata.
    rig.client.clear_pending_bodies_for_test();
    rig.client.tick_for_test();

    // RED on the pre-change code: the skipped inv is never re-pulled (stranded
    // behind the 600 s InvDedup TTL), so tx_pull_inflight() stays 0 forever.
    // GREEN with the retry queue: exactly one getdata is now in flight.
    EXPECT_EQ(rig.client.tx_pull_inflight(), 1u);
    EXPECT_EQ(rig.client.tx_pull_sent_count(), 1u);
    EXPECT_EQ(rig.client.tx_retry_busy_count(), 0u);
    EXPECT_EQ(rig.client.tx_retry_drained_count(), 1u);
}

} // namespace
