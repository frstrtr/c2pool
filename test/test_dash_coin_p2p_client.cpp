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
///   (c) CoinClient handshake drive — the REAL client class fed byte-exact
///       wire messages (message_version / message_verack round-tripped
///       through make_raw -> Handler::parse, the same path live socket bytes
///       take): peer metadata capture, handshake completion, the
///       on_handshake_complete seam, unknown-command tolerance (dashd spork/
///       governance traffic), and teardown-on-error resetting the session.
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

#include <memory>
#include <string>
#include <vector>

using dash::coin::p2p::CoinClient;
using dash::coin::p2p::DialPlan;
using dash::coin::p2p::HandshakeTracker;

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
    // dashd pushes spork/governance/quorum commands outside our Handler set;
    // the client must ignore them without tearing the session down.
    ClientRig rig;
    rig.wire_connected();
    rig.deliver(rig.peer_version(70230, 1, 100, "/Dash Core:21.1.0/"));
    rig.deliver(dash::coin::p2p::message_verack::make_raw());
    ASSERT_TRUE(rig.client.is_handshake_complete());

    auto spork = std::make_unique<RawMessage>("spork", PackStream{});
    rig.deliver(std::move(spork));                       // must not throw
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

} // namespace
