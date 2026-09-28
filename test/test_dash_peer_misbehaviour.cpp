// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH sharechain peer misbehaviour score and IP ban (#1829).
//
// Every behavioural KAT runs a real dash::Node (Legacy + Actual dispatch)
// whose peer is attached through the REAL NodeImpl::connected() over a
// loopback TCP socket, so "disconnected" means the connection left
// m_connections and the far end of the socket read EOF, and "inbound
// reconnect refused" means connected() closed a new socket from the same IP.
// Messages go through the real Legacy / Actual handle_message.
//
// What is pinned:
//   1. A flood of invalid shares crosses the threshold: 5 invalid-PoW shares
//      (v36 network and public network), 10 structurally invalid shares (v36)
//      -> every connection from the IP closed, the IP banned, an inbound
//      reconnect from a new port refused until the ban expires.
//   2. The score decays: two bursts of 4 invalid-PoW shares 6000 s apart do
//      not ban; one more share after the second burst does.
//   3. Each graded offence is charged its weight on the v36 network; an
//      unknown command and a future-timestamp share are charged nothing.
//   4. Guards (green on the base revision too): an honest peer interleaving
//      valid shares with occasional invalid ones is never banned; a
//      whitelisted peer is never scored; on the public network nothing the
//      p2pool-dash oracle tolerates is charged (unknown commands, share types
//      it skips or refuses to load, over-cap frames, unparseable payloads,
//      orphan and duplicate shares); a refused old build is not scored.
//   5. The classification rule and every reject text; the pure scorer.
//
// Red on the base revision: build this TU with DASH_PEER_BAN_BASE_REVISION
// defined (it fences out what names new symbols); the ban KATs in section 1
// and 2 fail there, because the base never disconnects or bans on the receive
// path.
//
// Folded into test_dash_node (needs dash::Node + c2pool_storage).

#include <gtest/gtest.h>

#include "dash_v36_mint_fixture.hpp"   // mine_v16/mine_v36, LoopbackPair, handshake_on, ...

#ifndef DASH_PEER_BAN_BASE_REVISION
#include <impl/dash/peer_misbehaviour.hpp>
#endif
#include <impl/dash/messages.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

namespace {

#ifndef DASH_PEER_BAN_BASE_REVISION
using dash::misbehaviour::Offence;
using Scorer = dash::misbehaviour::PeerMisbehaviourScorer<std::string>;
#endif

struct PowCounter {
    std::shared_ptr<std::atomic<int>> calls = std::make_shared<std::atomic<int>>(0);
    core::CoinParams wrap(core::CoinParams p) const {
        auto inner = p.pow_func;
        auto c = calls;
        p.pow_func = [inner, c](std::span<const unsigned char> h) {
            c->fetch_add(1);
            return inner(h);
        };
        return p;
    }
    int n() const { return calls->load(); }
};

struct BanProbe : dash::Node {
    BanProbe(boost::asio::io_context* ctx, dash::Config* cfg)
        : dash::NodeImpl(ctx, cfg), dash::Node(ctx, cfg) {}
    void hold_think_slot(bool hold) { m_think_running.store(hold); if (!hold) m_rethink_pending.store(false); }
    bool has_connection(const NetService& a) const { return m_connections.contains(a); }
    dash::NodeImpl::peer_ptr connection(const NetService& a) {
        auto it = m_connections.find(a);
        return it == m_connections.end() ? nullptr : it->second;
    }
#ifndef DASH_PEER_BAN_BASE_REVISION
    void set_clock(std::function<double()> f) { m_misbehaviour_now = std::move(f); }
#endif
};

// One loopback TCP connection attached to the node through connected().
struct Conn {
    LoopbackPair pair;
    NetService addr;
    dash::NodeImpl::peer_ptr peer;   // null when connected() refused it
};

bool far_end_closed(Conn& c, std::chrono::milliseconds wait)
{
    auto& s = *c.pair.theirs;
    s.non_blocking(true);
    const auto deadline = std::chrono::steady_clock::now() + wait;
    while (std::chrono::steady_clock::now() < deadline) {
        std::array<std::byte, 65536> chunk{};
        boost::system::error_code ec;
        const std::size_t n = s.read_some(boost::asio::buffer(chunk), ec);
        if (n > 0)
            continue;   // our version message; keep draining
        if (ec == boost::asio::error::would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        return ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset;
    }
    return false;
}

struct Rig {
    boost::asio::io_context ioc;
    dash::Config cfg{"dash-peer-ban-kat"};
    StubCommunicator stub;
    std::vector<std::unique_ptr<Conn>> conns;   // outlive the node (their sockets live in it)
    PowCounter pow;
    std::unique_ptr<BanProbe> node;
    bool legacy_peers;

    Rig(const core::CoinParams& p, bool legacy, const std::vector<NetService>& bootstrap = {})
        : legacy_peers(legacy)
    {
        cfg.pool()->m_bootstrap_addrs = bootstrap;
        node = std::make_unique<BanProbe>(&ioc, &cfg);
        node->tracker().m_coin_params = pow.wrap(p);
        const auto sub = SharechainConfig::data_subdir(false);
        fs::create_directories(core::filesystem::config_path() / sub);
        node->init_storage(sub);
        node->hold_think_slot(true);   // observe the receive path alone
    }
    ~Rig()
    {
        node->join_compute_pools();
        ioc.restart();
        ioc.poll();   // run what the verify pool posted while the node is alive
        node->hold_think_slot(false);
        node->shutdown_persistence();
        for (auto& c : conns) c->peer.reset();
        node.reset();
        ioc.restart();
        ioc.poll();   // run the deferred peer releases while the sockets' contexts live
        conns.clear();
    }

    // A new inbound-style connection from 127.0.0.1 (a new source port each
    // time: each LoopbackPair listens on its own ephemeral port).
    Conn& attach()
    {
        conns.push_back(std::make_unique<Conn>());
        Conn& c = *conns.back();
        auto sock = std::make_shared<core::Socket>(
            std::move(c.pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        c.addr = sock->get_addr();
        node->connected(sock);
        c.peer = node->connection(c.addr);
        if (c.peer)
            c.peer->stable(legacy_peers ? pool::PeerConnectionType::legacy
                                        : pool::PeerConnectionType::actual, 100);
        return c;
    }

    // The REAL handle_version on an attached connection: "" = admitted, else
    // the exception text. Runs the connection's socket context meanwhile.
    std::string version(Conn& c, uint32_t proto, uint64_t nonce)
    {
        IoThread io(c.pair.ioc_node);
        std::string result;
        try {
            auto t = node->handle_version(make_version(proto, nonce), c.peer);
            result = t.has_value() ? "" : "<no peer type>";
        } catch (const std::exception& e) {
            result = e.what();
        }
        io.stop(c.pair.ioc_node);
        return result;
    }

    void send(Conn& c, std::unique_ptr<RawMessage> m)
    {
        ASSERT_TRUE(c.peer) << "sending on a refused connection";
        if (legacy_peers) static_cast<dash::Legacy&>(*node).handle_message(std::move(m), c.peer);
        else              static_cast<dash::Actual&>(*node).handle_message(std::move(m), c.peer);
    }

    void send_shares(Conn& c, const std::vector<chain::RawShare>& shares)
    {
        send(c, dash::message_shares::make_raw(shares));
    }

    void pump(int ms = 100)
    {
        const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < end) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(5));
        }
    }

    // Pump until `k` X11 calls were made (the verify pool ran every share of
    // the message), then a little more so the posted charges run.
    void settle_pow(int k)
    {
        for (int i = 0; i < 400 && pow.n() < k; ++i) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(10));
        }
        pump(60);
    }

    template <typename Pred>
    bool pump_until(Pred&& pred)
    {
        for (int i = 0; i < 400; ++i) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(20));
            auto g = node->read_tracker();
            if (g && pred(*g))
                return true;
        }
        return false;
    }

    bool connected(const Conn& c) const { return node->has_connection(c.addr); }
};

chain::RawShare raw(uint64_t type, const Bytes& wire) { return chain::RawShare(type, PackStream(wire)); }

std::vector<dash::producer::BuiltV36Share> v36_chain(const core::CoinParams& p, int n, uint8_t tag0 = 0xa0)
{
    dash::ShareChain scratch;
    std::vector<dash::producer::BuiltV36Share> out;
    uint256 prev;
    for (int i = 0; i < n; ++i) {
        auto b = mine_v36(scratch, p, info(prev, static_cast<uint32_t>(i + 1),
                                           static_cast<uint8_t>(tag0 + i), 36));
        scratch.add(new dash::DashV36Share(b.share));
        prev = b.share.m_hash;
        out.push_back(b);
    }
    return out;
}

// Share target 1 (compact 0x03000001 + k): valid (non-zero, below MAX_TARGET),
// and no X11 hash meets it, so share_init_verify throws "share PoW hash does
// not meet target" after exactly one X11 call. `k` keeps the shares distinct.
template <typename S>
S pow_miss(S s, uint32_t k)
{
    s.m_bits = 0x03000001u + k;
    return s;
}

template <typename S>
S merkle_17(S s, uint8_t k)
{
    s.m_merkle_link.m_branch.assign(17, tag_hash(k));
    return s;
}

// hash_link extra_data longer than any extra_length (< 64): check_hash_link
// throws "check_hash_link: extra size mismatch" (not a typed reject).
template <typename S>
S bad_hash_link(S s)
{
    s.m_hash_link.m_extra_data = BaseScript(Bytes(70, 0x11));
    return s;
}

// The smallest parseable v16 share (the #1828 MinimalV16RawShareSize shape).
Bytes minimal_v16_wire(uint8_t k)
{
    dash::DashShare s;
    s.m_coinbase = BaseScript(Bytes{0x01, k});
    s.m_min_header.m_version = 0;
    s.m_desired_version = 16;
    s.m_hash_link.m_state.m_data.assign(32, 0x00);
    s.m_hash_link.m_length = 0;
    return wire_of(s);
}

std::unique_ptr<RawMessage> truncated_shares_message(const Bytes& share_wire)
{
    auto full = dash::message_shares::make_raw(std::vector<chain::RawShare>{raw(36, share_wire)});
    Bytes b = to_bytes(full->m_data);
    b.resize(b.size() / 2);
    return std::make_unique<RawMessage>(std::string("shares"), PackStream(b));
}

std::unique_ptr<RawMessage> unknown_command_message()
{
    return std::make_unique<RawMessage>(std::string("bogus_cmd"), PackStream(Bytes{0x01, 0x02}));
}

uint32_t wall_now()
{
    return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

// A clock the test advances by hand (the decay seam).
struct ManualClock {
    std::shared_ptr<double> t = std::make_shared<double>(1000.0);
    std::function<double()> fn() const { auto p = t; return [p] { return *p; }; }
    void advance(double s) { *t += s; }
};

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// 1. A flood crosses the threshold: disconnect + IP ban + inbound refused
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashPeerMisbehaviour, FiveInvalidPowSharesBanAndDisconnectOnV36)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_v36pow");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);

    for (uint32_t i = 0; i < 4; ++i) {
        rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, i)))});
        rig.settle_pow(static_cast<int>(i + 1));
    }
    EXPECT_TRUE(rig.connected(c)) << "4 invalid-PoW shares (score 80) stay below the threshold";
    EXPECT_FALSE(rig.node->is_banned(c.addr));
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 80.0);
    EXPECT_EQ(rig.node->misbehaviour_notes(Offence::invalid_pow), 4u);
#endif

    rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, 4)))});
    rig.settle_pow(5);
    EXPECT_FALSE(rig.connected(c)) << "the 5th invalid-PoW share must disconnect the peer";
    EXPECT_TRUE(rig.node->is_banned(c.addr)) << "and ban its IP";
    EXPECT_TRUE(far_end_closed(c, std::chrono::milliseconds(1000))) << "the socket is closed";
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_EQ(rig.node->misbehaviour_bans(), 1u);
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 0.0) << "cleared after the ban";
#endif
}

TEST(DashPeerMisbehaviour, FiveInvalidPowSharesBanOnPublicProfile)
{
    // The oracle bans at the FIRST invalid-PoW share (p2pool/data.py:360-362 ->
    // p2pool/p2p.py:89-102); the public network scores the same offence and
    // acts at the threshold.
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_pubpow");
    const auto p = public_params();
    ASSERT_FALSE(SharechainConfig::isolated_v36());
    dash::ShareChain scratch;
    const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
    Rig rig(p, /*legacy=*/true);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    for (uint32_t i = 0; i < 4; ++i) {
        rig.send_shares(c, {raw(16, wire_of(pow_miss(b.share, i)))});
        rig.settle_pow(static_cast<int>(i + 1));
    }
    EXPECT_TRUE(rig.connected(c));
    rig.send_shares(c, {raw(16, wire_of(pow_miss(b.share, 4)))});
    rig.settle_pow(5);
    EXPECT_FALSE(rig.connected(c)) << "public: 5 invalid-PoW shares disconnect";
    EXPECT_TRUE(rig.node->is_banned(c.addr));
    EXPECT_TRUE(far_end_closed(c, std::chrono::milliseconds(1000)));
}

TEST(DashPeerMisbehaviour, BannedIpInboundReconnectRefusedUntilExpiry)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_inbound");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    rig.node->set_ban_duration(2);
    const uint32_t proto = SharechainConfig::share_profile().advertised_protocol_version;
    const uint64_t nonce = 0x1829'0001;
    Conn& c1 = rig.attach();
    ASSERT_TRUE(c1.peer);
    // c1 completes the handshake, so its nonce is in the node's peer table.
    ASSERT_EQ(rig.version(c1, proto, nonce), "");
    for (uint32_t i = 0; i < 5; ++i)
        rig.send_shares(c1, {raw(36, wire_of(pow_miss(sh[0].share, i)))});
    rig.settle_pow(5);
    ASSERT_FALSE(rig.connected(c1));

    // Same IP, new source port: refused before the handshake.
    Conn& c2 = rig.attach();
    EXPECT_NE(c2.addr.port(), c1.addr.port());
    EXPECT_EQ(c2.addr.address(), c1.addr.address());
    EXPECT_FALSE(c2.peer) << "an inbound reconnect from the banned IP must be refused";
    EXPECT_FALSE(rig.connected(c2));
    EXPECT_TRUE(rig.node->is_banned(c2.addr)) << "the ban is on the IP, not the IP:port";
    EXPECT_TRUE(far_end_closed(c2, std::chrono::milliseconds(1000)));

    // The ban expires.
    std::this_thread::sleep_for(std::chrono::milliseconds(2300));
    EXPECT_FALSE(rig.node->is_banned(c2.addr));
    Conn& c3 = rig.attach();
    ASSERT_TRUE(c3.peer) << "accepted again once the ban expired";
    EXPECT_TRUE(rig.connected(c3));
    // The same node (same nonce) handshakes again: the ban dropped c1's nonce
    // entry, so this is not refused as a duplicate connection.
    EXPECT_EQ(rig.version(c3, proto, nonce), "")
        << "a reconnect after the ban expired must not be refused as a duplicate";
    EXPECT_TRUE(rig.connected(c3));
}

TEST(DashPeerMisbehaviour, ParallelSocketsFromTheBannedIpAreAllClosed)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_parallel");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& a = rig.attach();
    Conn& b = rig.attach();
    ASSERT_TRUE(a.peer);
    ASSERT_TRUE(b.peer);
    for (uint32_t i = 0; i < 5; ++i)
        rig.send_shares(a, {raw(36, wire_of(pow_miss(sh[0].share, i)))});
    rig.settle_pow(5);
    EXPECT_FALSE(rig.connected(a));
    EXPECT_FALSE(rig.connected(b)) << "every connection from the banned IP is closed";
    EXPECT_TRUE(far_end_closed(a, std::chrono::milliseconds(1000)));
    EXPECT_TRUE(far_end_closed(b, std::chrono::milliseconds(1000)));
}

TEST(DashPeerMisbehaviour, TenStructuralViolationsBanOnV36)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_struct");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    for (int i = 0; i < 9; ++i)
        rig.send_shares(c, {raw(36, wire_of(merkle_17(sh[0].share, static_cast<uint8_t>(i + 1))))});
    rig.pump(300);
    EXPECT_TRUE(rig.connected(c)) << "9 structural rejects (score 90) stay below the threshold";
    rig.send_shares(c, {raw(36, wire_of(merkle_17(sh[0].share, 0x40)))});
    rig.pump(300);
    EXPECT_EQ(rig.pow.n(), 0) << "rejected before X11";
    EXPECT_FALSE(rig.connected(c)) << "the 10th structural reject disconnects";
    EXPECT_TRUE(rig.node->is_banned(c.addr));
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Decay
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashPeerMisbehaviour, ScoreDecaysBetweenBursts)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_decay");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    uint32_t k = 0;
    for (int i = 0; i < 4; ++i, ++k)
        rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, k)))});
    rig.settle_pow(4);
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 80.0);
    clk.advance(6000.0);   // 10 half-lives: 80 -> 0.078
    EXPECT_NEAR(rig.node->misbehaviour_score(c.addr), 80.0 / 1024.0, 1e-9);
#endif
    for (int i = 0; i < 4; ++i, ++k)
        rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, k)))});
    rig.settle_pow(8);
    EXPECT_TRUE(rig.connected(c)) << "8 invalid shares in two bursts 10 half-lives apart do not ban";
    rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, k)))});
    rig.settle_pow(9);
    EXPECT_FALSE(rig.connected(c)) << "one more share on top of the second burst does";
    EXPECT_TRUE(rig.node->is_banned(c.addr));
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Each graded offence is charged its weight on the v36 network
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashPeerMisbehaviour, V36GradedOffencesAreCharged)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_graded");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    const Bytes good = wire_of(sh[0].share);
    auto future = sh[0].share;
    future.m_timestamp = wall_now() + 3600;

    struct Case {
        const char* name;
        std::function<void(Rig&, Conn&)> send;
#ifndef DASH_PEER_BAN_BASE_REVISION
        std::optional<Offence> offence;   // nullopt: charged nothing
#endif
    };
    const std::vector<Case> cases = {
        {"structural (merkle branch 17)", [&](Rig& r, Conn& c) {
             r.send_shares(c, {raw(36, wire_of(merkle_17(sh[0].share, 1)))}); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::structural
#endif
        },
        {"bad_verify (hash_link extra_data)", [&](Rig& r, Conn& c) {
             r.send_shares(c, {raw(36, wire_of(bad_hash_link(sh[0].share)))}); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::bad_verify
#endif
        },
        {"wrong_share_type (v16 wire)", [&](Rig& r, Conn& c) {
             r.send_shares(c, {raw(16, minimal_v16_wire(0x02))}); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::wrong_share_type
#endif
        },
        {"precheck_drop (65 shares in one 'shares')", [&](Rig& r, Conn& c) {
             r.send_shares(c, std::vector<chain::RawShare>(65, raw(36, good))); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::precheck_drop
#endif
        },
        {"parse_failure (truncated 'shares' payload)", [&](Rig& r, Conn& c) {
             r.send(c, truncated_shares_message(good)); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::parse_failure
#endif
        },
        {"parse_failure (share contents do not load)", [&](Rig& r, Conn& c) {
             r.send_shares(c, {raw(36, Bytes(10, 0xff))}); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         Offence::parse_failure
#endif
        },
        {"unknown command", [&](Rig& r, Conn& c) { r.send(c, unknown_command_message()); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         std::nullopt
#endif
        },
        {"future timestamp (+1 h)", [&](Rig& r, Conn& c) {
             r.send_shares(c, {raw(36, wire_of(future))}); },
#ifndef DASH_PEER_BAN_BASE_REVISION
         std::nullopt
#endif
        },
    };
    for (const auto& cs : cases) {
        SCOPED_TRACE(cs.name);
        Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
        ManualClock clk;
        rig.node->set_clock(clk.fn());
#endif
        Conn& c = rig.attach();
        ASSERT_TRUE(c.peer);
        cs.send(rig, c);
        rig.pump(300);
        EXPECT_TRUE(rig.connected(c)) << "one offence never disconnects";
        EXPECT_FALSE(rig.node->is_banned(c.addr));
#ifndef DASH_PEER_BAN_BASE_REVISION
        uint64_t total = 0;
        for (std::size_t o = 0; o < dash::misbehaviour::OFFENCE_COUNT; ++o)
            total += rig.node->misbehaviour_notes(static_cast<Offence>(o));
        if (cs.offence) {
            EXPECT_EQ(rig.node->misbehaviour_notes(*cs.offence), 1u);
            EXPECT_EQ(total, 1u) << "exactly one charge";
            EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), dash::misbehaviour::weight(*cs.offence));
        } else {
            EXPECT_EQ(total, 0u);
            EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 0.0);
        }
#endif
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Guards: never penalise an honest peer (green on the base revision too)
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashPeerMisbehaviour, HonestPeerInterleavingValidSharesIsNeverBanned)
{
    // One invalid-PoW share per 600 s half-life next to a valid chain share:
    // the score settles at 40 (s = s/2 + 20) and never reaches 100.
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_honest");
    const auto p = iso_params(36);
    const int rounds = 24;
    const auto sh = v36_chain(p, rounds);
    Rig rig(p, /*legacy=*/false);
#ifndef DASH_PEER_BAN_BASE_REVISION
    ManualClock clk;
    rig.node->set_clock(clk.fn());
#endif
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    for (int i = 0; i < rounds; ++i) {
        rig.send_shares(c, {raw(36, wire_of(sh[i].share)),
                            raw(36, wire_of(pow_miss(sh[i].share, static_cast<uint32_t>(i))))});
        rig.settle_pow(2 * (i + 1));
        ASSERT_TRUE(rig.connected(c)) << "round " << i;
#ifndef DASH_PEER_BAN_BASE_REVISION
        EXPECT_LE(rig.node->misbehaviour_score(c.addr), 40.0 + 1e-9) << "round " << i;
        clk.advance(600.0);
#endif
    }
    EXPECT_TRUE(rig.pump_until([&](dash::ShareTracker& t) {
        for (int i = 0; i < rounds; ++i) if (!t.chain.contains(sh[i].share.m_hash)) return false;
        return true;
    })) << "every valid share was accepted";
    EXPECT_FALSE(rig.node->is_banned(c.addr));
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_EQ(rig.node->misbehaviour_bans(), 0u);
    EXPECT_EQ(rig.node->misbehaviour_notes(Offence::invalid_pow), static_cast<uint64_t>(rounds));
#endif
}

TEST(DashPeerMisbehaviour, WhitelistedPeerIsNeverScored)
{
    // --addnode / --connect seeds (m_bootstrap_addrs) are whitelisted by IP.
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_whitelist");
    const auto p = iso_params(36);
    const auto sh = v36_chain(p, 1);
    Rig rig(p, /*legacy=*/false, {NetService("127.0.0.1", 1)});
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    ASSERT_TRUE(rig.node->is_whitelisted(c.addr));
    for (uint32_t i = 0; i < 50; ++i)
        rig.send_shares(c, {raw(36, wire_of(pow_miss(sh[0].share, i)))});
    rig.settle_pow(50);
    for (int i = 0; i < 20; ++i)
        rig.send(c, truncated_shares_message(wire_of(sh[0].share)));
    rig.pump(100);
    EXPECT_TRUE(rig.connected(c));
    EXPECT_FALSE(rig.node->is_banned(c.addr));
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 0.0);
    for (std::size_t o = 0; o < dash::misbehaviour::OFFENCE_COUNT; ++o)
        EXPECT_EQ(rig.node->misbehaviour_notes(static_cast<Offence>(o)), 0u) << o;
#endif
}

TEST(DashPeerMisbehaviour, PublicHonestOracleBehavioursNotPenalised)
{
    // Everything here is tolerated by p2pool-dash (unknown command skipped,
    // util/p2protocol.py:49-53; older share type skipped, p2p.py:334; oversize
    // frame skipped, p2protocol.py:38-40) or at worst disconnects there without
    // a ban (unknown share type, unparseable payload). None is charged on the
    // public network.
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_public");
    const auto p = public_params();
    ASSERT_FALSE(SharechainConfig::isolated_v36());
    dash::ShareChain scratch;
    const auto honest = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
    scratch.add(new dash::DashShare(honest.share));
    // `orphan` is sent BEFORE its parent `honest`: the node sees an unknown parent.
    const auto orphan = mine_v16(scratch, p, info(honest.share.m_hash, 2, 0xab, 16));
    const Bytes w = wire_of(honest.share);

    Rig rig(p, /*legacy=*/true);
    Conn& c = rig.attach();
    ASSERT_TRUE(c.peer);
    for (int i = 0; i < 50; ++i) rig.send(c, unknown_command_message());
    for (int i = 0; i < 50; ++i) rig.send_shares(c, {raw(36, Bytes(300, static_cast<unsigned char>(i)))});
    for (int i = 0; i < 50; ++i) rig.send_shares(c, {raw(15, w)});
    for (int i = 0; i < 50; ++i) rig.send(c, truncated_shares_message(w));
    {
        // 3 x ~1 MiB: one byte over the 3145728-byte payload cap (#1828).
        std::vector<chain::RawShare> big;
        for (int i = 0; i < 3; ++i) {
            Bytes pad = w;
            pad.resize(1048576, 0x00);
            big.push_back(raw(16, pad));
        }
        for (int i = 0; i < 5; ++i) rig.send_shares(c, big);
    }
    rig.send_shares(c, {raw(16, wire_of(orphan.share))});
    rig.send_shares(c, {raw(16, w)});
    rig.send_shares(c, {raw(16, w)});   // duplicate
    EXPECT_TRUE(rig.pump_until([&](dash::ShareTracker& t) {
        return t.chain.contains(honest.share.m_hash) && t.chain.contains(orphan.share.m_hash);
    })) << "the honest and the orphan share are both accepted";
    rig.pump(200);
    EXPECT_TRUE(rig.connected(c));
    EXPECT_FALSE(rig.node->is_banned(c.addr));
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_EQ(rig.node->precheck_dropped_messages(), 5u);
    for (std::size_t o = 0; o < dash::misbehaviour::OFFENCE_COUNT; ++o)
        EXPECT_EQ(rig.node->misbehaviour_notes(static_cast<Offence>(o)), 0u) << o;
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(c.addr), 0.0);
#endif
}

TEST(DashPeerMisbehaviour, RefusedOldBuildIsNotScored)
{
    // A build below the v36 protocol floor is refused at the handshake; the
    // refusal never reaches the scorer (the oracle bans "peer too old",
    // p2pool/p2p.py:150-151; c2pool deliberately does not).
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_peerban_old");
    const auto p = iso_params(36);
    LoopbackPair pair;       // outlives the node
    StubCommunicator stub;
    Rig rig(p, /*legacy=*/false);
    NetService a;
    const std::string r = handshake_on(*rig.node, pair, stub, 1700, 0x1829, &a);
    EXPECT_NE(r, "") << "1700 is refused on the v36 network";
    EXPECT_FALSE(rig.node->is_banned(a));
#ifndef DASH_PEER_BAN_BASE_REVISION
    EXPECT_DOUBLE_EQ(rig.node->misbehaviour_score(a), 0.0);
    EXPECT_EQ(rig.node->misbehaviour_bans(), 0u);
#endif
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Pins (new symbols; fenced out of the base-revision build)
// ═════════════════════════════════════════════════════════════════════════════
#ifndef DASH_PEER_BAN_BASE_REVISION

namespace {
struct Caught {
    std::string what;
    std::optional<Offence> pub, v36;
    bool pow_miss{false}, structure{false}, clock{false}, invalid_arg{false};
};
template <typename S>
Caught catch_verify(const S& s, const core::CoinParams& p, bool check_pow = true)
{
    Caught c;
    try {
        (void)dash::share_init_verify(s, p, check_pow);
        c.what = "<no exception>";
    } catch (const std::exception& e) {
        c.what = e.what();
        c.pub = dash::misbehaviour::classify_verify_failure(e, false);
        c.v36 = dash::misbehaviour::classify_verify_failure(e, true);
        c.pow_miss = dynamic_cast<const dash::SharePoWTargetMiss*>(&e) != nullptr;
        c.structure = dynamic_cast<const dash::ShareStructureReject*>(&e) != nullptr;
        c.clock = dynamic_cast<const dash::ShareClockReject*>(&e) != nullptr;
        c.invalid_arg = dynamic_cast<const std::invalid_argument*>(&e) != nullptr;
    }
    return c;
}
} // namespace

TEST(DashPeerMisbehaviour, ClassificationPinsTypedRejectsAndTexts)
{
    IdentityGuard guard;
    {
        const auto p = public_params();
        dash::ShareChain scratch;
        const auto b = mine_v16(scratch, p, info(uint256(), 1, 0xaa, 16));
        EXPECT_EQ(catch_verify(b.share, p).what, "<no exception>");

        auto c = catch_verify(pow_miss(b.share, 0), p);
        EXPECT_EQ(c.what, "share PoW hash does not meet target");
        EXPECT_TRUE(c.pow_miss); EXPECT_TRUE(c.invalid_arg);
        EXPECT_TRUE(c.pub == Offence::invalid_pow); EXPECT_TRUE(c.v36 == Offence::invalid_pow);

        auto s = b.share; s.m_bits = 0;
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share target is zero");
        EXPECT_TRUE(c.pow_miss); EXPECT_TRUE(c.pub == Offence::invalid_pow);

        s = b.share; s.m_bits = 0x2100ffffu;   // easier than MAX_TARGET
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share target invalid");
        EXPECT_TRUE(c.pow_miss); EXPECT_TRUE(c.pub == Offence::invalid_pow);

        s = b.share; s.m_coinbase = BaseScript(Bytes{0x01});
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "bad coinbase size");
        EXPECT_TRUE(c.structure); EXPECT_TRUE(c.invalid_arg);
        EXPECT_TRUE(c.pub == Offence::structural); EXPECT_TRUE(c.v36 == Offence::structural);

        c = catch_verify(merkle_17(b.share, 1), p);
        EXPECT_EQ(c.what, "merkle branch too long");
        EXPECT_TRUE(c.structure); EXPECT_TRUE(c.pub == Offence::structural);

        s = b.share; s.m_transaction_hash_refs = {110, 0};
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "bad transaction_hash_refs");
        EXPECT_TRUE(c.structure); EXPECT_TRUE(c.pub == Offence::structural);

        c = catch_verify(bad_hash_link(b.share), p);
        EXPECT_EQ(c.what, "check_hash_link: extra size mismatch");
        EXPECT_FALSE(c.pow_miss || c.structure || c.clock);
        EXPECT_FALSE(c.pub.has_value()) << "the public network does not grade other verify failures";
        EXPECT_TRUE(c.v36 == Offence::bad_verify);
    }
    {
        const auto p = iso_params(36);
        const auto sh = v36_chain(p, 1);
        EXPECT_EQ(catch_verify(sh[0].share, p).what, "<no exception>");

        auto s = sh[0].share; s.m_timestamp = wall_now() + 3600;
        auto c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share timestamp is too far in the future");
        EXPECT_TRUE(c.clock); EXPECT_TRUE(c.invalid_arg);
        EXPECT_FALSE(c.pub.has_value()); EXPECT_FALSE(c.v36.has_value()) << "clock skew is never charged";

        c = catch_verify(pow_miss(sh[0].share, 0), p);
        EXPECT_EQ(c.what, "share PoW hash does not meet target");
        EXPECT_TRUE(c.pow_miss); EXPECT_TRUE(c.v36 == Offence::invalid_pow);

        s = sh[0].share; s.m_coinbase = BaseScript(Bytes(101, 0x01));
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "bad coinbase size");
        EXPECT_TRUE(c.structure);

        c = catch_verify(merkle_17(sh[0].share, 2), p);
        EXPECT_EQ(c.what, "merkle branch too long");
        EXPECT_TRUE(c.structure);

        s = sh[0].share; s.m_pubkey_type = 1;
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share pubkey_type must be 0 (P2PKH)");
        EXPECT_TRUE(c.structure); EXPECT_TRUE(c.v36 == Offence::structural);

        s = sh[0].share; s.m_merged_payout_hash = tag_hash(0x09);
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share merged-mining fields must be empty");
        EXPECT_TRUE(c.structure);

        s = sh[0].share; s.m_message_data = BaseScript(Bytes(562, 0x01));
        c = catch_verify(s, p);
        EXPECT_EQ(c.what, "share message_data exceeds MAX_TOTAL_MESSAGE_BYTES");
        EXPECT_TRUE(c.structure);

        // message_data that does not decrypt: the plain invalid_argument
        // check_v36_message_data throws after the PoW gate (check_pow off
        // here, so the tampered share needs no re-mining) -> bad_verify.
        s = sh[0].share; s.m_message_data = BaseScript(Bytes(100, 0x5a));
        c = catch_verify(s, p, /*check_pow=*/false);
        EXPECT_EQ(c.what.rfind("share ", 0), 0u) << c.what;
        EXPECT_FALSE(c.pow_miss || c.structure || c.clock);
        EXPECT_TRUE(c.invalid_arg);
        EXPECT_TRUE(c.v36 == Offence::bad_verify);
        EXPECT_FALSE(c.pub.has_value());

        c = catch_verify(bad_hash_link(sh[0].share), p);
        EXPECT_EQ(c.what, "check_hash_link: extra size mismatch");
        EXPECT_TRUE(c.v36 == Offence::bad_verify);
    }
    // The type-admission reject (processing_shares charges wrong_share_type
    // from its own catch) keeps its text.
    {
        const auto p = iso_params(36);
        EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(16, p); }),
                  "share type v16 not admitted: this sharechain speaks v36");
    }
}

TEST(DashPeerMisbehaviour, PolicyTable)
{
    using namespace dash::misbehaviour;
    EXPECT_EQ(weight(Offence::invalid_pow), 20.0);
    EXPECT_EQ(weight(Offence::structural), 10.0);
    EXPECT_EQ(weight(Offence::bad_verify), 10.0);
    EXPECT_EQ(weight(Offence::wrong_share_type), 5.0);
    EXPECT_EQ(weight(Offence::precheck_drop), 10.0);
    EXPECT_EQ(weight(Offence::parse_failure), 5.0);
    EXPECT_EQ(Scorer::BAN_THRESHOLD, 100.0);
    EXPECT_EQ(Scorer::HALFLIFE_SECONDS, 600.0);
    // Public network: only what the oracle itself treats as a peer error.
    EXPECT_TRUE(applies(Offence::invalid_pow, false));
    EXPECT_TRUE(applies(Offence::structural, false));
    EXPECT_FALSE(applies(Offence::bad_verify, false));
    EXPECT_FALSE(applies(Offence::wrong_share_type, false));
    EXPECT_FALSE(applies(Offence::precheck_drop, false));
    EXPECT_FALSE(applies(Offence::parse_failure, false));
    for (std::size_t o = 0; o < OFFENCE_COUNT; ++o)
        EXPECT_TRUE(applies(static_cast<Offence>(o), true)) << name(static_cast<Offence>(o));
    EXPECT_FALSE(applies(Offence::COUNT, true));
    EXPECT_FALSE(SharechainConfig::PUBLIC_PROFILE.full_misbehaviour_grading);
    EXPECT_TRUE(SharechainConfig::ISOLATED_V36_PROFILE.full_misbehaviour_grading);
}

TEST(DashPeerMisbehaviour, ScorerThresholdIsExact)
{
    Scorer s;
    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(s.note("a", 20.0, 50.0)) << i;
    EXPECT_DOUBLE_EQ(s.score("a", 50.0), 80.0);
    EXPECT_TRUE(s.note("a", 20.0, 50.0));
    Scorer t;
    for (int i = 0; i < 9; ++i) EXPECT_FALSE(t.note("b", 10.0, 1.0));
    EXPECT_TRUE(t.note("b", 10.0, 1.0));
    Scorer u;
    for (int i = 0; i < 19; ++i) EXPECT_FALSE(u.note("c", 5.0, 1.0));
    EXPECT_TRUE(u.note("c", 5.0, 1.0));
}

TEST(DashPeerMisbehaviour, ScorerTrickleNeverBans)
{
    // One invalid-PoW share per half-life: s -> s/2 + 20, bounded by 40.
    Scorer s;
    double t = 0.0;
    for (int i = 0; i < 1000; ++i, t += 600.0)
        ASSERT_FALSE(s.note("a", 20.0, t)) << i;
    EXPECT_NEAR(s.score("a", t - 600.0), 40.0, 1e-9);
    // Two per half-life: bounded by 80, still no ban.
    Scorer d;
    t = 0.0;
    for (int i = 0; i < 1000; ++i, t += 300.0)
        ASSERT_FALSE(d.note("a", 20.0, t)) << i;
}

TEST(DashPeerMisbehaviour, ScorerDecaysToZeroAndPrunes)
{
    Scorer s;
    EXPECT_FALSE(s.note("a", 80.0, 0.0));
    EXPECT_DOUBLE_EQ(s.score("a", 600.0), 40.0);
    EXPECT_DOUBLE_EQ(s.score("a", 1200.0), 20.0);
    EXPECT_DOUBLE_EQ(s.score("a", 0.0), 80.0) << "reading does not advance the clock";
    EXPECT_LT(s.score("a", 600.0 * 20), 0.001);
    EXPECT_FALSE(s.note("b", 10.0, 0.0));
    EXPECT_EQ(s.tracked_peers(), 2u);
    s.prune(600.0 * 5);   // a: 2.5, b: 0.31 -> both kept
    EXPECT_EQ(s.tracked_peers(), 2u);
    s.prune(600.0 * 10);  // a: 0.078, b: 0.0098 -> b dropped
    EXPECT_EQ(s.tracked_peers(), 1u);
    s.prune(600.0 * 20);
    EXPECT_EQ(s.tracked_peers(), 0u);
    EXPECT_DOUBLE_EQ(s.score("a", 0.0), 0.0);
}

TEST(DashPeerMisbehaviour, ScorerKeysAreIndependentAndClearForgets)
{
    Scorer s;
    for (int i = 0; i < 4; ++i) s.note("203.0.113.7", 20.0, 5.0);
    s.note("198.51.100.9", 20.0, 5.0);
    EXPECT_DOUBLE_EQ(s.score("203.0.113.7", 5.0), 80.0);
    EXPECT_DOUBLE_EQ(s.score("198.51.100.9", 5.0), 20.0);
    s.clear("203.0.113.7");
    EXPECT_DOUBLE_EQ(s.score("203.0.113.7", 5.0), 0.0);
    EXPECT_FALSE(s.note("203.0.113.7", 20.0, 5.0)) << "starts again from zero";
    EXPECT_DOUBLE_EQ(s.score("198.51.100.9", 5.0), 20.0);
}

#endif // DASH_PEER_BAN_BASE_REVISION
