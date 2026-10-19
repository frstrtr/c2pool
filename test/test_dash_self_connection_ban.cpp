// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #1716 part B -- a DASH sharechain self-connection is dropped, counted per
// non-loopback host, and the 4th inside 600 s bans that host for 300 s.
//
// Canonical: frstrtr/p2pool-dash @81bf1618 p2pool/p2p.py:168-206. A version
// carrying our own nonce is dropped. A loopback one (127.0.0.0/8, ::1) is only
// dropped, never counted or banned (:179-183, p2pool-dash #757). Any other
// host is counted; a count resets once its first attempt is more than 600 s
// old; the attempt that finds 3 already counted bans the host for a flat
// 300 s. The base revision dropped every self-connection uncounted, so the
// endpoint was redialled on every maintenance pass.
//
// Every KAT runs the REAL dash::Node. The connection is attached through the
// real NodeImpl::connected() over a TCP socket, and the version goes through
// the real NodeBridge::handle() (pool/node.hpp), the entry the socket read
// loop calls. "Dropped" means close_connection() ran and the far end read
// EOF. "Refused" means connected() closed a new socket from the same host
// before any handshake. Because loopback is exempt, the ban KATs connect over
// this machine's first non-loopback IPv4 interface address.
//
// Red on the base revision: build this TU with DASH_SELF_BAN_BASE_REVISION
// defined (it fences out the clock seam). The ban KATs fail there; the two
// loopback/foreign guards pass there too.
//
// Folded into the EXISTING allowlisted test_dash_node target; a standalone
// add_executable would be missing from the build.yml --target list and report
// "Not Run".

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <impl/dash/messages.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#ifndef _WIN32
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

const std::vector<std::byte>& self_ban_prefix()
{
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

struct SelfBanStub : public core::ICommunicator
{
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return self_ban_prefix(); }
};

// One loopback TCP connection whose far end listens on `host`. The node sees
// the peer at host:<ephemeral port>, a new port per connection.
struct HostPair
{
    boost::asio::io_context ioc_peer, ioc_node;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ip::tcp::socket> theirs, ours;
    explicit HostPair(const std::string& host)
    {
        using boost::asio::ip::tcp;
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_peer, tcp::endpoint(boost::asio::ip::make_address(host), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc_node);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

struct SelfBanIoThread
{
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
    std::thread thread;
    explicit SelfBanIoThread(boost::asio::io_context& ioc)
        : guard(boost::asio::make_work_guard(ioc)), thread([&ioc] { ioc.run(); }) {}
    void stop(boost::asio::io_context& ioc)
    {
        guard.reset();
        ioc.stop();
        if (thread.joinable()) thread.join();
    }
};

// A manual clock for the 600 s window: fixed origin plus whatever the KAT
// advanced, so a boundary assertion does not race the real clock.
struct WindowClock
{
    std::chrono::steady_clock::time_point origin = std::chrono::steady_clock::now();
    std::shared_ptr<std::chrono::steady_clock::duration> offset =
        std::make_shared<std::chrono::steady_clock::duration>(0);
    std::function<std::chrono::steady_clock::time_point()> fn() const
    {
        return [o = origin, off = offset] { return o + *off; };
    }
    void advance(std::chrono::seconds s) { *offset += s; }
};

struct SelfBanProbe : dash::Node
{
    SelfBanProbe(boost::asio::io_context* ctx, dash::Config* cfg)
        : dash::NodeImpl(ctx, cfg), dash::Node(ctx, cfg) {}
    uint64_t own_nonce() const { return m_nonce; }
    bool has_connection(const NetService& a) const { return m_connections.contains(a); }
    dash::NodeImpl::peer_ptr connection(const NetService& a)
    {
        auto it = m_connections.find(a);
        return it == m_connections.end() ? nullptr : it->second;
    }
    // Seconds left on the host-keyed ban, or -1 when there is none.
    long long ip_ban_left_s(const std::string& host) const
    {
        auto it = m_ip_ban_list.find(host);
        if (it == m_ip_ban_list.end()) return -1;
        return std::chrono::duration_cast<std::chrono::seconds>(
            it->second - std::chrono::steady_clock::now()).count();
    }
#ifndef DASH_SELF_BAN_BASE_REVISION
    void set_window_clock(std::function<std::chrono::steady_clock::time_point()> f)
    {
        m_self_nonce_now = std::move(f);
    }
    // The think-cycle sweep (node.cpp prune call), run directly.
    void prune_self_nonce() { prune_self_nonce_attempts(); }
    std::size_t self_nonce_hosts() const { return m_self_nonce_attempts.size(); }
#endif
};

struct Conn
{
    HostPair pair;
    NetService addr;
    dash::NodeImpl::peer_ptr peer;   // null when connected() refused it
    explicit Conn(const std::string& host) : pair(host) {}
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

std::string unique_config_name(const char* tag)
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::string("dash-selfban-kat-") + tag + "-" + std::to_string(ticks);
}

struct Rig
{
    boost::asio::io_context ioc;
    std::string name;
    dash::Config cfg;
    SelfBanStub stub;
    std::vector<std::unique_ptr<Conn>> conns;   // outlive the node (their sockets live in it)
    std::unique_ptr<SelfBanProbe> node;

    explicit Rig(const char* tag) : name(unique_config_name(tag)), cfg{name}
    {
        node = std::make_unique<SelfBanProbe>(&ioc, &cfg);
    }
    ~Rig()
    {
        node->join_compute_pools();
        ioc.restart();
        ioc.poll();
        node->shutdown_persistence();
        for (auto& c : conns) c->peer.reset();
        node.reset();
        ioc.restart();
        ioc.poll();   // run the deferred peer releases while the sockets' contexts live
        conns.clear();
        std::error_code ec;
        std::filesystem::remove_all(core::filesystem::config_path() / name, ec);
    }

    // A new inbound-style connection from `host`, through the real connected().
    Conn& attach(const std::string& host = "127.0.0.1")
    {
        conns.push_back(std::make_unique<Conn>(host));
        Conn& c = *conns.back();
        auto sock = std::make_shared<core::Socket>(
            std::move(c.pair.ours), core::outgoing, &stub,
            std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
        sock->init();
        c.addr = sock->get_addr();
        node->connected(sock);
        c.peer = node->connection(c.addr);
        return c;
    }

    // The peer's version, through the real NodeBridge::handle().
    void version(Conn& c, uint64_t nonce)
    {
        const uint32_t proto = dash::SharechainConfig::share_profile().advertised_protocol_version;
        auto msg = dash::message_version::make_raw(
            proto, uint64_t{0},
            addr_t(1u, NetService("203.0.113.1", 9999)),
            addr_t(1u, NetService("203.0.113.2", 8888)),
            nonce, std::string("c2pool-dash-selfban-kat"), 1u, uint256());
        SelfBanIoThread io(c.pair.ioc_node);
        node->handle(std::move(msg), c.addr);
        io.stop(c.pair.ioc_node);
    }

    bool connected(const Conn& c) const { return node->has_connection(c.addr); }

    // One self-dial: attach, send our own nonce, and check it was dropped.
    Conn& self_dial(const std::string& host = "127.0.0.1")
    {
        Conn& c = attach(host);
        EXPECT_TRUE(c.peer) << "a self-dial from an unbanned host must reach the handshake";
        if (c.peer) {
            version(c, node->own_nonce());
            EXPECT_FALSE(connected(c)) << "a self-connection is always dropped (p2p.py:182, :205)";
            EXPECT_TRUE(far_end_closed(c, 1000ms));
        }
        return c;
    }
};

bool can_bind(const std::string& host)
{
    boost::asio::io_context ioc;
    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor a(ioc);
    a.open(boost::asio::ip::tcp::v4(), ec);
    if (!ec) a.bind({boost::asio::ip::make_address(host, ec), 0}, ec);
    return !ec;
}

// The first up, non-loopback IPv4 interface address that this process can
// bind and connect to, or "" if there is none. A connection to it never leaves
// the machine, but the node sees a non-loopback peer host.
std::string non_loopback_ipv4()
{
#ifndef _WIN32
    ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0) return {};
    std::string found;
    for (ifaddrs* i = ifs; i && found.empty(); i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
        char buf[INET_ADDRSTRLEN] = {};
        const auto* sin = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
        if (!inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) continue;
        const std::string ip = buf;
        if (classify_address(ip) == AddrClass::loopback) continue;
        try {
            HostPair probe(ip);   // bind + connect + accept, as a Conn will
            found = ip;
        } catch (const std::exception&) {}
    }
    freeifaddrs(ifs);
    return found;
#else
    return {};
#endif
}

#define REQUIRE_NON_LOOPBACK(var)                                              \
    const std::string var = non_loopback_ipv4();                               \
    if (var.empty())                                                           \
        GTEST_SKIP() << "no bindable non-loopback IPv4 interface on this host"

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// 1. Canonical tolerates 3 self-dials from one non-loopback host inside 600 s.
//    The 4th is dropped AND bans the host for a flat 300 s. The ban is on the
//    host: a new connection from another port is refused before the
//    handshake, and the dialer's is_banned() check covers every port.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, FourthSelfDialInsideWindowBansHost)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("fourth");
    for (int i = 1; i <= 3; ++i) {
        Conn& c = rig.self_dial(host);
        EXPECT_FALSE(rig.node->is_banned(c.addr))
            << "self-dial " << i << " of 3 is tolerated (p2p.py:195 `count >= 3`)";
    }

    Conn& c4 = rig.self_dial(host);
    EXPECT_TRUE(rig.node->is_banned(c4.addr))
        << "the 4th self-dial inside 600 s must ban the host (p2p.py:195-199)";
    const long long left = rig.node->ip_ban_left_s(host);
    EXPECT_GT(left, 290) << "flat 300 s ban (p2p.py:197)";
    EXPECT_LE(left, 300) << "flat 300 s ban (p2p.py:197), not 3600*banscore^2";
    EXPECT_TRUE(rig.node->is_banned(NetService(host, 8999)))
        << "the ban is on the host, so the dialer skips it on any port";

    Conn& c5 = rig.attach(host);
    EXPECT_FALSE(c5.peer) << "a new connection from the banned host must be refused";
    EXPECT_FALSE(rig.connected(c5));
    EXPECT_TRUE(far_end_closed(c5, 1000ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The window. A count whose first attempt is more than 600 s old is reset
//    (p2p.py:186-189), so 3 self-dials, a gap past 600 s, then 3 more do not
//    ban; the 4th of the new window does.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, CountResetsAfterWindow)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("window");
    WindowClock clk;
#ifndef DASH_SELF_BAN_BASE_REVISION
    rig.node->set_window_clock(clk.fn());
#endif
    for (int i = 0; i < 3; ++i) rig.self_dial(host);
    clk.advance(601s);
    for (int i = 1; i <= 3; ++i) {
        Conn& c = rig.self_dial(host);
        EXPECT_FALSE(rig.node->is_banned(c.addr))
            << "attempt " << i << " after the window lapsed starts a new count";
    }
    Conn& c = rig.self_dial(host);
    EXPECT_TRUE(rig.node->is_banned(c.addr)) << "the 4th of the new window bans";
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The window edge is strict (`now - first_time > 600`, p2p.py:188): an
//    attempt exactly 600 s after the first still counts against it.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, WindowEdgeIsStrict)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("edge");
    WindowClock clk;
#ifndef DASH_SELF_BAN_BASE_REVISION
    rig.node->set_window_clock(clk.fn());
#endif
    for (int i = 0; i < 3; ++i) rig.self_dial(host);
    clk.advance(600s);
    Conn& c = rig.self_dial(host);
    EXPECT_TRUE(rig.node->is_banned(c.addr))
        << "600 s is still inside the window, so this is the 4th and bans";
}

// ─────────────────────────────────────────────────────────────────────────────
// 3b. The think-cycle prune uses the same strict edge. A sweep at exactly
//     600 s keeps the count, so the 4th still bans; a sweep at 601 s drops it.
//     Without this the prune comparison is unpinned: flipping it to >= left
//     every other KAT green, yet in production a sweep landing on the edge
//     would erase the count before the 4th arrived.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, PruneWindowEdgeIsStrict)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("prune-edge");
    WindowClock clk;
#ifndef DASH_SELF_BAN_BASE_REVISION
    rig.node->set_window_clock(clk.fn());
#endif
    for (int i = 0; i < 3; ++i) rig.self_dial(host);
    clk.advance(600s);
#ifndef DASH_SELF_BAN_BASE_REVISION
    rig.node->prune_self_nonce();
    EXPECT_EQ(rig.node->self_nonce_hosts(), 1u) << "a sweep at 600 s keeps the count";
#endif
    Conn& c = rig.self_dial(host);
    EXPECT_TRUE(rig.node->is_banned(c.addr))
        << "the count survived the 600 s sweep, so this is the 4th and bans";
#ifndef DASH_SELF_BAN_BASE_REVISION
    clk.advance(1s);
    rig.node->prune_self_nonce();
    EXPECT_EQ(rig.node->self_nonce_hosts(), 0u) << "a sweep at 601 s drops it";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Counts are per host and loopback is never counted: loopback self-dials
//    in between do not move a non-loopback host's count, and the host's own
//    4th bans it and nothing else.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, LoopbackDialsDoNotAddToAHostCount)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("perhost");
    for (int i = 0; i < 3; ++i) rig.self_dial(host);
    for (int i = 0; i < 5; ++i) rig.self_dial("127.0.0.1");
    EXPECT_FALSE(rig.node->is_banned(NetService(host, 1)));
    Conn& c = rig.self_dial(host);
    EXPECT_TRUE(rig.node->is_banned(c.addr)) << "the host's own 4th bans it";
    EXPECT_FALSE(rig.node->is_banned(NetService("127.0.0.1", 1))) << "and only it";
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Guard (green on the base revision too): loopback is never banned
//    (p2p.py:179-183). Six self-dials from 127.0.0.1, and four from
//    127.0.0.2 where bindable (canonical exempts all of 127.0.0.0/8), are all
//    dropped, nothing is banned, and a real peer on 127.0.0.1 is still
//    admitted afterwards.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, LoopbackIsNeverCountedOrBanned)
{
    Rig rig("loopback");
    for (int i = 0; i < 6; ++i) {
        Conn& c = rig.self_dial("127.0.0.1");
        EXPECT_FALSE(rig.node->is_banned(c.addr)) << "loopback self-dial " << i + 1;
    }
    if (can_bind("127.0.0.2")) {
        for (int i = 0; i < 4; ++i) rig.self_dial("127.0.0.2");
        EXPECT_FALSE(rig.node->is_banned(NetService("127.0.0.2", 1)));
    }
    Conn& peer = rig.attach("127.0.0.1");
    ASSERT_TRUE(peer.peer) << "a co-located peer must not be refused (p2pool-dash #757)";
    rig.version(peer, rig.node->own_nonce() ^ 0x1716ULL);
    EXPECT_TRUE(rig.connected(peer));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Guard (green on the base revision too): another node's nonce is never
//    counted. Five handshakes with distinct foreign nonces are all admitted
//    and nothing is banned.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashSelfConnectionBan, ForeignNonceIsNeverCounted)
{
    REQUIRE_NON_LOOPBACK(host);
    Rig rig("foreign");
    const uint64_t self = rig.node->own_nonce();
    for (uint64_t i = 1; i <= 5; ++i) {
        Conn& c = rig.attach(host);
        ASSERT_TRUE(c.peer);
        const uint64_t foreign = self ^ (0x1716'0000ULL + i);
        rig.version(c, foreign);
        EXPECT_TRUE(rig.connected(c)) << "a foreign-nonce handshake " << i << " is admitted";
        EXPECT_FALSE(rig.node->is_banned(c.addr));
    }
}
