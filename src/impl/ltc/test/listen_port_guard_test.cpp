// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC addrme listen-port guard KAT, issue #925 part (b).
//
// Canonical p2pool-merged-v36 (7bd23583) p2p.py:127 advertises only
// `if self.node.serverfactory.listen_port is not None`. ltc's handle_version
// read core::Server::listen_port() unconditionally, and that accessor is
// m_acceptor->local_endpoint().port() with no guard (core/factory.hpp:270).
//
// LTC has one production path that leaves the node running with no listener.
// main_ltc.cpp:3892 calls core::Server::listen(p2p_port) and carries on. If
// the bind fails (port in use, no permission), bind_listener closes the
// acceptor (factory.hpp:111, 119) and listen() logs and returns
// (factory.hpp:256-260). The node keeps dialing out. Every outbound handshake
// then reaches the addrme write, local_endpoint() throws
// boost::system::system_error (bad_descriptor), and the throw leaves
// handle_version, so the peer is dropped. The result is a node that runs but
// can never hold a single sharechain peer.
//
// These cases use REAL types, not mocks. They build a real ltc::Node on a real
// io_context, put it through the real core::Server::listen() bind-failure path
// on a port that is already taken, and run the real NodeImpl::handle_version
// over a real accepted TCP socket. The bytes the peer receives are read off
// the far end of the socket and parsed frame by frame.
//
//   BindFailureKeepsTheHandshakeAndSkipsAddrme   FAILS without the fix
//   ListeningNodeAdvertisesItsBoundPort          passes both: positive control
//
// FOLDED into the EXISTING allowlisted share_test target (#769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unistd.h>
#include <thread>
#include <vector>

namespace {

using boost::asio::ip::tcp;

const std::vector<std::byte>& test_prefix()
{
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

struct StubCommunicator : public core::ICommunicator
{
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

// Real TCP pair. `ours` is wrapped in the core::Socket handed to the handler;
// `theirs` is the remote peer, read back to see exactly what we sent.
//
// The io_context is NOT owned here. handle_version keeps the peer in the
// node's m_peers map (ltc/node.cpp:351), so the core::Socket wrapping `ours`
// lives until the node is destroyed. An io_context owned by SocketPair died
// when handshake() returned, and the node's teardown then destroyed a socket
// whose reactive_socket_service was already freed (heap-use-after-free under
// ASan). The fixture owns this context and declares it before m_node so it
// outlives every socket the node retains.
struct SocketPair
{
    boost::asio::io_context& ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    explicit SocketPair(boost::asio::io_context& ctx) : ioc(ctx)
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.2"), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

struct Frame
{
    std::string command;
    std::vector<std::byte> payload;
};

// Split the byte stream into [prefix 4][command 12][length 4][checksum 4]
// [payload] frames (core/packet.hpp from_message).
std::vector<Frame> parse_frames(const std::vector<std::byte>& buf)
{
    std::vector<Frame> out;
    const size_t P = test_prefix().size();
    size_t off = 0;
    while (off + P + 12 + 4 + 4 <= buf.size())
    {
        if (std::memcmp(buf.data() + off, test_prefix().data(), P) != 0)
            break;
        const char* cmd = reinterpret_cast<const char*>(buf.data() + off + P);
        Frame f;
        f.command.assign(cmd, strnlen(cmd, 12));
        uint32_t len = 0;
        std::memcpy(&len, buf.data() + off + P + 12, 4);
        const size_t body = off + P + 12 + 4 + 4;
        if (body + len > buf.size())
            break;
        f.payload.assign(buf.begin() + body, buf.begin() + body + len);
        out.push_back(std::move(f));
        off = body + len;
    }
    return out;
}

struct HandshakeResult
{
    bool threw = false;
    std::string what;
    std::optional<pool::PeerConnectionType> verdict;
    std::vector<Frame> frames;
};

HandshakeResult handshake(ltc::Node& node, boost::asio::io_context& peer_ioc)
{
    SocketPair pair(peer_ioc);
    StubCommunicator stub;
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();
    auto peer = std::make_shared<ltc::NodeImpl::peer_t>(sock);

    // A foreign nonce at the advertised version: this passes the self check
    // and the min-version floor, so handle_version reaches the addrme write.
    auto rmsg = ltc::message_version::make_raw(
        ltc::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 1,
        addr_t{1, NetService{"0.0.0.0", 0}},
        addr_t{1, NetService{"0.0.0.0", ltc::PoolConfig::P2P_PORT}},
        /*nonce=*/0x0123'4567'89ab'cdefull, std::string("/c2pool:test/"), 1, uint256{});

    HandshakeResult r;
    try {
        r.verdict = node.handle_version(std::move(rmsg), peer);
    } catch (const std::exception& e) {
        r.threw = true;
        r.what = e.what();
    }

    // Drain our queued writes, then read whatever reached the far end.
    for (int i = 0; i < 50; ++i) {
        pair.ioc.poll();
        pair.ioc.restart();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    std::vector<std::byte> buf;
    pair.theirs->non_blocking(true);
    for (;;) {
        std::byte chunk[65536];
        boost::system::error_code ec;
        size_t n = pair.theirs->read_some(boost::asio::buffer(chunk), ec);
        if (ec || n == 0) break;
        buf.insert(buf.end(), chunk, chunk + n);
    }
    r.frames = parse_frames(buf);
    return r;
}

const Frame* find(const std::vector<Frame>& fs, const std::string& cmd)
{
    for (const auto& f : fs)
        if (f.command == cmd) return &f;
    return nullptr;
}

class LtcListenPortGuard : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-925b-listenport-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        core::filesystem::set_data_dir(m_dir);
        m_config = std::make_unique<ltc::Config>("ltc_925b_test");
        m_config->m_testnet = false;
        m_config->pool()->m_bootstrap_addrs.clear();
        m_node = std::make_unique<ltc::Node>(&m_ioc, m_config.get());
    }
    void TearDown() override
    {
        m_node.reset();
        m_config.reset();
        core::filesystem::set_data_dir(m_prev);
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    boost::asio::io_context m_ioc;
    // Owns the test peer sockets. Declared before m_node so it is destroyed
    // after it: the node keeps those sockets alive in m_peers.
    boost::asio::io_context m_peer_ioc;
    std::unique_ptr<ltc::Config> m_config;
    std::unique_ptr<ltc::Node> m_node;

private:
    std::filesystem::path m_prev;
    std::filesystem::path m_dir;
};

} // namespace

TEST_F(LtcListenPortGuard, BindFailureKeepsTheHandshakeAndSkipsAddrme)
{
    // Take a port on the IPv4 and IPv6 wildcards, listening, so the node's own
    // listen() cannot bind it in either family.
    boost::asio::io_context squat_ioc;
    tcp::acceptor squat4(squat_ioc, tcp::endpoint(tcp::v4(), 0));
    squat4.listen();
    const uint16_t taken = squat4.local_endpoint().port();
    std::optional<tcp::acceptor> squat6;
    try {
        squat6.emplace(squat_ioc);
        squat6->open(tcp::v6());
        squat6->set_option(boost::asio::ip::v6_only(true));
        squat6->bind(tcp::endpoint(tcp::v6(), taken));
        squat6->listen();
    } catch (...) { squat6.reset(); }  // host without IPv6: the v4 squat suffices

    // The real production call (main_ltc.cpp:3892). It logs and returns.
    m_node->core::Server::listen(taken);

    // Precondition: the node really is in the not-listening state.
    ASSERT_FALSE(m_node->listen_port_or_none().has_value())
        << "bind should have failed on port " << taken;

    const auto r = handshake(*m_node, m_peer_ioc);

    EXPECT_FALSE(r.threw)
        << "handle_version threw (" << r.what << "): the unguarded listen_port() "
           "drops every peer of a node whose bind failed";
    ASSERT_TRUE(r.verdict.has_value());
    EXPECT_EQ(*r.verdict, pool::PeerConnectionType::legacy);

    EXPECT_NE(find(r.frames, "getaddrs"), nullptr)
        << "the handshake still sends getaddrs";
    EXPECT_EQ(find(r.frames, "addrme"), nullptr)
        << "canonical merged-v36 p2p.py:127 sends no addrme when listen_port is None";
}

TEST_F(LtcListenPortGuard, ListeningNodeAdvertisesItsBoundPort)
{
    m_node->core::Server::listen(0);  // ephemeral, always bindable
    const auto port = m_node->listen_port_or_none();
    ASSERT_TRUE(port.has_value());
    ASSERT_NE(*port, 0);

    const auto r = handshake(*m_node, m_peer_ioc);
    ASSERT_FALSE(r.threw) << r.what;
    ASSERT_TRUE(r.verdict.has_value());

    const Frame* addrme = find(r.frames, "addrme");
    ASSERT_NE(addrme, nullptr) << "a listening node must advertise itself";
    ASSERT_EQ(addrme->payload.size(), 2u);
    uint16_t advertised = 0;
    std::memcpy(&advertised, addrme->payload.data(), 2);  // little-endian on the wire
    EXPECT_EQ(advertised, *port) << "addrme carries the port we actually bound";
}
