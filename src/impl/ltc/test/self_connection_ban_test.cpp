// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC self-connection ban KAT, issue #1716 part B.
//
// Part A fixed the addrme self-probe compare. Part B is what happens after the
// node dials its own public endpoint and the version handshake reveals our own
// nonce. Canonical jtoomim/p2pool p2pool/p2p.py:160-161 raises
// PeerMisbehavingError('was connected to self'). packetReceived (:92-94) turns
// that into badPeerHappened() (:96-105), which bans the HOST, never 127.0.0.1,
// for 3600 * banscore^2 seconds. Both the dial loop (_think, :648) and the
// acceptor (buildProtocol, :548) skip a banned host.
//
// Before this fix ltc's handle_version returned nullopt with no ban. The
// endpoint stayed dialable and was redialled on every think tick.
//
// These cases use REAL types, not mocks. They drive the real
// ltc::NodeImpl::handle_version with a peer built from a real accepted TCP
// socket bound to 127.0.0.2. That address is loopback to the OS, so it binds
// without privilege, but it is not the 127.0.0.1 that canonical exempts.
//
//   SelfNonceBansTheHost                   FAILS without the fix
//   RepeatSelfConnectionEscalatesQuadratically   FAILS without the fix
//   LoopbackSelfConnectionIsNeverBanned    passes both: the canonical exemption
//   ForeignNonceIsNotBanned                passes both: only the self arm bans
//
// FOLDED into the EXISTING allowlisted share_test target (#769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
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

// Real TCP pair. `ours` is the end wrapped in the core::Socket handed to the
// handler, so peer->addr() is latched from the real remote endpoint.
struct SocketPair
{
    boost::asio::io_context ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    explicit SocketPair(const std::string& bind_addr)
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc, tcp::endpoint(boost::asio::ip::make_address(bind_addr), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

// ltc::Legacy is abstract on its own: the raw-frame entry is supplied by
// pool::NodeBridge in production, so it is stubbed here. handle_version and
// is_banned are the real NodeImpl / SharechainNode members.
class Probe : public ltc::Legacy
{
public:
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    void set_nonce(uint64_t n) { this->m_nonce = n; }

    // Seconds until the host-level ban on `ip` expires, or 0 if none.
    long long ban_seconds_left(const std::string& ip) const
    {
        auto it = this->m_ip_ban_list.find(ip);
        if (it == this->m_ip_ban_list.end()) return 0;
        return std::chrono::duration_cast<std::chrono::seconds>(
            it->second - std::chrono::steady_clock::now()).count();
    }
};

ltc::NodeImpl::peer_ptr make_socket_peer(SocketPair& pair, StubCommunicator& stub)
{
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();
    return std::make_shared<ltc::NodeImpl::peer_t>(sock);
}

std::unique_ptr<RawMessage> version_with_nonce(
    uint64_t nonce, uint32_t version = ltc::PoolConfig::ADVERTISED_PROTOCOL_VERSION)
{
    return ltc::message_version::make_raw(
        version, 1,
        addr_t{1, NetService{"0.0.0.0", 0}},
        addr_t{1, NetService{"0.0.0.0", ltc::PoolConfig::P2P_PORT}},
        nonce, std::string("/c2pool:test/"), 1, uint256{});
}

// One handshake on a fresh socket from bind_addr. Returns handle_version's
// verdict; the peer's own address is written to *peer_ip.
std::optional<pool::PeerConnectionType>
handshake(Probe& node, const std::string& bind_addr, uint64_t their_nonce,
          std::string* peer_ip = nullptr,
          uint32_t their_version = ltc::PoolConfig::ADVERTISED_PROTOCOL_VERSION)
{
    SocketPair pair(bind_addr);
    StubCommunicator stub;
    auto peer = make_socket_peer(pair, stub);
    if (peer_ip) *peer_ip = peer->addr().address();
    return node.handle_version(version_with_nonce(their_nonce, their_version), peer);
}

constexpr uint64_t kOurNonce   = 0x5e1f'5e1f'5e1f'5e1full;
constexpr uint64_t kOtherNonce = 0x0123'4567'89ab'cdefull;
constexpr long long kSlack     = 60;  // seconds of scheduling headroom

// A default-constructed node's AddrStore is file-backed, so each case gets a
// private data dir (same isolation as legacy_addrme_self_probe_test.cpp).
class LtcSelfConnectionBan : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-1716b-selfban-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        core::filesystem::set_data_dir(m_dir);
    }
    void TearDown() override
    {
        core::filesystem::set_data_dir(m_prev);
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

private:
    std::filesystem::path m_prev;
    std::filesystem::path m_dir;
};

} // namespace

TEST_F(LtcSelfConnectionBan, SelfNonceBansTheHost)
{
    Probe node;
    node.set_nonce(kOurNonce);

    std::string ip;
    auto verdict = handshake(node, "127.0.0.2", kOurNonce, &ip);
    ASSERT_EQ(ip, "127.0.0.2");

    EXPECT_FALSE(verdict.has_value()) << "a self-connection must still be refused";

    // Host-level, as canonical: the dial loop and the acceptor both consult
    // is_banned(), and the redial targets the same host on any port.
    EXPECT_TRUE(node.is_banned(NetService{std::string("127.0.0.2"), ltc::PoolConfig::P2P_PORT}))
        << "canonical p2p.py:160-161 -> badPeerHappened bans the self host";
    EXPECT_TRUE(node.is_banned(NetService{std::string("127.0.0.2"), 40123}))
        << "the ban is per host, not per host:port";

    const auto left = node.ban_seconds_left("127.0.0.2");
    EXPECT_GE(left, 3600 - kSlack) << "first offence: 3600 * 1^2";
    EXPECT_LE(left, 3600 + kSlack);
}

TEST_F(LtcSelfConnectionBan, RepeatSelfConnectionEscalatesQuadratically)
{
    Probe node;
    node.set_nonce(kOurNonce);

    handshake(node, "127.0.0.2", kOurNonce);
    handshake(node, "127.0.0.2", kOurNonce);

    // A real self-dial trips BOTH ends (outbound and inbound) of the same
    // connection, so canonical reaches score 2 on the first dial. The KAT pins
    // the per-offence rule, 3600 * n^2, not the per-dial count.
    const auto left = node.ban_seconds_left("127.0.0.2");
    EXPECT_GE(left, 4 * 3600 - kSlack) << "second offence: 3600 * 2^2";
    EXPECT_LE(left, 4 * 3600 + kSlack);

    handshake(node, "127.0.0.2", kOurNonce);
    EXPECT_GE(node.ban_seconds_left("127.0.0.2"), 9 * 3600 - kSlack)
        << "third offence: 3600 * 3^2";
}

TEST_F(LtcSelfConnectionBan, LoopbackSelfConnectionIsNeverBanned)
{
    Probe node;
    node.set_nonce(kOurNonce);

    std::string ip;
    auto verdict = handshake(node, "127.0.0.1", kOurNonce, &ip);
    ASSERT_EQ(ip, "127.0.0.1");

    EXPECT_FALSE(verdict.has_value());
    EXPECT_FALSE(node.is_banned(NetService{std::string("127.0.0.1"), ltc::PoolConfig::P2P_PORT}))
        << "canonical p2p.py:99 never bans localhost";
    EXPECT_EQ(node.ban_seconds_left("127.0.0.1"), 0);
}

TEST_F(LtcSelfConnectionBan, ForeignNonceIsNotBanned)
{
    Probe node;
    node.set_nonce(kOurNonce);

    // A foreign nonce must pass the self check without a ban. The peer
    // advertises a protocol below MINIMUM_PROTOCOL_VERSION, so handle_version
    // stops at the pre-insert refusal, the first exit after the self check, and
    // never reaches the addrme write. That write calls
    // core::Server::listen_port(), which on this rig-free node dereferences an
    // EMPTY std::optional acceptor. That is undefined behaviour, not a clean
    // throw: UBSan reports a null reference binding (io_object_impl.hpp:127).
    // The accessor is the unguarded one tracked in #925 and is shared core, so
    // it is out of scope here. This case covers the self-check arm only, not
    // the post-insert handshake.
    static_assert(ltc::PoolConfig::MINIMUM_PROTOCOL_VERSION > 0);
    EXPECT_THROW(handshake(node, "127.0.0.2", kOtherNonce, nullptr,
                           ltc::PoolConfig::MINIMUM_PROTOCOL_VERSION - 1),
                 std::runtime_error)
        << "an old foreign peer is refused pre-insert, not treated as self";

    EXPECT_FALSE(node.is_banned(NetService{std::string("127.0.0.2"), ltc::PoolConfig::P2P_PORT}));
    EXPECT_EQ(node.ban_seconds_left("127.0.0.2"), 0);
}
