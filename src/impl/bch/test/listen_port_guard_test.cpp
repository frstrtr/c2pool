// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCH addrme listen-port guard KAT, issue #925 part (b).
//
// The bch canonical is frstrtr/p2poolBCH @6603b79 (the conformance anchor named
// in protocol_legacy.cpp and config_pool.hpp). p2pool/p2p.py:113
// sendAdvertisement advertises only `if self.node.serverfactory.listen_port is
// not None`. bch's handle_version read core::Server::listen_port()
// unconditionally, and that accessor is m_acceptor->local_endpoint().port()
// with no guard (core/factory.hpp:359).
//
// BCH has one production listen site. pool_entrypoint.hpp:214 calls
// node.core::Server::listen(PoolConfig::P2P_PORT) and carries on. If the bind
// fails (port in use, no permission), bind_listener closes the acceptor and
// listen() logs and returns (factory.hpp:318-323). The entrypoint then calls
// start_outbound_connections() (pool_entrypoint.hpp:219), so the node keeps
// dialing out. Every outbound handshake reaches the addrme write,
// local_endpoint() throws boost::system::system_error (bad_descriptor), and the
// throw leaves handle_version, so the peer is dropped. The result is a node
// that runs but can never hold a single sharechain peer.
//
// These cases use REAL types, not mocks. They build a real bch::Node on a real
// io_context, put it through the real core::Server::listen() bind-failure path
// on a port that is already taken, and run the real NodeImpl::handle_version
// over a real accepted TCP socket. The bytes the peer receives are read off
// the far end of the socket and parsed frame by frame.
//
//   BindFailureKeepsTheHandshakeAndSkipsAddrme   FAILS without the fix
//   ListeningNodeAdvertisesItsBoundPort          passes both: positive control
//
// HARNESS: the bch test tree is plain int main()/CHECK (no GTest), so this TU
// exposes run_listen_port_guard_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable, which compiles the real
// node.cpp TU and the two config TUs. No new add_executable, so no "Not Run"
// (#769) trap.

#include <impl/bch/node.hpp>
#include <impl/bch/messages.hpp>
#include <impl/bch/config.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

using boost::asio::ip::tcp;

int g_failures = 0;
int g_case_failures = 0;

// EXPECT-style: record and continue. REQUIRE-style: record and leave the case,
// for preconditions the rest of the case depends on.
#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; } } while (0)
#define REQUIRE(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; return; } } while (0)

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

// A node's AddrStore is file-backed, so each case gets a private data dir.
// Construct it BEFORE the node.
class PrivateDataDir
{
public:
    PrivateDataDir()
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-925b-bch-listenport-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        core::filesystem::set_data_dir(m_dir);
    }
    ~PrivateDataDir()
    {
        core::filesystem::set_data_dir(m_prev);
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

private:
    std::filesystem::path m_prev;
    std::filesystem::path m_dir;
};

// A real node on a real io_context, as the entrypoint builds it. NodeImpl is a
// virtual base of bch::Node, so the most-derived class constructs it. A
// rig-free (default-constructed) node has an EMPTY acceptor, where
// listen_port() is undefined behaviour rather than the production throw; the
// (ctx, config) ctor gives the engaged-but-closed acceptor of a failed bind.
class LiveNode : public bch::Node
{
public:
    LiveNode(boost::asio::io_context* ctx, bch::Config* cfg)
        : bch::NodeImpl(ctx, cfg), bch::Node(ctx, cfg) {}
};

// Real TCP pair. `ours` is wrapped in the core::Socket handed to the handler;
// `theirs` is the remote peer, read back to see exactly what we sent.
//
// The io_context is NOT owned here. handle_version keeps the peer in the
// node's m_peers map, so the core::Socket wrapping `ours` lives until the node
// is destroyed. Each case owns that context and declares it before the node so
// it outlives every socket the node retains (the ltc #2129 ASan
// heap-use-after-free, fixed the same way).
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

HandshakeResult handshake(LiveNode& node, boost::asio::io_context& peer_ioc)
{
    SocketPair pair(peer_ioc);
    StubCommunicator stub;
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();
    auto peer = std::make_shared<bch::NodeImpl::peer_t>(sock);

    // A foreign nonce at the advertised version: this passes the self check
    // and the min-version floor, so handle_version reaches the addrme write.
    auto rmsg = bch::message_version::make_raw(
        bch::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 1,
        addr_t{1, NetService{"0.0.0.0", 0}},
        addr_t{1, NetService{"0.0.0.0", bch::PoolConfig::P2P_PORT}},
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

void BindFailureKeepsTheHandshakeAndSkipsAddrme()
{
    PrivateDataDir dir;
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

    bch::Config config("bch");
    boost::asio::io_context ioc;
    // Owns the test peer sockets. Declared before the node so it is destroyed
    // after it: the node keeps those sockets alive in m_peers.
    boost::asio::io_context peer_ioc;
    LiveNode node(&ioc, &config);

    // The real production call (pool_entrypoint.hpp:214). It logs and returns.
    node.core::Server::listen(taken);

    // Precondition: the node really is in the not-listening state.
    REQUIRE(!node.listen_port_or_none().has_value(),
            "bind should have failed on port " << taken);

    const auto r = handshake(node, peer_ioc);

    CHECK(!r.threw,
          "handle_version threw (" << r.what << "): the unguarded listen_port() "
          "drops every peer of a node whose bind failed");
    REQUIRE(r.verdict.has_value(), "the handshake must complete");
    CHECK(*r.verdict == pool::PeerConnectionType::legacy, "legacy verdict at the advertised version");

    CHECK(find(r.frames, "getaddrs") != nullptr, "the handshake still sends getaddrs");
    CHECK(find(r.frames, "addrme") == nullptr,
          "canonical p2poolBCH p2p.py:113 sends no addrme when listen_port is None");
}

void ListeningNodeAdvertisesItsBoundPort()
{
    PrivateDataDir dir;
    bch::Config config("bch");
    boost::asio::io_context ioc;
    boost::asio::io_context peer_ioc;
    LiveNode node(&ioc, &config);

    node.core::Server::listen(0);  // ephemeral, always bindable
    const auto port = node.listen_port_or_none();
    REQUIRE(port.has_value(), "listen(0) must bind");
    REQUIRE(*port != 0, "an ephemeral bind reports its real port");

    const auto r = handshake(node, peer_ioc);
    REQUIRE(!r.threw, r.what);
    REQUIRE(r.verdict.has_value(), "the handshake must complete");

    const Frame* addrme = find(r.frames, "addrme");
    REQUIRE(addrme != nullptr, "a listening node must advertise itself");
    REQUIRE(addrme->payload.size() == 2u, "addrme payload is one uint16 port");
    uint16_t advertised = 0;
    std::memcpy(&advertised, addrme->payload.data(), 2);  // little-endian on the wire
    CHECK(advertised == *port,
          "addrme carries the port we actually bound: got " << advertised << " want " << *port);
}

void run_case(const char* name, void (*fn)())
{
    g_case_failures = 0;
    try {
        fn();
    } catch (const std::exception& e) {
        std::cerr << "  FAIL: threw: " << e.what() << "\n";
        ++g_case_failures;
    }
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchListenPortGuard."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_listen_port_guard_checks()
{
    g_failures = 0;
    run_case("BindFailureKeepsTheHandshakeAndSkipsAddrme",
             BindFailureKeepsTheHandshakeAndSkipsAddrme);
    run_case("ListeningNodeAdvertisesItsBoundPort", ListeningNodeAdvertisesItsBoundPort);
    return g_failures;
}
