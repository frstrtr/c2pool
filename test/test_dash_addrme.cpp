// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH addrme KAT — issue #882.
//
// Two independent defects, both proven here against the REAL code paths rather
// than against a re-implementation:
//
//  (a) DASH never ORIGINATED an addrme. dash::message_addrme was registered as a
//      handler on both generations (src/impl/dash/node.hpp:1272 Legacy,
//      :1291 Actual) but nothing in the lane ever WROTE one, while ltc
//      (node.cpp:346), btc (:346), bch (:344) and dgb (:352) all write one from
//      handle_version. A DASH peer therefore never learned our listen port from
//      us directly. `HandleVersionWritesAddrmeCarryingOurListenPort` drives the
//      real NodeImpl::handle_version over a real TCP socket and reads the frames
//      the node actually put on the wire — it sees NO addrme frame before the
//      fix.
//
//  (b) The Legacy addrme self-probe compared "127.0.0.0", the loopback NETWORK
//      address, which no peer can ever present as its source IP.
//      `LoopbackPeerPresentsHostAddressNotNetworkAddress` proves that with a
//      real accepted loopback connection, and
//      `LoopbackAddrmeIsNotRecordedAsARoutablePeer` drives the real
//      dash::Legacy::handle(message_addrme) and shows the else-arm consequence:
//      before the fix a loopback addrme was inserted into the AddrStore as a
//      routable peer and gossiped onward. Legacy is the ONLY generation live on
//      DASH today (handle_version returns legacy until the floor is ratcheted).
//
// Wire format is UNCHANGED and pinned here as well as in the pre-existing
// DashPoolNodeMessages.Message_Addrme_LayoutPinned KAT
// (test/test_dash_poolnode_messages.cpp:50).
//
// FOLDED into the EXISTING allowlisted `test_dash_node` target — a standalone
// add_executable is absent from build.yml's --target list, is never built in CI,
// and CTest then reports its cases "Not Run" (the #769 trap).

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/messages.hpp>

#include <core/factory.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using boost::asio::ip::tcp;

// Wire header written by core::Packet::from_message (src/core/packet.hpp:22):
//   prefix(N) | command(12, NUL-padded) | length(4, LE) | checksum(4) | payload
constexpr std::size_t kCommandLen  = 12;
constexpr std::size_t kLengthLen   = 4;
constexpr std::size_t kChecksumLen = 4;

const std::vector<std::byte>& test_prefix()
{
    // Arbitrary but fixed: the framing prefix is a per-net constant and is not
    // what this KAT is about. Same shape as core/test/socket_write_queue_test.cpp.
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

// Minimal ICommunicator for core::Socket. On the WRITE path the socket only
// needs get_prefix(); error() covers the failure path. Constructed with an empty
// weak_ptr<INetwork> and was_managed=false, i.e. the legacy unmanaged-node path,
// so acquire_node() short-circuits to true and no INetwork is required.
struct StubCommunicator : public core::ICommunicator
{
    std::atomic<int> error_count{0};

    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        error_count.fetch_add(1, std::memory_order_relaxed);
    }
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        error_count.fetch_add(1, std::memory_order_relaxed);
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

// Real loopback TCP pair. `ours` is the end the node writes to (wrapped in a
// core::Socket and handed to a pool::Peer); `theirs` is the peer end, read
// synchronously so the test sees exactly the bytes that went on the wire.
struct LoopbackPair
{
    boost::asio::io_context ioc_peer;
    boost::asio::io_context ioc_node;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    LoopbackPair()
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_peer, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();

        ours = std::make_unique<tcp::socket>(ioc_node);
        ours->connect(acceptor->local_endpoint());

        theirs = std::make_unique<tcp::socket>(acceptor->accept());

        boost::system::error_code ec;
        ours->set_option(tcp::no_delay(true), ec);
        theirs->set_option(tcp::no_delay(true), ec);
    }
};

// Runs an io_context on its own thread for the lifetime of the scope — the
// production shape: writes are submitted from the caller's thread and drained
// by the io thread.
struct IoThread
{
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
    std::thread thread;

    explicit IoThread(boost::asio::io_context& ioc)
        : guard(boost::asio::make_work_guard(ioc)), thread([&ioc] { ioc.run(); })
    {
    }
    void stop(boost::asio::io_context& ioc)
    {
        guard.reset();
        ioc.stop();
        if (thread.joinable()) thread.join();
    }
};

struct Frame
{
    std::string command;                 // trimmed of NUL padding
    std::vector<std::byte> payload;
};

// Drains up to `budget` bytes from a synchronous socket, stopping early once the
// socket goes quiet, then splits the stream into wire frames. Bounded by a read
// deadline so a missing message fails the assertion instead of hanging CI.
std::vector<Frame> read_frames(tcp::socket& s, std::chrono::milliseconds quiet_for)
{
    std::vector<std::byte> buf;
    const auto deadline = std::chrono::steady_clock::now() + quiet_for;

    // Non-blocking drain: poll until the deadline, accumulating whatever the
    // node wrote. There is no length prefix at the stream level to key off, so a
    // time budget is the honest stop condition.
    s.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline)
    {
        std::array<std::byte, 4096> chunk{};
        boost::system::error_code ec;
        const std::size_t n = s.read_some(boost::asio::buffer(chunk), ec);
        if (n > 0)
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
        else if (ec == boost::asio::error::would_block)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        else if (ec)
            break;
    }

    std::vector<Frame> frames;
    const std::size_t prefix_len = test_prefix().size();
    const std::size_t header = prefix_len + kCommandLen + kLengthLen + kChecksumLen;
    std::size_t off = 0;
    while (off + header <= buf.size())
    {
        // Prefix must match or the stream is not what we think it is.
        if (std::memcmp(buf.data() + off, test_prefix().data(), prefix_len) != 0)
            break;

        const auto* cmd = reinterpret_cast<const char*>(buf.data() + off + prefix_len);
        std::string command(cmd, kCommandLen);
        if (const auto z = command.find('\0'); z != std::string::npos)
            command.resize(z);

        std::uint32_t len = 0;
        std::memcpy(&len, buf.data() + off + prefix_len + kCommandLen, kLengthLen);

        if (off + header + len > buf.size())
            break;

        Frame f;
        f.command = std::move(command);
        f.payload.assign(buf.begin() + off + header, buf.begin() + off + header + len);
        frames.push_back(std::move(f));

        off += header + len;
    }
    return frames;
}

const Frame* find_frame(const std::vector<Frame>& frames, std::string_view command)
{
    for (const auto& f : frames)
        if (f.command == command) return &f;
    return nullptr;
}

// Exposes the protected AddrStore so the loopback-pollution assertion can look
// at what the handler actually recorded.
class ProbeLegacy : public dash::Legacy
{
public:
    using dash::Legacy::Legacy;
    core::AddrStore& addrs() { return m_addrs; }
    std::map<uint64_t, peer_ptr>& peers() { return m_peers; }
};

dash::NodeImpl::peer_ptr make_socket_peer(LoopbackPair& pair, StubCommunicator& stub)
{
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    // init() latches m_addr from the REAL remote endpoint — this is where
    // peer->addr().address() gets its value on the live path.
    sock->init();
    return std::make_shared<dash::NodeImpl::peer_t>(sock);
}

std::unique_ptr<RawMessage> make_version(std::uint64_t nonce)
{
    return dash::message_version::make_raw(
        dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION,          // exactly at the cold floor
        std::uint64_t{0},                                          // services
        addr_t(1u, NetService("192.168.1.1", 9999)),          // addr_to
        addr_t(1u, NetService("192.168.1.2", 8888)),          // addr_from
        nonce,
        std::string("c2pool-dash-addrme-kat"),
        1u,                                                        // mode
        uint256());                                                // best_share = null
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// 0. WIRE FORMAT IS UNCHANGED. The fix adds a CALL SITE, never a byte.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, WireFormatByteIdentical)
{
    auto rmsg = dash::message_addrme::make_raw(std::uint16_t(0x1234));
    ASSERT_EQ(rmsg->m_command, "addrme");

    auto span = rmsg->m_data.get_span();
    ASSERT_EQ(span.size(), 2u);
    EXPECT_EQ(std::to_integer<int>(span[0]), 0x34);   // uint16 port, little-endian
    EXPECT_EQ(std::to_integer<int>(span[1]), 0x12);

    // Full framed packet: prefix | "addrme" NUL-padded to 12 | length=2 | ...
    auto stream = core::Packet::from_message(test_prefix(), rmsg);
    const auto* bytes = reinterpret_cast<const unsigned char*>(stream.data());
    ASSERT_GE(stream.size(), test_prefix().size() + kCommandLen + kLengthLen + kChecksumLen + 2);

    const std::size_t p = test_prefix().size();
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(bytes + p), 6), "addrme");
    for (std::size_t i = 6; i < kCommandLen; ++i)
        EXPECT_EQ(bytes[p + i], 0u) << "command field must stay NUL-padded at " << i;

    std::uint32_t len = 0;
    std::memcpy(&len, bytes + p + kCommandLen, kLengthLen);
    EXPECT_EQ(len, 2u);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. DEFECT (a): handle_version must ORIGINATE an addrme carrying our listen
//    port. Drives the REAL NodeImpl::handle_version over a REAL socket and reads
//    the frames the node actually wrote. Before the fix there is no addrme frame
//    at all, so the ASSERT_NE below fires.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, HandleVersionWritesAddrmeCarryingOurListenPort)
{
    LoopbackPair pair;
    StubCommunicator stub;

    dash::Config cfg{"dash-addrme-kat"};
    cfg.pool()->m_prefix = test_prefix();

    dash::NodeImpl node(&pair.ioc_node, &cfg);
    // Bind an EPHEMERAL port: the assertion is that the addrme carries whatever
    // the OS handed us, not a hardcoded constant.
    node.core::Server::listen(std::uint16_t{0});
    const auto listen_port = node.core::Server::listen_port_or_none();
    ASSERT_TRUE(listen_port.has_value()) << "test node must be listening";

    auto peer = make_socket_peer(pair, stub);
    IoThread io(pair.ioc_node);

    const auto type = node.handle_version(make_version(0xD45E'C0FF'EE01'2345ull), peer);
    ASSERT_TRUE(type.has_value()) << "handshake must be accepted at the cold floor";
    EXPECT_EQ(*type, pool::PeerConnectionType::legacy)
        << "un-ratcheted DASH negotiates Legacy — the generation the fix targets";

    const auto frames = read_frames(*pair.theirs, std::chrono::milliseconds(400));
    io.stop(pair.ioc_node);

    // getaddrs is the pre-existing handshake write; its presence proves the
    // harness really is observing handle_version's output.
    EXPECT_NE(find_frame(frames, "getaddrs"), nullptr)
        << "harness sanity: the existing getaddrs write must be visible";

    const Frame* addrme = find_frame(frames, "addrme");
    ASSERT_NE(addrme, nullptr)
        << "#882(a): handle_version never originated an addrme on the DASH lane";

    ASSERT_EQ(addrme->payload.size(), 2u);
    std::uint16_t advertised = 0;
    std::memcpy(&advertised, addrme->payload.data(), sizeof(advertised));
    EXPECT_EQ(advertised, *listen_port)
        << "the addrme must carry OUR real listen port";
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Canonical parity for the NON-listening case. p2p.py:110 gates the whole
//    advertisement on `if self.node.serverfactory.listen_port is not None`, and
//    DASH has a real non-listening mode (`--connect` without `--listen`,
//    src/c2pool/main_dash.cpp:566). An UNGUARDED core::Server::listen_port()
//    throws on an acceptor that was never opened, and a throw out of
//    handle_version makes the bridge drop the connection — so this test is what
//    keeps the fix from breaking --connect.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, NonListeningNodeAdvertisesNothingAndDoesNotThrow)
{
    LoopbackPair pair;
    StubCommunicator stub;

    // Rig-free construction: Factory(nullptr, ...) never even engages the
    // optional acceptor.
    dash::NodeImpl node;
    EXPECT_FALSE(node.core::Server::listen_port_or_none().has_value());

    auto peer = make_socket_peer(pair, stub);
    IoThread io(pair.ioc_node);

    std::optional<pool::PeerConnectionType> type;
    ASSERT_NO_THROW(type = node.handle_version(make_version(0x0BAD'F00D'1234'5678ull), peer));
    ASSERT_TRUE(type.has_value());

    const auto frames = read_frames(*pair.theirs, std::chrono::milliseconds(250));
    io.stop(pair.ioc_node);

    EXPECT_EQ(find_frame(frames, "addrme"), nullptr)
        << "canonical advertises nothing when there is no listen port";
}

// ─────────────────────────────────────────────────────────────────────────────
// 2b. The EXACT `--connect` shape, and the reason the guard is not decoration.
//     `--connect` without `--listen` constructs the node WITH an io_context (so
//     the optional acceptor IS engaged) and then never calls listen(), leaving
//     the acceptor closed. core::Server::listen_port() calls local_endpoint()
//     on it, which THROWS; a throw out of handle_version is what makes the
//     bridge drop the connection. listen_port_or_none() answers nullopt
//     instead, which is what canonical's `is not None` test does.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, ConnectOnlyNodeHasNoListenPortAndUnguardedReadWouldThrow)
{
    boost::asio::io_context ioc;
    dash::Config cfg{"dash-addrme-kat"};
    cfg.pool()->m_prefix = test_prefix();

    // Context present, listen() never called — precisely --connect mode
    // (src/c2pool/main_dash.cpp:566 skips listen() when connect_only).
    dash::NodeImpl node(&ioc, &cfg);

    EXPECT_FALSE(node.core::Server::listen_port_or_none().has_value())
        << "a connect-only node has no listen port to advertise";
    EXPECT_ANY_THROW((void) node.core::Server::listen_port())
        << "this is the throw an unguarded ltc/btc-shaped port would have "
           "taken out of handle_version, dropping every --connect handshake";
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DEFECT (b), evidence: a real accepted loopback connection presents the
//    loopback HOST address. "127.0.0.0" is the /8 NETWORK address and is not a
//    value any peer can ever present, which is precisely why the old Legacy
//    guard was dead code.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, LoopbackPeerPresentsHostAddressNotNetworkAddress)
{
    LoopbackPair pair;
    StubCommunicator stub;

    auto peer = make_socket_peer(pair, stub);

    EXPECT_EQ(peer->addr().address(), "127.0.0.1");
    EXPECT_NE(peer->addr().address(), "127.0.0.0")
        << "the pre-#882 Legacy guard compared a value no peer can present";
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. DEFECT (b), behaviour: drive the REAL dash::Legacy addrme handler with a
//    loopback sender. Canonical (p2p.py:281) takes the self-probe arm and does
//    NOT record the address. Before the fix the dead guard sent every loopback
//    addrme down the else arm, which called got_addr(127.0.0.1:port) — inserting
//    loopback into our AddrStore as a routable peer, from where get_good_peers()
//    would hand it to other nodes in an addrs reply. Same subsystem as #910,
//    which fixes the other direction (a hostname serialising AS 127.0.0.1).
//
//    Repeated: the relay inside each arm is probabilistic (0.8) and picks a
//    random peer, but got_addr() in the else arm is UNCONDITIONAL, so a single
//    iteration is already decisive; the loop simply removes any doubt.
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashAddrme, LoopbackAddrmeIsNotRecordedAsARoutablePeer)
{
    constexpr std::uint16_t kAdvertisedPort = 41337;  // distinctive; not a real seed port

    LoopbackPair pair;
    StubCommunicator stub;

    ProbeLegacy legacy;
    auto peer = make_socket_peer(pair, stub);
    ASSERT_EQ(peer->addr().address(), "127.0.0.1");

    // A relay target must exist, otherwise the self-probe arm is a no-op and the
    // two arms would be indistinguishable from the outside.
    peer->m_nonce = 0x1111'2222'3333'4444ull;
    legacy.peers()[peer->m_nonce] = peer;

    const NetService loopback_record{std::string("127.0.0.1"), kAdvertisedPort};
    ASSERT_FALSE(legacy.addrs().check(loopback_record))
        << "precondition: the store must not already carry this record";

    IoThread io(pair.ioc_node);
    for (int i = 0; i < 32; ++i)
    {
        auto raw = dash::message_addrme::make_raw(kAdvertisedPort);
        legacy.handle(dash::message_addrme::make(raw->m_data), peer);
    }

    const auto frames = read_frames(*pair.theirs, std::chrono::milliseconds(300));
    io.stop(pair.ioc_node);

    EXPECT_FALSE(legacy.addrs().check(loopback_record))
        << "#882(b): a loopback addrme was recorded in the AddrStore as a "
           "routable peer — the dead 127.0.0.0 guard sent it down the else arm";

    // The else arm also gossips the bogus record onward as an addrs message.
    // With the self-probe arm reachable, addrme is what gets relayed instead.
    EXPECT_EQ(find_frame(frames, "addrs"), nullptr)
        << "#882(b): loopback was gossiped to peers in an addrs relay";
    EXPECT_NE(find_frame(frames, "addrme"), nullptr)
        << "canonical relays the addrme onward so a peer that CAN see our "
           "public address answers it (p2p.py:282-283)";
}
