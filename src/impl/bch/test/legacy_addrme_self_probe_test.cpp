// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCH addrme self-probe KAT, issue #1716 (the sibling half of #882).
//
// #915 fixed the DASH Legacy addrme self-probe only. bch's Legacy handler
// (src/impl/bch/protocol_legacy.cpp) still compared the peer's source against
// "127.0.0.0", the loopback NETWORK address. No peer can present that as its
// source, so the self-probe arm never ran. Every addrme, including one that
// arrived over loopback, fell into the else arm: it recorded
// 127.0.0.1:<port> in our AddrStore as if it were a routable peer and then
// gossiped that loopback record onward in an addrs message. The BCH canonical,
// frstrtr/p2poolBCH p2p.py:267 (handle_addrme, @6603b79, the conformance anchor
// named in protocol_legacy.cpp and config_pool.hpp), compares
// `host == '127.0.0.1'`, and so does bch's own Actual generation
// (protocol_actual.cpp:94). Legacy is the generation live on bch today.
//
// These cases use REAL types, not mocks. They drive the real
// bch::Legacy::handle(message_addrme) and bch::Actual::handle(message_addrme)
// with a peer built from a real accepted loopback TCP socket (core::Socket
// latches peer->addr() from the real remote endpoint, the same as the live
// path). They read the frames the handler actually put on the wire. Same KAT
// as the btc, ltc and dgb halves of #1716 (PRs #1717, #1745 and #1748,
// src/impl/{btc,ltc,dgb}/test/legacy_addrme_self_probe_test.cpp), which were
// ported from the DASH #882 KAT (test/test_dash_addrme.cpp).
//
//   LoopbackAddrmeIsNotRecordedAsARoutablePeer    FAILS without the fix
//   LoopbackPeerPresentsHostAddressNotNetworkAddress   evidence; passes both
//   RoutableSourceIsRecordedAndRelayedWithByteIdenticalFields
//       passes both: for any source that is neither constant, the old and new
//       compare fail identically, so the routable arm is unchanged by the fix
//   ActualGenerationAgreesOnLoopback               parity pin; passes both
//
// Each case gets a private data dir, so the file-backed AddrStore never touches
// ~/.c2pool/addrs.json.
//
// HARNESS: the bch test tree is plain int main()/CHECK (no GTest), so this TU
// exposes run_legacy_addrme_self_probe_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable, which already compiles the real
// node.cpp / protocol_legacy.cpp / protocol_actual.cpp TUs. A standalone
// add_executable is not in build.yml's --target list, so CI would never build
// it and CTest would report it "Not Run" (the #769 trap).

#include <impl/bch/node.hpp>
#include <impl/bch/messages.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/packet.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <span>
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

// Wire header written by core::Packet::from_message (src/core/packet.hpp):
//   prefix(N) | command(12, NUL-padded) | length(4, LE) | checksum(4) | payload
constexpr std::size_t kCommandLen  = 12;
constexpr std::size_t kLengthLen   = 4;
constexpr std::size_t kChecksumLen = 4;

const std::vector<std::byte>& test_prefix()
{
    // Arbitrary but fixed. The framing prefix is a per-net constant and is not
    // what this KAT is about.
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

// Minimal ICommunicator for core::Socket. The write path only needs
// get_prefix(). Built with an empty weak_ptr<INetwork> and was_managed=false
// (the unmanaged-node path), so no INetwork is required.
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

// Real loopback TCP pair. `ours` is the end the handler writes to (wrapped in a
// core::Socket and handed to a pool::Peer). `theirs` is the peer end, read
// synchronously so the test sees exactly the bytes that went on the wire.
//
// bind_addr defaults to the loopback HOST address (127.0.0.1). The routable case
// binds 127.0.0.2: still loopback to the OS, so it is bindable without
// privilege, but it is neither self-probe constant, so the handler takes the
// else (routable) arm.
struct LoopbackPair
{
    boost::asio::io_context ioc_peer;
    boost::asio::io_context ioc_node;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    explicit LoopbackPair(const std::string& bind_addr = "127.0.0.1")
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_peer, tcp::endpoint(boost::asio::ip::make_address(bind_addr), 0));
        acceptor->listen();

        ours = std::make_unique<tcp::socket>(ioc_node);
        ours->connect(acceptor->local_endpoint());

        theirs = std::make_unique<tcp::socket>(acceptor->accept());

        boost::system::error_code ec;
        ours->set_option(tcp::no_delay(true), ec);
        theirs->set_option(tcp::no_delay(true), ec);
    }
};

// Runs an io_context on its own thread for the lifetime of the scope, the
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

// Drains the peer end until it has been quiet for the budget, then splits the
// stream into wire frames. Bounded, so a missing message fails a check instead
// of hanging CI.
std::vector<Frame> read_frames(tcp::socket& s, std::chrono::milliseconds quiet_for)
{
    std::vector<std::byte> buf;
    const auto deadline = std::chrono::steady_clock::now() + quiet_for;

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

// Expose the protected AddrStore and peer map so the checks can see what the
// real handler recorded and where it can relay.
//
// bch::Legacy / bch::Actual are abstract on their own: the raw-frame entry
// core::ICommunicator::handle(RawMessage, NetService) is supplied by
// pool::NodeBridge in production. The tests call the typed addrme handler
// directly, so the raw entry is stubbed. `using Generation::handle` keeps the
// real typed handler overloads visible past that stub.
template <typename Generation>
class Probe : public Generation
{
public:
    using Generation::handle;
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    core::AddrStore& addrs() { return this->m_addrs; }
    std::map<uint64_t, bch::NodeImpl::peer_ptr>& peers() { return this->m_peers; }
};

using ProbeLegacy = Probe<bch::Legacy>;
using ProbeActual = Probe<bch::Actual>;

bch::NodeImpl::peer_ptr make_socket_peer(LoopbackPair& pair, StubCommunicator& stub)
{
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    // init() latches m_addr from the REAL remote endpoint. On the live path this
    // is where peer->addr().address() gets its value.
    sock->init();
    return std::make_shared<bch::NodeImpl::peer_t>(sock);
}

// A default-constructed node's AddrStore is FILE-BACKED: BaseNode() builds
// m_addrs(""), i.e. <config_path()>/addrs.json, and every add()/update() rewrites
// it. Without isolation these cases would read and write the developer's (or the
// CI runner's) ~/.c2pool/addrs.json, and a record persisted by one run would
// break the "store must not already carry this record" precondition on the
// next. Each case gets its own empty data dir via the --data-dir override, and
// the previous override is restored afterwards. Construct it BEFORE the node.
class PrivateDataDir
{
public:
    PrivateDataDir()
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-1716-bch-addrme-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
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

// Drive a loopback addrme through the given generation's REAL handler and
// report what it recorded and what it put on the wire.
struct LoopbackOutcome
{
    bool ran = false;
    bool recorded = false;
    std::vector<Frame> frames;
};

template <typename ProbeT>
void drive_loopback_addrme(std::uint16_t advertised_port, LoopbackOutcome& out)
{
    LoopbackPair pair;
    StubCommunicator stub;

    ProbeT gen;
    auto peer = make_socket_peer(pair, stub);
    REQUIRE(peer->addr().address() == "127.0.0.1",
            "a loopback socket must present the loopback host address");

    // A relay target must exist. Otherwise the self-probe arm does nothing and
    // the two arms cannot be told apart from outside.
    peer->m_nonce = 0x1111'2222'3333'4444ull;
    gen.peers()[peer->m_nonce] = peer;

    const NetService loopback_record{std::string("127.0.0.1"), advertised_port};
    REQUIRE(!gen.addrs().check(loopback_record),
            "precondition: the store must not already carry this record");

    // The relay in each arm is probabilistic (0.8), but got_addr() in the else
    // arm is unconditional, so one iteration already decides the record. The
    // loop makes the relayed frame observable.
    IoThread io(pair.ioc_node);
    for (int i = 0; i < 32; ++i)
    {
        auto raw = bch::message_addrme::make_raw(advertised_port);
        gen.handle(bch::message_addrme::make(raw->m_data), peer);
    }
    out.frames = read_frames(*pair.theirs, std::chrono::milliseconds(300));
    io.stop(pair.ioc_node);

    out.recorded = gen.addrs().check(loopback_record);
    out.ran = true;
}

// A real accepted loopback connection presents the loopback HOST address.
// "127.0.0.0" is the /8 NETWORK address and no peer can ever present it, which
// is why the pre-#1716 Legacy guard was dead code.
void LoopbackPeerPresentsHostAddressNotNetworkAddress()
{
    LoopbackPair pair;
    StubCommunicator stub;

    auto peer = make_socket_peer(pair, stub);

    CHECK(peer->addr().address() == "127.0.0.1",
          "a loopback socket must present the loopback host address");
    CHECK(peer->addr().address() != "127.0.0.0",
          "the pre-#1716 Legacy guard compared a value no peer can present");
}

// THE DEFECT. Canonical (p2poolBCH p2p.py:267) takes the self-probe arm for a
// loopback sender: it does NOT record the address and relays the addrme onward
// so a peer that can see our public address answers it (p2p.py:268-269).
// Before the fix, bch Legacy sent it down the else arm: got_addr(127.0.0.1:port)
// put loopback in the AddrStore as a routable peer (where get_good_peers()
// would hand it to other nodes in an addrs reply) and gossiped it as an addrs
// message.
void LoopbackAddrmeIsNotRecordedAsARoutablePeer()
{
    PrivateDataDir dir;
    LoopbackOutcome out;
    drive_loopback_addrme<ProbeLegacy>(41337, out);
    REQUIRE(out.ran, "the loopback drive did not complete");

    CHECK(!out.recorded,
          "#1716: a loopback addrme was recorded in the AddrStore as a routable "
          "peer; the dead 127.0.0.0 guard sent it down the else arm");
    CHECK(find_frame(out.frames, "addrs") == nullptr,
          "#1716: loopback was gossiped to peers in an addrs relay");
    CHECK(find_frame(out.frames, "addrme") != nullptr,
          "canonical relays the addrme onward (p2poolBCH p2p.py:268-269)");
}

// The dormant Actual generation already compares 127.0.0.1
// (protocol_actual.cpp:94). With the Legacy fix, both generations behave the
// same for a loopback sender. This pins that agreement so neither can drift
// before Actual goes live at the v36 crossing.
void ActualGenerationAgreesOnLoopback()
{
    PrivateDataDir dir;
    LoopbackOutcome out;
    drive_loopback_addrme<ProbeActual>(41338, out);
    REQUIRE(out.ran, "the loopback drive did not complete");

    CHECK(!out.recorded, "Actual recorded a loopback addrme");
    CHECK(find_frame(out.frames, "addrs") == nullptr, "Actual gossiped loopback as addrs");
    CHECK(find_frame(out.frames, "addrme") != nullptr, "Actual did not relay the addrme");
}

// Byte identity for a ROUTABLE source (the case #925 set as a gate for #915's
// DASH fix, carried here from the start). The self-probe is one string compare
// against a hardcoded constant. For any source that is neither constant, the
// old "127.0.0.0" and the new "127.0.0.1" fail the compare identically and take
// the same else arm, so the fix leaves the routable path unchanged. 127.0.0.2
// is the smallest bindable stand-in for that class. The test pins the else-arm
// contract by decoding the frame the handler actually wrote: got_addr records
// the endpoint and services verbatim, and the record is gossiped as an `addrs`
// (never `addrme`) carrying identical bytes.
void RoutableSourceIsRecordedAndRelayedWithByteIdenticalFields()
{
    constexpr std::uint16_t kAdvertisedPort = 9349;                     // bch sharechain P2P port (config_pool.hpp:65)
    constexpr std::uint64_t kServices       = 0xA5A5'0000'1234'5678ull; // distinctive, non-zero

    PrivateDataDir dir;
    LoopbackPair pair("127.0.0.2");   // routable to the self-probe; loopback to the OS
    StubCommunicator stub;

    ProbeLegacy legacy;
    auto peer = make_socket_peer(pair, stub);
    REQUIRE(peer->addr().address() == "127.0.0.2",
            "the source must be a non-loopback-HOST address to reach the else arm");

    peer->m_other_services = kServices;
    peer->m_nonce = 0x5555'6666'7777'8888ull;
    legacy.peers()[peer->m_nonce] = peer;   // relay target (also the source)

    const NetService routable_record{std::string("127.0.0.2"), kAdvertisedPort};
    REQUIRE(!legacy.addrs().check(routable_record),
            "precondition: the store must not already carry this record");

    IoThread io(pair.ioc_node);
    for (int i = 0; i < 32; ++i)
    {
        auto raw = bch::message_addrme::make_raw(kAdvertisedPort);
        legacy.handle(bch::message_addrme::make(raw->m_data), peer);
    }
    const auto frames = read_frames(*pair.theirs, std::chrono::milliseconds(300));
    io.stop(pair.ioc_node);

    REQUIRE(legacy.addrs().check(routable_record),
            "a routable addrme must be recorded as a peer via the else arm");
    CHECK(legacy.addrs().get(routable_record).m_service == kServices,
          "the recorded services must be the peer's, unchanged");

    CHECK(find_frame(frames, "addrme") == nullptr,
          "addrme relay belongs to the self-probe arm; a routable source must "
          "not take it");
    const Frame* addrs = find_frame(frames, "addrs");
    REQUIRE(addrs != nullptr,
            "the else arm relays the routable record in an addrs message");

    PackStream ps{std::span<const std::byte>(addrs->payload)};
    auto parsed = bch::message_addrs::make(ps);
    REQUIRE(parsed->m_addrs.size() == 1u,
            "the relay carries exactly the one record the handler built");
    CHECK(parsed->m_addrs[0].m_endpoint.address() == "127.0.0.2", "relayed address");
    CHECK(parsed->m_addrs[0].m_endpoint.port() == kAdvertisedPort, "relayed port");
    CHECK(parsed->m_addrs[0].m_services == kServices,
          "relayed services must equal the peer's negotiated services");
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
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchLegacyAddrme."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_legacy_addrme_self_probe_checks()
{
    g_failures = 0;
    run_case("LoopbackPeerPresentsHostAddressNotNetworkAddress",
             LoopbackPeerPresentsHostAddressNotNetworkAddress);
    run_case("LoopbackAddrmeIsNotRecordedAsARoutablePeer",
             LoopbackAddrmeIsNotRecordedAsARoutablePeer);
    run_case("ActualGenerationAgreesOnLoopback",
             ActualGenerationAgreesOnLoopback);
    run_case("RoutableSourceIsRecordedAndRelayedWithByteIdenticalFields",
             RoutableSourceIsRecordedAndRelayedWithByteIdenticalFields);
    return g_failures;
}
