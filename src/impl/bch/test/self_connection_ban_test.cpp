// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCH self-connection ban KAT, issue #1716 part B.
//
// Part A fixed the addrme self-probe compare. Part B is what happens after the
// node dials its own public endpoint and the version handshake reveals our own
// nonce. The bch canonical is frstrtr/p2poolBCH @6603b79 (the conformance anchor
// named in protocol_legacy.cpp and config_pool.hpp). p2pool/p2p.py:160-161
// raises PeerMisbehavingError('was connected to self'). packetReceived (:92-94)
// turns that into badPeerHappened() (:96-105), which bans the HOST, never
// 127.0.0.1, for 3600 * banscore^2 seconds. Both the acceptor (:548) and the
// dial loop (:648) skip a banned host. forgive_transgressions (:715-719) takes
// one point off every score each hour (:712-713), clamped at zero.
//
// Before this fix bch's handle_version returned nullopt with no ban. The
// endpoint stayed dialable and was redialled on every think tick.
//
// These cases use REAL types, not mocks. They drive the real
// bch::NodeImpl::handle_version with a peer built from a real accepted TCP
// socket bound to 127.0.0.2. That address is loopback to the OS, so it binds
// without privilege, but it is not the 127.0.0.1 that canonical exempts.
//
//   SelfNonceBansTheHost                          FAILS without the fix
//   RepeatSelfConnectionEscalatesQuadratically    FAILS without the fix
//   HourlyForgivenessLowersTheNextBan             FAILS without the fix
//   LoopbackSelfConnectionIsNeverBanned           passes both: the canonical exemption
//   ForeignNonceIsNotBanned                       passes both: only the self arm bans
//
// HARNESS: the bch test tree is plain int main()/CHECK (no GTest), so this TU
// exposes run_self_connection_ban_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable, which compiles the real
// node.cpp TU. No new add_executable, so no "Not Run" (#769) trap.

#include <impl/bch/node.hpp>
#include <impl/bch/messages.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
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

// bch::Legacy is abstract on its own: the raw-frame entry is supplied by
// pool::NodeBridge in production, so it is stubbed here. handle_version and
// is_banned are the real NodeImpl / SharechainNode members.
class Probe : public bch::Legacy
{
public:
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    void set_nonce(uint64_t n) { this->m_nonce = n; }

    // Run the forgiveness clock as if `hours` had passed since the node started.
    void advance_hours(int hours)
    {
        this->run_forgiveness(this->m_forgiveness_epoch + hours * FORGIVENESS_INTERVAL
                              + std::chrono::seconds(1));
    }

    // Seconds until the host-level ban on `ip` expires, or 0 if none.
    long long ban_seconds_left(const std::string& ip) const
    {
        auto it = this->m_ip_ban_list.find(ip);
        if (it == this->m_ip_ban_list.end()) return 0;
        return std::chrono::duration_cast<std::chrono::seconds>(
            it->second - std::chrono::steady_clock::now()).count();
    }
};

bch::NodeImpl::peer_ptr make_socket_peer(SocketPair& pair, StubCommunicator& stub)
{
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();
    return std::make_shared<bch::NodeImpl::peer_t>(sock);
}

std::unique_ptr<RawMessage> version_with_nonce(
    uint64_t nonce, uint32_t version = bch::PoolConfig::ADVERTISED_PROTOCOL_VERSION)
{
    return bch::message_version::make_raw(
        version, 1,
        addr_t{1, NetService{"0.0.0.0", 0}},
        addr_t{1, NetService{"0.0.0.0", bch::PoolConfig::P2P_PORT}},
        nonce, std::string("/c2pool:test/"), 1, uint256{});
}

// One handshake on a fresh socket from bind_addr. Returns handle_version's
// verdict; the peer's own address is written to *peer_ip.
std::optional<pool::PeerConnectionType>
handshake(Probe& node, const std::string& bind_addr, uint64_t their_nonce,
          std::string* peer_ip = nullptr,
          uint32_t their_version = bch::PoolConfig::ADVERTISED_PROTOCOL_VERSION)
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
// Construct it BEFORE the node.
class PrivateDataDir
{
public:
    PrivateDataDir()
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-1716b-bch-selfban-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
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

void SelfNonceBansTheHost()
{
    PrivateDataDir dir;
    Probe node;
    node.set_nonce(kOurNonce);

    std::string ip;
    auto verdict = handshake(node, "127.0.0.2", kOurNonce, &ip);
    REQUIRE(ip == "127.0.0.2", "the peer must present the bound source address");

    CHECK(!verdict.has_value(), "a self-connection must still be refused");

    // Host-level, as canonical: the dial loop and the acceptor both consult
    // is_banned(), and the redial targets the same host on any port.
    CHECK(node.is_banned(NetService{std::string("127.0.0.2"), bch::PoolConfig::P2P_PORT}),
          "canonical p2p.py:160-161 -> badPeerHappened bans the self host");
    CHECK(node.is_banned(NetService{std::string("127.0.0.2"), 40123}),
          "the ban is per host, not per host:port");

    const auto left = node.ban_seconds_left("127.0.0.2");
    CHECK(left >= 3600 - kSlack, "first offence: 3600 * 1^2, got " << left);
    CHECK(left <= 3600 + kSlack, "first offence: 3600 * 1^2, got " << left);
}

void RepeatSelfConnectionEscalatesQuadratically()
{
    PrivateDataDir dir;
    Probe node;
    node.set_nonce(kOurNonce);

    handshake(node, "127.0.0.2", kOurNonce);
    handshake(node, "127.0.0.2", kOurNonce);

    // A real self-dial trips BOTH ends (outbound and inbound) of the same
    // connection, so canonical reaches score 2 on the first dial. The KAT pins
    // the per-offence rule, 3600 * n^2, not the per-dial count.
    const auto left = node.ban_seconds_left("127.0.0.2");
    CHECK(left >= 4 * 3600 - kSlack, "second offence: 3600 * 2^2, got " << left);
    CHECK(left <= 4 * 3600 + kSlack, "second offence: 3600 * 2^2, got " << left);

    handshake(node, "127.0.0.2", kOurNonce);
    const auto third = node.ban_seconds_left("127.0.0.2");
    CHECK(third >= 9 * 3600 - kSlack, "third offence: 3600 * 3^2, got " << third);
}

void HourlyForgivenessLowersTheNextBan()
{
    PrivateDataDir dir;
    Probe node;
    node.set_nonce(kOurNonce);

    // Score 2 (a real self-dial trips both ends of the connection).
    handshake(node, "127.0.0.2", kOurNonce);
    handshake(node, "127.0.0.2", kOurNonce);

    // Two hourly passes take the score 2 -> 1 -> 0. The next offence starts
    // over at score 1, so it is a 1 h ban, not the 9 h that score 3 would give.
    node.advance_hours(2);
    handshake(node, "127.0.0.2", kOurNonce);

    const auto left = node.ban_seconds_left("127.0.0.2");
    CHECK(left >= 3600 - kSlack,
          "p2poolBCH p2p.py:715-719 forgives one point per hour, got " << left);
    CHECK(left <= 3600 + kSlack,
          "without forgiveness the third offence is 3600 * 3^2, got " << left);
}

void LoopbackSelfConnectionIsNeverBanned()
{
    PrivateDataDir dir;
    Probe node;
    node.set_nonce(kOurNonce);

    std::string ip;
    auto verdict = handshake(node, "127.0.0.1", kOurNonce, &ip);
    REQUIRE(ip == "127.0.0.1", "the peer must present the loopback host address");

    CHECK(!verdict.has_value(), "a self-connection must still be refused");
    CHECK(!node.is_banned(NetService{std::string("127.0.0.1"), bch::PoolConfig::P2P_PORT}),
          "canonical p2p.py:99 never bans localhost");
    CHECK(node.ban_seconds_left("127.0.0.1") == 0, "no ban entry for localhost");
}

void ForeignNonceIsNotBanned()
{
    PrivateDataDir dir;
    Probe node;
    node.set_nonce(kOurNonce);

    // A foreign nonce must pass the self check without a ban. The peer
    // advertises a protocol below MINIMUM_PROTOCOL_VERSION, so handle_version
    // stops at the pre-insert refusal, the first exit after the self check, and
    // never reaches the addrme write. That write calls
    // core::Server::listen_port(), which on this rig-free node dereferences an
    // EMPTY std::optional acceptor (undefined behaviour, the unguarded accessor
    // tracked in #925, shared core and out of scope here). This case covers the
    // self-check arm only, not the post-insert handshake.
    static_assert(bch::PoolConfig::MINIMUM_PROTOCOL_VERSION > 0);
    bool threw = false;
    try {
        handshake(node, "127.0.0.2", kOtherNonce, nullptr,
                  bch::PoolConfig::MINIMUM_PROTOCOL_VERSION - 1);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw, "an old foreign peer is refused pre-insert, not treated as self");

    CHECK(!node.is_banned(NetService{std::string("127.0.0.2"), bch::PoolConfig::P2P_PORT}),
          "a foreign nonce must not ban the host");
    CHECK(node.ban_seconds_left("127.0.0.2") == 0, "no ban entry for a foreign nonce");
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
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchSelfConnectionBan."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_self_connection_ban_checks()
{
    g_failures = 0;
    run_case("SelfNonceBansTheHost", SelfNonceBansTheHost);
    run_case("RepeatSelfConnectionEscalatesQuadratically",
             RepeatSelfConnectionEscalatesQuadratically);
    run_case("HourlyForgivenessLowersTheNextBan", HourlyForgivenessLowersTheNextBan);
    run_case("LoopbackSelfConnectionIsNeverBanned", LoopbackSelfConnectionIsNeverBanned);
    run_case("ForeignNonceIsNotBanned", ForeignNonceIsNotBanned);
    return g_failures;
}
