// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCH sharechain dialer KAT: connect_failed() handling (ported from the DASH
// node) and persistent --sharechain-addnode pins (python --p2pool-node).
//
// Before the fix bch::NodeImpl had no connect_failed() override and its Node
// was a stack object, so core::Factory dropped the failure signal: a dial that
// failed left the address in m_pending_outbound for the life of the process and
// it was never dialed again (the 92.53.224.27:9349 addnode on contabo).
//
//   ConnectFailedClearsPending          FAILS before the fix
//   PinIsDialedAtOnceAndBacksOff        FAILS before the fix (no pins)
//   HandshakeResetsDelayAndDropRedials  FAILS before the fix
//   BannedPinIsStillDialed              FAILS before the fix
//   FailedDialLogIsRateLimited          FAILS before the fix
//   UnmanagedNodeNeverHearsTheFailure   passes both: why standup_pool_run now
//                                       owns the node through a shared_ptr
//   ArmedNodeRedialsAfterRefusedDial    FAILS before the fix: a real io_context,
//                                       a real refused TCP dial through
//                                       core::Factory, the pin redialed ~2.7 s later
//
// HARNESS: plain int main()/CHECK; runs from the already-allowlisted
// bch_embedded_block_broadcast_test executable (run_pool_dialer_redial_checks()).

#include <impl/bch/config.hpp>
#include <impl/bch/node.hpp>

#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

using clock_t_ = std::chrono::steady_clock;

int g_failures = 0;
int g_case_failures = 0;

#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; } } while (0)
#define REQUIRE(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; return; } } while (0)

class PrivateDataDir
{
public:
    PrivateDataDir()
    {
        m_prev = core::filesystem::data_dir_override();
        static int seq = 0;
        m_dir = std::filesystem::temp_directory_path()
              / ("c2pool-bch-dialer-" + std::to_string(::getpid()) + "-" + std::to_string(seq++));
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

// Rig-free node (no io_context): begin_outbound_dial only records the dial and
// marks it pending, so the dial decisions are observable without a network.
class Probe : public bch::Legacy
{
public:
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    std::vector<NetService> dials;
    bool pending(const NetService& a) const { return this->m_pending_outbound.contains(a); }
    void mark_pending(const NetService& a) { this->m_pending_outbound.insert(a); }
    void mark_outbound(const NetService& a) { this->m_outbound_addrs.insert(a); }
    bool outbound(const NetService& a) const { return this->m_outbound_addrs.contains(a); }
    void handshake(const NetService& a) { this->note_pin_handshake(a); }
    void ban_host(const std::string& ip)
    {
        this->m_ip_ban_list[ip] = clock_t_::now() + std::chrono::hours(1);
    }
    const auto& fail_log(const NetService& a) { return this->m_failed_dial_log[a]; }
    void log_fail(const NetService& a, clock_t_::time_point t) { this->log_failed_dial(a, t); }

protected:
    void begin_outbound_dial(const NetService& addr) override
    {
        dials.push_back(addr);
        this->m_pending_outbound.insert(addr);
    }
};

const double E = 2.7182818284590451;

bool near(double a, double b, double tol = 0.2) { return std::fabs(a - b) <= tol; }

void ConnectFailedClearsPending()
{
    PrivateDataDir dir;
    Probe node;
    const NetService peer{std::string("192.0.2.7"), 9349};
    node.mark_pending(peer);
    node.mark_outbound(peer);
    node.connect_failed(peer);
    CHECK(!node.pending(peer), "a failed dial must not stay pending (the next pass redials it)");
    CHECK(!node.outbound(peer), "no live connection, so it is no longer an outbound peer");
    CHECK(node.pin_seconds_until_redial(peer, clock_t_::now()) < 0, "not a pin");
}

void PinIsDialedAtOnceAndBacksOff()
{
    PrivateDataDir dir;
    Probe node;
    const NetService pin{std::string("192.0.2.8"), 9349};
    node.add_pinned_peer(pin);

    auto t0 = clock_t_::now();
    CHECK(node.maintain_pinned_peers(t0) == 1, "a pin is dialed at once");
    CHECK(node.maintain_pinned_peers(t0) == 0, "not again while the dial is pending");
    REQUIRE(node.dials.size() == 1 && node.dials[0] == pin, "dialed the pin");

    // ReconnectingClientFactory: 1 s initial delay, x e per retry, 3600 s cap.
    double delay = 1.0;
    for (int k = 1; k <= 12; ++k)
    {
        node.connect_failed(pin);
        delay = std::min(delay * E, 3600.0);
        const auto t = clock_t_::now();
        CHECK(!node.pending(pin), "failed dial cleared");
        CHECK(near(node.pin_seconds_until_redial(pin, t), delay),
              "retry " << k << ": redial in " << node.pin_seconds_until_redial(pin, t) << " s, want " << delay);
        const size_t before = node.dials.size();
        CHECK(node.maintain_pinned_peers(t + std::chrono::duration_cast<clock_t_::duration>(
                  std::chrono::duration<double>(delay - 0.5))) == 0, "retry " << k << ": not before the delay");
        CHECK(node.maintain_pinned_peers(t + std::chrono::duration_cast<clock_t_::duration>(
                  std::chrono::duration<double>(delay + 0.5))) == 1, "retry " << k << ": redialed after the delay");
        CHECK(node.dials.size() == before + 1, "one dial per retry");
    }
    CHECK(near(delay, 3600.0, 1e-9), "the delay is capped at 3600 s");
}

void HandshakeResetsDelayAndDropRedials()
{
    PrivateDataDir dir;
    Probe node;
    const NetService pin{std::string("192.0.2.9"), 9349};
    node.add_pinned_peer(pin);
    node.maintain_pinned_peers(clock_t_::now());
    for (int k = 0; k < 5; ++k)
    {
        node.connect_failed(pin);
        node.mark_pending(pin);
    }
    // Connected and handshaken: the delay goes back to 1 s (resetDelay).
    node.handshake(pin);
    // The connection drops: redial e seconds later, not e^6.
    node.close_connection(pin);
    CHECK(near(node.pin_seconds_until_redial(pin, clock_t_::now()), E),
          "after a drop of a handshaken pin, redial in e s; got "
          << node.pin_seconds_until_redial(pin, clock_t_::now()));
    // Same through error() (socket error / peer timeout).
    node.handshake(pin);
    node.error("test drop", pin);
    CHECK(near(node.pin_seconds_until_redial(pin, clock_t_::now()), E), "error() drop redials too");
}

void BannedPinIsStillDialed()
{
    PrivateDataDir dir;
    Probe node;
    const NetService pin{std::string("192.0.2.10"), 9349};
    node.ban_host("192.0.2.10");
    CHECK(node.is_banned(pin), "precondition: the host is banned");
    node.add_pinned_peer(pin);
    CHECK(node.maintain_pinned_peers(clock_t_::now()) == 1,
          "python's --p2pool-node connection never consults the bans");
}

void FailedDialLogIsRateLimited()
{
    PrivateDataDir dir;
    Probe node;
    const NetService peer{std::string("192.0.2.11"), 9349};
    node.mark_pending(peer);
    node.connect_failed(peer);                 // logged
    CHECK(node.fail_log(peer).logged && node.fail_log(peer).suppressed == 0, "first failure logged");
    node.mark_pending(peer);
    node.connect_failed(peer);                 // within 600 s: counted, not logged
    CHECK(node.fail_log(peer).suppressed == 1, "second failure suppressed");
    const auto later = clock_t_::now() + std::chrono::seconds(601);
    node.log_fail(peer, later);                // past the interval: logged with the count
    CHECK(node.fail_log(peer).suppressed == 0 && node.fail_log(peer).last == later,
          "logged again after the interval");
}

// A real node on a real io_context. NodeImpl is a virtual base of bch::Node,
// so the most-derived class constructs it.
class LiveNode : public bch::Node
{
public:
    LiveNode(boost::asio::io_context* ctx, bch::Config* cfg)
        : bch::NodeImpl(ctx, cfg), bch::Node(ctx, cfg) {}
    int dials = 0;
    bool pending(const NetService& a) const { return this->m_pending_outbound.contains(a); }

protected:
    void begin_outbound_dial(const NetService& addr) override
    {
        ++dials;
        bch::NodeImpl::begin_outbound_dial(addr);
    }
};

uint16_t closed_loopback_port()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    const uint16_t port = a.local_endpoint().port();
    a.close();
    return port;
}

void UnmanagedNodeNeverHearsTheFailure()
{
    PrivateDataDir dir;
    bch::Config config("bch");
    boost::asio::io_context ioc;
    const NetService pin{std::string("127.0.0.1"), closed_loopback_port()};
    {
        LiveNode node(&ioc, &config);        // stack object, no lifetime handle
        node.add_pinned_peer(pin);
        node.maintain_pinned_peers(clock_t_::now());
        ioc.run_for(std::chrono::milliseconds(1500));
        CHECK(node.dials == 1, "dials " << node.dials);
        CHECK(node.pending(pin), "the Factory drops connect_failed for an unmanaged node, so the "
                                 "dial stays pending: this is the leak the shared_ptr owner closes");
    }
    ioc.restart();
    ioc.poll();
}

void ArmedNodeRedialsAfterRefusedDial()
{
    PrivateDataDir dir;
    bch::Config config("bch");               // outlives ioc (pending handlers pin the node)
    boost::asio::io_context ioc;
    const NetService pin{std::string("127.0.0.1"), closed_loopback_port()};
    auto node = std::make_shared<LiveNode>(&ioc, &config);
    node->set_lifetime(node);
    REQUIRE(node->lifetime_armed(), "lifetime armed");
    node->set_target_outbound_peers(8);
    node->add_pinned_peer(pin);
    node->start_outbound_connections();      // pins first, then the (empty) addr-store dialer

    ioc.run_for(std::chrono::milliseconds(4500));
    CHECK(node->dials == 2, "initial dial + one redial after ~e s within 4.5 s, got " << node->dials);
    CHECK(!node->pending(pin), "the refused dial reached connect_failed");
    const double left = node->pin_seconds_until_redial(pin, clock_t_::now());
    CHECK(left > 2.0 && left <= E * E + 0.2, "second retry delay e^2, " << left << " s left");
    node.reset();
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
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchPoolDialer."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_pool_dialer_redial_checks()
{
    g_failures = 0;
    run_case("ConnectFailedClearsPending", ConnectFailedClearsPending);
    run_case("PinIsDialedAtOnceAndBacksOff", PinIsDialedAtOnceAndBacksOff);
    run_case("HandshakeResetsDelayAndDropRedials", HandshakeResetsDelayAndDropRedials);
    run_case("BannedPinIsStillDialed", BannedPinIsStillDialed);
    run_case("FailedDialLogIsRateLimited", FailedDialLogIsRateLimited);
    run_case("UnmanagedNodeNeverHearsTheFailure", UnmanagedNodeNeverHearsTheFailure);
    run_case("ArmedNodeRedialsAfterRefusedDial", ArmedNodeRedialsAfterRefusedDial);
    return g_failures;
}
