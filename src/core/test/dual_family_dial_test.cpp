// #965 Phase-3: outbound dial across address families (core/dial.hpp, wired in
// core::Factory's Client, core/factory.hpp).
//
// REAL types throughout: real boost::asio sockets/acceptors on loopback, the
// real tcp::resolver, the real core::dial_endpoints / order_dial_endpoints, and
// -- for the wiring cases -- a real core::Factory<core::Client> dialling
// "localhost". No mock resolver, no mock socket.
//
// Which cases FAIL without the fix (pre-#965-Ph3 Client = range async_connect
// over the resolver's order, no deadline, no memory of what worked):
//   * Blackholed v6 -> v4 fallback: the pre-fix range connect is still stuck on
//     the AAAA attempt when this test's deadline expires. The test RUNS that
//     pre-fix path as a control and asserts it is still pending, so the
//     blackhole is proven real and the green case cannot pass vacuously.
//   * Prior-success reorder through Factory<Client>: pre-fix the dial follows
//     the resolver (::1 ahead of 127.0.0.1 under RFC 6724), so the v6 listener
//     takes the connection the test requires to land on v4.
//   * Success writes the family memo through Factory<Client>: no memo pre-fix.
// The remaining cases PIN behaviour that must not change (A-only / AAAA-only
// hosts, refused-v6 fallback, which plain asio already did) -- they are
// preservation guards, not red-without-fix tests, and are labelled as such.
//
// v6-dependent cases GTEST_SKIP on a runner with no IPv6 loopback (same policy
// as listener_family_test.cpp). Folded into the EXISTING allowlisted core_test
// target -- never a new add_executable (the #769 "Not Run" trap).

#include <gtest/gtest.h>

#include <core/dial.hpp>
#include <core/factory.hpp>
#include <core/inetwork.hpp>
#include <core/netaddress.hpp>
#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <source_location>
#include <string>
#include <vector>

namespace {

using boost::asio::ip::tcp;
using boost::asio::ip::make_address;
using core::DialFamily;

tcp::endpoint ep(const char* ip, unsigned short port = 9999)
{
    return tcp::endpoint(make_address(ip), port);
}

// Bind a listener on `ip`:`port` (0 = ephemeral). nullopt when the family is
// unavailable on this host.
std::unique_ptr<tcp::acceptor> try_listen(boost::asio::io_context& ioc, const char* ip,
                                          unsigned short port = 0, int backlog = 16)
{
    boost::system::error_code ec;
    auto addr = make_address(ip, ec);
    if (ec) return nullptr;
    auto acc = std::make_unique<tcp::acceptor>(ioc);
    tcp::endpoint where(addr, port);
    acc->open(where.protocol(), ec);
    if (ec) return nullptr;
    if (addr.is_v6())
        acc->set_option(boost::asio::ip::v6_only(true), ec);
    acc->bind(where, ec);
    if (ec) return nullptr;
    acc->listen(backlog, ec);
    if (ec) return nullptr;
    return acc;
}

unsigned short port_of(const tcp::acceptor& a) { return a.local_endpoint().port(); }

// A port on ::1 with nothing listening (bind, read the port, close).
std::optional<unsigned short> closed_v6_port(boost::asio::io_context& ioc)
{
    auto acc = try_listen(ioc, "::1");
    if (!acc) return std::nullopt;
    auto p = port_of(*acc);
    acc->close();
    return p;
}

struct DialResult
{
    bool done = false;
    boost::system::error_code ec;
    tcp::endpoint ep;
};

// Run `ioc` until `r.done` or `limit` elapses. Returns elapsed time.
std::chrono::milliseconds run_until(boost::asio::io_context& ioc, const DialResult& r,
                                    std::chrono::milliseconds limit)
{
    const auto t0 = std::chrono::steady_clock::now();
    ioc.restart();
    while (!r.done && std::chrono::steady_clock::now() - t0 < limit)
        ioc.run_for(std::chrono::milliseconds(20));
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
}

// ── ordering (pure) ──────────────────────────────────────────────────────────

// Preservation: an A-only host's list must come back byte-identical, whatever
// the memo says -- this is the "v4-only hosts: nothing changes" guarantee.
TEST(DualFamilyDial, AOnlyHostOrderIsUnchanged)
{
    std::vector<tcp::endpoint> in{ep("203.0.113.7"), ep("198.51.100.1"), ep("192.0.2.9")};
    EXPECT_FALSE(core::is_mixed_family(in));
    EXPECT_EQ(core::order_dial_endpoints(in, std::nullopt), in);
    EXPECT_EQ(core::order_dial_endpoints(in, DialFamily::V6), in);
}

TEST(DualFamilyDial, AaaaOnlyHostOrderIsUnchanged)
{
    std::vector<tcp::endpoint> in{ep("2001:db8::2"), ep("2001:db8::1")};
    EXPECT_FALSE(core::is_mixed_family(in));
    EXPECT_EQ(core::order_dial_endpoints(in, DialFamily::V4), in);
}

TEST(DualFamilyDial, V4MappedCountsAsV4)
{
    std::vector<tcp::endpoint> in{ep("::ffff:203.0.113.7"), ep("203.0.113.8")};
    EXPECT_FALSE(core::is_mixed_family(in));
    EXPECT_EQ(core::dial_family_of(make_address("::ffff:203.0.113.7")), DialFamily::V4);
}

TEST(DualFamilyDial, MixedInterleavesLedByResolverFirstFamily)
{
    std::vector<tcp::endpoint> in{ep("2001:db8::1"), ep("2001:db8::2"), ep("203.0.113.7")};
    std::vector<tcp::endpoint> want{ep("2001:db8::1"), ep("203.0.113.7"), ep("2001:db8::2")};
    EXPECT_TRUE(core::is_mixed_family(in));
    EXPECT_EQ(core::order_dial_endpoints(in, std::nullopt), want);
}

TEST(DualFamilyDial, MixedLedByPriorSuccessFamily)
{
    std::vector<tcp::endpoint> in{ep("2001:db8::1"), ep("2001:db8::2"), ep("203.0.113.7")};
    std::vector<tcp::endpoint> want{ep("203.0.113.7"), ep("2001:db8::1"), ep("2001:db8::2")};
    EXPECT_EQ(core::order_dial_endpoints(in, DialFamily::V4), want);
}

TEST(DualFamilyDial, FamilyMemoSkipsLiteralsAndRecordsNames)
{
    core::clear_dial_families();
    core::record_dial_family("203.0.113.7", DialFamily::V4);
    core::record_dial_family("2001:db8::1", DialFamily::V6);
    EXPECT_FALSE(core::preferred_dial_family("203.0.113.7").has_value());
    EXPECT_FALSE(core::preferred_dial_family("2001:db8::1").has_value());

    core::record_dial_family("seed.example", DialFamily::V6);
    EXPECT_EQ(core::preferred_dial_family("seed.example"), DialFamily::V6);
    core::record_dial_family("seed.example", DialFamily::V4);
    EXPECT_EQ(core::preferred_dial_family("seed.example"), DialFamily::V4);
    core::clear_dial_families();
    EXPECT_FALSE(core::preferred_dial_family("seed.example").has_value());
}

// ── AAAA resolution (real resolver) ──────────────────────────────────────────

// The Client's resolver call is async_resolve(host, port) -- protocol
// unspecified -- so the AAAA answer is in the list it dials, and the ordering
// keeps it. Skips where the host's resolver yields no AAAA for "localhost"
// (AI_ADDRCONFIG with no configured non-loopback v6, or /etc/hosts without ::1).
TEST(DualFamilyDial, ResolverReturnsAaaaAndOrderingKeepsIt)
{
    boost::asio::io_context ioc;
    tcp::resolver res(ioc);
    boost::system::error_code ec;
    auto results = res.resolve("localhost", "9999", ec);
    ASSERT_FALSE(ec) << ec.message();

    std::vector<tcp::endpoint> eps;
    for (const auto& r : results) eps.push_back(r.endpoint());
    bool has_v6 = false, has_v4 = false;
    for (const auto& e : eps)
        (core::dial_family_of(e.address()) == DialFamily::V6 ? has_v6 : has_v4) = true;
    if (!has_v6)
        GTEST_SKIP() << "resolver returned no AAAA for localhost on this host";

    auto ordered = core::order_dial_endpoints(eps, std::nullopt);
    ASSERT_EQ(ordered.size(), eps.size());
    bool kept_v6 = false;
    for (const auto& e : ordered)
        kept_v6 |= core::dial_family_of(e.address()) == DialFamily::V6;
    EXPECT_TRUE(kept_v6);
    if (has_v4)
        EXPECT_NE(core::dial_family_of(ordered[0].address()),
                  core::dial_family_of(ordered[1].address()))
            << "mixed list must alternate families";
}

// ── real dials ───────────────────────────────────────────────────────────────

// Preservation: A-only host -> the legacy range-connect path, connects.
TEST(DualFamilyDial, AOnlyHostConnects)
{
    boost::asio::io_context ioc;
    auto v4 = try_listen(ioc, "127.0.0.1");
    ASSERT_TRUE(v4);
    tcp::socket s(ioc);
    DialResult r;
    core::dial_endpoints(s, {tcp::endpoint(make_address("127.0.0.1"), port_of(*v4))},
                         std::chrono::milliseconds(300), "kat",
                         [&](const boost::system::error_code& ec, tcp::endpoint e)
                         { r = {true, ec, e}; });
    run_until(ioc, r, std::chrono::seconds(5));
    ASSERT_TRUE(r.done);
    EXPECT_FALSE(r.ec) << r.ec.message();
    EXPECT_TRUE(r.ep.address().is_v4());
}

TEST(DualFamilyDial, AaaaOnlyHostConnects)
{
    boost::asio::io_context ioc;
    auto v6 = try_listen(ioc, "::1");
    if (!v6) GTEST_SKIP() << "no IPv6 loopback on this host";
    tcp::socket s(ioc);
    DialResult r;
    core::dial_endpoints(s, {tcp::endpoint(make_address("::1"), port_of(*v6))},
                         std::chrono::milliseconds(300), "kat",
                         [&](const boost::system::error_code& ec, tcp::endpoint e)
                         { r = {true, ec, e}; });
    run_until(ioc, r, std::chrono::seconds(5));
    ASSERT_TRUE(r.done);
    EXPECT_FALSE(r.ec) << r.ec.message();
    EXPECT_TRUE(r.ep.address().is_v6());
}

// Preservation: v6 REFUSED -> v4. (Plain asio already did this; pinned so the
// staged path does not lose it.)
TEST(DualFamilyDial, FallsBackToV4WhenV6Refused)
{
    boost::asio::io_context ioc;
    auto dead6 = closed_v6_port(ioc);
    if (!dead6) GTEST_SKIP() << "no IPv6 loopback on this host";
    auto v4 = try_listen(ioc, "127.0.0.1");
    ASSERT_TRUE(v4);

    tcp::socket s(ioc);
    DialResult r;
    core::dial_endpoints(s, {tcp::endpoint(make_address("::1"), *dead6),
                             tcp::endpoint(make_address("127.0.0.1"), port_of(*v4))},
                         std::chrono::milliseconds(300), "kat",
                         [&](const boost::system::error_code& ec, tcp::endpoint e)
                         { r = {true, ec, e}; });
    run_until(ioc, r, std::chrono::seconds(5));
    ASSERT_TRUE(r.done);
    EXPECT_FALSE(r.ec) << r.ec.message();
    EXPECT_TRUE(r.ep.address().is_v4());
}

// RED without the fix. A v6 listener whose accept queue is full drops further
// SYNs (Linux, tcp_abort_on_overflow=0): the connect hangs in retransmits, the
// same shape as a configured-but-unrouted v6 path. Pre-fix range connect stays
// stuck on it; the staged dial abandons it at the deadline and lands on v4.
TEST(DualFamilyDial, FallsBackToV4WhenV6Blackholed)
{
    boost::asio::io_context ioc;
    auto hole = try_listen(ioc, "::1", 0, /*backlog=*/0);
    if (!hole) GTEST_SKIP() << "no IPv6 loopback on this host";
    auto v4 = try_listen(ioc, "127.0.0.1");
    ASSERT_TRUE(v4);
    const tcp::endpoint hole_ep(make_address("::1"), port_of(*hole));
    const tcp::endpoint live_ep(make_address("127.0.0.1"), port_of(*v4));

    // Fill the accept queue (never accepted).
    std::vector<std::unique_ptr<tcp::socket>> fillers;
    for (int i = 0; i < 4; ++i)
    {
        fillers.push_back(std::make_unique<tcp::socket>(ioc));
        fillers.back()->async_connect(hole_ep, [](const boost::system::error_code&) {});
    }
    ioc.run_for(std::chrono::milliseconds(300));

    // CONTROL -- the pre-fix path, verbatim: range async_connect over the same
    // list. It must still be pending after 2 s, or this host cannot blackhole
    // and the green case below would prove nothing.
    {
        tcp::socket legacy(ioc);
        DialResult lr;
        boost::asio::async_connect(legacy, std::vector<tcp::endpoint>{hole_ep, live_ep},
            [&](const boost::system::error_code& ec, tcp::endpoint e) { lr = {true, ec, e}; });
        run_until(ioc, lr, std::chrono::seconds(2));
        if (lr.done)
            GTEST_SKIP() << "accept-queue blackhole not reproducible here (legacy dial "
                            "completed: " << lr.ec.message() << ")";
        boost::system::error_code ig;
        legacy.close(ig);
        ioc.restart();
        ioc.poll();
    }

    tcp::socket s(ioc);
    DialResult r;
    core::dial_endpoints(s, {hole_ep, live_ep}, std::chrono::milliseconds(300), "kat",
                         [&](const boost::system::error_code& ec, tcp::endpoint e)
                         { r = {true, ec, e}; });
    const auto took = run_until(ioc, r, std::chrono::seconds(5));
    ASSERT_TRUE(r.done) << "staged dial did not fall back to v4 within 5 s";
    EXPECT_FALSE(r.ec) << r.ec.message();
    EXPECT_EQ(r.ep, live_ep);
    EXPECT_LT(took.count(), 2000);
}

// ── wiring through the real core::Factory<core::Client> ──────────────────────

const std::vector<std::byte>& probe_prefix()
{
    static const std::vector<std::byte> p{};
    return p;
}

struct DialProbeNode : public core::ICommunicator,
                       public core::INetwork,
                       public core::Factory<core::Client>
{
    explicit DialProbeNode(boost::asio::io_context* c)
        : core::Factory<core::Client>(c, this, "kat-965ph3") {}

    std::shared_ptr<core::Socket> last;
    int failed = 0;

    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<::RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return probe_prefix(); }
    void connected(std::shared_ptr<core::Socket> s) override { last = std::move(s); }
    void disconnect() override {}
    void connect_failed(const ::NetService&) override { ++failed; }
};

// "localhost" listeners on the SAME port in both families, or skip.
struct DualLocalhost
{
    std::unique_ptr<tcp::acceptor> v4, v6;
    unsigned short port = 0;
};

std::optional<DualLocalhost> dual_localhost(boost::asio::io_context& ioc)
{
    {
        tcp::resolver res(ioc);
        boost::system::error_code ec;
        auto results = res.resolve("localhost", "9999", ec);
        if (ec) return std::nullopt;
        bool v4 = false, v6 = false;
        for (const auto& r : results)
            (r.endpoint().address().is_v6() ? v6 : v4) = true;
        if (!(v4 && v6)) return std::nullopt;
    }
    for (int i = 0; i < 20; ++i)
    {
        DualLocalhost d;
        d.v4 = try_listen(ioc, "127.0.0.1");
        if (!d.v4) return std::nullopt;
        d.port = port_of(*d.v4);
        d.v6 = try_listen(ioc, "::1", d.port);
        if (d.v6) return d;
    }
    return std::nullopt;
}

// Which listener the Factory dial landed on.
std::optional<DialFamily> accept_one(boost::asio::io_context& ioc, DualLocalhost& d,
                                     DialProbeNode& node)
{
    std::optional<DialFamily> got;
    tcp::socket a4(ioc), a6(ioc);
    d.v4->async_accept(a4, [&](const boost::system::error_code& ec)
                       { if (!ec && !got) got = DialFamily::V4; });
    d.v6->async_accept(a6, [&](const boost::system::error_code& ec)
                       { if (!ec && !got) got = DialFamily::V6; });
    node.connect(::NetService(std::string("localhost"), std::to_string(d.port)));

    const auto t0 = std::chrono::steady_clock::now();
    ioc.restart();
    while ((!got || !node.last) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5))
        ioc.run_for(std::chrono::milliseconds(20));
    d.v4->cancel();
    d.v6->cancel();
    ioc.restart();
    ioc.poll();
    return got;
}

// RED without the fix: the memo says v4 worked last time, so the dial must lead
// with 127.0.0.1 even though the resolver lists ::1 first. Run both ways so a
// resolver that happens to list v4 first cannot make it pass by coincidence.
TEST(DualFamilyDial, FactoryClientLeadsWithPriorSuccessFamily)
{
    boost::asio::io_context ioc;
    auto d = dual_localhost(ioc);
    if (!d) GTEST_SKIP() << "localhost does not resolve to both ::1 and 127.0.0.1 here";

    for (DialFamily want : {DialFamily::V4, DialFamily::V6})
    {
        core::clear_dial_families();
        core::record_dial_family("localhost", want);
        auto node = std::make_shared<DialProbeNode>(&ioc);
        node->set_lifetime(node);
        auto got = accept_one(ioc, *d, *node);
        ASSERT_TRUE(got.has_value()) << "no inbound accepted";
        EXPECT_EQ(*got, want) << "led with " << core::dial_family_name(*got)
                              << ", memo said " << core::dial_family_name(want);
        if (node->last) node->last->close();
    }
    core::clear_dial_families();
}

// RED without the fix: a completed mixed-family dial writes the family memo.
TEST(DualFamilyDial, FactoryClientRecordsWinningFamily)
{
    boost::asio::io_context ioc;
    auto d = dual_localhost(ioc);
    if (!d) GTEST_SKIP() << "localhost does not resolve to both ::1 and 127.0.0.1 here";

    core::clear_dial_families();
    auto node = std::make_shared<DialProbeNode>(&ioc);
    node->set_lifetime(node);
    auto got = accept_one(ioc, *d, *node);
    ASSERT_TRUE(got.has_value());
    ASSERT_TRUE(node->last) << "connected() never fired";
    EXPECT_EQ(core::preferred_dial_family("localhost"), got);
    node->last->close();
    core::clear_dial_families();
}

} // namespace
