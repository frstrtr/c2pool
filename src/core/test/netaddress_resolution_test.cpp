// Regression cover for issue #910 — a DNS-named --addnode was advertised to
// peers as 127.0.0.1.
//
// NetAddress::Write_IPV4 used to split the address string on '.', demand
// exactly four parts, and silently substitute loopback otherwise. The stored
// string for `--addnode rov.p2p-spb.xyz:8999` is the HOSTNAME (kept on purpose,
// so every reconnect re-resolves it), so every addrs/getaddrs reply carrying
// that seed put 127.0.0.1 on the wire — an address that, for the peer learning
// it, points back at itself.
//
// Three layers here:
//
//  1. WIRE PINS. Write_IPV4 emits 4 raw IPv4 bytes inside a 16-byte
//     IPv4-in-IPv6 envelope. That is a p2p surface shared with canonical python
//     p2pool, so the fix must not move a single byte for numeric input. Every
//     dotted-quad KAT below is the byte string this serializer produced before
//     the fix and must keep producing — including a genuine
//     `--addnode 127.0.0.1:18999`, which the hotel legitimately runs.
//
//  2. THE DEFECT. A hostname must not serialize to loopback, and once the
//     outbound-connect resolver has resolved it, it must serialize to that A
//     record. Both of these fail on the pre-fix serializer.
//
//  3. THE ADVERTISEMENT FILTER. A source KAT pinning the
//     is_wire_advertisable() guard into all ten per-coin
//     protocol_actual.cpp / protocol_legacy.cpp getaddrs handlers, so no lane
//     can quietly regress to advertising an unrenderable address.
//
// Folded into the EXISTING allowlisted core_test target — a standalone
// add_executable is not in build.yml's --target list, so CI would never build
// it and CTest would report the cases "Not Run" (the #769 trap). One KAT covers
// every coin because all five node lanes consume this one shared core file.

#include <gtest/gtest.h>

#include <core/netaddress.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

// The IPv4-in-IPv6 envelope every Write_IPV4 output carries.
const std::vector<uint8_t> V4_PREFIX{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

std::vector<uint8_t> serialize(const NetAddress& addr)
{
    PackStream stream;
    stream << addr;

    std::vector<uint8_t> out;
    for (auto b : stream.get_span())
        out.push_back(std::to_integer<uint8_t>(b));
    return out;
}

// The four address bytes, after asserting the 16-byte envelope.
std::vector<uint8_t> wire_quad(const NetAddress& addr)
{
    auto bytes = serialize(addr);
    EXPECT_EQ(bytes.size(), 16u) << "IPv4 addresses must occupy exactly 16 wire bytes";
    if (bytes.size() != 16)
        return {};
    EXPECT_TRUE(std::equal(V4_PREFIX.begin(), V4_PREFIX.end(), bytes.begin()))
        << "IPv4-in-IPv6 prefix must be unchanged";
    return std::vector<uint8_t>(bytes.begin() + 12, bytes.end());
}

const std::vector<uint8_t> LOOPBACK_QUAD{0x7f, 0x00, 0x00, 0x01};

// The two DNS names from the production hotel's --addnode list, and the
// addresses they actually resolve to (issue #910).
constexpr const char* HOST_ROV = "rov.p2p-spb.xyz";
constexpr const char* HOST_USA = "usa.p2p-spb.xyz";
constexpr const char* IP_ROV   = "83.221.211.116";
constexpr const char* IP_USA   = "66.151.242.154";

struct ResolvedHostsFixture : public ::testing::Test
{
    void SetUp() override { core::clear_resolved_hosts(); }
    void TearDown() override { core::clear_resolved_hosts(); }
};

} // namespace

// ---------------------------------------------------------------------------
// Layer 1: wire-format pins. These must be byte-identical before and after.
// ---------------------------------------------------------------------------

TEST_F(ResolvedHostsFixture, DottedQuadWireBytesAreUnchanged)
{
    struct Case { const char* ip; std::vector<uint8_t> quad; };
    const std::vector<Case> cases{
        {"0.0.0.0",         {0x00, 0x00, 0x00, 0x00}},
        {"1.2.3.4",         {0x01, 0x02, 0x03, 0x04}},
        {"10.0.0.1",        {0x0a, 0x00, 0x00, 0x01}},
        {"192.168.1.1",     {0xc0, 0xa8, 0x01, 0x01}},
        {"83.221.211.116",  {0x53, 0xdd, 0xd3, 0x74}},   // rov.p2p-spb.xyz
        {"66.151.242.154",  {0x42, 0x97, 0xf2, 0x9a}},   // usa.p2p-spb.xyz
        {"255.255.255.255", {0xff, 0xff, 0xff, 0xff}},
    };

    for (const auto& c : cases)
    {
        EXPECT_EQ(wire_quad(NetAddress(std::string(c.ip))), c.quad)
            << "wire encoding changed for " << c.ip;
    }
}

TEST_F(ResolvedHostsFixture, GenuineLoopbackStillSerializesAndRoundTrips)
{
    // The hotel legitimately runs `--addnode 127.0.0.1:18999`. A real loopback
    // address is NOT what #910 is about and must keep working untouched.
    EXPECT_EQ(wire_quad(NetAddress(std::string("127.0.0.1"))), LOOPBACK_QUAD);

    PackStream stream;
    NetService written{std::string("127.0.0.1"), uint16_t{18999}};
    stream << written;
    EXPECT_EQ(stream.get_span().size(), 18u);  // 16 address bytes + 2 port bytes

    NetService read;
    stream >> read;
    EXPECT_EQ(read.address(), "127.0.0.1");
    EXPECT_EQ(read.port(), uint16_t{18999});
}

TEST_F(ResolvedHostsFixture, LocalhostStillMapsToLoopback)
{
    // "localhost" IS 127.0.0.1 — a genuine resolution, not the blanket
    // substitution. The default-constructed NetAddress carries "localhost", so
    // this also pins the default ctor's wire bytes.
    EXPECT_EQ(wire_quad(NetAddress(std::string("localhost"))), LOOPBACK_QUAD);
    EXPECT_EQ(wire_quad(NetAddress()), LOOPBACK_QUAD);
}

TEST_F(ResolvedHostsFixture, DottedQuadRoundTripsThroughUnserialize)
{
    PackStream stream;
    NetAddress written{std::string("83.221.211.116")};
    stream << written;

    NetAddress read;
    stream >> read;
    EXPECT_EQ(read.address(), "83.221.211.116");
}

// ---------------------------------------------------------------------------
// Layer 2: the defect. Both of these fail on the pre-fix serializer.
// ---------------------------------------------------------------------------

TEST_F(ResolvedHostsFixture, UnresolvedHostnameDoesNotSerializeToLoopback)
{
    // Pre-fix: split("rov.p2p-spb.xyz", '.') yields 3 parts, so the serializer
    // substituted {127,0,0,1} and we advertised loopback to every peer.
    auto quad = wire_quad(NetAddress(std::string(HOST_ROV)));
    EXPECT_NE(quad, LOOPBACK_QUAD)
        << "a DNS name must never be advertised as loopback (#910)";

    // Nor may it become any other plausible-looking address. Unknown means
    // unroutable: 0.0.0.0 is rejected by is_connectable() at the far end.
    EXPECT_EQ(quad, (std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00}));
}

TEST_F(ResolvedHostsFixture, HostnameWithFourLabelsDoesNotSerializeAsGarbage)
{
    // A four-label name split into exactly four parts pre-fix and was fed
    // straight into lexical_cast, producing silent garbage rather than an
    // error. It is a name, not a literal, and must be treated as one.
    auto quad = wire_quad(NetAddress(std::string("seed.node.example.com")));
    EXPECT_NE(quad, LOOPBACK_QUAD);
    EXPECT_EQ(quad, (std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00}));

    core::record_resolved_host("seed.node.example.com", IP_USA);
    EXPECT_EQ(wire_quad(NetAddress(std::string("seed.node.example.com"))),
              (std::vector<uint8_t>{0x42, 0x97, 0xf2, 0x9a}));
}

TEST_F(ResolvedHostsFixture, ResolvedHostnameSerializesToItsARecord)
{
    // This is what the outbound-connect resolver records on every dial.
    core::record_resolved_host(HOST_ROV, IP_ROV);
    core::record_resolved_host(HOST_USA, IP_USA);

    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_ROV))),
              (std::vector<uint8_t>{0x53, 0xdd, 0xd3, 0x74}));
    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_USA))),
              (std::vector<uint8_t>{0x42, 0x97, 0xf2, 0x9a}));

    // ...and identical to serializing the literal directly.
    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_ROV))),
              wire_quad(NetAddress(std::string(IP_ROV))));
}

TEST_F(ResolvedHostsFixture, ResolvedHostnameKeepsItsNameForReconnect)
{
    // The whole point of a DNS seed is that it survives an IP change, so the
    // name must stay the stored/dialled identity — only the wire rendering
    // changes.
    core::record_resolved_host(HOST_USA, IP_USA);
    NetService svc{std::string(HOST_USA), uint16_t{8999}};
    EXPECT_EQ(svc.address(), HOST_USA);
    EXPECT_EQ(svc.to_string(), std::string(HOST_USA) + ":8999");
}

TEST_F(ResolvedHostsFixture, ReResolutionTracksAnIpChange)
{
    core::record_resolved_host(HOST_USA, IP_ROV);
    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_USA))),
              (std::vector<uint8_t>{0x53, 0xdd, 0xd3, 0x74}));

    core::record_resolved_host(HOST_USA, IP_USA);   // next dial, new answer
    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_USA))),
              (std::vector<uint8_t>{0x42, 0x97, 0xf2, 0x9a}));
}

TEST_F(ResolvedHostsFixture, MemoRefusesNonNumericAnswersAndLiteralKeys)
{
    // The memo records answers from the ONE existing resolver; it must never
    // become a second source of names, and a literal needs no memo.
    core::record_resolved_host(HOST_ROV, "not-an-address");
    EXPECT_FALSE(core::lookup_resolved_host(HOST_ROV).has_value());

    core::record_resolved_host("1.2.3.4", IP_ROV);
    EXPECT_FALSE(core::lookup_resolved_host("1.2.3.4").has_value());
    // ...and a literal still serializes as itself regardless.
    EXPECT_EQ(wire_quad(NetAddress(std::string("1.2.3.4"))),
              (std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}));

    // An AAAA-only answer cannot be squeezed into four IPv4 bytes, so it is
    // treated as unknown rather than corrupting the envelope.
    core::record_resolved_host(HOST_USA, "2001:db8::1");
    EXPECT_TRUE(core::lookup_resolved_host(HOST_USA).has_value());
    EXPECT_FALSE(NetAddress(std::string(HOST_USA)).is_wire_advertisable());
    EXPECT_EQ(wire_quad(NetAddress(std::string(HOST_USA))),
              (std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00}));
}

// ---------------------------------------------------------------------------
// Layer 3: the advertisement gate
// ---------------------------------------------------------------------------

TEST_F(ResolvedHostsFixture, AdvertisabilityGate)
{
    // Numeric literals are always advertisable — including genuine loopback,
    // which is existing behaviour this fix must not disturb.
    EXPECT_TRUE(NetAddress(std::string("83.221.211.116")).is_wire_advertisable());
    EXPECT_TRUE(NetAddress(std::string("127.0.0.1")).is_wire_advertisable());
    EXPECT_TRUE(NetAddress(std::string("0.0.0.0")).is_wire_advertisable());
    EXPECT_TRUE(NetAddress(std::string("localhost")).is_wire_advertisable());

    // An unresolved name is not — it gets skipped rather than advertised.
    EXPECT_FALSE(NetAddress(std::string(HOST_ROV)).is_wire_advertisable());

    core::record_resolved_host(HOST_ROV, IP_ROV);
    EXPECT_TRUE(NetAddress(std::string(HOST_ROV)).is_wire_advertisable());

    // NetService inherits the gate, which is the form the addr store holds.
    EXPECT_FALSE(NetService(std::string(HOST_USA), uint16_t{8999}).is_wire_advertisable());
    core::record_resolved_host(HOST_USA, IP_USA);
    EXPECT_TRUE(NetService(std::string(HOST_USA), uint16_t{8999}).is_wire_advertisable());
}

// ---------------------------------------------------------------------------
// Source KAT: every per-coin getaddrs handler must carry the filter.
//
// get_good_peers() feeds both the outbound dialler (where a hostname is
// correct and must NOT be filtered) and the getaddrs reply (where an
// unrenderable address must never reach the wire), so the guard lives at the
// ten reply sites. This pins it there for all five lanes.
// ---------------------------------------------------------------------------

namespace
{

std::string read_source(const std::string& rel)
{
#ifndef C2POOL_SRC_ROOT
#error "C2POOL_SRC_ROOT must be defined for the source KAT"
#endif
    const std::string path = std::string(C2POOL_SRC_ROOT) + "/" + rel;
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("cannot open source file: " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

TEST(NetAddressAdvertiseFilterSourceKAT, EveryLaneFiltersUnrenderableAddrsFromGetaddrs)
{
    const std::vector<std::string> coins{"btc", "ltc", "bch", "dgb", "dash"};
    const std::vector<std::string> protocols{"protocol_actual.cpp", "protocol_legacy.cpp"};

    // The push that puts an addr store entry onto the wire.
    const std::regex push_re(
        R"(addrs\.push_back\(\{pair\.value\.m_service,\s*pair\.addr,\s*pair\.value\.m_last_seen\}\);)");
    // The guard that must precede it.
    const std::regex guard_re(
        R"(if\s*\(!pair\.addr\.is_wire_advertisable\(\)\)\s*continue;)");

    for (const auto& coin : coins)
    {
        for (const auto& proto : protocols)
        {
            const std::string rel = "impl/" + coin + "/" + proto;
            const std::string src = read_source(rel);

            EXPECT_TRUE(std::regex_search(src, push_re))
                << rel << ": getaddrs reply push site not found — the KAT has "
                          "drifted from the code it is meant to pin";

            std::smatch guard_m, push_m;
            ASSERT_TRUE(std::regex_search(src, guard_m, guard_re))
                << rel << ": getaddrs must skip addresses that cannot be "
                          "rendered on the wire (#910)";
            ASSERT_TRUE(std::regex_search(src, push_m, push_re));

            EXPECT_LT(guard_m.position(0), push_m.position(0))
                << rel << ": the is_wire_advertisable() guard must precede the "
                          "addrs.push_back()";
        }
    }
}
