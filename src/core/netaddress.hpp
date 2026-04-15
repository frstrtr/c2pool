#pragma once

#include <core/pack_types.hpp>

#include <boost/spirit/home/x3.hpp>
#include <boost/fusion/adapted/std_tuple.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio.hpp>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include <optional>
#include <string_view>

enum AddrType
{
    NET_IPV4,
    NET_IPV6
};

static const std::array<uint8_t, 12> IPV4_IN_IPV6_PREFIX
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF};

inline auto parse_address(std::string_view address_spec, std::string_view default_service = "https")
{
    using namespace boost::spirit::x3;
    auto service = ':' >> +~char_(":") >> eoi;
    auto host    = '[' >> *~char_(']') >> ']' // e.g. for IPV6
        | raw[*("::" | (char_ - service))];

    std::tuple<std::string, std::string> result;
    parse(begin(address_spec), end(address_spec),
          expect[host >> (service | attr(default_service))], result);

    return result;
}

class NetAddress
{
protected:
    AddrType m_type {NET_IPV4};

    std::string m_ip;

public:
    NetAddress() : m_ip("localhost") { }

    NetAddress(const std::string& ip) : m_ip(ip) { }
    NetAddress(std::string&& ip) : m_ip(ip) { }

    NetAddress(const boost::asio::ip::address& boost_addr) : m_ip(boost_addr.to_string()) { if (boost_addr.is_v6()) m_type = {NET_IPV6}; } 
    NetAddress(const boost::asio::ip::tcp::endpoint& ep) : NetAddress(ep.address()) { }

    void set_address(std::string ip) { m_ip = ip; }
    auto address() const { return m_ip; }

    friend bool operator==(const NetAddress& l, const NetAddress& r)
    { return (l.m_type == r.m_type) && (l.m_ip == r.m_ip); }

    friend bool operator!=(const NetAddress& l, const NetAddress& r)
    { return !(l == r); }

    friend bool operator<(const NetAddress& l, const NetAddress& r)
    { return l.m_ip < r.m_ip; }

    friend bool operator>(const NetAddress& l, const NetAddress& r)
    { return r < l; }

    friend bool operator<=(const NetAddress& l, const NetAddress& r)
    { return !(r < l); }

    friend bool operator>=(const NetAddress& l, const NetAddress& r)
    { return !(l < r); }

    void Serialize(PackStream &os) const
    {
        switch (m_type)
        {
        case NET_IPV4:
            Write_IPV4(os);
            break;
        case NET_IPV6:
            Write_IPV6(os);
            break;
        };
    }

    void Unserialize(PackStream &is)
    {
        switch (m_type)
        {
        case NET_IPV4:
            Read_IPV4(is);
            break;
        case NET_IPV6:
            Read_IPV6(is);
            break;
        };
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NetAddress, m_ip);

protected:
    void Write_IPV4(PackStream& os) const;
    void Read_IPV4(PackStream& is);
    
    void Write_IPV6(PackStream& os) const;
    void Read_IPV6(PackStream& is);
};

class NetService : public NetAddress
{
protected:
    uint16_t m_port{};

public:

    NetService() = default;

    NetService(std::string addr) 
    { 
        auto [ip, port] = parse_address(addr);

        set_address(ip);
        m_port = std::stoi(port);
    }
    NetService(std::string addr, std::string port) : NetAddress(addr), m_port(std::stoi(port)) { }
    NetService(const std::string& ip, uint16_t port) : NetAddress(ip), m_port(port) { }
    NetService(const boost::asio::ip::address& boost_addr, uint16_t port) : NetAddress(boost_addr), m_port(port) 
    { if (boost_addr.is_v6()) m_type = {NET_IPV6}; } 
    NetService(const boost::asio::ip::tcp::endpoint& ep) : NetAddress(ep.address()), m_port(ep.port()) { }

    uint16_t port() const { return m_port; }
    std::string port_str() const { return std::to_string(m_port); }
    std::string to_string() const { return m_ip + ":" + port_str(); }

    SERIALIZE_METHODS(NetService) { READWRITE(AsBase<NetAddress>(obj), Using<IntType<16, true>>(obj.m_port)); }

    friend bool operator==(const NetService& l, const NetService& r)
    { return (l.m_type == r.m_type) && (l.m_ip == r.m_ip) && (l.m_port == r.m_port); }

    friend bool operator!=(const NetService& l, const NetService& r)
    { return !(l == r); }

    friend bool operator<(const NetService& l, const NetService& r)
    { return std::tie(l.m_ip, l.m_port) < std::tie(r.m_ip, r.m_port); }

    friend bool operator>(const NetService& l, const NetService& r)
    { return r < l; }

    friend bool operator<=(const NetService& l, const NetService& r)
    { return !(r < l); }

    friend bool operator>=(const NetService& l, const NetService& r)
    { return !(l < r); }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NetService, m_ip, m_port);
};

namespace YAML {
template<>
struct convert<NetService> {
    static Node encode(const NetService& rhs) 
    {
        Node node;
        node = rhs.to_string();
        return node;
    }

    static bool decode(const Node& node, NetService& rhs) 
    {
        rhs = NetService(node.as<std::string>());
        return true;
    }
};
}

struct addr_t
{
    uint64_t m_services { };
    NetService m_endpoint;

    addr_t() { }
    addr_t(uint64_t services, NetService endpoint) : m_services(services), m_endpoint(endpoint) { }

    SERIALIZE_METHODS(addr_t) { READWRITE(obj.m_services, obj.m_endpoint); }
};

struct addr_record_t : addr_t
{
    uint64_t m_timestamp{};

    addr_record_t() : addr_t() {}
    addr_record_t(addr_t addr, uint64_t timestamp) : addr_t(addr), m_timestamp(timestamp) { }
    addr_record_t(uint64_t services, NetService endpoint, uint64_t timestamp) : addr_t(services, endpoint), m_timestamp(timestamp) {}

    SERIALIZE_METHODS(addr_record_t) { READWRITE(obj.m_timestamp, AsBase<addr_t>(obj)); }
};


// template <IsInteger int_type>
// inline void Serialize(PackStream& os, const NetAddr& value)
// {
//     os.write(std::as_bytes(std::span{&value, 1}));
// }

// template <IsInteger int_type>
// inline void Unserialize(PackStream& is, NetAddr& value)
// {
//     is.read(std::as_writable_bytes(std::span{&value, 1}));
// }

// ═══════════════════════════════════════════════════════════════════════════════
// Address classification — port of Bitcoin Core's CNetAddr::IsRoutable()
// ═══════════════════════════════════════════════════════════════════════════════

/// RFC-based IP address classification (Bitcoin Core netaddress.h).
/// classify_address() computes this once; PeerEndpoint caches it.
enum class AddrClass : uint8_t
{
    invalid,        // empty or unparseable
    unspecified,    // 0.0.0.0/8, ::/128
    loopback,       // 127.0.0.0/8, ::1
    link_local,     // 169.254.0.0/16 (RFC3927), fe80::/10 (RFC4862)
    private_net,    // 10/8, 172.16/12, 192.168/16 (RFC1918), fc00::/7 (RFC4193)
    carrier_nat,    // 100.64.0.0/10 (RFC6598)
    documentation,  // 192.0.2/24, 198.51.100/24, 203.0.113/24 (RFC5737)
    benchmark,      // 198.18.0.0/15 (RFC2544)
    multicast,      // 224.0.0.0/4, ff00::/8
    routable        // globally reachable
};

/// Classify an IP address string using Bitcoin Core's rules.
/// Returns AddrClass::invalid for empty or unparseable strings.
AddrClass classify_address(std::string_view ip);

/// True if the address is globally routable (not private, loopback, etc.).
inline bool is_routable(std::string_view ip) { return classify_address(ip) == AddrClass::routable; }

/// True if the address can be used as a connection target at all
/// (non-empty, parseable, not unspecified 0.0.0.0). Includes local/private.
inline bool is_connectable(std::string_view ip)
{
    auto c = classify_address(ip);
    return c != AddrClass::invalid && c != AddrClass::unspecified
        && c != AddrClass::documentation && c != AddrClass::multicast;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PeerEndpoint — validated network endpoint for peer connections.
//
// Invariants enforced at construction via factory (private ctor):
//   • host is non-empty and parseable as IPv4 or IPv6
//   • port > 0
//   • AddrClass is computed and cached
//
// Unvalidated NetService stays for wire protocol / serialization.
// PeerEndpoint is the boundary at the peer management layer.
// ═══════════════════════════════════════════════════════════════════════════════

class PeerEndpoint
{
public:
    /// Factory: validate and construct. Returns nullopt if host is empty,
    /// unparseable, unspecified (0.0.0.0), or port is 0.
    [[nodiscard]] static std::optional<PeerEndpoint> from(
        const std::string& host, uint16_t port)
    {
        if (host.empty() || port == 0) return std::nullopt;
        auto cls = classify_address(host);
        if (cls == AddrClass::invalid || cls == AddrClass::unspecified) return std::nullopt;
        return PeerEndpoint{host, port, cls};
    }

    /// Factory: validate from existing NetService.
    [[nodiscard]] static std::optional<PeerEndpoint> from(const NetService& addr)
    {
        return from(addr.address(), addr.port());
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    const std::string& host() const noexcept { return m_host; }
    uint16_t port() const noexcept { return m_port; }
    AddrClass addr_class() const noexcept { return m_class; }

    /// True if globally routable (not private, loopback, link-local, etc.)
    bool is_routable() const noexcept { return m_class == AddrClass::routable; }

    /// True if local: loopback or RFC1918 private.
    bool is_local() const noexcept
    {
        return m_class == AddrClass::loopback || m_class == AddrClass::private_net;
    }

    std::string to_string() const { return m_host + ":" + std::to_string(m_port); }

    /// Convert back to NetService for existing APIs / wire protocol.
    NetService to_net_service() const { return NetService(m_host, m_port); }

    // ── Comparison ─────────────────────────────────────────────────────────

    friend bool operator==(const PeerEndpoint& a, const PeerEndpoint& b)
    { return a.m_host == b.m_host && a.m_port == b.m_port; }

    friend bool operator!=(const PeerEndpoint& a, const PeerEndpoint& b)
    { return !(a == b); }

    friend bool operator<(const PeerEndpoint& a, const PeerEndpoint& b)
    { return std::tie(a.m_host, a.m_port) < std::tie(b.m_host, b.m_port); }

    // ── JSON serialization (for peer database persistence) ─────────────────

    friend void to_json(nlohmann::json& j, const PeerEndpoint& ep)
    {
        j = nlohmann::json{{"host", ep.m_host}, {"port", ep.m_port}};
    }

    friend void from_json(const nlohmann::json& j, PeerEndpoint& ep)
    {
        // Deserialize into a temporary and validate
        std::string host = j.at("host").get<std::string>();
        uint16_t port = j.at("port").get<uint16_t>();
        auto maybe = PeerEndpoint::from(host, port);
        if (!maybe) throw std::invalid_argument("invalid PeerEndpoint: " + host + ":" + std::to_string(port));
        ep = *maybe;
    }

private:
    PeerEndpoint(std::string host, uint16_t port, AddrClass cls)
        : m_host(std::move(host)), m_port(port), m_class(cls) {}

    std::string m_host;
    uint16_t    m_port;
    AddrClass   m_class;
};