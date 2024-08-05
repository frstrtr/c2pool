#pragma once

#include <core/pack_types.hpp>

#include <boost/spirit/home/x3.hpp>
#include <boost/fusion/adapted/std_tuple.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio.hpp>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

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