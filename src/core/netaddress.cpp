#include "netaddress.hpp"

#include <core/log.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <sstream>
#include <iomanip>

void NetAddress::Write_IPV4(PackStream& os) const
{
    auto ip = m_ip;
    std::vector<uint8_t> data;
    if (ip.find(':') < ip.size())
    {
        boost::erase_all(ip, ":");
        data = ParseHex(ip);
    } else
    {
        std::vector<std::string> split_res;
        boost::algorithm::split(split_res, ip, boost::is_any_of("."));
        if (split_res.size() != 4)
        {
            // Not a dotted-decimal IPv4 address (e.g. "localhost") — use loopback 127.0.0.1
            LOG_WARNING << "Write_IPV4: non-dotted address '" << ip << "', substituting 127.0.0.1";
            split_res = {"127", "0", "0", "1"};
        }

        std::vector<unsigned int> bits;
        for (auto bit: split_res)
        {
            int bit_int = 0;
            try
            {
                bit_int = boost::lexical_cast<unsigned int>(bit);
            } catch (boost::bad_lexical_cast const &)
            {
                LOG_ERROR << "Error lexical cast in IPV6AddressType";
            }
            bits.push_back(bit_int);
        }

        data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
        for (auto x: bits)
        {
            data.push_back((uint8_t) x);
        }
    }

    assert(data.size() == 16);
    os << Using<ArrayType<DefaultFormat, 16>>(data);
}

void NetAddress::Read_IPV4(PackStream& is)
{
    std::vector<unsigned char> hex_data{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    // if (is.size() >= 16)
    {
        // std::vector<unsigned char> data{stream.data.begin(), stream.data.begin() + 16};
        // stream.data.erase(stream.data.begin(), stream.data.begin() + 16);
        std::vector<uint8_t> data;
        is >> Using<ArrayType<DefaultFormat, 16>>(data);
        bool ipv4 = true;
        for (int i = 0; i < 12; i++)
        {
            if (data[i] != hex_data[i])
            {
                ipv4 = false;
                break;
            }
        }

        if (ipv4)
        {
            std::vector<std::string> nums;
            for (int i = 12; i < 16; i++)
            {
                auto num = std::to_string((unsigned int) data[i]);
                nums.push_back(num);
            }
            m_ip = boost::algorithm::join(nums, ".");
        } else
        {
            // Real IPv6: format 16 bytes as colon-separated hex groups
            std::ostringstream oss;
            for (int i = 0; i < 16; i += 2)
            {
                if (i > 0) oss << ':';
                oss << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<unsigned>(data[i])
                    << std::setw(2)
                    << static_cast<unsigned>(data[i + 1]);
            }
            m_ip = oss.str();
            m_type = NET_IPV6;
        }
    //else
    // {
    //     throw std::runtime_error("Invalid address!");
    // }
    // return stream;
    }
}
    
void NetAddress::Write_IPV6(PackStream& os) const
{
    // If m_ip contains colons, parse as IPv6 hex string
    // Otherwise fall back to all-zeros
    std::vector<uint8_t> data(16, 0);
    try {
        boost::asio::ip::address_v6 addr = boost::asio::ip::make_address_v6(m_ip);
        auto bytes = addr.to_bytes();
        std::copy(bytes.begin(), bytes.end(), data.begin());
    } catch (...) {
        // If the address looks like IPv4, serialize as IPv4-mapped
        try {
            boost::asio::ip::address_v4 v4 = boost::asio::ip::make_address_v4(m_ip);
            data = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff};
            auto v4b = v4.to_bytes();
            data.insert(data.end(), v4b.begin(), v4b.end());
        } catch (...) {
            LOG_WARNING << "Write_IPV6: cannot serialize address: " << m_ip;
        }
    }
    os << Using<ArrayType<DefaultFormat, 16>>(data);
}

void NetAddress::Read_IPV6(PackStream& is)
{
    // Read 16 bytes, same as Read_IPV4 — detect IPv4-mapped or real IPv6
    Read_IPV4(is);
}

// ═══════════════════════════════════════════════════════════════════════════════
// classify_address() — Bitcoin Core CNetAddr::IsRoutable() port
//
// Reference: bitcoin/src/netaddress.cpp (IsRFC1918, IsRFC2544, IsRFC3927,
//            IsRFC4193, IsRFC4862, IsRFC5737, IsRFC6598, IsLocal, IsRoutable)
// ═══════════════════════════════════════════════════════════════════════════════

AddrClass classify_address(std::string_view ip)
{
    if (ip.empty()) return AddrClass::invalid;

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(std::string(ip), ec);
    if (ec) return AddrClass::invalid;

    // ── IPv4 ────────────────────────────────────────────────────────────────
    if (addr.is_v4()) {
        auto b = addr.to_v4().to_bytes();

        // 0.0.0.0/8 — unspecified
        if (b[0] == 0) return AddrClass::unspecified;

        // 127.0.0.0/8 — loopback
        if (b[0] == 127) return AddrClass::loopback;

        // 169.254.0.0/16 — link-local (RFC3927)
        if (b[0] == 169 && b[1] == 254) return AddrClass::link_local;

        // 10.0.0.0/8 — private (RFC1918)
        if (b[0] == 10) return AddrClass::private_net;

        // 172.16.0.0/12 — private (RFC1918)
        if (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) return AddrClass::private_net;

        // 192.168.0.0/16 — private (RFC1918)
        if (b[0] == 192 && b[1] == 168) return AddrClass::private_net;

        // 100.64.0.0/10 — carrier-grade NAT (RFC6598)
        if (b[0] == 100 && (b[1] >= 64 && b[1] <= 127)) return AddrClass::carrier_nat;

        // 192.0.2.0/24 — documentation (RFC5737)
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return AddrClass::documentation;

        // 198.51.100.0/24 — documentation (RFC5737)
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return AddrClass::documentation;

        // 203.0.113.0/24 — documentation (RFC5737)
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return AddrClass::documentation;

        // 198.18.0.0/15 — benchmark (RFC2544)
        if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return AddrClass::benchmark;

        // 224.0.0.0/4 — multicast
        if (b[0] >= 224 && b[0] <= 239) return AddrClass::multicast;

        // 240.0.0.0/4 — reserved (future use / broadcast)
        if (b[0] >= 240) return AddrClass::invalid;

        return AddrClass::routable;
    }

    // ── IPv6 ────────────────────────────────────────────────────────────────
    if (addr.is_v6()) {
        auto v6 = addr.to_v6();

        // IPv4-mapped (::ffff:x.x.x.x) — classify the embedded IPv4
        if (v6.is_v4_mapped()) {
            auto v4 = boost::asio::ip::make_address_v4(
                boost::asio::ip::v4_mapped, v6);
            return classify_address(v4.to_string());
        }

        // ::1 — loopback
        if (v6.is_loopback()) return AddrClass::loopback;

        // :: — unspecified
        if (v6 == boost::asio::ip::address_v6::any()) return AddrClass::unspecified;

        auto b = v6.to_bytes();

        // fe80::/10 — link-local (RFC4862)
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return AddrClass::link_local;

        // fc00::/7 — unique local / private (RFC4193)
        if ((b[0] & 0xfe) == 0xfc) return AddrClass::private_net;

        // ff00::/8 — multicast
        if (b[0] == 0xff) return AddrClass::multicast;

        // 2001:db8::/32 — documentation (RFC3849)
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
            return AddrClass::documentation;

        // 2001:10::/28 — ORCHID deprecated (RFC4843)
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xf0) == 0x10)
            return AddrClass::benchmark; // treated same as benchmark

        // 2001:20::/28 — ORCHIDv2 (RFC7343)
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xf0) == 0x20)
            return AddrClass::benchmark;

        return AddrClass::routable;
    }

    return AddrClass::invalid;
}
