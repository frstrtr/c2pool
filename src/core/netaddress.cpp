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
            throw (std::runtime_error("Invalid address in IPV6AddressType"));
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
