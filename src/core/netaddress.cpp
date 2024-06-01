#include "netaddress.hpp"

#include <core/log.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

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
            //TODO: IPV6
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

}

void NetAddress::Read_IPV6(PackStream& is)
{

}
