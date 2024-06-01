#include "netaddress.hpp"

#include <core/log.hpp>
#include <btclibs/util/strencodings.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

void NetAddress::Write_IPV4(PackStream& os) const
{
    std::vector<uint8_t> data;
    if (m_ip.find(':') < m_ip.size())
    {
        boost::erase_all(m_ip, ":");
        data = ParseHex(m_ip);
    } else
    {
        std::vector<std::string> split_res;
        boost::algorithm::split(split_res, m_ip, boost::is_any_of("."));
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
    // os << data;
}

void NetAddress::Read_IPV4(PackStream& is)
{

}
    
void NetAddress::Write_IPV6(PackStream& os) const
{

}

void NetAddress::Read_IPV6(PackStream& is)
{

}
