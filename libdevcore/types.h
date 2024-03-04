#pragma once

#include <string>
#include <sstream>
#include <tuple>
#include <string>

#include "common.h"
#include "logger.h"
#include "stream_types.h"

#include <nlohmann/json.hpp>
#include <btclibs/uint256.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/tcp.hpp>

class address_type
{
public:
    /*
        ('services', pack.IntType(64)),
        ('address', pack.IPV6AddressType()),
        ('port', pack.IntType(16, 'big')),
     */
    unsigned long long services;
    std::string address;
    int port;

    address_type();
    address_type(unsigned long long _services, std::string _address, int _port);
	address_type(unsigned long long _services, std::string _address, std::string _port);

    friend bool operator==(const address_type &first, const address_type &second);
    friend bool operator!=(const address_type &first, const address_type &second);

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(address_type, services, address, port);
};

class share_type
{
public:
    /*
        ('type', pack.VarIntType()),
        ('contents', pack.VarStrType()),
    */
    int type;
    std::string contents;

    share_type();
    share_type(int _type, std::string _contents);

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(share_type, type, contents);
};

class addr
{
public:
    uint32_t timestamp;
    address_type address;

    addr();
    addr(uint32_t t, address_type a);
    addr(uint32_t t, int _services, std::string _address, int _port);

    friend bool operator==(const addr &first, const addr &second);
    friend bool operator!=(const addr &first, const addr &second);

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(addr, timestamp, address);
};

enum inventory_type
{
    tx = 1,
    block = 2
};

class inventory
{
public:
    /*
        ('type', pack.EnumType(pack.IntType(32), {1: 'tx', 2: 'block'})),
        ('hash', pack.IntType(256))
    */
    inventory_type type;
    uint256 hash;

    inventory();
    inventory(inventory_type _type, uint256 _hash);

    inventory_type parse_inv_type(std::string _type)
    {
        if (_type == "tx")
        {
            return inventory_type::tx;
        }
        if (_type == "block")
        {
            return inventory_type::block;
        }
        LOG_ERROR << "inv type don't parsed!";
        return inventory_type::tx; //if error
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(inventory, type, hash);
};

namespace stream
{
    struct IPV6AddressType
    {
        std::string value;

        IPV6AddressType()
        {

        }

        IPV6AddressType(std::string _value) : value(_value)
        {

        }

        IPV6AddressType &operator=(std::string _value)
        {
            value = _value;
            return *this;
        }

        std::string get() const
        {
            return value;
        }

        PackStream &write(PackStream &stream)
        {
            vector<unsigned char> data;
            if (value.find(':') < value.size())
            {
                boost::erase_all(value, ":");
                data = ParseHex(value);
            } else
            {
                std::vector<std::string> split_res;
                boost::algorithm::split(split_res, value, boost::is_any_of("."));
                if (split_res.size() != 4)
                {
                    throw (std::runtime_error("Invalid address in IPV6AddressType"));
                }

                vector<unsigned int> bits;
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
                    data.push_back((unsigned char) x);
                }
            }

            assert(data.size() == 16);

            PackStream _data(data);
            stream << _data;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            vector<unsigned char> hex_data{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
            if (stream.size() >= 16)
            {
                vector<unsigned char> data{stream.data.begin(), stream.data.begin() + 16};
                stream.data.erase(stream.data.begin(), stream.data.begin() + 16);
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
                    vector<std::string> nums;
                    for (int i = 12; i < 16; i++)
                    {
                        auto num = std::to_string((unsigned int) data[i]);
                        nums.push_back(num);
                    }
                    value = boost::algorithm::join(nums, ".");
                } else
                {
                    //TODO: IPV6
                }
            } else
            {
                throw std::runtime_error("Invalid address!");
            }
            return stream;
        }
    };

    struct address_type_stream
    {
        IntType(64) services;
        IPV6AddressType address; //IPV6AddressType
        IntType<uint16_t, true> port;

        PackStream &write(PackStream &stream)
        {
            stream << services << address << port;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> services >> address >> port;
            return stream;
        }

        address_type_stream &operator=(const address_type &val)
        {
            services = val.services;
            address = val.address;
            port = val.port;
            return *this;
        }

        address_type get()
        {
            return address_type(services.get(), address.get(), port.get());
        }
    };

    struct addr32_stream : Maker<addr32_stream, addr>
    {
        IntType(32) timestamp;
        address_type_stream address;

        addr32_stream()
        {}

        addr32_stream(const addr &value)
        {
            *this = value;
        }

        PackStream &write(PackStream &stream)
        {
            stream << timestamp << address;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> timestamp >> address;
            return stream;
        }

        addr32_stream &operator=(const addr &val)
        {
            timestamp = val.timestamp;
            address = val.address;
            return *this;
        }

        addr get()
        {
            return addr(timestamp.get(), address.services.get(), address.address.get(), address.port.get());
        }
    };

    struct addr_stream : Maker<addr_stream, addr>
    {
        IntType(64) timestamp;
        address_type_stream address;

        addr_stream()
        {}

        addr_stream(const addr &value)
        {
            *this = value;
        }

        PackStream &write(PackStream &stream)
        {
            stream << timestamp << address;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> timestamp >> address;
            return stream;
        }

        addr_stream &operator=(const addr &val)
        {
            timestamp = val.timestamp;
            address = val.address;
            return *this;
        }

        addr get()
        {
            return addr(timestamp.get(), address.services.get(), address.address.get(), address.port.get());
        }
    };

    struct share_type_stream : Maker<share_type_stream, share_type>
    {
        VarIntType type;
        StrType contents;

        share_type_stream()
        {};

        share_type_stream(share_type val)
        {
            type = val.type;
            contents = val.contents;
        };

        PackStream &write(PackStream &stream)
        {
            stream << type << contents;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> type >> contents;
            return stream;
        }

        share_type_stream &operator=(const share_type &val)
        {
            type = val.type;
            contents = val.contents;
            return *this;
        }

        share_type get()
        {
            return share_type(type.value, contents.get());
        }
    };

    struct inventory_stream : Maker<inventory_stream, inventory>
    {
        EnumType<inventory_type, IntType(32) > type;
        IntType(256) hash;

        inventory_stream() = default;

        inventory_stream(inventory inv)
        {
            type = inv.type;
            hash = inv.hash;
        }

        PackStream &write(PackStream &stream)
        {
            stream << type << hash;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> type >> hash;
            return stream;
        }

        inventory get()
        {
            return inventory(type.get(), hash.get());
        }

    };
}

struct NetAddress
{
    std::string ip{};
    std::string port{};

    NetAddress() = default;

    NetAddress(const std::string& _ip, const std::string& _port)
        : ip(_ip), port(_port) {}
    NetAddress(const std::string& _ip, const int& _port) 
        : ip(_ip), port(std::to_string(_port)) {}
    NetAddress(const boost::asio::ip::tcp::endpoint& ep)
        : ip(ep.address().to_string()), port(std::to_string(ep.port())) {}
    //TODO: NetAddress(const std::string& full_address)

    std::string to_string() const
    {
        return ip + ":" + port;
    }

    int get_port() const
    {
        return stoi(port);
    }

    bool operator<(const NetAddress& value) const
    {
        return std::make_tuple(ip, port) < std::make_tuple(value.ip, value.port);
    }

    bool operator>(const NetAddress& value) const
    {
        return std::make_tuple(ip, port) > std::make_tuple(value.ip, value.port);
    }

    bool operator==(const NetAddress& value) const
    {
        return std::make_tuple(ip, port) == std::make_tuple(value.ip, value.port);
    }

    bool operator!=(const NetAddress& value) const
    {
        return !(*this == value);
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(NetAddress, ip, port);
};

typedef std::tuple<std::string, std::string> addr_type; //old name: c2pool::libnet::addr
