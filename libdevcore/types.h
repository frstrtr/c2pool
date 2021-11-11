#pragma once

#include <string>
#include <sstream>
#include <tuple>
#include <string>

#include <univalue.h>
#include <btclibs/uint256.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include "common.h"
#include "logger.h"
#include "stream_types.h"

//todo: move all methods to types.cpp
namespace c2pool::messages
{
    //TODO: stream_type
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

        address_type &operator=(UniValue value)
        {
            services = value["services"].get_uint64();

            address = value["address"].get_str();
            port = value["port"].get_int();
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("services", (uint64_t)services);
            result.pushKV("address", address);
            result.pushKV("port", port);

            return result;
        }

        friend bool operator==(const address_type &first, const address_type &second);

        friend bool operator!=(const address_type &first, const address_type &second);
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

        share_type &operator=(UniValue value)
        {
            type = value["type"].get_int();
            contents = value["contents"].get_str();
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("type", type);
            result.pushKV("contents", contents);

            return result;
        }
    };

    class addr
    {
    public:
        int timestamp;
        address_type address;

        addr();

        addr(int t, address_type a);

        addr(int t, int _services, std::string _address, int _port);

        addr &operator=(UniValue value)
        {
            timestamp = value["timestamp"].get_int();

            address = value["address"].get_obj();
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("timestamp", timestamp);
            result.pushKV("contents", address);

            return result;
        }

        friend bool operator==(const addr &first, const addr &second);

        friend bool operator!=(const addr &first, const addr &second);
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

        inventory_type parse_inv_type(std::string type)
        {
            if (type == "tx")
                return inventory_type::tx;
            if (type == "block")
                return inventory_type::block;
            LOG_ERROR << "inv type don't parsed!";
            return inventory_type::tx; //if error
        }

        inventory &operator=(UniValue value)
        {
            type = parse_inv_type(value["type"].get_str());
            hash.SetHex(value["hash"].get_str());
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("type", type);
            result.pushKV("hash", hash.GetHex());

            return result;
        }
    };
} // namespace c2pool::messages

namespace c2pool::messages::stream
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

        //TODO: test
        PackStream &write(PackStream &stream)
        {
            //TODO: IPV6
//            if ':' in item:
//                data = ''.join(item.replace(':', '')).decode('hex')
//            else

            std::vector<std::string> split_res;
            boost::algorithm::split(split_res, value, boost::is_any_of("."));
            if (split_res.size() != 4) {
                throw (std::runtime_error("Invalid address in IPV6AddressType"));
            }

            vector<unsigned int> bits;
            for (auto bit: split_res) {
                int bit_int = 0;
                try {
                    bit_int = boost::lexical_cast<unsigned int>(bit);
                } catch (boost::bad_lexical_cast const &) {
                    LOG_ERROR << "Error lexical cast in IPV6AddressType";
                }
                bits.push_back(bit_int);
            }

            vector<unsigned char> data{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
            for (auto x: bits) {
                data.push_back((unsigned char) x);
            }

            PackStream _data(data);
            stream << _data;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            //TODO: finish
            return stream;
        }
    };

    struct address_type_stream
    {
        IntType(64) services;
        IPV6AddressType address; //IPV6AddressType
        IntType(16) port;

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

        address_type_stream& operator =(const address_type& val)
        {
            services = val.services;
            address = StrType::make_type(val.address);
            port = val.port;
        }

        address_type get()
        {
            return address_type(services.get(), address.get(), port.get());
        }
    };
}

namespace c2pool::libnet{
    typedef std::tuple<std::string, std::string> addr;
}