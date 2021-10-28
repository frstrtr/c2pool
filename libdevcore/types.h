#pragma once

#include <string>
#include <sstream>
#include <tuple>
#include <string>

#include <univalue.h>
#include <btclibs/uint256.h>

#include "common.h"
#include "logger.h"

//todo: move all methods to types.cpp
namespace c2pool::messages
{
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

namespace c2pool::libnet{
    typedef std::tuple<std::string, std::string> addr;
}