#pragma once

#include "converter.h"

#include <lib/univalue/include/univalue.h>
#include <util/types.h>
#include <btclibs/uint256.h>
#include <sharechain/shareTypes.h>

#include <sstream>
#include <string>
#include <vector>
#include <memory>

using namespace c2pool::util::messages;

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::messages
{

    enum commands
    {
        cmd_error = 9999,
        cmd_version = 0,
        cmd_addrs,
        cmd_getaddrs,
        cmd_ping,
        cmd_addrme,
        //new:
        cmd_shares,
        cmd_sharereq,
        cmd_sharereply,
        cmd_best_block, //TODO
        cmd_have_tx,
        cmd_losing_tx
    };

    //base_message type for handle
    class raw_message
    {
        friend c2pool::libnet::p2p::P2PSocket;

    public:
        c2pool::libnet::messages::commands name_type;
        UniValue value;

    protected:
        std::shared_ptr<bytes_converter> converter;

    public:
        raw_message()
        {
            converter = std::make_shared<empty_converter>();
        }

        template <class converter_type>
        void set_converter_type()
        {
            converter = std::make_shared<converter_type>(converter);
        }

        void deserialize()
        {
            UniValue _value = converter->decode();

            name_type = (c2pool::libnet::messages::commands)_value["name_type"].get_int();
            value = _value["value"].get_obj();
        }
    };

    class base_message
    {
    protected:
        std::shared_ptr<bytes_converter> converter;

        virtual UniValue json_pack() = 0;

    public:
        base_message(const char *_cmd)
        {
            converter = std::make_shared<empty_converter>(_cmd);
        }

        template <class converter_type>
        void set_converter_type()
        {
            converter = std::make_shared<converter_type>(converter);
        }

        //base_message -> bytes; msg = self
        char *serialize()
        {
            UniValue json_msg(UniValue::VOBJ);
            json_msg.pushKV("name_type", converter->get_command());
            UniValue msg_value(UniValue::VOBJ);
            msg_value = json_pack();
            json_msg.pushKV("value", msg_value);

            return converter->encode(json_msg);
        }

        friend class c2pool::python::PyPackTypes;
    };

    /*
    template <class converter_type>
    class message_addrs
    {
    public:
        message_addrs(UniValue v) {}
    };
    */

    class message_error : public base_message
    {
    public:
        message_error() : base_message("error") {}

        message_error &operator=(UniValue value)
        {
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            return result;
        }
    };

    enum PoolVersion
    {
        None = 0,
        C2Pool = 1
    };

    class message_version : public base_message
    {
    public:
        int version;
        int services;
        address_type addr_to;
        address_type addr_from;
        unsigned long long nonce;
        std::string sub_version;
        int mode; //# always 1 for legacy compatibility
        uint256 best_share_hash;
        PoolVersion pool_version;

    public:
        message_version() : base_message("version") {}

        message_version(int ver, int serv, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int _mode, uint256 best_hash, PoolVersion pool_ver = PoolVersion::None) : base_message("version")
        {
            version = ver;
            services = serv;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
            mode = _mode;
            best_share_hash = best_hash;
            pool_version = pool_ver;
        }

        message_version &operator=(UniValue value)
        {
            version = value["version"].get_int();
            services = value["services"].get_int();
            addr_to = value["addr_to"].get_obj();
            addr_from = value["addr_from"].get_obj();
            nonce = value["nonce"].get_int64();
            sub_version = value["sub_version"].get_str();
            mode = value["mode"].get_int();
            best_share_hash.SetHex(value["best_share_hash"].get_str());
            if (value.exists("pool_version"))
            {
                int pool_ver_temp = value["pool_version"].get_int();
                pool_version = (PoolVersion)pool_ver_temp;
            }
            else
            {
                pool_version = PoolVersion::None;
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("version", version);
            result.pushKV("services", services);
            result.pushKV("addr_to", addr_to);
            result.pushKV("addr_from", addr_from);
            result.pushKV("nonce", (uint64_t)nonce);
            result.pushKV("sub_version", sub_version);
            result.pushKV("mode", mode);
            result.pushKV("best_share_hash", best_share_hash.GetHex());

            return result;
        }
    };

    class message_ping : public base_message
    {
    public:
        message_ping() : base_message("ping") {}

        message_ping &operator=(UniValue value)
        {
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            return result;
        }
    };

    class message_addrme : public base_message
    {
    public:
        int port;

    public:
        message_addrme() : base_message("addrme") {}

        message_addrme(int _port) : base_message("addrme")
        {
            port = _port;
        }

        message_addrme &operator=(UniValue value)
        {
            port = value["port"].get_int();

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("port", port);

            return result;
        }
    };

    class message_getaddrs : public base_message
    {
    public:
        int count;

    public:
        message_getaddrs() : base_message("getaddrs") {}

        message_getaddrs(int cnt) : base_message("getaddrs")
        {
            count = cnt;
        }

        message_getaddrs &operator=(UniValue value)
        {

            count = value["count"].get_int();

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("count", count);

            return result;
        }
    };

    class message_addrs : public base_message
    {
    public:
        std::vector<addr> addrs;

    public:
        message_addrs() : base_message("addrs") {}

        message_addrs(std::vector<addr> _addrs) : base_message("addrs")
        {
            addrs = _addrs;
        }

        message_addrs &operator=(UniValue value)
        {
            for (auto arr_value : value["addrs"].get_array().getValues())
            {
                addr _temp_addr;
                _temp_addr = arr_value;
                addrs.push_back(_temp_addr);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue addrs_array(UniValue::VARR);

            for (auto _addr : addrs)
            {
                addrs_array.push_back(_addr);
            }
            result.pushKV("addrs", addrs_array);

            return result;
        }
    };

    class message_shares : public base_message
    {
    public:
        std::vector<c2pool::shares::RawShare> shares;

    public:
        message_shares() : base_message("shares") {}

        message_shares(std::vector<c2pool::shares::RawShare> _shares) : base_message("shares")
        {
            shares = _shares;
        }

        message_shares &operator=(UniValue value)
        {
            for (auto arr_value : value["shares"].get_array().getValues())
            {
                c2pool::shares::RawShare _temp_share;
                _temp_share = arr_value;
                shares.push_back(_temp_share);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue shares_array(UniValue::VARR);
            for (auto _share : shares)
            {
                shares_array.push_back(_share);
            }
            result.pushKV("shares", shares_array);

            return result;
        }
    };

    class message_sharereq : public base_message
    {
    public:
        uint256 id;
        std::vector<uint256> hashes;
        unsigned long long parents;
        std::vector<uint256> stops;

    public:
        message_sharereq() : base_message("sharereq") {}

        message_sharereq(uint256 _id, std::vector<uint256> _hashes, unsigned long long _parents, std::vector<uint256> _stops) : base_message("sharereq")
        {
            id = _id;
            hashes = _hashes;
            parents = _parents;
            stops = _stops;
        }

        message_sharereq &operator=(UniValue value)
        {
            id.SetHex(value["id"].get_str());
            for (auto arr_value : value["hashes"].get_array().getValues())
            {
                uint256 _temp_hash;
                _temp_hash.SetHex(arr_value.get_str());
                hashes.push_back(_temp_hash);
            }
            parents = value["parents"].get_int64();
            for (auto arr_value : value["stops"].get_array().getValues())
            {
                uint256 _temp_stop;
                _temp_stop.SetHex(arr_value.get_str());
                stops.push_back(_temp_stop);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("id", id.GetHex());

            UniValue hashes_array(UniValue::VARR);
            for (auto _hash : hashes)
            {
                hashes_array.push_back(_hash.GetHex());
            }
            result.pushKV("hashes", hashes_array);

            result.pushKV("parents", (uint64_t)parents);

            UniValue stops_array(UniValue::VARR);
            for (auto _stop : stops)
            {
                hashes_array.push_back(_stop.GetHex());
            }
            result.pushKV("stops", stops_array);

            return result;
        }
    };

    enum ShareReplyResult
    {
        good = 0,
        too_long = 1,
        unk2 = 2,
        unk3 = 3,
        unk4 = 4,
        unk5 = 5,
        unk6 = 6
    };

    class message_sharereply : public base_message
    {
    public:
        uint256 id;
        ShareReplyResult result;
        std::vector<c2pool::shares::RawShare> shares;

    public:
        message_sharereply() : base_message("sharereply") {}

        message_sharereply(uint256 _id, ShareReplyResult _result, std::vector<c2pool::shares::RawShare> _shares) : base_message("sharereply")
        {
            id = _id;
            result = _result;
            shares = _shares;
        }

        message_sharereply &operator=(UniValue value)
        {
            id.SetHex(value["id"].get_str());

            result = (ShareReplyResult)value["result"].get_int();

            for (auto arr_value : value["shares"].get_array().getValues())
            {
                c2pool::shares::RawShare _temp_share;
                _temp_share = arr_value;
                shares.push_back(_temp_share);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue _result(UniValue::VOBJ);

            _result.pushKV("id", id.GetHex());

            _result.pushKV("result", (int)result);

            UniValue shares_array(UniValue::VARR);
            for (auto _share : shares)
            {
                shares_array.push_back(_share);
            }
            _result.pushKV("shares", shares_array);

            return result;
        }
    };

    class message_have_tx : public base_message
    {
    public:
        std::vector<uint256> tx_hashes;

    public:
        message_have_tx() : base_message("have_tx") {}

        message_have_tx(std::vector<uint256> _tx_hashes) : base_message("have_tx")
        {
            tx_hashes = _tx_hashes;
        }

        message_have_tx &operator=(UniValue value)
        {
            for (auto arr_value : value["tx_hashes"].get_array().getValues())
            {
                uint256 _temp_tx_hash;
                _temp_tx_hash.SetHex(arr_value.get_str());
                tx_hashes.push_back(_temp_tx_hash);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue tx_hashes_array(UniValue::VARR);
            for (auto _tx_hash : tx_hashes)
            {
                tx_hashes_array.push_back(_tx_hash.GetHex());
            }
            result.pushKV("tx_hashes", tx_hashes_array);

            return result;
        }
    };

    class message_losing_tx : public base_message
    {
    public:
        std::vector<uint256> tx_hashes;

    public:
        message_losing_tx() : base_message("losing_tx") {}

        message_losing_tx(std::vector<uint256> _tx_hashes) : base_message("losing_tx")
        {
            tx_hashes = _tx_hashes;
        }

        message_losing_tx &operator=(UniValue value)
        {
            for (auto arr_value : value["tx_hashes"].get_array().getValues())
            {
                uint256 _temp_tx_hash;
                _temp_tx_hash.SetHex(arr_value.get_str());
                tx_hashes.push_back(_temp_tx_hash);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue tx_hashes_array(UniValue::VARR);
            for (auto _tx_hash : tx_hashes)
            {
                tx_hashes_array.push_back(_tx_hash.GetHex());
            }
            result.pushKV("tx_hashes", tx_hashes_array);

            return result;
        }
    };

} // namespace c2pool::libnet::messages