#pragma once

#include "converter.h"

#include <univalue.h>
#include <btclibs/uint256.h>
//#include <sharechain/shareTypes.h>
#include <util/types.h>
using namespace c2pool::util::messages;
#include <networks/network.h>

#include <sstream>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <tuple>

#include <devcore/logger.h>

namespace coind::p2p
{
    class P2PSocket;
}

namespace coind::p2p::messages
{

    enum commands
    {
        cmd_error = 9999,
        cmd_version = 0,
        cmd_verack,
        cmd_ping,
        cmd_pong,
        cmd_alert,
        cmd_getaddr,
        cmd_addr,
        cmd_inv,
        cmd_getdata,
        cmd_reject,
        cmd_getblocks,
        cmd_getheaders,
        cmd_tx,
        cmd_block,
        cmd_headers
    };

    //base_message type for handle
    class raw_message
    {
        friend coind::p2p::P2PSocket;

    public:
        coind::p2p::messages::commands name_type;
        UniValue value;

    protected:
        std::shared_ptr<coind_converter> converter;

    public:
        raw_message()
        {
            converter = std::make_shared<coind_converter>();
        }

        void set_prefix(std::shared_ptr<coind::ParentNetwork> _net)
        {
            //TODO: correct prefix set!
            converter->set_prefix((const char *)_net->PREFIX, _net->PREFIX_LENGTH);
        }

        void deserialize()
        {
            UniValue _value = converter->decode();
            LOG_TRACE << "deserialize value :" << _value.write();
            name_type = (coind::p2p::messages::commands)_value["name_type"].get_int();
            value = _value["value"].get_obj();
        }
    };

    class base_message
    {
        friend class coind::p2p::python::PyPackCoindTypes;

    protected:
        std::shared_ptr<coind_converter> converter;

        virtual UniValue json_pack() = 0;

    public:
        base_message(const char *_cmd)
        {
            converter = std::make_shared<coind_converter>(_cmd);
        }

        void set_prefix(std::shared_ptr<coind::ParentNetwork> _net)
        {
            converter->set_prefix((const char *)_net->PREFIX, _net->PREFIX_LENGTH);
        }

        std::tuple<char *, int> get_prefix()
        {
            auto res = std::make_tuple<char *, int>(converter->get_prefix(), converter->get_prefix_len());
            return res;
        }

        //base_message -> bytes; msg = self
        std::tuple<char *, int> serialize()
        {
            LOG_TRACE << "start serialize msg";
            UniValue json_msg(UniValue::VOBJ);
            json_msg.pushKV("name_type", converter->get_command());
            UniValue msg_value(UniValue::VOBJ);
            msg_value = json_pack();
            json_msg.pushKV("value", msg_value);
            LOG_TRACE << "before encode message in serialize";
            return converter->encode(json_msg);
        }
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
        std::string command;
        std::string error_text;

    public:
        message_error() : base_message("error") {}

        message_error &operator=(UniValue value)
        {
            command = value["command"].get_str();
            error_text = value["error_text"].get_str();
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
        int32_t version;
        uint64_t services;
        int64_t timestamp;
        address_type addr_to;
        address_type addr_from;
        unsigned long long nonce;
        std::string sub_version;
        int32_t start_height;

    public:
        message_version() : base_message("version") {}

        message_version(int ver, int serv, int64_t _timestamp, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int32_t _start_height) : base_message("version")
        {
            version = ver;
            services = serv;
            timestamp = _timestamp;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
            start_height = _start_height;
        }

        message_version &operator=(UniValue value)
        {
            version = value["version"].get_int();
            services = value["services"].get_uint64();
            timestamp = value["time"].get_int64();
            addr_to = value["addr_to"].get_obj();
            addr_from = value["addr_from"].get_obj();
            nonce = value["nonce"].get_uint64();
            sub_version = value["sub_version_num"].get_str();
            start_height = value["start_height"].get_int();
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("version", version);
            result.pushKV("services", services);
            result.pushKV("time", timestamp);
            result.pushKV("addr_to", addr_to);
            result.pushKV("addr_from", addr_from);
            result.pushKV("nonce", (uint64_t)nonce);
            result.pushKV("sub_version_num", sub_version);
            result.pushKV("start_height", start_height);

            return result;
        }
    };

    class message_verack : public base_message
    {
    public:
        message_verack() : base_message("verack") {}

        message_verack &operator=(UniValue value)
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

    class message_ping : public base_message
    {
    public:
        uint64_t nonce;

    public:
        message_ping() : base_message("ping") {}

        message_ping(uint64_t _nonce) : base_message("ping")
        {
            nonce = _nonce;
        }

        message_ping &operator=(UniValue value)
        {
            nonce = value["nonce"].get_uint64();
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("nonce", (uint64_t)nonce);
            return result;
        }
    };

    class message_pong : public base_message
    {
    public:
        uint64_t nonce;

    public:
        message_pong() : base_message("pong") {}

        message_pong(uint64_t _nonce) : base_message("pong")
        {
            nonce = _nonce;
        }

        message_pong &operator=(UniValue value)
        {
            nonce = value["nonce"].get_uint64();
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("nonce", (uint64_t)nonce);
            return result;
        }
    };

    class message_alert : public base_message
    {
    public:
        std::string message;
        std::string signature;

    public:
        message_alert() : base_message("alert") {}

        message_alert &operator=(UniValue value)
        {
            message = value["message"].get_str();
            signature = value["signature"].get_str();
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("message", message);
            result.pushKV("signature", signature);
            return result;
        }
    };

    class message_getaddr : public base_message
    {
    public:
    public:
        message_getaddr() : base_message("getaddr") {}

        message_getaddr &operator=(UniValue value)
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

    class message_addr : public base_message
    {
    public:
        std::vector<addr> addrs;

    public:
        message_addr() : base_message("addr") {}

        message_addr(std::vector<addr> _addrs) : base_message("addr")
        {
            addrs = _addrs;
        }

        message_addr &operator=(UniValue value)
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

    class message_inv : public base_message
    {
    public:
        std::vector<inventory> invs;

    public:
        message_inv() : base_message("inv") {}

        message_inv(std::vector<inventory> _invs) : base_message("inv")
        {
            invs = _invs;
        }

        message_inv &operator=(UniValue value)
        {
            for (auto arr_value : value["invs"].get_array().getValues())
            {
                inventory _temp_inv;
                _temp_inv = arr_value;
                invs.push_back(_temp_inv);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue inventory_array(UniValue::VARR);

            for (auto _inv : invs)
            {
                inventory_array.push_back(_inv);
            }
            result.pushKV("invs", inventory_array);

            return result;
        }
    };

    class message_getdata : public base_message
    {
    public:
        std::vector<inventory> requests;

    public:
        message_getdata() : base_message("getdata") {}

        message_getdata(std::vector<inventory> _reqs) : base_message("getdata")
        {
            requests = _reqs;
        }

        message_getdata &operator=(UniValue value)
        {
            for (auto arr_value : value["requests"].get_array().getValues())
            {
                inventory _temp_inv;
                _temp_inv = arr_value;
                requests.push_back(_temp_inv);
            }
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);

            UniValue inventory_array(UniValue::VARR);

            for (auto _inv : requests)
            {
                inventory_array.push_back(_inv);
            }
            result.pushKV("requests", inventory_array);

            return result;
        }
    };

    class message_reject : public base_message
    {
    public:
        std::string message;
        char ccode;
        std::string reason;
        uint256 data;

    public:
        message_reject() : base_message("reject") {}

        message_reject &operator=(UniValue value)
        {
            message = value["message"].get_str();
            ccode = value["ccode"].get_str()[0];
            reason = value["reason"].get_str();
            data.SetHex(value["data"].get_str());
            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("message", message);
            result.pushKV("ccode", ccode);
            result.pushKV("reason", reason);
            result.pushKV("data", data.GetHex());
            return result;
        }
    };

    class message_getblocks : public base_message
    {
    public:
        uint32_t version;
        std::vector<uint256> have;
        uint256 last;

    public:
        message_getblocks() : base_message("getblocks") {}

        message_getblocks &operator=(UniValue value)
        {
            version = value["version"].get_int();

            for (auto arr_value : value["have"].get_array().getValues())
            {
                uint256 _temp_hash;
                _temp_hash.SetHex(arr_value.get_str());
                have.push_back(_temp_hash);
            }

            last.SetHex(value["last"].get_str());

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("version", (int)version);

            UniValue have_array(UniValue::VARR);

            for (auto _hash : have)
            {
                have_array.push_back(_hash.GetHex());
            }
            result.pushKV("have", have_array);

            result.pushKV("last", last.GetHex());
            return result;
        }
    };

    class message_getheaders : public base_message
    {
    public:
        uint32_t version;
        std::vector<uint256> have;
        uint256 last;

    public:
        message_getheaders() : base_message("getheaders") {}

        message_getheaders &operator=(UniValue value)
        {
            version = value["version"].get_int();

            for (auto arr_value : value["have"].get_array().getValues())
            {
                uint256 _temp_hash;
                _temp_hash.SetHex(arr_value.get_str());
                have.push_back(_temp_hash);
            }

            last.SetHex(value["last"].get_str());

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("version", (int)version);

            UniValue have_array(UniValue::VARR);

            for (auto _hash : have)
            {
                have_array.push_back(_hash.GetHex());
            }
            result.pushKV("have", have_array);

            result.pushKV("last", last.GetHex());
            return result;
        }
    };

    class message_tx : public base_message
    {
    public:
        /*
        message_tx = pack.ComposedType([
        ('tx', bitcoin_data.tx_type),
        ])
        */
        UniValue tx;

    public:
        message_tx() : base_message("tx") {}

        message_tx &operator=(UniValue value)
        {
            tx = value["tx"].get_obj();

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("tx", tx);

            return result;
        }
    };

    class message_block : public base_message
    {
    public:
        /*
        message_block = pack.ComposedType([
        ('block', bitcoin_data.block_type),
        ])
        */
        UniValue block;

    public:
        message_block() : base_message("block") {}

        message_block &operator=(UniValue value)
        {
            block = value["block"].get_obj();

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("block", block);

            return result;
        }
    };

    class message_headers : public base_message
    {
    public:
        /*
        message_headers = pack.ComposedType([
        ('headers', pack.ListType(bitcoin_data.block_type)),
        ])
        */
        UniValue headers;

    public:
        message_headers() : base_message("headers") {}

        message_headers &operator=(UniValue value)
        {
            headers = value["headers"].get_obj();

            return *this;
        }

    protected:
        UniValue json_pack() override
        {
            UniValue result(UniValue::VOBJ);
            result.pushKV("headers", headers);

            return result;
        }
    };
} // namespace c2pool::libnet::messages