#pragma once

#include "types.h"
#include "uint256.h"
#include "shareTypes.h"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace c2pool::p2p
{
    class Protocol;
}

//for packing: UniValue value = msg;
namespace c2pool::messages
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

    class IMessage
    {
    public:
        //TODO: enum -> macros in config file
        enum
        {
            command_length = 12
        };
        enum
        {
            payload_length = 4 //len(payload)
        };
        enum
        {
            checksum_length = 4 //sha256(sha256(payload))[:4]
        };
        enum
        {
            max_payload_length = 8000000 //max len payload
        };

        const size_t prefix_length() const
        {
            return _prefix_length;
        }

        void set_unpacked_length(char *packed_len = nullptr);
        const unsigned int unpacked_length();

        char *prefix;
        char command[command_length + 1];
        char length[payload_length + 1];
        char checksum[checksum_length + 1];
        char payload[max_payload_length + 1];
        char data[command_length + payload_length + checksum_length + max_payload_length]; //full message without prefix //TODO
    private:
        size_t _prefix_length;
        unsigned int _unpacked_length = 0;

    public:
        IMessage() {}

        IMessage(const char *current_prefix);

        void set_data(char *data_);

        //from data to command, length, checksum, payload
        void encode_data();

        //from command, length, checksum, payload to data
        void decode_data();

        int get_length();

    protected:
        //возвращает длину для упакованного payload msg, которое формируется в c2pool.
        virtual int pack_payload_length() { return 0; }

        int set_length(char *data_);
    };

    class message : public IMessage
    {
    public:
        message(const char *_cmd);

        ~message()
        {
            delete packed_c_str;
        }

        //receive message data from IMessage::command, IMessage::checksum, IMessage::payload, IMessage::unpacked_length;
        //TODO: void receive();
        //receive message data from IMessage::data; use _set_data for init IMessage::data.
        //TODO: void receive_from_data(char *_set_data);
        //
        void send();

    protected:
        int pack_payload_length() override;

    private:
        char *packed_c_str;
    };

    class message_error : public message
    {
    public:
        message_error() : message("error") {}

        message_error &operator=(UniValue value)
        {
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            return result;
        }
    };

    class message_version : public message
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

    public:
        message_version() : message("version") {}

        message_version(int ver, int serv, address_type to, address_type from, unsigned long long _nonce, std::string sub_ver, int _mode, uint256 best_hash) : message("version")
        {
            version = ver;
            services = serv;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
            mode = _mode;
            best_share_hash = best_hash;
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
            return *this;
        }

        operator UniValue()
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

    class message_ping : public message
    {
    public:
        message_ping() : message("ping") {}

        message_ping &operator=(UniValue value)
        {
            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            return result;
        }
    };

    class message_addrme : public message
    {
    public:
        int port;

    public:
        message_addrme() : message("addrme") {}

        message_addrme(int _port) : message("addrme")
        {
            port = _port;
        }

        message_addrme &operator=(UniValue value)
        {
            port = value["port"].get_int();

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("port", port);

            return result;
        }
    };

    class message_getaddrs : public message
    {
    public:
        int count;

    public:
        message_getaddrs() : message("getaddrs") {}

        message_getaddrs(int cnt) : message("getaddrs")
        {
            count = cnt;
        }

        message_getaddrs &operator=(UniValue value)
        {

            count = value["count"].get_int();

            return *this;
        }

        operator UniValue()
        {
            UniValue result(UniValue::VOBJ);

            result.pushKV("count", count);

            return result;
        }
    };

    class message_addrs : public message
    {
    public:
        std::vector<c2pool::messages::addr> addrs;

    public:
        message_addrs() : message("addrs") {}

        message_addrs(std::vector<c2pool::messages::addr> _addrs) : message("addrs")
        {
            addrs = _addrs;
        }

        message_addrs &operator=(UniValue value)
        {
            for (auto arr_value : value["addrs"].get_array().getValues())
            {
                c2pool::messages::addr _temp_addr;
                _temp_addr = arr_value;
                addrs.push_back(_temp_addr);
            }
            return *this;
        }

        operator UniValue()
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

    class message_shares : public message
    {
    public:
        std::vector<c2pool::shares::RawShare> shares;

    public:
        message_shares() : message("shares") {}

        message_shares(std::vector<c2pool::shares::RawShare> _shares) : message("shares")
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

        operator UniValue()
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

    class message_sharereq : public message
    {
    public:
        uint256 id;
        std::vector<uint256> hashes;
        unsigned long long parents;
        std::vector<uint256> stops;

    public:
        message_sharereq() : message("sharereq") {}

        message_sharereq(uint256 _id, std::vector<uint256> _hashes, unsigned long long _parents, std::vector<uint256> _stops) : message("sharereq")
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

        operator UniValue()
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

    class message_sharereply : public message
    {
    public:
        uint256 id;
        ShareReplyResult result;
        std::vector<c2pool::shares::RawShare> shares;

    public:
        message_sharereply() : message("sharereply") {}

        message_sharereply(uint256 _id, ShareReplyResult _result, std::vector<c2pool::shares::RawShare> _shares) : message("sharereply")
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

        operator UniValue()
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

    class message_have_tx : public message
    {
    public:
        std::vector<uint256> tx_hashes;

    public:
        message_have_tx() : message("have_tx") {}

        message_have_tx(std::vector<uint256> _tx_hashes) : message("have_tx")
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

        operator UniValue()
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

    class message_losing_tx : public message
    {
    public:
        std::vector<uint256> tx_hashes;

    public:
        message_losing_tx() : message("losing_tx") {}

        message_losing_tx(std::vector<uint256> _tx_hashes) : message("losing_tx")
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

        operator UniValue()
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

} // namespace c2pool::messages