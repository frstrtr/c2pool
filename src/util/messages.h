#ifndef CPOOL_MESSAGES_H
#define CPOOL_MESSAGES_H

#include <iostream>
#include <sstream>
#include <string>
#include "types.h"
#include "uint256.h"
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
        cmd_addrme
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
            result.pushKV("nonce", nonce);
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

} // namespace c2pool::messages

#endif //CPOOL_MESSAGES_H
