#ifndef CPOOL_MESSAGES_H
#define CPOOL_MESSAGES_H

#include <iostream>
#include <sstream>
#include <string>
#include "types.h"
#include "uint256.h"
#include <vector>

//TODO: remove trash comments

namespace c2pool::p2p
{
    class Protocol;
}

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
        void receive();
        //receive message data from IMessage::data; use _set_data for init IMessage::data.
        void receive_from_data(char *_set_data);
        //
        void send();

        void unpack(UniValue &value);
        UniValue pack();

        // char *data() override
        // {
        //     //TODO:
        // }

        // std::size_t length() override
        // {
        //     //TODO:
        // }

        virtual void _unpack(UniValue &value) = 0;
        virtual UniValue _pack() = 0;

    protected:
        int pack_payload_length() override;

    private:
        char *packed_c_str;
    };

    class message_error : public message
    {
    public:
        void _unpack(UniValue &value) override;

        UniValue _pack() override;

        message_error() : message("error") {}
    };

    class message_version : public message
    {
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

        void _unpack(UniValue &value) override;

        UniValue _pack() override;

        //= pack.ComposedType([
        //     ('version', pack.IntType(32)),
        int version;
        //     ('services', pack.IntType(64)),
        int services;
        //     ('addr_to', bitcoin_data.address_type),
        address_type addr_to;
        //     ('addr_from', bitcoin_data.address_type),
        address_type addr_from;
        //     ('nonce', pack.IntType(64)),
        unsigned long long nonce;
        //     ('sub_version', pack.VarStrType()),
        std::string sub_version;
        //     ('mode', pack.IntType(32)), # always 1 for legacy compatibility
        int mode;
        //     ('best_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
        uint256 best_share_hash;
        // ])

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
        // message_ping(const std::string cmd = "ping") : message(cmd) {}

        void _unpack(UniValue &value) override;

        UniValue _pack() override;

        // message_ping = pack.ComposedType([])
        //todo Empty list
    };

    class message_addrme : public message
    {
    public:
        message_addrme() : message("addrme") {}
        // message_addrme(int _port, const string cmd = "addrme") : message(cmd)
        // {
        //     port = _port;
        // }
        message_addrme(int prt) : message("addrme")
        {
            port = prt;
        }

        void _unpack(UniValue &value) override;

        UniValue _pack() override;

        //= pack.ComposedType([
        //    ('port', pack.IntType(16)),
        int port;
        //])
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
        message_getaddrs() : message("getaddrs") {}
        // message_getaddrs(int cnt, const string cmd = "getaddr") : message(cmd)
        // {
        //     count = cnt;
        // }
        message_getaddrs(int cnt) : message("getaddrs")
        {
            count = cnt;
        }

        void _unpack(UniValue &value) override;

        UniValue _pack() override;

        //     = pack.ComposedType([
        //     ('count', pack.IntType(32)),
        int count;
        // ])

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

        void _unpack(UniValue &value) override;

        UniValue _pack() override;

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

            for (auto _addr : addrs){
                addrs_array.push_back(_addr);
            } 
            result.pushKV("addrs", addrs_array);

            return result;
        }
    };

} // namespace c2pool::messages

#endif //CPOOL_MESSAGES_H
