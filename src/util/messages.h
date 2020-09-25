#ifndef CPOOL_MESSAGES_H
#define CPOOL_MESSAGES_H

#include <iostream>
#include <sstream>
#include <string>
#include "types.h"
#include "pack.h"
#include <tuple>

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

        //return all msg with prefix, ready for send
        std::tuple<char *, int> send_data(const void *_prefix, int _prefix_len);

        void unpack(std::string item);
        void unpack(std::stringstream &ss);
        string pack();

        char *pack_c_str();

        // char *data() override
        // {
        //     //TODO:
        // }

        // std::size_t length() override
        // {
        //     //TODO:
        // }

        virtual void _unpack(std::stringstream &ss) = 0;
        virtual std::string _pack() = 0;

    protected:
        int pack_payload_length() override;

    private:
        char *packed_c_str;
    };

    class message_error : public message
    {
    public:
        void _unpack(std::stringstream &ss) override; //TODO

        std::string _pack() override; //TODO

        message_error() : message("error") {}
    };

    class message_version : public message
    {
    public:
        message_version() : message("version") {}

        message_version(int ver, int serv, address_type to, address_type from, unsigned long long _nonce, string sub_ver, int _mode, long best_hash) : message("version")
        {
            version = ver;
            services = serv;
            addr_to = to;
            addr_from = from;
            nonce = _nonce;
            sub_version = sub_ver;
            mode = _mode;
            best_share_hash = best_hash;
            std::cout << "version " << version << std::endl;
            std::cout << "services " << services << std::endl;
            std::cout << "addr_to " << addr_to << std::endl;
            std::cout << "addr_from " << addr_from << std::endl;
            std::cout << "nonce " << nonce << std::endl;
            std::cout << "sub_version " << sub_version << std::endl;
            std::cout << "mode " << mode << std::endl;
            std::cout << "best_share_hash " << best_share_hash << std::endl;
        }

        void _unpack(std::stringstream &ss) override;

        std::string _pack() override;

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
        string sub_version;
        //     ('mode', pack.IntType(32)), # always 1 for legacy compatibility
        int mode;
        //     ('best_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
        long best_share_hash; // TODO: long long?
        // ])
    };

    class message_ping : public message
    {
    public:
        message_ping() : message("ping") {}
        // message_ping(const std::string cmd = "ping") : message(cmd) {}

        void _unpack(std::stringstream &ss) override;

        std::string _pack() override;

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

        void _unpack(stringstream &ss) override;

        string _pack() override;

        //= pack.ComposedType([
        //    ('port', pack.IntType(16)),
        int port;
        //])
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

        void _unpack(stringstream &ss) override;

        string _pack() override;

        //     = pack.ComposedType([
        //     ('count', pack.IntType(32)),
        int count;
        // ])
    };

    class message_addrs : public message
    {
    public:
        vector<c2pool::messages::addr> addrs;

        message_addrs() : message("addrs") {}

        message_addrs(vector<c2pool::messages::addr> _addrs) : message("addrs")
        {
            addrs = _addrs;
        }

        void _unpack(stringstream &ss) override;

        string _pack() override;
    };
} // namespace c2pool::messages

#endif //CPOOL_MESSAGES_H
