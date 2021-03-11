#pragma once

#include <memory>
#include <lib/univalue/include/univalue.h>
#include <devcore/logger.h>

#include <tuple>
using std::tuple;

#define COMMAND_LENGTH 12
#define PAYLOAD_LENGTH 4           //len(payload)
#define CHECKSUM_LENGTH 4          //sha256(sha256(payload))[:4]
#define MAX_PAYLOAD_LENGTH 8000000 //max len payload

namespace c2pool::python
{
    class PyPackTypes;
}

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::messages
{
    class bytes_converter
    {
        friend c2pool::python::PyPackTypes;
        friend c2pool::libnet::p2p::P2PSocket;

    protected:
        char *prefix;
        int prefix_length = 0;

        char command[COMMAND_LENGTH + 1];
        char length[PAYLOAD_LENGTH + 1];
        char checksum[CHECKSUM_LENGTH + 1];
        char payload[MAX_PAYLOAD_LENGTH + 1];
        char data[COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + MAX_PAYLOAD_LENGTH]; //full message without prefix //TODO
    public:
        bytes_converter() : prefix(NULL)
        {
        }

        virtual char *get_data() = 0;
        virtual void set_data(char *data_) = 0;

        char *get_prefix()
        {
            return prefix;
        }

        int get_prefix_len()
        {
            return prefix_length;
        }

        void set_prefix(const char *_prefix, int pref_len)
        {
            prefix = new char[pref_len];
            memcpy(prefix, _prefix, pref_len);
            prefix_length = pref_len;
        }

        //from command, length, checksum, payload to data
        virtual UniValue decode() = 0; //old: decode_data
        //from msg_obj to tuple<char*, int>s(data, len)
        virtual tuple<char *, int> encode(UniValue json) = 0; //old: encode_data

        virtual const char *get_command() = 0;
        virtual void set_command(const char *_command) = 0;

        virtual bool isEmpty() { return false; }

        virtual void set_unpacked_len(char *packed_len = nullptr) = 0;
        virtual int get_unpacked_len() = 0;
    };

    class empty_converter : public bytes_converter
    {
    public:
        char command[COMMAND_LENGTH + 1];

    public:
        empty_converter() {}

        empty_converter(const char *_command) { set_command(_command); }

        char *get_data() override
        {
            return nullptr;
        }

        void set_data(char *data_) override {}

        UniValue decode() override
        {
            UniValue result(UniValue::VNULL);
            return result;
        }

        tuple<char *, int> encode(UniValue json) override
        {

            LOG_WARNING << "called encode(json) from empty_converter!";
            return std::make_tuple<char *, int>(get_data(), 0);
        }

        virtual const char *get_command() { return command; }

        void set_command(const char *_command) { strcpy(command, _command); }

        bool isEmpty() override { return true; }

        void set_unpacked_len(char *packed_len = nullptr) override {}
        int get_unpacked_len() override { return 0; }
    };

    //for p2pool serialize/deserialize
    class p2pool_converter : public bytes_converter, public std::enable_shared_from_this<p2pool_converter>
    {
        friend c2pool::python::PyPackTypes;

    public:
        void set_unpacked_len(char *packed_len = nullptr);
        int get_unpacked_len() override;

    private:
        unsigned int _unpacked_length = 0;

    public:
        p2pool_converter() {}

        p2pool_converter(const char *_command) { set_command(_command); }

        p2pool_converter(std::shared_ptr<bytes_converter> _empty)
        {
            set_command(_empty->get_command());
        }

        //p2pool_converter(const char *current_prefix);

        ~p2pool_converter()
        {
            if (prefix != nullptr)
            {
                delete[] prefix;
            }
        }

        char *get_data() override { return data; }
        void set_data(char *data_) override;

        //from command, length, checksum, payload to data
        //void decode_data();
        UniValue decode() override;

        //from data to command, length, checksum, payload
        //void encode_data();
        tuple<char *, int> encode(UniValue json) override;

        virtual const char *get_command() override { return command; }
        void set_command(const char *_command) override { strcpy(command, _command); }

        int get_length();

    protected:
        int set_length(char *data_);
    };

    //TODO: create C2PoolConverter!
}