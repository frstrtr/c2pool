#pragma once

#include <memory>
#include <lib/univalue/include/univalue.h>

#define COMMAND_LENGTH 12
#define PAYLOAD_LENGTH 4           //len(payload)
#define CHECKSUM_LENGTH 4          //sha256(sha256(payload))[:4]
#define MAX_PAYLOAD_LENGTH 8000000 //max len payload

namespace c2pool::python
{
    class PyPackTypes;
}

namespace c2pool::libnet::messages
{
    class bytes_converter
    {
    public:
        virtual char *get_data() = 0;
        virtual void set_data(char *data_) = 0;

        //from command, length, checksum, payload to data
        virtual UniValue decode() = 0; //old: decode_data
        //from data to command, length, checksum, payload
        virtual char *encode(UniValue json) = 0; //old: encode_data

        virtual const char *get_command() = 0;
        virtual void set_command(const char *_command) = 0;

        virtual bool isEmpty() { return false; }
    };

    class empty_converter : public bytes_converter
    {
    public:
        char command[COMMAND_LENGTH + 1];

    public:
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

        char *encode(UniValue json) override { return get_data(); }

        virtual const char *get_command() { return command; }

        void set_command(const char *_command) { strcpy(command, _command); }

        bool isEmpty() override { return true; }
    };

    //for p2pool serialize/deserialize
    class p2pool_converter : public bytes_converter, public std::enable_shared_from_this<p2pool_converter>
    {
        friend c2pool::python::PyPackTypes;

    public:
        int prefix_length;
        const unsigned int unpacked_length();

    public:
        char *prefix;
        char command[COMMAND_LENGTH + 1];
        char length[PAYLOAD_LENGTH + 1];
        char checksum[CHECKSUM_LENGTH + 1];
        char payload[MAX_PAYLOAD_LENGTH + 1];
        char data[COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + MAX_PAYLOAD_LENGTH]; //full message without prefix //TODO
    private:
        unsigned int _unpacked_length = 0;

    public:
        p2pool_converter() {}

        p2pool_converter(const char *current_prefix);

        ~p2pool_converter()
        {
            delete prefix;
        }

        char *get_data() { return data; }
        void set_data(char *data_);

        void set_unpacked_length(char *packed_len = nullptr);

        //from command, length, checksum, payload to data
        //void decode_data();
        UniValue decode();

        //from data to command, length, checksum, payload
        //void encode_data();
        char *encode(UniValue json);

        int get_length();

    protected:
        int set_length(char *data_);
    };

    //TODO: create C2PoolConverter!
}