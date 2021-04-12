#pragma once

#include <memory>
#include <univalue.h>
#include <devcore/logger.h>

#include <tuple>
using std::tuple;

#define COMMAND_LENGTH 12
#define PAYLOAD_LENGTH 4           //len(payload)
#define CHECKSUM_LENGTH 4          //sha256(sha256(payload))[:4]
// #define MAX_PAYLOAD_LENGTH 8000000 //max len payload

namespace coind::p2p::python{
    class PyPackCoindTypes;
}

namespace coind::p2p
{
    class P2PSocket;
}

namespace coind::p2p::messages
{
    class coind_converter : public std::enable_shared_from_this<coind_converter>
    {
        friend coind::p2p::python::PyPackCoindTypes;
        friend coind::p2p::P2PSocket;

    protected:
        char *prefix;
        int prefix_length = 0;

        char command[COMMAND_LENGTH + 1];
        char length[PAYLOAD_LENGTH + 1];
        char checksum[CHECKSUM_LENGTH + 1];
        char* payload;
        char* data;//[COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH]; //full message without prefix //TODO
    public:
        coind_converter() : prefix(NULL) {}

        coind_converter(const char *_command) : prefix(NULL) { set_command(_command); }

        ~coind_converter()
        {
            if (prefix != nullptr)
            {
                delete[] prefix;
            }
        }

        char *get_data() { return data; }
        void set_data(char *data_);

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
        UniValue decode();

        //from data to command, length, checksum, payload
        //void encode_data();
        tuple<char *, int> encode(UniValue json);

        const char *get_command() { return command; }
        void set_command(const char *_command) { strcpy(command, _command); }

        virtual bool isEmpty() { return false; }

        void set_unpacked_len();
        int get_unpacked_len();

        int get_length();
        int set_length(char *data_);

    private:
        unsigned int _unpacked_length = -1;

    public:
    };
}