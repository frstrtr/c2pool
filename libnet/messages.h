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

    //message type for handle
    class raw_message
    {
    public:
        c2pool::libnet::messages::commands name_type;
        UniValue value;

    protected:
        std::unique_ptr<bytes_converter> converter;

    public:
        template <class converter_type>
        raw_message()
        {
            converter = std::make_unique<converter_type>();
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
        template <class converter_type>
        base_message(const char *_cmd)
        {
            converter = std::make_shared<converter_type>();
            converter->set_command(_cmd);
        }

        base_message(const char *_cmd)
        {
            converter = std::make_shared<empty_converter>(_cmd);
        }

        template <class converter_type>
        void set_converter()
        {
            std::shared_ptr<converter_type> new_converter = std::make_shared<converter_type>();
            new_converter->set_command(converter->get_command());
            converter = new_converter;
        }

        //message -> bytes; msg = self
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

} // namespace c2pool::libnet::messages