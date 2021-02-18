#pragma once

#include <memory>
#include <lib/univalue/include/univalue.h>

#include "converter.h"


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