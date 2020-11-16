#include "messages.h"
#include "protocol.h"
#include <iostream>
#include "types.h"
#include "other.h"
#include <sstream>
#include <string>
#include <cstring>
#include "console.h"
#include "pystruct.h"
#include "univalue.h"
using namespace c2pool::messages;

namespace c2pool::messages
{
    //IMessage

    IMessage::IMessage(const char *current_prefix)
    {
        if (sizeof(current_prefix) > 0)
        {
            _prefix_length = sizeof(current_prefix) / sizeof(current_prefix[0]);
        }
        else
        {
            _prefix_length = 0;
            LOG_WARNING << "prefix length <= 0!";
        }
        prefix = new char[prefix_length()];
        memcpy(prefix, current_prefix, prefix_length());
    }

    void IMessage::set_data(char *data_)
    {
        memcpy(data, data_, set_length(data_));
        //strcpy(data, data_);
    }

    void IMessage::encode_data()
    {
        c2pool::str::substr(command, data, 0, command_length);
        if (_unpacked_length == 0)
        {
            c2pool::str::substr(length, data, command_length, payload_length);
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }
        c2pool::str::substr(checksum, data, command_length + payload_length, checksum_length);
        c2pool::str::substr(payload, data, command_length + payload_length + checksum_length, _unpacked_length);
    }

    void IMessage::decode_data()
    {
        sprintf(data, "%s%s%s%s", command, length, checksum, payload);
    }

    void IMessage::set_unpacked_length(char* packed_len){
        if (packed_len != nullptr)
        {
            memcpy(length, packed_len, payload_length);
        }
        if (length != nullptr){
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }
    }

    const unsigned int IMessage::unpacked_length()
    {
        return _unpacked_length;
    }

    int IMessage::set_length(char *data_)
    {
        if (data_ != nullptr)
        {
            c2pool::str::substr(length, data_, command_length, payload_length);
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }

        return get_length();
    }

    int IMessage::get_length()
    {
        return command_length + payload_length + checksum_length + unpacked_length();
    }

    //message

    message::message(const char *_cmd)
    {
        strcpy(command, _cmd);
    }

    /*TODO: REWORK FOR STATIC TEMPLATE [for tests]
    void message::receive()
    {
        UniValue value = c2pool::python::PyPackTypes::deserialize(this);
        unpack(value);
    }

    void message::receive_from_data(char *_set_data = nullptr)
    {
        if (_set_data != nullptr)
        {
            set_data(_set_data);
        }
        encode_data();
        receive();
    } 
    */

    void message::send()
    {
        set_data(c2pool::python::PyPackTypes::serialize(this));
    }

    UniValue message::pack()
    {
        return _pack();
    }

    int message::pack_payload_length()
    {
        return c2pool::python::PyPackTypes::payload_length(this);
    }

    //message_error

    UniValue message_error::_pack()
    {
        UniValue value(UniValue::VOBJ);
        value.pushKV("text", "MESSAGE_ERROR");
        return value;
    }

    //message_version

    UniValue message_version::_pack()
    {
        UniValue value(UniValue::VOBJ);
        value = *this;
        return value;
    }

    //message_ping

    UniValue message_ping::_pack()
    {
        UniValue value(UniValue::VOBJ);
        return value;
    }

    //message_addrme

    UniValue message_addrme::_pack()
    {
        UniValue value(UniValue::VOBJ);
        value = *this;
        return value;
    }

    //message_getaddrs

    UniValue message_getaddrs::_pack()
    {
        UniValue value(UniValue::VOBJ);
        value = *this;
        return value;
    }

    //message_addrs

    UniValue message_addrs::_pack()
    {
        UniValue value(UniValue::VOBJ);
        value = *this;
        return value;
    }

} // namespace c2pool::messages
