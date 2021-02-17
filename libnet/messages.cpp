#include "messages.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include <util/pystruct.h>

namespace c2pool::libnet::messages
{
    //p2pool_converter

    p2pool_converter::p2pool_converter(const char *current_prefix)
    {
        if (sizeof(current_prefix) > 0)
        {
            prefix_length = sizeof(current_prefix) / sizeof(current_prefix[0]);
        }
        else
        {
            prefix_length = 0;
            LOG_WARNING << "prefix length <= 0!";
        }
        prefix = new char[prefix_length];
        memcpy(prefix, current_prefix, prefix_length);
    }

    void p2pool_converter::set_data(char *data_)
    {
        memcpy(data, data_, set_length(data_));
    }

    // void p2pool_converter::deserialize()
    // {
    //     c2pool::dev::substr(command, data, 0, COMMAND_LENGTH);
    //     if (_unpacked_length == 0)
    //     {
    //         c2pool::dev::substr(length, data, COMMAND_LENGTH, PAYLOAD_LENGTH);
    //         _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
    //     }
    //     c2pool::dev::substr(checksum, data, COMMAND_LENGTH + PAYLOAD_LENGTH, CHECKSUM_LENGTH);
    //     c2pool::dev::substr(payload, data, COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH, _unpacked_length);
    // }

    // void p2pool_converter::serialize()
    // {
    //     sprintf(data, "%s%s%s%s", command, length, checksum, payload);
    // }

    void p2pool_converter::set_unpacked_length(char *packed_len)
    {
        if (packed_len != nullptr) //TODO: wanna to remove?
        {
            memcpy(length, packed_len, PAYLOAD_LENGTH);
        }
        if (length != nullptr)
        {
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }
    }

    const unsigned int p2pool_converter::unpacked_length()
    {
        set_unpacked_length();
        return _unpacked_length;
    }

    int p2pool_converter::set_length(char *data_)
    {
        if (data_ != nullptr)
        {
            c2pool::dev::substr(length, data_, COMMAND_LENGTH, PAYLOAD_LENGTH);
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }

        return get_length();
    }

    int p2pool_converter::get_length()
    {
        return COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + unpacked_length();
    }

    //new p2pool_converter

    char* p2pool_converter::encode(UniValue json)
    {
        set_data(c2pool::python::PyPackTypes::encode(json));
        return get_data();
    }

    UniValue p2pool_converter::decode(){
        return c2pool::python::PyPackTypes::decode(shared_from_this());
    }

    //base_message

    //message

    // void message::send()
    // {
    //     set_data(c2pool::python::PyPackTypes::serialize(this));
    // }

    // int message::pack_payload_length()
    // {
    //     return c2pool::python::PyPackTypes::payload_length(this);
    // }
} // namespace c2pool::libnet::messages