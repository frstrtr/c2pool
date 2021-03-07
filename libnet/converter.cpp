#include "converter.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include <util/pystruct.h>

#include <tuple>
using std::tuple;

namespace c2pool::libnet::messages
{
    //p2pool_converter

    //TODO:
    // p2pool_converter::p2pool_converter(const char *current_prefix)
    // {
    //     if (sizeof(current_prefix) > 0)
    //     {
    //         prefix_length = sizeof(current_prefix) / sizeof(current_prefix[0]);
    //     }
    //     else
    //     {
    //         prefix_length = 0;
    //         LOG_WARNING << "prefix length <= 0!";
    //     }
    //     prefix = new char[prefix_length];
    //     memcpy(prefix, current_prefix, prefix_length);
    // } //TODO: update?

    void p2pool_converter::set_unpacked_len(char *packed_len)
    {
        if (packed_len != nullptr) //TODO: wanna to remove?
        {
            memcpy(length, packed_len, PAYLOAD_LENGTH);
        }
        if (length != nullptr)
        {
            LOG_TRACE << "set_unpacked_len length != nullptr";
            _unpacked_length = c2pool::python::PyPackTypes::receive_length(length);
        }
    }

    int p2pool_converter::get_unpacked_len()
    {
        set_unpacked_len();
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

    //new p2pool_converter

    // p2pool_converter::p2pool_converter(const char *current_prefix)
    // {
    //     if (sizeof(current_prefix) > 0)
    //     {
    //         prefix_length = sizeof(current_prefix) / sizeof(current_prefix[0]);
    //     }
    //     else
    //     {
    //         prefix_length = 0;
    //         LOG_WARNING << "prefix length <= 0!";
    //     }
    //     prefix = new char[prefix_length];
    //     memcpy(prefix, current_prefix, prefix_length);
    // }

    tuple<char *, int> p2pool_converter::encode(UniValue json)
    {
        LOG_TRACE << "before set data with pypacktypes encode";
        set_data(c2pool::python::PyPackTypes::encode(json));
        LOG_TRACE << "before return encode result";
        return make_tuple<char*, int>(get_data(), get_length());
    }

    UniValue p2pool_converter::decode()
    {
        LOG_TRACE << "p2pool_converter::decode() called!";
        return c2pool::python::PyPackTypes::decode(shared_from_this());
    }

    void p2pool_converter::set_data(char *data_)
    {
        memcpy(data, data_, set_length(data_));
    }

    int p2pool_converter::get_length()
    {
        return COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + get_unpacked_len();
    }

} // namespace c2pool::libnet::messages