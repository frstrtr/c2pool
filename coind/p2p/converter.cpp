#include "converter.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include "pystruct.h"

#include <tuple>
using std::tuple, std::make_tuple;

namespace c2pool::coind::p2p::messages
{

    void coind_converter::set_unpacked_len(char *packed_len)
    {
        if (packed_len != nullptr) //TODO: wanna to remove?
        {
            memcpy(length, packed_len, PAYLOAD_LENGTH);
        }
        if (length != nullptr)
        {
            LOG_TRACE << "set_unpacked_len length != nullptr";
            _unpacked_length = c2pool::coind::p2p::python::PyPackCoindTypes::receive_length(length);
        }
    }

    int coind_converter::get_unpacked_len()
    {
        set_unpacked_len();
        return _unpacked_length;
    }

    int coind_converter::set_length(char *data_)
    {
        if (data_ != nullptr)
        {
            c2pool::dev::substr(length, data_, COMMAND_LENGTH, PAYLOAD_LENGTH);
            _unpacked_length = c2pool::coind::p2p::python::PyPackCoindTypes::receive_length(length);
        }

        return get_length();
    }

    tuple<char *, int> coind_converter::encode(UniValue json)
    {
        LOG_TRACE << "before set data with pypacktypes encode";
        set_data(c2pool::coind::p2p::python::PyPackCoindTypes::encode(json));
        LOG_TRACE << "before return encode result";
        return make_tuple<char *, int>(get_data(), get_length());
    }

    UniValue coind_converter::decode()
    {
        LOG_TRACE << "p2pool_converter::decode() called!";
        return c2pool::coind::p2p::python::PyPackCoindTypes::decode(shared_from_this());
    }

    void coind_converter::set_data(char *data_)
    {
        memcpy(data, data_, set_length(data_)); //set_length return len for data_
    }

    int coind_converter::get_length()
    {
        return COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + get_unpacked_len();
    }

} // namespace c2pool::libnet::messages