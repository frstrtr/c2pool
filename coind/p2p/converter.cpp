#include "converter.h"
#include <devcore/logger.h>
#include <devcore/str.h>
#include "pystruct.h"

#include <tuple>
using std::tuple, std::make_tuple;

namespace coind::p2p::messages
{

    void coind_converter::set_unpacked_len()
    {
        if (length != nullptr && _unpacked_length == -1)
        {
            LOG_TRACE << "set_unpacked_len length != nullptr";
            _unpacked_length = coind::p2p::python::PyPackCoindTypes::receive_length(length);
            LOG_TRACE << "_unpacked_len = " << _unpacked_length;
            payload = new char[_unpacked_length+1];
        }
    }

    int coind_converter::get_unpacked_len()
    {
        set_unpacked_len();
        if (_unpacked_length < 0)
        {
            //TODO: LOG _unpacked_length < 0
            return 0;
        }
        return _unpacked_length;
    }

    int coind_converter::set_length(char *data_)
    {
        if (data_ != nullptr)
        {
            c2pool::dev::substr(length, data_, COMMAND_LENGTH, PAYLOAD_LENGTH);
            _unpacked_length = coind::p2p::python::PyPackCoindTypes::receive_length(length);
        }

        return get_length();
    }

    tuple<char *, int> coind_converter::encode(UniValue json)
    {
        LOG_TRACE << "before set data with pypacktypes encode";
        set_data(coind::p2p::python::PyPackCoindTypes::encode(json));
        LOG_TRACE << "before return encode result";
        return make_tuple<char *, int>(get_data(), get_length());
    }

    UniValue coind_converter::decode()
    {
        LOG_TRACE << "p2pool_converter::decode() called!";
        return coind::p2p::python::PyPackCoindTypes::decode(shared_from_this());
    }

    void coind_converter::set_data(char *data_)
    {
        auto data_length = set_length(data_);
        data = new char[data_length];
        memcpy(data, data_, data_length); //set_length return len for data_
    }

    int coind_converter::get_length()
    {
        return COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + get_unpacked_len();
    }

} // namespace c2pool::libnet::messages