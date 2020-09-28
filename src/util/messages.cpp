#include "messages.h"
#include "protocol.h"
#include <iostream>
#include "types.h"
#include "pack.h"
#include "other.h"
#include <sstream>
#include <string>
#include <cstring>
#include "console.h"
#include <tuple>
using namespace c2pool::messages;

namespace c2pool::messages
{
    //MessageData

    packageMessageData::packageMessageData(const char *current_prefix)
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

    void packageMessageData::set_data(char *data_)
    {
        memcpy(data, data_, set_length(data_));
        //strcpy(data, data_);
    }

    void packageMessageData::encode_data()
    {
        c2pool::str::substr(command, data, 0, command_length);
        if (_unpacked_length == 0)
        {
            c2pool::str::substr(length, data, command_length, payload_length);
            _unpacked_length = c2pool::messages::python::pymessage::receive_length(length);
        }
        c2pool::str::substr(checksum, data, command_length + payload_length, checksum_length);
        c2pool::str::substr(payload, data, command_length + payload_length + checksum_length, _unpacked_length);
    }

    void packageMessageData::decode_data()
    {
        sprintf(data, "%s%s%s%s", command, length, checksum, payload); //TODO: NOT WORKED!
    }

    void packageMessageData::set_unpacked_length(char *packed_len)
    {
        if (packed_len != nullptr)
        {
            memcpy(length, packed_len, payload_length);
        }
        if (length != nullptr)
        {
            _unpacked_length = c2pool::messages::python::pymessage::receive_length(length);
        }
    }

    const unsigned int packageMessageData::unpacked_length()
    {
        return _unpacked_length;
    }

    int packageMessageData::set_length(char *data_)
    {
        if (data_ != nullptr)
        {
            c2pool::str::substr(length, data_, command_length, payload_length);
            _unpacked_length = c2pool::messages::python::pymessage::receive_length(length);
        }

        return get_length();
    }

    int packageMessageData::get_length()
    {
        return command_length + payload_length + checksum_length + unpacked_length();
    }

    //message

    message::message(const char *_cmd)
    {
        packageData = std::make_shared<packageMessageData>();
        strcpy(packageData->command, _cmd);
    }

    message::message(const char *_cmd, std::shared_ptr<packageMessageData> _packageData){
        packageData = _packageData;
        strcpy(packageData->command, _cmd);
    }

    void message::receive()
    {
        std::stringstream ss = c2pool::messages::python::pymessage::receive(packageData->command, packageData->checksum, packageData->payload, packageData->unpacked_length());
        unpack(ss);
    }

    void message::receive_from_data(char *_set_data = nullptr)
    {
        if (_set_data != nullptr)
        {
            packageData->set_data(_set_data);
        }
        packageData->encode_data();
        receive();
    }

    void message::send()
    {
        packageData = std::make_shared<packageMessageData>();
        packageData->set_data(c2pool::messages::python::pymessage::send(this));
    }

    std::tuple<char *, int> message::send_data(const void *_prefix, int _prefix_len)
    {
        send();

        char *full_data = new char[_prefix_len + packageData->get_length()+1]; //TODO: delete full_data

        memcpy(full_data, _prefix, _prefix_len);
        memcpy(full_data+_prefix_len, packageData->data, packageData->get_length());

        //std::cout << "pref_len = " << _prefix_len << ", data len = " << get_length() << ", full len = " << _prefix_len + get_length() << std::endl;

        return std::make_tuple(full_data, _prefix_len + packageData->get_length());
    }

    void message::unpack(std::string item)
    {
        std::stringstream ss;
        ss << item;
        _unpack(ss);
    }

    void message::unpack(std::stringstream &ss)
    {
        _unpack(ss);
    }

    std::string message::pack()
    {
        //TODO:
        return _pack();
    }

    char *message::pack_c_str()
    {
        std::string str = pack();
        packed_c_str = new char[str.length() + 1];
        memcpy(packed_c_str, str.c_str(), str.length() + 1);
        return packed_c_str;
    }

    int message::pack_payload_length()
    {
        return c2pool::messages::python::pymessage::payload_length(packageData->command, pack_c_str());
    }

    //message_error

    void message_error::_unpack(std::stringstream &ss)
    {
        //NOTHING :(
    }

    string message_error::_pack()
    {
        return std::string("MESSAGE_ERROR!");
    }

    //message_version

    void message_version::_unpack(std::stringstream &ss)
    {
        LOG_DEBUG << "TEST_UNPACKs";
        std::string temp;
        while(ss >> temp) LOG_DEBUG << temp;
        ss >> version >> services >> addr_to >> addr_from >> nonce >> sub_version >> mode >> best_share_hash;
    }

    string message_version::_pack()
    {
        c2pool::pack::ComposedType ct;
        ct.add(version);
        ct.add(services);
        ct.add(addr_to);
        ct.add(addr_from);
        ct.add(nonce);
        ct.add(sub_version);
        ct.add(mode);
        ct.add(best_share_hash);
        return ct.read();
    }

    //message_ping

    void message_ping::_unpack(std::stringstream &ss)
    {
        //todo: Empty variables list
    }

    std::string message_ping::_pack()
    {
        c2pool::pack::ComposedType ct;
        //TODO: ct.add(cmd);
        return ct.read();
    }

    //message_addrme

    void message_addrme::_unpack(std::stringstream &ss)
    {
        ss >> port;
    }

    std::string message_addrme::_pack()
    {
        c2pool::pack::ComposedType ct;
        ct.add(port);
        return ct.read();
    }

    //message_getaddrs

    void message_getaddrs::_unpack(std::stringstream &ss)
    {
        ss >> count;
    }

    std::string message_getaddrs::_pack()
    {
        c2pool::pack::ComposedType ct;
        ct.add(count);
        return ct.read();
    }

    //message_addrs

    void message_addrs::_unpack(std::stringstream &ss)
    {
        //перед массивом идёт int(длина массива)
        addr addrBuff;
        while (ss >> addrBuff)
        {
            addrs.push_back(addrBuff);
        }
    }

    std::string message_addrs::_pack()
    {
        c2pool::pack::ComposedType ct;
        ct.add(addrs);
        return ct.read();
    }

} // namespace c2pool::messages
