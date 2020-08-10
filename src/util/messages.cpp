#include "messages.h"
#include "protocol.h"
#include <iostream>
#include "types.h"
#include "pack.h"
#include "other.h"
#include <sstream>
#include <string>
#include <cstring>
using namespace c2pool::messages;

namespace c2pool::messages
{
    //IMessage

    IMessage::IMessage(const char *current_prefix)
    {
        _prefix_length = std::strlen(current_prefix);
        prefix = new char[prefix_length()];
        strcpy(prefix, current_prefix);
    }

    void IMessage::set_data(char *data_)
    {
        memcpy(data, data_, data_length());
        //strcpy(data, data_);
    }

    void IMessage::encode_data()
    {
        c2pool::str::substr(command, data, 0, command_length);
        c2pool::str::substr(length, data, command_length, payload_length);
        _unpacked_length = c2pool::messages::python::pymessage::receive_length(length);
        c2pool::str::substr(checksum, data, command_length + payload_length, checksum_length);
        c2pool::str::substr(payload, data, command_length + payload_length + checksum_length, _unpacked_length);
    }

    void IMessage::decode_data()
    {
        sprintf(data, "%s%s%s%s", command, length, checksum, payload);
    }

    const unsigned int IMessage::unpacked_length()
    {
        if (_unpacked_length == 0)
        {
            if (length == 0) {
                _unpacked_length = pack_payload_length();
            }
            else {
                _unpacked_length = c2pool::messages::python::pymessage::receive_length(length);
            }
        }
        return _unpacked_length;
    }

    int IMessage::data_length() {
        int res = 0;
        res += command_length + payload_length + checksum_length;
        res += unpacked_length();
        cout << "RES: " << res << endl;
        return res;
    }

    //message

    message::message(const char *_cmd)
    {
        strcpy(command, _cmd);
    }

    void message::receive()
    {
        std::stringstream ss = c2pool::messages::python::pymessage::receive(command, checksum, payload, unpacked_length());
        unpack(ss);
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

    void message::send()
    {
        set_data(c2pool::messages::python::pymessage::send(this));
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

    int message::pack_payload_length(){
        return c2pool::messages::python::pymessage::payload_length(command, pack_c_str());
    }

    //message_version

    void message_version::_unpack(std::stringstream &ss)
    {
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
