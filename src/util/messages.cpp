#include "messages.h"
#include "protocol.h"
#include <iostream>
#include "types.h"
#include "pack.h"
#include <sstream>
#include <string>
#include <cstring>
using namespace c2pool::messages;

namespace c2pool::messages
{
    //IMessageReader

    IMessageReader::IMessageReader(IMessageReader& msgData){
        strcpy(data_, msgData.data_);
    }

    //message

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
        ct.add(command);
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
        int count;
        addr addrBuff;
        ss >> count;
        for (int i = 0; i < count; i++)
        {
            ss >> addrBuff;
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
