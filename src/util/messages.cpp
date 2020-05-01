#include "messages.h"
#include "protocol.h"
#include <iostream>
#include "types.h"
#include "pack.h"
#include <sstream>
#include <string>
using namespace c2pool::messages;

namespace c2pool::messages
{
    void message::unpack(std::string item)
    {
        std::stringstream ss;
        ss << item;
        _unpack(ss);
    }

    std::string message::pack()
    {
        //TODO:
        return _pack();
    }

    message *fromStr(std::string str)
    {
        if (str == "version")
        {
            return new message_version();
        }

        return new message_error();
    }

    void message_version::_unpack(std::stringstream &ss)
    {
        ss >> version >> services >> addr_to >> addr_from >> nonce >> sub_version >> mode >> best_share_hash;

        //TODO: override operator >> for address_type;
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

    void message_version::handle(p2p::Protocol *protocol)
    {
        protocol->handle_version(/*todo*/);
    }

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

    void message_ping::handle(p2p::Protocol *protocol)
    {
        protocol->handle_ping(/*todo*/);
    }

    void message_addrme::_unpack(std::`stringstream &ss)
    {
        ss >> port;
    }

    std::string message_addrme::_pack()
    {
        c2pool::pack::ComposedType ct;
        ct.add(port);
        return ct.read();
    }

    void handle(p2p::Protocol *protocol)
    {
        protocol->handle_addrme(/*todo*/);
    }

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

    void message_getaddrs::handle(p2p::Protocol *protocol)
    {
        protocol->handle_getaddrs(/*todo*/);
    }

    void message_addrs::_unpack(std::stringstream &ss)
    {
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
        ct.add(addrs); //TODO: override operator << for this
        return ct.read();
    }

    void message_addrs::handle(p2p::Protocol *protocol)
    {
        protocol->handle_addrs(/*todo*/);
    }

} // namespace c2pool::messages
