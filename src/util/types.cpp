#include "types.h"
#include <iostream>
#include <string>

namespace c2pool::messages
{

    address_type::address_type()
    {
        services = 0;
        address = "";
        port = 0;
    }

    address_type::address_type(int _services, std::string _address, int _port)
    {
        services = _services;
        address = _address;
        port = _port;
    }

    bool operator==(const address_type &first, const address_type &second)
    {
        if (first.address != second.address)
            return false;
        if (first.port != second.port)
            return false;
        if (first.services != second.services)
            return false;
        return true;
    }

    bool operator!=(const address_type &first, const address_type &second)
    {
        return !(first == second);
    }
    //share_type:

    share_type::share_type()
    {
        type = 0;
        contents = "";
    }

    share_type::share_type(int _type, std::string _contents)
    {
        type = type;
        contents = _contents;
    }

    addr::addr()
    {
        address = address_type();
        timestamp = 0;
    }

    addr::addr(int t, address_type a)
    {
        address = a;
        timestamp = t;
    }

    addr::addr(int t, int _services, std::string _address, int _port)
    {
        address_type a = address_type(_services, _address, _port);
        address = a;
        timestamp = t;
    }

    bool operator==(const addr &first, const addr &second)
    {
        if (first.address != second.address)
            return false;
        if (first.timestamp != second.timestamp)
            return false;
        return true;
    }

    bool operator!=(const addr &first, const addr &second)
    {
        return !(first == second);
    }

} // namespace c2pool::messages