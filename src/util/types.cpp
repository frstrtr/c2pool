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

    std::istream &operator>>(std::istream &is, address_type &value)
    {
        is >> value.services >> value.address >> value.port; //TODO: read string to address, from parse '<data>'
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const address_type &value)
    {
        os << value.services << ";" << value.address << ";" << value.port;
        return os;
    }

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

    std::istream &operator>>(std::istream &is, share_type &value)
    {
        is >> value.type >> value.contents; //TODO: read string to contents, from parse '<data>'
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const share_type &value)
    {
        os << value.type << ";"
           << "'" << value.contents << "'";
        return os;
    }

    addr::addr()
    {
        address = address_type();
        timestamp = 0;
    }

    addr::addr(address_type a, int t)
    {
        address = a;
        timestamp = t;
    }

    addr::addr(int _services, std::string _address, int _port, int t)
    {
        address_type a = address_type(_services, _address, _port);
        address = a;
        timestamp = t;
    }

    std::istream &operator>>(std::istream &is, addr &value)
    {
        is >> value.address >> value.timestamp;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const addr &value)
    {
        os << value.address << ";" << value.timestamp;
        return os;
    }

} // namespace c2pool::messages