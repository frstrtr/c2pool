#include "types.h"
#include <iostream>
#include <sstream>
#include <string>

address_type::address_type()
{
    services = 0;
    address = "";
    port = 0;
}

address_type::address_type(unsigned long long _services, std::string _address, int _port)
{
    services = _services;
    address = _address;
    port = _port;
}

address_type::address_type(unsigned long long _services, std::string _address, std::string _port)
{
	services = _services;
	address = _address;

	std::stringstream ss;
	ss << _port;
	ss >> port;
}

bool operator==(const address_type &first, const address_type &second)
{
    if (first.address != second.address)
    {
        return false;
    }
    if (first.port != second.port)
    {
        return false;
    }
    if (first.services != second.services)
    {
        return false;
    }
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

//addr

addr::addr()
{
    address = address_type();
    timestamp = 0;
}

addr::addr(int64_t t, address_type a)
{
    address = a;
    timestamp = t;
}

addr::addr(int64_t t, int _services, std::string _address, int _port)
{
    address_type a = address_type(_services, _address, _port);
    address = a;
    timestamp = t;
}

bool operator==(const addr &first, const addr &second)
{
    if (first.address != second.address)
    {
        return false;
    }
    if (first.timestamp != second.timestamp)
    {
        return false;
    }
    return true;
}

bool operator!=(const addr &first, const addr &second)
{
    return !(first == second);
}

//inventory

inventory::inventory()
{
    type = inventory_type::tx;
    hash.SetNull();
}

inventory::inventory(inventory_type _type, uint256 _hash)
{
    type = _type;
    hash = _hash;
}

bool operator==(const inventory &first, const inventory &second)
{
    if (first.type != second.type)
    {
        return false;
    }
    if (first.hash != second.hash)
    {
        return false;
    }
    return true;
}

bool operator!=(const inventory &first, const inventory &second)
{
    return !(first == second);
}
