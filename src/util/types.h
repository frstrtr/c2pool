#ifndef CPOOL_TYPES_H
#define CPOOL_TYPES_H

#include <string>

//todo: move all methods to types.cpp
namespace c2pool::messages
{

    class address_type
    {
    public:
        /*
            ('services', pack.IntType(64)),
            ('address', pack.IPV6AddressType()),
            ('port', pack.IntType(16, 'big')),
         */
        int services;
        std::string address;
        int port;

        address_type();

        address_type(int _services, std::string _address, int _port);

        friend std::istream &operator>>(std::istream &is, address_type &value);

        friend std::ostream &operator<<(std::ostream &os, const address_type &value);

        friend bool operator==(const address_type &first, const address_type &second);

        friend bool operator!=(const address_type &first, const address_type &second);
    };

    class share_type
    {
    public:
        /*
            ('type', pack.VarIntType()),
            ('contents', pack.VarStrType()),
        */
        int type;
        std::string contents;

        share_type();

        share_type(int _type, std::string _contents);

        friend std::istream &operator>>(std::istream &is, share_type &value);

        friend std::ostream &operator<<(std::ostream &os, const share_type &value);
    };

    class addr
    {
    public:
        addr();

        addr(address_type a, int t);

        addr(int _services, std::string _address, int _port, int t);

        friend std::istream &operator>>(std::istream &is, addr &value);
        friend std::ostream &operator<<(std::ostream &os, const addr &value);

        address_type address;
        int timestamp;
    };
} // namespace c2pool::messages

#endif //CPOOL_TYPES_H