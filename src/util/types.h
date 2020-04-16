#ifndef CPOOL_TYPES_H
#define CPOOL_TYPES_H

#include <iostream>
#include <string>
using namespace std;

//todo: move all methods to types.cpp
namespace c2pool::messages{

    class address_type{
    public:
        /*
            ('services', pack.IntType(64)),
            ('address', pack.IPV6AddressType()),
            ('port', pack.IntType(16, 'big')),
         */
        int services;
        string address;
        int port;


        address_type(){
            services = 0;
            address = "";
            port = 0;
        }

        address_type(int _services, string _address, int _port){
            services = _services;
            address = _address;
            port = _port;
        }

        friend istream& operator>>(istream& is, address_type& value){
            is >> value.services >> value.address >> value.port; //TODO: read string to address, from parse '<data>'
            return is;
        }

        friend ostream& operator<<(ostream& os, const address_type& value){
            os << value.services << ";" << value.address << ";" << value.port;
            return os;
        }
    };

    class share_type{
    public:
        /*
            ('type', pack.VarIntType()),
            ('contents', pack.VarStrType()),
        */
        int type;
        string contents;

        share_type(){
            type = 0;
            contents = "";
        }

        share_type(int _type, string _contents){
            type = type;
            contents = _contents;
        }

        friend istream& operator>>(istream& is, share_type& value){
            is >> value.type >> value.contents; //TODO: read string to contents, from parse '<data>'
            return is;
        }

        friend ostream& operator<<(ostream& os, const share_type& value){
            os << value.type << ";" << "'" << value.contents << "'";
            return os;
        }
    };

    class addr{
    public:
        addr(){
            address = address_type();
            timestamp = 0;
        }

        addr(address_type a, int t){
            address = a;
            timestamp = t;
        }

        addr(int _services, string _address, int _port, int t){
            address_type a = address_type(_services,_address, _port);
            address = a;
            timestamp = t;
        }

        friend istream& operator>>(istream& is, addr& value){
            is >> value.address >> value.timestamp;
            return is;
        }

        friend ostream& operator<<(ostream& os, const addr& value){
            os << value.address << ";" << value.timestamp;
        }

        address_type address;
        int timestamp;

    };


}



#endif //CPOOL_TYPES_H
