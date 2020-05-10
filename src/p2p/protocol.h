#ifndef CPOOL_PROTOCOL_H
#define CPOOL_PROTOCOL_H

#include "boost/asio.hpp"
#include "types.h"
#include "node.h"
// #include "factory.h"
// #include "node.h"
// //#include <stdio>
// #include <string>
// #include "pystruct.h"
// #include <sstream>
// #include "config.cpp"
// #include <map>
// #include <iostream>
// #include <boost/algorithm/string.hpp>
// #include "log.cpp"
// #include "converter.cpp"
// #include "other.h"

namespace c2pool::messages
{
    class message;
}

namespace c2pool::p2p{
    class Factory;
}

namespace c2pool::p2p
{

    /*
     * TODO future: вынести логику Server и Client протокола в разные классы???
     */

    
    class BaseProtocol
    {
    public:
        BaseProtocol(boost::asio::io_context &_io, int _version);

        BaseProtocol(boost::asio::io_context &_io, int _version, long _max_payload_length);

        void sendPacket(c2pool::messages::message *payload2);

        ///called, when start connection
        virtual void connectionMade() = 0;

    protected:
        void disconnect();

        void dataReceived(std::string data);

        virtual void packetReceived(c2pool::messages::message *msg) = 0;

    protected:
        const int version;
        Factory *factory;
        boost::asio::ip::tcp::socket socket;
        long max_payload_length;
        boost::asio::streambuf buff;

        friend class Factory;
    };

    class Protocol : public BaseProtocol
    {
    public:
        Protocol(boost::asio::io_context& io);

        Protocol(boost::asio::io_context& io, unsigned long _max_payload_length);

        //Parse msg for handle in protocol
        c2pool::messages::message *fromStr(std::stringstream ss);

        void connectionMade() override;

        void packetReceived(c2pool::messages::message *msg) override;

        //todo: connect_timeout

        void connect_timeout(const boost::system::error_code & /*e*/);

        void _timeout(const boost::system::error_code & /*e*/);

        void send_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash);

        void handle_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash);

        void sendAdvertisement();

        void send_addrs(std::vector<c2pool::messages::addr> _addrs);

        void handle_addrs(std::vector<c2pool::messages::addr> addrs);

        void send_addrme(int port);

        void handle_addrme(int port);

        void send_ping();

        void handle_ping(long long _nonce);

        void send_getaddrs(int _count);

        void handle_getaddrs(int count);

        void setFactory(Factory *_factory)
        {
            factory = _factory;
        }

        std::string getHost()
        {
            return ""; //TODO: return ip for host [python ex: _host_to_ident(proto.host)]
        }

        boost::asio::io_context& getIOcontext(){
            return socket.get_executor().context(); //TODO
        }
    public:
        int nonce; //TODO: int64? IntType(64)

    private:
        c2pool::p2p::P2PNode *node;

        unsigned int other_version = -1;
        std::string other_sub_version;
        int other_services; //TODO: int64? IntType(64)

        bool connected2 = false;
        std::tuple<std::string, int> addr;                    //TODO
        boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.
    };


    class ClientProtocol :  {
        
    };
    
    class ServerProtocol {

    };

}

#endif //CPOOL_PROTOCOL_H
