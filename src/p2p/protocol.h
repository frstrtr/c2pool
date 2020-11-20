#ifndef CPOOL_PROTOCOL_H
#define CPOOL_PROTOCOL_H

#include "boost/asio.hpp"
#include "types.h"

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
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include "messages.h"
//#include "node.h"
using boost::asio::ip::tcp;

//-----------------------------------------------------------

namespace c2pool::p2p
{
    class Node;
    class NodesManager;
    class Factory;
}
namespace c2pool::messages
{
    class message;
}
//-----------------------------------------------------------
namespace c2pool::p2p
{
    class Protocol : public std::enable_shared_from_this<Protocol>
    {
    public:
        Protocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory);

        virtual void send(c2pool::messages::message *msg);

        //OLD: fromStr
        virtual void handle(UniValue &value);

        unsigned long long nonce() const{
            return _nonce;
        }

    protected:
        //used for write message in protocol
        //virtual void write(unique_ptr<c2pool::messages::message> msg);

        void read_prefix();

        void read_command();

        void read_length();

        void read_checksum();

        void read_payload();
        
        //py: dataReceived(self, data)
        //virtual void handlePacket() = 0;
        //virtual void sendPacket(c2pool::messages::message *payload) = 0;
        //virtual void connectionMade() = 0;
        virtual void disconnect();

        template <class MsgType>
        MsgType *GenerateMsg(UniValue &value);

        virtual void handle(c2pool::messages::message_version *msg);

        virtual void handle(c2pool::messages::message_addrs *msg);

        virtual void handle(c2pool::messages::message_addrme *msg);

        virtual void handle(c2pool::messages::message_ping *msg);

        virtual void handle(c2pool::messages::message_getaddrs *msg);

        virtual void handle(c2pool::messages::message_error *msg);

        virtual void handle(c2pool::messages::message_shares *msg);

        virtual void handle(c2pool::messages::message_sharereq *msg);

        virtual void handle(c2pool::messages::message_sharereply *msg);

        //TODO: virtual void handle(c2pool::messages::message_best_block *msg);

        virtual void handle(c2pool::messages::message_have_tx *msg);

        virtual void handle(c2pool::messages::message_losing_tx *msg);

        
        void update_addr();
        //TODO: Friend class: Message for handle_<command>
    protected:
        const int version;

        unsigned int other_version = -1;
        std::string other_sub_version;
        int other_services; //TODO: int64? IntType(64)
        unsigned long long _nonce;

        //peer address
        std::tuple<std::string, std::string> addr;

        boost::asio::ip::tcp::socket socket;
        std::shared_ptr<c2pool::p2p::NodesManager> nodes;
        c2pool::p2p::Factory *factory; //todo: shared_ptr

        std::unique_ptr<c2pool::messages::IMessage> tempMessage; 
    };

    class ClientProtocol : public Protocol
    {
    public:
        ClientProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory, const boost::asio::ip::tcp::resolver::results_type endpoints);

        void do_connect(const boost::asio::ip::tcp::resolver::results_type endpoint);
    };

    class ServerProtocol : public Protocol
    {
    public:
        ServerProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory);

        void start();
    };
} // namespace c2pool::p2p
//________________________________OLD___________________________________
// class BaseProtocol
// {
// public:
//     BaseProtocol(boost::asio::io_context &_io, int _version);

//     BaseProtocol(boost::asio::io_context &_io, int _version, long _max_payload_length);

//     void sendPacket(c2pool::messages::message *payload2);

//     ///called, when start connection
//     virtual void connectionMade() = 0;

// protected:
//     void disconnect();

//     void dataReceived(std::string data);

//     virtual void packetReceived(c2pool::messages::message *msg) = 0;

// protected:
//     const int version;
//     Factory *factory;
//     boost::asio::ip::tcp::socket socket;
//     long max_payload_length;
//     boost::asio::streambuf buff;

//     friend class Factory;
// };

// class Protocol : public BaseProtocol
// {
// public:
//     Protocol(boost::asio::io_context& io);

//     Protocol(boost::asio::io_context& io, unsigned long _max_payload_length);

//     //Parse msg for handle in protocol
//     c2pool::messages::message *fromStr(std::stringstream ss);

//     void connectionMade() override;

//     void packetReceived(c2pool::messages::message *msg) override;

//     //todo: connect_timeout

//     void connect_timeout(const boost::system::error_code & /*e*/);

//     void _timeout(const boost::system::error_code & /*e*/);

//     void sendAdvertisement();

//     void setFactory(Factory *_factory)
//     {
//         factory = _factory;
//     }

//     std::string getHost()
//     {
//         return ""; //TODO: return ip for host [python ex: _host_to_ident(proto.host)]
//     }

//     boost::asio::io_context& getIOcontext(){
//         return socket.get_executor().context(); //TODO
//     }
// public:
//     int nonce; //TODO: int64? IntType(64)

// protected:
//     c2pool::p2p::P2PNode *node;

//     unsigned int other_version = -1;
//     std::string other_sub_version;
//     int other_services; //TODO: int64? IntType(64)

//     bool connected2 = false;
//     std::tuple<std::string, int> addr;                    //TODO
//     boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.
// };

// class ClientProtocol : public Protocol{
//     void send_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash);

//     void send_addrs(std::vector<c2pool::messages::addr> _addrs);

//     void send_addrme(int port);

//     void send_ping();

//     void send_getaddrs(int _count);

// };

// class ServerProtocol : public Protocol {
//     void handle_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash);

//     void handle_addrs(std::vector<c2pool::messages::addr> addrs);

//     void handle_addrme(int port);

//     void handle_ping(long long _nonce);

//     void handle_getaddrs(int count);
// };

#endif //CPOOL_PROTOCOL_H
