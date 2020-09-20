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
} // namespace c2pool::p2p
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

        //used for write message in protocol
        virtual void send(c2pool::messages::message *msg);

        //handle for msg from c2pool
        virtual void handle(std::stringstream ss);

        //handle for msg from p2pool
        virtual void handle(c2pool::messages::IMessage *_msg);

        unsigned long long nonce() const
        {
            return _nonce;
        }

    protected:
        //call when connection has been made.
        void connectionMade();

        void read_prefix();

        void read_command();

        void read_length();

        void read_checksum();

        void read_payload();

        virtual void disconnect();

        c2pool::messages::commands getCommand(char *cmd);

        //py: packetReceived(self, command, payload2):
        void handlePacket(c2pool::messages::IMessage *_msg);

        //GenerateMsg for msg from c2pool
        template <class MsgType>
        MsgType *GenerateMsg(std::stringstream &ss);

        //GenerateMsg for msg from p2pool
        template <class MsgType>
        MsgType *GenerateMsg(c2pool::messages::IMessage *_msg);

        virtual void handle(c2pool::messages::message_version *msg);

        virtual void handle(c2pool::messages::message_addrs *msg);

        virtual void handle(c2pool::messages::message_addrme *msg);

        virtual void handle(c2pool::messages::message_ping *msg);

        virtual void handle(c2pool::messages::message_getaddrs *msg);

        virtual void handle(c2pool::messages::message_error *msg);

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
        //host address
        std::tuple<std::string, std::string> addrHost;

        boost::asio::ip::tcp::socket socket;
        std::shared_ptr<c2pool::p2p::NodesManager> nodes;
        c2pool::p2p::Factory *factory; //todo: shared_ptr

        bool connected = false; //in p2pool -> connected2
        boost::asio::deadline_timer timeout_timer;//timeout_delayed;

        c2pool::messages::IMessage *tempMessage;

    private:
        void connect_timeout(const boost::system::error_code &error);
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

#endif //CPOOL_PROTOCOL_H
