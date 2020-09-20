#ifndef CPOOL_FACTORY_H
#define CPOOL_FACTORY_H

// #include "boost/asio.hpp"
// #include <vector>
// #include <algorithm>
// #include <map>
// #include <boost/algorithm/string.hpp>
// #include <boost/exception/all.hpp> //TODO: all reason = boost::exception???

#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <string>

using boost::asio::ip::tcp;

namespace c2pool::p2p
{
    class NodesManager;
    class Protocol;
    class ClientProtocol;
    class ServerProtocol;
} 
namespace c2pool::messages
{
    class message;
}

//____________________________________________________________________
namespace c2pool::p2p
{
    class Factory
    {
    public:
        Factory(boost::asio::io_context &context, std::shared_ptr<c2pool::p2p::NodesManager> _nodes);

        void protocol_connected(std::shared_ptr<c2pool::p2p::Protocol> proto);
    public:
        boost::asio::io_context &io_context;

        std::shared_ptr<NodesManager> getNode();

    protected:
        std::shared_ptr<NodesManager> nodes;
        std::list<std::shared_ptr<Protocol>> conns; //todo: shared_ptr
    };

    class Client : public Factory
    {
    public:
        Client(boost::asio::io_context &io_context_, std::shared_ptr<c2pool::p2p::NodesManager> _nodes, int _desired_conns, int _max_attempts);

        //todo: void -> bool
        void connect(std::string ip, std::string port);

        void _think(const boost::system::error_code &error); //TODO: change name

    protected:
        std::set<std::tuple<std::string, std::string>> attempts;
        tcp::resolver resolver;
        int desired_conns, max_attempts;
        boost::asio::deadline_timer _think_timer;
    };

    class Server : public Factory
    {
    public:
        Server(boost::asio::io_context &io_context_, std::shared_ptr<c2pool::p2p::NodesManager> _nodes, const tcp::endpoint &endpoint, int _max_conns);

        void accept();

    protected:
        boost::asio::ip::tcp::acceptor acceptor_;
        int max_conns;
    };
} // namespace c2pool::p2p

// class Factory
// {
// public:

//     Factory(c2pool::p2p::P2PNode *_node);

//     virtual void start() = 0;
//     //TODO: add destructor
//     virtual Protocol *buildProtocol(std::string addrs) = 0;

//     virtual void proto_connected(Protocol *proto) = 0;

//     virtual void proto_disconnected(Protocol *proto, boost::exception &reason) = 0;

// protected:
//     bool running = false;
//     c2pool::p2p::P2PNode *node;

//     //argument host = just ip, without port
//     //return <string>: {1}+{2} from ip: {1}.{2}.{3}.{4}
//     std::string _host_to_ident(std::string host);
// };

// class Server : public Factory
// {
// public:
//     Server(c2pool::p2p::P2PNode *_node, int _max_conns);

//     Protocol *buildProtocol(std::string addrs);

//     void proto_made_connection(Protocol *proto);

//     void proto_lost_connection(Protocol *proto, boost::exception &reason);

//     void proto_connected(Protocol *proto) override;

//     void proto_disconnected(Protocol *proto, boost::exception &reason) override;

//     void start();

//     void stop();

//     int getListenPort() { return listen_port; }

// public:
//     std::map<std::string, int> connections; //Список текущих подключений.
// private:
//     int max_conns;
//     int listen_port; //TODO: type <int>?
// };

// class Client : Factory
// {
// public:
//     Client(c2pool::p2p::P2PNode *node, int _desired_conns, int _max_attempts);

//     Protocol *buildProtocol(std::string addrs);

//     void startedConnecting(auto connector);

//     void clientConnectionFailed(auto connector, boost::exception &reason); //todo: connector, reason

//     void clientConnectionLost(auto connector, boost::exception &reason); //todo: connector, reason

//     /*
//      * ???
//      * def proto_made_connection(self, proto):
//     pass
// def proto_lost_connection(self, proto, reason):
//     pass
//      */

//     void proto_connected(Protocol *proto) override;

//     void proto_disconnected(Protocol *proto, boost::exception &reason) override;

//     void start();

//     void stop();

//     /* todo:???
//      def _think(self):
//     try:
//         if len(self.conns) < self.desired_conns and len(self.attempts) < self.max_attempts and self.node.addr_store:
//             (host, port), = self.node.get_good_peers(1)

//             if self._host_to_ident(host) in self.attempts:
//                 pass
//             elif host in self.node.bans and self.node.bans[host] > time.time():
//                 pass
//             else:
//                 #print 'Trying to connect to', host, port
//                 reactor.connectTCP(host, port, self, timeout=5)
//     except:
//         log.err()

//     return random.expovariate(1/1)
//      */

// private:
//     std::vector<boost::asio::ip::tcp::endpoint> connections; //Список текущих подключений.
//     std::vector<std::string> attempts;
//     int desired_conns;
//     int max_attempts;
// };
//} // namespace c2pool::p2p

#endif //CPOOL_FACTORY_H
