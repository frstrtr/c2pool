#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include <map>
#include <set>
#include <boost/exception/all.hpp> //TODO: all reason = boost::exception???

namespace c2pool::p2p
{
    class Server;
    class Client;
    class Protocol;
} // namespace c2pool::p2p

namespace c2pool::p2p
{

    class P2PNode;

    class Node
    {
        //node.py, Node
    public:
        P2PNode *p2p_node;
        Client *factory;
        //TODO: <type?> bitcoind;

        //TODO: self.best_share_var = variable.Variable(None)

        Node(Client *_factory /*, bitcoind, shares, known_verified_share_hashes*/);

        void start(); //TODO: coroutine

        void set_best_share();
    };

    class P2PNode
    {
        //p2p.py::Node + node.py::P2PNode
        /*,*/
        P2PNode(Node *_node, /*,best_share_hash_func*/ int _port, auto _addr_store,
                auto _connect_addrs, int des_out_cons = 10, int max_out_attempts = 30,
                int max_in_conns = 50, int pref_storage = 1000, bool _advertise_ip = true,
                auto external_ip = nullptr);

        void start();
        //TODO: @defer.inlineCallbacks ???
        void stop();

        float _think();

        void got_conn(Protocol *conn);

        void lost_conn(Protocol *conn, boost::exception& reason);

        void got_addr((host, port), services, timestamp); //TODO

        auto get_good_peers(auto max_count);
        //private:
    public:
        Node *node;
        bool running;

        c2pool::p2p::Client *client;
        c2pool::p2p::Server *server;

        //p2p.py
        int port;
        std::map<std::string, std::string> addr_store; //TODO: change type
        std::set<std::string> connect_addrs;
        int preferred_storage;
        std::map<int, Protocol*> peers; //TODO: type???
        bool advertise_ip;
    };

} // namespace c2pool::p2p

#endif //CPOOL_NODE_H
