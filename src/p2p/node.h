#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include <map>
#include <set>
#include <boost/exception/all.hpp> //TODO: all reason = boost::exception???
#include <memory>
#include "config.h"

namespace c2pool::p2p
{
    class Server;
    class Client;
    class Protocol;
    class P2PNode;
    class BitcoindNode;
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class NodesManager
    {
    public:
        //TODO: init in constructor
        c2pool::config::Network net() const
        {
            return _net;
        }

    private:
        c2pool::config::Network _net; //config class
        std::unique_ptr<c2pool::p2p::P2PNode> p2p_node;
        std::unique_ptr<c2pool::p2p::BitcoindNode> bitcoind_node;
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class INode
    {
    public:
        INode(NodesManager *_nodes) : nodes(_nodes)
        {
        }

        //getter for network [config class]
        c2pool::config::Network net() const
        {
            return nodes->net();
        }

    public:
        const NodesManager *nodes;

        virtual void start() = 0;
        
        virtual void stop() = 0;
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class BitcoindNode : INode
    {
        //TODO: BitcoindFactory + BitcoindClientProtocol
        //TODO: bitcoind
        //TODO: Tracker + clean_tracker()
        //TODO: set_best_share()
        //TODO: get_current_txouts


        //--------------------------------
        //TODO: known_txs_var
        //TODO: mining_txs_var
        //TODO: mining2_txs_var
        //TODO: best_share_var //CAN BE NULL IN message_version
        //TODO: desired_var
        //TODO: txidcache
        //--------------------------------

        void start() override{
            //TODO
        }

        void stop() override {
            //TODO:
        }

    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class Node : INode
    {
        c2pool::p2p::Client client;
        c2pool::p2p::Server server;

        void start() override{
            //TODO
        }

        void stop() override {
            //TODO:
        }

        virtual void handle_shares() = 0;
        virtual void handle_share_hashes() = 0;
        virtual void handle_get_shares() = 0;
        virtual void handle_bestblock() = 0;

        void got_conn(){
            //TODO
        }

        void lost_conn(){
            //TODO
        }

        void got_addr(){
            //TODO
        }

        void get_good_peers(){
            //TODO
        }


        /*
        7. nonce
        ______________

        2. addr_store
        3. connect_addrs
        4. preffered_storage
        8. peers
        10. _think???
        */


       std::string external_ip; //specify your own public IP address instead of asking peers to discover it, useful for running dual WAN or asymmetric routing
       std::string port;
       bool advertise_ip; //don't advertise local IP address as being available for incoming connections. useful for running a dark node, along with multiple -n ADDR's and --outgoing-conns 0

       //TODO: unsigned long long/unsigned long double/uint_fast64_t nonce; //TODO: random[0, 2^64) for this type
       //В питоне random.randrange возвращает [0, 2^64), что входит в максимальное значение unsigned long long = 2^64-1
    };

    class P2PNode : Node
    {
        //TODO: known_txs_var = BitcoindNode.known_txs_var
        //TODO: mining_txs_var = BitcoindNode.mining_txs_var
        //TODO: mining2_txs_var = BitcoindNode.mining2_txs_var

    };
} // namespace c2pool::p2p

// namespace c2pool::p2p
// {
//     class Node
//     {
//         //node.py, Node
//     public:
//         P2PNode *p2p_node;
//         Client *factory;
//         //TODO: <type?> bitcoind;

//         //TODO: self.best_share_var = variable.Variable(None)

//         Node(Client *_factory /*, bitcoind, shares, known_verified_share_hashes*/);

//         void start(); //TODO: coroutine

//         void set_best_share();
//     };

//     class P2PNode
//     {
//         //p2p.py::Node + node.py::P2PNode
//         P2PNode(Node *_node, /*,best_share_hash_func*/ int _port, auto _addr_store,
//                 auto _connect_addrs, int des_out_cons = 10, int max_out_attempts = 30,
//                 int max_in_conns = 50, int pref_storage = 1000, bool _advertise_ip = true,
//                 auto external_ip = nullptr);

//         void start();
//         //TODO: @defer.inlineCallbacks ???
//         void stop();

//         float _think();

//         void got_conn(Protocol *conn);

//         void lost_conn(Protocol *conn, boost::exception& reason);

//         void got_addr((host, port), services, timestamp); //TODO

//         auto get_good_peers(auto max_count);
//         //private:
//     public:
//         Node *node;
//         bool running;

//         c2pool::p2p::Client *client;
//         c2pool::p2p::Server *server;

//         //p2p.py
//         int port;
//         std::map<std::string, std::string> addr_store; //TODO: change type
//         std::set<std::string> connect_addrs;
//         int preferred_storage;
//         std::map<int, Protocol*> peers; //TODO: type???
//         bool advertise_ip;
//     };

// } // namespace c2pool::p2p

#endif //CPOOL_NODE_H