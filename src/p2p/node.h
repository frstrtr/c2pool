#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include <map>
#include <set>
#include <boost/exception/all.hpp> //TODO: all reason = boost::exception???
#include <boost/asio.hpp>
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
        NodesManager(boost::asio::io_context& _io, c2pool::config::Network _networkConfig) : _io_context(_io){
            //TODO: init _net
        }

        boost::asio::io_context& io_context() const{ //todo: const?
            return _io_context;
        }

        //TODO: init in constructor
        c2pool::config::Network net() const
        {
            return _net;
        }

    private:
        boost::asio::io_context& _io_context;
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
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class Node : INode
    {
    public:
        Node(c2pool::p2p::NodesManager *_nodes, std::string _port);

        virtual void handle_shares() = 0;
        virtual void handle_share_hashes() = 0;
        virtual void handle_get_shares() = 0;
        virtual void handle_bestblock() = 0;

        void got_conn(Protocol *protocol);
        void lost_conn(Protocol *protocol, boost::exception *reason);
        void _think(); //TODO: rename method

        //TODO: void got_addr();

        //TODO: void get_good_peers();

        
        //В питоне random.randrange возвращает [0, 2^64), что входит в максимальное значение unsigned long long = 2^64-1
        //Ещё варианты типов для nonce: unsigned long double; uint_fast64_t
        unsigned long long nonce;
        std::shared_ptr<c2pool::p2p::Client> client;
        std::shared_ptr<c2pool::p2p::Server> server;
        std::string port;
        std::map<unsigned long long, c2pool::p2p::Protocol *> peers;
        boost::asio::deadline_timer _think_timer;

    private:
        //TODO: int preffered_storage;
        //TODO: connect_addrs
        //TODO: addr_store //TODO: change type; net.BOOTSTRAP_ADDRS + saved addrs
        //TODO: bool advertise_ip; //don't advertise local IP address as being available for incoming connections. useful for running a dark node, along with multiple -n ADDR's and --outgoing-conns 0
        //TODO: std::string external_ip; //specify your own public IP address instead of asking peers to discover it, useful for running dual WAN or asymmetric routing
    };

    class P2PNode : Node
    {
        //TODO: known_txs_var = BitcoindNode.known_txs_var
        //TODO: mining_txs_var = BitcoindNode.mining_txs_var
        //TODO: mining2_txs_var = BitcoindNode.mining2_txs_var
    };
} // namespace c2pool::p2p

#endif //CPOOL_NODE_H