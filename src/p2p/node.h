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

        void start() override
        {
            //TODO
        }

        void stop() override
        {
            //TODO:
        }
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class Node : INode
    {
        Node(){
            nonce = c2pool::random::RandomNonce();
        }

        /*
        10. _think???
        */

        c2pool::p2p::Client client;
        c2pool::p2p::Server server;

        void start() override
        {
            if (running)
            {
                std::cout << "Node already running!" << std::endl; //todo: raise
                return;
            }

            client.start();
            server.start();

            running = true;
            //todo? self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]

            //todo?: self._stop_thinking = deferral.run_repeatedly(self._think)
        }

        void stop() override
        {
            if (!running)
            {
                std::cout << "Node already stopped!" << std::endl; //todo: raise
                return;
            }

            running = false;

            client.stop();
            server.stop();
        }

        virtual void handle_shares() = 0;
        virtual void handle_share_hashes() = 0;
        virtual void handle_get_shares() = 0;
        virtual void handle_bestblock() = 0;

        void got_conn(Protocol *protocol)
        {
            if (peers.count(protocol->nonce()) != 0)
            {
                std::cout << "Already have peer!" << std::endl; //TODO: raise ValueError('already have peer')
            }
            peers.insert(std::pair<int, Protocol *>(protocol->nonce(), protocol));
        }

        void lost_conn(Protocol *protocol, boost::exception *reason)
        {
            if (peers.count(protocol->nonce()) == 0)
            {
                std::cout << "Don't have peer!" << std::endl; //TODO: raise ValueError('''don't have peer''')
                return;
            }

            if (protocol != peers.at(protocol->nonce()))
            {
                std::cout << "Wrong conn!" << std::endl; //TODO: raise ValueError('wrong conn')
                return;
            }

            delete protocol; //todo: delete for smart pointer

            //todo: print 'Lost peer %s:%i - %s' % (conn.addr[0], conn.addr[1], reason.getErrorMessage())
        }

        void got_addr()
        {
            //TODO
        }

        void get_good_peers()
        {
            //TODO
        }

        

        //TODO: connect_addrs
        //TODO: addr_store //TODO: change type; net.BOOTSTRAP_ADDRS + saved addrs
        int preffered_storage;
        std::string external_ip; //specify your own public IP address instead of asking peers to discover it, useful for running dual WAN or asymmetric routing
        std::string port;
        std::map<unsigned long long, c2pool::p2p::Protocol *> peers;
        bool advertise_ip; //don't advertise local IP address as being available for incoming connections. useful for running a dark node, along with multiple -n ADDR's and --outgoing-conns 0

        //В питоне random.randrange возвращает [0, 2^64), что входит в максимальное значение unsigned long long = 2^64-1
        //Ещё варианты типов для nonce: unsigned long double; uint_fast64_t
        unsigned long long nonce; //TODO: random[0, 2^64) for this type

    private:
        bool running = false; // true - Node running
    };

    class P2PNode : Node
    {
        //TODO: known_txs_var = BitcoindNode.known_txs_var
        //TODO: mining_txs_var = BitcoindNode.mining_txs_var
        //TODO: mining2_txs_var = BitcoindNode.mining2_txs_var
    };
} // namespace c2pool::p2p

#endif //CPOOL_NODE_H