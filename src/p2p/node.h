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
        NodesManager(boost::asio::io_context& _io) : _io_context(_io){

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
        Node(NodesManager *_nodes, std::string _port) : INode(_nodes), _think_timer(_nodes->io_context(), boost::posix_time::seconds(0))
        {
            nonce = c2pool::random::RandomNonce();
            port = _port;

            client = std::make_shared<c2pool::p2p::Client>(); // client.start()
            server = std::make_shared<c2pool::p2p::Server>(); // server.start()

            //todo? self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]

            _think_timer.async_wait(_think);
        }

        std::shared_ptr<c2pool::p2p::Client> client;
        std::shared_ptr<c2pool::p2p::Server> server;

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

        void _think(){ //TODO: rename method
            if (peers.size() > 0)
            {
                c2pool::random::RandomChoice(peers).send_getaddrs(8);
            }
            boost::posix_time::seconds interval(c2pool::random::Expovariate(1.0 / 20));
            _think_timer.expires_at(_think_timer.expires_at() + interval);
            _think_timer.async_wait(_think);
        }

        //TODO: void got_addr();

        //TODO: void get_good_peers();

        //В питоне random.randrange возвращает [0, 2^64), что входит в максимальное значение unsigned long long = 2^64-1
        //Ещё варианты типов для nonce: unsigned long double; uint_fast64_t
        unsigned long long nonce;
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