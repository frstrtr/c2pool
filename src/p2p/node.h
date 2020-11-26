#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include "config.h"
#include "addrStore.h"
#include "events.h"

// #include <boost/exception/all.hpp> //TODO: all reason = boost::exception???
#include <boost/asio.hpp>
#include <map>
#include <set>
#include <memory>
#include <limits>
#include <algorithm>

using namespace c2pool::util::events;

namespace c2pool::p2p
{
    class Server;
    class Client;
    class Protocol;
    class P2PNode;
    class BitcoindNode;
    class AddrStore;
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class NodesManager
    {
    public:
        NodesManager(boost::asio::io_context &_io, c2pool::config::Network *_networkConfig);

        boost::asio::io_context &io_context() const
        { //todo: const?
            return _io_context;
        }

        c2pool::config::Network *net() const
        {
            return _net;
        }

    public:
        std::unique_ptr<c2pool::p2p::P2PNode> p2p_node;
        std::unique_ptr<c2pool::p2p::BitcoindNode> bitcoind_node;

    private:
        boost::asio::io_context &_io_context;
        c2pool::config::Network *_net; //config class
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    class INode
    {
    public:
        INode(std::shared_ptr<NodesManager> _nodes) : nodes(_nodes)
        {
        }

        //getter for network [config class]
        c2pool::config::Network *net() const
        {
            return nodes->net();
        }

    public:
        const std::shared_ptr<NodesManager> nodes;
    };
} // namespace c2pool::p2p

namespace c2pool::p2p
{
    //p2pool: Node.py::Node
    class BitcoindNode : INode
    {
    public:
        std::unique_ptr<c2pool::p2p::Factory> factory;
        //TODO: bitcoind
        std::shared_ptr<c2pool::shares::OkayTracker> tracker;
        std::shared_ptr<P2PNode> p2p_node;

        VariableDict</*TODO*/> known_txs_var;
        Variable</*TODO*/> mining_txs_var;
        Variable</*TODO*/> mining2_txs_var;
        Variable</*TODO*/> best_share_var;
        Variable</*TODO*/> desired_var;

    public:
        BitcoindNode(c2pool::p2p::Factory _factory, auto _bitcoind, auto shares, auto known_verified_share_hashes, std::shared_ptr<NodesManager> _nodes) : INode(_nodes)
        {
            factory = _factory;
            bitcoind = _bitcoind;
            tracker = std::make_shared<c2pool::shares::OkayTracker>(net());

            for (auto share : shares)
            {
                tracker.add(share);
            }

            for (auto share_hash : known_verified_share_hashes)
            {
                if (tracker.items.find(share_hash) != tracker.items.end())
                {
                    tracker.verified.add(tracker.items[share_hash]);
                }
            }
        }

        void set_best_share()
        {
            auto tracker_think_result = tracker.think(/*TODO: self.get_height_rel_highest, self.bitcoind_work.value['previous_block'], self.bitcoind_work.value['bits'], self.known_txs_var.value*/);
            /*TODO:
            self.best_share_var.set(best)
            self.desired_var.set(desired)
           */
            if (p2p_node != nullptr)
            {
                for (auto bad_peer_address : bad_peer_addresses)
                {
                    for (auto peer : p2p_node.peers)
                    {
                        if (peer.addr == bad_peer_address)
                        {
                            peer.badPeerHappened();
                            break;
                        }
                    }
                }
            }
        }

        void clean_tracker()
        {
            c2pool::shares::TrackerThinkResult think_result = tracker->think();

            auto best = think_result.best_hash;
            auto desired = think_result.desired;
            auto decorated_heads = think_result.decorated_heads;
            auto bad_peer_addresses = think_result.bad_peer_addresses;

            if (decorated_heads.size() > 0)
            {
                for (int i = 0; i < 1000; i++)
                {
                    bool skip_flag = false;
                    std::set<uint256> to_remove;
                    for (auto head : tracker.heads)
                    {
                        for (int h = decorated_heads.size() - 5; h < decorated_heads.size(); h++)
                        {
                            if (decorated_heads[h] == head.share_hash)
                            {
                                skip_flag = true;
                            }
                        }

                        if (tracker.items[head.share_hash].time_seen > c2pool::time::timestamp() - 300)
                        {
                            skip_flag = true;
                        }

                        if (tracker.verified.items.find(head.share_hash) == tracker.verified.items.end())
                        {
                            skip_flag = true;
                        }

                        //TODO:
                        //if max(self.tracker.items[after_tail_hash].time_seen for after_tail_hash in self.tracker.reverse.get(tail)) > time.time() - 120: # XXX stupid
                        //  continue

                        if (!skip_flag)
                        {
                            to_remove.insert(head.share_hash);
                        }
                    }
                    if (to_remove.size() == 0)
                    {
                        break;
                    }
                    for (auto share_hash : to_remove)
                    {
                        if (tracker.verified.items.find(share_hash) != tracker.verified.items.end())
                        {
                            tracker.verified.items.erase(share_hash);
                        }
                        tracker.remove(share_hash);
                    }
                }
            }

            for (int i = 0; i < 1000; i++)
            {
                bool skip_flag = false;
                std::set<uint256, set<uint256>> to_remove;

                for (auto tail : tracker.tails)
                {
                    int min_height = INT_MAX;
                    for (auto head : tail.heads)
                    {
                        min_height = std::min(min_height, tracker.get_heigth(head));
                        if (min_height < 2 * tracker->net->CHAIN_LENGTH + 10)
                        {
                            continue
                        }
                        to_remove.insert(tracker.reverse.get(head.tail, set<uint256>()));
                    }
                }

                if (to_remove.size() == 0)
                {
                    break;
                }

                //# if removed from this, it must be removed from verified
                for (auto aftertail : to_remove)
                {
                    if (tracker.tails.find(tracker.items[aftertail].previous_hash) == tracker.tails.end())
                    {
                        continue;
                    }
                    if (tracker.verified.items.find(aftertail) != tracker.verified.items.end())
                    {
                        tracker.verified.remove(aftertail);
                    }
                    tracker.remove(aftertail);
                }
                set_best_share();
            }
        }

        //TODO: BitcoindFactory + BitcoindClientProtocol
        //TODO: bitcoind
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
    //p2pool: p2p.py::Node
    class Node : public INode
    {
    public:
        Node(std::shared_ptr<c2pool::p2p::NodesManager> _nodes, std::string _port, c2pool::p2p::AddrStore _addr_store);

        virtual void handle_shares(auto shares, c2pool::p2p::Protocol peer){/*TODO*/};
        virtual void handle_share_hashes(std::vector<uint256> hashes, c2pool::p2p::Protocol peer){/*TODO*/};
        virtual void handle_get_shares(){/*TODO*/};
        virtual void handle_bestblock(){/*TODO*/};

        void got_conn(std::shared_ptr<Protocol> protocol);
        void lost_conn(std::shared_ptr<Protocol> protocol, boost::exception *reason);
        void _think(const boost::system::error_code &error); //TODO: rename method

        //TODO: void got_addr();
        //TODO: void get_good_peers();

        //В питоне random.randrange возвращает [0, 2^64), что входит в максимальное значение unsigned long long = 2^64-1
        //Ещё варианты типов для nonce: unsigned long double; uint_fast64_t
        unsigned long long nonce;
        std::unique_ptr<c2pool::p2p::Client> client;
        std::unique_ptr<c2pool::p2p::Server> server;
        std::string port;
        std::map<unsigned long long, std::shared_ptr<c2pool::p2p::Protocol>> peers;
        boost::asio::deadline_timer _think_timer;
        std::vector<ADDR> get_good_peers(int max_count);

    public:
        //TODO: int preffered_storage;
        //TODO: connect_addrs
        c2pool::p2p::AddrStore addr_store; //TODO: const
        //TODO: bool advertise_ip; //don't advertise local IP address as being available for incoming connections. useful for running a dark node, along with multiple -n ADDR's and --outgoing-conns 0
        //TODO: std::string external_ip; //specify your own public IP address instead of asking peers to discover it, useful for running dual WAN or asymmetric routing
    };

    //p2pool: node.py::P2PNode
    class P2PNode : public Node
    {
    public:
        P2PNode(std::shared_ptr<c2pool::p2p::NodesManager> _nodes, std::string _port, c2pool::p2p::AddrStore _addr_store);

        void handle_shares(auto shares, c2pool::p2p::Protocol peer){
            //TODO:
        }

        virtual void handle_shares(){/*TODO*/};
        virtual void handle_share_hashes(){/*TODO*/};
        virtual void handle_get_shares(){/*TODO*/};
        virtual void handle_bestblock(){/*TODO*/};


        //TODO: known_txs_var = BitcoindNode.known_txs_var
        //TODO: mining_txs_var = BitcoindNode.mining_txs_var
        //TODO: mining2_txs_var = BitcoindNode.mining2_txs_var
    };
} // namespace c2pool::p2p

#endif //CPOOL_NODE_H