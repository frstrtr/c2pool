#pragma once

#include <set>
#include <tuple>
#include <map>
#include <memory>
#include <chrono>

#include <boost/asio.hpp>

#include <libdevcore/addrStore.h>
#include <libdevcore/config.h>
#include <libdevcore/types.h>
#include <libdevcore/events.h>
#include <sharechains/tracker.h>
#include <networks/network.h>
#include <libcoind/transaction.h>
namespace io = boost::asio;
namespace ip = boost::asio::ip;
using std::set, std::tuple, std::map;
using std::shared_ptr, std::unique_ptr;


namespace c2pool
{
    namespace libnet
    {
        class CoindNode;
        namespace p2p
        {
            class Protocol;
            class P2PSocket;
        }
    }
} // namespace c2pool

#define HOST_IDENT std::string

using namespace c2pool::libnet;

namespace c2pool::libnet::p2p
{
    class P2PNode : public std::enable_shared_from_this<P2PNode>
    {
    public:
        P2PNode(std::shared_ptr<io::io_context> __context, std::shared_ptr<c2pool::Network> __net, std::shared_ptr<c2pool::dev::coind_config> __config, shared_ptr<c2pool::dev::AddrStore> __addr_store, shared_ptr<c2pool::libnet::CoindNode> __coind_node, shared_ptr<ShareTracker> __tracker);
        void start();

        std::vector<addr> get_good_peers(int max_count);
        void got_addr(c2pool::libnet::addr _addr, uint64_t services, int64_t timestamp);

        std::map<unsigned long long, shared_ptr<c2pool::libnet::p2p::Protocol>>& get_peers();
        unsigned long long get_nonce();

        bool is_connected() const;

    public:
        std::vector<ShareType> handle_get_shares(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, std::tuple<std::string, std::string> peer_addr)
        {
            parents = std::min(parents, 1000/hashes.size());
            std::vector<ShareType> shares;
            for (auto share_hash : hashes)
            {
                uint64_t n = std::min(parents+1, (uint64_t)_tracker->get_height(share_hash));
                auto get_chain_func = _tracker->get_chain(share_hash, n);

                uint256 _hash;
                while(get_chain_func(_hash))
                {
                    if (std::find(stops.begin(), stops.end(), _hash) != stops.end())
                        break;
                    shares.push_back(_tracker->get(_hash));
                }
            }

            if (shares.size() > 0)
            {
                LOG_INFO << "Sending " << shares.size() << " shares to " << std::get<0>(peer_addr) << ":" << std::get<1>(peer_addr);
            }
            return shares;
        }

        void handle_shares(vector<tuple<ShareType, std::vector<coind::data::tx_type>>> shares, shared_ptr<c2pool::libnet::p2p::Protocol> peer)
        {
            //TODO: finish
        }
        void handle_bestblock(::shares::stream::BlockHeaderType_stream header);
    private:
        bool protocol_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol);
        bool protocol_listen_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol);

        void listen();
        void auto_connect();

    public:
        VariableDict<uint256, coind::data::tx_type> known_txs;
        VariableDict<uint256, coind::data::tx_type> mining_txs;
        Variable<uint256> best_share;

    private:
        shared_ptr<c2pool::Network> _net;
        shared_ptr<c2pool::dev::coind_config> _config;
        shared_ptr<io::io_context> _context; //From NodeManager;
        shared_ptr<c2pool::dev::AddrStore> _addr_store;
        shared_ptr<c2pool::libnet::CoindNode> _coind_node;
        shared_ptr<ShareTracker> _tracker;

        io::steady_timer _auto_connect_timer;
        const std::chrono::seconds auto_connect_interval{std::chrono::seconds(1)};

        //client
        ip::tcp::resolver _resolver;
        //server
        ip::tcp::acceptor _acceptor;
    public:
        shared_ptr<c2pool::dev::AddrStore> get_addr_store() { return _addr_store; }

    private:
        unsigned long long node_id; //nonce

        map<HOST_IDENT, shared_ptr<P2PSocket>> client_attempts;
        set<shared_ptr<P2PSocket>> server_attempts;
        set<shared_ptr<c2pool::libnet::p2p::Protocol>> client_connections;
        map<HOST_IDENT, int> server_connections;
        map<unsigned long long, shared_ptr<c2pool::libnet::p2p::Protocol>> peers;
    };
} // namespace c2pool::p2p