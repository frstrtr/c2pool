#pragma once

#include <memory>
#include <thread>
#include <optional>

#include <boost/asio.hpp>

#include <networks/network.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <sharechains/tracker.h>
#include <sharechains/share_types.h>
#include <libdevcore/events.h>
#include <libcoind/jsonrpc/results.h>
#include <libcoind/jsonrpc/txidcache.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libcoind/height_tracker.h>


using namespace coind::jsonrpc;
using namespace c2pool::shares;
using namespace coind;

using std::make_shared;
using std::shared_ptr, std::unique_ptr;

namespace io = boost::asio;
namespace ip = boost::asio::ip;

namespace coind::p2p
{
    class CoindProtocol;
}

namespace c2pool::libnet
{
    class CoindNode
    {
    private:
        std::shared_ptr<io::io_context> _context; //From NodeManager
        ip::tcp::resolver _resolver;

    public:
        CoindNode(std::shared_ptr<io::io_context> __context, shared_ptr<coind::ParentNetwork> __parent_net, shared_ptr<coind::JSONRPC_Coind> __coind, shared_ptr<ShareTracker> __tracker);

        void start();

        shared_ptr<ShareTracker> tracker();
        void set_best_share();
        void clean_tracker();

    public:
        coind::TXIDCache txidcache;
        Event<> stop;

        VariableDict<uint256, coind::data::tx_type> known_txs;
        VariableDict<uint256, coind::data::tx_type> mining_txs;
        VariableDict<uint256, coind::data::tx_type> mining2_txs;
        Variable<uint256> best_share;
        Variable<c2pool::libnet::addr> desired;

        Event<uint256> new_block;                           //block_hash
        Event<coind::data::tx_type> new_tx;                 //bitcoin_data.tx_type
        Event<::shares::BlockHeaderType> new_headers; //bitcoin_data.block_header_type

        Variable<coind::getwork_result> coind_work;
        Variable<std::optional<::shares::BlockHeaderType>> best_block_header;
        HeightTracker get_height_rel_highest;

    private:
        boost::asio::deadline_timer work_poller_t;
        void work_poller();
        void poll_header();
    public:
        void handle_header(const ::shares::BlockHeaderType &new_header);
    private:
        shared_ptr<coind::ParentNetwork> _parent_net;
        shared_ptr<coind::p2p::CoindProtocol> protocol;
        shared_ptr<coind::JSONRPC_Coind> _coind;
        shared_ptr<ShareTracker> _tracker;
    };
}