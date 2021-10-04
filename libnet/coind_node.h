#pragma once

#include <memory>
#include <thread>
#include <optional>

#include <boost/asio.hpp>

#include "node_manager.h"
#include <networks/network.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <coind/jsonrpc/coind.h>
#include <sharechains/tracker.h>
#include <util/events.h>
#include <coind/jsonrpc/results.h>

using namespace coind::jsonrpc;
using namespace c2pool::shares;
using namespace c2pool::util::events;
using namespace coind::jsonrpc::data;

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
    class CoindNode : c2pool::libnet::NodeMember
    {
    public:
        CoindNode(shared_ptr<NodeManager> node_manager);

        void start();

        void set_best_share();
        void clean_tracker();

    public:
        coind::jsonrpc::TXIDCache txidcache;
        Event<> stop;

        VariableDict<uint256, coind::data::tx_type> known_txs;
        Variable<map<uint256, coind::data::tx_type>> mining_txs;
        Variable<map<uint256, coind::data::tx_type>> mining2_txs;
        Variable<uint256> best_share;
        Variable<c2pool::libnet::addr> desired;

        shared_ptr<Event<uint256>> new_block;    //block_hash
        shared_ptr<Event<coind::data::tx_type>> new_tx;      //bitcoin_data.tx_type
        shared_ptr<Event<c2pool::shares::BlockHeaderType>> new_headers; //bitcoin_data.block_header_type

        Variable<coind::jsonrpc::data::getwork_result> coind_work;
        Variable<std::optional<c2pool::shares::BlockHeaderType>> best_block_header;

    private:
        boost::asio::deadline_timer work_poller_t;
        void work_poller();
    
        void handle_header(const BlockHeaderType& new_header);
        void poll_header();

    private:
        shared_ptr<coind::p2p::CoindProtocol> protocol;

    private:
        ip::tcp::resolver _resolver;
    };
}