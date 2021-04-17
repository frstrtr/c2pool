#pragma once

#include <networks/network.h>
#include <devcore/logger.h>
#include "nodeManager.h"
using c2pool::libnet::NodeManager;

#include <coind/jsonrpc/coind.h>
using namespace coind::jsonrpc;

#include <sharechains/tracker.h>
using namespace c2pool::shares::tracker;

#include <util/events.h>
using namespace c2pool::util::events;

#include <memory>
#include <thread>
using std::make_shared;
using std::shared_ptr, std::unique_ptr;

#include <boost/asio.hpp>
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
    public:
        CoindNode(shared_ptr<NodeManager> node_manager);

        void start();

        void set_best_share();
        void clean_tracker();

    public:
        std::shared_ptr<Event<>> stop;

        std::shared_ptr<Event<uint256>> new_block;    //block_hash
        std::shared_ptr<Event<UniValue>> new_tx;      //bitcoin_data.tx_type
        std::shared_ptr<Event<UniValue>> new_headers; //bitcoin_data.block_header_type

        std::shared_ptr<Variable<coind::jsonrpc::data::getwork_result>> coind_work;
    private:
        void work_poller();
    private:
        shared_ptr<Coind> _coind;
        shared_ptr<coind::ParentNetwork> _net;
        shared_ptr<NodeManager> _node_manager;

        shared_ptr<coind::p2p::CoindProtocol> protocol;
        shared_ptr<ShareTracker> _tracker; //init + move to NodeManager?

    private:
        unique_ptr<std::thread> _thread;
        io::io_context _context;
        ip::tcp::resolver _resolver;
    };
}