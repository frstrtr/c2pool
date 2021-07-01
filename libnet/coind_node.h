#pragma once

#include <networks/network.h>
#include <devcore/logger.h>
#include "nodeManager.h"
#include "node_member.h"

#include <coind/jsonrpc/coind.h>
using namespace coind::jsonrpc;

#include <sharechains/tracker.h>
using namespace c2pool::shares;

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
    class CoindNode: public c2pool::libnet::INodeMember
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

        //TODO: std::shared_ptr<Variable</*TODO*/>> best_share_var;
        //TODO: std::shared_ptr<Variable</*TODO*/>> best_block_header;

        std::shared_ptr<Variable<coind::jsonrpc::data::getwork_result>> coind_work;
    private:
        void work_poller();
        void poll_header();
    private:
        shared_ptr<coind::p2p::CoindProtocol> protocol;

    private:
        unique_ptr<std::thread> _thread;
        io::io_context _context;
        ip::tcp::resolver _resolver;
    };
}