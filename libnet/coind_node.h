#pragma once

#include <memory>
#include <thread>

#include <boost/asio.hpp>

#include "node_manager.h"
#include <networks/network.h>
#include <devcore/logger.h>
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
    class CoindNode : public c2pool::libnet::NodeMember
    {
    public:
        CoindNode(shared_ptr<NodeManager> node_manager);

        void start();

        void set_best_share();
        void clean_tracker();

    public:
        Event<> stop;

        Event<uint256> new_block;    //block_hash
        Event<UniValue> new_tx;      //bitcoin_data.tx_type
        Event<UniValue> new_headers; //bitcoin_data.block_header_type

        //TODO: std::shared_ptr<Variable</*TODO*/>> best_share_var;
        //TODO: std::shared_ptr<Variable</*TODO*/>> best_block_header;

        Variable<coind::jsonrpc::data::getwork_result> coind_work;
        Variable<c2pool::shares::BlockHeaderType> best_block_header;
    private:
        void work_poller();
        void handle_header();
        void poll_header();
    private:
        shared_ptr<coind::p2p::CoindProtocol> protocol;

    private:
        unique_ptr<std::thread> _thread;
        io::io_context _context;
        ip::tcp::resolver _resolver;
    };
}