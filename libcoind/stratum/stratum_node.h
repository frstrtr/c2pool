#pragma once

#include <memory>

#include "stratum.h"
#include <libdevcore/timer.h>
#include <libdevcore/types.h>
#include <libp2p/net_errors.h>
#include <libp2p/network_tree_node.h>

#include <boost/asio.hpp>

class StratumNode : public NetworkTreeNode
{
    typedef NetAddress addr_t;
    boost::asio::io_context* _context;

    ip::tcp::acceptor acceptor;

    Worker* _worker;

    // connected miners
    std::map<addr_t, Stratum*> miners;
    std::map<std::string, std::unique_ptr<c2pool::Timer>> bans;
public:
    StratumNode(boost::asio::io_context* context, Worker* worker);

    void run() override
    {
        LOG_INFO << "StratumNode running...";
        // init + listen boost::asio::acceptor
        ip::tcp::endpoint listen_ep(ip::tcp::v4(), 1131);

        acceptor.open(listen_ep.protocol());
        acceptor.set_option(io::socket_base::reuse_address(true));
        acceptor.bind(listen_ep);
        acceptor.listen();

        // start processing stratum connections
        listen();
    }

    void stop() override
    {
        LOG_INFO << "StratumNode stop";
        // stop boost::asio::acceptor
        acceptor.cancel();

        // disconnect all miners
        for (const auto& [addr_, stratum_] : miners)
        {
            disconnect(addr_, false);
        }

        // discard all bans
        for (auto& [addr_, timer_] : bans)
        {
            timer_->happened();
        }
    }
private:
    void listen();
    void ban(const addr_t& _addr);
    void disconnect(const addr_t& addr, bool is_ban = true);
    void miner_processing(ip::tcp::socket& _socket);
};