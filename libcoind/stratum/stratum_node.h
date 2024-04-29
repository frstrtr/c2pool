#pragma once

#include <memory>

#include "stratum.h"
#include <libdevcore/timer.h>
#include <libdevcore/types.h>
#include <libp2p/net_errors.h>
#include <libp2p/workflow_node.h>

#include <boost/asio.hpp>

class StratumNode : public WorkflowNode
{
    typedef NetAddress addr_t;
    boost::asio::io_context* _context;

    ip::tcp::acceptor acceptor;

    Worker* _worker;

    // connected miners
    std::map<addr_t, Stratum*> miners;
    std::map<std::string, std::unique_ptr<c2pool::Timer>> bans;

protected:
    void run_node() override
    {
        boost::asio::dispatch(*_context,
            [&, PROCESS_DUPLICATE]
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
                connected();
                LOG_INFO << "...StratumNode connected!";
            }
        );
    }

    void stop_node() override
    {
        boost::asio::dispatch(*_context,
            [&, PROCESS_DUPLICATE]
            {
                LOG_INFO << "StratumNode stopping...!";
                // stop boost::asio::acceptor
                acceptor.cancel();
                acceptor.close();

                // disconnect all miners
                std::vector<addr_t> disconnect_addrs;
                for (const auto& [addr_, stratum_] : miners)
                {
                    disconnect_addrs.push_back(addr_);
                }

                for (const auto& addr_ : disconnect_addrs)
                {
                    disconnect(addr_, "stop node");
                }

                // discard all bans
                for (auto& [addr_, timer_] : bans)
                {
                    timer_->stop();
                }
                bans.clear();
            }
        );
    }
    
    void disconnect_notify() override
    {
        LOG_INFO << "...StratumNode stopped!";
    }

public:
    StratumNode(boost::asio::io_context* context, Worker* worker);
    
private:
    void listen();
    void ban(const addr_t& _addr, int sec);
    void disconnect(const addr_t& addr, std::string reason, int ban_time = 10);
    void miner_processing(ip::tcp::socket& _socket);
};