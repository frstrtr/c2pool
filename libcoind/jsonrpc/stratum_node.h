#pragma once

#include <memory>

#include "stratum.h"
#include <boost/asio.hpp>

class StratumNode
{
    typedef std::tuple<std::string, unsigned short> addr_t;
    boost::asio::io_context* _context;

    ip::tcp::acceptor acceptor;

    Worker* _worker;

    // connected miners
    std::map<addr_t, Stratum*> miners;
    std::map<std::string, std::shared_ptr<boost::asio::steady_timer>> bans;
public:
    StratumNode(boost::asio::io_context* context, Worker* worker);

    void listen();
    void ban(const addr_t& _addr);
private:
    void disconnect(const addr_t& addr);
};