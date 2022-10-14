#pragma once

#include <memory>

#include "stratum.h"

#include <boost/asio.hpp>

class StratumNode
{
    typedef std::tuple<std::string, unsigned short> addr_t;
    std::shared_ptr<boost::asio::io_context> _context;

    ip::tcp::acceptor acceptor;
    ip::tcp::resolver resolver;

    std::shared_ptr<Worker> _worker;

    // connected miners
    std::map<addr_t, std::shared_ptr<Stratum>> miners;
    std::map<std::string, std::shared_ptr<boost::asio::steady_timer>> bans;
public:
    StratumNode(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<Worker> worker);

    void listen();
    void ban(const addr_t& _addr);
private:
    void disconnect(const addr_t& addr);
};

