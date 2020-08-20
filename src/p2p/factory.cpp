#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"
#include "other.h"
#include "node.h"
#include "console.h"

class Node;

//____________________________________________________________________
namespace c2pool::p2p
{
    //--------------------------Factory
    Factory::Factory(boost::asio::io_context &context, shared_ptr<c2pool::p2p::NodesManager> _nodes) : io_context(context)
    {
        nodes = _nodes;
    }

    void Factory::protocol_connected(shared_ptr<c2pool::p2p::Protocol> proto)
    {
        conns.push_back(std::move(proto));
    }

    //--------------------------Client
    Client::Client(boost::asio::io_context &io_context_, shared_ptr<c2pool::p2p::NodesManager> _nodes, int _desired_conns, int _max_attempts) : resolver(io_context_), Factory(io_context_, _nodes), _think_timer(_nodes->io_context(), boost::posix_time::seconds(0))
    {
        LOG_INFO << "ClientFactory created.";
        desired_conns = _desired_conns;
        max_attempts = _max_attempts;
        _think_timer.async_wait(boost::bind(&Client::_think, this, boost::asio::placeholders::error));
    }

    //todo: void -> bool
    void Client::connect(std::string ip, std::string port)
    {
        try
        {
            resolver.async_resolve(ip, port,
                                   [this](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                                       boost::asio::ip::tcp::socket socket(io_context);
                                       auto p = std::make_shared<ClientProtocol>(std::move(socket), this, endpoints);
                                       protocol_connected(p);
                                   });
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception Client::connect(): " << e.what() << std::endl;
        }
    }

    void Client::_think(const boost::system::error_code &error)
    {
        LOG_DEBUG << "ClientFactory _think.";
        if (!error)
        {
            //TODO: finish method
            float rand = c2pool::random::Expovariate(1);
            boost::posix_time::milliseconds interval(static_cast<int>(rand * 1000));
            LOG_DEBUG << "[Client::_think()] Expovariate: " << rand;
            _think_timer.expires_at(_think_timer.expires_at() + interval);
            _think_timer.async_wait(boost::bind(&Client::_think, this, boost::asio::placeholders::error));
        } else {
            LOG_ERROR << error;
        }
    }

    //--------------------------Server
    Server::Server(boost::asio::io_context &io_context_, shared_ptr<c2pool::p2p::NodesManager> _nodes, const tcp::endpoint &endpoint, int _max_conns)
        : acceptor_(io_context, endpoint), Factory(io_context_, _nodes)
    {
        LOG_INFO << "ServerFactory created.";
        max_conns = _max_conns;
        accept();
    }

    void Server::accept()
    {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec)
                {
                    auto p = std::make_shared<ServerProtocol>(std::move(socket), this);
                    protocol_connected(p);
                }
                accept();
            });
    }
} // namespace c2pool::p2p