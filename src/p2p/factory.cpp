#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"

class Node;

//____________________________________________________________________
namespace c2pool::p2p
{
    //--------------------------Factory
    Factory::Factory(boost::asio::io_context &context) : io_context(context)
    {
    }

    //--------------------------Client
    Client::Client(boost::asio::io_context &io_context_, int _desired_conns, int _max_attempts) : resolver(io_context_), Factory(io_context_)
    {
        desired_conns = _desired_conns;
        max_attempts = _max_attempts;
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
                                       conns.push_back(p.get());
                                   });
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception Client::connect(): " << e.what() << std::endl;
        }
    }

    //--------------------------Server
    Server::Server(boost::asio::io_context &io_context_, const tcp::endpoint &endpoint, int _max_conns)
        : acceptor_(io_context, endpoint), Factory(io_context_)
    {
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
                    conns.push_back(p.get());
                }

                accept();
            });
    }
} // namespace c2pool::p2p