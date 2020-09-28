#include <cstdlib>
#include <thread>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <tuple>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"
#include "other.h"
#include "node.h"
#include "console.h"

#include <boost/exception/diagnostic_information.hpp>

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

    std::shared_ptr<NodesManager> Factory::getNode()
    {
        return nodes;
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
            auto addr = std::make_tuple(ip, port);
            resolver.async_resolve(ip, port,
                                   [this, addr](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                                       attempts.insert(addr); //TODO: перенести в отдельный метод, который вызывает при подключении протоколом.
                                       boost::asio::ip::tcp::socket socket(io_context);
                                    //    try
                                    //    {
                                           //LOG_DEBUG << io_context.stopped();
                                           auto p = std::make_shared<ClientProtocol>(std::move(socket), this, endpoints); //TODO: shared and unique
                                        //    LOG_DEBUG << "TEST_RESOLVE for: " << std::get<0>(addr) << ":" << std::get<1>(addr);
                                           protocol_connected(p);
                                    //    }
                                    //    catch (const boost::exception &ex)
                                    //    {
                                    //        // error handling
                                    //        std::string info = boost::diagnostic_information(ex);
                                    //        LOG_DEBUG << info; // some logging function you have
                                    //    }
                                   });
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception Client::connect(): " << e.what() << std::endl;
        }
    }

    void Client::disconnect(std::tuple<std::string, std::string> addr)
    {
        attempts.erase(addr);
    }

    //TODO: finish method
    void Client::_think(const boost::system::error_code &error)
    {
        LOG_DEBUG << "ClientFactory _think.";
        if (!error)
        {
            if ((conns.size() < desired_conns) && (nodes->p2p_node->addr_store.len() > 0) && (attempts.size() <= max_attempts))
            {
                for (auto addr : nodes->p2p_node->get_good_peers(1))
                {
                    if (attempts.find(addr) == attempts.end())
                    {
                        connect(std::get<0>(addr), std::get<1>(addr));
                    }
                    else
                    {
                        LOG_TRACE << "Client already connected to " << std::get<0>(addr) << ":" << std::get<1>(addr) << "!";
                    }
                }
            }
            float rand = c2pool::random::Expovariate(1);
            boost::posix_time::milliseconds interval(static_cast<int>(rand * 1000));
            LOG_DEBUG << "[Client::_think()] Expovariate: " << rand;
            _think_timer.expires_at(_think_timer.expires_at() + interval);
            _think_timer.async_wait(boost::bind(&Client::_think, this, boost::asio::placeholders::error));
        }
        else
        {
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