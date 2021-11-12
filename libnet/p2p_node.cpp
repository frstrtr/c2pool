#include "p2p_node.h"

#include <iostream>
#include <tuple>
#include <algorithm>

#include <boost/bind.hpp>
#include <boost/asio.hpp>

#include "p2p_socket.h"
#include "p2p_protocol.h"
#include <libdevcore/logger.h>
#include <libdevcore/addrStore.h>
#include <libdevcore/common.h>
#include <libdevcore/random.h>
#include <libdevcore/config.h>

using std::max, std::min;
namespace io = boost::asio;
namespace ip = boost::asio::ip;
using namespace c2pool::libnet;

namespace c2pool::libnet::p2p
{
    P2PNode::P2PNode(std::shared_ptr<io::io_context> __context, std::shared_ptr<c2pool::Network> __net, std::shared_ptr<c2pool::dev::coind_config> __config, shared_ptr<c2pool::dev::AddrStore> __addr_store) : _context(__context), _net(__net), _config(__config), _addr_store(__addr_store), _resolver(*_context), _acceptor(*_context), _auto_connect_timer(*_context)
    {
        node_id = c2pool::random::RandomNonce();
        ip::tcp::endpoint listen_ep(ip::tcp::v4(), _config->listenPort);

        _acceptor.open(listen_ep.protocol());
        _acceptor.set_option(io::socket_base::reuse_address(true));
        _acceptor.bind(listen_ep);
        _acceptor.listen();
    }

    void P2PNode::start()
    {
        LOG_INFO << "... P2PNode starting...";

        listen();
        auto_connect();

        LOG_INFO << "... P2PNode started!";
    }

    void P2PNode::listen()
    {
        _acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket)
                               {
                                   if (!ec)
                                   {
                                       //c2pool::libnet::p2p::protocol_handle f = protocol_connected;
                                       auto _socket = std::make_shared<P2PSocket>(std::move(socket), _net, shared_from_this());
                                       server_attempts.insert(_socket);
                                       _socket->init(boost::bind(&P2PNode::protocol_listen_connected, this, _1));
                                   }
                                   else
                                   {
                                       LOG_ERROR << "P2PNode::listen: " << ec.message();
                                   }
                                   listen();
                               });
    }

    void P2PNode::auto_connect()
    {
        _auto_connect_timer.expires_after(auto_connect_interval);
        _auto_connect_timer.async_wait([this](boost::system::error_code const &_ec)
                                        {
                                            //LOG_DEBUG << "AUTO CONNECT";
                                            if (!_ec)
                                            {
                                                if (!((client_connections.size() < _config->desired_conns) && (_addr_store->len() > 0) && (client_attempts.size() <= _config->max_attempts)))
                                                    return;
                                                for (auto addr : get_good_peers(1))
                                                {
                                                    //LOG_TRACE << "for not empty";
                                                    if (client_attempts.find(std::get<0>(addr)) == client_attempts.end())
                                                    {

                                                        std::string ip = std::get<0>(addr);
                                                        std::string port = std::get<1>(addr);
                                                        LOG_TRACE << "try to connect: " << ip << ":" << port;
                                                        try
                                                        {
                                                            _resolver.async_resolve(ip, port,
                                                                                    [this, ip, port](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints)
                                                                                    {
                                                                                        ip::tcp::socket socket(*_context);
                                                                                        auto _socket = std::make_shared<P2PSocket>(std::move(socket), _net, shared_from_this());

                                                                                        client_attempts[ip] = _socket;
                                                                                        protocol_handle handle = [this](shared_ptr<c2pool::libnet::p2p::Protocol> protocol)
                                                                                        { return protocol_connected(protocol); };
                                                                                        _socket->connector_init(std::move(handle), endpoints);
                                                                                    });
                                                        }
                                                        catch (const std::exception &e)
                                                        {
                                                            std::cerr << "Exception Client::connect(): " << e.what() << std::endl;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        //TODO: [UNCOMMENT] LOG_WARNING << "Client already connected to " << std::get<0>(addr) << ":" << std::get<1>(addr) << "!";
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                LOG_ERROR << "P2PNode::auto_connect: " << _ec.message();
                                            }

                                            auto_connect();
                                        });
    }

    std::vector<addr> P2PNode::get_good_peers(int max_count)
    {
        float t = c2pool::dev::timestamp();

        std::vector<std::pair<float, addr>> values;
        for (auto kv : _addr_store->GetAll())
        {
            values.push_back(
                std::make_pair(
                    -log(max(3600.0, kv.second.last_seen - kv.second.first_seen)) / log(max(3600.0, t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
                    kv.first));
        }

        std::sort(values.begin(), values.end(), [](std::pair<float, addr> a, std::pair<float, addr> b)
                  { return a.first < b.first; });

        values.resize(min((int)values.size(), max_count));
        std::vector<addr> result;
        for (auto v : values)
        {
            result.push_back(v.second);
        }
        return result;
    }

    unsigned long long P2PNode::get_nonce()
    {
        return node_id;
    }

    bool P2PNode::is_connected() const
    {
        return client_connections.size();
    }

    bool P2PNode::protocol_listen_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol)
    {
        //TODO:
        return false;
    }

    bool P2PNode::protocol_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol)
    {
        LOG_DEBUG << "P2PNode::protocol_connected";
        if (protocol)
        {
            client_connections.insert(protocol);
            return true;
        }
        LOG_WARNING << "P2PNode::protocol_connected - protocol = nullptr";
        return false;
    }

} // namespace c2pool::p2p