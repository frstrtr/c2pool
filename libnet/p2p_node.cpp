#include "p2p_node.h"
#include "nodeManager.h"
#include "p2p_socket.h"
#include "p2p_protocol.h"
#include "node_member.h"

#include <devcore/logger.h>
#include <devcore/addrStore.h>
#include <devcore/common.h>
#include <devcore/random.h>

#include <iostream>
#include <utility>
#include <tuple>
#include <algorithm>
using std::max, std::min;

#include <boost/bind.hpp>
#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

using namespace c2pool::libnet;

namespace c2pool::libnet::p2p
{
    P2PNode::P2PNode(shared_ptr<NodeManager> _mngr, const ip::tcp::endpoint &listen_ep) : _context(1), _resolver(_context), _acceptor(_context, listen_ep), c2pool::libnet::INodeMember(_mngr)
    {
        node_id = c2pool::random::RandomNonce();
        
        _auto_connect_timer = std::make_shared<io::steady_timer>(_context);
    }

    void P2PNode::start()
    {
        LOG_INFO << "... P2PNode starting..."; //TODO: logging name thread
        _thread.reset(new std::thread([&]() {
            listen();
            auto_connect();

            _context.run();
        }));
        LOG_INFO << "... P2PNode started!"; //TODO: logging name thread
    }

    void P2PNode::listen()
    {
        _acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket) {
            if (!ec)
            {
                //c2pool::libnet::p2p::protocol_handle f = protocol_connected;
                auto _socket = std::make_shared<P2PSocket>(std::move(socket), _manager->net(), shared_from_this());

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
        _auto_connect_timer->expires_after(auto_connect_interval);
        _auto_connect_timer->async_wait([this](boost::system::error_code const &_ec) {
            //LOG_TRACE << "auto connect timer";
            if (!_ec)
            {
                //LOG_TRACE << "auto connect _ec false";
                //LOG_TRACE << client_connections.size() << " < " << _config->desired_conns;
                if ((client_connections.size() < _config->desired_conns) && (_manager->addr_store()->len() > 0) && (client_attempts.size() <= _config->max_attempts))
                {
                    //LOG_TRACE << "if true";
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
                                                        [this, ip, port](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                                                            ip::tcp::socket socket(_context);
                                                            auto _socket = std::make_shared<P2PSocket>(std::move(socket), _manager->net(), shared_from_this());

                                                            client_attempts[ip] = _socket;
                                                            protocol_handle handle = [this](shared_ptr<c2pool::libnet::p2p::Protocol> protocol){return protocol_connected(protocol);};
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
        for (auto kv : _manager->addr_store()->GetAll())
        {
            values.push_back(
                std::make_pair(
                    -log(max(3600.0, kv.second.last_seen - kv.second.first_seen)) / log(max(3600.0, t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
                    kv.first));
        }

        std::sort(values.begin(), values.end(), [](std::pair<float, addr> a, std::pair<float, addr> b) {
            return a.first < b.first;
        });

        values.resize(min((int)values.size(), max_count));
        std::vector<addr> result;
        for (auto v : values)
        {
            result.push_back(v.second);
        }
        return result;
    }

    bool P2PNode::protocol_listen_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol)
    {
        //TODO:
        return false;
    }

    bool P2PNode::protocol_connected(shared_ptr<c2pool::libnet::p2p::Protocol> protocol)
    {
        LOG_DEBUG << "P2PNode::protocol_connected";
        if (protocol){
            client_connections.insert(protocol);
            return true;
        }
        LOG_WARNING << "P2PNode::protocol_connected - protocol = nullptr";
        return false;
    }

} // namespace c2pool::p2p