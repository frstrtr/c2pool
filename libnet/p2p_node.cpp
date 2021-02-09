#include "p2p_node.h"
#include "nodeManager.h"
#include "p2p_socket.h"
#include <devcore/logger.h>
#include <devcore/addrStore.h>
#include <devcore/common.h>
#include <devcore/random.h>

#include <iostream>
#include <utility>
#include <tuple>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

using namespace c2pool::libnet;

namespace c2pool::p2p
{
    P2PNode::P2PNode(shared_ptr<NodeManager> _mngr, const ip::tcp::endpoint &listen_ep) : _context(1), _resolver(_context), _acceptor(_context, listen_ep), _manager(_mngr)
    {
        node_id = c2pool::random::RandomNonce();
        _config = _mngr->config();
        _auto_connect_timer = std::make_shared<io::steady_timer>(_context);
    }

    void P2PNode::listen()
    {
        _acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket) {
            if (!ec)
            {
                auto _socket = std::make_shared<P2PSocket>(std::move(socket));
                //TODO: protocol_connected()
                //передать protocol_connected по указателю на метод
                //и вызвать его только после обработки message_versionф
                //???
            }
            else
            {
                //TODO: error log
            }
            listen();
        });
    }

    void P2PNode::auto_connect()
    {
        _auto_connect_timer->expires_after(auto_connect_interval);
        _auto_connect_timer->async_wait([this](boost::system::error_code const &_ec) {
            if (!_ec)
            {
                if ((conns.size() < _config->desired_conns) && (_manager->addr_store.len() > 0) && (attempts.size() <= _config->max_attempts))
                {
                    for (auto addr : get_good_peers(1))
                    {
                        if (attempts.find(addr) == attempts.end())
                        {
                            attempts.insert(addr); //TODO: перенести в отдельный метод, который вызывает при подключении протоколом.
                            std::string ip = std::get<0>(addr);
                            std::string port = std::get<1>(addr);
                            try
                            {
                                _resolver.async_resolve(ip, port,
                                                       [this](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                                                           boost::asio::ip::tcp::socket socket(_context);
                                                           auto _socket = std::make_shared<P2PSocket>(std::move(socket));
                                                           auto p = std::make_shared<Protocol>(std::move(_socket), _manager, endpoints); //TODO: shared and unique
                                                           protocol_connected(p);
                                                       });
                            }
                            catch (const std::exception &e)
                            {
                                std::cerr << "Exception Client::connect(): " << e.what() << std::endl;
                            }
                        }
                        else
                        {
                            // LOG_TRACE << "Client already connected to " << std::get<0>(addr) << ":" << std::get<1>(addr) << "!";
                        }
                    }
                }
            }
            else
            {
                LOG_ERROR << _ec;
            }

            auto_connect();
        });
    }

    void P2PNode::start()
    {
        std::cout << "TEST" << std::endl;
        LOG_INFO << "P2PNode started!"; //TODO: logging name thread
        _thread.reset(new std::thread([&]() {
            listen();
        }));
    }

    std::vector<ADDR> P2PNode::get_good_peers(int max_count)
    {
        float t = c2pool::time::timestamp();

        std::vector<std::pair<float, ADDR>> values;
        for (auto kv : addr_store.GetAll())
        {
            values.push_back(
                std::make_pair(
                    -log(max(3600.0, kv.second.last_seen - kv.second.first_seen)) / log(max(3600.0, t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
                    kv.first));
        }

        std::sort(values.begin(), values.end(), [](std::pair<float, ADDR> a, std::pair<float, ADDR> b) {
            return a.first < b.first;
        });

        values.resize(min((int)values.size(), max_count));
        std::vector<ADDR> result;
        for (auto v : values)
        {
            result.push_back(v.second);
        }
        return result;
    }
} // namespace c2pool::p2p