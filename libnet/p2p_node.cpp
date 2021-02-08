#include "p2p_node.h"
#include "nodeManager.h"
#include "p2p_socket.h"
#include <devcore/logger.h>

#include <iostream>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = boost::asio::ip;

using namespace c2pool::libnet;

namespace c2pool::p2p
{
    P2PNode::P2PNode(shared_ptr<NodeManager> _mngr, const ip::tcp::endpoint &listen_ep) : _context(1), _resolver(_context), _acceptor(_context, listen_ep), _manager(_mngr)
    {
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
        _auto_connect_timer->async_wait([this](boost::system::error_code const &_ec){
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
} // namespace c2pool::p2p