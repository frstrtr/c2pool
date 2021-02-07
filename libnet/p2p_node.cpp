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
    P2PNode::P2PNode(shared_ptr<NodeManager> _mngr) : _context(1), _resolver(_context), _acceptor(_context), _manager(_mngr)
    {
        _config = _mngr->config();
    }

    void P2PNode::listen()
    {
        _acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket) {
            if (!ec)
            {
                auto _socket = std::make_shared<P2PSocket>(std::move(socket));
                
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