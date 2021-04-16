#include "coind_node.h"
#include <coind/p2p/p2p_socket.h>
#include <coind/p2p/p2p_protocol.h>

namespace c2pool::libnet
{

    CoindNode::CoindNode(shared_ptr<NodeManager> node_manager) : _context(1), _resolver(_context)
    {
        _node_manager = node_manager;
        _coind = _node_manager->coind();
        _net = _node_manager->netParent();

        new_block = std::make_shared<Event<uint256>>();
        new_tx = std::make_shared<Event<UniValue>>();
        new_headers = std::make_shared<Event<UniValue>>();
    }

    void CoindNode::start()
    {
        LOG_INFO << "... CoindNode starting..."; //TODO: log coind name
        _thread.reset(new std::thread([&]() {
            _resolver.async_resolve(_net->P2P_ADDRESS, std::to_string(_net->P2P_PORT), [this](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                ip::tcp::socket socket(_context);
                auto _socket = make_shared<coind::p2p::P2PSocket>(std::move(socket), _net);

                protocol = make_shared<coind::p2p::CoindProtocol>(_socket, _net);
                protocol->init(new_block, new_tx, new_headers);
                _socket->init(endpoints, protocol);
            });

            _context.run();
        }));
        LOG_INFO << "... CoindNode started!"; //TODO: log coind name
    }

}