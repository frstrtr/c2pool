#include "p2p_protocol.h"
#include "p2p_socket.h"
#include "messages.h"
using namespace coind::p2p::messages;

#include "converter.h"
#include <devcore/logger.h>

#include <univalue.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;

#include <boost/asio.hpp>

namespace coind::p2p
{
    CoindProtocol::CoindProtocol(shared_ptr<coind::p2p::P2PSocket> _sct, const c2pool::libnet::INodeMember &member) : c2pool::libnet::INodeMember(member)
    {
        LOG_TRACE << "CoindProtocol: "
                  << "start constuctor";
        _socket = _sct;

        pinger_timer = make_shared<boost::asio::steady_timer>(_socket->get().get_executor());
    }

    void CoindProtocol::pinger(int delay)
    {
        pinger_timer->expires_after(std::chrono::seconds(delay));
        pinger_timer->async_wait([this, delay](boost::system::error_code const &ec) {
            LOG_TRACE << "PINGER!";
            auto msg_ping = make_message<coind::p2p::messages::message_ping>(1234);
            _socket->write(msg_ping);
            LOG_TRACE << "status server: " << _socket->isConnected();
            pinger(delay);
        });
    }

    void CoindProtocol::get_block_header(uint256 hash)
    {
        std::vector<uint256> _have;
        auto _msg = make_message<coind::p2p::messages::message_getheaders>(1, _have, hash);
        _socket->write(_msg);
    }
}