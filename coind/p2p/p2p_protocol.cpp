#include "p2p_protocol.h"
#include "p2p_socket.h"
#include "messages.h"
using namespace c2pool::coind::p2p::messages;

#include "converter.h"
#include <devcore/logger.h>

#include <univalue.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;

namespace c2pool::coind::p2p
{
    CoindProtocol::CoindProtocol(shared_ptr<c2pool::coind::p2p::P2PSocket> _sct, std::shared_ptr<c2pool::Network> _network) :_net(_network) 
    {
        LOG_TRACE << "CoindProtocol: "
                  << "start constuctor";
        _socket = _sct;
    }
}