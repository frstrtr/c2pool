#pragma once

#include <libp2p/protocol.h>

class P2PProtocol : public Protocol
{
public:
    P2PProtocol(std::shared_ptr<Socket> _socket, const HandlerManager _handler_manager) : Protocol(_socket, _handler_manager) {}

};