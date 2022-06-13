//
//  CoindProtocol->init(...<events>...)
//
#pragma once

#include "coind_protocol_data.h"
#include <libp2p/protocol.h>
#include <libp2p/handler.h>
#include <libp2p/protocol_events.h>

//https://en.bitcoin.it/wiki/Protocol_documentation
class CoindProtocol : public Protocol<CoindProtocol>, public CoindProtocolData, ProtocolPinger
{
public:
    CoindProtocol(std::shared_ptr<boost::asio::io_context> _context, std::shared_ptr<Socket> _socket,
                  HandlerManagerPtr<CoindProtocol> _handler_manager) : Protocol<CoindProtocol>(std::move(_socket), std::move(handler_manager)),
                                                                       ProtocolPinger(_context, 30, std::bind(&CoindProtocol::out_time_ping, this))
    {

    }

private:
    void out_time_ping()
    {
        //TODO: out of ping timer;
        socket->disconnect();
    }
};