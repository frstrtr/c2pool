#pragma once

#include <memory>
#include <functional>

#include <libp2p/protocol_events.h>

#include "socket.h"
#include "protocol.h"
#include "message.h"

template <typename ProtocolType>
class Handshake : public virtual ProtocolEvents
{
protected:
    typedef ProtocolType protocol_type;

	Socket* socket;

    int bad_peer_event_id;
public:
	Handshake(auto _socket) : socket(_socket)
	{
		socket->set_message_handler(std::bind(&Handshake::handle_message, this, std::placeholders::_1));
	}

    ~Handshake() = default;

	auto get_socket() const
	{
		return socket;
	}

    auto get_addr() { return socket->get_addr(); }

	virtual void handle_message(std::shared_ptr<RawMessage> raw_msg) = 0;

    virtual void disconnect(const std::string &reason)
    {
        LOG_DEBUG_P2P << "Base Handshake disconnect called with reason: " << reason;
        socket->disconnect(reason);
		delete socket;
    }
};