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

	std::shared_ptr<Socket> socket;

    int bad_peer_event_id;
public:
	Handshake(auto _socket) : socket(_socket)
	{
		socket->set_message_handler(std::bind(&Handshake::handle_message, this, std::placeholders::_1));
        bad_peer_event_id = socket->bad_peer->subscribe([&](const std::string &reason){ disconnect(reason); });
	}

    ~Handshake()
    {
        socket->bad_peer->unsubscribe(bad_peer_event_id);
    }

	auto get_socket() const
	{
		return socket;
	}

    auto get_addr() { return socket->get_addr(); }

	virtual void handle_message(std::shared_ptr<RawMessage> raw_msg) = 0;

    virtual void disconnect(std::string reason)
    {
        LOG_DEBUG_P2P << "Base Handshake disconnect called with reason: " << reason;
        event_disconnect->happened();
        socket->disconnect();
    }
};