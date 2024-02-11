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
	Socket* socket;
public:
	Handshake(auto socket_) : socket(socket_)
	{
		socket->set_message_handler
		(
			[this](const std::shared_ptr<RawMessage>& raw_msg)
			{
				handle_message(raw_msg);
			}
		);
	}

    ~Handshake() = default;

	auto get_socket() const
	{
		return socket;
	}

    auto get_addr() { return socket->get_addr(); }

	virtual void handle_message(std::shared_ptr<RawMessage> raw_msg) = 0;

    virtual void close()
    {
        socket->disconnect();
		delete socket;
    }
};