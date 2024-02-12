#pragma once

#include <memory>
#include <functional>

#include <libp2p/protocol_events.h>

#include "socket.h"
#include "message.h"

template <typename SocketType>
class Handshake : public virtual ProtocolEvents
{
protected:
	typedef SocketType socket_type;
	SocketType* socket;
public:
	Event<> event_handle_message; // Вызывается, когда мы получаем любое сообщение.

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

	auto get_socket() const { return socket; }
    auto get_addr() const { return socket->get_addr(); }

	virtual void handle_message(std::shared_ptr<RawMessage> raw_msg) = 0;

    virtual void close()
    {
        socket->close();
		delete socket;
    }
};