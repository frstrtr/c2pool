#pragma once

#include <memory>
#include <functional>

#include <libp2p/protocol_components.h>

#include "socket.h"
#include "message.h"

template <typename SocketType, typename... COMPONENTS>
class BaseHandshake : public ProtocolEvents, public COMPONENTS...
{
protected:
	typedef SocketType socket_type;
	socket_type* socket;

	typedef std::function<void(const std::string&, NetAddress)> error_handler_type;
    error_handler_type error_handler;

	virtual void handle_raw(std::shared_ptr<RawMessage> raw_msg) = 0;
public:
	template <typename... Args>
	BaseHandshake(socket_type* socket_, error_handler_type error_handler_, Args... args) 
		: socket(socket_), error_handler(error_handler_), COMPONENTS(this, std::forward<Args>(args))...
	{
		socket->set_handler
		(
			[this](const std::shared_ptr<RawMessage>& raw_msg)
			{
				handle_message(raw_msg);
			}
		);
	}

    ~BaseHandshake() = default;

	auto get_socket() const { return socket; }
    auto get_addr() const { return socket->get_addr(); }

	void handle_message(std::shared_ptr<RawMessage> raw_msg) 
	{
		handle_raw(raw_msg);
		event_handle_message->happened();
	}

	void error(std::string reason)
    {
        error_handler(reason, get_addr());
    }

    void close()
    {
        socket->close();
		delete socket;
    }
};