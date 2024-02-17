#pragma once

#include <memory>
#include <map>
#include <string>
#include <functional>
#include <utility>

#include <libdevcore/logger.h>
#include "socket.h"
#include "message.h"
#include "protocol_events.h"
#include "handler.h"

template <typename SocketType, typename... COMPONENTS>
class BaseProtocol : public NetworkHandler, public ProtocolEvents, public COMPONENTS... 
{
protected:
	typedef SocketType socket_type;

    HandlerManagerPtr handler_manager;
	SocketType* socket;

public:
    virtual void write(std::shared_ptr<Message> msg) = 0;
    
public:
    template <typenames... Args>
    explicit BaseProtocol (socket_type* socket_, HandlerManagerPtr handler_manager_, Args... args) 
        : socket(socket_), handler_manager(handler_manager_), COMPONENTS(this, std::forward<Args>(args))...
    {
        socket->set_message_handler
		(
			[this](const std::shared_ptr<RawMessage>& raw_msg)
			{
				handle_message(raw_msg);
			}
		);
    }

    ~BaseProtocol() = default;

public:
    auto get_socket() const { return socket; }
    auto get_addr() const { return socket->get_addr(); }

    void handle_message(std::shared_ptr<RawMessage> raw_msg) 
	{
        auto handler = handler_manager->get_handler(raw_msg->command);
        if (handler)
        {
            LOG_DEBUG_P2P << name << " protocol call handler for " << raw_msg->command;
            handler->invoke(raw_msg->value, (ProtocolType*)this);
        } else
        {
            LOG_WARNING << "Handler " << raw_msg->command << " not found!";
        }
        
        event_handle_message->happened();
	}

    void close()
    {
        socket->close();
		delete socket;
    }

    bool operator<(BaseProtocol* rhs)
    {
        if (!socket)
        {
            // TODO: throw
        }
        if (!rhs->socket)
        {
            // TODO: throw
        }

        return get_addr() < rhs->get_addr();
    }
};