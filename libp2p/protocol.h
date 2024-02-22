#pragma once

#include <memory>
#include <map>
#include <string>
#include <functional>
#include <utility>

#include <libdevcore/logger.h>
#include "socket.h"
#include "message.h"
#include "protocol_components.h"
#include "handler.h"

template <typename SocketType, typename... COMPONENTS>
class BaseProtocol : public NetworkHandler, public ProtocolEvents, public COMPONENTS... 
{
protected:
	typedef SocketType socket_type;
    socket_type* socket;

    typedef std::function<void(const std::string&, NetAddress)> error_handler_type;
    error_handler_type error_handler;
    
    HandlerManagerPtr handler_manager;
    
public:
    virtual void write(std::shared_ptr<Message> msg) = 0;

public:
    template <typename... Args>
    explicit BaseProtocol (socket_type* socket_, HandlerManagerPtr handler_manager_, error_handler_type error_handler_, Args&&...args)
        : socket(socket_), handler_manager(handler_manager_), error_handler(error_handler_),
            COMPONENTS(this, std::forward<Args>(args))...
    {
        socket->set_handler
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
            LOG_DEBUG_P2P << "Protocol call handler for " << raw_msg->command;
            handler->invoke(raw_msg->value, this);
        } else
        {
            LOG_WARNING << "Handler " << raw_msg->command << " not found!";
        }
        
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