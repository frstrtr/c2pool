#pragma once

#include <memory>
#include <map>
#include <string>
#include <functional>

#include "socket.h"
#include "message.h"
#include "protocol_events.h"
#include "handler.h"
#include <libdevcore/logger.h>

class BaseProtocol : public virtual ProtocolEvents
{
protected:
    std::shared_ptr<Socket> socket;

public:
    virtual void write(std::shared_ptr<Message> msg);
    virtual void handle(std::shared_ptr<RawMessage> raw_msg) = 0;
public:
    // Not safe, socket->message_handler = nullptr; wanna for manual setup
    BaseProtocol() = default;

    BaseProtocol (std::shared_ptr<Socket> _socket) : socket(_socket) {}

public:
    void set_socket(std::shared_ptr<Socket> _socket);
    std::shared_ptr<Socket> get_socket() { return socket; }
    auto get_addr() { return socket->get_addr(); }

    bool operator<(const BaseProtocol &rhs)
    {
        if (!socket)
        {
            // TODO: throw
        }
        if (!rhs.socket)
        {
            // TODO: throw
        }

        return socket->get_addr() < rhs.socket->get_addr();
    }
};

template <typename T>
class Protocol : public enable_shared_from_this<T>, public BaseProtocol
{
protected:
    HandlerManagerPtr<T> handler_manager;

public:
    // Not safe, socket->message_handler = nullptr; handler_manager = nullptr; wanna for manual setup
    Protocol() : BaseProtocol() {}

    Protocol (std::shared_ptr<Socket> _socket) : BaseProtocol(_socket) {}

    Protocol (std::shared_ptr<Socket> _socket, HandlerManagerPtr<T> _handler_manager): BaseProtocol(_socket),
                                                                                       handler_manager(_handler_manager)
    {
        _socket->set_message_handler(std::bind(&Protocol::handle, this, std::placeholders::_1));
    }

    virtual void handle(std::shared_ptr<RawMessage> raw_msg) override
    {
        event_handle_message.happened(); // ProtocolEvents::event_handle_message

        auto handler = handler_manager->get_handler(raw_msg->command);
        if (handler)
        {
			LOG_INFO << "Protocol call handler for " << raw_msg->command;
            handler->invoke(raw_msg->value, this->shared_from_this());
        } else
        {
            LOG_WARNING << "Handler " << raw_msg->command << " not found!";
        }
    }

public:
    void set_handler_manager(HandlerManagerPtr<T> _mngr)
    {
        handler_manager = _mngr;
    }

};