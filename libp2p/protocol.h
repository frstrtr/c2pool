#pragma once

#include <memory>
#include <map>
#include <string>
#include <functional>

#include "socket.h"
#include "message.h"
#include "handler.h"

class Protocol
{
protected:
    std::shared_ptr<Socket> socket;

    HandlerManager handler_manager;
public:
    virtual void write(std::shared_ptr<Message> msg)
    {
        socket->write(msg);
    }

    virtual void handle(std::shared_ptr<RawMessage> raw_msg)
    {
        auto handler = handler_manager[raw_msg->command];
        if (handler)
        {
            handler->invoke(raw_msg->value);
        } else
        {
            //TODO: empty handler
        }
    }

public:
    Protocol(std::shared_ptr<Socket> _socket, const HandlerManager _handler_manager) : socket(_socket),
                                                                                       handler_manager(_handler_manager)
    {
        _socket->set_message_handler(std::bind(&Protocol::handle, this, std::placeholders::_1));
    }
};