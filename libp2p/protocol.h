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

    std::map<std::string, HandlerPtr> handlers;
public:
    Protocol(std::shared_ptr<Socket> _socket) : socket(_socket)
    {}

    template<typename MessageType>
    void new_handler(std::string command, std::function<void(std::shared_ptr<MessageType>)> handlerF)
    {
        if (!handlers.count(command))
        {
            handlers[command] = make_handler<MessageType>(handlerF);
        } else
        {
            // TODO: handler for this command already exist in <handlers> map
        }
    }

public:
    virtual void write(std::shared_ptr<Message> msg)
    {
        socket->write(msg);
    }

    virtual void handle(std::shared_ptr<RawMessage> raw_msg)
    {
        if (!handlers.count(raw_msg->command))
        {
            // call handler for raw_msg.command
            handlers[raw_msg->command]->invoke(raw_msg->value);
        } else
        {
            //TODO: dont exist handler for this command
        }
    }
};