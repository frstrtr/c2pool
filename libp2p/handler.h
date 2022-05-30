// Message handler for protocol
#pragma once

#include <memory>
#include <functional>
#include <map>
#include <string>

#include "message.h"
#include <libdevcore/stream.h>

class Handler
{
public:
    virtual void invoke(PackStream &stream) = 0;
};

template <typename MessageType>
class MessageHandler : public Handler
{
protected:
    std::function<void(std::shared_ptr<MessageType>)> handlerF;

    std::shared_ptr<MessageType> generate_message(PackStream &stream)
    {
        std::shared_ptr<MessageType> msg = std::make_shared<MessageType>();
        stream >> *msg;
        return msg;
    }

public:
    MessageHandler(std::function<void(std::shared_ptr<MessageType>)> _handlerF) : handlerF(_handlerF) {}

    void invoke(PackStream &stream) override
    {
        auto msg = generate_message(stream);
        handlerF(msg);
    }
};

typedef std::shared_ptr<Handler> HandlerPtr;

template <typename MessageType>
HandlerPtr make_handler(std::function<void(std::shared_ptr<MessageType>)> handlerF)
{
    HandlerPtr handler = std::make_shared<MessageHandler<MessageType>>(std::move(handlerF));
    return handler;
}

class HandlerManager
{
private:
    std::shared_ptr<std::map<std::string, HandlerPtr>> handlers;

public:
    HandlerManager()
    {
        handlers = std::make_shared<std::map<std::string, HandlerPtr>>();
    }

    HandlerManager(const HandlerManager& manager) : handlers(manager.handlers) { }

    template<typename MessageType>
    void new_handler(std::string command, std::function<void(std::shared_ptr<MessageType>)> handlerF)
    {
        if (!handlers->count(command))
        {
            (*handlers)[command] = make_handler<MessageType>(handlerF);
        } else
        {
            // TODO: handler for this command already exist in <handlers> map
        }
    }

    HandlerPtr operator[](std::string command)
    {
        if (handlers->count(command))
        {
            return (*handlers)[command];
        } else
        {
            //TODO: dont exist handler for this command
            return nullptr;
        }
    }
};