// Message handler for protocol
#pragma once

#include <memory>
#include <functional>
#include <map>
#include <string>

#include "message.h"
#include "protocol.h"
#include <libdevcore/stream.h>

template <typename MessageType, typename ProtocolType>
using handler_type = std::function<void(std::shared_ptr<MessageType>, std::shared_ptr<ProtocolType>)>;


class Handler
{
public:
    virtual void invoke(PackStream &stream, std::shared_ptr<Protocol> _protocol) = 0;
};

template <typename MessageType, typename ProtocolType>
class MessageHandler : public Handler
{
protected:
    handler_type<MessageType, ProtocolType> handlerF;

    std::shared_ptr<MessageType> generate_message(PackStream &stream)
    {
        std::shared_ptr<MessageType> msg = std::make_shared<MessageType>();
        stream >> *msg;
        return msg;
    }

public:
    MessageHandler(handler_type<MessageType, ProtocolType> _handlerF) : handlerF(_handlerF) {}

    void invoke(PackStream &stream, std::shared_ptr<Protocol> _protocol) override
    {
        auto msg = generate_message(stream);
        auto protocol = std::static_pointer_cast<ProtocolType>(_protocol);
        handlerF(msg, protocol);
    }
};

typedef std::shared_ptr<Handler> HandlerPtr;

template <typename MessageType, typename ProtocolType>
HandlerPtr make_handler(handler_type<MessageType, ProtocolType> handlerF)
{
    HandlerPtr handler = std::make_shared<MessageHandler<MessageType, ProtocolType>>(std::move(handlerF));
    return handler;
}

class HandlerManager
{
private:
    std::map<std::string, HandlerPtr> handlers;

public:
    HandlerManager() {}

    HandlerManager(const HandlerManager& manager) = delete;

    template<typename MessageType, typename ProtocolType>
    void new_handler(std::string command, handler_type<MessageType, ProtocolType> handlerF)
    {
        if (!handlers.count(command))
        {
            handlers[command] = make_handler<MessageType, ProtocolType>(handlerF);
        } else
        {
            // TODO: handler for this command already exist in <handlers> map
        }
    }

    HandlerPtr operator[](std::string command)
    {
        if (handlers.count(command))
        {
            return handlers[command];
        } else
        {
            //TODO: dont exist handler for this command
            return nullptr;
        }
    }

    // operator[] for pointers
    HandlerPtr get_handler(std::string command)
    {
        return (*this)[command];
    }
};

typedef std::shared_ptr<HandlerManager> HandlerManagerPtr;