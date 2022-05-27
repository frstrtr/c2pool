// Message handler for protocol
#pragma once

#include <memory>
#include <functional>

#include "message.h"
#include <libdevcore/stream.h>

class Handler
{
public:
    virtual void invoke(PackStream &stream) = 0;
};

template <typename MessageType>
class MessageHandler : Handler
{
protected:
    std::function<void(MessageType)> handlerF;

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
HandlerPtr make_handler(std::function<void(MessageType)> handlerF)
{
    auto handler = std::make_shared<MessageType>(std::move(handlerF));
    return handler;
}