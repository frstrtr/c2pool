// Message handler for protocol
#pragma once

#include <memory>
#include <functional>
#include <map>
#include <string>

#include "message.h"
#include <libdevcore/stream.h>

template <typename MessageType, typename ProtocolType>
using handler_type = std::function<void(std::shared_ptr<MessageType>, ProtocolType*)>;

template <typename ProtocolType>
class Handler
{
public:
    virtual void invoke(PackStream &stream, ProtocolType* _protocol) = 0;
};

template <typename MessageType, typename ProtocolType>
class MessageHandler : public Handler<ProtocolType>
{
protected:
    handler_type<MessageType, ProtocolType> handlerF;

    std::shared_ptr<MessageType> generate_message(PackStream &stream)
    {
        std::shared_ptr<MessageType> msg = std::make_shared<MessageType>();

        LOG_DEBUG_P2P << "\tMessage data: " << stream;

        stream >> *msg;
        return msg;
    }

public:
    MessageHandler(handler_type<MessageType, ProtocolType> _handlerF) : handlerF(_handlerF) {}

    void invoke(PackStream &stream, ProtocolType* _protocol) override
    {
        auto msg = generate_message(stream);
//        auto protocol = std::static_pointer_cast<ProtocolType>(_protocol);
        handlerF(msg, _protocol);
    }
};

template <typename ProtocolType>
using HandlerPtr = std::shared_ptr<Handler<ProtocolType>>;

template <typename MessageType, typename ProtocolType>
HandlerPtr<ProtocolType> make_handler(handler_type<MessageType, ProtocolType> handlerF)
{
    HandlerPtr<ProtocolType> handler = std::make_shared<MessageHandler<MessageType, ProtocolType>>(std::move(handlerF));
    return handler;
}

template <typename ProtocolType>
class HandlerManager
{
private:
    std::map<std::string, HandlerPtr<ProtocolType>> handlers;

public:
    HandlerManager() = default;

    HandlerManager(const HandlerManager& manager) = delete;

    template<typename MessageType>
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

    HandlerPtr<ProtocolType> operator[](std::string command)
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
    HandlerPtr<ProtocolType> get_handler(std::string command)
    {
        return (*this)[command];
    }
};

template <typename ProtocolType>
using HandlerManagerPtr = std::shared_ptr<HandlerManager<ProtocolType>>;