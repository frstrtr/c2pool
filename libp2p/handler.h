// Message handler for protocol
#pragma once

#include <memory>
#include <functional>
#include <map>
#include <string>

#include "message.h"
#include <libdevcore/stream.h>

// От этого класса должен наследоваться любой класс, который собирается принимать сообщения.
class NetworkHandler
{
};

template <typename MessageType, typename ProtocolType>
using handler_type = std::function<void(std::shared_ptr<MessageType>, ProtocolType*)>;

class Handler
{
public:
    virtual void invoke(PackStream &stream, NetworkHandler* protocol_) = 0;
};

template <typename MessageType, typename ProtocolType>
class MessageHandler : public Handler
{
protected:
    handler_type<MessageType, ProtocolType> handler;

    std::shared_ptr<MessageType> generate_message(PackStream &stream)
    {
        LOG_DEBUG_P2P << "\tMessage data: " << stream;
        
        std::shared_ptr<MessageType> msg = std::make_shared<MessageType>();
        stream >> *msg;
        return msg;
    }

public:
    MessageHandler(handler_type<MessageType, ProtocolType> handler_) : handler(handler_) {}

    void invoke(PackStream &stream, NetworkHandler* protocol_) override
    {
        auto msg = generate_message(stream);
        handler(msg, static_cast<ProtocolType*>(protocol_));
    }
};

using HandlerPtr = std::shared_ptr<Handler>;

template <typename MessageType, typename ProtocolType>
HandlerPtr make_handler(handler_type<MessageType, ProtocolType> handler_)
{
    HandlerPtr handler = std::make_shared<MessageHandler<MessageType, ProtocolType>>(std::move(handler_));
    return handler;
}

class HandlerManager
{
private:
    std::map<std::string, HandlerPtr> handlers;

public:
    HandlerManager() = default;

    HandlerManager(const HandlerManager& manager) = delete;

    template<typename MessageType, typename ProtocolType>
    void new_handler(std::string command, handler_type<MessageType, ProtocolType> handler_)
    {
        if (!handlers.count(command))
        {
            handlers[command] = make_handler<MessageType, ProtocolType>(handler_);
        } else
        {
            // TODO: handler for this command already exist in <handlers> map
        }
    }

    HandlerPtr get_handler(std::string command)
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
};

using HandlerManagerPtr = std::shared_ptr<HandlerManager>;