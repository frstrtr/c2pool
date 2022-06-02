#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>
#include <utility>

#include "message.h"

class Socket
{
protected:
    typedef std::function<void(std::shared_ptr<RawMessage> raw_msg)> handler_type;

    handler_type handler;

public:
    Socket() {}

    Socket(handler_type message_handler) : handler(std::move(message_handler)) {}

    void set_message_handler(handler_type message_handler)
    {
        handler = std::move(message_handler);
    }

    virtual void write(std::shared_ptr<Message>) = 0;

    virtual void read() = 0;

    virtual bool isConnected() = 0;

	virtual void connect() = 0;
    virtual void disconnect() = 0;

    virtual std::tuple<std::string, std::string> get_addr() = 0;
};