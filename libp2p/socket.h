#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>

#include "message.h"

class Socket
{
protected:
    std::function<void()> handler;

public:
    Socket(std::function<void()> message_handler) : handler(message_handler) {}

    virtual void write(std::shared_ptr<Message>) = 0;

    virtual void read() = 0;

    virtual void isConnected() = 0;

    virtual void disconnect() = 0;

    virtual std::tuple<std::string, std::string> get_addr() = 0;
};