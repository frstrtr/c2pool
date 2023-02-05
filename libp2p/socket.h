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

    std::tuple<std::string, std::string> addr;
    std::string last_message_sent; // last message sent by me and received by peer.
    std::string last_message_received; // last message sent by peer and received by me.
    std::map<std::string, int32_t> not_received; // messages sent by me and not yet received by peer

    void add_not_received(const std::string& key)
    {
        auto &it = not_received[key];
        it += 1;
    }

    void remove_not_received(const std::string& key)
    {
        auto &it = not_received[key];
        it -= 1;
        if (it <= 0)
            not_received.erase(key);
    }
public:
    Socket() {}

    Socket(handler_type message_handler) : handler(std::move(message_handler)) {}

    void set_message_handler(handler_type message_handler)
    {
        handler = std::move(message_handler);
    }

    virtual void write(std::shared_ptr<Message> msg) = 0;
    virtual void read() = 0;

    virtual bool isConnected() = 0;
    virtual void disconnect() = 0;

    virtual void set_addr() = 0;
    virtual std::tuple<std::string, std::string> get_addr()
    {
        return addr;
    }
};