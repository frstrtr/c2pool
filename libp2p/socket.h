#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>
#include <utility>

#include <libdevcore/events.h>
#include <libdevcore/types.h>

#include "message.h"

enum connection_type
{
    unknown,
    incoming,
    outgoing
};

class Socket
{
public:
    Event<std::string> bad_peer; // call disconnect from Protocol; Protocol need sub to this event
protected:
    typedef std::function<void(std::shared_ptr<RawMessage> raw_msg)> handler_type;
    handler_type handler;

    NetAddress addr;
    NetAddress addr_local;

    connection_type conn_type_; // unk, in, out
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
    explicit Socket(connection_type conn_type = connection_type::unknown) : conn_type_(conn_type), bad_peer(make_event<std::string>()) {}
    Socket(handler_type message_handler, connection_type conn_type = connection_type::unknown) : conn_type_(conn_type), bad_peer(make_event<std::string>()), handler(std::move(message_handler)){}

    ~Socket()
    {
        delete bad_peer;
    }

    void set_message_handler(handler_type message_handler)
    {
        handler = std::move(message_handler);
    }

    connection_type get_type() const { return conn_type_; }

    virtual void write(std::shared_ptr<Message> msg) = 0;
    virtual void read() = 0;

    virtual bool isConnected() = 0;
    virtual void disconnect(const std::string& reason) = 0;

    virtual void set_addr() = 0;
    virtual NetAddress get_addr()
    {
        return addr;
    }

    virtual NetAddress get_addr_local()
    {
        return addr_local;
    }

    friend std::ostream& operator<<(std::ostream& stream, const std::shared_ptr<Socket>& value)
    {
        auto [local_ip, local_port] = value->addr_local;
        auto [ip, port] = value->addr;

        stream << "(local addr = " << local_ip << ":" << local_port
        << ", global addr = " << ip << ":" << port << ")";
        return stream;
    }
};