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

template <typename... COMPONENTS>
class BaseSocket : public COMPONENTS...
{
public:
    typedef BaseSocket<COMPONENTS...> socket_type;
protected:
    typedef std::function<void(std::shared_ptr<RawMessage> raw_msg)> handler_type;
    handler_type handler;

    NetAddress addr;
    NetAddress addr_local;

    connection_type conn_type_; // unk, in, out
public:
    Event<> event_disconnect; // Вызывается, когда мы каким-либо образом отключаемся от пира или он от нас.

    template <typename...Args>
    explicit BaseSocket(connection_type conn_type = connection_type::unknown, Args&&...args)
        : conn_type_(conn_type), event_disconnect(make_event()), COMPONENTS(std::forward<Args>(args))...
    {
    }

    ~BaseSocket()
    {
        delete event_disconnect;
    }

    void set_handler(handler_type message_handler)
    {
        handler = std::move(message_handler);
    }

    connection_type get_type() const { return conn_type_; }

    virtual void write(std::shared_ptr<Message> msg) = 0;
    virtual void read() = 0;

    virtual bool is_connected() = 0;
    virtual void close() = 0;
    virtual void error(const std::string& err) = 0;

    // call in constructor
    virtual void init_addr() = 0;
    NetAddress get_addr()
    {
        return addr;
    }

    NetAddress get_addr_local()
    {
        return addr_local;
    }

    friend std::ostream& operator<<(std::ostream& stream, const socket_type* value)
    {
        stream << "(local addr = " << value->addr_local.to_string()
                << ", global addr = " << value->addr.to_string() << ")";
        return stream;
    }
};

typedef BaseSocket<> Socket;

struct CustomSocketDisconnect
{
    // type for function PoolNodeServer::disconnect();
    typedef std::function<void(const NetAddress& addr)> disconnect_type;

    disconnect_type disconnect;

    CustomSocketDisconnect(disconnect_type disconnect_) 
        : disconnect(std::move(disconnect_)) 
    {
    }
};

struct DebugMessages
{
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
};