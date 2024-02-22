#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>
#include <utility>

#include <libdevcore/events.h>
#include <libdevcore/types.h>

#include "message.h"
#include "socket_components.h"

enum connection_type
{
    unknown,
    incoming,
    outgoing
};

template <typename... COMPONENTS>
class BaseSocket : public SocketEvents, public COMPONENTS...
{
public:
    typedef BaseSocket<COMPONENTS...> socket_type;
protected:
    typedef std::function<void(std::shared_ptr<RawMessage> raw_msg)> msg_handler_type;
    msg_handler_type msg_handler;

    typedef std::function<void(const std::string&, NetAddress)> error_handler_type;
    error_handler_type error_handler;

    NetAddress addr;
    NetAddress addr_local;

    connection_type conn_type; // unk, in, out

public:
    template <typename...Args>
    explicit BaseSocket(connection_type conn_type_, error_handler_type error_handler_, Args&&...args)
        : conn_type(conn_type_), error_handler(error_handler_), COMPONENTS(this, std::forward<Args>(args))...
    {
    }

    ~BaseSocket()
    {
    }

    void set_handler(msg_handler_type message_handler)
    {
        msg_handler = std::move(message_handler);
    }

    void handle(std::shared_ptr<RawMessage> raw_msg)
    {
        event_handle_message->happened(raw_msg->command);
        msg_handler(raw_msg);
    }

    connection_type get_type() const { return conn_type; }

    virtual void write(std::shared_ptr<Message> msg) = 0;
    virtual void read() = 0;

    virtual bool is_connected() = 0;
    virtual void close() = 0;
    virtual void error(const std::string& err)
	{
		error_handler(err, get_addr());
	}

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