#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <boost/system/error_code.hpp>

#include "net_errors.h"
#include "socket.h"

enum NodeRunState
{
    disable = 0,
	onlyClient = 1,
	onlyServer = 1 << 1,
	both = onlyClient | onlyServer
};

template <typename SocketType>
class Listener
{
public:
    using socket_type = SocketType;

protected:
    // type for function socket_handle();
    using socket_handler_type = std::function<void(socket_type*)>;
    // type for Server::error(...)
    using error_handler_type = std::function<void(const libp2p::error&)>;

    socket_handler_type socket_handler;
    error_handler_type error_handler;

public:
    Listener() = default;
    void init(socket_handler_type socket_handler_, error_handler_type error_handle_)
    {
        socket_handler = std::move(socket_handler_);
        error_handler = std::move(error_handle_);
    }

    virtual void run() = 0;
    virtual void stop() = 0;
protected:
    virtual void async_loop() = 0;
};

template <typename SocketType>
class Connector
{
public:
    using socket_type = SocketType;

protected:
    // type for function socket_handle();
    using socket_handler_type = std::function<void(socket_type*)>;
    // type for Server::error(...)
    using error_handler_type = std::function<void(const libp2p::error&)>;

    socket_handler_type socket_handler;
    error_handler_type error_handler;

public:
	Connector() = default;
    void init(socket_handler_type socket_handler_, error_handler_type error_handle_)
    {
        socket_handler = std::move(socket_handler_);
        error_handler = std::move(error_handle_);
    }

	virtual void try_connect(NetAddress addr_) = 0;
    virtual void run() = 0;
    virtual void stop() = 0;
};

// InterfaceType = Listener or Connector
template <typename InterfaceType>
class CommunicationType
{
protected:
    using interface_type = InterfaceType;
    using socket_type = typename InterfaceType::socket_type;

    std::unique_ptr<interface_type> interface;

public:
    CommunicationType() = default;

    template <typename ConnectorType, typename... Args>
    void init(Args&&... args)
    {
        interface = std::make_unique<interface_type>(args...);//(context, net);
        interface->init(
                // socket_handler
                [&](BasePoolSocket* socket)
                {
                    socket_handle(socket);
                },
                // error
                [&](const libp2p::error& err)
                {
                    error(err);
                }
        );
    }

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void disconnect(const NetAddress& addr) = 0;
protected:
    virtual void error(const libp2p::error&) = 0;
    virtual void socket_handle(socket_type* socket) = 0;
};

template <typename BaseSocketType>
using Server = CommunicationType<Listener<BaseSocketType>>;

template <typename BaseSocketType>
using Client = CommunicationType<Connector<BaseSocketType>>;