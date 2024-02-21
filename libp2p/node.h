#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <boost/system/error_code.hpp>

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
protected:
    typedef SocketType socket_type;
    // type for function PoolNodeServer::socket_handle();
    typedef std::function<void(socket_type*)> socket_handler_type;

    socket_handler_type socket_handler;
public:
    Listener() = default;

	void init(socket_handler_type socket_handler_)
    {
        socket_handler = std::move(socket_handler_);
    }

    virtual void run() = 0;
    virtual void stop() = 0;
protected:
    virtual void async_loop() = 0;
};

template <typename SocketType>
class Connector
{
protected:
    typedef SocketType socket_type;
    // type for function socket_handle();
    typedef std::function<void(socket_type*)> socket_handler_type;
    // type for function error()
    typedef std::function<void(NetAddress, std::string)> error_handler_type;

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

template <typename BaseSocketType>
class Server
{
protected:
    typedef BaseSocketType socket_type;
    typedef Listener<socket_type> listener_type;
    
    std::unique_ptr<listener_type> listener;

    virtual void socket_handle(socket_type* socket) = 0;

public:
    Server() = default;

    template <typename ListenerType, typename... Args>
    void init(Args&&... args)
    {
        listener = std::make_unique<ListenerType>(args...);//(context, net, config->c2pool_port);
        listener->init(
                // socket from listener
                [&](socket_type* socket)
                {
                    socket_handle(socket);
                },
                // disconnect
                [&](const NetAddress& addr)
                {
                    disconnect(addr);
                }
        );
    }

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void disconnect(const NetAddress& addr) = 0;
};

template <typename BaseSocketType>
class Client
{
protected:
    typedef BaseSocketType socket_type;
    typedef Connector<socket_type> connector_type;

    std::unique_ptr<connector_type> connector;

    virtual void socket_handle(socket_type* socket) = 0;

public:
    Client() = default;

    template <typename ConnectorType, typename... Args>
    void init(Args&&... args)
    {
        connector = std::make_unique<ConnectorType>(args...);//(context, net);
        connector->init(
                // socket_handler
                [&](BasePoolSocket* socket)
                {
                    socket_handle(socket);
                },
                // disconnect
                [&](const NetAddress& addr)
                {
                    disconnect(addr);
                }
        );
    }

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void disconnect(const NetAddress& addr) = 0;
};