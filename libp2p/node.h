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

class Client
{
    
};

class Server
{
    std::unique_ptr<Listener<BasePoolSocket>> listener;
public:
    template <typename ListenerType>
    void init()
    {
        
    }
};