#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <boost/system/error_code.hpp>

#include "socket.h"

class Listener
{
protected:
    // type for function PoolNodeServer::socket_handle();
    typedef std::function<void(Socket*)> socket_handler_type;
    // type for function PoolNodeServer::disconnect();
    typedef std::function<void(const NetAddress& addr)> disconnect_type;

    socket_handler_type socket_handler;
    disconnect_type disconnect;
public:
    Listener() = default;

	void init(socket_handler_type socket_handler_, disconnect_type disconnect_)
    {
        socket_handler = std::move(socket_handler_);
        disconnect = std::move(disconnect_);
    }

    virtual void run() = 0;
    virtual void stop() = 0;
protected:
    virtual void async_loop() = 0;
};

class Connector
{
protected:
    // type for function socket_handle();
    typedef std::function<void(Socket*)> socket_handler_type;
    // type for function error()
    typedef std::function<void(NetAddress, std::string)> error_handler_type;

    socket_handler_type socket_handler;
    error_handler_type error_handler;
public:
	Connector() = default;

    void init(socket_handler_type _socket_handler, error_handler_type _error_handle)
    {
        socket_handler = std::move(_socket_handler);
        error_handler = std::move(_error_handle);
    }

	virtual void tick(NetAddress _addr) = 0;
    virtual void run() = 0;
    virtual void stop() = 0;
};

enum NodeRunState
{
    disable = 0,
	onlyClient = 1,
	onlyServer = 1 << 1,
	both = onlyClient | onlyServer
};