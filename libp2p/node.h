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
    // type for function socket_handle();
    typedef std::function<void(Socket*)> socket_handler_type;
    // type for function error()
    typedef std::function<void(boost::system::error_code)> error_handler_type;

    socket_handler_type socket_handler;
    error_handler_type error_handler;
public:
    Listener() = default;

	void init(socket_handler_type _socket_handler, error_handler_type _error_handler)
    {
        socket_handler = std::move(_socket_handler);
        error_handler = std::move(_error_handler);
    }

    virtual void run() = 0;
    virtual void stop() = 0;
    virtual void tick() = 0;
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
	onlyClient,
	onlyServer,
	both
};