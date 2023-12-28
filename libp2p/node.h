#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "socket.h"

class Listener
{
protected:
    // type for function socket_handle();
    typedef std::function<void(std::shared_ptr<Socket>)> socket_handler_type;
    // type for function finish()
    typedef std::function<void()> finish_handler_type;
    // type for function error()
    typedef std::function<void(NetAddress, std::string)> error_handler_type;

    socket_handler_type socket_handler;
    error_handler_type error_handler;
    finish_handler_type finish_handler;
public:
    Listener() = default;

	void init(socket_handler_type _socket_handler, error_handler_type _error_handler, finish_handler_type _finish_handler)
    {
        socket_handler = std::move(_socket_handler);
        error_handler = std::move(_error_handler);
        finish_handler = std::move(_finish_handler);
    }

	virtual void tick() = 0;
};

class Connector
{
protected:
    // type for function socket_handle();
    typedef std::function<void(std::shared_ptr<Socket>)> socket_handler_type;
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
};

enum NodeRunState
{
	onlyClient,
	onlyServer,
	both
};