#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <boost/system/error_code.hpp>

#include "net_errors.h"
#include "socket.h"

enum NodeMode
{
    disable = 0,
	onlyClient = 1,
	onlyServer = 1 << 1,
	both = onlyClient | onlyServer
};

template <typename SocketType>
class BaseInterface
{
public:
    using socket_type = SocketType;

protected:
    // type for function socket_handle();
    using socket_handler_type = std::function<void(std::shared_ptr<socket_type>)>;
    // type for Server::error(...)
    using error_handler_type = std::function<void(const libp2p::error&)>;

    socket_handler_type socket_handler;
    error_handler_type error_handler;

    void error(const libp2p::errcode& errc, const std::string& reason, const NetAddress& addr)
    {
        error_handler(libp2p::error{errc, reason, addr});
    }

public:
    void init(socket_handler_type socket_handler_, error_handler_type error_handle_)
    {
        socket_handler = std::move(socket_handler_);
        error_handler = std::move(error_handle_);
    }

    virtual void run() = 0;
    virtual void stop() = 0;
};

template <typename SocketType>
class Listener : public BaseInterface<SocketType>
{
public:
    Listener() = default;
    
protected:
    virtual void async_loop() = 0;
};

template <typename SocketType>
class Connector : public BaseInterface<SocketType>
{
public:
	Connector() = default;
	virtual void try_connect(const NetAddress& addr_) = 0;
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
        interface = std::make_unique<ConnectorType>(args...);//(context, net);
        interface->init(
                // socket_handler
                [&](std::shared_ptr<BasePoolSocket> socket)
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
    virtual void socket_handle(std::shared_ptr<socket_type> socket) = 0;
};

template <typename BaseSocketType>
using Server = CommunicationType<Listener<BaseSocketType>>;

template <typename BaseSocketType>
using Client = CommunicationType<Connector<BaseSocketType>>;