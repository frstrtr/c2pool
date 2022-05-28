#pragma once

#include <memory>
#include <functional>

#include "socket.h"
#include "protocol.h"
#include "message.h"

template <typename SOCKET_TYPE, typename ENDPOINT_TYPE>
class Handshake
{
protected:
    typedef ENDPOINT_TYPE endpoint_type;
    typedef SOCKET_TYPE socket_type;

    socket_type socket;

    HandlerManager handler_manager;

    std::function<void(std::shared_ptr<Protocol>)> client_connected;
    std::function<void(std::shared_ptr<Protocol>)> server_connected;

public:
    Handshake(socket_type _socket, HandlerManager _handler_manager) : socket(_socket), handler_manager(_handler_manager)
    {
        socket->set_message_handler(std::bind(&Handshake::handle_message, this, std::placeholders::_1));
    }

    /// [Client] Try to connect
    virtual void connect(ENDPOINT_TYPE endpoint, std::function<void(std::shared_ptr<Protocol>)> handler) = 0;

    /// [Server] Try to resolve connection
    virtual void listen_connection(std::function<void(std::shared_ptr<Protocol>)> handler) = 0;

    virtual void handle_message(std::shared_ptr<RawMessage> raw_msg) = 0;

};