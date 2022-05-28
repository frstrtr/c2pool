#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>
#include <utility>

#include "message.h"

class Socket
{
protected:
    typedef std::function<void(std::shared_ptr<RawMessage> raw_msg)> handler_type;

    handler_type handler;

public:
    Socket(handler_type message_handler) : handler(std::move(message_handler)) {}

    void set_message_handler(handler_type message_handler)
    {
        handler = std::move(message_handler);
    }

    virtual void write(std::shared_ptr<Message>) = 0;

    virtual void read() = 0;

    virtual bool isConnected() = 0;

    virtual void disconnect() = 0;

    virtual std::tuple<std::string, std::string> get_addr() = 0;
};

/// Хранит и позволяет получить доступ к фундаментальному объекту сокета, вокруг которого обёрнут класс Socket.
template <typename SOCKET_TYPE>
class FundamentalSocketObject
{
public:
    typedef SOCKET_TYPE socket_type;
private:
    std::shared_ptr<Socket> socket;
    socket_type fundamental_socket;
public:
    FundamentalSocketObject(socket_type _fundamental_socket, std::shared_ptr<Socket> _socket) :
            fundamental_socket(_fundamental_socket), socket(std::move(_socket))
    {

    }

    std::shared_ptr<Socket> get_socket()
    {
        return socket;
    }

    socket_type get_fundamental_socket()
    {
        return fundamental_socket;
    }
};