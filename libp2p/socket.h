#pragma once

#include <memory>
#include <string>
#include <tuple>
#include <functional>

#include "message.h"

class Socket
{
protected:
    std::function<void()> handler;

public:
    Socket(std::function<void()> message_handler) : handler(message_handler) {}

    virtual void write(std::shared_ptr<Message>) = 0;

    virtual void read() = 0;

    virtual void isConnected() = 0;

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
            fundamental_socket(_fundamental_socket), socket(_socket)
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