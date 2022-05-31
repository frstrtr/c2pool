#pragma once

#include <memory>
#include <map>
#include <string>
#include <functional>

#include "socket.h"
#include "message.h"
#include "protocol_events.h"

class HandlerManager;

class Protocol : public virtual ProtocolEvents, public enable_shared_from_this<Protocol>
{
protected:
    std::shared_ptr<Socket> socket;
    std::shared_ptr<HandlerManager> handler_manager;
public:
    virtual void write(std::shared_ptr<Message> msg);
    virtual void handle(std::shared_ptr<RawMessage> raw_msg);
public:
    // Not safe, socket->message_handler = nullptr; handler_manager = nullptr; wanna for manual setup
    Protocol() {}

    Protocol(std::shared_ptr<Socket> _socket, std::shared_ptr<HandlerManager> _handler_manager);

public:
    void set_socket(std::shared_ptr<Socket> _socket);

    void set_handler_manager(std::shared_ptr<HandlerManager> _mngr);
};