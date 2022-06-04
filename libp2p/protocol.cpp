#include "protocol.h"

#include "handler.h"

void BaseProtocol::write(std::shared_ptr<Message> msg)
{
    socket->write(msg);
}

void BaseProtocol::set_socket(std::shared_ptr<Socket> _socket)
{
    socket = _socket;
    _socket->set_message_handler(std::bind(&BaseProtocol::handle, this, std::placeholders::_1));
}