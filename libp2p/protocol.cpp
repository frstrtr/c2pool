#include "protocol.h"
#include "handler.h"

void BaseProtocol::write(std::shared_ptr<Message> msg)
{
    socket->write(msg);
}

void BaseProtocol::set_socket(Socket* _socket)
{
    socket = _socket;
    _socket->set_message_handler(std::bind(&BaseProtocol::handle, this, std::placeholders::_1));
}

void BaseProtocol::disconnect(const std::string &reason)
{
    LOG_DEBUG_P2P << "BaseProtocol disconnect called!";
    socket->disconnect(reason);
    delete socket;
}