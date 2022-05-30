#include "protocol.h"

#include "handler.h"

void Protocol::write(std::shared_ptr<Message> msg)
{
    socket->write(msg);
}

void Protocol::handle(std::shared_ptr<RawMessage> raw_msg)
{
    auto handler = handler_manager->get_handler(raw_msg->command);
    if (handler)
    {
        handler->invoke(raw_msg->value, shared_from_this());
    } else
    {
        //TODO: empty handler
    }
}

Protocol::Protocol(std::shared_ptr<Socket> _socket,  HandlerManagerPtr _handler_manager) : socket(_socket),
                                                                                             handler_manager(_handler_manager)
{
    _socket->set_message_handler(std::bind(&Protocol::handle, this, std::placeholders::_1));
}

void Protocol::set_socket(std::shared_ptr<Socket> _socket)
{
    socket = _socket;
    _socket->set_message_handler(std::bind(&Protocol::handle, this, std::placeholders::_1));
}

void Protocol::set_handler_manager(std::shared_ptr<HandlerManager> _mngr)
{
    handler_manager = _mngr;
}
