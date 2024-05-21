#pragma once
#include "messages.hpp"
#include <pool/handler.hpp>
namespace ltc
{

class Protocol : public c2pool::pool::MessageHandler<ltc::Protocol>
{
    INIT_MESSAGE_HANDLER_BEGIN

    ADD_MESSAGE_CALLBACK(ping)

    INIT_MESSAGE_HANDLER_FINISH

public:
    MESSAGE_CALLBACK(ping)
    {

    }
    
public:
    Protocol();
    ~Protocol();
};

Protocol::Protocol(/* args */)
{
}

Protocol::~Protocol()
{
}


} // namespace ltc
