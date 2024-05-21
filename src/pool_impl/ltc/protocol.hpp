#pragma once
#include <pool/handler.hpp>

namespace ltc
{

class Protocol : public c2pool::pool::MessageHandler<ltc::Protocol>
{
    INIT_MESSAGE_HANDLER_BEGIN

    MESSAGE_CALLBACK(ping)

    INIT_MESSAGE_HANDLER_FINISH

private:
    void ping()
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
