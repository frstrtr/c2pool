#pragma once

#include <pool/message.hpp>

namespace ltc
{
    
// struct message_ping : public c2pool::pool::Message
// {
//     message_ping() : c2pool::pool::Message(std::string("ping")) {}
//     // message_ping() : c2pool::pool::Message(std::move(command)) {}
// };

BEGIN_MESSAGE(ping)
    
END_MESSAGE()

// MAKE_MESSAGE(
//     version, 
//     (int, version),
//     (std::string, )
// )

} // namespace ltc
