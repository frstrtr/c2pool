#pragma once

#include <core/pack.hpp>
#include <core/pack_types.hpp>

#include <pool/message.hpp>
#include <pool/message_macro.hpp>

namespace ltc
{
    
// struct message_ping : public c2pool::pool::Message
// {
//     message_ping() : c2pool::pool::Message(std::string("ping")) {}
//     // message_ping() : c2pool::pool::Message(std::move(command)) {}
// };

BEGIN_MESSAGE(ping)
    MESSAGE_FIELDS
    (
        (IntType(64), data),
        (IntType(16), data2),
        (IntType(32), data3)
    )
END_MESSAGE()


// MAKE_MESSAGE(
//     version, 
//     (int, version),
//     (std::string, )
// )

} // namespace ltc
