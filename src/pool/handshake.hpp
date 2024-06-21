#pragma once

#include <core/message.hpp>
#include <pool/protocol.hpp>


namespace c2pool
{
    
namespace pool
{

template <typename BaseProtocol, typename P2PoolProtocol, typename C2PoolProtocol>
class Handshake
{
public:
    using protocol_type = BaseProtocol;
    using p2pool_protocol = P2PoolProtocol;
    using c2pool_protocol = C2PoolProtocol;

    protocol_type* handle(std::unique_ptr<c2pool::Message> protocol)
    {

    }
};

} // namespace pool

} // namespace c2pool
