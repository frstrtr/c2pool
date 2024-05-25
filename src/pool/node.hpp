#pragma once

namespace c2pool
{

namespace pool
{
    
template <typename HandshakeType, typename P2PoolProtocol, typename C2PoolProtocol>
class Node
{
    using handshake_type = HandshakeType;
    using p2pool_type = P2PoolProtocol;
    using c2pool_type = C2PoolProtocol;
    
public:
    Node()
    {

    }

    // Client* make_connection
};

} // namespace pool

} // namespace c2pool
