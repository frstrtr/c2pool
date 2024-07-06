#pragma once

#include <core/node_interface.hpp>

namespace c2pool
{

namespace pool
{

// template <typename HandshakeType, typename P2PoolProtocol, typename C2PoolProtocol>
// Legacy -- p2pool; Actual -- c2pool.
// template <typename ILegacyProtocol, typename IActualProtocol>
// class Node : public INode, ILegacyProtocol, IActualProtocol
// {
//     // using handshake_type = HandshakeType;
//     // using p2pool_type = P2PoolProtocol;
//     // using c2pool_type = C2PoolProtocol;

// public:
//     Node()
//     {
        
//     }

//     // Client* make_connection
// };
template <typename NodeType>
class IProtocol : public virtual NodeType
{
protected:
    virtual void handle_message() = 0;
};

// Legacy -- p2pool; Actual -- c2pool
template <typename Base, typename Legacy, typename Actual>
class BaseNode : public Legacy, public Actual
{
    static_assert(std::is_base_of_v<IProtocol<Base>, Legacy> && std::is_base_of_v<IProtocol<Base>, Actual>);

public:
    template <typename... Args>
    BaseNode(Args... args) : Base(args...) { }
}



} // namespace pool

} // namespace c2pool
