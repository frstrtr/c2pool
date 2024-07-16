#pragma once
#include <memory>

#include <pool/peer.hpp>
#include <core/message.hpp>

namespace c2pool
{

namespace pool
{
    
// class IProtocol
// {
    
// };

template <typename NodeType>
class Protocol : public virtual NodeType
{
    // static_assert(std::is_base_of_v<NodeInterface, NodeType>);

    virtual void handle_message(std::unique_ptr<RawMessage> rmsg, typename NodeType::peer_ptr peer) = 0;
};

} // namespace pool

} // namespace c2pool