#pragma once

namespace c2pool
{

namespace pool
{
    
class IProtocol
{
    virtual void handle_message() = 0;
};

template <typename NodeType>
class Protocol : public IProtocol, public virtual NodeType
{
    // static_assert(std::is_base_of_v<NodeInterface, NodeType>);
};

} // namespace pool

} // namespace c2pool