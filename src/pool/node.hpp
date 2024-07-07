#pragma once

#include <map>

#include <pool/factory.hpp>
#include <pool/peer.hpp>
#include <core/node_interface.hpp>

namespace c2pool
{

namespace pool
{

template <typename NodeType>
class IProtocol : public virtual NodeType
{
    static_assert(std::is_base_of_v<INode, NodeType>);
protected:
    virtual void handle_message() = 0;
};

// Legacy -- p2pool; Actual -- c2pool
template <typename Base, typename Legacy, typename Actual, typename PeerType>
class BaseNode : public Legacy, public Actual, public Factory
{
    static_assert(std::is_base_of_v<IProtocol<Base>, Legacy> && std::is_base_of_v<IProtocol<Base>, Actual>);

    std::map<NetService, PeerType> peers;

public:
    template <typename... Args>
    BaseNode(boost::asio::io_context* ctx, Args... args) : Base(ctx, args...), Factory(ctx, this) { }

    void handle(std::unique_ptr<RawMessage> msg, const NetService& peer) override
    {
        
    }
};

#define ADD_HANDLER(name, msg_type)\
    

} // namespace pool

} // namespace c2pool
