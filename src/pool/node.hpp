#pragma once

#include <map>

#include <pool/factory.hpp>
#include <pool/peer.hpp>
#include <core/socket.hpp>

namespace c2pool
{

namespace pool
{

class NodeInterface : public Communicator, public INetwork
{
    
};

template <typename NodeType>
class IProtocol : public virtual NodeType
{
    static_assert(std::is_base_of_v<NodeInterface, NodeType>);
protected:
    virtual void handle_message() = 0;
};

// Legacy -- p2pool; Actual -- c2pool
template <typename Base, typename Legacy, typename Actual, typename PeerType>
class BaseNode : public Legacy, public Actual, public Factory
{
    static_assert(std::is_base_of_v<IProtocol<Base>, Legacy> && std::is_base_of_v<IProtocol<Base>, Actual>);

    // For implementation override:
    //  Communicator:
    //      void error(const message_error_type& err)
    //      void handle_version(std::unique_ptr<RawMessage> rmsg, const NetService& service)
    //  INetwork:
    //      void connected(std::shared_ptr<Socket> socket) = 0;
    //      void disconnect() = 0;

    std::map<NetService, PeerType*> peers;

public:
    template <typename... Args>
    BaseNode(boost::asio::io_context* ctx, Args... args) : Base(ctx, args...), Factory(ctx, this) { }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto peer = peers[service];

        if (peer->type() == PeerConnectionType::unknown)
        {
            if (rmsg->m_command != "version")
                //TODO: error, message wanna for be version 
                {}



            handle_version(std::move(rmsg), service);
        }

        IProtocol* protocol;
        switch (peer->type())
        {
        case PeerConnectionType::unknown:
            return;
        case PeerConnectionType::legacy:
            protocol = static_cast<Legacy>(this);
            break;
        case PeerConnectionType::actual:
            protocol = static_cast<Actual>(this);
            break;
        default:
            // TODO: error
            return;
        }

        protocol->handle_message(rmsg, peer);
    }
};

// #define ADD_HANDLER(name, msg_type)\
    

} // namespace pool

} // namespace c2pool
