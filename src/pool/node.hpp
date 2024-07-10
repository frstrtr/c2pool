#pragma once

#include <map>

#include <pool/factory.hpp>
#include <pool/peer.hpp>
#include <pool/protocol.hpp>
#include <core/socket.hpp>
#include <core/message.hpp>

namespace c2pool
{

namespace pool
{

class NodeInterface : public ICommunicator, public INetwork
{
};

template <typename PeerData>
class BaseNode : public NodeInterface, private Factory
{
    // For implementation override:
    //  Communicator:
    //      void error(const message_error_type& err)
    //  INetwork:
    //      void connected(std::shared_ptr<Socket> socket)
    //      void disconnect()
    // BaseNode:
    //      void handle_version(std::unique_ptr<RawMessage> rmsg, const peer_t& peer)
    std::vector<std::byte> m_prefix;

public:
    using peer_t = c2pool::pool::Peer<PeerData>;

protected:
    std::map<NetService, peer_t*> peers;

public:
    BaseNode() : Factory(nullptr, this) {}
    BaseNode(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : Factory(ctx, this) {}

    const std::vector<std::byte>& get_prefix() const override { return m_prefix; }

    virtual void handle_version(std::unique_ptr<RawMessage> rmsg, peer_t* peer) = 0;
};

// Legacy -- p2pool; Actual -- c2pool
template <typename Base, typename Legacy, typename Actual>
class NodeBridge : public virtual Base, public Legacy, public Actual
{
    static_assert(std::is_base_of_v<Protocol<Base>, Legacy> && std::is_base_of_v<Protocol<Base>, Actual>);

public:
    template <typename... Args>
    NodeBridge(boost::asio::io_context* ctx, Args... args) : Base(ctx, args...){ }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto peer = Base::peers[service];

        if (peer->type() == PeerConnectionType::unknown)
        {
            if (rmsg->m_command != "version")
                //TODO: error, message wanna for be version 
                {}

            Base::handle_version(std::move(rmsg), peer);
        }

        IProtocol* protocol;
        switch (peer->type())
        {
        case PeerConnectionType::unknown:
            return;
        case PeerConnectionType::legacy:
            protocol = static_cast<Legacy*>(this);
            break;
        case PeerConnectionType::actual:
            protocol = static_cast<Actual*>(this);
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
