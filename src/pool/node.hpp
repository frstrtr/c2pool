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
class BaseNode : public NodeInterface, public Factory
{
    // For implementation override:
    //  INetwork:
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
    BaseNode(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : Factory(ctx, this), m_prefix(prefix) {}

    const std::vector<std::byte>& get_prefix() const override { return m_prefix; }
    void connected(std::shared_ptr<c2pool::Socket> socket) override { peers[socket->get_addr()] = new peer_t(socket); }

    void error(const message_error_type& err, const NetService& service)
    {
        std::cout << "Error in node [" << service.to_string() << "]: " << err << std::endl;
        if (peers.contains(service))
        {
            auto peer = peers.extract(service);
            delete peer.mapped();
        }
        else
        {
            std::cout << "\tpeers not exist " << service.to_string() << std::endl;
        }
    }

    void error(const message_error_type& err, const boost::system::error_code& ec, const NetService& service)
    {
        std::string error_message = err;
        std::cout << "\t" << ec.value() << std::endl;
        switch (ec.value())
        {
            
        }

        error(error_message, service);
    }

    virtual PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_t* peer) = 0;
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

            auto peer_type = Base::handle_version(std::move(rmsg), peer);
            peer->set_type(peer_type);
            return;
        }

        switch (peer->type())
        {
        case PeerConnectionType::legacy:
            static_cast<Legacy*>(this)->handle_message(std::move(rmsg), peer);
            break;
        case PeerConnectionType::actual:
            static_cast<Actual*>(this)->handle_message(std::move(rmsg), peer);
            break;
        default:
            // TODO: error
            return;
        }
    }
};

// #define ADD_HANDLER(name, msg_type)\
    

} // namespace pool

} // namespace c2pool
