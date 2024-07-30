#pragma once

#include <map>
#include <source_location>

#include <pool/factory.hpp>
#include <pool/peer.hpp>
#include <pool/protocol.hpp>
#include <core/socket.hpp>
#include <core/message.hpp>
#include <core/config.hpp>

namespace pool
{

std::string parse_net_error(const boost::system::error_code& ec);

class NodeInterface : public core::ICommunicator, public INetwork
{
};

template <typename ConfigType, typename ShareChainType, typename PeerData>
class BaseNode : public NodeInterface, public Factory
{
    // For implementation override:
    //  INetwork:
    //      void disconnect()
    // BaseNode:
    //      void handle_version(std::unique_ptr<RawMessage> rmsg, const peer_t& peer)
protected:
    const time_t NEW_PEER_TIMEOUT_TIME = 10;
    const time_t PEER_TIMEOUT_TIME = 100;

public:
    using base_t = BaseNode<ConfigType, ShareChainType, PeerData>;
    using peer_t = pool::Peer<PeerData>;
    using peer_ptr = std::shared_ptr<peer_t>;
    using config_t = ConfigType;

protected:
    config_t* m_config; // todo: init
    ShareChainType* m_chain; // todo: init

    uint64_t m_nonce; // node_id todo: init
    std::map<NetService, peer_ptr> m_connections;
    std::set<int> m_peers; // values = peers nonce

public:
    BaseNode() : Factory(nullptr, "", this) {}
    BaseNode(boost::asio::io_context* context, config_t* config) : Factory(context, config->m_name, this), m_config(config) {}

    const std::vector<std::byte>& get_prefix() const override { return m_config->pool()->m_prefix; }
    void connected(std::shared_ptr<core::Socket> socket) override 
    {
        // make peer
        auto peer = std::make_shared<peer_t>(socket);
        // move peer to m_connections
        m_connections[socket->get_addr()] = peer;
        // configure peer timeout timer
        peer->m_timeout = std::make_unique<core::Timer>(Factory::m_context, true);
        peer->m_timeout->start(NEW_PEER_TIMEOUT_TIME, [&, addr = peer->addr()](){ timeout(addr); });

        LOG_INFO << socket->get_addr().to_string() << " try to connect!";
    }

    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        LOG_ERROR << "PoolNode <NetName>[" << service.to_string() << "]:";
        LOG_ERROR << "\terror: " << err;
        LOG_ERROR << "\twhere: " << where.function_name();
        if (m_connections.contains(service))
        {
            std::cout << m_connections.size() << std::endl;
            auto peer = m_connections.extract(service);
            peer.mapped()->m_timeout->stop(); // for case: peer stored somewhere (or leak)
            peer.mapped()->cancel();
            peer.mapped()->close();
            std::cout << m_connections.size() << std::endl;
        }
        else
        {
            LOG_ERROR << "\tpeers not exist " << service.to_string();
        }
    }

    void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        error(parse_net_error(ec), service, where);
    }

    void timeout(const NetService& service)
    {
        error("peer timeout!", service);
    }

    virtual PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) = 0;
};

// Legacy -- p2pool; Actual -- c2pool
template <typename Base, typename Legacy, typename Actual>
class NodeBridge : public virtual Base, public Legacy, public Actual
{
    static_assert(std::is_base_of_v<Protocol<Base>, Legacy> && std::is_base_of_v<Protocol<Base>, Actual>);

public:
    template <typename... Args>
    NodeBridge(boost::asio::io_context* ctx, Base::config_t* config, Args... args) : Base(ctx, config, args...){ }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto peer = Base::m_connections[service];
        peer->m_timeout->restart();

        if (peer->type() == PeerConnectionType::unknown)
        {
            std::cout << "[" << rmsg->m_command << "] != \"version\"?: " << (rmsg->m_command.compare(0, 7, "version") != 0) << std::endl;
            if (rmsg->m_command.compare(0, 7, "version") != 0)
                return Base::error("message wanna for be version", service);

            auto peer_type = Base::handle_version(std::move(rmsg), peer);
            if (peer_type != PeerConnectionType::unknown)
            {
                peer->set_type(peer_type);
                peer->m_timeout->restart(Base::PEER_TIMEOUT_TIME); // change timeout 10s -> 100s
            }
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

#define ADD_HANDLER(name, msg_type)\
    void handle_ ##name (std::unique_ptr<msg_type> msg, peer_ptr peer)

#define HANDLER(name)\
    handle_ ##name (std::unique_ptr<message_ ##name> msg, peer_ptr peer)

} // namespace pool
