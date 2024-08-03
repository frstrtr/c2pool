#pragma once

#include <map>
#include <source_location>

#include <pool/peer.hpp>
#include <pool/protocol.hpp>
#include <core/common.hpp>
#include <core/factory.hpp>
#include <core/socket.hpp>
#include <core/message.hpp>
#include <core/config.hpp>
#include <core/random.hpp>
#include <core/addr_store.hpp>

namespace pool
{

std::string parse_net_error(const boost::system::error_code& ec);

class NodeInterfaces : public core::ICommunicator, public core::INetwork
{
    //-core::ICommmunicator:
    // void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    // void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    // void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) = 0;
    // const std::vector<std::byte>& get_prefix() const = 0;
    //
    //-core::INetwork:
    // void connected(std::shared_ptr<core::Socket> socket) = 0;
    // void disconnect() = 0;
};

template <typename ConfigType, typename ShareChainType, typename PeerData>
class BaseNode : public NodeInterfaces, public core::Factory<core::Server, core::Client>
{
    // For implementation override:
    //  INetwork:
    //      void disconnect()
    // BaseNode:
    //      void handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
    //      void send_ping(peer_ptr peer);
protected:
    const time_t NEW_PEER_TIMEOUT_TIME = 10;
    const time_t PEER_TIMEOUT_TIME = 100;
    const time_t PING_DELAY = 60;

public:
    using base_t = BaseNode<ConfigType, ShareChainType, PeerData>;
    using peer_t = pool::Peer<PeerData>;
    using peer_ptr = std::shared_ptr<peer_t>;
    using config_t = ConfigType;

protected:
    boost::asio::io_context* m_context;
    config_t* m_config; // todo: init
    ShareChainType* m_chain; // todo: init
    core::AddrStore m_addrs;

    uint64_t m_nonce; // node_id todo: init
    std::map<NetService, peer_ptr> m_connections;
    std::map<int, peer_ptr> m_peers; // key = peers nonce

    std::unique_ptr<core::Timer> m_ping_timer;

public:
    BaseNode() : Factory<Server, Client>(nullptr, this), m_addrs("") {}
    BaseNode(boost::asio::io_context* context, config_t* config) 
        : Factory<Server, Client>(context, this), m_context(context), m_addrs(config->m_name), m_config(config) 
    {
        // ping timer for all peers
        m_ping_timer = std::make_unique<core::Timer>(m_context, true);
        m_ping_timer->start(PING_DELAY, 
            [&]()
            {
                for (auto& [nonce, peer] : m_peers)
                {
                    if (m_peers.contains(peer->m_nonce))
                        send_ping(peer);
                }
            }
        );
    }

    const std::vector<std::byte>& get_prefix() const override { return m_config->pool()->m_prefix; }
    void connected(std::shared_ptr<core::Socket> socket) override 
    {
        // make peer
        auto peer = std::make_shared<peer_t>(socket);
        // move peer to m_connections
        m_connections[socket->get_addr()] = peer;
        // configure peer timeout timer
        peer->m_timeout = std::make_unique<core::Timer>(m_context, true);
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
            auto peer = m_connections.extract(service);
            peer.mapped()->m_timeout->stop(); // for case: peer stored somewhere (or leak)
            peer.mapped()->cancel();
            peer.mapped()->close();
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

    void got_addr(NetService addr, uint64_t services, uint64_t timestamp)
    {
    	if (m_addrs.check(addr))
    	{
    		auto old = m_addrs.get(addr);
    		m_addrs.update(addr, {services, old.m_first_seen, std::max(old.m_last_seen, timestamp)});
    	}
    	else
    	{
    		if (m_addrs.len() < 10000)
    			m_addrs.add(addr, {services, timestamp, timestamp});
    	}
    }

	std::vector<core::AddrStorePair> get_good_peers(size_t max_count)
    {
	    auto t = core::timestamp();

        std::vector<std::pair<float, core::AddrStorePair>> values;
	    for (auto pair : m_addrs.get_all())
	    {
	    	values.push_back(
	    			std::make_pair(
	    					-log(std::max(uint64_t(3600), pair.value.m_last_seen - pair.value.m_first_seen)) / log(std::max(uint64_t(3600), t - pair.value.m_last_seen)) * core::random::expovariate(1),
	    					pair)
            );
	    }

	    std::sort(values.begin(), values.end(), [](const auto& a, auto b)
	    { return a.first < b.first; });

	    values.resize(std::min(values.size(), max_count));
	    std::vector<core::AddrStorePair> result;
	    for (const auto& v : values)
	    {
	    	result.push_back(v.second);
	    }
	    return result;
    }

    virtual void send_ping(peer_ptr peer) = 0;
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

            PeerConnectionType peer_type = unknown;
            try
            {
                peer_type = Base::handle_version(std::move(rmsg), peer);
            } catch (const std::exception& ex)
            {
                Base::error(ex.what(), service);
                return;
            }
            assert(peer_type != PeerConnectionType::unknown); // peer_type is "unknown" after message_version!
            peer->set_type(peer_type);
            peer->m_timeout->restart(Base::PEER_TIMEOUT_TIME); // change timeout 10s -> 100s
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
