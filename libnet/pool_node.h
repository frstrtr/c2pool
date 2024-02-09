#pragma once

#include <memory>
#include <set>
#include <map>
#include <utility>
#include <vector>
#include <tuple>
#include <functional>

#include "pool_socket.h"
#include "pool_protocol.h"
#include "pool_handshake.h"
#include "pool_node_data.h"
#include <libp2p/net_supervisor.h>
#include <libp2p/handler.h>
#include <libp2p/node.h>
#include <libdevcore/exceptions.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

#define HOST_IDENT NetAddress

class PoolNodeServer : virtual PoolNodeData
{
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, PoolHandshake*)> msg_version_handler_type;

protected:
	std::unique_ptr<Listener> listener; // from P2PNode::run()

    std::map<HOST_IDENT, PoolHandshakeServer*> server_attempts;
    std::map<HOST_IDENT, PoolProtocol*> server_connections;
private:
    msg_version_handler_type message_version_handle;
public:
	PoolNodeServer(io::io_context* context_, msg_version_handler_type version_handle) 
        : PoolNodeData(context_), message_version_handle(std::move(version_handle)) {}

    template <typename ListenerType>
    void init()
    {
        listener = std::make_unique<ListenerType>(context, net, config->c2pool_port);
        listener->init(
                // socket from listener
                [&](Socket* socket)
                {
                    socket_handle(socket);
                },
                // disconnect
                [&](const NetAddress& addr)
                {
                    disconnect(addr);
                }
        );
    }

	void socket_handle(Socket* socket)
    {
        server_attempts[socket->get_addr()] = new PoolHandshakeServer(socket, message_version_handle,
                                                                         [&](PoolHandshake* _handshake)
                                                                         {
                                                                            handshake_handle(_handshake);
                                                                         }
        );
        socket->read();
    }

    void handshake_handle(PoolHandshake* handshake)
    {
        LOG_DEBUG_POOL << "PoolServer has been connected to: " << handshake->get_socket();
        auto sock = handshake->get_socket();
        auto addr = sock->get_addr();

		auto protocol = new PoolProtocol(context, sock, handler_manager, handshake);
        peers[protocol->nonce] = protocol;

        sock->event_disconnect->subscribe(
                [&, addr = addr]()
                {
                    auto proto = server_connections[addr];

                    proto->stop();
                    peers.erase(proto->nonce);
                    server_connections.erase(addr);
                });
        server_connections[addr] = protocol;
    }

	void start()
    {
        listener->run();
    }

    void stop()
    {   
        // disable listener
        listener->stop();

        // disconnect and delete all server_connections
        for (auto& [addr, protocol] : server_connections) 
        {
            if (protocol)
            {
                protocol->close();
                delete protocol;
            }            
        }
        server_connections.clear();

        // stop all server attempts
        for (auto& [socket, handshake] : server_attempts)
        {
            handshake->close();
            delete handshake;
        }
        server_attempts.clear();
    }

    void disconnect(const NetAddress& addr)
    {
        if (server_attempts.count(addr))
        {
            auto handshake = server_attempts[addr];
            handshake->close();
            delete handshake;
            server_attempts.erase(addr);
        }

        if (server_connections.count(addr))
        {
            auto protocol = server_connections[addr];
            peers.erase(protocol->nonce);
            protocol->close();
            delete protocol;
            server_connections.erase(addr);
        }
    }
};

class PoolNodeClient : virtual PoolNodeData
{
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, PoolHandshake*)> msg_version_handler_type;
protected:
	std::unique_ptr<Connector> connector; // from P2PNode::run()

	std::map<HOST_IDENT, PoolHandshakeClient*> client_attempts;
    std::map<HOST_IDENT, PoolProtocol*> client_connections;
private:
	io::steady_timer auto_connect_timer;
	const std::chrono::seconds auto_connect_interval{1s};

    msg_version_handler_type message_version_handle;
public:
	PoolNodeClient(io::io_context* _context, msg_version_handler_type version_handle) : PoolNodeData(_context), message_version_handle(std::move(version_handle)), auto_connect_timer(*context) {}

    void socket_handle(Socket* socket)
    {
        socket->set_addr();
        client_attempts[socket->get_addr()] =
                new PoolHandshakeClient(socket, message_version_handle,
                                                      [&](PoolHandshake* _handshake){ handshake_handle(_handshake);});
    }

    void handshake_handle(PoolHandshake* handshake)
    {
        LOG_DEBUG_POOL << "PoolServer has been connected to: " << handshake->get_socket();
        auto sock = handshake->get_socket();
        auto addr = sock->get_addr();
        auto protocol = new PoolProtocol(context, sock, handler_manager, handshake);

        peers[protocol->nonce] = protocol;
        sock->event_disconnect->subscribe(
                [&, addr=addr]()
                {
                    auto proto = client_connections[addr];

                    proto->stop();
                    peers.erase(proto->nonce);
                    client_connections.erase(addr);
                });

        client_connections[addr] = protocol;
	    client_attempts.erase(addr);
    }

    void try_connect(const boost::system::error_code& ec)
    {
        if (ec)
        {
            if (ec != boost::system::errc::operation_canceled)
                LOG_ERROR << "P2PNode::auto_connect: " << ec.message();
            return;
        }

        if (!((client_connections.size() < config->desired_conns) &&
              (addr_store->len() > 0) &&
              (client_attempts.size() <= config->max_attempts)))
            return;

        for (const auto &addr: get_good_peers(1))
        {
            if (client_attempts.count(addr) || client_connections.count(addr))
            {
//                LOG_WARNING << "Client already connected to " << addr.to_string() << "!";
                continue;
            }
            LOG_TRACE << "try to connect: " << addr.to_string();
            client_attempts[addr] = nullptr;
            connector->tick(addr);
        }

        auto_connect();
    }

	void auto_connect()
    {
        auto_connect_timer.expires_from_now(auto_connect_interval);
        auto_connect_timer.async_wait(
                [this](const boost::system::error_code &ec)
                {
                    try_connect(ec);
                });
    }

    // handshake error in connector
    void error_handle(const NetAddress& addr, const std::string& err)
    {
        LOG_ERROR << "Pool Server[->" << addr.to_string() << "] error: " << err;
        client_attempts.erase(addr);
    }

	std::vector<NetAddress> get_good_peers(int max_count);

    void stop_client()
    {   
        // disable connector
        connector->stop();

        // disconnect and delete all client_connections
        for (auto& [addr, protocol] : client_connections) 
        {
            if (protocol)
            {
                protocol->disconnect();
                delete protocol;
            }            
        }
        client_connections.clear();

        // stop all client attempts
        for (auto& [socket, handshake] : client_attempts)
        {
            handshake->disconnect();
            delete handshake;
        }
        client_attempts.clear();

        // stop auto_connect_timer
        auto_connect_timer.cancel();
    }
};

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<pool::messages::message_##msg>(#msg, [&](auto _msg, auto _proto){ handle_message_##msg(_msg, _proto); });

class PoolNode : public virtual PoolNodeData, public NodeExceptionHandler, public SupervisorElement, PoolNodeServer, PoolNodeClient, protected WebPoolNode
{
    struct DownloadShareManager
    {
        struct resp_data
        {
            std::vector<ShareType> shares;
            NetAddress peer_addr;
        };

        std::shared_ptr<boost::asio::io_service::strand> strand;
        PoolNode* node{};

        int64_t id_gen {0};
        bool is_processing {false};
        std::optional<std::vector<std::tuple<NetAddress, uint256>>> cache_desired;

        DownloadShareManager() = default;

        void handle(const resp_data& value)
        {
            if (value.shares.empty())
                // TODO: sleep 1s
                return;

            HandleSharesData _shares;
            for (auto& _share : value.shares)
            {
                _shares.add(_share, {});
            }

            node->handle_shares(_shares, value.peer_addr);
        }

        void processing_request(const std::vector<ShareType> &shares, const NetAddress& peer_addr, uint64_t _id)
        {
            resp_data resp{shares, peer_addr};
            strand->post([&, resp = std::move(resp), _id = _id]()
            {
                handle(resp);
                LOG_INFO << "Finish processing download share, id = " << _id;
                if (cache_desired)
                {
                    strand->post([&, copy_cache = cache_desired.value()]()
                                 {
                                     request_shares(copy_cache);
                                 });
                    cache_desired.reset();
                } else
                {
                    is_processing = false;
                }
            });
        }

        void request_shares(const std::vector<std::tuple<NetAddress, uint256>>& desired)
        {
            auto id = id_gen++;
            LOG_DEBUG_POOL << "REQUEST SHARES, id " << id;
            auto [peer_addr, share_hash] = c2pool::random::RandomChoice(desired);

            if (node->peers.empty())
            {
                LOG_WARNING << "request_shares: peers.size() == 0";
                // TODO: sleep 1s
                return;
            }

            auto peer = c2pool::random::RandomChoice(node->peers);
            auto [peer_ip, peer_port] = peer->get_addr();

            LOG_INFO << "Requesting[" << id <<"] parent share " << share_hash.GetHex() << "; from peer: " << peer_ip << ":"
                     << peer_port;
//          TODO:  try
//            {
            std::vector<uint256> stops;
            {
                std::set<uint256> _stops;
                for (const auto &s: node->tracker->heads)
                {
                    _stops.insert(s.first);
                }

                for (const auto &s: node->tracker->heads)
                {
                    uint256 stop_hash = node->tracker->get_nth_parent_key(s.first, std::min(
                            std::max(0, node->tracker->get_height_and_last(s.first).height - 1), 10));
                    _stops.insert(stop_hash);
                }
                stops = vector<uint256>{_stops.begin(), _stops.end()};
            }

            LOG_TRACE << "Stops: " << stops;

            peer->get_shares.yield(node->context, [&, peer = peer, id=id](const std::vector<ShareType> &shares)
                                   { processing_request(shares, peer->get_addr(), id); },
                                   std::vector<uint256>{share_hash},
                                   (uint64_t) c2pool::random::RandomInt(0, 500), //randomize parents so that we eventually get past a too large block of shares
                                   stops
            );
//            }
        }

        void start(PoolNode* _node);
    };

private:
    uint64_t nonce; // node_id

    DownloadShareManager download_share_manager;
public:
	PoolNode(io::io_context* _context) : PoolNodeData(_context),
              PoolNodeServer(context, [&](std::shared_ptr<pool::messages::message_version> msg, PoolHandshake* handshake) { handle_message_version(msg, handshake); }),
              PoolNodeClient(context, [&](std::shared_ptr<pool::messages::message_version> msg, PoolHandshake* handshake) { handle_message_version(msg, handshake); })
	{
        LOG_INFO << "PoolNode created!";
		SET_POOL_DEFAULT_HANDLER(addrs);
		SET_POOL_DEFAULT_HANDLER(addrme);
		SET_POOL_DEFAULT_HANDLER(ping);
		SET_POOL_DEFAULT_HANDLER(getaddrs);
		SET_POOL_DEFAULT_HANDLER(shares);
		SET_POOL_DEFAULT_HANDLER(sharereq);
		SET_POOL_DEFAULT_HANDLER(sharereply);
		SET_POOL_DEFAULT_HANDLER(bestblock);
		SET_POOL_DEFAULT_HANDLER(have_tx);
		SET_POOL_DEFAULT_HANDLER(losing_tx);
		SET_POOL_DEFAULT_HANDLER(remember_tx);
		SET_POOL_DEFAULT_HANDLER(forget_tx);

        nonce = c2pool::random::randomNonce();
//		handler_manager->new_handler<pool::messages::message_addrs>("addrs", [&](auto msg, auto proto){ handle_message_addrs(msg, proto); });
//		SET_POOL_DEFAULT_HANDLER()
	}

	template <typename ListenerType, typename ConnectorType>
	void run(NodeRunState run_state = both)
	{
		if (run_state & onlyServer)
        {
            PoolNodeServer::init<ListenerType>();
            PoolNodeServer::start();
        }

		if (run_state & onlyClient)
		{
			connector = std::make_unique<ConnectorType>(context, net);
            connector->init(
                    // socket_handler
                    [&](Socket* socket)
                    {
                        PoolNodeClient::socket_handle(socket);
                    },
                    // error_handle
                    [&](const NetAddress& addr, const std::string& err)
                    {
                        PoolNodeClient::error_handle(addr, err);
                    }
            );
			auto_connect();
		}
        start();
        init_web_metrics();
	}

	// Handshake handlers
    void handle_message_version(std::shared_ptr<pool::messages::message_version> msg, PoolHandshake* handshake);

	// Pool handlers
    void handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, PoolProtocol* protocol);

    void handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, PoolProtocol* protocol);

    void handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, PoolProtocol* protocol);

    void handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, PoolProtocol* protocol);

    void handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, PoolProtocol* protocol);

    void handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, PoolProtocol* protocol);

    void handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, PoolProtocol* protocol);

    void handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, PoolProtocol* protocol);

    void handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, PoolProtocol* protocol);

    void handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, PoolProtocol* protocol);

    void handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, PoolProtocol* protocol);

    void handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, PoolProtocol* protocol);
private:
    void start();
    void init_web_metrics() override;

protected:
    // SupervisorElement
    void stop() override
    {
        if (state == disconnected)
            return;

        stop_server();
        stop_client();

        set_state(disconnected);
    }

    void reconnect() override
    {
        //TODO: restart server+client
        reconnected();
    }

    // NodeExceptionHandler
    void HandleNodeException() override
	{
		restart();
	}

    void HandleNetException(NetExcept* data) override
	{
		//TODO: disconnect peer
	}
};
#undef SET_POOL_DEFAULT_HANDLER