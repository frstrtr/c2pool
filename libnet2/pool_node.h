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
#include <libp2p/handler.h>
#include <libp2p/node.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

#define HOST_IDENT std::string

class PoolNodeServer : virtual PoolNodeData
{
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, std::shared_ptr<PoolHandshake>)> msg_version_handler_type;

protected:
	std::shared_ptr<Listener> listener; // from P2PNode::run()

    std::map<std::shared_ptr<Socket>, std::shared_ptr<PoolHandshakeServer>> server_attempts;
    std::map<HOST_IDENT, std::shared_ptr<PoolProtocol>> server_connections;
private:
    msg_version_handler_type message_version_handle;
public:
	PoolNodeServer(const std::shared_ptr<io::io_context>& _context, msg_version_handler_type version_handle) : PoolNodeData(_context), message_version_handle(std::move(version_handle)) {}

	void socket_handle(std::shared_ptr<Socket> socket)
    {
        auto _socket = socket;
        socket->set_addr();
        server_attempts[_socket] = std::make_shared<PoolHandshakeServer>(std::move(socket), message_version_handle,
                                                                         [&](const std::shared_ptr<PoolHandshake> &_handshake)
                                                                         {
                                                                             handshake_handle(_handshake);
                                                                         }
        );
    }

    void handshake_handle(const std::shared_ptr<PoolHandshake>& _handshake)
    {
        LOG_DEBUG_POOL << "PoolServer has been connected to: " << _handshake->get_socket();
		auto _protocol = std::make_shared<PoolProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);

        auto _sock = _protocol->get_socket();
        auto ip = _sock->get_addr().ip;
        peers[_protocol->nonce] = _protocol;

        _sock->event_disconnect->subscribe(
                [&, _ip = ip]()
                {
                    auto proto = server_connections[_ip];

                    proto->stop();
                    peers.erase(proto->nonce);
                    server_connections.erase(_ip);
                });
        server_connections[ip] = std::move(_protocol);
    }

    void error_handle(const NetAddress& addr, const std::string& err)
    {
        LOG_ERROR << "Pool Server error: " << err;
    }

	void listen()
    {
        listener->tick();
    }
};

class PoolNodeClient : virtual PoolNodeData
{
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, std::shared_ptr<PoolHandshake>)> msg_version_handler_type;
protected:
	std::shared_ptr<Connector> connector; // from P2PNode::run()

	std::map<HOST_IDENT, std::shared_ptr<PoolHandshakeClient>> client_attempts;
    std::map<HOST_IDENT, std::shared_ptr<PoolProtocol>> client_connections;
private:
	io::steady_timer auto_connect_timer;
	const std::chrono::seconds auto_connect_interval{1s};

    msg_version_handler_type message_version_handle;
public:
	PoolNodeClient(std::shared_ptr<io::io_context> _context, msg_version_handler_type version_handle) : PoolNodeData(std::move(_context)), message_version_handle(std::move(version_handle)), auto_connect_timer(*context) {}

    void socket_handle(std::shared_ptr<Socket> socket)
    {
        socket->set_addr();
        auto addr = socket->get_addr();
        client_attempts[addr.ip] =
                std::make_shared<PoolHandshakeClient>(std::move(socket),
                                                      message_version_handle,
                                                      [&](const std::shared_ptr<PoolHandshake>& _handshake){ handshake_handle(_handshake);});
    }

    void handshake_handle(const std::shared_ptr<PoolHandshake>& _handshake)
    {
        LOG_DEBUG_POOL << "PoolServer has been connected to: " << _handshake->get_socket();
        auto _protocol = std::make_shared<PoolProtocol>(context, _handshake->get_socket(), handler_manager, _handshake);

        auto _sock = _protocol->get_socket();
        auto ip = _sock->get_addr().ip;
        peers[_protocol->nonce] = _protocol;
        _sock->event_disconnect->subscribe(
                [&, _ip = ip]()
                {
                    auto proto = client_connections[_ip];

                    proto->stop();
                    peers.erase(proto->nonce);
                    client_connections.erase(_ip);
                });

        client_connections[ip] = std::move(_protocol);
	    client_attempts.erase(ip);
    }

    void try_connect(const boost::system::error_code& ec)
    {
        if (ec)
        {
            LOG_ERROR << "P2PNode::auto_connect: " << ec.message();
            return;
        }

        if (!((client_connections.size() < config->desired_conns) &&
              (addr_store->len() > 0) &&
              (client_attempts.size() <= config->max_attempts)))
            return;

        for (const auto &addr: get_good_peers(1))
        {
            if (client_attempts.count(addr.ip) || client_connections.count(addr.ip))
            {
//                LOG_WARNING << "Client already connected to " << addr.to_string() << "!";
                continue;
            }
            LOG_TRACE << "try to connect: " << addr.to_string();
            client_attempts[addr.ip] = nullptr;
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

    void error_handle(const NetAddress& addr, const std::string& err)
    {
        LOG_ERROR << "Pool Server[->" << addr.to_string() << "] error: " << err;
        client_attempts.erase(addr.ip);
    }

	std::vector<NetAddress> get_good_peers(int max_count);
};

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<pool::messages::message_##msg>(#msg, [&](auto _msg, auto _proto){ handle_message_##msg(_msg, _proto); });

class PoolNode : public virtual PoolNodeData, PoolNodeServer, PoolNodeClient, protected WebPoolNode, public enable_shared_from_this<PoolNode>
{
    struct DownloadShareManager
    {
        struct resp_data
        {
            std::vector<ShareType> shares;
            NetAddress peer_addr;
        };

        std::shared_ptr<boost::asio::io_service::strand> strand;
        std::shared_ptr<PoolNode> node{};

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

        void start(const std::shared_ptr<PoolNode> &_node);
    };

private:
    uint64_t nonce; // node_id

    DownloadShareManager download_share_manager;
public:
	PoolNode(std::shared_ptr<io::io_context> _context)
			: PoolNodeData(std::move(_context)),
              PoolNodeServer(context, [&](std::shared_ptr<pool::messages::message_version> msg, std::shared_ptr<PoolHandshake> handshake) { handle_message_version(msg, handshake); }),
              PoolNodeClient(context, [&](std::shared_ptr<pool::messages::message_version> msg, std::shared_ptr<PoolHandshake> handshake) { handle_message_version(msg, handshake); })
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
		if (run_state == both || run_state == onlyServer)
        {
            listener = std::make_shared<ListenerType>(context, net, config->c2pool_port);
            listener->init(
                    // socket_handle
                    [&](std::shared_ptr<Socket> socket)
                    {
                        PoolNodeServer::socket_handle(std::move(socket));
                    },
                    // error
                    [&](const NetAddress& addr, const std::string& err)
                    {
                        PoolNodeServer::error_handle(addr, err);
                    },
                    // finish
                    [&]()
                    {
                        listen();
                    }
            );
            listen();
        }

		if (run_state == both || run_state == onlyClient)
		{
			connector = std::make_shared<ConnectorType>(context, net);
            connector->init(
                    // socket_handler
                    [&](const std::shared_ptr<Socket> &socket)
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
    void handle_message_version(std::shared_ptr<pool::messages::message_version> msg, std::shared_ptr<PoolHandshake> handshake);

	// Pool handlers
    void handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, std::shared_ptr<PoolProtocol> protocol);

    void handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, std::shared_ptr<PoolProtocol> protocol);
private:
    void start();

//    void download_shares();

    void init_web_metrics() override;
};
#undef SET_POOL_DEFAULT_HANDLER