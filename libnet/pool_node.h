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
#include "pool_network.h"
#include <libp2p/net_supervisor.h>
#include <libp2p/handler.h>
#include <libdevcore/exceptions.h>

// listener = std::make_unique<ListenerType>(context, net, config->c2pool_port);
// connector = std::make_unique<ConnectorType>(context, net);

#define SET_POOL_DEFAULT_HANDLER(msg) \
	handler_manager->new_handler<pool::messages::message_##msg, PoolProtocol>(#msg, [&](auto msg_, auto proto_){ handle_message_##msg(msg_, proto_); });

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
	PoolNode(io::io_context* context_) : PoolNodeData(context_),
              PoolNodeServer(this, [&](std::shared_ptr<pool::messages::message_version> msg, PoolHandshake* handshake) { handle_message_version(msg, handshake); }),
              PoolNodeClient(this, [&](std::shared_ptr<pool::messages::message_version> msg, PoolHandshake* handshake) { handle_message_version(msg, handshake); })
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
            PoolNodeClient::init<ConnectorType>();
            PoolNodeClient::start();
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

        PoolNodeServer::stop();
        PoolNodeClient::stop();

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