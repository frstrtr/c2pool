#pragma once

#include "config.hpp"
#include "share.hpp"
#include "peer.hpp"
#include "messages.hpp"

#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <core/reply_matcher.hpp>
#include <sharechain/prepared_list.hpp>

#include <random>

namespace ltc
{
struct HandleSharesData;

class NodeImpl : public pool::BaseNode<ltc::Config, ltc::ShareChain, ltc::Peer>
{
    // Async share downloader:
    // ID = uint256 (matches sharereq id to sharereply id)
    // RESPONSE = vector<ShareType>
    // REQUEST args: req_id, peer, hashes, parents, stops
    using share_getter_t = ReplyMatcher::ID<uint256>
        ::RESPONSE<std::vector<ltc::ShareType>>
        ::REQUEST<uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>>;

protected:
    ltc::Handler m_handler;
    share_getter_t m_share_getter;

    // Global pool of known transactions, populated by remember_tx and coin daemon.
    // Protocol handlers look up tx hashes here when processing shares.
    std::map<uint256, coin::Transaction> m_known_txs;

public:
    NodeImpl()
        : m_share_getter(nullptr,
            [](uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>){}) {}

    NodeImpl(boost::asio::io_context* ctx, config_t* config)
        : base_t(ctx, config),
          m_share_getter(ctx,
            [](uint256 req_id, peer_ptr to_peer,
               std::vector<uint256> hashes, uint64_t parents,
               std::vector<uint256> stops)
            {
                auto rmsg = ltc::message_sharereq::make_raw(req_id, hashes, parents, stops);
                to_peer->write(std::move(rmsg));
            })
    {
        // Seed addr store with hardcoded bootstrap peers
        m_addrs.load(config->pool()->m_bootstrap_addrs);
        // Randomise our nonce so we detect self-connections
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();
    }

    // INetwork:
    void disconnect() override { }
    void connected(std::shared_ptr<core::Socket> socket) override;

    // BaseNode:
    void send_ping(peer_ptr peer) override;
    pool::PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override;

    // ltc
    void send_version(peer_ptr peer);
    void processing_shares(HandleSharesData& data, NetService addr); // old handle_share

    // Async share download — response delivered to callback when sharereply arrives
    void request_shares(uint256 id, peer_ptr peer,
                        std::vector<uint256> hashes, uint64_t parents,
                        std::vector<uint256> stops,
                        std::function<void(std::vector<ltc::ShareType>)> callback)
    {
        m_share_getter.request(id, callback, id, peer, hashes, parents, stops);
    }

    // Called from HANDLER(sharereply) to complete a pending async request
    void got_share_reply(uint256 id, std::vector<ltc::ShareType> shares)
    {
        try { m_share_getter.got_response(id, shares); }
        catch (const std::invalid_argument&) { /* request already timed out */ }
    }

    // TODO: rename to processing_get_share
    std::vector<ltc::ShareType> handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr);

    /// Broadcast a new best-block notification to all connected P2P peers.
    void broadcast_bestblock(const coin::BlockHeaderType& header) {
        for (auto& [nonce, peer] : m_peers)
            peer->write(message_bestblock::make_raw(header));
    }

    /// Register a callback invoked whenever a bestblock message is received
    /// from any peer (after relaying). Use this to trigger work refresh.
    void set_on_bestblock(std::function<void()> fn) { m_on_bestblock = std::move(fn); }

    /// Send a set of shares (with any needed txs) to a single peer.
    /// Skips shares that originated from that peer.
    void send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes);

    /// Broadcast a locally-generated (or newly-received) share to all peers.
    void broadcast_share(const uint256& share_hash);

    /// Start downloading shares from a peer, beginning at `target_hash`.
    /// Recursively fetches parents until the chain is connected or CHAIN_LENGTH reached.
    void download_shares(peer_ptr peer, const uint256& target_hash);

    /// Return the hash of our tallest chain head, or uint256::ZERO if empty.
    uint256 best_share_hash();

protected:
    std::function<void()> m_on_bestblock;
    std::set<uint256> m_shared_share_hashes;  // de-dup set for broadcast_share
    std::set<uint256> m_downloading_shares;   // hashes currently being fetched
};

struct HandleSharesData
{
    std::vector<ShareType> m_items;
    std::map<uint256, std::vector<coin::MutableTransaction>> m_txs;

    void add(const ShareType& share, std::vector<coin::MutableTransaction> txs)
    {
        m_items.push_back(share);
        m_txs[share.hash()] = std::move(txs);
    }
};


/*
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
*/

class Legacy : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

class Actual : public pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer) override;

    ADD_HANDLER(addrs, ltc::message_addrs);
    ADD_HANDLER(addrme, ltc::message_addrme);
    ADD_HANDLER(ping, ltc::message_ping);
    ADD_HANDLER(getaddrs, ltc::message_getaddrs);
    ADD_HANDLER(shares, ltc::message_shares);
    ADD_HANDLER(sharereq, ltc::message_sharereq);
    ADD_HANDLER(sharereply, ltc::message_sharereply);
    ADD_HANDLER(bestblock, ltc::message_bestblock);
    ADD_HANDLER(have_tx, ltc::message_have_tx);
    ADD_HANDLER(losing_tx, ltc::message_losing_tx);
    ADD_HANDLER(remember_tx, ltc::message_remember_tx);
    ADD_HANDLER(forget_tx, ltc::message_forget_tx);
};

using Node = pool::NodeBridge<NodeImpl, Legacy, Actual>;

} // namespace ltc
