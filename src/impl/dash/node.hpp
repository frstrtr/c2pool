#pragma once

// DashNodeImpl: Dash p2pool node using BaseNode infrastructure.
// Handles v1700 protocol, v16 shares, X11 PoW validation.

#include "config.hpp"
#include "params.hpp"
#include "share.hpp"
#include "share_chain.hpp"
#include "share_tracker.hpp"
#include "peer.hpp"
#include "messages.hpp"
#include "coin/transaction.hpp"

#include <core/coin_params.hpp>
#include <core/random.hpp>
#include <pool/node.hpp>
#include <pool/protocol.hpp>
#include <core/message.hpp>
#include <core/reply_matcher.hpp>

#include <random>
#include <set>

namespace dash
{

struct ShareReplyData
{
    std::vector<ShareType> m_items;
    std::vector<chain::RawShare> m_raw_items;
};

class DashNodeImpl : public pool::BaseNode<dash::Config, dash::ShareChain, dash::Peer>
{
    using base_t = pool::BaseNode<dash::Config, dash::ShareChain, dash::Peer>;

    using share_getter_t = ReplyMatcher::ID<uint256>
        ::RESPONSE<dash::ShareReplyData>
        ::REQUEST<uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>>;

protected:
    core::CoinParams m_coin_params;
    dash::Handler m_handler;
    share_getter_t m_share_getter;
    ShareTracker m_tracker;

    std::set<uint256> m_downloading_shares;
    static constexpr int MAX_EMPTY_RETRIES = 3;
    std::unordered_map<uint256, int, dash::ShareHasher> m_download_fail_count;
    std::map<uint256, NetService> m_pending_share_reqs;

public:
    DashNodeImpl()
        : m_coin_params(dash::make_coin_params(false)),
          m_share_getter(nullptr,
            [](uint256, peer_ptr, std::vector<uint256>, uint64_t, std::vector<uint256>){})
    {
        m_tracker.m_params = &m_coin_params;
    }

    DashNodeImpl(boost::asio::io_context* ctx, config_t* config, bool testnet = false)
        : m_coin_params(dash::make_coin_params(testnet)),
          base_t(ctx, config),
          m_share_getter(ctx,
            [](uint256 req_id, peer_ptr to_peer,
               std::vector<uint256> hashes, uint64_t parents,
               std::vector<uint256> stops)
            {
                auto rmsg = dash::message_sharereq::make_raw(req_id, hashes, parents, stops);
                to_peer->write(std::move(rmsg));
            },
            15)
    {
        m_tracker.m_params = &m_coin_params;

        // Seed addr store with bootstrap peers
        m_addrs.load(config->pool()->m_bootstrap_addrs);

        // Random nonce
        std::mt19937_64 rng(std::random_device{}());
        m_nonce = rng();

        // Route chain pointer
        m_chain = &m_tracker.chain;
    }

    // INetwork
    void disconnect() override { }
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        auto addr = socket->get_addr();
        base_t::connected(socket);
        auto peer = m_connections[addr];
        send_version(peer);
    }

    // Send version message (protocol 1700)
    void send_version(peer_ptr peer)
    {
        auto rmsg = dash::message_version::make_raw(
            m_coin_params.minimum_protocol_version,
            0,                                    // services
            addr_t{0, peer->addr()},              // addr_to
            addr_t{0, NetService{"0.0.0.0", m_coin_params.p2p_port}},
            m_nonce,
            "/c2pool-dash:0.1/",
            1,                                    // mode
            best_share_hash()
        );
        peer->write(std::move(rmsg));
    }

    void send_ping(peer_ptr peer) override
    {
        auto rmsg = dash::message_ping::make_raw();
        peer->write(std::move(rmsg));
    }

    std::optional<pool::PeerConnectionType> handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override
    {
        auto msg = dash::message_version::make(rmsg->m_data);

        if (msg->m_version < m_coin_params.minimum_protocol_version)
        {
            LOG_WARNING << "[Dash] Peer protocol " << msg->m_version
                        << " < minimum " << m_coin_params.minimum_protocol_version;
            throw std::runtime_error("peer protocol too old");
        }

        peer->m_other_version = msg->m_version;
        peer->m_other_subversion = msg->m_subversion;
        peer->m_nonce = msg->m_nonce;

        LOG_INFO << "[Dash] Peer version=" << msg->m_version
                 << " subver=" << msg->m_subversion
                 << " best=" << msg->m_best_share.GetHex().substr(0, 16);

        // Store best_share for post-handshake download (peer not in m_peers until stable())
        peer->m_best_share = msg->m_best_share;

        return pool::PeerConnectionType::actual;
    }

    // Protocol message dispatch
    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        auto peer_it = m_connections.find(service);
        if (peer_it == m_connections.end()) return;

        auto& peer = peer_it->second;
        peer->m_timeout->restart();

        // Version handshake (must be first message)
        if (rmsg->m_command.compare(0, 7, "version") == 0)
        {
            auto type = handle_version(std::move(rmsg), peer);
            if (type.has_value()) {
                peer->stable(type.value(), PEER_TIMEOUT_TIME);
                m_peers[peer->m_nonce] = peer;
                LOG_INFO << "[Dash] Peer " << service.to_string() << " handshake OK";

                // Trigger share download now that peer is in m_peers
                if (!peer->m_best_share.IsNull() && !m_chain->contains(peer->m_best_share))
                    download_shares(peer, peer->m_best_share);
            }
            return;
        }

        // Parse through message handler
        try {
            auto result = m_handler.parse(rmsg);
            std::visit([&](auto& msg) {
                using T = std::decay_t<decltype(msg)>;
                if constexpr (std::is_same_v<T, std::unique_ptr<dash::message_shares>>) {
                    if (msg) {
                        process_shares(msg->m_shares, service);
                    }
                }
                else if constexpr (std::is_same_v<T, std::unique_ptr<dash::message_sharereply>>) {
                    if (msg) {
                        handle_sharereply(std::move(msg), peer);
                    }
                }
                else if constexpr (std::is_same_v<T, std::unique_ptr<dash::message_sharereq>>) {
                    if (msg) {
                        handle_sharereq(std::move(msg), peer);
                    }
                }
            }, result);
        } catch (const std::exception&) {
            // Unhandled messages (addrme, have_tx, etc.) — normal
        }
    }

    // ── Share request/reply handlers ────────────────────────────────────────

    void handle_sharereq(std::unique_ptr<dash::message_sharereq> msg, peer_ptr peer)
    {
        LOG_INFO << "[Dash] sharereq from " << peer->addr().to_string()
                 << " hashes=" << msg->m_hashes.size()
                 << " parents=" << msg->m_parents
                 << " stops=" << msg->m_stops.size();

        auto shares = handle_get_shares(msg->m_hashes, msg->m_parents, msg->m_stops);

        std::vector<chain::RawShare> rshares;
        try {
            for (auto& share : shares) {
                rshares.emplace_back(share.version(), pack(share));
            }
            auto reply = dash::message_sharereply::make_raw(
                msg->m_id, dash::ShareReplyResult::good, rshares);
            peer->write(std::move(reply));
        } catch (const std::invalid_argument&) {
            auto reply = dash::message_sharereply::make_raw(
                msg->m_id, dash::ShareReplyResult::too_long, {});
            peer->write(std::move(reply));
        }
    }

    void handle_sharereply(std::unique_ptr<dash::message_sharereply> msg, peer_ptr peer)
    {
        dash::ShareReplyData result;
        if (msg->m_result == ShareReplyResult::good)
        {
            result.m_items.reserve(msg->m_shares.size());
            result.m_raw_items.reserve(msg->m_shares.size());
            for (auto& rshare : msg->m_shares)
            {
                try {
                    auto share = dash::load_share(rshare, peer->addr());
                    result.m_items.push_back(share);
                    result.m_raw_items.push_back(rshare);
                } catch (const std::exception& e) {
                    LOG_WARNING << "[Dash] Failed to deserialize share reply (type="
                                << rshare.type << "): " << e.what();
                }
            }
        }
        got_share_reply(msg->m_id, result);
    }

    // Walk chain from hashes, collecting up to parents shares, stopping at stops
    std::vector<dash::ShareType> handle_get_shares(
        const std::vector<uint256>& hashes, uint64_t parents,
        const std::vector<uint256>& stops)
    {
        std::set<uint256> stop_set(stops.begin(), stops.end());
        std::vector<dash::ShareType> result;

        for (auto& hash : hashes)
        {
            if (!m_tracker.chain.contains(hash))
                continue;

            uint256 cur = hash;
            for (uint64_t i = 0; i <= parents; ++i)
            {
                if (cur.IsNull() || !m_tracker.chain.contains(cur))
                    break;
                if (stop_set.count(cur))
                    break;

                auto& entry = m_tracker.chain.get(cur);
                result.push_back(entry.share);

                // Walk to parent
                entry.share.invoke([&](auto* obj) { cur = obj->m_prev_hash; });
            }
        }
        return result;
    }

    // ── Async share download ────────────────────────────────────────────────

    void request_shares(uint256 id, peer_ptr peer,
                        std::vector<uint256> hashes, uint64_t parents,
                        std::vector<uint256> stops,
                        std::function<void(dash::ShareReplyData)> callback)
    {
        m_share_getter.request(id, callback, id, peer, hashes, parents, stops);
    }

    void got_share_reply(uint256 id, dash::ShareReplyData shares)
    {
        try { m_share_getter.got_response(id, shares); }
        catch (const std::invalid_argument&) { /* timed out */ }
    }

    // p2pool node.py download_shares() — recursive chain walker
    void download_shares(peer_ptr /*unused_peer*/, const uint256& target_hash)
    {
        if (m_downloading_shares.count(target_hash))
            return;

        if (m_download_fail_count[target_hash] >= MAX_EMPTY_RETRIES) {
            LOG_INFO << "[Dash] Skipping failed hash "
                     << target_hash.GetHex().substr(0, 16)
                     << " (failed " << m_download_fail_count[target_hash] << "x)";
            return;
        }

        m_downloading_shares.insert(target_hash);

        if (m_peers.empty()) {
            m_downloading_shares.erase(target_hash);
            return;
        }

        // Random peer selection
        auto peer_it = m_peers.begin();
        if (m_peers.size() > 1)
            std::advance(peer_it, core::random::random_uint256().GetLow64() % m_peers.size());
        auto& peer = peer_it->second;

        // Random parent count 0-499
        uint64_t parents = core::random::random_uint256().GetLow64() % 500;

        // Build stops from known chain heads (only if we have a non-fragmented chain)
        std::vector<uint256> stops;
        if (!m_tracker.verified.get_heads().empty()) {
            std::set<uint256> stop_set;
            for (auto& [head_hash, tail_hash] : m_tracker.chain.get_heads()) {
                stop_set.insert(head_hash);
                auto h = m_tracker.chain.get_acc_height(head_hash);
                auto nth = std::min(std::max(0, h - 1), 10);
                if (nth > 0) {
                    auto parent = m_tracker.chain.get_nth_parent_via_skip(head_hash, nth);
                    if (!parent.IsNull())
                        stop_set.insert(parent);
                }
            }
            int count = 0;
            for (auto& s : stop_set) {
                if (count++ >= 100) break;
                stops.push_back(s);
            }
        }

        auto req_id = core::random::random_uint256();
        std::vector<uint256> hashes = { target_hash };
        m_pending_share_reqs[req_id] = peer->addr();

        LOG_INFO << "[Dash] Requesting parent share "
                 << target_hash.GetHex().substr(0, 16)
                 << " from " << peer->addr().to_string()
                 << " (parents=" << parents << " stops=" << stops.size() << ")";

        std::weak_ptr<pool::Peer<dash::Peer>> weak_peer = peer;
        auto peer_addr = peer->addr();

        request_shares(req_id, peer, hashes, parents, stops,
            [this, weak_peer, target_hash, peer_addr, req_id](dash::ShareReplyData reply)
            {
                m_downloading_shares.erase(target_hash);
                m_pending_share_reqs.erase(req_id);

                if (reply.m_items.empty())
                {
                    auto& fail_cnt = m_download_fail_count[target_hash];
                    ++fail_cnt;
                    LOG_INFO << "[Dash] Share request empty for "
                             << target_hash.GetHex().substr(0, 16)
                             << " (fail " << fail_cnt << "/" << MAX_EMPTY_RETRIES << ")";
                    return;
                }

                m_download_fail_count.erase(target_hash);

                LOG_INFO << "[Dash] Received " << reply.m_items.size()
                         << " shares for download request";

                // Verify and add each share
                for (auto& share_var : reply.m_items)
                {
                    share_var.invoke([&](auto* obj) {
                        try {
                            uint256 share_hash = dash::share_init_verify(*obj, m_coin_params, true);
                            obj->m_hash = share_hash;

                            if (!m_tracker.chain.contains(share_hash)) {
                                auto* heap_share = new dash::DashShare(*obj);
                                m_tracker.add(heap_share);
                            }
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[Dash] Share verification failed in download: " << e.what();
                        }
                    });
                }

                LOG_INFO << "[Dash] Tracker: " << m_tracker.chain.size() << " shares"
                         << " heads=" << m_tracker.chain.get_heads().size();

                // Recursively download oldest parent if unknown
                uint256 oldest_parent;
                reply.m_items.back().invoke([&](auto* obj) { oldest_parent = obj->m_prev_hash; });

                if (!oldest_parent.IsNull() && !m_chain->contains(oldest_parent))
                {
                    auto locked = weak_peer.lock();
                    if (locked)
                        download_shares(locked, oldest_parent);
                }
            }
        );
    }

    // ── Process received shares (pushed by peer, not requested) ─────────────

    void process_shares(std::vector<chain::RawShare>& raw_shares, const NetService& from)
    {
        LOG_INFO << "[Dash] Processing " << raw_shares.size() << " share(s) from " << from.to_string();

        for (auto& raw_share : raw_shares)
        {
            if (raw_share.type != 16) {
                LOG_WARNING << "[Dash] Unknown share type " << raw_share.type << ", skipping";
                continue;
            }

            try {
                auto stream = raw_share.contents.as_stream();
                auto share_var = dash::ShareType::load(raw_share.type, stream);

                share_var.ACTION({
                    LOG_INFO << "[Dash] Share deserialized:"
                             << " prev=" << obj->m_prev_hash.GetHex().substr(0, 16)
                             << " height=" << obj->m_absheight
                             << " bits=0x" << std::hex << obj->m_bits << std::dec
                             << " subsidy=" << obj->m_subsidy
                             << " donation=" << obj->m_donation
                             << " payments=" << obj->m_packed_payments.size()
                             << " timestamp=" << obj->m_timestamp;

                    try {
                        uint256 share_hash = dash::share_init_verify(*obj, m_coin_params, true);
                        obj->m_hash = share_hash;
                        LOG_INFO << "[Dash] Share VERIFIED: hash=" << share_hash.GetHex().substr(0, 16)
                                 << " X11 PoW valid!";

                        if (!m_tracker.chain.contains(share_hash)) {
                            auto* heap_share = new dash::DashShare(*obj);
                            m_tracker.add(heap_share);
                            LOG_INFO << "[Dash] Share added to tracker (total: " << m_tracker.chain.size() << ")";
                        }
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[Dash] Share verification failed: " << e.what();
                    }
                });
            } catch (const std::exception& e) {
                LOG_WARNING << "[Dash] Share deserialization failed: " << e.what()
                            << " (type=" << raw_share.type << " size=" << raw_share.contents.size() << ")";
            }
        }
    }

    // Access
    ShareTracker& tracker() { return m_tracker; }
    const core::CoinParams& coin_params() const { return m_coin_params; }

    uint256 best_share_hash() const
    {
        auto heads = m_tracker.chain.get_heads();
        if (heads.empty())
            return uint256();
        return heads.begin()->first;
    }

    // Add a locally-generated share into the tracker. Takes ownership of the
    // DashShare via heap allocation matching process_shares()'s pattern.
    // Returns the share_hash that was computed during verification. Throws on
    // verification failure.
    uint256 add_local_share(const dash::DashShare& share)
    {
        auto* heap_share = new dash::DashShare(share);
        heap_share->m_hash = share.m_hash.IsNull()
            ? dash::share_init_verify(*heap_share, m_coin_params, /*check_pow=*/false)
            : share.m_hash;
        if (!m_tracker.chain.contains(heap_share->m_hash))
            m_tracker.add(heap_share);
        return heap_share->m_hash;
    }

    // Broadcast a single locally-created share to every connected peer via
    // the message_shares wire message. Pack once, build a fresh RawMessage
    // per peer (Peer::write() takes ownership of the unique_ptr).
    void broadcast_share(const dash::DashShare& share)
    {
        broadcast_share(share, {});
    }

    // Overload that ships tx bodies via message_remember_tx BEFORE the share,
    // then follows with message_forget_tx so peer's remembered_txs map doesn't
    // grow unboundedly. Mirrors p2pool-dash/p2p.py:390-394 send order:
    //   send_remember_tx → send_shares → send_forget_tx.
    //
    // forget_tx MUST list the hash of every tx body sent in remember_tx
    // (not just share.m_new_transaction_hashes) — otherwise peer's
    // remembered_txs retains entries across broadcasts, and the next
    // remember_tx for overlapping txs triggers 'Peer referenced transaction
    // twice, disconnecting' (p2p.py:455-458).
    void broadcast_share(const dash::DashShare& share,
                         const std::vector<dash::coin::MutableTransaction>& tx_bodies)
    {
        auto packed = pack(dash::ShareType(const_cast<dash::DashShare*>(&share)));

        // Precompute hash256 of each tx body (matches what peer computes in
        // handle_remember_tx / forget_tx — data.py hash256(tx_type.pack(tx))).
        std::vector<uint256> tx_body_hashes;
        tx_body_hashes.reserve(tx_bodies.size());
        for (const auto& tx : tx_bodies) {
            auto ps = pack(tx);
            auto sp = ps.get_span();
            std::vector<unsigned char> bytes(sp.size());
            for (size_t i = 0; i < sp.size(); ++i)
                bytes[i] = static_cast<unsigned char>(sp[i]);
            tx_body_hashes.push_back(Hash(std::span<const unsigned char>(
                bytes.data(), bytes.size())));
        }

        size_t sent = 0;
        for (auto& [nonce, peer] : m_peers) {
            if (!peer) continue;

            // 1. remember_tx with the tx bodies (empty tx_hashes means peer
            //    must compute hash from each body; peer already has our GBT
            //    txs in its own known_txs_var but this guarantees coverage
            //    across mempool timing skew). Skip if there are no bodies.
            if (!tx_bodies.empty()) {
                auto rmem = dash::message_remember_tx::make_raw(
                    std::vector<uint256>{},     // m_tx_hashes (empty — send full bodies)
                    tx_bodies);                  // m_txs
                peer->write(std::move(rmem));
            }

            // 2. the share itself
            chain::RawShare rshare(dash::DashShare::version, packed);
            auto rmsg = dash::message_shares::make_raw(
                std::vector<chain::RawShare>{rshare});
            peer->write(std::move(rmsg));

            // 3. forget_tx for EVERY body we just sent — else peer's
            //    remembered_txs accumulates and next remember_tx with an
            //    overlapping body is rejected as duplicate.
            if (!tx_body_hashes.empty()) {
                auto rforget = dash::message_forget_tx::make_raw(tx_body_hashes);
                peer->write(std::move(rforget));
            }

            ++sent;
        }
        LOG_INFO << "[Dash] broadcast_share hash=" << share.m_hash.GetHex().substr(0, 16)
                 << " tx_refs=" << tx_bodies.size()
                 << " to " << sent << " peer(s)";
    }

    void error(const message_error_type& err, const NetService& service,
               const std::source_location where = std::source_location::current()) override
    {
        LOG_ERROR << "[Dash] P2P error from " << service.to_string() << ": " << err;
        base_t::error(err, service, where);
    }
};

} // namespace dash
