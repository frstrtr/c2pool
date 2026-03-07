#include "node.hpp"

#include <core/common.hpp>
#include <core/hash.hpp>
#include <core/random.hpp>
#include <sharechain/prepared_list.hpp>

#include <random>

namespace ltc
{

static uint64_t make_random_nonce()
{
    std::mt19937_64 rng(std::random_device{}());
    return rng();
}

void NodeImpl::send_ping(peer_ptr peer)
{
        auto rmsg = ltc::message_ping::make_raw();
        peer->write(std::move(rmsg));
};

void NodeImpl::connected(std::shared_ptr<core::Socket> socket)
{
    // Let BaseNode create the peer and set up the timeout timer
    base_t::connected(socket);

    auto peer = m_connections[socket->get_addr()];
    send_version(peer);
}

void NodeImpl::send_version(peer_ptr peer)
{
    auto rmsg = ltc::message_version::make_raw(
        ltc::PoolConfig::MINIMUM_PROTOCOL_VERSION,
        1,                                    // services
        addr_t{1, peer->addr()},              // addr_to (the remote)
        addr_t{1, NetService{"0.0.0.0", ltc::PoolConfig::P2P_PORT}}, // addr_from (us)
        m_nonce,
        "/c2pool:0.1/",
        1,                                    // mode (always 1 for legacy compat)
        best_share_hash()                     // advertise our tallest chain head
    );
    peer->write(std::move(rmsg));
}

pool::PeerConnectionType NodeImpl::handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    LOG_DEBUG_POOL << "handle message_version";
        std::unique_ptr<ltc::message_version> msg;
        msg = ltc::message_version::make(rmsg->m_data);

        LOG_INFO << "Peer "
                 << msg->m_addr_from.m_endpoint.to_string()
                 << " says protocol version is "
                 << msg->m_version
                 << ", client version "
                 << msg->m_subversion;

        if (peer->m_other_version.has_value())
        {
            LOG_DEBUG_POOL << "more than one version message";
            throw std::runtime_error("more than one version message");
        }

        peer->m_other_version = msg->m_version;
        peer->m_other_subversion = msg->m_subversion;
        peer->m_other_services = msg->m_services;

        if (m_nonce == msg->m_nonce)
        {
                LOG_WARNING << "was connected to self";
                throw std::runtime_error("was connected to self"); //TODO:
        }

        if (m_peers.contains(msg->m_nonce))
        {
                std::string reason = "[handle_message_version] Detected duplicate connection, disconnecting from " + peer->addr().to_string();
                LOG_ERROR << reason;
                throw std::runtime_error(reason);
        // TODO: handshake->error(libp2p::BAD_PEER, reason);
        }

        peer->m_nonce = msg->m_nonce;
        m_peers[peer->m_nonce] = peer;

        // Request peers from the newly established connection
        {
            auto getaddrs_msg = ltc::message_getaddrs::make_raw(8);
            peer->write(std::move(getaddrs_msg));
        }

        // Reject peers running too-old protocol
        if (msg->m_version < ltc::PoolConfig::MINIMUM_PROTOCOL_VERSION)
        {
            LOG_WARNING << "Peer " << msg->m_addr_from.m_endpoint.to_string()
                        << " protocol " << msg->m_version
                        << " < minimum " << ltc::PoolConfig::MINIMUM_PROTOCOL_VERSION
                        << ", disconnecting";
            throw std::runtime_error("peer protocol too old");
        }

        if (!msg->m_best_share.IsNull())
        {
            LOG_INFO << "Best share hash for " << msg->m_addr_from.m_endpoint.to_string()
                     << " = " << msg->m_best_share.ToString();

            // Start downloading shares if we don't have the peer's best
            if (!m_chain->contains(msg->m_best_share))
                download_shares(peer, msg->m_best_share);
        }

        return pool::PeerConnectionType::legacy;
}
    
void NodeImpl::processing_shares(HandleSharesData& data, NetService addr)
{
    // auto t1 = core::debug_timestamp();
    chain::PreparedList<uint256, ShareType> prepare_shares(data.m_items);
    std::vector<ShareType> shares = prepare_shares.build_list();

    if (shares.size() > 5)
    {
        LOG_INFO << "Processing " << shares.size() << " shares from " << addr.to_string() << "...";
    }

    int32_t new_count = 0;
	std::map<uint256, coin::MutableTransaction> all_new_txs;
	for (auto& share : shares)
	{
        auto& new_txs = data.m_txs[share.hash()];
		if (!new_txs.empty())
		{
			for (auto& new_tx : new_txs)
			{
                PackStream packed_tx = pack(coin::TX_WITH_WITNESS(new_tx)); //TODO: WITH_WITNESS?
				all_new_txs[Hash(packed_tx.get_span())] = new_tx;
			}
		}

		if (m_chain->contains(share.hash()))
		{
            LOG_WARNING << "Got duplicate share, ignoring. Hash: " << share.hash().ToString();
			continue;
		}

		new_count++;
		m_chain->add(share);
	}
}

std::vector<ltc::ShareType> NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr)
{
    parents = std::min(parents, (uint64_t)1000/hashes.size());
	std::vector<ltc::ShareType> shares;
	for (const auto& handle_hash : hashes)
	{
		uint64_t n = std::min(parents+1, (uint64_t) m_chain->get_height(handle_hash));
		for (auto& [hash, data] : m_chain->get_chain(handle_hash, n))
        {
			if (std::find(stops.begin(), stops.end(), hash) != stops.end())
				break;
			shares.push_back(data.share);
		}
	}

	if (!shares.empty())
	{
		LOG_INFO << "Sending " << shares.size() << " shares to " << peer_addr.to_string();
	}
	return shares;
}

void NodeImpl::send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes)
{
    // Collect shares that exist in our chain
    std::vector<ShareType> shares;
    for (const auto& hash : share_hashes)
    {
        if (!m_chain->contains(hash))
            continue;
        // Retrieve the share via get_chain(hash, 1) — first element is the share itself
        for (auto& [h, data] : m_chain->get_chain(hash, 1))
        {
            shares.push_back(data.share);
            break;
        }
    }

    if (shares.empty())
        return;

    // Collect transactions that the peer doesn't know about
    std::set<uint256> needed_txs;
    for (auto& share : shares)
    {
        share.invoke([&](auto* obj) {
            if constexpr (requires { obj->m_new_transaction_hashes; })
            {
                for (const auto& th : obj->m_new_transaction_hashes)
                {
                    if (!peer->m_remote_txs.count(th) &&
                        !peer->m_remembered_txs.count(th))
                        needed_txs.insert(th);
                }
            }
        });
    }

    // Send remember_tx for txs the peer needs
    if (!needed_txs.empty())
    {
        std::vector<uint256> known_hashes;   // hashes in peer's remote set
        std::vector<coin::MutableTransaction> full_txs;  // full txs otherwise

        for (const auto& th : needed_txs)
        {
            if (peer->m_remote_txs.count(th))
            {
                known_hashes.push_back(th);
            }
            else
            {
                auto it = m_known_txs.find(th);
                if (it != m_known_txs.end())
                    full_txs.emplace_back(it->second);
            }
        }

        if (!known_hashes.empty() || !full_txs.empty())
        {
            auto rtx_msg = message_remember_tx::make_raw(known_hashes, full_txs);
            peer->write(std::move(rtx_msg));
        }
    }

    // Pack and send shares
    std::vector<chain::RawShare> rshares;
    rshares.reserve(shares.size());
    for (auto& share : shares)
        rshares.emplace_back(share.version(), pack(share));

    auto shares_msg = message_shares::make_raw(rshares);
    peer->write(std::move(shares_msg));

    // Send forget_tx so peer can free the remembered txs
    if (!needed_txs.empty())
    {
        std::vector<uint256> forget_vec(needed_txs.begin(), needed_txs.end());
        auto ftx_msg = message_forget_tx::make_raw(forget_vec);
        peer->write(std::move(ftx_msg));
    }

    LOG_INFO << "Sent " << shares.size() << " shares (+" << needed_txs.size()
             << " txs) to " << peer->addr().to_string();
}

void NodeImpl::broadcast_share(const uint256& share_hash)
{
    // Walk the chain back from share_hash, collecting un-broadcast shares
    std::vector<uint256> to_send;
    int32_t height = m_chain->get_height(share_hash);
    int32_t walk = std::min(height, 5);

    for (auto& [hash, data] : m_chain->get_chain(share_hash, walk))
    {
        if (m_shared_share_hashes.count(hash))
            break;
        m_shared_share_hashes.insert(hash);
        to_send.push_back(hash);
    }

    if (to_send.empty())
        return;

    for (auto& [nonce, peer] : m_peers)
        send_shares(peer, to_send);
}

uint256 NodeImpl::best_share_hash()
{
    if (!m_chain || m_chain->size() == 0)
        return uint256::ZERO;

    // Pick the head with the greatest height
    uint256 best;
    int32_t best_height = -1;
    for (const auto& [head_hash, tail_hash] : m_chain->get_heads())
    {
        auto h = m_chain->get_height(head_hash);
        if (h > best_height)
        {
            best = head_hash;
            best_height = h;
        }
    }
    return best;
}

void NodeImpl::download_shares(peer_ptr peer, const uint256& target_hash)
{
    // Already downloading this hash — avoid duplicate requests
    if (m_downloading_shares.count(target_hash))
        return;
    m_downloading_shares.insert(target_hash);

    auto req_id = core::random::random_uint256();

    // Request up to 500 parents starting from target
    constexpr uint64_t PARENTS_PER_REQUEST = 500;
    std::vector<uint256> hashes = { target_hash };
    std::vector<uint256> stops;  // empty — don't stop early, let handle_get_share apply limits

    LOG_INFO << "Requesting shares from " << peer->addr().to_string()
             << " starting at " << target_hash.ToString()
             << " (parents=" << PARENTS_PER_REQUEST << ")";

    // weak_ptr prevents use-after-free if peer disconnects before reply
    std::weak_ptr<pool::Peer<ltc::Peer>> weak_peer = peer;

    request_shares(req_id, peer, hashes, PARENTS_PER_REQUEST, stops,
        [this, weak_peer, target_hash](std::vector<ltc::ShareType> shares)
        {
            m_downloading_shares.erase(target_hash);

            if (shares.empty())
            {
                LOG_DEBUG_POOL << "Empty sharereply for " << target_hash.ToString();
                return;
            }

            LOG_INFO << "Received " << shares.size() << " shares for download request";

            // Feed into processing pipeline
            HandleSharesData data;
            for (auto& s : shares)
                data.add(s, {});
            processing_shares(data, NetService{});

            // Find the oldest share's parent — if unknown, keep fetching
            uint256 oldest_parent;
            shares.back().invoke([&](auto* obj) { oldest_parent = obj->m_prev_hash; });

            if (!oldest_parent.IsNull() && !m_chain->contains(oldest_parent))
            {
                auto locked = weak_peer.lock();
                if (locked)
                    download_shares(locked, oldest_parent);
            }
        }
    );
}

} // namespace ltc
