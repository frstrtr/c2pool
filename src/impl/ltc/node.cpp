#include "node.hpp"

#include <core/common.hpp>
#include <core/hash.hpp>
#include <core/random.hpp>
#include <core/target_utils.hpp>
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
    auto addr = socket->get_addr();
    bool is_outbound = m_pending_outbound.erase(addr) > 0;

    // Reject banned peers
    if (is_banned(addr))
    {
        LOG_INFO << "Rejecting connection from banned peer " << addr.to_string();
        socket->close();
        return;
    }

    // Let BaseNode create the peer and set up the timeout timer
    base_t::connected(socket);

    if (is_outbound)
        m_outbound_addrs.insert(addr);

    auto peer = m_connections[addr];
    send_version(peer);
}

void NodeImpl::error(const message_error_type& err, const NetService& service, const std::source_location where)
{
    // Clean outbound tracking before base removes the peer
    m_pending_outbound.erase(service);
    m_outbound_addrs.erase(service);

    base_t::error(err, service, where);
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
		m_tracker.add(share);

		// Persist to LevelDB
		if (m_storage && m_storage->is_available())
		{
			PackStream ps = pack(share);
			auto span = ps.get_span();
			std::vector<uint8_t> bytes(reinterpret_cast<const uint8_t*>(span.data()),
			                           reinterpret_cast<const uint8_t*>(span.data()) + span.size());
			// Store version as the first 8 bytes so we can reconstruct on load
			uint64_t ver = share.version();
			std::vector<uint8_t> versioned;
			versioned.resize(8 + bytes.size());
			std::memcpy(versioned.data(), &ver, 8);
			std::memcpy(versioned.data() + 8, bytes.data(), bytes.size());

			share.ACTION({
				uint256 target = chain::bits_to_target(obj->m_bits);
				m_storage->store_share(obj->m_hash, versioned, obj->m_prev_hash,
				                       /*height*/ 0, obj->m_timestamp,
				                       /*work*/ uint256::ZERO, target);
			});
		}
	}

    // Attempt verification on newly added shares
    if (new_count > 0)
    {
        int32_t verified_count = 0;
        for (auto& share : shares)
        {
            auto h = share.hash();
            if (m_tracker.verified.contains(h))
                continue;
            if (m_tracker.attempt_verify(h))
                verified_count++;
        }

        if (verified_count > 0)
            LOG_INFO << "Verified " << verified_count << "/" << new_count << " new shares";

        // Run think() to detect bad peers and request missing shares
        run_think();
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

void NodeImpl::load_persisted_shares()
{
    if (!m_storage || !m_storage->is_available())
        return;

    // load_sharechain iterates the height index and loads each share
    auto hashes = m_storage->get_shares_by_height_range(0, UINT64_MAX);
    if (hashes.empty())
    {
        LOG_INFO << "No persisted shares found in LevelDB";
        return;
    }

    int loaded = 0;
    for (const auto& hash : hashes)
    {
        std::vector<uint8_t> data;
        uint256 prev; uint64_t height, ts; uint256 work, target; bool orphan;
        if (!m_storage->load_share(hash, data, prev, height, ts, work, target, orphan))
            continue;
        if (data.size() < 8)
            continue;

        try
        {
            // First 8 bytes = version (uint64_t LE), rest = packed share
            uint64_t ver;
            std::memcpy(&ver, data.data(), 8);

            std::vector<unsigned char> share_bytes(data.begin() + 8, data.end());
            PackStream ps(share_bytes);

            auto share = ltc::load_share(static_cast<int64_t>(ver), ps, NetService{"0.0.0.0", 0});
            if (!m_chain->contains(share.hash()))
            {
                m_tracker.add(share);
                loaded++;
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING << "Failed to load share " << hash.ToString().substr(0, 16)
                        << "... from LevelDB: " << e.what();
        }
    }

    LOG_INFO << "Loaded " << loaded << " shares from LevelDB storage";
}

void NodeImpl::start_outbound_connections()
{
    // Try to connect to peers right away
    auto try_connect_peers = [this]() {
        size_t outbound = m_outbound_addrs.size();
        if (outbound >= TARGET_OUTBOUND_PEERS || m_connections.size() >= MAX_PEERS)
            return;

        size_t needed = TARGET_OUTBOUND_PEERS - outbound;
        auto good_peers = get_good_peers(needed + 4);  // ask for a few extra in case some are already connected

        for (auto& ap : good_peers)
        {
            if (needed == 0)
                break;
            // Skip if already connected, already dialing, or banned
            if (m_connections.contains(ap.addr) || m_pending_outbound.contains(ap.addr) || is_banned(ap.addr))
                continue;

            LOG_INFO << "Dialing outbound peer " << ap.addr.to_string();
            m_pending_outbound.insert(ap.addr);
            core::Client::connect(ap.addr);
            --needed;
        }
    };

    // Initial burst
    try_connect_peers();

    // Periodic maintenance — every 30 seconds, check if we need more outbound peers
    m_connect_timer = std::make_unique<core::Timer>(m_context, true);
    m_connect_timer->start(30, try_connect_peers);
}

void NodeImpl::run_think()
{
    // Rate-limit: skip if called too recently
    auto now = std::chrono::steady_clock::now();
    if (now - m_last_think_time < THINK_MIN_INTERVAL)
        return;
    m_last_think_time = now;

  try {
    // Use the wired block_rel_height function, or a safe default stub
    auto block_rel_height = m_block_rel_height_fn
        ? m_block_rel_height_fn
        : [](uint256) -> int32_t { return 0; };

    uint256 prev_block;  // zero — not used in basic think()
    uint32_t bits = 0;

    auto result = m_tracker.think(block_rel_height, prev_block, bits);

    // Ban peers that provided invalid/unverifiable shares
    auto now = std::chrono::steady_clock::now();
    for (const auto& bad_addr : result.bad_peer_addresses)
    {
        if (bad_addr.to_string().empty()) continue;
        m_ban_list[bad_addr] = now + BAN_DURATION;
        LOG_WARNING << "Banning peer " << bad_addr.to_string()
                    << " for " << BAN_DURATION.count() << "s (bad shares)";

        // Disconnect currently-connected bad peer
        for (auto& [nonce, peer] : m_peers) {
            if (peer->addr() == bad_addr) {
                peer->close();
                break;
            }
        }
    }

    // Expire old bans
    for (auto it = m_ban_list.begin(); it != m_ban_list.end(); ) {
        if (it->second <= now)
            it = m_ban_list.erase(it);
        else
            ++it;
    }

    // Request desired shares from peers
    for (const auto& [peer_addr, hash] : result.desired) {
        for (auto& [nonce, peer] : m_peers) {
            if (peer->addr() == peer_addr) {
                download_shares(peer, hash);
                break;
            }
        }
    }

    // Update best share
    if (!result.best.IsNull()) {
        LOG_DEBUG_POOL << "think(): best=" << result.best.GetHex().substr(0, 16) << "...";
    }

  } catch (const std::exception& e) {
    LOG_ERROR << "run_think() failed: " << e.what();
  } catch (...) {
    LOG_ERROR << "run_think() failed: unknown error";
  }
}

bool NodeImpl::is_banned(const NetService& addr) const
{
    auto it = m_ban_list.find(addr);
    if (it == m_ban_list.end()) return false;
    return it->second > std::chrono::steady_clock::now();
}

} // namespace ltc
