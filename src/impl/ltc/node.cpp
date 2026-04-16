#include "node.hpp"

#include <core/common.hpp>
#include <core/hash.hpp>
#include <core/random.hpp>
#include <core/target_utils.hpp>
#include <sharechain/prepared_list.hpp>

#include <algorithm>
#include <fstream>
#include <random>

// Helper: read current RSS from /proc/self/status (Linux only)
static long get_rss_mb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            long kb = 0;
            sscanf(line.c_str(), "VmRSS: %ld", &kb);
            return kb / 1024;
        }
    }
    return 0;
}

static constexpr long RSS_LIMIT_MB = 4000;  // abort if RSS exceeds 4GB

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
    // Drop stale nonce->peer entries for this endpoint before base cleanup.
    // Without this, reconnects can be rejected as false duplicates because
    // m_peers still contains the old nonce mapping.
    for (auto it = m_peers.begin(); it != m_peers.end(); )
    {
        if (it->second && it->second->addr() == service)
            it = m_peers.erase(it);
        else
            ++it;
    }

    // Clean outbound tracking before base removes the peer
    m_pending_outbound.erase(service);
    m_outbound_addrs.erase(service);

    base_t::error(err, service, where);
}

void NodeImpl::close_connection(const NetService& service)
{
    m_pending_outbound.erase(service);
    m_outbound_addrs.erase(service);
    base_t::close_connection(service);
}

void NodeImpl::send_version(peer_ptr peer)
{
    auto rmsg = ltc::message_version::make_raw(
        m_tracker.m_params->minimum_protocol_version,
        1,                                    // services
        addr_t{1, peer->addr()},              // addr_to (the remote)
        addr_t{1, NetService{"0.0.0.0", m_tracker.m_params->p2p_port}}, // addr_from (us)
        m_nonce,
        "/c2pool:0.1/",
        1,                                    // mode (always 1 for legacy compat)
        best_share_hash()                     // advertise our tallest chain head
    );
    peer->write(std::move(rmsg));
}

std::optional<pool::PeerConnectionType> NodeImpl::handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
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
                return std::nullopt;
        }

        if (m_peers.contains(msg->m_nonce))
        {
                LOG_DEBUG_POOL << "Detected duplicate connection, disconnecting from " << peer->addr().to_string();
                return std::nullopt;
        }

        peer->m_nonce = msg->m_nonce;
        m_peers[peer->m_nonce] = peer;

        // Request peers from the newly established connection
        {
            auto getaddrs_msg = ltc::message_getaddrs::make_raw(8);
            peer->write(std::move(getaddrs_msg));
        }

        // Reject peers running too-old protocol
        if (msg->m_version < m_tracker.m_params->minimum_protocol_version)
        {
            LOG_WARNING << "Peer " << msg->m_addr_from.m_endpoint.to_string()
                        << " protocol " << msg->m_version
                        << " < minimum " << m_tracker.m_params->minimum_protocol_version
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

        // Advertise ourselves to the peer (matching Python p2pool sendAdvertisement)
        {
            auto port = core::Server::listen_port();
            auto addrme_msg = ltc::message_addrme::make_raw(port);
            peer->write(std::move(addrme_msg));
        }

        return pool::PeerConnectionType::legacy;
}

void NodeImpl::processing_shares(HandleSharesData& data, NetService addr)
{
    // Step 1: Compute hashes for all shares FIRST so PreparedList can sort them.
    // Shares arrive with m_hash = 0 (hash is computed, not serialized).
    // Without valid hashes, PreparedList cannot topologically order shares.
    int32_t verify_fail_count = 0;
    std::vector<ShareType> valid_shares;
    valid_shares.reserve(data.m_items.size());
    for (size_t idx = 0; idx < data.m_items.size(); ++idx)
    {
        auto& share = data.m_items[idx];
        if (share.hash().IsNull())
        {
            try
            {
                share.ACTION({
                    obj->m_hash = share_init_verify(*obj, *m_tracker.m_params, true);
                });
            }
            catch (const std::exception& e)
            {
                ++verify_fail_count;
                continue;
            }
        }
        // Cache original raw bytes for relay (keyed by computed hash)
        if (idx < data.m_raw_items.size() && !data.m_raw_items[idx].contents.m_data.empty())
            m_raw_share_cache[share.hash()] = std::move(data.m_raw_items[idx]);
        valid_shares.push_back(share);
    }

    // Step 2: Topologically sort valid shares by hash/prev_hash linkage
    chain::PreparedList<uint256, ShareType> prepare_shares(valid_shares);
    std::vector<ShareType> shares = prepare_shares.build_list();

    // Step 3: Process sorted shares
    int32_t new_count = 0;
    int32_t dup_count = 0;
	std::map<uint256, coin::MutableTransaction> all_new_txs;
	for (int i = 0; i < (int)shares.size(); ++i)
	{
	    auto& share = shares[i];
	    
	    // Safety: abort if RSS exceeds limit
	    if (i % 100 == 0) {
	        long rss_now = get_rss_mb();
	        if (rss_now > RSS_LIMIT_MB) {
	            LOG_ERROR << "RSS LIMIT EXCEEDED (" << rss_now << "MB > " << RSS_LIMIT_MB << "MB) — aborting!";
	            std::abort();
	        }
	    }

        auto& new_txs = data.m_txs[share.hash()];
		if (!new_txs.empty())
		{
			for (auto& new_tx : new_txs)
			{
                PackStream packed_tx = pack(coin::TX_WITH_WITNESS(new_tx));
				all_new_txs[Hash(packed_tx.get_span())] = new_tx;
			}
		}

		if (m_chain->contains(share.hash()))
		{
		    ++dup_count;
			continue;
		}

		new_count++;

		m_tracker.add(share);

		// NOTE: Do NOT trim inside the processing loop. The trim in run_think()
		// handles pruning between batches. Trimming here is unsafe because
		// shares added at the tail can be freed while the loop still holds
		// dangling raw pointers to them (use-after-free).

		// Persist to LevelDB
		if (m_storage && m_storage->is_available())
		{
            std::vector<uint8_t> bytes;
            auto raw_it = m_raw_share_cache.find(share.hash());
            if (raw_it != m_raw_share_cache.end() &&
                raw_it->second.type == share.version() &&
                !raw_it->second.contents.m_data.empty())
            {
                bytes.assign(raw_it->second.contents.m_data.begin(),
                             raw_it->second.contents.m_data.end());
            }
            else
            {
                PackStream ps = pack(share);
                auto span = ps.get_span();
                bytes.assign(reinterpret_cast<const uint8_t*>(span.data()),
                             reinterpret_cast<const uint8_t*>(span.data()) + span.size());
            }
			uint64_t ver = share.version();
			std::vector<uint8_t> versioned;
			versioned.resize(8 + bytes.size());
			std::memcpy(versioned.data(), &ver, 8);
			std::memcpy(versioned.data() + 8, bytes.data(), bytes.size());

			share.ACTION({
				uint256 target = chain::bits_to_target(obj->m_bits);
				// Convert m_abswork (uint128) to uint256 by zero-padding high 128 bits
				uint256 abswork_256;
				std::copy(obj->m_abswork.begin(), obj->m_abswork.end(), abswork_256.begin());
				m_storage->store_share(obj->m_hash, versioned, obj->m_prev_hash,
				                       obj->m_absheight, obj->m_timestamp,
				                       abswork_256, target);
			});
		}
	}

    // NOTE: Do NOT call run_think() here. During download sync, the chain is
    // incomplete and run_think would mark verifiable shares as "bad" and ban
    // the peer we're downloading from — killing the sync.
    // run_think() is called periodically from the main event loop instead.
}

std::vector<ltc::ShareType> NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr)
{
    parents = std::min(parents, (uint64_t)1000/hashes.size());
	std::vector<ltc::ShareType> shares;
	for (const auto& handle_hash : hashes)
	{
		if (!m_chain->contains(handle_hash))
			continue;
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

    // Pack and send shares — use cached original bytes when available
    std::vector<chain::RawShare> rshares;
    rshares.reserve(shares.size());
    for (size_t i = 0; i < shares.size(); ++i)
    {
        auto it = m_raw_share_cache.find(shares[i].hash());
        if (it != m_raw_share_cache.end())
        {
            rshares.push_back(it->second);
        }
        else
        {
            rshares.emplace_back(shares[i].version(), pack(shares[i]));
        }
    }

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
    // Return the cached result from the most recent think() cycle.
    // Falls back to O(heads) scan only when think() hasn't run yet.
    if (!m_best_share_hash.IsNull())
        return m_best_share_hash;

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
        [this, weak_peer, target_hash](ltc::ShareReplyData reply)
        {
            m_downloading_shares.erase(target_hash);

            if (reply.m_items.empty())
            {
                LOG_DEBUG_POOL << "Empty sharereply for " << target_hash.ToString();
                return;
            }

            LOG_INFO << "Received " << reply.m_items.size() << " shares for download request";

            // Feed into processing pipeline
            HandleSharesData data;
            for (size_t idx = 0; idx < reply.m_items.size(); ++idx)
            {
                if (idx < reply.m_raw_items.size())
                    data.add(reply.m_items[idx], {}, reply.m_raw_items[idx]);
                else
                    data.add(reply.m_items[idx], {});
            }
            processing_shares(data, NetService{});

            // Find the oldest share's parent — if unknown, keep fetching
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
    if (m_target_outbound_peers == 0)
    {
        LOG_INFO << "Outbound peer dialing disabled (target=0)";
        return;
    }

    // Try to connect to peers right away
    auto try_connect_peers = [this]() {
        size_t outbound = m_outbound_addrs.size();
        if (outbound >= m_target_outbound_peers || m_connections.size() >= MAX_PEERS)
            return;

        size_t needed = m_target_outbound_peers - outbound;
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

    LOG_INFO << "run_think(): chain=" << m_tracker.chain.size()
             << " verified=" << m_tracker.verified.size()
             << " heads=" << m_tracker.chain.get_heads().size();

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
    if (!result.bad_peer_addresses.empty()) {
        for (const auto& bad_addr : result.bad_peer_addresses) {
            LOG_WARNING << "run_think: banning peer " << bad_addr.to_string()
                        << " for unverifiable shares";
            m_ban_list[bad_addr] = now + std::chrono::seconds(300);
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
        m_best_share_hash = result.best;
        LOG_INFO << "think(): best=" << result.best.GetHex().substr(0, 16) << "...";
    } else {
        LOG_WARNING << "think(): result.best is NULL — verified_tails="
                    << m_tracker.verified.get_tails().size()
                    << " verified_heads=" << m_tracker.verified.get_heads().size();
    }

    // Trim stale shares to prevent unbounded memory growth.
    // Keep 2 * chain_length per head (matches Python p2pool behavior).
    // Must trim even when result.best is null (during initial sync).
    const size_t keep_per_head = m_tracker.m_params->chain_length * 2 + 10;
    auto trim_chain = [&](auto& sc, const char* label, bool owns_data = true) {
        if (sc.size() <= keep_per_head)
            return;
        // Copy heads since trim may modify the heads map
        auto heads_copy = sc.get_heads();
        size_t total_removed = 0;
        for (auto& [head_hash, tail_hash] : heads_copy) {
            auto removed = sc.trim(head_hash, keep_per_head, owns_data);
            total_removed += removed;
        }
        if (total_removed > 0)
            LOG_INFO << "Trimmed " << total_removed << " old shares from " << label
                     << " (now " << sc.size() << ")";
    };
    // Trim verified FIRST (non-destructive: it borrows share data from chain)
    trim_chain(m_tracker.verified, "verified", /*owns_data=*/false);
    // Then trim chain (destructive: it owns the share data)
    trim_chain(m_tracker.chain, "chain");

    // Prune caches — fixed caps safe for variable chain_length (v37+)
    constexpr size_t MAX_SHARED_HASHES  = 50000;
    constexpr size_t MAX_KNOWN_TXS      = 10000;
    constexpr size_t MAX_RAW_CACHE      = 50000;

    if (m_shared_share_hashes.size() > MAX_SHARED_HASHES)
        m_shared_share_hashes.clear();
    if (m_known_txs.size() > MAX_KNOWN_TXS)
        m_known_txs.clear();
    if (m_raw_share_cache.size() > MAX_RAW_CACHE)
        m_raw_share_cache.clear();

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
