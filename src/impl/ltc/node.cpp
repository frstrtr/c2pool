#include "node.hpp"

#include <core/common.hpp>
#include <core/hash.hpp>
#include <core/random.hpp>
#include <core/target_utils.hpp>
#include <sharechain/prepared_list.hpp>

#include <algorithm>
#include <fstream>
#include <iomanip>
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

static long g_rss_limit_mb = 4000;  // abort if RSS exceeds this (configurable)

// p2pool-style hashrate formatting: auto-scale to H/s, kH/s, MH/s, GH/s, TH/s
static std::string format_hashrate(double hs) {
    std::ostringstream os;
    os << std::fixed;
    if (hs >= 1e12)      os << std::setprecision(2) << hs / 1e12 << "TH/s";
    else if (hs >= 1e9)  os << std::setprecision(2) << hs / 1e9  << "GH/s";
    else if (hs >= 1e6)  os << std::setprecision(2) << hs / 1e6  << "MH/s";
    else if (hs >= 1e3)  os << std::setprecision(1) << hs / 1e3  << "kH/s";
    else                 os << std::setprecision(0) << hs         << "H/s";
    return os.str();
}

// p2pool-style duration formatting: auto-scale to seconds, hours, days, years
static std::string format_duration(double secs) {
    if (secs <= 0 || !std::isfinite(secs)) return "???";
    std::ostringstream os;
    os << std::fixed;
    if (secs >= 86400.0 * 365.25)
        os << std::setprecision(1) << secs / (86400.0 * 365.25) << " years";
    else if (secs >= 86400.0)
        os << std::setprecision(1) << secs / 86400.0 << " days";
    else if (secs >= 3600.0)
        os << std::setprecision(1) << secs / 3600.0 << " hours";
    else if (secs >= 60.0)
        os << std::setprecision(1) << secs / 60.0 << " minutes";
    else
        os << std::setprecision(1) << secs << " seconds";
    return os.str();
}

// p2pool-style Wilson score confidence interval (util/math.py:133-152)
// Returns "~X.Y% (lo-hi%)" string for binomial proportion x/n at 95% confidence.
static std::string format_binomial_conf(int x, int n, double conf = 0.95) {
    if (n == 0) return "???";
    // z for 95% ≈ 1.96 (inverse error function approximation)
    double z = 1.96;
    double p = static_cast<double>(x) / n;
    double topa = p + z * z / (2.0 * n);
    double topb = z * std::sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n));
    double bottom = 1.0 + z * z / n;
    double lo = std::max(0.0, (topa - topb) / bottom);
    double hi = std::min(1.0, (topa + topb) / bottom);
    std::ostringstream os;
    os << "~" << std::fixed << std::setprecision(1) << (100.0 * p) << "% ("
       << static_cast<int>(std::floor(100.0 * lo)) << "-"
       << static_cast<int>(std::ceil(100.0 * hi)) << "%)";
    return os.str();
}

// Wilson score confidence interval for efficiency: 1 - stale_rate, scaled
static std::string format_binomial_conf_efficiency(int stale, int n, double stale_prop) {
    if (n == 0) return "???";
    double z = 1.96;
    double p = static_cast<double>(stale) / n;
    double topa = p + z * z / (2.0 * n);
    double topb = z * std::sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n));
    double bottom = 1.0 + z * z / n;
    double lo_stale = std::max(0.0, (topa - topb) / bottom);
    double hi_stale = std::min(1.0, (topa + topb) / bottom);
    // Efficiency = (1 - stale_rate) / (1 - stale_prop)
    double denom = (stale_prop < 0.999) ? (1.0 - stale_prop) : 1.0;
    double eff = (1.0 - p) / denom;
    double eff_lo = (1.0 - hi_stale) / denom;
    double eff_hi = (1.0 - lo_stale) / denom;
    eff_lo = std::max(0.0, eff_lo);
    eff_hi = std::min(1.0, eff_hi);
    std::ostringstream os;
    os << "~" << std::fixed << std::setprecision(1) << (100.0 * eff) << "% ("
       << static_cast<int>(std::floor(100.0 * eff_lo)) << "-"
       << static_cast<int>(std::ceil(100.0 * eff_hi)) << "%)";
    return os.str();
}

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
        LOG_INFO << "[Pool] Rejecting connection from banned peer " << addr.to_string();
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
    // If peer disconnected within 10s of us sending shares, those shares
    // were likely rejected (e.g. PoW-invalid).  Mark them so we don't
    // keep re-broadcasting the same bad share on every reconnection.
    {
        auto it = m_last_broadcast_to.find(service);
        if (it != m_last_broadcast_to.end()) {
            auto elapsed = std::chrono::steady_clock::now() - it->second.when;
            if (elapsed < std::chrono::seconds(10)) {
                for (const auto& h : it->second.hashes) {
                    if (m_rejected_share_hashes.insert(h).second) {
                        LOG_WARNING << "[Pool] Marking share " << h.GetHex().substr(0, 16)
                                    << " as rejected (peer " << service.to_string()
                                    << " disconnected " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                                    << "ms after broadcast)";
                    }
                }
            }
            m_last_broadcast_to.erase(it);
        }
    }

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

    // p2pool p2p.py:595: self.get_shares.respond_all(reason)
    // Cancel pending share requests for this peer — invokes callbacks with
    // empty response so m_downloading_shares entries are cleaned up immediately
    // instead of waiting for the 5s ReplyMatcher timeout.
    {
        std::vector<uint256> to_cancel;
        for (auto& [req_id, peer_addr] : m_pending_share_reqs) {
            if (peer_addr == service)
                to_cancel.push_back(req_id);
        }
        for (auto& req_id : to_cancel) {
            m_pending_share_reqs.erase(req_id);
            m_share_getter.cancel(req_id);
        }
    }

    base_t::error(err, service, where);
}

void NodeImpl::close_connection(const NetService& service)
{
    // Same rejection tracking as error() — close_connection is another
    // path for peer disconnection.
    {
        auto it = m_last_broadcast_to.find(service);
        if (it != m_last_broadcast_to.end()) {
            auto elapsed = std::chrono::steady_clock::now() - it->second.when;
            if (elapsed < std::chrono::seconds(10)) {
                for (const auto& h : it->second.hashes)
                    m_rejected_share_hashes.insert(h);
            }
            m_last_broadcast_to.erase(it);
        }
    }

    m_pending_outbound.erase(service);
    m_outbound_addrs.erase(service);

    // Cancel pending share requests for this peer (same as in error())
    {
        std::vector<uint256> to_cancel;
        for (auto& [req_id, peer_addr] : m_pending_share_reqs) {
            if (peer_addr == service)
                to_cancel.push_back(req_id);
        }
        for (auto& req_id : to_cancel) {
            m_pending_share_reqs.erase(req_id);
            m_share_getter.cancel(req_id);
        }
    }

    base_t::close_connection(service);
}

void NodeImpl::send_version(peer_ptr peer)
{
    auto rmsg = ltc::message_version::make_raw(
        ltc::PoolConfig::ADVERTISED_PROTOCOL_VERSION,
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

std::optional<pool::PeerConnectionType> NodeImpl::handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    LOG_DEBUG_POOL << "handle message_version";
        std::unique_ptr<ltc::message_version> msg;
        msg = ltc::message_version::make(rmsg->m_data);

        LOG_INFO << "[Pool] Peer "
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
                LOG_WARNING << "[Pool] was connected to self";
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

            if (!m_chain->contains(msg->m_best_share)) {
                // Start downloading shares we don't have
                download_shares(peer, msg->m_best_share);
            } else {
                // p2pool: handle_share_hashes → handle_shares → set_best_share()
                // Even when the share is known, re-run think() to re-evaluate
                // best chain with the peer's perspective. Critical after restart:
                // shares loaded from LevelDB may have stale best_share selection.
                run_think();
            }
        }

        // Advertise ourselves to the peer (matching Python p2pool sendAdvertisement)
        {
            auto port = core::Server::listen_port();
            auto addrme_msg = ltc::message_addrme::make_raw(port);
            peer->write(std::move(addrme_msg));
        }

        return pool::PeerConnectionType::legacy;
}

void NodeImpl::processing_shares(HandleSharesData& data_ref, NetService addr)
{
    // Take ownership immediately so the caller can return/free its local.
    auto data = std::make_shared<HandleSharesData>(std::move(data_ref));
    size_t n = data->m_items.size();
    if (n == 0) return;

    // Phase 1 (thread pool, parallel): run share_init_verify() for each share.
    // share_init_verify() does scrypt-1024 (~20ms each) — must NOT block io_context.
    // Each share's hash computation is independent, so we can fully parallelize.
    auto remaining = std::make_shared<std::atomic<int>>(static_cast<int>(n));
    for (size_t i = 0; i < n; i++)
    {
        boost::asio::post(m_verify_pool,
            [i, data, remaining, this, addr]()
            {
                auto& share = data->m_items[i];
                if (share.hash().IsNull())
                {
                    try
                    {
                        share.ACTION({
                            obj->m_hash = share_init_verify(*obj, true);
                        });
                    }
                    catch (const std::exception&)
                    {
                        // leave hash null — phase 2 will skip this share
                    }
                }
                // When all verifications are done, schedule phase 2 on io_context
                if (--(*remaining) == 0)
                {
                    boost::asio::post(*m_context,
                        [data, this, addr]()
                        {
                            processing_shares_phase2(*data, addr);
                        });
                }
            });
    }
}

void NodeImpl::processing_shares_phase2(HandleSharesData& data, NetService addr)
{
    // Phase 2 (io_context thread): topological sort + chain insertion + LevelDB store.
    // All shared state (m_tracker, m_chain, m_raw_share_cache, m_storage) touched here.
    // NOTE: think() runs synchronously on the same ioc thread, so ASIO guarantees
    // handlers don't overlap.  The old 500ms defer was unnecessary and caused
    // cascading delays under high share arrival rate (ROOT CAUSE 3 of verified lag).

    // Step 1: collect verified shares (skip any that failed verification, hash still null)
    std::vector<ShareType> valid_shares;
    valid_shares.reserve(data.m_items.size());
    for (size_t idx = 0; idx < data.m_items.size(); ++idx)
    {
        auto& share = data.m_items[idx];
        if (share.hash().IsNull())
            continue; // verification failed in phase 1

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
    std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry> db_batch;
    for (int i = 0; i < (int)shares.size(); ++i)
    {
        auto& share = shares[i];

        // Safety: abort if RSS exceeds limit
        if (i % 100 == 0) {
            long rss_now = get_rss_mb();
            if (rss_now > g_rss_limit_mb) {
                LOG_ERROR << "RSS LIMIT EXCEEDED (" << rss_now << "MB > " << g_rss_limit_mb << "MB) — aborting!";
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

        ++new_count;

        // Log received share — p2pool format: "Received share diff=X hash=Y miner=Z"
        share.invoke([](auto* obj) {
            auto target = chain::bits_to_target(obj->m_bits);
            double diff = chain::target_to_difficulty(target);
            // Extract miner identity (pubkey_hash for v17/v33/v36, address script for v34/v35)
            std::string miner_hex;
            if constexpr (requires { obj->m_pubkey_hash; })
                miner_hex = obj->m_pubkey_hash.GetHex().substr(0, 16);
            else if constexpr (requires { obj->m_address; })
                miner_hex = "script";
            LOG_INFO << "Received share: diff=" << std::scientific << std::setprecision(2) << diff
                     << " hash=" << obj->m_hash.GetHex().substr(0, 16)
                     << " miner=" << miner_hex;
        });

        m_tracker.add(share);

        // Log fork detection: if this share's prev_hash has other children, it forks
        {
            uint256 prev;
            bool is_local = false;
            share.invoke([&](auto* obj) {
                prev = obj->m_prev_hash;
                is_local = (obj->peer_addr == NetService{"0.0.0.0", 0} ||
                            obj->peer_addr == NetService{});
            });
            if (is_local && !prev.IsNull()) {
                auto& rev = m_tracker.chain.get_reverse();
                auto it = rev.find(prev);
                if (it != rev.end() && it->second.size() > 1) {
                    static int fork_log = 0;
                    if (fork_log++ < 50)
                        LOG_WARNING << "[FORK] Local share forks! prev=" << prev.GetHex().substr(0,16)
                                    << " siblings=" << it->second.size()
                                    << " verified_best=" << m_best_share_hash.GetHex().substr(0,16);
                }
            }
        }

        // Verification is deferred to think() Phase 1 (called after this batch).
        // p2pool: handle_shares() only adds, set_best_share()→think() verifies.
        // Inline verification was redundant and caused double-verify CPU waste.

        // NOTE: Do NOT trim inside the processing loop. The trim in run_think()
        // handles pruning between batches. Trimming here is unsafe because
        // shares added at the tail can be freed while the loop still holds
        // dangling raw pointers to them (use-after-free).

        // Collect for batch LevelDB persist (committed atomically after loop)
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
                uint256 abswork_256;
                std::copy(obj->m_abswork.begin(), obj->m_abswork.end(), abswork_256.begin());
                c2pool::storage::SharechainStorage::ShareBatchEntry entry;
                entry.hash = obj->m_hash;
                entry.serialized_data = std::move(versioned);
                entry.prev_hash = obj->m_prev_hash;
                entry.height = obj->m_absheight;
                entry.timestamp = obj->m_timestamp;
                entry.work = abswork_256;
                entry.target = target;
                db_batch.push_back(std::move(entry));
            });
        }
    }

    // Commit all shares to LevelDB atomically (one WriteBatch for entire batch).
    // Crash-safe: either ALL shares persisted or NONE.
    if (!db_batch.empty() && m_storage && m_storage->is_available()) {
        m_storage->store_shares_batch(db_batch);
    }

    if (new_count > 0) {
        auto as2 = addr.to_string();
        std::string source = (addr.port() == 0) ? as2.substr(0, as2.rfind(':')) : as2;
        LOG_INFO << "Processing " << new_count << " shares from "
                 << source << "... (dup=" << dup_count
                 << " chain=" << m_tracker.chain.size() << ")";
    }

    // Trigger think() after every share batch (p2pool: set_best_share after handle_shares).
    // p2pool calls set_best_share() after EVERY batch with new_count > 0 — no size gate.
    // think() scores heads and updates best_share + desired set for download_shares.
    if (new_count > 0) {
        run_think();
    }
}

std::vector<ltc::ShareType> NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr)
{
    parents = std::min(parents, (uint64_t)1000/hashes.size());
	std::vector<ltc::ShareType> shares;
	for (const auto& handle_hash : hashes)
	{
		if (!m_chain->contains(handle_hash))
		{
			static int miss_log = 0;
			if (miss_log++ < 5)
				LOG_WARNING << "[handle_get_share] hash NOT in chain: "
				            << handle_hash.ToString().substr(0, 16)
				            << " chain_size=" << m_chain->size()
				            << " tracker_chain_size=" << m_tracker.chain.size();
			continue;
		}
		uint64_t n = std::min(parents+1, (uint64_t) m_chain->get_height(handle_hash));
		for (auto [hash, data] : m_chain->get_chain(handle_hash, n))
        {
			if (std::find(stops.begin(), stops.end(), hash) != stops.end())
				break;
			if (m_rejected_share_hashes.count(hash))
				continue;
			shares.push_back(data.share);
		}
	}

	if (!shares.empty())
	{
		LOG_INFO << "[Pool] Sending " << shares.size() << " shares to " << peer_addr.to_string();
	}
	return shares;
}

void NodeImpl::send_shares(peer_ptr peer, const std::vector<uint256>& share_hashes)
{
    // Collect shares that exist in our chain (skip rejected)
    std::vector<ShareType> shares;
    for (const auto& hash : share_hashes)
    {
        if (!m_chain->contains(hash))
            continue;
        if (m_rejected_share_hashes.count(hash))
            continue;
        // Retrieve the share via get_chain(hash, 1) — first element is the share itself
        for (auto [h, data] : m_chain->get_chain(hash, 1))
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

    LOG_INFO << "[Pool] Sent " << shares.size() << " shares (+" << needed_txs.size()
             << " txs) to " << peer->addr().to_string();
}

void NodeImpl::broadcast_share(const uint256& share_hash)
{
    // Walk the chain back from share_hash, collecting un-broadcast shares
    std::vector<uint256> to_send;
    int32_t height = m_chain->get_height(share_hash);
    int32_t walk = std::min(height, 5);

    for (auto [hash, data] : m_chain->get_chain(share_hash, walk))
    {
        if (m_shared_share_hashes.count(hash))
            break;
        if (m_rejected_share_hashes.count(hash))
            continue; // skip shares previously rejected by peers
        m_shared_share_hashes.insert(hash);
        to_send.push_back(hash);
    }

    if (to_send.empty())
        return;

    auto now = std::chrono::steady_clock::now();
    for (auto& [nonce, peer] : m_peers) {
        send_shares(peer, to_send);
        m_last_broadcast_to[peer->addr()] = {to_send, now};
    }
}

void NodeImpl::notify_local_share(const uint256& share_hash)
{
    // p2pool: set_best_share() runs think() synchronously on the reactor thread.
    // Both notify_local_share and run_think() execute on the same io_context thread
    // (single-threaded ASIO), so m_think_running is never set when we get here.
    //
    // CRITICAL: the old code bypassed think() and directly set m_best_share_hash.
    // This created a self-reinforcing fork: if the local share extended the wrong
    // fork (during bootstrap), think() could never override it — each new local
    // share re-asserted the wrong best via the direct override.
    //
    // Fix: use think() for ALL best_share decisions, matching p2pool exactly.
    // think() will verify the local share, score all heads, and pick the correct
    // best — including our local share if it's on the winning chain.
    if (share_hash.IsNull() || !m_tracker.chain.contains(share_hash))
        return;

    // Inline verify the local share first — it extends current best tip,
    // so parent is already verified → attempt_verify succeeds immediately.
    m_tracker.attempt_verify(share_hash);

    // Let think() decide the best share through proper scoring.
    // think() runs synchronously, so the stratum response (new work)
    // is queued after think() completes — no stale work window.
    run_think();
}

uint256 NodeImpl::best_share_hash()
{
    // p2pool's think() returns the best VERIFIED head — not the raw chain tip.
    // This ensures shares are built on a chain that all peers agree on.
    // Use think().best ONLY if it's on the VERIFIED chain.
    // p2pool's think() only considers verified shares for the best head.
    // If think().best is on an unverified fork (e.g., our own shares that
    // p2pool hasn't verified yet), fall back to the best verified head.
    // This prevents building a self-reinforcing fork that never joins
    // the main chain.
    if (!m_best_share_hash.IsNull() && m_tracker.verified.contains(m_best_share_hash)) {
        static int log_count = 0;
        if (log_count++ % 60 == 0) {
            auto h = m_tracker.verified.get_height(m_best_share_hash);
            LOG_INFO << "[best_share] using think() result height=" << h
                     << " verified=" << m_tracker.verified.size()
                     << " raw=" << (m_chain ? m_chain->size() : 0);
        }
        return m_best_share_hash;
    }
    // Fallback: if think() hasn't run yet, pick best verified head by work
    auto& verified = m_tracker.verified;
    if (verified.size() > 0) {
        uint256 best;
        uint288 best_work;
        bool first = true;
        for (const auto& [head_hash, tail_hash] : verified.get_heads()) {
            auto* idx = verified.get_index(head_hash);
            if (idx && (first || idx->work > best_work)) {
                best = head_hash;
                best_work = idx->work;
                first = false;
            }
        }
        if (!best.IsNull()) {
            static int log_count2 = 0;
            auto best_height = verified.get_height(best);
            if (log_count2++ % 60 == 0)
                LOG_INFO << "[best_share] fallback VERIFIED head height=" << best_height
                         << " work=" << best_work.GetHex().substr(0, 16)
                         << " verified=" << verified.size()
                         << " raw=" << (m_chain ? m_chain->size() : 0);
            return best;
        }
    }

    // No verified chain yet — return null to prevent creating shares with
    // MAX_TARGET max_bits.  p2pool does the same: best_share_var.value = None
    // until the verified chain exists, and generate_transaction refuses to
    // create work when best_share is None (with peers connected).
    //
    // On a genesis node (no peers, fresh chain), this returns ZERO which
    // triggers genesis share creation with 100% donation payout.
    if (!m_peers.empty()) {
        static int wait_log = 0;
        if (wait_log++ % 12 == 0)
            LOG_INFO << "[best_share] waiting for verified chain (peers="
                     << m_peers.size() << " raw="
                     << (m_chain ? m_chain->size() : 0) << ")";
        return uint256::ZERO;
    }

    // True genesis: no peers at all — use raw chain to bootstrap
    if (!m_chain || m_chain->size() == 0)
        return uint256::ZERO;

    uint256 best;
    int32_t best_height = -1;
    for (const auto& [head_hash, tail_hash] : m_chain->get_heads()) {
        auto h = m_chain->get_height(head_hash);
        if (h > best_height) {
            best = head_hash;
            best_height = h;
        }
    }
    static int raw_log = 0;
    if (raw_log++ % 60 == 0)
        LOG_INFO << "[best_share] using RAW head (genesis, no peers) height=" << best_height;
    return best;
}

void NodeImpl::download_shares(peer_ptr /*unused_peer*/, const uint256& target_hash)
{
    // p2pool node.py:108-141 download_shares() — exact translation.
    //
    // Key differences from old c2pool implementation:
    // 1. RANDOM peer selection (not the reporting peer)
    // 2. RANDOM parent count 0-499 (not fixed 500)
    // 3. STOPS list: known heads + their 10th parents (not empty)
    // 4. Log format: "Requesting parent share XXXX from IP:PORT"

    // Already downloading this hash — avoid duplicate requests
    if (m_downloading_shares.count(target_hash))
        return;
    m_downloading_shares.insert(target_hash);

    // p2pool: if len(self.peers) == 0: sleep(1); continue
    if (m_peers.empty()) {
        m_downloading_shares.erase(target_hash);
        return;
    }

    // p2pool: peer = random.choice(self.peers.values())
    auto peer_it = m_peers.begin();
    if (m_peers.size() > 1) {
        std::advance(peer_it, core::random::random_uint256().GetLow64() % m_peers.size());
    }
    auto& peer = peer_it->second;

    // p2pool: parents=random.randrange(500)
    uint64_t parents = core::random::random_uint256().GetLow64() % 500;

    // p2pool: stops=list(set(tracker.heads) | set(
    //   tracker.get_nth_parent_hash(head, min(max(0, height-1), 10))
    //   for head in tracker.heads))[:100]
    //
    // IMPORTANT: On cold-start with fragmented chains (many heads, 0 verified),
    // including ALL heads as stops causes the responding peer to stop walking
    // after just 10-15 shares (every share in their chain hits one of our stops).
    // Fix: only use stops when we have a verified chain (non-fragmented state).
    std::vector<uint256> stops;
    bool has_verified_chain = !m_tracker.verified.get_heads().empty();
    if (has_verified_chain) {
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
    // Cold-start: empty stops → peer sends full chain from target_hash

    auto req_id = core::random::random_uint256();
    std::vector<uint256> hashes = { target_hash };

    // Track req_id → peer for selective cancellation on disconnect
    m_pending_share_reqs[req_id] = peer->addr();

    // p2pool: print 'Requesting parent share %s from %s'
    LOG_INFO << "[Pool] Requesting parent share "
             << target_hash.ToString().substr(0,16)
             << " from " << peer->addr().to_string()
             << " (parents=" << parents << " stops=" << stops.size() << ")";

    // weak_ptr prevents use-after-free if peer disconnects before reply
    std::weak_ptr<pool::Peer<ltc::Peer>> weak_peer = peer;
    auto peer_addr_for_log = peer->addr();

    request_shares(req_id, peer, hashes, parents, stops,
        [this, weak_peer, target_hash, peer_addr_for_log, req_id](ltc::ShareReplyData reply)
        {
            m_downloading_shares.erase(target_hash);
            m_pending_share_reqs.erase(req_id);

            if (reply.m_items.empty())
            {
                // Empty reply = timeout or peer had no matching shares (p2pool: sleep(1), continue)
                LOG_INFO << "[Pool] Share request completed with no data for "
                         << target_hash.ToString().substr(0,16)
                         << " (timeout or empty reply from " << peer_addr_for_log.to_string() << ")";
                return;
            }

            LOG_INFO << "[Pool] Received " << reply.m_items.size() << " shares for download request";

            // Feed into processing pipeline
            HandleSharesData data;
            for (size_t idx = 0; idx < reply.m_items.size(); ++idx)
            {
                if (idx < reply.m_raw_items.size())
                    data.add(reply.m_items[idx], {}, reply.m_raw_items[idx]);
                else
                    data.add(reply.m_items[idx], {});
            }
            processing_shares(data, peer_addr_for_log);

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

    // load_sharechain iterates the height index and loads each share.
    // Limit to keep_per_head shares to avoid loading unbounded history
    // into memory (LevelDB is never pruned, so it accumulates forever).
    LOG_INFO << "[Pool] Scanning LevelDB height index for persisted shares...";
    auto t0 = std::chrono::steady_clock::now();
    auto all_hashes = m_storage->get_shares_by_height_range(0, UINT64_MAX);
    auto scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    {
        std::set<uint256> unique(all_hashes.begin(), all_hashes.end());
        LOG_INFO << "[Pool] Height index scan: " << all_hashes.size() << " entries ("
                 << unique.size() << " unique) in " << scan_ms << "ms";
    }
    if (all_hashes.empty())
    {
        LOG_INFO << "No persisted shares found in LevelDB";
        return;
    }

    const size_t keep_per_head = PoolConfig::chain_length() * 2 + 10;
    const size_t total_in_db = all_hashes.size();

    // Only load the most recent shares (highest height = end of vector)
    size_t skip = 0;
    if (total_in_db > keep_per_head)
    {
        skip = total_in_db - keep_per_head;
        LOG_INFO << "[Pool] LevelDB has " << total_in_db << " shares, loading only newest "
                 << keep_per_head << " (skipping " << skip << " old shares)";
    }

    const size_t to_load = total_in_db - skip;
    LOG_INFO << "[Pool] Loading shares from LevelDB: " << to_load << " shares to process...";
    int loaded = 0, skipped_contains = 0, skipped_load = 0, skipped_small = 0;
    std::vector<uint256> verified_hashes; // shares to pre-populate into verified
    for (size_t i = skip; i < total_in_db; ++i)
    {
        const auto& hash = all_hashes[i];
        std::vector<uint8_t> data;
        core::ShareMetadata meta;
        if (!m_storage->load_share(hash, data, meta)) {
            ++skipped_load;
            continue;
        }
        if (data.size() < 8) {
            ++skipped_small;
            continue;
        }

        try
        {
            // First 8 bytes = version (uint64_t LE), rest = packed share
            uint64_t ver;
            std::memcpy(&ver, data.data(), 8);

            std::vector<unsigned char> share_bytes(data.begin() + 8, data.end());
            PackStream ps(share_bytes);

            auto share = ltc::load_share(static_cast<int64_t>(ver), ps, NetService{"database", 0});
            // m_hash is not part of the serialized format — it's computed
            // during share_check validation.  Restore it from the LevelDB key.
            share.ACTION({ obj->m_hash = hash; });
            if (!m_chain->contains(share.hash()))
            {
                m_tracker.add(share);
                loaded++;

                // p2pool known_verified: pre-populate verified tracker without re-verification
                if (meta.is_verified)
                    verified_hashes.push_back(share.hash());

                if (loaded % 1000 == 0) {
                    size_t progress = i - skip + 1;
                    LOG_INFO << "[Pool] Loading shares: " << progress << "/" << to_load
                             << " (" << (100 * progress / to_load) << "%)";
                }
            } else {
                ++skipped_contains;
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING << "Failed to load share " << hash.ToString()
                        << " from LevelDB: " << e.what();
        }
    }

    // Pre-populate verified chain from persisted known_verified set (p2pool node.py:190-192).
    // Shares are loaded by ascending height, so parent-before-child order is guaranteed.
    int pre_verified = 0;
    for (const auto& vh : verified_hashes) {
        if (m_tracker.chain.contains(vh) && !m_tracker.verified.contains(vh)) {
            try {
                auto& share_var = m_tracker.chain.get_share(vh);
                m_tracker.verified.add(share_var);
                ++pre_verified;
            } catch (...) {}
        }
    }
    if (pre_verified > 0)
        LOG_INFO << "[Pool] Pre-populated " << pre_verified << " verified shares from LevelDB";

    LOG_INFO << "[Pool] Loaded " << loaded << " shares from LevelDB storage"
             << " (DB total: " << total_in_db << ", limit: " << keep_per_head
             << ", skipped: load=" << skipped_load << " small=" << skipped_small
             << " dup=" << skipped_contains << ")";

    // Prune old shares from LevelDB that we skipped
    if (skip > 0)
    {
        size_t pruned = 0;
        for (size_t i = 0; i < skip; ++i)
        {
            if (m_storage->remove_share(all_hashes[i]))
                ++pruned;
        }
        LOG_INFO << "[Pool] Pruned " << pruned << " old shares from LevelDB";
    }
}

void NodeImpl::flush_verified_to_leveldb()
{
    if (m_verified_flush_buf.empty() || !m_storage || !m_storage->is_available())
        return;
    m_storage->mark_shares_verified(m_verified_flush_buf);
    m_verified_flush_buf.clear();
}

void NodeImpl::shutdown()
{
    LOG_INFO << "[Pool] NodeImpl shutdown: flushing pending LevelDB buffers...";
    flush_verified_to_leveldb();
    if (!m_removal_flush_buf.empty() && m_storage && m_storage->is_available())
    {
        m_storage->remove_shares_batch(m_removal_flush_buf);
        m_removal_flush_buf.clear();
    }
    LOG_INFO << "[Pool] NodeImpl shutdown complete";
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
        if (outbound >= m_target_outbound_peers || m_connections.size() >= m_max_peers)
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

            LOG_INFO << "[Pool] Dialing outbound peer " << ap.addr.to_string();
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

void NodeImpl::prune_shares(const uint256& /*best_share*/)
{
    // Matches p2pool node.py:381-398 tail-dropping exactly:
    // - Check each tail: if min(height(head) for heads) < 2*CL+10 → skip
    // - Remove ONE child of qualifying tail per iteration
    // - Loop up to 1000 times (gradual, not bulk)
    // - Also cascade removal to verified
    const auto CL = static_cast<int32_t>(PoolConfig::chain_length());
    const int32_t min_depth = 2 * CL + 10;

    for (int iter = 0; iter < 1000; ++iter)
    {
        // p2pool node.py:382-398: find ONE qualifying tail child to remove
        uint256 to_remove;
        bool found = false;
        auto tails_copy = m_tracker.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            // Check min height across ALL heads for this tail
            int32_t min_height = std::numeric_limits<int32_t>::max();
            for (auto& hh : head_hashes) {
                if (!m_tracker.chain.contains(hh)) continue;
                try {
                    min_height = std::min(min_height, m_tracker.chain.get_height(hh));
                } catch (...) { continue; }
            }
            if (min_height < min_depth) continue;

            // Find ONE child of this tail (p2pool removes one at a time)
            auto& rev = m_tracker.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end() && !rev_it->second.empty()) {
                to_remove = *rev_it->second.begin();
                found = true;
                break;  // one per iteration
            }
        }

        if (!found) break;

        if (!m_tracker.chain.contains(to_remove)) continue;
        // p2pool node.py:393 — safety check: parent must be a tail
        auto* idx = m_tracker.chain.get_index(to_remove);
        if (!idx) continue;
        bool parent_is_tail = m_tracker.chain.get_tails().contains(idx->tail);
        if (!parent_is_tail) {
            LOG_DEBUG_POOL << "prune skip: parent " << idx->tail.ToString().substr(0,16)
                           << " not a tail";
            continue;
        }
        if (m_tracker.verified.contains(to_remove))
            m_tracker.verified.remove(to_remove, /*owns_data=*/false);
        m_tracker.chain.remove(to_remove);
    }

    // Cache cleanup (kept from original)
    if (m_shared_share_hashes.size() > m_max_shared_hashes)
        m_shared_share_hashes.clear();
    if (m_known_txs.size() > m_max_known_txs)
        m_known_txs.clear();
    if (m_raw_share_cache.size() > m_max_raw_shares)
        m_raw_share_cache.clear();
}

// (old phases 5-7 removed — replaced by p2pool-style pruning above)

void NodeImpl::run_think()
{
    // Rate-limit: skip if called too recently
    auto now = std::chrono::steady_clock::now();
    if (now - m_last_think_time < THINK_MIN_INTERVAL)
        return;
    m_last_think_time = now;

    // Skip if a think() is already running on the think pool.
    // Litecoin Core pattern: validation runs on its own thread, never blocking
    // the net/ioc thread.  The atomic flag prevents concurrent think + phase2.
    if (m_think_running.exchange(true))
        return;

    // p2pool-style periodic heartbeat (matches main.py:603-648)
    {
        auto chain_sz  = m_tracker.chain.size();
        auto verified  = m_tracker.verified.size();
        auto peers     = m_peers.size();

        // Count incoming peers (not in m_outbound_addrs)
        int incoming_peers = 0;
        for (auto& [nonce, peer] : m_peers) {
            if (peer && !m_outbound_addrs.contains(peer->addr()))
                ++incoming_peers;
        }

        // p2pool-compatible chain height: verified.get_height(best_share)
        // This walks from best_share to chain end, matching p2pool's tracker.get_height().
        // chain.get_height() includes LevelDB history beyond pruning — too large.
        int height = 0;
        int verified_height = 0;
        if (!m_best_share_hash.IsNull()) {
            if (m_tracker.chain.contains(m_best_share_hash))
                height = m_tracker.chain.get_height(m_best_share_hash);
            if (m_tracker.verified.contains(m_best_share_hash))
                verified_height = m_tracker.verified.get_height(m_best_share_hash);
        }
        if (height == 0 && verified > 0)
            height = static_cast<int>(verified);

        // L1: p2pool format — "c2pool: N shares in chain (V verified/T total) Peers: P (I incoming)"
        LOG_INFO << "c2pool: " << height << " shares in chain ("
                 << verified << " verified/" << chain_sz << " total)"
                 << " Peers: " << peers << " (" << incoming_peers << " incoming)";

        // L2: Local hashrate + DOA% + time window + expected time to share
        // p2pool: " Local: XH/s in last Y minutes Local dead on arrival: ~Z% (lo-hi%) Expected time to share: T"
        uint32_t share_bits = 0;
        if (!m_best_share_hash.IsNull() && m_tracker.chain.contains(m_best_share_hash)) {
            m_tracker.chain.get(m_best_share_hash).share.invoke([&](auto* s) {
                share_bits = s->m_bits;
            });
        }

        if (m_local_rate_stats_fn) {
            auto stats = m_local_rate_stats_fn();
            std::ostringstream local_line;
            local_line << " Local: " << format_hashrate(stats.hashrate);
            if (stats.effective_dt > 0)
                local_line << " in last " << format_duration(stats.effective_dt);
            local_line << " Local dead on arrival: "
                       << format_binomial_conf(stats.dead_datums, stats.total_datums);
            // Expected time to share: target_to_average_attempts(share_bits) / hashrate
            if (stats.hashrate > 0 && share_bits != 0) {
                auto share_target = chain::bits_to_target(share_bits);
                auto share_aps = chain::target_to_average_attempts(share_target);
                double ets = static_cast<double>(share_aps.GetLow64()) / stats.hashrate;
                local_line << " Expected time to share: " << format_duration(ets);
            }
            LOG_INFO << local_line.str();
        } else if (m_local_hashrate_fn) {
            double local_hs = m_local_hashrate_fn();
            LOG_INFO << " Local: " << format_hashrate(local_hs);
        }

        // Count orphan/DOA shares in best chain via CIterator (handles segments)
        int orphan_count = 0, doa_count = 0, total_recent = 0;
        uint256 walk_start = m_best_share_hash;
        if (walk_start.IsNull() || !m_tracker.chain.contains(walk_start)) {
            auto& vheads = m_tracker.verified.get_heads();
            if (!vheads.empty())
                walk_start = vheads.begin()->first;
        }
        if (!walk_start.IsNull() && m_tracker.chain.contains(walk_start)) {
            int window = std::min(height, static_cast<int>(
                std::min(size_t(3600) / PoolConfig::share_period(), size_t(height))));
            if (window > 0) {
                auto walkable = m_tracker.chain.get_height(walk_start);
                auto walk_n = std::min(window, walkable);
                if (walk_n > 0) {
                    try {
                        auto view = m_tracker.chain.get_chain(walk_start, walk_n);
                        for (auto [hash, data] : view) {
                            data.share.invoke([&](auto* s) {
                                if (s->m_stale_info == ltc::StaleInfo::orphan) ++orphan_count;
                                else if (s->m_stale_info == ltc::StaleInfo::doa) ++doa_count;
                            });
                            ++total_recent;
                        }
                    } catch (...) {}
                }
            }
        }
        double stale_prop = total_recent > 0 ? static_cast<double>(orphan_count + doa_count) / total_recent : 0.0;

        // L3: Shares line — "Shares: N (O orphan, D dead) Stale rate: ~X% Efficiency: ~Y% Current payout: Z tLTC"
        {
            std::ostringstream shares_line;
            shares_line << " Shares: " << chain_sz
                        << " (" << orphan_count << " orphan, " << doa_count << " dead)"
                        << " Stale rate: " << format_binomial_conf(orphan_count + doa_count, total_recent)
                        << " Efficiency: " << format_binomial_conf_efficiency(orphan_count + doa_count, total_recent, stale_prop);

            // Current payout from PPLNS cache.
            // p2pool matches its -a address (which IS the miner's address).
            // c2pool: match --address script, AND also try local miner scripts
            // by checking PPLNS output scripts against known local pubkey_hashes
            // from the stratum server's RateMonitor (via get_local_addr_rates).
            if (m_current_pplns_fn) {
                auto outputs = m_current_pplns_fn();
                uint64_t my_payout = 0;

                // Build set of local scripts from --address + local miner pubkeys
                std::set<std::string> local_scripts;
                if (!m_node_payout_script_hex.empty())
                    local_scripts.insert(m_node_payout_script_hex);

                // Add local miner scripts from stratum pubkey_hashes
                if (m_local_miner_scripts_fn) {
                    for (const auto& s : m_local_miner_scripts_fn())
                        local_scripts.insert(s);
                }

                for (const auto& [script, amount] : outputs) {
                    if (local_scripts.count(script))
                        my_payout += amount;
                }
                if (my_payout > 0) {
                    double coins = static_cast<double>(my_payout) / 1e8;
                    shares_line << " Current payout: (" << std::fixed << std::setprecision(4) << coins
                                << ")=" << coins << " tLTC";
                }
            }

            shares_line << " [heads=" << m_tracker.chain.get_heads().size()
                        << " v_heads=" << m_tracker.verified.get_heads().size()
                        << " rss=" << get_rss_mb() << "MB]";
            LOG_INFO << shares_line.str();
        }

        // L4: Pool hashrate + expected time to block
        // p2pool: " Pool: XH/s Stale rate: Y.Y% Expected time to block: Z"
        if (height > 2) {
            try {
                auto aps = m_tracker.get_pool_attempts_per_second(
                    m_best_share_hash,
                    std::min(height - 1, static_cast<int>(PoolConfig::TARGET_LOOKBEHIND)),
                    /*min_work=*/false);
                double pool_hs = static_cast<double>(aps.GetLow64());
                double real_pool_hs = (stale_prop < 0.999 && pool_hs > 0)
                    ? pool_hs / (1.0 - stale_prop) : pool_hs;

                // ETB: use block target (network difficulty) from best share's header
                double etb_secs = 0;
                uint32_t block_bits = 0;
                if (!m_best_share_hash.IsNull() && m_tracker.chain.contains(m_best_share_hash)) {
                    m_tracker.chain.get(m_best_share_hash).share.invoke([&](auto* s) {
                        block_bits = s->m_min_header.m_bits;
                    });
                }
                if (real_pool_hs > 0 && block_bits != 0) {
                    auto block_target = chain::bits_to_target(block_bits);
                    auto block_aps = chain::target_to_average_attempts(block_target);
                    etb_secs = static_cast<double>(block_aps.GetLow64()) / real_pool_hs;
                    if (block_aps.IsNull() && !block_target.IsNull())
                        etb_secs = 1e18;
                }

                LOG_INFO << " Pool: " << format_hashrate(real_pool_hs)
                         << " Stale rate: " << std::fixed << std::setprecision(1)
                         << (100.0 * stale_prop) << "% Expected time to block: "
                         << format_duration(etb_secs);
            } catch (...) {}
        }
    }

    // Capture block_rel_height fn by value for thread safety
    auto block_rel_height = m_block_rel_height_fn
        ? m_block_rel_height_fn
        : std::function<int32_t(uint256)>([](uint256) -> int32_t { return 0; });

    // Run think() synchronously on the ioc thread (matching p2pool).
    // p2pool's think() runs synchronously in set_best_share() — no thread pool.
    // Running on a separate thread caused SIGSEGV: prune_shares() freed shares
    // that think() was traversing via prev pointers.
    {
          try {
            uint256 prev_block;
            uint32_t bits = 0;

            LOG_INFO << "[Pool] think() starting: chain=" << m_tracker.chain.size()
                     << " verified=" << m_tracker.verified.size();
            auto think_t0 = std::chrono::steady_clock::now();
            auto result = m_tracker.think(block_rel_height, prev_block, bits);
            auto think_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - think_t0).count();
            if (think_ms > 1000)
                LOG_INFO << "[Pool] think() completed in " << think_ms << "ms";

            // Process results inline (same ioc thread — no race with phase2)
            {
                    // p2pool: pruning happens in clean_tracker() (every 5s timer),
                    // NOT in set_best_share(). Verification must complete BEFORE
                    // pruning — otherwise pruned shares break cached deltas.
                    // prune_shares moved to clean_tracker() below.

                    // Ban peers that provided invalid/unverifiable shares.
                    // Skip localhost:0 — that's our own locally created shares
                    // which can fail GENTX during chain growth (timing race, not a bug).
                    auto now = std::chrono::steady_clock::now();
                    for (const auto& bad_addr : result.bad_peer_addresses) {
                        if (bad_addr.port() == 0)
                            continue; // local share — don't ban ourselves
                        LOG_WARNING << "run_think: banning peer " << bad_addr.to_string()
                                    << " for unverifiable shares";
                        m_ban_list[bad_addr] = now + m_ban_duration;
                    }

                    // Expire old bans
                    for (auto it = m_ban_list.begin(); it != m_ban_list.end(); ) {
                        if (it->second <= now)
                            it = m_ban_list.erase(it);
                        else
                            ++it;
                    }

                    // p2pool node.py:108-141: download_shares is a continuous loop
                    // that re-requests every cycle with no dedup set.
                    // Safety: clear stale entries each cycle. Normally cleaned up by
                    // ReplyMatcher timeout callbacks and peer disconnect cancellation,
                    // but this ensures no hash gets permanently stuck.
                    m_downloading_shares.clear();

                    if (!result.desired.empty() && !m_peers.empty()) {
                        for (auto& [peer_addr, hash] : result.desired) {
                            // Pick random peer (p2pool: random.choice(self.peers.values()))
                            auto peer_it = m_peers.begin();
                            if (m_peers.size() > 1)
                                std::advance(peer_it, core::random::random_uint256().GetLow64() % m_peers.size());
                            download_shares(peer_it->second, hash);
                        }
                    }

                    // Save top-5 heads for clean_tracker (p2pool node.py:363)
                    m_last_top5_heads = std::move(result.top5_heads);

                    // Update best share — only trigger work update when best changes.
                    // p2pool: best_share_var.set(best) fires Variable.changed
                    // which ONLY fires when value differs — new_work_event follows.
                    // If best is unchanged (e.g. fork share, clean_tracker tick),
                    // the miner's prev_share and PPLNS are identical — no new work needed.
                    if (!result.best.IsNull()) {
                        bool changed = (m_best_share_hash != result.best);
                        m_best_share_hash = result.best;
                        if (changed) {
                            LOG_INFO << "[Pool] think(): best=" << result.best.GetHex();
                            if (m_on_best_share_changed) m_on_best_share_changed();
                        }
                    } else {
                        LOG_WARNING << "[Pool] think(): result.best is NULL — verified_tails="
                                    << m_tracker.verified.get_tails().size()
                                    << " verified_heads=" << m_tracker.verified.get_heads().size();
                    }

                    m_think_running.store(false);

                    // Flush any remaining verified hashes to LevelDB
                    flush_verified_to_leveldb();

                    // If think() Phase 2 hit its budget, schedule a continuation
                    // so the io_context can process network I/O between batches.
                    if (m_tracker.m_think_needs_continue) {
                        boost::asio::post(*m_context, [this]() { run_think(); });
                    }
            }

          } catch (const std::exception& e) {
            LOG_ERROR << "run_think() failed: " << e.what();
            m_think_running.store(false);
          } catch (...) {
            LOG_ERROR << "run_think() failed: unknown error";
            m_think_running.store(false);
          }
    }
}

// Periodic maintenance: eat stale heads, drop tails.
// Direct translation of p2pool node.py:355-402 clean_tracker().
void NodeImpl::clean_tracker()
{
    // Prevent concurrent clean_tracker (timer re-entry safety).
    if (m_clean_running.exchange(true))
        return;
    // RAII guard: always clear flag on exit (even on exception)
    struct CleanGuard {
        std::atomic<bool>& flag;
        ~CleanGuard() { flag.store(false); }
    } clean_guard{m_clean_running};

    // Step 1: Run think() to get current scoring + remove bad shares
    // (also populates m_last_top5_heads)
    run_think();

    auto now_sec = static_cast<int64_t>(std::time(nullptr));
    auto CL = static_cast<int32_t>(ltc::PoolConfig::chain_length());

    // Step 2: Eat stale heads (p2pool node.py:358-378)
    // Three guards protect useful heads:
    //   1. Top-5 scored heads (decorated_heads[-5:])
    //   2. Heads seen < 300s ago
    //   3. Unverified heads whose tail has recent child activity (< 120s)
    if (!m_last_top5_heads.empty())  // p2pool node.py:359: if decorated_heads:
    {
        // Build top-5 set for O(1) lookup
        std::set<uint256> top5_set(m_last_top5_heads.begin(), m_last_top5_heads.end());

        for (int iter = 0; iter < 1000; ++iter)
        {
            std::vector<uint256> to_remove;
            auto heads_copy = m_tracker.chain.get_heads();
            for (auto& [head_hash, tail_hash] : heads_copy)
            {
                if (!m_tracker.chain.contains(head_hash)) continue;

                // Guard 1: keep top-5 scored heads (p2pool node.py:363)
                if (top5_set.count(head_hash)) continue;

                // Guard 2: keep heads seen < 300s ago (p2pool node.py:366)
                auto* idx = m_tracker.chain.get_index(head_hash);
                if (!idx || idx->time_seen > now_sec - 300) continue;

                // Guard 3: keep unverified heads with recent tail activity (p2pool node.py:369)
                if (!m_tracker.verified.contains(head_hash))
                {
                    auto& rev = m_tracker.chain.get_reverse();
                    auto rev_it = rev.find(tail_hash);
                    if (rev_it != rev.end() && !rev_it->second.empty())
                    {
                        int64_t max_child_ts = 0;
                        for (const auto& child : rev_it->second)
                        {
                            auto* cidx = m_tracker.chain.get_index(child);
                            if (cidx && cidx->time_seen > max_child_ts)
                                max_child_ts = cidx->time_seen;
                        }
                        if (max_child_ts > now_sec - 120) continue;
                    }
                }

                to_remove.push_back(head_hash);
            }

            if (to_remove.empty()) break;

            for (const auto& h : to_remove)
            {
                try {
                    if (m_tracker.verified.contains(h))
                        m_tracker.verified.remove(h, /*owns_data=*/false);
                    if (m_tracker.chain.contains(h))
                        m_tracker.chain.remove(h);
                } catch (...) {}
            }
        }
    }

    // Step 3: Drop tails — remove ALL children of qualifying tails.
    // Exact translation of p2pool node.py:382-398.
    // p2pool has NO best-chain protection — the 2*CHAIN_LENGTH+10 threshold
    // ensures only shares far beyond the PPLNS window are removed.
    {
        int total_dropped = 0;
        for (int iter = 0; iter < 1000; ++iter)
        {
            std::vector<uint256> to_remove;
            auto tails_copy = m_tracker.chain.get_tails();
            for (auto& [tail_hash, head_hashes] : tails_copy)
            {
                int32_t min_height = 0;  // default 0 → skip if no valid heads
                for (auto& hh : head_hashes) {
                    if (!m_tracker.chain.contains(hh)) continue;
                    auto h = m_tracker.chain.get_height(hh);
                    if (min_height == 0 || h < min_height)
                        min_height = h;
                }
                if (min_height < 2 * CL + 10) continue;

                if (iter == 0) {
                    LOG_WARNING << "[drop-tails-QUALIFY] tail=" << tail_hash.GetHex().substr(0,16)
                                << " min_height=" << min_height << " threshold=" << (2*CL+10)
                                << " n_heads=" << head_hashes.size()
                                << " chain_size=" << m_tracker.chain.size();
                }

                // p2pool node.py:386: to_remove.update(tracker.reverse.get(tail, set()))
                auto& rev = m_tracker.chain.get_reverse();
                auto rev_it = rev.find(tail_hash);
                if (rev_it != rev.end()) {
                    for (const auto& child : rev_it->second)
                        to_remove.push_back(child);
                }
            }

            if (to_remove.empty()) break;

            // p2pool node.py:392-398
            for (const auto& aftertail : to_remove)
            {
                try {
                    if (!m_tracker.chain.contains(aftertail)) continue;
                    // p2pool node.py:393: if items[aftertail].previous_hash not in tails: continue
                    auto* idx = m_tracker.chain.get_index(aftertail);
                    if (!idx) continue;
                    if (!m_tracker.chain.get_tails().count(idx->tail)) {
                        continue;
                    }
                    if (m_tracker.verified.contains(aftertail))
                        m_tracker.verified.remove(aftertail, /*owns_data=*/false);
                    m_tracker.chain.remove(aftertail);
                    ++total_dropped;
                } catch (...) {}
            }
        }
        if (total_dropped > 0)
            LOG_INFO << "[clean-drop-tails] dropped " << total_dropped << " shares"
                     << " chain_size=" << m_tracker.chain.size()
                     << " heads=" << m_tracker.chain.get_heads().size();
    }

    // Step 4: Update best share (p2pool node.py:402)
    run_think();

    // Step 5: Flush pruned shares from LevelDB (p2pool main.py:269-270)
    if (!m_removal_flush_buf.empty() && m_storage && m_storage->is_available())
    {
        auto count = m_removal_flush_buf.size();
        if (m_storage->remove_shares_batch(m_removal_flush_buf))
            LOG_INFO << "[clean-leveldb] removed " << count << " pruned shares from LevelDB";
        else
            LOG_WARNING << "[clean-leveldb] batch remove failed, count=" << count;
        m_removal_flush_buf.clear();
    }

    // Orphan/fork diagnostics — understand chain topology
    {
        auto& chain = m_tracker.chain;
        auto& verified = m_tracker.verified;
        size_t total_heads = chain.get_heads().size();
        size_t verified_heads = verified.get_heads().size();
        size_t total_tails = chain.get_tails().size();

        // Count c2pool's own shares in verified vs total
        int local_in_chain = 0, local_in_verified = 0;
        int total_in_chain = 0;
        for (auto& [head_hash, tail_hash] : chain.get_heads()) {
            auto height = chain.get_height(head_hash);
            total_in_chain += height;
            // Check if this head is in verified
            if (verified.contains(head_hash)) {
                // Walk backward and count local shares
                // (expensive — only sample first 50)
            }
        }

        static int diag_count = 0;
        if (diag_count++ % 6 == 0) { // every 30s (5s * 6)
            LOG_INFO << "[FORK-DIAG] heads=" << total_heads
                     << " verified_heads=" << verified_heads
                     << " tails=" << total_tails
                     << " chain=" << chain.size()
                     << " verified=" << verified.size()
                     << " gap=" << (chain.size() - verified.size())
                     << " best_h=" << (m_best_share_hash.IsNull() ? 0
                         : (verified.contains(m_best_share_hash)
                            ? verified.get_height(m_best_share_hash) : -1))
                     << " chain_h=" << (m_best_share_hash.IsNull() ? 0
                         : (chain.contains(m_best_share_hash)
                            ? chain.get_height(m_best_share_hash) : -1))
                     << " best=" << (m_best_share_hash.IsNull()
                         ? std::string("null")
                         : m_best_share_hash.GetHex().substr(0, 16));
        }
    }
}

bool NodeImpl::is_banned(const NetService& addr) const
{
    auto it = m_ban_list.find(addr);
    if (it == m_ban_list.end()) return false;
    return it->second > std::chrono::steady_clock::now();
}

void NodeImpl::set_rss_limit_mb(long mb)
{
    g_rss_limit_mb = mb;
}

} // namespace ltc
