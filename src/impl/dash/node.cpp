#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/common.hpp>

#include <boost/asio/post.hpp>

#include <atomic>
#include <memory>
#include <vector>

// Dash p2pool sharechain pool-node — S8 pool-node reception, slice .4 (bodies).
//
// SLICE SCOPE (integrator-confirmed 2026-07-09, #656 a1444b4 branch-tip (awaiting merge tap)): the two
// link-deferred declarations from node.hpp — processing_shares() and
// handle_get_share() — get their REDUCED dash-native bodies here. "Reduced"
// means: the parallel X11 share_init_verify -> try_lock + m_tracker.add core,
// with think()/download/best-share/persist DEFERRED to their own later slices.
//
// This is a deliberate, non-1:1 port of src/impl/ltc/node.cpp. The DASH node is
// header-only and does NOT carry the ~8 LTC-only symbols the full ltc bodies
// touch (run_think/think, chain::PreparedList, m_raw_share_cache,
// m_best_share_hash, chain::get_reverse fork-logging, m_rejected_share_hashes,
// processing_shares_phase2 as a distinct TU method). Those are intentionally
// absent — force-fitting them would be scope creep. What remains is the minimal
// admit path that makes the Legacy/Actual dispatch (protocol_{legacy,actual}.cpp)
// actually reach the tracker: verify in parallel off the io_context, then insert
// under the non-blocking tracker lock on the io_context thread.

namespace dash
{

void NodeImpl::processing_shares(HandleSharesData& data_ref, NetService addr)
{
    // Take ownership immediately so the caller (the dispatch handler) can return
    // and free its local HandleSharesData.
    auto data = std::make_shared<HandleSharesData>(std::move(data_ref));
    size_t n = data->m_items.size();
    if (n == 0)
        return;

    // ── Phase 1 (m_verify_pool, parallel) ────────────────────────────────
    // Run share_init_verify() for each received share off the io_context thread.
    // DASH is X11 (~ms of CPU per share); the structural + PoW verify must NOT
    // block network I/O. Each share's hash computation is independent, so the
    // batch fully parallelises across the pool. A share that throws is left with
    // a null hash and skipped in phase 2.
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
                            obj->m_hash = share_init_verify(*obj, m_tracker.m_coin_params, true);
                        });
                    }
                    catch (const std::exception&)
                    {
                        // leave hash null — phase 2 will skip this share
                    }
                }

                // Last verify done → hop back to the io_context thread for the
                // tracker insertion (writes stay single-threaded on io_context).
                if (--(*remaining) == 0)
                {
                    boost::asio::post(*m_context,
                        [data, this, addr]()
                        {
                            add_verified_shares(*data, addr);
                        });
                }
            });
    }
}

void NodeImpl::add_verified_shares(HandleSharesData& data, NetService addr)
{
    // io_context thread. Non-blocking tracker lock (architectural rule,
    // node.hpp): the compute thread (a later slice's think()) takes the
    // exclusive lock; the IO thread must NEVER block on it. If think() holds the
    // lock, defer this batch onto m_pending_adds — the compute thread drains it
    // after releasing. Until the think() slice lands nothing takes the exclusive
    // lock, so try_to_lock always succeeds here.
    {
        std::unique_lock lock(m_tracker_mutex, std::try_to_lock);
        if (!lock.owns_lock())
        {
            if (m_pending_adds.size() < MAX_PENDING_ADDS)
            {
                LOG_INFO << "[ASYNC-DEFER] add_verified_shares: tracker busy, queuing "
                         << data.m_items.size() << " shares from " << addr.to_string()
                         << " (pending=" << m_pending_adds.size() + 1 << ")";
                m_pending_adds.push_back(PendingShareBatch{
                    std::make_unique<HandleSharesData>(std::move(data)), addr});
            }
            else
            {
                LOG_WARNING << "[ASYNC-DEFER] add_verified_shares: pending queue full ("
                            << MAX_PENDING_ADDS << ") — dropping batch from "
                            << addr.to_string();
            }
            return;
        }
        // Lock held for the whole insertion below.

        int32_t new_count = 0;
        int32_t dup_count = 0;
        for (auto& share : data.m_items)
        {
            // Skip shares that failed phase-1 verification (hash still null).
            if (share.hash().IsNull())
                continue;

            if (m_chain->contains(share.hash()))
            {
                ++dup_count;
                continue;
            }

            m_tracker.add(share);
            ++new_count;
        }

        if (new_count > 0)
        {
            auto as = addr.to_string();
            std::string source = (addr.port() == 0) ? as.substr(0, as.rfind(':')) : as;
            LOG_INFO << "Processing " << new_count << " shares from " << source
                     << "... (dup=" << dup_count
                     << " chain=" << m_tracker.chain.size() << ")";
        }
    }
    // Scoring / best-share selection / persist / relay ride the think() and
    // broadcast slices; slice .4 stops at tracker insertion.
}

std::vector<dash::ShareType>
NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents,
                           std::vector<uint256> stops, NetService peer_addr)
{
    // try_to_lock per the architectural rule (node.hpp): the IO thread MUST
    // never block on m_tracker_mutex. An empty reply does not disconnect the
    // requesting peer — p2pool's downloader retries against another random peer,
    // so a busy-skip just shifts the request one iteration.
    std::shared_lock<std::shared_mutex> lock(m_tracker_mutex, std::try_to_lock);
    if (!lock.owns_lock())
    {
        static int defer_log = 0;
        if (defer_log++ % 50 == 0)
            LOG_INFO << "[handle_get_share] tracker busy — returning empty to "
                     << peer_addr.to_string()
                     << " (peer will retry against another peer)";
        return {};
    }

    if (hashes.empty())
        return {};

    parents = std::min(parents, (uint64_t)1000 / hashes.size());
    std::vector<dash::ShareType> shares;
    for (const auto& handle_hash : hashes)
    {
        if (!m_chain->contains(handle_hash))
        {
            static int miss_log = 0;
            if (miss_log++ < 5)
                LOG_WARNING << "[handle_get_share] hash NOT in chain: "
                            << handle_hash.ToString().substr(0, 16)
                            << " chain_size=" << m_chain->size();
            continue;
        }
        uint64_t n = std::min(parents + 1, (uint64_t)m_chain->get_height(handle_hash));
        for (auto [hash, data] : m_chain->get_chain(handle_hash, n))
        {
            if (std::find(stops.begin(), stops.end(), hash) != stops.end())
                break;
            shares.push_back(data.share);
        }
    }

    if (!shares.empty())
        LOG_INFO << "[Pool] Sending " << shares.size() << " shares to " << peer_addr.to_string();

    return shares;
}

} // namespace dash
