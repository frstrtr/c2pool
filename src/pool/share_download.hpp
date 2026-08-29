// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Shared sharechain-download helpers (#754) — the coin-agnostic half of the
// p2pool share-download loop, extracted from the PROVEN ltc reference
// (src/impl/ltc/node.cpp:968-1105 download_shares + :1600-1618 think()-desired
// dispatch), which itself mirrors the python p2pool oracle (node.py
// Node.download_shares + p2p.py Protocol.get_shares).
//
// ONE downloader, reused per coin (operator direction): every coin node
// (ltc/btc/dgb/dash/bch) runs the same request-planning + retry-gating logic;
// only the per-coin seams (message codec instance, ShareType, tracker,
// processing pipeline) stay in each NodeImpl. This header is ADDITIVE shared
// core: nothing existing links it until a coin opts in (dash first — #754);
// migrating the ltc/btc/dgb inline copies onto it is a mechanical follow-up.
//
// Header-only on purpose: the dash pool-node KAT targets are link-deferred
// (they instantiate NodeImpl without the node.cpp TU), and the download-leg
// KAT (test/test_dash_share_download.cpp) must drive the same code the node
// runs without sockets.

#include <core/uint256.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace pool::download
{

// oracle node.py download loop: parents=random.randrange(500) — a RANDOM chunk
// size per request, NOT a fixed 500 (mirrors ltc node.cpp:1010).
inline constexpr uint64_t PARENTS_RANGE = 500;

// oracle: stops list truncated [:100] (node.py download loop; ltc:1035-1039).
inline constexpr std::size_t STOPS_CAP = 100;

// Empty-reply cap per hash per think() cycle (ltc node.hpp:504). p2pool has no
// permanent blacklist — it re-adds desired from scratch every loop iteration
// with sleep(1) backoff; the cap is reset each think() cycle to match
// (permanent blacklisting stalls bootstrap: ltc node.cpp:1603-1608).
inline constexpr int MAX_EMPTY_RETRIES = 3;

// De-dup + retry gate for in-flight share downloads. IO-thread only (all
// mutation happens on the io_context thread: think()'s IO phase, the
// sharereply callbacks, and the ReplyMatcher timeout timers).
struct DownloadGate
{
    std::set<uint256> in_flight;          // hashes with a pending sharereq
    std::map<uint256, int> fail_count;    // consecutive empty replies per hash

    // True if `h` may be requested now (not already in flight, not failed
    // out this cycle); marks it in flight. Mirrors ltc node.cpp:978-994.
    bool try_begin(const uint256& h)
    {
        if (in_flight.count(h))
            return false;
        auto it = fail_count.find(h);
        if (it != fail_count.end() && it->second >= MAX_EMPTY_RETRIES)
            return false;
        in_flight.insert(h);
        return true;
    }

    // The request was not actually dispatched (no peers / tracker busy).
    void abort(const uint256& h) { in_flight.erase(h); }

    // Empty reply or ReplyMatcher timeout: release + count the failure.
    // Returns the new failure count (for logging against MAX_EMPTY_RETRIES).
    int on_empty(const uint256& h)
    {
        in_flight.erase(h);
        return ++fail_count[h];
    }

    // Non-empty reply: release + clear the failure history for the hash.
    void on_success(const uint256& h)
    {
        in_flight.erase(h);
        fail_count.erase(h);
    }

    // think()-cycle reset (ltc node.cpp:1600-1608): clear the stale download
    // set and the fail counts so desired hashes are retried from scratch.
    void new_cycle()
    {
        in_flight.clear();
        fail_count.clear();
    }
};

// stops = known heads + their min(max(0, height-1), 10)-th parents, capped at
// STOPS_CAP (oracle node.py download loop stops=...[:100]; ltc:1022-1040
// port). Bounds each reply to the actual info-gap between our chain and the
// peer's — without stops the peer dumps up to `parents` shares along one
// lineage per request, which can cross 2*CHAIN_LENGTH+10 during bootstrap and
// get drop-tailed. Caller must hold (or be safe without) the tracker lock.
template <typename ChainT>
std::vector<uint256> build_stops(ChainT& chain)
{
    std::set<uint256> stop_set;
    for (const auto& [head_hash, tail_hash] : chain.get_heads())
    {
        stop_set.insert(head_hash);
        const int h = chain.get_acc_height(head_hash);
        const int nth = std::min(std::max(0, h - 1), 10);
        if (nth > 0)
        {
            auto parent = chain.get_nth_parent_via_skip(head_hash, nth);
            if (!parent.IsNull())
                stop_set.insert(parent);
        }
    }
    std::vector<uint256> stops;
    for (const auto& s : stop_set)
    {
        if (stops.size() >= STOPS_CAP)
            break;
        stops.push_back(s);
    }
    return stops;
}

// Backfill continuation rule (ltc node.cpp:1093-1102): a sharereply carries
// shares child→parent (handle_get_share's get_chain walk order), so the LAST
// item is the oldest; its prev_hash is the next download target when still
// unknown. Returns ZERO for an empty batch (nothing to continue from) or when
// the oldest share is the chain genesis (prev == ZERO → fully rooted).
// ShareVecT = std::vector<coin ShareType> (the coin's share variant exposes
// invoke() over the concrete share object).
template <typename ShareVecT>
uint256 oldest_parent(ShareVecT& items)
{
    if (items.empty())
        return uint256::ZERO;
    uint256 prev;
    items.back().invoke([&](auto* obj) { prev = obj->m_prev_hash; });
    return prev;
}

} // namespace pool::download
