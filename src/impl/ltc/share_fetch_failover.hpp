#pragma once

// share_fetch_failover.hpp — pure, per-(hash,peer) failure memory for the parent
// share-download path (node.cpp download_shares). Extracted into a header so the
// failover policy can be exercised by a KAT without a live node.
//
// c2pool port of p2pool-merged-v36 kr1z1s convergence hotfix #25(C) (9a2a90e8,
// P2PNode.download_shares): remember which peer recently failed to serve a given
// share hash, skip those peers for THAT hash, prefer the peer that advertised it,
// and back off only once EVERY connected peer has failed it. Guarantees no single
// slow / black-hole / malicious peer can wedge a parent fetch or desync the node
// (the measured kr1z1s wall-parent loop: one hash re-requested 247x in 40 min,
// 12,929 requests for 4,459 hashes in 4h).
//
// On master c2pool used a peer-BLIND per-hash counter (m_download_fail_count,
// MAX_EMPTY_RETRIES=3, reset every think()): after 3 empty replies the hash was
// skipped for the WHOLE peer set, so one black-hole peer that answers "empty"
// starved every other peer that actually had the parent. This replaces that with
// per-peer memory that ages out on a TTL.
//
// Pure / templated: no c2pool types, no consensus surface. HashT and PeerKeyT are
// any ordered, copyable key types (production: uint256 hash, NetService peer key).

#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <optional>

namespace ltc {

template <typename HashT, typename PeerKeyT>
class FetchFailureMemory {
public:
    // p2pool node.py: _fetch_failure_ttl = 90.0 (~6*SHARE_PERIOD). Long enough to
    // route around a black-hole peer across several attempts; short enough that a
    // transiently-busy honest peer is retried and a parent that becomes available
    // again is re-fetched.
    static constexpr double kDefaultTtl = 90.0;

    explicit FetchFailureMemory(double ttl = kDefaultTtl) : m_ttl(ttl) {}

    double ttl() const { return m_ttl; }

    // Record that `peer` failed to serve `hash` at time `now` (empty reply,
    // timeout, connection loss, or handler exception).
    void record(const HashT& hash, const PeerKeyT& peer, double now)
    {
        m_failures[hash][peer] = now;
    }

    // The parent became fetchable again — forget its whole failure record.
    void clear_hash(const HashT& hash)
    {
        m_failures.erase(hash);
    }

    // Drop failure entries older than the TTL (and empty hash buckets). Bounds
    // memory; called once per download cycle.
    void prune(double now)
    {
        for (auto it = m_failures.begin(); it != m_failures.end();) {
            auto& per_peer = it->second;
            for (auto pit = per_peer.begin(); pit != per_peer.end();) {
                if (now - pit->second > m_ttl)
                    pit = per_peer.erase(pit);
                else
                    ++pit;
            }
            if (per_peer.empty())
                it = m_failures.erase(it);
            else
                ++it;
        }
    }

    // Peer keys that failed `hash` within the TTL (i.e. currently ineligible).
    std::set<PeerKeyT> failed_keys(const HashT& hash, double now) const
    {
        std::set<PeerKeyT> out;
        auto it = m_failures.find(hash);
        if (it == m_failures.end())
            return out;
        for (const auto& [peer, ts] : it->second)
            if (now - ts <= m_ttl)
                out.insert(peer);
        return out;
    }

    // Pick a peer to request `hash` from, EXCLUDING peers that failed this exact
    // hash within the TTL. Prefer `advertiser` if it is still eligible. Returns
    // nullopt iff every connected peer has recently failed this hash (caller backs
    // off and lets the failures age out). `pick_index(n)` chooses a uniform index
    // in [0, n) — injected so the KAT is deterministic; production passes the RNG.
    //
    // This is the attack-vector fix: a single black-hole / slow / malicious peer
    // can never wedge a parent fetch, because the node always fails over to
    // another peer that may have the parent.
    template <typename PickIndexFn>
    std::optional<PeerKeyT> choose(const HashT& hash,
                                   const std::optional<PeerKeyT>& advertiser,
                                   const std::vector<PeerKeyT>& peers,
                                   double now,
                                   PickIndexFn&& pick_index) const
    {
        // ⛔ MASTER SEMANTICS (pre-fix) — this is the c2pool download-path policy
        // BEFORE the #25(C) failover hotfix: a peer-BLIND per-hash counter. Any
        // failure recorded for the hash within the TTL skips it for the WHOLE peer
        // set (the m_download_fail_count / MAX_EMPTY_RETRIES model), so one
        // black-hole peer that answers "empty" starves every other peer that has
        // the parent. share_fetch_failover_test.cpp is RED against this body and
        // GREEN once it is replaced by the per-peer failover.
        if (peers.empty())
            return std::nullopt;
        if (!failed_keys(hash, now).empty())
            return std::nullopt;                 // peer-blind: any failure blocks all
        if (advertiser.has_value())
            for (const auto& p : peers)
                if (p == *advertiser)
                    return p;
        const std::size_t idx = pick_index(peers.size());
        return peers[idx % peers.size()];
    }

    // True iff there ARE connected peers and EVERY one has recently failed
    // `hash` — the parent is unfetchable from the whole peer set, so a head
    // waiting on it may be reaped (clean_tracker Guard 2b). No peers, or any peer
    // not-yet-failed -> false: the download is still viable, keep protecting.
    bool abandoned(const HashT& hash,
                   const std::vector<PeerKeyT>& peers,
                   double now) const
    {
        if (peers.empty())
            return false;
        const std::set<PeerKeyT> failed = failed_keys(hash, now);
        for (const auto& p : peers)
            if (!failed.count(p))
                return false;
        return true;
    }

    std::size_t tracked_hashes() const { return m_failures.size(); }

private:
    double m_ttl;
    // hash -> { peer_key -> last_failure_timestamp }
    std::map<HashT, std::map<PeerKeyT, double>> m_failures;
};

} // namespace ltc
