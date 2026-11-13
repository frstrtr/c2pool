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
    //
    // download_shares no longer picks peers with this (its 90 s memory forgets
    // a failure before the pacer's longer backoffs retry): see FetchPeerRotation.
    template <typename PickIndexFn>
    std::optional<PeerKeyT> choose(const HashT& hash,
                                   const std::optional<PeerKeyT>& advertiser,
                                   const std::vector<PeerKeyT>& peers,
                                   double now,
                                   PickIndexFn&& pick_index) const
    {
        if (peers.empty())
            return std::nullopt;
        const std::set<PeerKeyT> failed = failed_keys(hash, now);

        std::vector<PeerKeyT> eligible;
        eligible.reserve(peers.size());
        for (const auto& p : peers)
            if (!failed.count(p))
                eligible.push_back(p);

        if (eligible.empty())
            return std::nullopt;

        // Prefer the advertiser when it is still eligible.
        if (advertiser.has_value())
            for (const auto& p : eligible)
                if (p == *advertiser)
                    return p;

        const std::size_t idx = pick_index(eligible.size());
        return eligible[idx % eligible.size()];
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

// FetchPeerRotation — WHICH peer to ask next for a parent share. download_shares
// picks peers with this; FetchFailureMemory above stays the (90 s) input to
// abandoned() and clean_tracker's head retention, unchanged.
//
// Why not FetchFailureMemory::choose: its failures age out after 90 s, while
// DesiredRequestPacer spaces the retries of a hash 5, 10, 20 ... 300 s apart.
// From about the sixth retry the gap exceeds 90 s, every failure has aged out,
// and choose() goes back to the advertiser — the peer that has already answered
// empty — every time. A peer that holds the share but was not among the first
// few random picks is never asked again. 2026-11-13: two stuck LTC nodes each
// held the share the other needed and kept asking only the original
// advertisers for hours.
//
// The policy:
//  * Untried peers first: any connected peer that has not failed this hash
//    within kDefaultTtl (30 min), not only the advertiser. The advertiser is
//    preferred only while it is untried.
//  * record_failure() says whether an untried connected peer is left. If so
//    the caller asks it at once, with no backoff; the pacer backs a hash off
//    only after every connected peer has failed it.
//  * Every connected peer failed: the one that failed it longest ago (a
//    rotation through the whole peer set, at the pacer's pace).
//  * A peer that (re)connects is forgotten: it is untried for every hash.
//
// Pure / templated like FetchFailureMemory. IO-thread confined in node.cpp.
template <typename HashT, typename PeerKeyT>
class FetchPeerRotation {
public:
    // Long enough to outlast the pacer's whole backoff ladder (5 s .. 300 s),
    // so a peer that answered empty is not asked again before every other
    // connected peer has been.
    static constexpr double kDefaultTtl = 1800.0;

    explicit FetchPeerRotation(double ttl = kDefaultTtl) : m_ttl(ttl) {}

    double ttl() const { return m_ttl; }

    // `peer` failed `hash` at `now` (empty reply, timeout, disconnect). True iff
    // a peer of `peers` (the connected set) has still not failed it: ask that
    // one now. False: every connected peer has failed it — back off.
    bool record_failure(const HashT& hash, const PeerKeyT& peer,
                        const std::vector<PeerKeyT>& peers, double now)
    {
        m_failed[hash][peer] = now;
        return has_untried(hash, peers, now);
    }

    bool has_untried(const HashT& hash, const std::vector<PeerKeyT>& peers, double now) const
    {
        for (const auto& p : peers)
            if (!failed_at(hash, p, now).has_value())
                return true;
        return false;
    }

    // The peer to ask for `hash`: the advertiser if it is connected and
    // untried; else an untried peer (`pick_index(n)` in [0, n), injected as in
    // FetchFailureMemory::choose); else the peer whose failure is the oldest.
    // nullopt only when `peers` is empty.
    template <typename PickIndexFn>
    std::optional<PeerKeyT> choose(const HashT& hash,
                                   const std::optional<PeerKeyT>& advertiser,
                                   const std::vector<PeerKeyT>& peers,
                                   double now,
                                   PickIndexFn&& pick_index) const
    {
        if (peers.empty())
            return std::nullopt;

        if (advertiser.has_value() && !failed_at(hash, *advertiser, now).has_value())
            for (const auto& p : peers)
                if (p == *advertiser)
                    return p;

        std::vector<PeerKeyT> untried;
        for (const auto& p : peers)
            if (!failed_at(hash, p, now).has_value())
                untried.push_back(p);
        if (!untried.empty())
            return untried[pick_index(untried.size()) % untried.size()];

        // Every connected peer has failed it: rotate, oldest failure first.
        const PeerKeyT* oldest = nullptr;
        double oldest_at = 0.0;
        for (const auto& p : peers) {
            const double at = *failed_at(hash, p, now);
            if (oldest == nullptr || at < oldest_at) {
                oldest = &p;
                oldest_at = at;
            }
        }
        return *oldest;
    }

    // The hash was served — forget it.
    void clear_hash(const HashT& hash) { m_failed.erase(hash); }

    // A peer just (re)connected: it is untried for every hash.
    void forget_peer(const PeerKeyT& peer)
    {
        for (auto it = m_failed.begin(); it != m_failed.end();) {
            it->second.erase(peer);
            if (it->second.empty())
                it = m_failed.erase(it);
            else
                ++it;
        }
    }

    // Drop failures older than the TTL (and empty hash buckets).
    void prune(double now)
    {
        for (auto it = m_failed.begin(); it != m_failed.end();) {
            auto& per_peer = it->second;
            for (auto pit = per_peer.begin(); pit != per_peer.end();) {
                if (now - pit->second > m_ttl)
                    pit = per_peer.erase(pit);
                else
                    ++pit;
            }
            if (per_peer.empty())
                it = m_failed.erase(it);
            else
                ++it;
        }
    }

    std::size_t tracked_hashes() const { return m_failed.size(); }

private:
    std::optional<double> failed_at(const HashT& hash, const PeerKeyT& peer, double now) const
    {
        auto it = m_failed.find(hash);
        if (it == m_failed.end())
            return std::nullopt;
        auto pit = it->second.find(peer);
        if (pit == it->second.end() || now - pit->second > m_ttl)
            return std::nullopt;
        return pit->second;
    }

    double m_ttl;
    // hash -> { peer_key -> last_failure_timestamp }
    std::map<HashT, std::map<PeerKeyT, double>> m_failed;
};

} // namespace ltc
