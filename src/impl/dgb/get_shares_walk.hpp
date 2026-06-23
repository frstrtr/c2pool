#pragma once

// SSOT for the pool share-exchange GetShares walk — the SHAREREQ -> SHAREREPLY
// path consumed by both protocol_actual.cpp and protocol_legacy.cpp via
// NodeImpl::handle_get_share.  Until now this walk had ZERO coverage in any
// tree (dgb/ltc/btc/core); a drift in the parents cap, the per-hash walk bound,
// the stop-hash break, or the missing-hash skip would let two c2pool-dgb peers
// (or a c2pool-dgb peer and a p2pool-merged-v36 reference node) silently fail
// to exchange the right share span with no compile error.
//
// Oracle: p2pool node.py  Node.handle_get_shares(hashes, parents, stops, peer):
//     parents = min(parents, 1000//len(hashes))
//     stops = set(stops)
//     shares = []
//     for share_hash in hashes:
//         for share in self.tracker.get_chain(
//                 share_hash, min(parents + 1, self.tracker.get_height(share_hash))):
//             if share.hash in stops:
//                 break
//             shares.append(share)
//     return shares
//
// c2pool adds two node-local defensive guards that are CONSISTENT with p2pool's
// downloader contract (node.py:120 picks a random peer per request and retries,
// so a partial/empty hit just shifts to another peer):
//   (a) skip a requested hash not currently in our chain (continue), and
//   (b) skip any locally-rejected share hash.
// Neither changes the oracle walk for a well-formed in-chain request against a
// peer holding no rejections — the common case — so the byte span is identical.
//
// Per-coin isolation: dgb/ only.  Header-only, additive; this slice does not yet
// rewire node.cpp (that is the byte-identity-fenced delegation follow-on) — it
// pins the walk as a free function so the KAT can exercise it against a fake
// chain with no NodeImpl/tracker standup.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include <core/uint256.hpp>

namespace dgb {

// parents cap — p2pool node.py handle_get_shares first line: min(parents,
// 1000//len(hashes)).  Integer division matches Python //.  n_hashes is
// guaranteed >= 1 by the caller (an empty SHAREREQ produces no work and never
// reaches the walk); we still guard divide-by-zero by returning parents
// unchanged for an empty request rather than faulting.
inline uint64_t get_shares_parents_cap(uint64_t parents, std::size_t n_hashes)
{
    if (n_hashes == 0)
        return parents;
    return std::min(parents, static_cast<uint64_t>(1000) / static_cast<uint64_t>(n_hashes));
}

// per-hash walk length — min(parents+1, height).  Never request more shares
// above the requested hash than the chain actually holds.
inline uint64_t get_shares_walk_count(uint64_t capped_parents, uint64_t height)
{
    return std::min(capped_parents + 1, height);
}

// The full GetShares walk, generic over the chain accessor and the share type.
//   Chain must provide:  bool contains(const uint256&),
//                        int-ish get_height(const uint256&),
//                        ChainView get_chain(const uint256&, uint64_t)
//                          yielding structured [hash, data] with data.share.
//   is_rejected(hash) -> bool   skips a locally-rejected share.
//   on_missing(hash)            optional side-effect for a not-in-chain request.
template <class ShareT, class Chain, class RejectedPred>
std::vector<ShareT> collect_get_shares(
    Chain& chain,
    const std::vector<uint256>& hashes,
    uint64_t parents,
    const std::vector<uint256>& stops,
    RejectedPred is_rejected,
    const std::function<void(const uint256&)>& on_missing = {})
{
    std::vector<ShareT> shares;
    if (hashes.empty())
        return shares;

    parents = get_shares_parents_cap(parents, hashes.size());

    for (const auto& handle_hash : hashes)
    {
        if (!chain.contains(handle_hash))
        {
            if (on_missing)
                on_missing(handle_hash);
            continue;
        }

        uint64_t n = get_shares_walk_count(parents, static_cast<uint64_t>(chain.get_height(handle_hash)));
        for (auto [hash, data] : chain.get_chain(handle_hash, n))
        {
            if (std::find(stops.begin(), stops.end(), hash) != stops.end())
                break;
            if (is_rejected(hash))
                continue;
            shares.push_back(data.share);
        }
    }
    return shares;
}

} // namespace dgb
