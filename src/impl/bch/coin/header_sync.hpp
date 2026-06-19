#pragma once
// ---------------------------------------------------------------------------
// bch::coin::header_sync -- M5 full-block body. Headers-first IBD continuation
// decision, factored out of NodeP2P's `headers` handler as a PURE function so
// the three-way follow-up policy is unit-testable without a live peer/socket.
//
// THE GAP THIS CLOSES: the `headers` handler fired new_headers and, for a
// small BIP130 tip-announce batch (<= 3), issued a getdata for the announced
// full block(s). But a MAXIMAL headers batch -- the peer capped the response at
// MAX_HEADERS_RESULTS because it has MORE -- was a dead end: cold-start initial
// block download (IBD) advanced exactly one batch of headers and then stalled.
// The header chain (which the embedded daemon drives ASERT DAA and the ABLA
// size feed off) could never sync past the first 2000 headers from genesis /
// the cold-start anchor.
//
// POLICY (mirrors Bitcoin/BCHN headers-first sync):
//   * empty batch                       -> Idle          (nothing arrived)
//   * batch size >= MAX_HEADERS_RESULTS -> ContinueSync  (peer has more: re-
//                                          issue getheaders with a locator
//                                          anchored at the last header to walk
//                                          the chain forward to the peer tip)
//   * batch size <= announce_threshold  -> RequestBlocks (BIP130 header-first
//                                          block announcement: getdata it)
//   * otherwise (partial IBD batch)     -> Idle          (a non-maximal batch
//                                          means we reached the peer's tip;
//                                          nothing further to pull)
//
// MAX_HEADERS_RESULTS == 2000 matches Bitcoin Cash Node (the upstream the
// embedded daemon forks from); a peer never returns more than this per
// `headers` message, so "== cap" is the canonical "has more" signal.
//
// p2pool-merged-v36 SURFACE: NONE -- pure SPV/IBD wire-sync plumbing; no PoW
// hash, share format, coinbase commitment, AuxPoW, or PPLNS math. PER-COIN
// ISOLATION: src/impl/bch/coin/ only; header-only, build-INERT (bch stays
// skip-green).
// ---------------------------------------------------------------------------

#include <cstddef>
#include <vector>

namespace bch::coin::header_sync {

/// Upstream cap on headers returned per `headers` message (BCHN/Bitcoin).
inline constexpr std::size_t MAX_HEADERS_RESULTS = 2000;

/// BIP130 header-first announcement is a small batch; at or below this we treat
/// the headers as block announcements and getdata the corresponding block(s).
inline constexpr std::size_t DEFAULT_ANNOUNCE_THRESHOLD = 3;

/// Follow-up action after a `headers` message is ingested into the chain.
enum class Followup {
    Idle,          ///< Nothing to do (empty, or a non-maximal IBD batch = caught up).
    RequestBlocks, ///< BIP130 tip announce: getdata the announced block(s).
    ContinueSync,  ///< Maximal IBD batch: re-issue getheaders for the next batch.
};

/// Classify the follow-up for a just-ingested headers batch. PURE.
inline Followup classify_headers_batch(
    std::size_t batch_size,
    std::size_t announce_threshold = DEFAULT_ANNOUNCE_THRESHOLD,
    std::size_t max_results        = MAX_HEADERS_RESULTS)
{
    if (batch_size == 0)
        return Followup::Idle;
    if (batch_size >= max_results)
        return Followup::ContinueSync;
    if (batch_size <= announce_threshold)
        return Followup::RequestBlocks;
    return Followup::Idle;
}

/// Choose the getheaders locator for a ContinueSync IBD follow-up. PURE.
///
/// Prefer the robust HeaderChain-backed locator (`chain_locator`): an
/// exponential back-off set of hashes lets the peer find a common ancestor even
/// if our latest header sits on a minority fork. Fall back to a single-hash
/// locator anchored at the last learned header (`last_hash`) ONLY when the
/// chain-backed locator is unavailable -- i.e. no provider wired yet -- in which
/// case the peer may stall if it cannot anchor that lone hash (degraded, but
/// still forward-progressing on the common-chain case). Templated on the hash
/// type so it stays dependency-light and unit-testable without uint256/coin lib.
template <class Hash>
inline std::vector<Hash> choose_continue_locator(
    std::vector<Hash> chain_locator, const Hash& last_hash)
{
    if (!chain_locator.empty())
        return chain_locator;
    return {last_hash};
}

} // namespace bch::coin::header_sync
