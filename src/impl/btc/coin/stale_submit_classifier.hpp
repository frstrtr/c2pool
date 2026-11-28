// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::classify_pending_submit — pure decision logic for the B5
// stale-submit warning timer in src/c2pool/main_btc.cpp.
//
// The timer used to warn "[BTC-SUBMIT] STALE ... bitcoind likely rejected" for
// EVERY submit still pending after 60s. On a fast sharechain (regtest, or any
// min-diff burst) several of our own blocks are routinely won at the SAME
// height: the first one bitcoind sees becomes the tip, and Core silently
// ignores the same-work second-seen siblings. No reject is logged anywhere,
// the sibling's header never shows up in HeaderChain, and the old tracker
// misreported each lost sibling as a rejected block (observed 2026-11-01 on
// the .234 MTP regtest run: 209 STALE warnings, 209 distinct hashes over 35
// heights, every height filled by an accepted block, 0 rejects in debug.log).
//
// Before warning, the timer now looks at HeaderChain's best-chain entry at the
// submit's height:
//   - our own hash is there        -> Confirmed (late roundtrip, no warn)
//   - a different hash is there    -> SiblingFilled (height won elsewhere, no
//                                     warn; logged at info)
//   - nothing there yet            -> Stale (genuine: warn as before)
// This header is the SSOT for both the shipped timer and the KAT
// (src/impl/btc/test/stale_submit_classifier_test.cpp). Header-only, no I/O.
// ---------------------------------------------------------------------------
#ifndef C2POOL_IMPL_BTC_COIN_STALE_SUBMIT_CLASSIFIER_HPP
#define C2POOL_IMPL_BTC_COIN_STALE_SUBMIT_CLASSIFIER_HPP

#include <core/uint256.hpp>

#include <chrono>
#include <optional>

namespace btc::coin {

// Age after which an unconfirmed submit is classified. Shared by the shipped
// timer and the KAT so the two cannot drift.
inline constexpr std::chrono::seconds kStaleSubmitAfter{60};

enum class PendingSubmitVerdict {
    Pending,        // younger than kStaleSubmitAfter: keep waiting
    Confirmed,      // our block is on HeaderChain's best chain at its height
    SiblingFilled,  // a different block holds that height: lost race, not a reject
    Stale,          // nothing at that height yet: genuinely unconfirmed, warn
};

// @param age                time since the submit was sent
// @param own_hash           SHA256d hash of the block we submitted
// @param best_at_height     HeaderChain best-chain hash at the submit's height,
//                           or nullopt if HeaderChain has not reached it
inline PendingSubmitVerdict classify_pending_submit(
    std::chrono::seconds age,
    const uint256& own_hash,
    const std::optional<uint256>& best_at_height)
{
    if (age < kStaleSubmitAfter)
        return PendingSubmitVerdict::Pending;
    if (!best_at_height)
        return PendingSubmitVerdict::Stale;
    if (*best_at_height == own_hash)
        return PendingSubmitVerdict::Confirmed;
    return PendingSubmitVerdict::SiblingFilled;
}

} // namespace btc::coin

#endif // C2POOL_IMPL_BTC_COIN_STALE_SUBMIT_CLASSIFIER_HPP
