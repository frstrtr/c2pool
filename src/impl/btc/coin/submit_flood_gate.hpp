// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin submit-flood gate — pure decision logic that stops c2pool from
// amplifying a bitcoind cs_main wedge with duplicate submitblock requests.
//
// Observed on the .234 G3b testnet rig (2026-09-20..22): submitblock held
// cs_main long enough that a single won block sat ~31.9s in flight, just past
// NodeRPC's 30s SO_RCVTIMEO deadline. Two c2pool-side amplifiers then stacked
// more work behind the same lock:
//
//   1. Send() treated a READ timeout like a dead socket: it reconnected and
//      RE-SENT the same body. But a read timeout means the request was already
//      DELIVERED -- bitcoind keeps grinding the first submitblock after we hang
//      up, so the resend queued a SECOND copy of the block behind cs_main.
//   2. Two independent callers submit the SAME won block: the stratum connect
//      path (submit_block_for_connect) and the won-block dispatch
//      (m_on_block_found -> submit_block_hex_str). With (1) that is up to
//      2 callers x 2 attempts = 4 submitblocks per block.
//
// Fix: (a) a non-idempotent call (submitblock) is resent ONLY when the request
// was never delivered (write failure -- the stale keep-alive case the retry
// exists for); (b) a per-block dedupe in front of submitblock collapses both
// callers onto one delivered request and replays its verdict.
//
// Header-only, no I/O: this is the SSOT for both NodeRPC (coin/rpc.cpp) and the
// submit_flood_gate KAT (test/submit_flood_gate_test.cpp).
// ---------------------------------------------------------------------------
#ifndef C2POOL_IMPL_BTC_COIN_SUBMIT_FLOOD_GATE_HPP
#define C2POOL_IMPL_BTC_COIN_SUBMIT_FLOOD_GATE_HPP

#include <algorithm>
#include <cstddef>
#include <deque>
#include <optional>
#include <string>
#include <utility>

namespace btc::coin {

// Where a single Send() attempt failed.
enum class RpcFailure {
    Write,        // http::write threw -- the request never reached bitcoind
    Read,         // http::read threw (incl. the 30s SO_RCVTIMEO) -- DELIVERED
    EmptyNon200,  // bitcoind answered with an empty non-200 body -- DELIVERED
};

// May Send() re-send the same body after a reconnect? Idempotent reads keep
// the legacy retry-once behaviour. A non-idempotent call may be re-sent only
// when it was never delivered: re-sending a delivered submitblock stacks a
// second copy of the block behind cs_main.
constexpr bool rpc_may_resend(RpcFailure failure, bool non_idempotent) noexcept
{
    if (!non_idempotent)
        return true;
    return failure == RpcFailure::Write;
}

// Per-block submitblock dedupe. NodeRPC is ioc-confined, so no locking.
class SubmitDedupe
{
public:
    enum class Verdict {
        Accepted,           // null / duplicate / inconclusive (submitblock_result_accepted)
        Rejected,           // daemon returned a reject reason
        DeliveredUnknown,   // request delivered, response lost (read timeout)
    };

    // Recent-block window. Won blocks are rare; 16 covers any burst of
    // same-height races while keeping the lookup a trivial linear scan.
    static constexpr std::size_t kCapacity = 16;

    // The 80-byte header (first 160 hex chars) identifies the block without
    // hashing; both callers feed the same canonical hex.
    static std::string key_of(const std::string& block_hex)
    {
        return block_hex.substr(0, 160);
    }

    // Prior verdict for this block, or nullopt if it was never delivered.
    std::optional<Verdict> lookup(const std::string& key) const
    {
        auto it = find(key);
        if (it == m_entries.end())
            return std::nullopt;
        return it->second;
    }

    // Record a delivered submit. A later verdict for the same key overwrites
    // an earlier one (DeliveredUnknown can be superseded by a real answer).
    void record(const std::string& key, Verdict verdict)
    {
        auto it = find(key);
        if (it != m_entries.end()) {
            it->second = verdict;
            return;
        }
        if (m_entries.size() >= kCapacity)
            m_entries.pop_front();
        m_entries.emplace_back(key, verdict);
    }

    // What a deduped caller reports. DeliveredUnknown counts as reached: the
    // block is in bitcoind's queue and the pending-submit roundtrip tracks
    // whether it actually connects.
    static constexpr bool reached(Verdict verdict) noexcept
    {
        return verdict != Verdict::Rejected;
    }

    static constexpr const char* name(Verdict verdict) noexcept
    {
        switch (verdict) {
        case Verdict::Accepted:         return "accepted";
        case Verdict::Rejected:         return "rejected";
        case Verdict::DeliveredUnknown: return "delivered-unknown";
        }
        return "?";
    }

    std::size_t size() const { return m_entries.size(); }

private:
    using Entry = std::pair<std::string, Verdict>;
    std::deque<Entry> m_entries;

    std::deque<Entry>::iterator find(const std::string& key)
    {
        return std::find_if(m_entries.begin(), m_entries.end(),
                            [&](const Entry& e) { return e.first == key; });
    }
    std::deque<Entry>::const_iterator find(const std::string& key) const
    {
        return std::find_if(m_entries.begin(), m_entries.end(),
                            [&](const Entry& e) { return e.first == key; });
    }
};

} // namespace btc::coin

#endif // C2POOL_IMPL_BTC_COIN_SUBMIT_FLOOD_GATE_HPP
