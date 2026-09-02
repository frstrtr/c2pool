// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::ParentTxResolver — TIER-3 daemonless input pricing driver.
//
// An embedded SPV node has no full UTXO set, so a mempool tx whose input is
// neither in our post-anchor UTXO view (T2) nor an in-mempool parent (T1/CPFP)
// is fee-UNKNOWN and EXCLUDED from templates (fail closed). Tier 3 recovers a
// subset by fetching the missing parent txs over P2P:
//
//   pump()  ->  Mempool::missing_parents()  ->  getdata(MSG_WITNESS_TX ...)
//
// A parent that a fork peer still holds in its relay/mempool set arrives via the
// normal `tx` message -> the run loop feeds it to Mempool::add_parent_priced
// (self-authenticating: the SHA256d txid is recomputed and must match the
// requested hash — a peer cannot forge a value) AND to Mempool::add_tx (so a
// parent that is itself serveable becomes a CPFP T1 parent). The next
// recompute_unknown_fees then prices the child.
//
// Bounded: each requested txid is rate-limited (m_retry_interval) and capped
// (m_max_retries); a parent that peers never serve (e.g. spends an old confirmed
// coin — getdata(tx) does not answer confirmed history) is simply never priced,
// and its child stays fail-closed EXCLUDED. This class only REQUESTS; it never
// prices — validity stays with the mempool's own MoneyRange/maturity checks.
//
// PER-COIN ISOLATION: src/impl/bip110 only. ZERO DASH code.
// ---------------------------------------------------------------------------

#include "mempool.hpp"

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace bip110 {
namespace coin {

class ParentTxResolver {
public:
    // getdata_tx_fn issues a single getdata(MSG_WITNESS_TX) for the batch of
    // txids (main wires it to NodeP2P::request_tx). Returns nothing; a failure to
    // send just means the txid is retried on a later pump().
    using GetdataTxFn = std::function<void(const std::vector<uint256>&)>;

    ParentTxResolver(Mempool& pool, GetdataTxFn fn)
        : m_pool(pool), m_getdata(std::move(fn)) {}

    void set_max_per_pump(size_t n)  { m_max_per_pump = n; }
    void set_max_retries(int n)      { m_max_retries = n; }
    void set_retry_interval(std::chrono::seconds s) { m_retry_interval = s; }

    // One resolution cycle: request the not-recently-requested, under-retry-cap
    // subset of the mempool's currently-missing parent txids. Call on a timer.
    // Returns the number of txids requested this cycle.
    size_t pump() {
        const auto now = std::chrono::steady_clock::now();
        auto missing = m_pool.missing_parents();
        std::vector<uint256> batch;
        for (const auto& txid : missing) {
            auto it = m_state.find(txid);
            if (it == m_state.end()) {
                m_state[txid] = { now, 1 };
            } else {
                if (it->second.tries >= m_max_retries) continue;      // give up (fail closed)
                if (now - it->second.last < m_retry_interval) continue; // rate limit
                it->second.last = now;
                it->second.tries += 1;
            }
            batch.push_back(txid);
            if (batch.size() >= m_max_per_pump) break;
        }
        // Forget parents no longer missing (resolved or child evicted), so a
        // txid that reappears later starts its retry budget fresh.
        {
            std::map<uint256, bool> still;
            for (const auto& t : missing) still[t] = true;
            for (auto it = m_state.begin(); it != m_state.end();) {
                if (!still.count(it->first)) it = m_state.erase(it);
                else ++it;
            }
        }
        if (!batch.empty()) {
            LOG_INFO << "[EMB-BIP110] T3 parent-fetch: requesting " << batch.size()
                     << " missing parent tx(s) via getdata(MSG_WITNESS_TX)"
                     << " (missing_total=" << missing.size() << ")";
            m_getdata(batch);
        }
        return batch.size();
    }

private:
    struct Req { std::chrono::steady_clock::time_point last; int tries; };

    Mempool&    m_pool;
    GetdataTxFn m_getdata;
    std::map<uint256, Req> m_state;

    size_t                 m_max_per_pump   = 64;
    int                    m_max_retries    = 5;
    std::chrono::seconds   m_retry_interval{20};
};

} // namespace coin
} // namespace bip110
