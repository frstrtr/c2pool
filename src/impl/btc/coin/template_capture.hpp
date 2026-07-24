// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// template_capture.hpp -- the per-job template-retention seam: the PRODUCTION
// captured_template_txs_fn provider that feeds the won-block reconstructor's
// template_other_txs_fn through the deserialize bridge (template_other_txs.hpp,
// make_template_other_txs_fn -- BTC reconstructor slice 5, not yet landed).
//
// WHY a capture store, not mempool re-selection:
//   A won share commits to the GBT template it was MINED AGAINST at job hand-
//   out. The reconstructed broadcast block's non-coinbase set MUST be that
//   template's transactions[] in template order, because the share's merkle
//   root was computed over [gentx] ++ those txs. A won-block path that RE-
//   SELECTS the live embedded mempool is merkle-consistent ONLY while the
//   mempool is static across the won window (true under regtest, FALSE in prod:
//   any mempool mutation between hand-out and won-block diverges the set ->
//   wrong merkle root -> daemon-rejected block -> lost reward). This store
//   removes that race: capture the template's transactions[] at hand-out keyed
//   by the resulting share_hash, replay it verbatim at won-block.
//
// SSOT split: this header owns ONLY the keyed retain/replay + bounded eviction.
// The transactions[] -> MutableTransaction decode is template_other_txs.hpp
// (BTC slice 5); compose make_template_other_txs_fn(capture.provider()) to get
// the template_other_txs_fn the reconstruct closure installs.
//
// Miss policy: an absent share_hash yields an EMPTY transactions[] (json
// ::array()) -> the bridge decodes to an empty other_txs -> a VALID coinbase-
// only won block (the reconstructor's documented empty contract), NOT a fail-
// closed nullopt. A won block that loses its fee txs is still a valid, network-
// accepted block carrying the full subsidy; dropping it on a capture miss would
// forfeit the subsidy too. Logged so a miss is never silent.
//
// Bounded: jobs are handed out continuously; the store keeps the most recent
// `capacity` templates (FIFO eviction) so memory is O(capacity), not O(jobs).
// A won share is reconstructed within a few jobs of hand-out, so a modest
// capacity covers every realistic won-window.
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE.
// Thread-safe: capture() runs on the job/mint path, provider() fires on the
// COMPUTE thread inside the won-block closure -- guarded by one mutex.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>

namespace btc::coin
{

// Per-job captured-template store keyed by share_hash. Retains each handed-out
// template's transactions[] (the conformant GBT shape: array of {data,txid,
// hash,fee}) so the won-block reconstructor can replay the exact non-coinbase
// set the share committed to.
class TemplateCapture
{
public:
    static constexpr std::size_t DEFAULT_CAPACITY = 256;

    explicit TemplateCapture(std::size_t capacity = DEFAULT_CAPACITY)
        : m_capacity(capacity == 0 ? 1 : capacity) {}

    // Retain `transactions` (a GBT transactions[] array) for `share_hash`.
    // Overwrites an existing entry for the same hash WITHOUT enqueuing the key
    // twice (so eviction stays in true insertion order). FIFO-evicts the oldest
    // once a new key would exceed capacity.
    void capture(const uint256& share_hash, nlohmann::json transactions)
    {
        const std::string key = share_hash.GetHex();
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_store.find(key);
        if (it == m_store.end())
        {
            if (m_store.size() >= m_capacity && !m_order.empty())
            {
                m_store.erase(m_order.front());
                m_order.pop_front();
            }
            m_order.push_back(key);
        }
        m_store[key] = std::move(transactions);
    }

    // Replay the captured transactions[] for `share_hash`. Returns an empty
    // json::array() on a miss (-> coinbase-only valid block), logged.
    nlohmann::json provide(const uint256& share_hash) const
    {
        const std::string key = share_hash.GetHex();
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_store.find(key);
        if (it == m_store.end())
        {
            std::cout << "[BTC-POOL-BLOCK] template-capture MISS for won share "
                      << key.substr(0, 16)
                      << " -- reconstructing coinbase-only (no retained template)"
                      << std::endl;
            return nlohmann::json::array();
        }
        return it->second;
    }

    // The captured_template_txs_fn make_template_other_txs_fn (slice 5) consumes.
    // The returned closure captures `this`; the TemplateCapture MUST outlive the
    // reconstruct closure it is installed into (it does in main_btc: a run-loop-
    // scoped member outliving the tracker callback).
    std::function<nlohmann::json(const uint256&)> provider() const
    {
        return [this](const uint256& h) { return provide(h); };
    }

    std::size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_store.size();
    }

private:
    const std::size_t m_capacity;
    mutable std::mutex m_mtx;
    std::unordered_map<std::string, nlohmann::json> m_store;
    std::deque<std::string> m_order;
};

} // namespace btc::coin
