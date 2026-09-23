// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// G2 fill-budget RUNTIME owner for the embedded LTC template source.
// Port of p2pool-merged-v36 work.py _g2_newtx_budget() (grant frozen per
// work event + lazy block reset) and the got_response() settle, bound to
// c2pool's EmbeddedCoinNode:
//
//   begin_work(prev)    ONE grant per work event. EmbeddedCoinNode::getwork()
//                       is called once per MiningInterface::refresh_work(), so
//                       one getwork() == one work event. A changed parent block
//                       first fires on_block_reset() lazily (the reference keys
//                       on (version, prev, bits); for LTC version and bits are
//                       functions of prev, so prev alone is the block edge).
//   record(txs, spent)  remember the new-tx bytes the built template actually
//                       committed, keyed by its coinbase merkle branch.
//   settle_found(br)    a local share was FOUND on the job carrying branch
//                       `br`: debit exactly that template's bytes. DOA/orphan
//                       shares settle too (their bytes hit the wire).
//
// Keyed by the coinbase merkle branch because that is what the job hands
// back at share-creation time (ShareCreationParams::merkle_branches), and the
// branch is a function of the template's tx set -- as is spent. A share on a
// job older than RECENT_TEMPLATES rebuilds (miss) settles the held grant: an
// upper bound on what that template could have committed, never an
// under-debit.
//
// Grant and settle ship TOGETHER, never grant alone: without settle,
// shares_since_reset stays 0 after the first block reset and every later
// template is pinned to the 50 kB floor.
//
// RPC/GBT mode (litecoind fallback) has no owner and no budget: build is
// byte-identical to pre-G2. Deferred -- fallback path only.

#include "fill_budget.hpp"

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace ltc::coin {

// Derived LTC parent bucket: rate = 1 MB / 150 s block = 6666 B/s,
// burst = 250 kB, floor = legacy 50 kB, ramp = 4 shares.
inline constexpr double  LTC_FILL_RATE        = 6666;
inline constexpr int64_t LTC_FILL_BURST       = 250000;
inline constexpr int64_t LTC_FILL_RAMP_SHARES = 4;

// Coinbase (index 0) merkle branch over the template's tx hashes. Mirrors
// core::MiningInterface::compute_merkle_branches() step for step, minus its
// GetHex/SetHex/HexStr round-trip (an identity on the bytes), so the result
// is element-for-element equal to ShareCreationParams::merkle_branches.
inline std::vector<uint256> coinbase_merkle_branch(std::vector<uint256> level)
{
    std::vector<uint256> branch;
    while (!level.empty()) {
        branch.push_back(level.front());
        level.erase(level.begin());
        if (level.empty())
            break;
        if (level.size() % 2 == 1)
            level.push_back(level.back());
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i + 1 < level.size(); i += 2)
            next.push_back(Hash(level[i], level[i + 1]));
        level = std::move(next);
    }
    return branch;
}

class ParentFillBudget {
public:
    static constexpr size_t RECENT_TEMPLATES = 32;

    struct Settled {
        uint64_t bytes;    // debited from the bucket
        bool     matched;  // true = exact template bytes; false = held grant
    };

    explicit ParentFillBudget(FillBudget bucket) : m_bucket(std::move(bucket)) {}

    static ParentFillBudget ltc(FillBudget::Clock clock = {})
    {
        return ParentFillBudget(FillBudget("ltc", LTC_FILL_RATE, LTC_FILL_BURST,
                                           LEGACY_NEWTX_CAP, LTC_FILL_RAMP_SHARES,
                                           std::move(clock)));
    }

    // One grant per work event; `prev` = parent block the template builds on.
    // First parent seen does not reset (boot is already full, ramp complete).
    int64_t begin_work(const uint256& prev)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_have_parent && prev != m_parent)
            m_bucket.on_block_reset();
        m_parent      = prev;
        m_have_parent = true;
        m_grant       = m_bucket.grant();
        return m_grant;
    }

    void record(const std::vector<uint256>& tx_hashes, uint64_t spent)
    {
        auto branch = coinbase_merkle_branch(tx_hashes);   // hashing outside the lock
        std::lock_guard<std::mutex> lk(m_mutex);
        m_recent.push_back({std::move(branch), spent});
        while (m_recent.size() > RECENT_TEMPLATES)
            m_recent.pop_front();
    }

    Settled settle_found(const std::vector<uint256>& branch)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        Settled s{static_cast<uint64_t>(m_grant), false};
        for (auto it = m_recent.rbegin(); it != m_recent.rend(); ++it) {
            if (it->branch == branch) {
                s = {it->spent, true};
                break;
            }
        }
        m_bucket.settle(static_cast<double>(s.bytes));
        return s;
    }

    // accessors (KATs / log lines)
    int64_t held_grant() const         { std::lock_guard<std::mutex> lk(m_mutex); return m_grant; }
    int64_t current_cap() const        { std::lock_guard<std::mutex> lk(m_mutex); return m_bucket.current_cap(); }
    int64_t shares_since_reset() const { std::lock_guard<std::mutex> lk(m_mutex); return m_bucket.shares_since_reset(); }
    double  tokens() const             { std::lock_guard<std::mutex> lk(m_mutex); return m_bucket.tokens(); }

private:
    struct Recent {
        std::vector<uint256> branch;
        uint64_t             spent;
    };

    mutable std::mutex m_mutex;
    FillBudget         m_bucket;
    uint256            m_parent;
    bool               m_have_parent = false;
    int64_t            m_grant = 0;
    std::deque<Recent> m_recent;
};

} // namespace ltc::coin
