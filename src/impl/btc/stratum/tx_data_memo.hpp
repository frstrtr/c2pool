// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// H5 leak-fix seam (acceptance-gate testable unit).
//
// build_connection_coinbase rebuilt the per-job tx hex vector on every call
// even when the mempool tx set was unchanged -- the dominant churn/leak site
// in the 2026-06-02 heaptrack (work_source.cpp:634, 768MB / 1.2M calls, ~78%
// of leaked bytes). The fix memoizes the shared_ptr in a single slot keyed to
// a fingerprint over the merkle leaf set (wd->m_hashes, in merkle-leaf order):
// a repeat call against the same tx set returns the cached shared_ptr (a
// refcount bump) instead of re-serializing the whole mempool. The key is the
// exact leaf set that built this job merkle, so a hit is atomic-with-merkle by
// construction (no stale-tx-vs-fresh-merkle mismatch on submit). Single slot =>
// bounded memory (one tx set retained), self-evicting on tx-set roll.
//
// Factored out of build_connection_coinbase so the invariant can be proven
// deterministically by a standalone harness (pointer-identity + O(1) repeat
// call) without standing up a full BTCWorkSource. The call site holds
// template_mutex_ across the call; this helper itself does no locking.

#include <memory>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <btclibs/hash.h>       // CHash256
#include <core/uint256.hpp>     // uint256 (c2pool canonical)

namespace btc::stratum::detail {

// Fingerprint the template tx set over its merkle leaf hashes, in leaf order.
inline uint256 tx_data_fingerprint(const std::vector<uint256>& leaf_hashes)
{
    legacy::CHash256 fp_hasher;
    for (const auto& h : leaf_hashes)
        fp_hasher.Write(std::span<const unsigned char>(h.data(), 32));
    uint256 fp;
    fp_hasher.Finalize(std::span<unsigned char>(fp.data(), 32));
    return fp;
}

// Single-slot memo: return the cached tx-hex vector when the leaf set matches
// the fingerprint of the prior call; otherwise rebuild from txs_field and
// overwrite the slot (the prior shared_ptr refcount drops). The two memo
// fields are owned by the caller (BTCWorkSource members, guarded by
// template_mutex_); this function mutates them but takes no lock itself.
inline std::shared_ptr<std::vector<std::string>> tx_data_memo_get_or_build(
    const std::vector<uint256>&                 leaf_hashes,
    const nlohmann::json&                       txs_field,
    uint256&                                    memo_fp,
    std::shared_ptr<std::vector<std::string>>&  memo_slot)
{
    const uint256 fp = tx_data_fingerprint(leaf_hashes);
    if (memo_slot && memo_fp == fp)
        return memo_slot;  // unchanged tx set -> refcount bump, no rebuild

    auto txd = std::make_shared<std::vector<std::string>>();
    txd->reserve(txs_field.size());
    for (const auto& t : txs_field) {
        if (t.is_object() && t.contains("data") && t["data"].is_string())
            txd->push_back(t["data"].get<std::string>());
    }
    memo_fp   = fp;    // single slot: overwrite, prior set refcount drops
    memo_slot = txd;
    return txd;
}

}  // namespace btc::stratum::detail