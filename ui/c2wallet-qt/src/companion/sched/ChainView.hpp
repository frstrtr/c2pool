// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — what the node knows, read over NodeApi and cached for one
// tick: the tip (only while the node says synced), the inject lane status, the
// mempool txid set, one mempool entry's time_added, and retained block bodies.
//
// Field contracts (master node):
//   getblockchaininfo -> "blocks" only when "synced" is true; otherwise the tip
//     is unknown and "sync_blocked_by" says why (a stale tip is never used).
//   getblock?height=H -> a retained body carries "hash" and "tx" (objects with
//     "txid", or txid strings); outside the 288-block body window, or without
//     --embedded-utxo, the reply has no "tx" (header-only partial).
//   getblockhash?height=H -> a JSON string (DASH coin hook) or {"result": "..."}.
//   getrawmempool -> ["<txid>", ...]; getmempoolentry -> {..., "time_added"}
//     or {"error": "Transaction not in mempool"}.
// Confirmation of a txid must come from block bodies: getrawtransaction is
// refused by name on a daemonless node.

#include "NodeApi.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace c2w::companion::sched {

inline constexpr int64_t kBodyWindow = 288; // DASH_EXPLORER_DEPTH

struct TipInfo {
    bool known = false;          // a synced tip
    int64_t height = 0;
    std::string hash;
    bool transport_error = false;
    std::string why;             // why unknown
};

struct InjectStatus {
    bool ok = false;             // the status route answered
    bool transport_error = false;
    std::string error;
    bool wired = false;
    bool enabled = false;
    int64_t pool_entries = 0;
    int64_t pool_bytes = 0;
    int64_t pool_max_entries = 0;
    int64_t pool_max_total_bytes = 0;
    bool have_rate = false;
    int64_t local_in_window = 0;
    int64_t max_per_window = 0;
    int64_t window_sec = 60;
};

struct MempoolView {
    bool ok = false;
    std::set<std::string> txids;
    std::string error;
};

struct MempoolEntryInfo {
    bool ok = false;      // the route answered
    bool present = false;
    std::optional<int64_t> time_added;
    std::string error;
};

struct BlockInfo {
    bool ok = false;      // the route answered with a block object
    bool has_body = false;
    int64_t height = 0;
    std::string hash;
    std::vector<std::string> txids;
    std::string error;
};

struct FindResult {
    bool found = false;
    int64_t height = 0;
    std::string hash;
    int64_t searched = 0;     // heights with a body that were searched
    int64_t missing = 0;      // heights without a retained body
    std::string why;
};

class ChainView {
public:
    explicit ChainView(NodeApi& api) : api_(api) {}

    // Drop every cached answer (call once at the start of a tick).
    void begin_tick();

    const TipInfo& tip();
    const InjectStatus& inject_status(bool refresh = false);
    const MempoolView& mempool();
    void invalidate_mempool() { mempool_.reset(); }
    MempoolEntryInfo mempool_entry(const std::string& txid);
    const BlockInfo& block_at(int64_t height);
    std::optional<std::string> block_hash(int64_t height, std::string& why);

    // Search heights [lo, hi] newest-first for `txid` in retained bodies.
    FindResult find_tx(const std::string& txid, int64_t lo, int64_t hi);

    NodeApi& api() { return api_; }

private:
    NodeApi& api_;
    std::optional<TipInfo> tip_;
    std::optional<InjectStatus> status_;
    std::optional<MempoolView> mempool_;
    std::map<int64_t, BlockInfo> blocks_;
};

} // namespace c2w::companion::sched
