// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ChainView.hpp"

#include "Json.hpp"

namespace c2w::companion::sched {

namespace {

// Parse a 200 reply into `out`; false + why on transport / HTTP / JSON error or
// an {"error": ...} object.
bool read_reply(const HttpReply& r, json::J& out, std::string& why, bool& transport_error)
{
    transport_error = false;
    if (!r.transport_ok) {
        transport_error = true;
        why = "node unreachable (" + (r.error.empty() ? std::string("no reply") : r.error) + ")";
        return false;
    }
    std::string perr;
    const bool parsed = json::parse_bounded(r.body, out, perr);
    if (parsed && out.is_object() && out.contains("error") && out["error"].is_string()) {
        why = out["error"].get<std::string>();
        if (why == "Explorer not enabled") why += " (the node runs with --no-explorer)";
        return false;
    }
    if (r.status != 200) {
        why = "HTTP " + std::to_string(r.status);
        return false;
    }
    if (!parsed) {
        why = perr;
        return false;
    }
    return true;
}

} // namespace

void ChainView::begin_tick()
{
    tip_.reset();
    status_.reset();
    mempool_.reset();
    blocks_.clear();
}

const TipInfo& ChainView::tip()
{
    if (tip_) return *tip_;
    TipInfo t;
    json::J j;
    std::string why;
    if (!read_reply(api_.get(route::kChainInfo), j, why, t.transport_error)) {
        t.why = "tip unknown: getblockchaininfo: " + why;
        t.explorer_disabled = why.rfind("Explorer not enabled", 0) == 0;
    } else if (!j.is_object()) {
        t.why = "tip unknown: getblockchaininfo is not an object";
    } else {
        const bool synced = j.contains("synced") && j["synced"].is_boolean() && j["synced"].get<bool>();
        if (!synced) {
            std::string by = j.contains("sync_blocked_by") && j["sync_blocked_by"].is_string()
                                 ? j["sync_blocked_by"].get<std::string>()
                                 : std::string("not reported");
            t.why = "tip unknown: node not synced (sync_blocked_by=" + by + ")";
        } else if (!j.contains("blocks") || !j["blocks"].is_number_integer()) {
            t.why = "tip unknown: getblockchaininfo carries no numeric blocks";
        } else {
            t.known = true;
            t.height = j["blocks"].get<int64_t>();
            if (j.contains("bestblockhash") && j["bestblockhash"].is_string())
                t.hash = j["bestblockhash"].get<std::string>();
        }
    }
    tip_ = t;
    return *tip_;
}

const InjectStatus& ChainView::inject_status(bool refresh)
{
    if (status_ && !refresh) return *status_;
    InjectStatus s;
    json::J j;
    std::string why;
    if (!read_reply(api_.get(route::kStatus), j, why, s.transport_error) || !j.is_object()) {
        s.error = why.empty() ? "tx-inject-status is not an object" : why;
    } else {
        json::Reader rd;
        s.ok = true;
        s.wired = rd.boolean(j, "wired", "status");
        s.enabled = rd.boolean(j, "enabled", "status");
        if (const json::J* pool = rd.obj(j, "pool", "status")) {
            s.pool_entries = rd.i64(*pool, "entries", "status.pool");
            s.pool_bytes = rd.i64(*pool, "bytes", "status.pool");
            s.pool_max_entries = rd.i64(*pool, "max_entries", "status.pool");
            s.pool_max_total_bytes = rd.i64(*pool, "max_total_bytes", "status.pool");
        }
        if (const json::J* rl = rd.obj(j, "rate_limit", "status")) {
            const json::J* local = rd.obj(*rl, "local", "status.rate_limit");
            const json::J* caps = rd.obj(*rl, "caps", "status.rate_limit");
            if (local && caps) {
                s.have_rate = true;
                s.local_in_window = rd.i64(*local, "in_window", "status.rate_limit.local");
                s.max_per_window = rd.i64(*caps, "max_per_window", "status.rate_limit.caps");
                s.window_sec = rd.i64(*caps, "window_sec", "status.rate_limit.caps", 60);
            }
        }
        if (!rd.ok()) {
            s.ok = false;
            s.error = rd.err;
        }
    }
    status_ = s;
    return *status_;
}

const MempoolView& ChainView::mempool()
{
    if (mempool_) return *mempool_;
    MempoolView m;
    json::J j;
    std::string why;
    bool te = false;
    if (!read_reply(api_.get(route::kRawMempool), j, why, te)) {
        m.error = "getrawmempool: " + why;
    } else if (!j.is_array()) {
        m.error = "getrawmempool is not an array";
    } else {
        m.ok = true;
        for (const auto& e : j) {
            if (e.is_string()) m.txids.insert(e.get<std::string>());
            else if (e.is_object() && e.contains("txid") && e["txid"].is_string())
                m.txids.insert(e["txid"].get<std::string>());
        }
    }
    mempool_ = m;
    return *mempool_;
}

MempoolEntryInfo ChainView::mempool_entry(const std::string& txid)
{
    MempoolEntryInfo e;
    const HttpReply r = api_.get(std::string(route::kMempoolEntry) + txid);
    json::J j;
    std::string why;
    bool te = false;
    if (!read_reply(r, j, why, te)) {
        if (why == "Transaction not in mempool") {
            e.ok = true;
            e.present = false;
        } else {
            e.error = "getmempoolentry: " + why;
        }
        return e;
    }
    e.ok = true;
    e.present = j.is_object();
    if (e.present && j.contains("time_added") && j["time_added"].is_number_integer())
        e.time_added = j["time_added"].get<int64_t>();
    return e;
}

const BlockInfo& ChainView::block_at(int64_t height)
{
    auto it = blocks_.find(height);
    if (it != blocks_.end()) return it->second;
    BlockInfo b;
    b.height = height;
    json::J j;
    std::string why;
    bool te = false;
    if (!read_reply(api_.get(std::string(route::kBlockAtHeight) + std::to_string(height)), j, why, te)) {
        b.error = "getblock " + std::to_string(height) + ": " + why;
    } else if (!j.is_object()) {
        b.error = "getblock " + std::to_string(height) + ": not an object";
    } else {
        b.ok = true;
        if (j.contains("hash") && j["hash"].is_string()) b.hash = j["hash"].get<std::string>();
        if (j.contains("tx") && j["tx"].is_array()) {
            b.has_body = true;
            for (const auto& t : j["tx"]) {
                if (t.is_string()) b.txids.push_back(t.get<std::string>());
                else if (t.is_object() && t.contains("txid") && t["txid"].is_string())
                    b.txids.push_back(t["txid"].get<std::string>());
            }
        }
    }
    return blocks_.emplace(height, std::move(b)).first->second;
}

std::optional<std::string> ChainView::block_hash(int64_t height, std::string& why)
{
    json::J j;
    bool te = false;
    if (!read_reply(api_.get(std::string(route::kBlockHash) + std::to_string(height)), j, why, te))
        return std::nullopt;
    if (j.is_string()) return j.get<std::string>();
    if (j.is_object() && j.contains("result") && j["result"].is_string()) return j["result"].get<std::string>();
    why = "getblockhash: unexpected reply shape";
    return std::nullopt;
}

FindResult ChainView::find_tx(const std::string& txid, int64_t lo, int64_t hi)
{
    FindResult f;
    if (lo < 1) lo = 1;
    for (int64_t h = hi; h >= lo; --h) {
        const BlockInfo& b = block_at(h);
        if (!b.ok || !b.has_body) {
            ++f.missing;
            if (f.why.empty()) f.why = b.ok ? "no retained body at " + std::to_string(h) : b.error;
            continue;
        }
        ++f.searched;
        for (const auto& t : b.txids) {
            if (t == txid) {
                f.found = true;
                f.height = h;
                f.hash = b.hash;
                return f;
            }
        }
    }
    return f;
}

} // namespace c2w::companion::sched
