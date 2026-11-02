// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// GET /api/utxo/scan — every unspent coin of the full UTXO set that pays one
/// of up to 16 scripts (c2wallet Scan & Plan, node slice N1). Read-only: it
/// reads the set and the mempool and changes neither.
///
/// Request (query string):
///   address=   base58 P2PKH/P2SH of the node's network, matched as its script
///   script=    hex scriptPubKey (the general form)
///              address= and script= together: 1..16, duplicates counted once
///   exclude_mempool_spent=0|1   default 1
///   min_value= duffs, default 0
///   limit=     rows, default 20000, max 100000
///
/// Reply (200):
///   { ok, tip_height, tip_hash, utxo{mode,state,coins}, scanned, elapsed_ms,
///     tip_moved, truncated, scripts[{address?,script_hex}],
///     unspents[{txid,vout,value,script_hex,height,coinbase}],
///     mempool_spent[{txid,vout,spent_by}], total_value }
/// The rows are the set at tip_hash (UTXOViewCache::scan_coins reads one
/// LevelDB snapshot taken with the best block). tip_moved: the lane connected
/// a block during the pass, or had unflushed changes when it began; the
/// caller scans again. truncated: more rows matched than `limit`; the pass
/// stopped there. A coin a pool tx spends is listed in mempool_spent and,
/// with exclude_mempool_spent=1, left out of unspents and total_value.
///
/// Refusals, named in "error", with an "http_status" hint:
///   400 utxo-scan-bad-param | utxo-scan-bad-address | utxo-scan-bad-script |
///       utxo-scan-no-script | utxo-scan-too-many-scripts
///   409 utxo-set-not-full | utxo-set-withheld | utxo-set-catching-up |
///       utxo-set-verifying-base | utxo-set-not-serving — from the lane's
///       published status: a scan of the 288-block accrual view (or of a set
///       that is not at the tip) would silently miss coins, so it is refused,
///       not degraded
///   500 utxo-scan-db-error      503 utxo-scan-cancelled | utxo-scan-detached
/// The direct-local gate (403), one scan at a time (409 utxo-scan-busy), the
/// rate (429) and the wait cap (504) belong to the web server
/// (MiningInterface::rest_utxo_scan), which runs this on its scan thread —
/// never on the node io thread.

#include "governance_object.hpp"   // dash_address_to_script (chain-strict base58)
#include "utxo_adapter.hpp"
#include "utxo_lane.hpp"

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

inline constexpr size_t   kUtxoScanMaxScripts   = 16;
inline constexpr size_t   kUtxoScanDefaultLimit = 20000;
inline constexpr size_t   kUtxoScanMaxLimit     = 100000;
inline constexpr size_t   kUtxoScanMaxScriptLen = 10000;   // MAX_SCRIPT_SIZE
inline constexpr int64_t  kUtxoScanMaxMoney     = 21'000'000LL * 100'000'000LL;

struct UtxoScanRequest {
    struct Script {
        std::string          address;   // empty for script=
        std::vector<uint8_t> spk;
    };
    std::vector<Script> scripts;
    bool    exclude_mempool_spent{true};
    int64_t min_value{0};
    size_t  limit{kUtxoScanDefaultLimit};
};

namespace utxo_scan_detail {

inline std::string hex(const uint8_t* p, size_t n)
{
    static constexpr char H[] = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        s[2 * i] = H[p[i] >> 4];
        s[2 * i + 1] = H[p[i] & 0x0f];
    }
    return s;
}

inline bool unhex(const std::string& s, std::vector<uint8_t>& out)
{
    if (s.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int a = nib(s[i]), b = nib(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<uint8_t>((a << 4) | b));
    }
    return true;
}

/// Percent-decoding of one query component ('+' is a space).
inline bool url_decode(const std::string& in, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c == '+') {
            out.push_back(' ');
        } else if (c == '%') {
            std::vector<uint8_t> b;
            if (i + 2 >= in.size()) return false;
            if (!unhex(in.substr(i + 1, 2), b)) return false;
            out.push_back(static_cast<char>(b[0]));
            i += 2;
        } else {
            out.push_back(c);
        }
    }
    return true;
}

template <typename T>
inline bool parse_uint(const std::string& s, T& out)
{
    if (s.empty()) return false;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

inline nlohmann::json refusal(int http, const std::string& error, const std::string& detail = std::string())
{
    nlohmann::json j = {{"ok", false}, {"error", error}, {"http_status", http}};
    if (!detail.empty()) j["detail"] = detail;
    return j;
}

} // namespace utxo_scan_detail

/// Parse the query string of a scan request. False with a named `error`
/// (http 400) and a `detail` on any bad or unknown parameter.
inline bool parse_utxo_scan_query(const std::string& query, bool testnet, UtxoScanRequest& out,
                                  std::string& error, std::string& detail)
{
    using namespace utxo_scan_detail;
    out = UtxoScanRequest{};
    auto add_script = [&](std::vector<uint8_t> spk, const std::string& address) {
        for (const auto& s : out.scripts)
            if (s.spk == spk) return true;   // counted once
        if (out.scripts.size() >= kUtxoScanMaxScripts) {
            error = "utxo-scan-too-many-scripts";
            detail = "at most " + std::to_string(kUtxoScanMaxScripts) + " addresses and scripts in all";
            return false;
        }
        out.scripts.push_back({address, std::move(spk)});
        return true;
    };
    size_t start = 0;
    while (start <= query.size()) {
        size_t end = query.find('&', start);
        if (end == std::string::npos) end = query.size();
        const std::string part = query.substr(start, end - start);
        start = end + 1;
        if (part.empty()) {
            if (end == query.size()) break;
            continue;
        }
        const size_t eq = part.find('=');
        std::string key, value;
        if (!url_decode(part.substr(0, eq), key) ||
            !url_decode(eq == std::string::npos ? std::string() : part.substr(eq + 1), value)) {
            error = "utxo-scan-bad-param";
            detail = "bad percent-encoding in '" + part + "'";
            return false;
        }
        if (key == "address") {
            auto spk = dash_address_to_script(value, testnet);
            if (spk.empty()) {
                error = "utxo-scan-bad-address";
                detail = "'" + value + "' is not a base58 P2PKH/P2SH address of this node's network (" +
                         (testnet ? "testnet" : "mainnet") + ")";
                return false;
            }
            if (!add_script(std::move(spk), value)) return false;
        } else if (key == "script") {
            std::vector<uint8_t> spk;
            if (!unhex(value, spk) || spk.empty() || spk.size() > kUtxoScanMaxScriptLen) {
                error = "utxo-scan-bad-script";
                detail = "script= must be 1.." + std::to_string(kUtxoScanMaxScriptLen) + " bytes of hex";
                return false;
            }
            if (!add_script(std::move(spk), std::string())) return false;
        } else if (key == "exclude_mempool_spent") {
            if (value == "1" || value == "true") out.exclude_mempool_spent = true;
            else if (value == "0" || value == "false") out.exclude_mempool_spent = false;
            else {
                error = "utxo-scan-bad-param";
                detail = "exclude_mempool_spent must be 0 or 1";
                return false;
            }
        } else if (key == "min_value") {
            uint64_t v = 0;
            if (!parse_uint(value, v) || v > static_cast<uint64_t>(kUtxoScanMaxMoney)) {
                error = "utxo-scan-bad-param";
                detail = "min_value must be duffs, 0.." + std::to_string(kUtxoScanMaxMoney);
                return false;
            }
            out.min_value = static_cast<int64_t>(v);
        } else if (key == "limit") {
            size_t v = 0;
            if (!parse_uint(value, v) || v == 0 || v > kUtxoScanMaxLimit) {
                error = "utxo-scan-bad-param";
                detail = "limit must be 1.." + std::to_string(kUtxoScanMaxLimit);
                return false;
            }
            out.limit = v;
        } else {
            error = "utxo-scan-bad-param";
            detail = "unknown parameter '" + key + "'";
            return false;
        }
    }
    if (out.scripts.empty()) {
        error = "utxo-scan-no-script";
        detail = "give at least one address= or script=";
        return false;
    }
    return true;
}

/// The lane posture a scan needs: a full set, serving. nullopt = scan.
inline std::optional<std::string> utxo_scan_posture_refusal(const UtxoLane::FullStatus& st)
{
    if (!st.full) return std::string("utxo-set-not-full");
    if (st.state == "serving") return std::nullopt;
    if (st.state == "withheld") return std::string("utxo-set-withheld");
    if (st.state == "catching-up") return std::string("utxo-set-catching-up");
    if (st.state == "verifying-base") return std::string("utxo-set-verifying-base");
    return std::string("utxo-set-not-serving");
}

/// Which of the given outpoints a pool tx spends (Mempool::pool_spenders).
using UtxoScanSpendersFn = std::function<std::vector<std::pair<Outpoint, uint256>>(
    const std::vector<Outpoint>&)>;

/// The scan proper over `cache` (the posture is the caller's): the 200 reply,
/// or 500 utxo-scan-db-error / 503 utxo-scan-cancelled. The reply carries
/// "scanned" whenever the pass ran (the web server's rate counts those).
inline nlohmann::json run_utxo_scan(const UtxoViewCache& cache, const UtxoScanRequest& req,
                                    const UtxoScanSpendersFn& spenders,
                                    const std::function<bool()>& cancelled = {})
{
    using namespace utxo_scan_detail;
    using Clock = std::chrono::steady_clock;
    const auto t0 = Clock::now();

    struct Row {
        Outpoint op;
        ::core::coin::Coin coin;
    };
    std::vector<Row> rows;
    bool truncated = false;
    auto match = [&req](const uint8_t* spk, size_t len) {
        for (const auto& s : req.scripts)
            if (s.spk.size() == len && std::memcmp(s.spk.data(), spk, len) == 0) return true;
        return false;
    };
    auto take = [&](const Outpoint& op, const ::core::coin::Coin& c) {
        if (c.value < req.min_value) return true;
        if (rows.size() >= req.limit) {
            truncated = true;
            return false;
        }
        rows.push_back({op, c});
        return true;
    };
    const auto st = cache.scan_coins(match, take, cancelled);
    if (st.cancelled) {
        auto j = refusal(503, "utxo-scan-cancelled", "the node is stopping");
        j["scanned"] = st.scanned;
        return j;
    }
    if (!st.ok) {
        auto j = refusal(500, "utxo-scan-db-error", "the full set's 'C' records could not be read");
        j["scanned"] = st.scanned;
        return j;
    }

    std::map<std::pair<uint256, uint32_t>, uint256> spent_by;
    if (spenders && !rows.empty()) {
        std::vector<Outpoint> ops;
        ops.reserve(rows.size());
        for (const auto& r : rows) ops.push_back(r.op);
        for (const auto& [op, txid] : spenders(ops)) spent_by.emplace(std::make_pair(op.txid, op.index), txid);
    }

    nlohmann::json scripts = nlohmann::json::array();
    for (const auto& s : req.scripts) {
        nlohmann::json e = nlohmann::json::object();
        if (!s.address.empty()) e["address"] = s.address;
        e["script_hex"] = hex(s.spk.data(), s.spk.size());
        scripts.push_back(std::move(e));
    }
    nlohmann::json unspents = nlohmann::json::array();
    nlohmann::json mempool_spent = nlohmann::json::array();
    int64_t total = 0;
    for (const auto& r : rows) {
        const auto sp = spent_by.find(std::make_pair(r.op.txid, r.op.index));
        if (sp != spent_by.end()) {
            mempool_spent.push_back({{"txid", r.op.txid.GetHex()}, {"vout", r.op.index},
                                     {"spent_by", sp->second.GetHex()}});
            if (req.exclude_mempool_spent) continue;
        }
        const auto& spk = r.coin.scriptPubKey.m_data;
        unspents.push_back({{"txid", r.op.txid.GetHex()},
                            {"vout", r.op.index},
                            {"value", r.coin.value},
                            {"script_hex", hex(spk.data(), spk.size())},
                            {"height", r.coin.height},
                            {"coinbase", r.coin.coinbase}});
        total += r.coin.value;
    }

    nlohmann::json j = nlohmann::json::object();
    j["ok"] = true;
    j["tip_height"] = st.best_height;
    j["tip_hash"] = st.best_block.GetHex();
    j["scanned"] = st.scanned;
    j["elapsed_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
    j["tip_moved"] = st.tip_moved();
    j["truncated"] = truncated;
    j["scripts"] = std::move(scripts);
    j["unspents"] = std::move(unspents);
    j["mempool_spent"] = std::move(mempool_spent);
    j["total_value"] = total;
    j["http_status"] = 200;
    return j;
}

/// The node state a scan reads, shared with the web server's scan thread.
/// handle() is the scan fn; detach() is called by the coin target before the
/// lane or the mempool is destroyed: it cancels a running pass, waits for it,
/// and every later request is refused (503 utxo-scan-detached).
class UtxoScanSource {
public:
    UtxoScanSource(UtxoLane& lane, UtxoScanSpendersFn spenders, bool testnet)
        : m_lane(&lane), m_spenders(std::move(spenders)), m_testnet(testnet)
    {}
    UtxoScanSource(const UtxoScanSource&) = delete;
    UtxoScanSource& operator=(const UtxoScanSource&) = delete;

    nlohmann::json handle(const std::string& query, const std::atomic<bool>& cancel)
    {
        using namespace utxo_scan_detail;
        std::lock_guard<std::mutex> lk(m_mu);
        if (!m_lane) return refusal(503, "utxo-scan-detached", "the node is stopping");
        UtxoScanRequest req;
        std::string error, detail;
        if (!parse_utxo_scan_query(query, m_testnet, req, error, detail)) return refusal(400, error, detail);
        // The published status (any thread). cache() is read only once the
        // status says full: open_full sets the cache before it publishes.
        const auto st = m_lane->full_status();
        nlohmann::json utxo = {{"mode", st.full ? "full" : "not-full"}};
        if (st.full) {
            utxo["state"] = st.state;
            utxo["coins"] = st.coins;
            utxo["best_height"] = st.best_height;
        }
        if (auto why = utxo_scan_posture_refusal(st)) {
            auto j = refusal(409, *why, st.withheld_reason);
            j["utxo"] = std::move(utxo);
            return j;
        }
        const UtxoViewCache* cache = m_lane->cache();
        if (!cache) {
            auto j = refusal(409, "utxo-set-not-full");
            j["utxo"] = std::move(utxo);
            return j;
        }
        auto j = run_utxo_scan(*cache, req, m_spenders,
                               [&cancel, this] { return cancel.load() || m_cancel.load(); });
        j["utxo"] = std::move(utxo);
        return j;
    }

    void detach()
    {
        m_cancel.store(true);
        std::lock_guard<std::mutex> lk(m_mu);
        m_lane = nullptr;
        m_spenders = nullptr;
    }

private:
    std::mutex         m_mu;        // held for a whole request: detach() waits for it
    UtxoLane*          m_lane;
    UtxoScanSpendersFn m_spenders;
    bool               m_testnet;
    std::atomic<bool>  m_cancel{false};
};

} // namespace coin
} // namespace dash
