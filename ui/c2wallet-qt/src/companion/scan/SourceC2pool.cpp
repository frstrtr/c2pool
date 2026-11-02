// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SourceC2pool.hpp"

#include "../sched/Json.hpp"

#include <algorithm>
#include <chrono>
#include <set>

namespace c2w::companion::scan {

namespace {

using J = sched::json::J;

[[noreturn]] void bad(const std::string& what) { throw ScanRefusal(cause::kBadReply, "/api/utxo/scan: " + what); }

int64_t need_int(const J& o, const char* k, const std::string& where)
{
    const auto it = o.find(k);
    if (it == o.end() || !it->is_number_integer()) bad(where + ": \"" + k + "\" must be an integer");
    return it->get<int64_t>();
}

std::string need_str(const J& o, const char* k, const std::string& where)
{
    const auto it = o.find(k);
    if (it == o.end() || !it->is_string()) bad(where + ": \"" + k + "\" must be a string");
    return it->get<std::string>();
}

bool need_bool(const J& o, const char* k, const std::string& where)
{
    const auto it = o.find(k);
    if (it == o.end() || !it->is_boolean()) bad(where + ": \"" + k + "\" must be a boolean");
    return it->get<bool>();
}

// The node's refusal name: {"error": "..."} or {"cause": "..."}, else the body.
std::string refusal_name(const std::string& body)
{
    J j;
    std::string why;
    if (sched::json::parse_bounded(body, j, why) && j.is_object()) {
        for (const char* k : {"error", "cause"}) {
            const auto it = j.find(k);
            if (it != j.end() && it->is_string()) return it->get<std::string>();
        }
    }
    return body.size() > 200 ? body.substr(0, 200) + "..." : body;
}

} // namespace

std::string utxo_scan_path(const std::vector<std::string>& addresses, bool exclude_mempool_spent)
{
    std::string p = kUtxoScanRoute;
    char sep = '?';
    for (const std::string& a : addresses) {
        p += sep;
        p += "address=" + a;
        sep = '&';
    }
    p += sep;
    p += std::string("exclude_mempool_spent=") + (exclude_mempool_spent ? "1" : "0");
    return p;
}

ScanResult SourceC2pool::scan(const std::vector<std::string>& addresses, const ScanOptions& opt)
{
    const auto t0 = std::chrono::steady_clock::now();
    const std::vector<AddressScript> scripts = address_scripts(addresses, opt.testnet);
    const std::string path = utxo_scan_path(addresses, true);
    for (int attempt = 1;; ++attempt) {
        if (is_cancelled(opt)) throw ScanRefusal(cause::kCancelled, "cancelled before the node scan");
        const sched::HttpReply r = node_.get(path);
        // A cancel aborts the GET on our side (the transport's stop check);
        // the node finishes its pass and drops the result, and refuses
        // another scan within its 10 s rate window (utxo-scan-rate).
        if (is_cancelled(opt))
            throw ScanRefusal(cause::kCancelled, "cancelled: the node scan request was dropped (the node finishes its "
                                                 "pass and discards it; a new scan may wait out its 10 s rate window)");
        if (!r.transport_ok) throw ScanRefusal(cause::kTransport, "c2pool " + path + ": " + r.error);
        if (r.status != 200) {
            const std::string name = refusal_name(r.body);
            if (r.status == 404) throw ScanRefusal(cause::kNodeNoRoute, "the node has no " + std::string(kUtxoScanRoute) +
                                                                       " route (HTTP 404: " + name + ")");
            if (name.rfind("utxo-set-", 0) == 0)
                throw ScanRefusal(cause::kNodeUtxoNotFull, "the node does not serve a full UTXO set (" + name + ")");
            throw ScanRefusal(cause::kNodeRefused, "HTTP " + std::to_string(r.status) + ": " + name);
        }
        J j;
        std::string why;
        if (!sched::json::parse_bounded(r.body, j, why) || !j.is_object()) bad(why.empty() ? "not a JSON object" : why);
        if (!need_bool(j, "ok", "reply")) throw ScanRefusal(cause::kNodeRefused, "ok:false: " + refusal_name(r.body));

        const auto utxo = j.find("utxo");
        if (utxo == j.end() || !utxo->is_object()) bad("no \"utxo\" posture object");
        const std::string mode = need_str(*utxo, "mode", "utxo");
        const std::string state = need_str(*utxo, "state", "utxo");
        if (mode != "full" || state != "serving")
            throw ScanRefusal(cause::kNodeUtxoNotFull, "utxo mode \"" + mode + "\" state \"" + state +
                                                           "\": a scan needs the full set serving");
        if (need_bool(j, "truncated", "reply"))
            throw ScanRefusal(cause::kTruncated, "the node stopped at its row limit; an incomplete set is not exported");
        if (need_bool(j, "tip_moved", "reply")) {
            if (attempt >= opt.c2pool_tip_retries)
                throw ScanRefusal(cause::kTipUnstable, "the node tip moved during " + std::to_string(attempt) +
                                                           " scans; try again");
            continue;
        }

        const int64_t tip_height = need_int(j, "tip_height", "reply");
        const std::string tip_hash = lower(need_str(j, "tip_hash", "reply"));

        // The scripts the node matched must be exactly the requested ones.
        const auto sc = j.find("scripts");
        if (sc == j.end() || !sc->is_array()) bad("no \"scripts\" array");
        // The node names the address it matched when asked by address; the
        // script is the match itself and always present.
        std::set<std::string> want, got;
        for (const AddressScript& a : scripts) want.insert(a.script_hex);
        for (const J& s : *sc) {
            if (!s.is_object()) bad("scripts: not an object");
            const std::string hex = lower(need_str(s, "script_hex", "scripts"));
            const auto ad = s.find("address");
            if (ad != s.end() && ad->is_string()) {
                bool named = false;
                for (const AddressScript& a : scripts) named |= a.address == ad->get<std::string>() && a.script_hex == hex;
                if (!named)
                    throw ScanRefusal(cause::kSourceInconsistent, "the node matched " + ad->get<std::string>() +
                                                                      " to another script than its P2PKH");
            }
            got.insert(hex);
        }
        if (got != want)
            throw ScanRefusal(cause::kSourceInconsistent, "the node matched other scripts than the requested addresses");

        const auto un = j.find("unspents");
        if (un == j.end() || !un->is_array()) bad("no \"unspents\" array");
        std::set<Outpoint> spent;
        const auto ms = j.find("mempool_spent");
        if (ms != j.end() && !ms->is_null()) {
            if (!ms->is_array()) bad("\"mempool_spent\" must be an array");
            for (const J& o : *ms) {
                if (!o.is_object()) bad("mempool_spent: not an object");
                const std::string txid = lower(need_str(o, "txid", "mempool_spent"));
                const int64_t vout = need_int(o, "vout", "mempool_spent");
                if (!is_hex64(txid) || vout < 0 || vout > 0xffffffffll) bad("mempool_spent: bad outpoint");
                spent.insert({txid, static_cast<uint32_t>(vout)});
            }
        }
        std::vector<RawRow> rows;
        int64_t sum = 0;
        for (size_t i = 0; i < un->size(); ++i) {
            const J& o = (*un)[i];
            const std::string where = "unspent " + std::to_string(i);
            if (!o.is_object()) bad(where + ": not an object");
            RawRow row;
            c2w::dash::Utxo& u = row.utxo;
            u.txid = lower(need_str(o, "txid", where));
            const int64_t vout = need_int(o, "vout", where);
            if (vout < 0 || vout > 0xffffffffll) bad(where + ": vout out of range");
            u.vout = static_cast<uint32_t>(vout);
            u.satoshis = need_int(o, "value", where);
            u.script_pubkey_hex = lower(need_str(o, "script_hex", where));
            u.height = need_int(o, "height", where);
            u.coinbase = need_bool(o, "coinbase", where);
            if (u.satoshis < 0 || __builtin_add_overflow(sum, u.satoshis, &sum)) bad(where + ": bad value");
            // exclude_mempool_spent=1: the node lists those separately. A row
            // in both lists is excluded, never exported.
            if (spent.count({u.txid, u.vout})) continue;
            rows.push_back(std::move(row));
        }
        if (j.contains("total_value") && need_int(j, "total_value", "reply") != sum)
            throw ScanRefusal(cause::kSourceInconsistent, "total_value disagrees with the sum of the rows");

        ScanResult out;
        out.source = kSourceC2pool;
        out.tip_height = tip_height;
        out.tip_hash = tip_hash;
        out.imports = group_rows(rows, scripts, tip_height, tip_hash, opt.testnet);
        out.mempool_spent.assign(spent.begin(), spent.end());
        out.c2pool_detail = "utxo " + mode + " " + state;
        if (utxo->contains("coins") && (*utxo)["coins"].is_number_integer())
            out.c2pool_detail += " coins=" + std::to_string((*utxo)["coins"].get<int64_t>());
        out.elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        return out;
    }
}

} // namespace c2w::companion::scan
