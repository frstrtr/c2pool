// SPDX-License-Identifier: AGPL-3.0-or-later
#include "CrossCheck.hpp"

#include <map>
#include <optional>
#include <set>

namespace c2w::companion::scan {

namespace {

using c2w::dash::Utxo;

std::set<Outpoint> spent_union(const ScanResult& a, const ScanResult& b)
{
    std::set<Outpoint> s(a.mempool_spent.begin(), a.mempool_spent.end());
    s.insert(b.mempool_spent.begin(), b.mempool_spent.end());
    return s;
}

std::map<Outpoint, const Utxo*> rows_of(const ScanResult& r, const std::set<Outpoint>& spent)
{
    std::map<Outpoint, const Utxo*> m;
    for (const auto& imp : r.imports)
        for (const Utxo& u : imp.utxos)
            if (!spent.count({u.txid, u.vout})) m[{u.txid, u.vout}] = &u;
    return m;
}

std::string cb(const std::optional<bool>& c) { return !c ? "unknown" : (*c ? "true" : "false"); }

// Posture refusals: the source cannot serve this scan at all. Only these may
// be downgraded to a single-source scan.
bool is_unavailable(const ScanRefusal& e)
{
    return e.cause() == cause::kNodeNoRoute || e.cause() == cause::kNodeUtxoNotFull ||
           e.cause() == cause::kTransport || e.cause() == cause::kNodeRefused;
}

ScanResult drop_spent(ScanResult r, const std::set<Outpoint>& spent)
{
    for (auto& imp : r.imports) {
        std::vector<Utxo> kept;
        imp.total = 0;
        for (Utxo& u : imp.utxos)
            if (!spent.count({u.txid, u.vout})) {
                imp.total += u.satoshis;
                kept.push_back(std::move(u));
            }
        imp.utxos = std::move(kept);
    }
    r.mempool_spent.assign(spent.begin(), spent.end());
    return r;
}

} // namespace

std::vector<std::string> diff_scans(const ScanResult& a, const ScanResult& b)
{
    std::vector<std::string> out;
    const std::set<Outpoint> spent = spent_union(a, b);
    const auto ra = rows_of(a, spent);
    const auto rb = rows_of(b, spent);
    for (const auto& [op, u] : ra) {
        const auto it = rb.find(op);
        const std::string name = outpoint_str(op);
        if (it == rb.end()) {
            out.push_back(name + " only in " + a.source);
            continue;
        }
        const Utxo& v = *it->second;
        if (u->satoshis != v.satoshis)
            out.push_back(name + " value " + std::to_string(u->satoshis) + " != " + std::to_string(v.satoshis));
        if (u->script_pubkey_hex != v.script_pubkey_hex)
            out.push_back(name + " script " + u->script_pubkey_hex + " != " + v.script_pubkey_hex);
        if (u->height != v.height)
            out.push_back(name + " height " + std::to_string(u->height) + " != " + std::to_string(v.height));
        if (u->coinbase != v.coinbase) out.push_back(name + " coinbase " + cb(u->coinbase) + " != " + cb(v.coinbase));
    }
    for (const auto& [op, v] : rb)
        if (!ra.count(op)) out.push_back(outpoint_str(op) + " only in " + b.source);
    return out;
}

ScanResult scan_both(UtxoSource& dashd, UtxoSource& c2pool, const std::vector<std::string>& addresses,
                     const ScanOptions& opt, const CrossCheckOptions& cc)
{
    std::optional<ScanResult> a, b;
    std::optional<ScanRefusal> a_err, b_err;
    try { a = dashd.scan(addresses, opt); } catch (const ScanRefusal& e) {
        if (!is_unavailable(e)) throw;
        a_err = e;
    }
    try { b = c2pool.scan(addresses, opt); } catch (const ScanRefusal& e) {
        if (!is_unavailable(e)) throw;
        b_err = e;
    }
    if (a_err || b_err) {
        if (a_err && b_err) throw *a_err;
        const ScanRefusal& why = a_err ? *a_err : *b_err;
        if (!cc.allow_single_source)
            throw ScanRefusal(why.cause(), std::string(why.what()) +
                                               " -- no cross-check possible; allow a single-source scan to export "
                                               "from the other source alone (cross_checked false)");
        ScanResult one = a ? *a : *b;
        one.cross_checked = false;
        one.warning = (one.warning.empty() ? "" : one.warning + "; ") + "single source: " +
                      (a_err ? "dashd" : "c2pool") + " unavailable (" + why.what() + ")";
        return one;
    }

    for (int round = 0; a->tip_hash != b->tip_hash; ++round) {
        if (round >= cc.tip_rounds)
            throw ScanRefusal(cause::kTipsDiffer, "dashd is at " + std::to_string(a->tip_height) + " " + a->tip_hash +
                                                      ", the node at " + std::to_string(b->tip_height) + " " +
                                                      b->tip_hash + " after " + std::to_string(round) + " re-reads");
        if (a->tip_height <= b->tip_height) a = dashd.scan(addresses, opt);
        if (b->tip_height <= a->tip_height && a->tip_hash != b->tip_hash) b = c2pool.scan(addresses, opt);
    }

    const std::vector<std::string> diffs = diff_scans(*a, *b);
    if (!diffs.empty()) {
        std::string d;
        for (size_t i = 0; i < diffs.size() && i < 20; ++i) d += (i ? "; " : "") + diffs[i];
        if (diffs.size() > 20) d += "; ... " + std::to_string(diffs.size() - 20) + " more";
        throw ScanRefusal(cause::kSourceMismatch, "dashd and the node disagree at tip " +
                                                      std::to_string(a->tip_height) + ": " + d);
    }
    ScanResult out = drop_spent(*a, spent_union(*a, *b));
    out.source = kSourceBoth;
    out.cross_checked = true;
    out.c2pool_detail = b->c2pool_detail;
    if (!b->warning.empty()) out.warning = (out.warning.empty() ? "" : out.warning + "; ") + b->warning;
    out.elapsed_ms = a->elapsed_ms + b->elapsed_ms;
    return out;
}

} // namespace c2w::companion::scan
