// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SourceDashd.hpp"

#include "../sched/Json.hpp"

#include <algorithm>
#include <chrono>
#include <optional>

namespace c2w::companion::scan {

namespace {

using J = sched::json::J;
using c2w::dash::Utxo;

// A JSON-RPC error answer. Internal: scan() turns an unhandled one into
// ScanRefusal(kRpcError); the getaddressutxos call handles -32600 itself.
struct RpcErr {
    int64_t code = 0;
    std::string message;
};

constexpr int64_t kRpcInvalidRequest = -32600; // "Address index is disabled"

class Rpc {
public:
    Rpc(RpcApi& api, CancelCheck cancelled) : api_(api), cancelled_(std::move(cancelled)) {}

    bool cancelled() const { return cancelled_ && cancelled_(); }

    J call(const std::string& method, const J& params)
    {
        if (cancelled()) throw ScanRefusal(cause::kCancelled, "cancelled before dashd " + method);
        return finish(method, api_.call(method, sched::json::dump_compact(params)));
    }

    // scantxoutset "start": on a cancel the transport sends scantxoutset
    // "abort" on its own request and waits for the start to return.
    J call_scan(const J& params, bool& aborted)
    {
        if (cancelled()) throw ScanRefusal(cause::kCancelled, "cancelled before dashd scantxoutset");
        const RpcReply r = api_.call_long("scantxoutset", sched::json::dump_compact(params), cancelled_, [&] {
            aborted = true;
            (void)api_.call("scantxoutset", R"(["abort"])");
        });
        if (aborted || cancelled())
            throw ScanRefusal(cause::kCancelled, "cancelled: dashd scantxoutset was aborted (scantxoutset \"abort\")");
        return finish("scantxoutset", r);
    }

private:
    J finish(const std::string& method, const RpcReply& r)
    {
        if (!r.transport_ok)
            throw ScanRefusal(cause::kTransport, "dashd " + method + ": " + r.error);
        // dashd answers a bad cookie / rpcauth with 401 and a client outside
        // rpcallowip with 403, both without a JSON-RPC envelope: name it, so
        // the operator fixes the credentials file, not the node.
        if (r.http_status == 401 || r.http_status == 403)
            throw ScanRefusal(cause::kAuthRefused, "dashd " + method + ": HTTP " + std::to_string(r.http_status) +
                                                       " (check the RPC cookie / rpcauth file and rpcallowip)");
        J env;
        std::string why;
        if (!sched::json::parse_bounded(r.body, env, why) || !env.is_object())
            throw ScanRefusal(cause::kBadReply, "dashd " + method + " (HTTP " + std::to_string(r.http_status) +
                                                    "): " + (why.empty() ? "not a JSON-RPC reply object" : why));
        const auto e = env.find("error");
        if (e != env.end() && !e->is_null()) {
            RpcErr err;
            if (e->is_object()) {
                const auto c = e->find("code");
                if (c != e->end() && c->is_number_integer()) err.code = c->get<int64_t>();
                const auto m = e->find("message");
                if (m != e->end() && m->is_string()) err.message = m->get<std::string>();
            }
            throw err;
        }
        if (r.http_status != 200)
            throw ScanRefusal(cause::kRpcError, "dashd " + method + ": HTTP " + std::to_string(r.http_status));
        const auto res = env.find("result");
        if (res == env.end())
            throw ScanRefusal(cause::kBadReply, "dashd " + method + ": reply without a result");
        return *res;
    }

    RpcApi& api_;
    CancelCheck cancelled_;
};

[[noreturn]] void bad(const std::string& what) { throw ScanRefusal(cause::kBadReply, what); }

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

// A DASH amount: dashd prints a float with 8 decimals; an integer is accepted too.
int64_t need_amount(const J& o, const char* k, const std::string& where)
{
    const auto it = o.find(k);
    if (it == o.end() || !it->is_number()) bad(where + ": \"" + k + "\" must be a number");
    int64_t duffs = 0;
    if (!dash_to_duffs(it->get<double>(), duffs)) bad(where + ": \"" + k + "\" is not a real DASH amount");
    return duffs;
}

void check_chain(const J& info, bool testnet)
{
    if (!info.is_object()) bad("getblockchaininfo: not an object");
    const std::string chain = need_str(info, "chain", "getblockchaininfo");
    // regtest / devnet use testnet addresses, as tools/export_utxos.py assumes.
    if ((chain == "main") == testnet)
        throw ScanRefusal(cause::kWrongNetwork, "dashd serves chain \"" + chain + "\", the scan is for " +
                                                    (testnet ? "testnet" : "mainnet"));
}

struct Snapshot {
    std::string source;
    std::string detail;
    int64_t tip_height = 0;
    std::string tip_hash;
    std::vector<RawRow> rows;
    std::vector<std::optional<bool>> scan_coinbase; // scantxoutset's own flag per row
    std::vector<Outpoint> spent;
};

Utxo row_base(const std::string& txid, int64_t vout, int64_t satoshis, int64_t height, const std::string& script,
              const std::string& where)
{
    if (!is_hex64(txid)) bad(where + ": txid must be 64 hex characters");
    if (vout < 0 || vout > 0xffffffffll) bad(where + ": output index out of range");
    Utxo u;
    u.txid = lower(txid);
    u.vout = static_cast<uint32_t>(vout);
    u.satoshis = satoshis;
    u.height = height;
    u.script_pubkey_hex = lower(script);
    return u;
}

// getaddressutxos. false when the tip moved while reading.
bool read_index(Rpc& rpc, const std::vector<AddressScript>& scripts, bool testnet, Snapshot& s)
{
    const J info = rpc.call("getblockchaininfo", J::array());
    check_chain(info, testnet);
    const int64_t before = need_int(info, "blocks", "getblockchaininfo");
    J addrs = J::array();
    for (const AddressScript& a : scripts) addrs.push_back(a.address);
    J req = J::object();
    req["addresses"] = addrs;
    req["chainInfo"] = true;
    const J res = rpc.call("getaddressutxos", J::array({req}));
    const J* rows = nullptr;
    if (res.is_object()) {
        // {"utxos": [...], "hash", "height"}: the tip the rows were read at.
        const auto u = res.find("utxos");
        if (u == res.end() || !u->is_array()) bad("getaddressutxos: object without a \"utxos\" array");
        rows = &*u;
        s.tip_height = need_int(res, "height", "getaddressutxos");
        s.tip_hash = lower(need_str(res, "hash", "getaddressutxos"));
    } else if (res.is_array()) {
        // A dashd that ignores chainInfo: the tip is the one read before.
        rows = &res;
        s.tip_height = before;
        const J h = rpc.call("getblockhash", J::array({before}));
        if (!h.is_string()) bad("getblockhash: not a string");
        s.tip_hash = lower(h.get<std::string>());
    } else {
        bad("getaddressutxos: neither an array nor the chainInfo object");
    }
    const J count = rpc.call("getblockcount", J::array());
    if (!count.is_number_integer()) bad("getblockcount: not an integer");
    if (count.get<int64_t>() != s.tip_height || before != s.tip_height) return false;

    s.source = kSourceDashdIndex;
    s.detail = "dashd addressindex";
    for (size_t i = 0; i < rows->size(); ++i) {
        const J& r = (*rows)[i];
        const std::string where = "getaddressutxos row " + std::to_string(i);
        if (!r.is_object()) bad(where + ": not an object");
        // dashd 23.x prints outputIndex; the help text says index.
        const char* idx = r.contains("outputIndex") ? "outputIndex" : "index";
        const int64_t sat = need_int(r, "satoshis", where);
        RawRow row;
        row.utxo = row_base(need_str(r, "txid", where), need_int(r, idx, where), sat,
                            need_int(r, "height", where), need_str(r, "script", where), where);
        if (r.contains("address") && r["address"].is_string()) row.stated_address = r["address"].get<std::string>();
        s.rows.push_back(std::move(row));
        s.scan_coinbase.push_back(std::nullopt);
    }
    return true;
}

// scantxoutset "start". false when the tip moved under the scan.
bool read_scantxoutset(Rpc& rpc, const std::vector<AddressScript>& scripts, bool testnet, Snapshot& s)
{
    const J info = rpc.call("getblockchaininfo", J::array());
    check_chain(info, testnet);
    J descs = J::array();
    for (const AddressScript& a : scripts) descs.push_back("addr(" + a.address + ")");
    bool aborted = false;
    const J res = rpc.call_scan(J::array({"start", descs}), aborted);
    if (!res.is_object()) bad("scantxoutset: not an object");
    const auto ok = res.find("success");
    if (ok == res.end() || !ok->is_boolean() || !ok->get<bool>())
        throw ScanRefusal(cause::kScanFailed, "scantxoutset did not complete (success is not true)");
    s.tip_height = need_int(res, "height", "scantxoutset");
    s.tip_hash = lower(need_str(res, "bestblock", "scantxoutset"));
    const J best = rpc.call("getbestblockhash", J::array());
    if (!best.is_string()) bad("getbestblockhash: not a string");
    if (lower(best.get<std::string>()) != s.tip_hash) return false;

    s.source = kSourceDashdScan;
    s.detail = "dashd scantxoutset";
    if (res.contains("txouts") && res["txouts"].is_number_integer())
        s.detail += " txouts=" + std::to_string(res["txouts"].get<int64_t>());
    const auto un = res.find("unspents");
    if (un == res.end() || !un->is_array()) bad("scantxoutset: no \"unspents\" array");
    int64_t sum = 0;
    for (size_t i = 0; i < un->size(); ++i) {
        const J& r = (*un)[i];
        const std::string where = "scantxoutset unspent " + std::to_string(i);
        if (!r.is_object()) bad(where + ": not an object");
        RawRow row;
        row.utxo = row_base(need_str(r, "txid", where), need_int(r, "vout", where), need_amount(r, "amount", where),
                            need_int(r, "height", where), need_str(r, "scriptPubKey", where), where);
        sum += row.utxo.satoshis;
        const auto cb = r.find("coinbase");
        if (cb != r.end() && !cb->is_boolean()) bad(where + ": \"coinbase\" must be a boolean");
        s.scan_coinbase.push_back(cb != r.end() ? std::optional<bool>(cb->get<bool>()) : std::nullopt);
        s.rows.push_back(std::move(row));
    }
    if (res.contains("total_amount") && sum != need_amount(res, "total_amount", "scantxoutset"))
        throw ScanRefusal(cause::kSourceInconsistent, "scantxoutset total_amount disagrees with the sum of its rows");
    return true;
}

// gettxout per row. false when the tip moved during the pass.
bool confirm_rows(Rpc& rpc, Snapshot& s)
{
    std::vector<RawRow> kept;
    for (size_t i = 0; i < s.rows.size(); ++i) {
        RawRow& row = s.rows[i];
        Utxo& u = row.utxo;
        const std::string where = "gettxout " + u.txid + ":" + std::to_string(u.vout);
        const J t = rpc.call("gettxout", J::array({u.txid, u.vout, true}));
        if (t.is_null()) {
            s.spent.push_back({u.txid, u.vout});
            continue;
        }
        if (!t.is_object()) bad(where + ": neither null nor an object");
        if (lower(need_str(t, "bestblock", where)) != s.tip_hash) return false;
        const int64_t value = need_amount(t, "value", where);
        const auto spk = t.find("scriptPubKey");
        if (spk == t.end() || !spk->is_object()) bad(where + ": no scriptPubKey object");
        const std::string hex = lower(need_str(*spk, "hex", where + " scriptPubKey"));
        const int64_t conf = need_int(t, "confirmations", where);
        const auto cb = t.find("coinbase");
        if (cb == t.end() || !cb->is_boolean()) bad(where + ": \"coinbase\" must be a boolean");
        if (value != u.satoshis)
            throw ScanRefusal(cause::kSourceInconsistent, where + " value " + std::to_string(value) +
                                                              " duffs != the scan's " + std::to_string(u.satoshis));
        if (hex != u.script_pubkey_hex)
            throw ScanRefusal(cause::kSourceInconsistent, where + " scriptPubKey " + hex + " != the scan's " +
                                                              u.script_pubkey_hex);
        if (conf != s.tip_height - u.height + 1)
            throw ScanRefusal(cause::kSourceInconsistent, where + " confirmations " + std::to_string(conf) +
                                                              " != tip - height + 1 = " +
                                                              std::to_string(s.tip_height - u.height + 1));
        if (s.scan_coinbase[i].has_value() && *s.scan_coinbase[i] != cb->get<bool>())
            throw ScanRefusal(cause::kSourceInconsistent, where + " coinbase flag disagrees with scantxoutset");
        u.coinbase = cb->get<bool>();
        kept.push_back(std::move(row));
    }
    s.rows = std::move(kept);
    return true;
}

} // namespace

std::vector<UnspentCheck> SourceDashd::check_unspent(const std::vector<Utxo>& inputs, const ScanOptions& opt)
{
    Rpc rpc(rpc_, opt.cancelled);
    std::vector<UnspentCheck> out;
    try {
        for (const Utxo& u : inputs) {
            UnspentCheck c;
            c.outpoint = {lower(u.txid), u.vout};
            const std::string where = "gettxout " + outpoint_str(c.outpoint);
            const J t = rpc.call("gettxout", J::array({c.outpoint.txid, u.vout, true}));
            if (t.is_null()) {
                c.problem = "spent (in a block or in dashd's mempool)";
            } else if (!t.is_object()) {
                bad(where + ": neither null nor an object");
            } else {
                const int64_t value = need_amount(t, "value", where);
                const auto spk = t.find("scriptPubKey");
                const std::string hex =
                    spk != t.end() && spk->is_object() ? lower(need_str(*spk, "hex", where)) : std::string();
                if (value != u.satoshis)
                    c.problem = "value " + std::to_string(value) + " duffs, the manifest says " + std::to_string(u.satoshis);
                else if (hex != lower(u.script_pubkey_hex))
                    c.problem = "scriptPubKey " + hex + ", the manifest says " + u.script_pubkey_hex;
                else
                    c.unspent = true;
            }
            out.push_back(std::move(c));
        }
    } catch (const RpcErr& e) {
        throw ScanRefusal(cause::kRpcError, "dashd answered error " + std::to_string(e.code) + ": " + e.message);
    }
    return out;
}

ScanResult SourceDashd::scan(const std::vector<std::string>& addresses, const ScanOptions& opt)
{
    const auto t0 = std::chrono::steady_clock::now();
    const std::vector<AddressScript> scripts = address_scripts(addresses, opt.testnet);
    Rpc rpc(rpc_, opt.cancelled);
    std::string warning;
    try {
        bool index = true;
        int index_tries = 0, scan_tries = 0;
        for (;;) {
            Snapshot s;
            bool stable = false;
            if (index) {
                if (index_tries >= opt.dashd_tip_retries)
                    throw ScanRefusal(cause::kTipUnstable, "the dashd tip kept moving over " +
                                                               std::to_string(index_tries) + " reads; try again");
                ++index_tries;
                try {
                    stable = read_index(rpc, scripts, opt.testnet, s);
                } catch (const RpcErr& e) {
                    if (e.code != kRpcInvalidRequest) throw;
                    index = false;
                    warning = "dashd has no address index (" + std::to_string(e.code) + " " + e.message +
                              "); used scantxoutset";
                    continue;
                }
            } else {
                if (scan_tries >= opt.scantxoutset_retries)
                    throw ScanRefusal(cause::kTipUnstable, "the dashd tip moved under " + std::to_string(scan_tries) +
                                                               " scantxoutset runs; try again");
                ++scan_tries;
                stable = read_scantxoutset(rpc, scripts, opt.testnet, s);
            }
            if (!stable || !confirm_rows(rpc, s)) continue;

            ScanResult out;
            out.source = s.source;
            out.tip_height = s.tip_height;
            out.tip_hash = s.tip_hash;
            out.imports = group_rows(s.rows, scripts, s.tip_height, s.tip_hash, opt.testnet);
            out.mempool_spent = std::move(s.spent);
            std::sort(out.mempool_spent.begin(), out.mempool_spent.end());
            out.dashd_detail = s.detail;
            out.warning = warning;
            out.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0)
                                 .count();
            return out;
        }
    } catch (const RpcErr& e) {
        throw ScanRefusal(cause::kRpcError, "dashd answered error " + std::to_string(e.code) + ": " + e.message);
    }
}

} // namespace c2w::companion::scan
