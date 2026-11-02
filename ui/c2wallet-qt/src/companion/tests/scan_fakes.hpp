// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Shared test doubles for the companion Scan & Plan KATs (test_scan.cpp) and
// the signer round trip (test_scan_roundtrip.cpp). Test-only; nothing here is
// linked into a companion or signer artifact.
//
//   FakeDashd     a scripted dashd JSON-RPC (scan::RpcApi): getaddressutxos
//                 with chainInfo / bare array / `index` or `outputIndex`, the
//                 -32600 of a dashd without addressindex, a SYNTHESISED
//                 scantxoutset reply (the field set of the real vm210 capture
//                 and the RPC help, built from the same rows), gettxout with
//                 mempool spends and contradicting answers, a tip-moving hook.
//   ReplayRpc     replays the REAL recorded vm210 session fixture.
//   FakeUtxoNode  a scripted c2pool node (sched::NodeApi) answering the
//                 SYNTHESISED /api/utxo/scan reply of the design's N1 shape.
//
// The chain view is the REAL getaddressutxos capture of XdgF55... at tip
// 2563986 with tests/mock_dash_cli.py's coinbase rule (outputIndex 1 =
// non-coinbase) and its tip hash.

#include "../scan/RpcApi.hpp"
#include "../scan/ScanFiles.hpp"
#include "../scan/ScanTypes.hpp"
#include "../scan/SourceDashd.hpp"
#include "../sched/NodeApi.hpp"

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace scan_kat {

using namespace c2w::companion::scan;
namespace dash = c2w::dash;
namespace sched = c2w::companion::sched;
namespace art = c2w::artifact;
using nj = nlohmann::json;

#ifndef C2W_DASH_FIXTURE_DIR
#error "C2W_DASH_FIXTURE_DIR must point at family/bitcoin/dash/tests/fixtures"
#endif

inline const char* const kXdgf = "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u";
inline const char* const kXdgfScript = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
inline const char* const kOther = "Xn9KtWHuvMBuSbpzPFTzYG2bC9Wp2ZZJJG"; // a second public mainnet P2PKH
inline constexpr int64_t kTip = 2563986;

inline std::string read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline std::string sha_hex(const std::string& s)
{
    return art::to_hex(art::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

// tests/mock_dash_cli.py's block hash at the fixture tip; any other tip hashes
// to a fixed function of its height.
inline std::string tip_hash_of(int64_t h)
{
    if (h == kTip) {
        std::string s = "0000000000000012";
        for (int i = 0; i < 24; ++i) s += "ab";
        return s;
    }
    return sha_hex("fake tip " + std::to_string(h));
}

inline std::string script_of(const std::string& addr)
{
    const auto s = dash::p2pkh_script(dash::addr_to_h160(addr, false));
    return art::to_hex(s.data(), s.size());
}

template <class F>
inline bool refuses(F&& fn, const char* cause_name, std::string* what = nullptr)
{
    try {
        fn();
    } catch (const ScanRefusal& e) {
        if (what) *what = e.what();
        if (e.cause() != cause_name) std::printf("    (refused with %s: %s)\n", e.cause().c_str(), e.what());
        return e.cause() == cause_name;
    } catch (const std::exception& e) {
        std::printf("    (threw %s)\n", e.what());
        return false;
    }
    return false;
}

template <class F>
inline bool runs(F&& fn, const char* what)
{
    try {
        fn();
        return true;
    } catch (const std::exception& e) {
        std::printf("    (%s threw: %s)\n", what, e.what());
        return false;
    }
}

// ── the chain view the fakes serve ──────────────────────────────────────────

struct Row {
    std::string address, txid;
    uint32_t vout = 0;
    std::string script;
    int64_t sat = 0;
    int64_t height = 0;
    bool coinbase = true;
};

inline std::vector<Row> fixture_rows()
{
    const nj a = nj::parse(read_file(std::string(C2W_DASH_FIXTURE_DIR) + "/xdgf-getaddressutxos-tip2563986.json"));
    std::vector<Row> v;
    for (const nj& r : a) {
        Row x;
        x.address = r["address"];
        x.txid = r["txid"];
        x.vout = r["outputIndex"];
        x.script = r["script"];
        x.sat = r["satoshis"];
        x.height = r["height"];
        x.coinbase = x.vout != 1; // tests/mock_dash_cli.py: every outputIndex-1 row is non-coinbase
        v.push_back(x);
    }
    return v;
}

// The first row by (height, txid, outputIndex): mock_dash_cli.py reports it
// spent in the mempool.
inline Outpoint mock_spent_row(const std::vector<Row>& rows)
{
    const Row* f = &rows[0];
    for (const Row& r : rows)
        if (std::tie(r.height, r.txid, r.vout) < std::tie(f->height, f->txid, f->vout)) f = &r;
    return {f->txid, f->vout};
}

inline std::vector<Row> synthetic_rows(const std::string& addr, size_t n, int64_t sat, int64_t base_height)
{
    std::vector<Row> v;
    for (size_t i = 0; i < n; ++i) {
        Row r;
        r.address = addr;
        r.txid = sha_hex("scan KAT synthetic row " + addr + " " + std::to_string(i));
        r.vout = static_cast<uint32_t>(i % 5);
        r.script = script_of(addr);
        r.sat = sat;
        r.height = base_height + static_cast<int64_t>(i);
        r.coinbase = true;
        v.push_back(r);
    }
    return v;
}

inline std::vector<std::string> addresses_in(const nj& list)
{
    std::vector<std::string> v;
    for (const nj& a : list) v.push_back(a.get<std::string>());
    return v;
}

// A scripted dashd: addressindex on or off, chainInfo or the bare array, the
// help text's `index` or the real `outputIndex`, mempool spends (gettxout
// null), contradicting gettxout answers, and a hook that moves the tip.
class FakeDashd : public RpcApi {
public:
    std::vector<Row> rows;
    int64_t tip = kTip;
    bool addressindex = true;
    bool chain_info = true;
    std::string index_field = "outputIndex";
    std::string chain = "main";
    std::set<Outpoint> spent;
    std::map<Outpoint, int64_t> value_override;
    std::map<Outpoint, std::string> script_override;
    std::function<void(FakeDashd&, const std::string&)> hook;
    std::vector<std::string> calls;
    int bare_http_status = 0; // e.g. 401: answer with that status and an empty body (no JSON-RPC envelope)

    RpcReply call(const std::string& method, const std::string& params_json) override
    {
        calls.push_back(method);
        if (hook) hook(*this, method);
        if (bare_http_status) return {true, bare_http_status, "", ""};
        const nj p = nj::parse(params_json);
        if (method == "getblockchaininfo")
            return ok({{"chain", chain}, {"blocks", tip}, {"headers", tip}, {"bestblockhash", tip_hash_of(tip)}});
        if (method == "getblockcount") return ok(tip);
        if (method == "getbestblockhash") return ok(tip_hash_of(tip));
        if (method == "getblockhash") return ok(tip_hash_of(p[0].get<int64_t>()));
        if (method == "getaddressutxos") {
            if (!addressindex)
                return err(-32600, "Address index is disabled. You should run Dash Core with -addressindex (requires reindex)");
            const std::vector<std::string> want = addresses_in(p[0]["addresses"]);
            nj list = nj::array();
            for (const Row& r : visible(want))
                list.push_back({{"address", r.address}, {"txid", r.txid}, {index_field, r.vout}, {"script", r.script},
                                {"satoshis", r.sat}, {"height", r.height}});
            if (!chain_info) return ok(list);
            return ok({{"utxos", list}, {"hash", tip_hash_of(tip)}, {"height", tip}});
        }
        if (method == "scantxoutset") {
            // SYNTHESISED scantxoutset reply: the field set of the real vm210
            // capture (K2b) and the RPC help, built from the same rows.
            if (p[0] != "start") return err(-8, "Invalid command");
            std::vector<std::string> want;
            for (const nj& d : p[1]) {
                const std::string s = d.get<std::string>();
                want.push_back(s.substr(5, s.size() - 6)); // addr(X)
            }
            nj un = nj::array();
            int64_t total = 0;
            for (const Row& r : visible(want)) {
                un.push_back({{"txid", r.txid}, {"vout", r.vout}, {"scriptPubKey", r.script},
                              {"desc", "addr(" + r.address + ")#z8zezxyy"}, {"amount", static_cast<double>(r.sat) / 1e8},
                              {"coinbase", r.coinbase}, {"height", r.height}});
                total += r.sat;
            }
            return ok({{"success", true}, {"txouts", 4530592}, {"height", tip}, {"bestblock", tip_hash_of(tip)},
                       {"unspents", un}, {"total_amount", static_cast<double>(total) / 1e8}});
        }
        if (method == "gettxout") {
            const Outpoint o{p[0].get<std::string>(), p[1].get<uint32_t>()};
            for (const Row& r : rows) {
                if (r.txid != o.txid || r.vout != o.vout || r.height > tip) continue;
                if (spent.count(o)) return ok(nullptr);
                const int64_t v = value_override.count(o) ? value_override[o] : r.sat;
                const std::string s = script_override.count(o) ? script_override[o] : r.script;
                return ok({{"bestblock", tip_hash_of(tip)}, {"confirmations", tip - r.height + 1},
                           {"value", static_cast<double>(v) / 1e8},
                           {"scriptPubKey", {{"hex", s}, {"address", r.address}, {"type", "pubkeyhash"}}},
                           {"coinbase", r.coinbase}});
            }
            return ok(nullptr);
        }
        return err(-32601, "Method not found");
    }
    const char* name() const override { return "fake-dashd"; }

    size_t count(const std::string& m) const { return static_cast<size_t>(std::count(calls.begin(), calls.end(), m)); }

private:
    std::vector<Row> visible(const std::vector<std::string>& want) const
    {
        std::vector<Row> v;
        for (const Row& r : rows)
            if (r.height <= tip && std::find(want.begin(), want.end(), r.address) != want.end()) v.push_back(r);
        return v;
    }
    static RpcReply ok(const nj& result)
    {
        return {true, 200, nj({{"result", result}, {"error", nullptr}, {"id", 1}}).dump(), ""};
    }
    static RpcReply err(int code, const std::string& msg)
    {
        return {true, 500, nj({{"result", nullptr}, {"error", {{"code", code}, {"message", msg}}}, {"id", 1}}).dump(), ""};
    }
};

// Replays the REAL recorded vm210 session: every call must have been recorded.
class ReplayRpc : public RpcApi {
public:
    explicit ReplayRpc(const std::string& path) : doc_(nj::parse(read_file(path))) {}
    RpcReply call(const std::string& method, const std::string& params_json) override
    {
        const nj p = nj::parse(params_json);
        for (const nj& c : doc_["calls"]) {
            if (c["method"] != method || c["params"] != p) continue;
            nj env = {{"id", 1}};
            if (c.contains("error")) {
                env["result"] = nullptr;
                env["error"] = c["error"];
                return {true, 500, env.dump(), ""};
            }
            env["result"] = c["result"];
            env["error"] = nullptr;
            return {true, 200, env.dump(), ""};
        }
        ++unrecorded;
        return {false, 0, "", "not in the recorded session: " + method + " " + params_json};
    }
    const char* name() const override { return "replay-vm210"; }
    int unrecorded = 0;
    const nj& doc() const { return doc_; }

private:
    nj doc_;
};

// A scripted c2pool node serving the N1 route. Its reply is the SYNTHESISED
// /api/utxo/scan shape of the design (§3.6).
class FakeUtxoNode : public sched::NodeApi {
public:
    std::vector<Row> rows;
    int64_t tip = kTip;
    std::string mode = "full", state = "serving";
    bool truncated = false;
    int tip_moved_times = 0;
    int status = 200;
    std::string error_body;
    std::set<Outpoint> spent;
    std::map<Outpoint, int64_t> value_override;
    std::string echo_script_override;
    int64_t total_value_delta = 0;
    std::function<void(FakeUtxoNode&)> hook;
    std::vector<std::string> paths;

    sched::HttpReply get(const std::string& path) override
    {
        paths.push_back(path);
        if (hook) hook(*this);
        if (status != 200) return {true, status, error_body, ""};
        std::vector<std::string> want;
        for (size_t at = path.find("address="); at != std::string::npos; at = path.find("address=", at + 1)) {
            const size_t end = path.find('&', at);
            want.push_back(path.substr(at + 8, end == std::string::npos ? std::string::npos : end - at - 8));
        }
        nj scripts = nj::array();
        for (const std::string& a : want)
            scripts.push_back({{"address", a}, {"script_hex", echo_script_override.empty() ? script_of(a) : echo_script_override}});
        nj un = nj::array(), ms = nj::array();
        int64_t total = 0;
        for (const Row& r : rows) {
            if (r.height > tip || std::find(want.begin(), want.end(), r.address) == want.end()) continue;
            const Outpoint o{r.txid, r.vout};
            if (spent.count(o)) {
                ms.push_back({{"txid", r.txid}, {"vout", r.vout}});
                continue;
            }
            const int64_t v = value_override.count(o) ? value_override[o] : r.sat;
            un.push_back({{"txid", r.txid}, {"vout", r.vout}, {"value", v}, {"script_hex", r.script},
                          {"height", r.height}, {"coinbase", r.coinbase}});
            total += v;
        }
        const bool moved = tip_moved_times > 0;
        if (moved) --tip_moved_times;
        const nj reply = {{"ok", true}, {"tip_height", tip}, {"tip_hash", tip_hash_of(tip)},
                          {"utxo", {{"mode", mode}, {"state", state}, {"coins", 4531254}}},
                          {"scanned", 4531254}, {"elapsed_ms", 4100}, {"tip_moved", moved}, {"truncated", truncated},
                          {"scripts", scripts}, {"unspents", un}, {"mempool_spent", ms},
                          {"total_value", total + total_value_delta}};
        return {true, 200, reply.dump(), ""};
    }
    sched::HttpReply post_json(const std::string&, const std::string&) override { return {true, 404, "", ""}; }
    const char* name() const override { return "fake-utxo-node"; }
};

inline bool same_rows(const std::vector<dash::Utxo>& a, const std::vector<dash::Utxo>& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].txid != b[i].txid || a[i].vout != b[i].vout || a[i].satoshis != b[i].satoshis ||
            a[i].height != b[i].height || a[i].confirmations != b[i].confirmations || a[i].coinbase != b[i].coinbase ||
            a[i].script_pubkey_hex != b[i].script_pubkey_hex)
            return false;
    return true;
}

inline ScanResult dashd_scan(FakeDashd& d, const std::vector<std::string>& addrs = {kXdgf})
{
    SourceDashd s(d);
    return s.scan(addrs, ScanOptions{});
}

inline std::string export_of(const ScanResult& r) { return write_export_v1(r.imports.at(0)); }

inline dash::UtxoImport import_of(const std::vector<Row>& rows, int64_t tip)
{
    FakeDashd d;
    d.rows = rows;
    d.tip = tip;
    return dashd_scan(d, {rows[0].address}).imports[0];
}

} // namespace scan_kat
