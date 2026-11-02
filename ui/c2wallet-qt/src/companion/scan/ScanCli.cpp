// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ScanCli.hpp"

#include "Classifier.hpp"
#include "CrossCheck.hpp"
#include "Planner.hpp"
#include "Preflight.hpp"
#include "RpcApi.hpp"
#include "ScanFiles.hpp"
#include "SourceC2pool.hpp"
#include "SourceDashd.hpp"
#include "Watch.hpp"

#include "../Submit.hpp" // parse_signed_artifact
#include "../sched/ChainView.hpp"
#include "../sched/Clock.hpp"
#include "../sched/InjectQueue.hpp"
#include "../sched/Json.hpp"
#include "../sched/Runner.hpp"
#include "../sched/TokenFile.hpp"
#include "../sched/Triggers.hpp" // kSecondsPerBlock

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"
#include "../../family/bitcoin/dash/InjectCaps.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"
#include "ValidateSeam.hpp" // crossgap_txid

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <sstream>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace c2w::companion::scan::cli {

namespace {

namespace sc = sched::cli;
using J = sched::json::J;
using c2w::dash::Utxo;
using c2w::dash::UtxoImport;

constexpr size_t kMaxFile = 64u * 1024u * 1024u;
inline constexpr const char* kDefaultNodeUrl = "http://127.0.0.1:8080";

// ── arguments ────────────────────────────────────────────────────────────────

struct Opt {
    std::map<std::string, std::vector<std::string>> values;
    std::set<std::string> flags;
    std::vector<std::string> pos;
    bool has(const std::string& k) const { return values.count(k) != 0 || flags.count(k) != 0; }
    const std::string* one(const std::string& k) const
    {
        auto it = values.find(k);
        return it == values.end() || it->second.empty() ? nullptr : &it->second.back();
    }
    std::vector<std::string> all(const std::string& k) const
    {
        auto it = values.find(k);
        return it == values.end() ? std::vector<std::string>{} : it->second;
    }
};

// Options that would put a dashd credential in argv. Refused by name, before
// anything else is looked at.
bool secret_by_value(const std::vector<std::string>& v, std::string& why)
{
    for (const std::string& t : v)
        for (const char* bad : {"--dashd-auth", "--dashd-password", "--dashd-user", "--rpcpassword", "--rpcauth", "--rpcuser"}) {
            const std::string b = bad;
            if (t == b || t.rfind(b + "=", 0) == 0) {
                why = "usage: there is no " + b + " VALUE (argv is world-readable); put the dashd credentials (the "
                      ".cookie, or user:password) in a 0600 file and pass --dashd-auth-file PATH";
                return true;
            }
        }
    return false;
}

const std::set<std::string> kSourceValued = {"--source", "--dashd-url", "--dashd-auth-file"};
const std::set<std::string> kPlanValued = {"--mode", "--fee-mode", "--fee-rate", "--destination", "--destination-confirm",
                                           "--target-height", "--min-conf", "--dust-floor", "--max-inputs",
                                           "--input-limit", "--key-encoding", "--gov-hash", "--change-address"};

bool parse(const std::vector<std::string>& v, size_t from, const std::set<std::string>& flags,
           const std::set<std::string>& valued, const std::set<std::string>& multi, Opt& o, std::string& why)
{
    for (size_t i = from; i < v.size(); ++i) {
        const std::string& t = v[i];
        if (t.size() > 2 && t.rfind("--", 0) == 0) {
            const size_t eq = t.find('=');
            const std::string name = eq == std::string::npos ? t : t.substr(0, eq);
            if (flags.count(name)) {
                if (eq != std::string::npos) {
                    why = "usage: " + name + " takes no value";
                    return false;
                }
                o.flags.insert(name);
                continue;
            }
            if (valued.count(name)) {
                std::string value;
                if (eq != std::string::npos) value = t.substr(eq + 1);
                else if (i + 1 < v.size()) value = v[++i];
                else {
                    why = "usage: " + name + " needs a value";
                    return false;
                }
                if (o.values.count(name) && !multi.count(name)) {
                    why = "usage: " + name + " given twice";
                    return false;
                }
                o.values[name].push_back(value);
                continue;
            }
            why = "usage: unknown option " + name;
            return false;
        }
        o.pos.push_back(t);
    }
    return true;
}

std::set<std::string> join(std::initializer_list<std::set<std::string>> sets)
{
    std::set<std::string> out;
    for (const auto& s : sets) out.insert(s.begin(), s.end());
    return out;
}

bool parse_i64(const std::string& s, int64_t lo, int64_t hi, int64_t& out)
{
    if (s.empty() || s.size() > 18) return false;
    int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    if (v < lo || v > hi) return false;
    out = v;
    return true;
}

bool read_file(const std::string& path, std::string& out, std::string& why)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        why = "cannot open " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    if (out.size() > kMaxFile) {
        why = path + " is larger than " + std::to_string(kMaxFile) + " bytes";
        return false;
    }
    return true;
}

bool exists(const std::string& path)
{
    std::ifstream f(path);
    return static_cast<bool>(f);
}

bool write_file(const std::string& path, const std::string& text, std::string& why)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << text;
    f.close();
    if (!f) {
        why = "cannot write " + path;
        return false;
    }
    return true;
}

struct Ctx {
    sc::Env& env;
    const sched::CliOverrides& g;
    std::string queue_path;
    std::ostream& out() { return *env.out; }
    std::ostream& err() { return *env.err; }
    int64_t now() const { return env.clock ? env.clock->now_unix() : 0; }
};

int usage(Ctx& c, const std::string& why)
{
    c.err() << why << "\n(see c2wallet-qt-schedd help)\n";
    return sc::kExitUsage;
}

int refuse(Ctx& c, const std::string& why)
{
    c.err() << "refused: " << why << "\n";
    return sc::kExitAttention;
}

// The queue, when there is one: its network, node URL / token file and the
// inputs of its unfinished items. Read-only.
struct QueueView {
    bool present = false;
    sched::Queue q;
};

QueueView read_queue(Ctx& c)
{
    QueueView v;
    std::string why;
    if (exists(c.queue_path) && sched::load_queue_file(c.queue_path, v.q, why)) v.present = true;
    return v;
}

bool testnet_of(const Opt& o, const QueueView& qv) { return o.has("--testnet") || (qv.present && qv.q.network == "testnet"); }

std::string node_url_of(Ctx& c, const QueueView& qv)
{
    if (c.g.node_url) return *c.g.node_url;
    if (qv.present && !qv.q.node.url.empty()) return qv.q.node.url;
    return kDefaultNodeUrl;
}

std::string token_file_of(Ctx& c, const QueueView& qv)
{
    if (c.g.token_file) return *c.g.token_file;
    if (qv.present) return qv.q.node.token_file;
    return {};
}

// ── sources ──────────────────────────────────────────────────────────────────

struct SourceCfg {
    bool dashd = false, c2pool = false, allow_single = false;
    std::string dashd_url, auth_file, node_url;
};

bool source_cfg(Ctx& c, const Opt& o, const QueueView& qv, bool allow_none, SourceCfg& s, std::string& why)
{
    std::string mode = o.one("--source") ? *o.one("--source") : (o.has("--dashd-url") ? "both" : "c2pool");
    if (mode == "dashd") s.dashd = true;
    else if (mode == "c2pool") s.c2pool = true;
    else if (mode == "both") s.dashd = s.c2pool = true;
    else if (mode == "none" && allow_none) {}
    else {
        why = "usage: --source must be dashd, c2pool or both" + std::string(allow_none ? " (or none)" : "");
        return false;
    }
    s.allow_single = o.has("--allow-single-source");
    s.node_url = node_url_of(c, qv);
    if (s.dashd) {
        const std::string* u = o.one("--dashd-url");
        const std::string* a = o.one("--dashd-auth-file");
        if (!u || !a) {
            why = "usage: the dashd source needs --dashd-url URL and --dashd-auth-file PATH";
            return false;
        }
        if (!sched::validate_node_url(*u, why)) {
            why = "usage: --dashd-url: " + why + " (reach a remote dashd with ssh -L)";
            return false;
        }
        s.dashd_url = *u;
        s.auth_file = *a;
    } else if (o.has("--dashd-url") || o.has("--dashd-auth-file")) {
        why = "usage: --dashd-url / --dashd-auth-file need --source dashd or both";
        return false;
    }
    return true;
}

struct Sources {
    std::unique_ptr<RpcApi> rpc;
    std::unique_ptr<sched::NodeApi> node;
    std::unique_ptr<SourceDashd> dashd;
    std::unique_ptr<SourceC2pool> c2pool;
};

bool make_sources(Ctx& c, const SourceCfg& s, Sources& out, std::string& why)
{
    if (s.dashd) {
        if (!c.env.make_rpc) {
            why = "this build has no dashd transport";
            return false;
        }
        out.rpc = c.env.make_rpc(s.dashd_url, s.auth_file, why);
        if (!out.rpc) return false;
        out.dashd = std::make_unique<SourceDashd>(*out.rpc);
    }
    if (s.c2pool) {
        auto& make = c.env.make_scan_api ? c.env.make_scan_api : c.env.make_api;
        if (!make) {
            why = "this build has no node transport";
            return false;
        }
        out.node = make(s.node_url, why);
        if (!out.node) return false;
        out.c2pool = std::make_unique<SourceC2pool>(*out.node);
    }
    return true;
}

ScanResult do_scan(Sources& src, const SourceCfg& s, const std::vector<std::string>& addresses, const ScanOptions& so)
{
    if (src.dashd && src.c2pool) {
        CrossCheckOptions cc;
        cc.allow_single_source = s.allow_single;
        return scan_both(*src.dashd, *src.c2pool, addresses, so, cc);
    }
    if (src.dashd) return src.dashd->scan(addresses, so);
    return src.c2pool->scan(addresses, so);
}

ScanOptions scan_options(Ctx& c, bool testnet)
{
    ScanOptions so;
    so.testnet = testnet;
    if (c.env.stop_requested) so.cancelled = c.env.stop_requested;
    return so;
}

// ── plan options ─────────────────────────────────────────────────────────────

bool plan_params(const Opt& o, PlanParams& p, std::string& why)
{
    int64_t n = 0;
    if (const std::string* s = o.one("--mode")) {
        if (*s == "consolidate") p.mode = PlanMode::Consolidate;
        else if (*s == "collateral") p.mode = PlanMode::Collateral;
        else { why = "usage: --mode consolidate|collateral"; return false; }
    }
    if (const std::string* s = o.one("--fee-mode")) {
        if (*s == "inject" || *s == "inject-zero-fee") p.fee_mode = c2w::dash::FeeMode::InjectOnlyZeroFee;
        else if (*s == "relay") p.fee_mode = c2w::dash::FeeMode::Relay;
        else { why = "usage: --fee-mode inject|relay"; return false; }
    }
    if (const std::string* s = o.one("--fee-rate")) {
        if (!parse_i64(*s, 0, 100, n)) { why = "usage: --fee-rate must be 0..100 duffs/B"; return false; }
        p.fee_rate_per_byte = n;
    }
    if (p.fee_mode == c2w::dash::FeeMode::Relay && !o.has("--fee-rate")) p.fee_rate_per_byte = c2w::dash::kMinRelayFeePerByte;
    if (const std::string* s = o.one("--destination")) {
        // A destination other than the funding address moves the funds off the
        // mining key: it must be typed twice (design §6 #7).
        const std::string* confirm = o.one("--destination-confirm");
        if (!confirm || *confirm != *s) {
            why = "usage: --destination ADDR needs --destination-confirm ADDR with the same address (typed twice)";
            return false;
        }
        p.destination = *s;
    } else if (o.has("--destination-confirm")) {
        why = "usage: --destination-confirm without --destination";
        return false;
    }
    if (const std::string* s = o.one("--target-height")) {
        if (!parse_i64(*s, 1, 1000000000, n)) { why = "usage: --target-height must be a block height"; return false; }
        p.target_height = n;
    }
    if (const std::string* s = o.one("--min-conf")) {
        if (!parse_i64(*s, 1, 1000000, n)) { why = "usage: --min-conf must be >= 1"; return false; }
        p.min_confirmations = n;
    }
    if (const std::string* s = o.one("--dust-floor")) {
        if (!parse_i64(*s, 0, c2w::dash::kMaxMoney, n)) { why = "usage: --dust-floor must be >= 0 duffs"; return false; }
        p.dust_floor = n;
    }
    if (const std::string* s = o.one("--max-inputs")) {
        if (!parse_i64(*s, 1, static_cast<int64_t>(c2w::dash::caps::kMaxInjectInputs), n)) {
            why = "usage: --max-inputs must be 1..1000";
            return false;
        }
        p.max_inputs_per_tx = static_cast<size_t>(n);
    }
    if (const std::string* s = o.one("--input-limit")) {
        if (!parse_i64(*s, 0, 1000000, n)) { why = "usage: --input-limit must be >= 0"; return false; }
        p.input_limit = static_cast<size_t>(n);
    }
    if (const std::string* s = o.one("--key-encoding")) {
        if (*s == "unknown") p.key_encoding = c2w::dash::PubkeyEncoding::Unknown;
        else if (*s == "compressed") p.key_encoding = c2w::dash::PubkeyEncoding::Compressed;
        else if (*s == "uncompressed") p.key_encoding = c2w::dash::PubkeyEncoding::Uncompressed;
        else { why = "usage: --key-encoding unknown|compressed|uncompressed"; return false; }
    }
    if (const std::string* s = o.one("--gov-hash")) {
        if (!is_hex64(*s)) { why = "usage: --gov-hash needs the 64-hex hash `gobject check` prints"; return false; }
        p.gov_hash = lower(*s);
    }
    if (const std::string* s = o.one("--change-address")) p.change_address = *s;
    return true;
}

// The node's posture for the fee advice (#4), when the node source was read.
FeeAdvice advice_for(Sources& src, const ScanResult& r, const ScanPlan& plan)
{
    NodePosture np;
    if (src.node) {
        sched::ChainView cv(*src.node);
        const sched::InjectStatus& st = cv.inject_status(true);
        if (st.ok) {
            np.armed = st.enabled;
            if (st.pool_max_total_bytes > 0) np.pool_free_bytes = std::max<int64_t>(0, st.pool_max_total_bytes - st.pool_bytes);
        }
        np.utxo_full_serving = r.c2pool_detail.rfind("utxo full serving", 0) == 0;
    }
    return advise_fee_mode(np, plan);
}

// ── writing the file set ─────────────────────────────────────────────────────

struct FileSet {
    std::string base;
    std::string utxos, scanplan, report, c2wu;
};

bool write_set(Ctx& c, const FileSet& f, bool overwrite, std::string& why)
{
    std::vector<std::pair<std::string, const std::string*>> files = {
        {f.base + ".utxos.json", &f.utxos}, {f.base + ".scanplan.json", &f.scanplan}, {f.base + ".report.txt", &f.report}};
    if (!f.c2wu.empty()) files.push_back({f.base + ".c2wu.hex", &f.c2wu});
    if (!overwrite)
        for (const auto& [path, text] : files)
            if (exists(path)) {
                why = path + " exists (--overwrite to replace it)";
                return false;
            }
    for (const auto& [path, text] : files) {
        if (!write_file(path, *text, why)) return false;
        c.out() << "wrote " << path << " (" << text->size() << " B)\n";
    }
    return true;
}

bool c2wu_text(const Opt& o, const ScanPlan& plan, std::string& out, std::string& why)
{
    if (!o.has("--emit-c2wu")) return true;
    std::optional<uint32_t> idx;
    if (const std::string* s = o.one("--derivation-index")) {
        int64_t n = 0;
        if (!parse_i64(*s, 0, 0x7fffffff, n)) {
            why = "usage: --derivation-index must be 0..2147483647";
            return false;
        }
        idx = static_cast<uint32_t>(n);
    }
    const std::vector<std::string> hx = emit_c2wu(plan, idx, why);
    if (hx.empty()) return false;
    for (const std::string& h : hx) out += h + "\n";
    return true;
}

// Classify, plan and render one import into a file set.
bool render(Ctx& c, Sources* src, const ScanResult& r, const UtxoImport& imp, const QueueView& qv, const PlanParams& pp,
            const Opt& o, const std::string& base, FileSet& f, std::string& why)
{
    const auto queued = qv.present ? queued_outpoints(qv.q) : std::map<Outpoint, std::string>{};
    try {
        const Classification cls = classify(imp, r.mempool_spent, queued, classify_params_of(pp));
        const ScanPlan plan = make_plan(cls.exportable, pp);
        const FeeAdvice adv = src ? advice_for(*src, r, plan) : advise_fee_mode(NodePosture{}, plan);
        f.base = base;
        f.utxos = write_export_v1(cls.exportable);
        f.scanplan = write_scan_plan(r, cls, plan, f.utxos, adv);
        const size_t slash = base.find_last_of('/');
        f.report = write_report(r, cls, plan, adv, slash == std::string::npos ? base : base.substr(slash + 1));
        if (!c2wu_text(o, plan, f.c2wu, why)) return false;
        return true;
    } catch (const ScanRefusal& e) {
        why = e.what();
        return false;
    }
}

// ── scan ─────────────────────────────────────────────────────────────────────

int cmd_scan(Ctx& c, const std::vector<std::string>& v)
{
    Opt o;
    std::string why;
    if (!parse(v, 1, {"--allow-single-source", "--emit-c2wu", "--overwrite", "--testnet"},
               join({kSourceValued, kPlanValued, {"--address", "--out", "--derivation-index"}}), {"--address"}, o, why))
        return usage(c, why);
    if (!o.pos.empty()) return usage(c, "usage: scan takes no positional argument (got '" + o.pos[0] + "')");
    const std::vector<std::string> addresses = o.all("--address");
    if (addresses.empty()) return usage(c, "usage: scan needs --address ADDR (up to 16)");
    PlanParams pp;
    if (!plan_params(o, pp, why)) return usage(c, why);
    const QueueView qv = read_queue(c);
    SourceCfg s;
    if (!source_cfg(c, o, qv, false, s, why)) return usage(c, why);
    Sources src;
    if (!make_sources(c, s, src, why)) return refuse(c, why);
    const bool testnet = testnet_of(o, qv);
    ScanResult r;
    try {
        r = do_scan(src, s, addresses, scan_options(c, testnet));
    } catch (const ScanRefusal& e) {
        return refuse(c, e.what());
    }
    c.out() << "scanned " << addresses.size() << " address(es) at tip " << r.tip_height << " " << r.tip_hash << " via "
            << r.source << (r.cross_checked ? " (cross-checked)" : "") << " in " << r.elapsed_ms << " ms\n";
    if (!r.warning.empty()) c.out() << "warning: " << r.warning << "\n";
    const std::string out = o.one("--out") ? *o.one("--out")
                                           : "scan-" + addresses[0].substr(0, 6) + "-" + std::to_string(r.tip_height);
    int written = 0;
    for (const UtxoImport& imp : r.imports) {
        const std::string base = r.imports.size() == 1 ? out : out + "." + imp.address;
        FileSet f;
        if (imp.utxos.empty()) {
            c.out() << imp.address << ": no unspent output\n";
            continue;
        }
        if (!render(c, &src, r, imp, qv, pp, o, base, f, why)) {
            c.out() << imp.address << ": no plan: " << why << "\n";
            continue;
        }
        if (!write_set(c, f, o.has("--overwrite"), why)) return refuse(c, why);
        c.out() << "\n" << f.report << "\n";
        ++written;
    }
    return written > 0 ? sc::kExitOk : sc::kExitAttention;
}

// ── plan ─────────────────────────────────────────────────────────────────────

bool params_from_sidecar(const J& sp, PlanParams& p, std::string& why)
{
    sched::json::Reader rd;
    const J* pr = rd.obj(sp, "params", "scanplan");
    if (!pr) {
        why = "scan-plan sidecar without params";
        return false;
    }
    const std::string mode = rd.str(*pr, "mode", "params");
    p.mode = mode == "collateral" ? PlanMode::Collateral : PlanMode::Consolidate;
    p.fee_mode = rd.str(*pr, "fee_mode", "params") == "relay" ? c2w::dash::FeeMode::Relay : c2w::dash::FeeMode::InjectOnlyZeroFee;
    p.fee_rate_per_byte = rd.i64(*pr, "fee_rate_duffs_per_byte", "params");
    p.destination = rd.str(*pr, "destination", "params");
    p.target_height = rd.i64(*pr, "target_height", "params");
    p.min_confirmations = rd.i64(*pr, "min_confirmations", "params", c2w::dash::kDefaultMinConf);
    p.dust_floor = rd.i64(*pr, "dust_floor", "params", 1000);
    p.max_inputs_per_tx = static_cast<size_t>(rd.i64(*pr, "max_inputs_per_tx", "params"));
    p.input_limit = static_cast<size_t>(rd.i64(*pr, "input_limit", "params"));
    const std::string enc = rd.str(*pr, "key_encoding", "params");
    p.key_encoding = enc == "compressed"     ? c2w::dash::PubkeyEncoding::Compressed
                     : enc == "uncompressed" ? c2w::dash::PubkeyEncoding::Uncompressed
                                             : c2w::dash::PubkeyEncoding::Unknown;
    p.gov_hash = rd.str(*pr, "gov_hash", "params");
    p.change_address = rd.str(*pr, "change_address", "params");
    if (!rd.ok()) {
        why = rd.err;
        return false;
    }
    return true;
}

std::string sha_hex(const std::string& s)
{
    return c2w::artifact::to_hex(c2w::artifact::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

int cmd_plan_stage2(Ctx& c, const Opt& o, bool testnet)
{
    std::string why, utxos_text, sp_text, hex_text;
    const std::string* up = o.one("--utxos");
    const std::string* spp = o.one("--scanplan");
    const std::string* hp = o.one("--stage1-hex");
    if (!up || !spp || !hp)
        return usage(c, "usage: plan --stage2 needs --utxos S1.utxos.json --scanplan S1.scanplan.json --stage1-hex S1.hex");
    if (!read_file(*up, utxos_text, why) || !read_file(*spp, sp_text, why) || !read_file(*hp, hex_text, why))
        return refuse(c, why);
    J sp;
    if (!sched::json::parse_bounded(sp_text, sp, why) || !sp.is_object()) return refuse(c, "scan-plan sidecar: " + why);
    if (!sp.contains("utxos_file_sha256") || sp["utxos_file_sha256"] != sha_hex(utxos_text))
        return refuse(c, "the stage-1 sidecar describes another utxos file (utxos_file_sha256)");
    PlanParams p1;
    if (!params_from_sidecar(sp, p1, why)) return refuse(c, why);
    try {
        const UtxoImport imp1 = c2w::dash::parse_utxo_export_v1(utxos_text, testnet);
        const ScanPlan plan1 = make_plan(imp1, p1);
        const std::string want_id = sp.contains("expected") ? sp["expected"].value("plan_id", std::string()) : "";
        if (plan1.plan_id != want_id)
            return refuse(c, "re-planning stage 1 from the export gives plan " + plan1.plan_id + ", the sidecar says " +
                                 want_id + " (another plan)");
        if (!plan1.two_stage) return refuse(c, "the stage-1 plan has one stage: there is no stage 2 to write");
        const size_t k = plan1.batches.size() - 1;
        const auto signed1 = parse_signed_artifact(hex_text, why);
        if (!signed1) return refuse(c, "stage-1 hex: " + why);
        if (signed1->tx_hexes.size() != k)
            return refuse(c, "stage 1 plans " + std::to_string(k) + " tx(s), the hex file carries " +
                                 std::to_string(signed1->tx_hexes.size()));
        const auto funding = c2w::dash::p2pkh_script(c2w::dash::addr_to_h160(plan1.address, testnet));
        const std::string funding_hex = c2w::artifact::to_hex(funding.data(), funding.size());
        std::vector<std::string> txids;
        for (size_t i = 0; i < k; ++i) {
            const std::string& hex = signed1->tx_hexes[i];
            if (!sched::preflight_raw_tx(hex, "", why)) return refuse(c, "stage-1 tx " + std::to_string(i + 1) + ": " + why);
            TxIO io;
            if (!parse_tx_io(hex, io, why)) return refuse(c, "stage-1 tx " + std::to_string(i + 1) + ": " + why);
            std::vector<Utxo> ins;
            for (const Outpoint& op : io.inputs) {
                Utxo u;
                u.txid = op.txid;
                u.vout = op.vout;
                ins.push_back(u);
            }
            const PlannedBatch& b = plan1.batches[i];
            if (io.outputs.size() != 1 || io.outputs[0].first != b.value_out || io.outputs[0].second != funding_hex ||
                inputs_digest(ins) != b.inputs_sha256)
                return refuse(c, "stage-1 tx " + std::to_string(i + 1) +
                                     " is not the planned stage-1 batch (inputs, or its one output to the funding address)");
            txids.push_back(c2w::artifact::crossgap_txid(hex));
        }
        int64_t landing = p1.target_height;
        if (const std::string* s = o.one("--landing-height")) {
            if (!parse_i64(*s, 1, 1000000000, landing)) return usage(c, "usage: --landing-height must be a block height");
        }
        const std::string s2 = stage2_export(plan1, txids, landing);
        const UtxoImport imp2 = c2w::dash::parse_utxo_export_v1(s2, testnet);
        PlanParams p2 = p1;
        p2.target_height = 0;
        const Classification cls2 = classify(imp2, {}, {}, classify_params_of(p2));
        const ScanPlan plan2 = make_plan(imp2, p2);
        ScanResult r2;
        r2.source = "stage2-intake";
        r2.tip_height = imp2.tip_height;
        r2.tip_hash = imp2.tip_hash;
        r2.imports = {imp2};
        const FeeAdvice adv = advise_fee_mode(NodePosture{}, plan2);
        FileSet f;
        f.base = o.one("--out") ? *o.one("--out") : "stage2-" + plan1.plan_id.substr(0, 8);
        f.utxos = s2;
        f.scanplan = write_scan_plan(r2, cls2, plan2, s2, adv);
        const size_t slash = f.base.find_last_of('/');
        f.report = write_report(r2, cls2, plan2, adv, slash == std::string::npos ? f.base : f.base.substr(slash + 1));
        if (!write_set(c, f, o.has("--overwrite"), why)) return refuse(c, why);
        c.out() << "\n" << f.report;
        return sc::kExitOk;
    } catch (const ScanRefusal& e) {
        return refuse(c, e.what());
    } catch (const c2w::dash::DashAbort& e) {
        return refuse(c, e.what());
    }
}

int cmd_plan(Ctx& c, const std::vector<std::string>& v)
{
    Opt o;
    std::string why;
    if (!parse(v, 1, {"--stage2", "--emit-c2wu", "--overwrite", "--testnet"},
               join({kPlanValued, {"--utxos", "--scanplan", "--stage1-hex", "--landing-height", "--out", "--derivation-index"}}),
               {}, o, why))
        return usage(c, why);
    if (!o.pos.empty()) return usage(c, "usage: plan takes no positional argument (got '" + o.pos[0] + "')");
    const QueueView qv = read_queue(c);
    const bool testnet = testnet_of(o, qv);
    if (o.has("--stage2")) {
        for (const std::string& k : kPlanValued)
            if (o.has(k)) return usage(c, "usage: plan --stage2 takes its parameters from the stage-1 sidecar (" + k + ")");
        return cmd_plan_stage2(c, o, testnet);
    }
    const std::string* up = o.one("--utxos");
    if (!up) return usage(c, "usage: plan needs --utxos FILE (an export v1 file)");
    if (o.has("--scanplan") || o.has("--stage1-hex") || o.has("--landing-height"))
        return usage(c, "usage: --scanplan / --stage1-hex / --landing-height belong to plan --stage2");
    PlanParams pp;
    if (!plan_params(o, pp, why)) return usage(c, why);
    std::string text;
    if (!read_file(*up, text, why)) return refuse(c, why);
    UtxoImport imp;
    try {
        imp = c2w::dash::parse_utxo_export_v1(text, testnet);
    } catch (const c2w::dash::DashAbort& e) {
        return refuse(c, std::string("the utxos file does not import: ") + e.what());
    }
    ScanResult r;
    r.source = "export-file";
    r.tip_height = imp.tip_height;
    r.tip_hash = imp.tip_hash;
    r.imports = {imp};
    FileSet f;
    const std::string base = o.one("--out") ? *o.one("--out") : "plan-" + imp.address.substr(0, 6) + "-" + std::to_string(imp.tip_height);
    if (!render(c, nullptr, r, imp, qv, pp, o, base, f, why)) return refuse(c, why);
    if (!write_set(c, f, o.has("--overwrite"), why)) return refuse(c, why);
    c.out() << "\n" << f.report;
    return sc::kExitOk;
}

// ── preflight ────────────────────────────────────────────────────────────────

const std::set<std::string> kPreflightFlags = {"--no-validate", "--testnet"};
const std::set<std::string> kPreflightValued = {"--utxos", "--scanplan", "--force", "--source", "--dashd-url",
                                                "--dashd-auth-file"};

int run_preflight_cmd(Ctx& c, const Opt& o, const std::string& hex_text, const std::string& manifest_text,
                      std::string& forced_reason, std::string& summary)
{
    std::string why;
    const QueueView qv = read_queue(c);
    SourceCfg s;
    if (!source_cfg(c, o, qv, true, s, why)) return usage(c, why);
    Sources src;
    if (!make_sources(c, s, src, why)) return refuse(c, why);
    PreflightInput in;
    in.hex_text = hex_text;
    in.manifest_text = manifest_text;
    std::string t;
    if (const std::string* p = o.one("--utxos")) {
        if (!read_file(*p, t, why)) return refuse(c, why);
        in.utxos_text = t;
    }
    if (const std::string* p = o.one("--scanplan")) {
        if (!read_file(*p, t, why)) return refuse(c, why);
        in.scanplan_text = t;
    }
    PreflightOptions po;
    po.testnet = testnet_of(o, qv);
    po.validate = !o.has("--no-validate");
    if (const std::string* f = o.one("--force")) {
        if (f->empty()) return usage(c, "usage: --force needs a reason (it is journaled)");
        po.force_reason = *f;
    }
    po.scan = scan_options(c, po.testnet);
    // The dry run needs the node (any source) and its control token.
    std::unique_ptr<sched::NodeApi> vnode;
    sched::NodeApi* node = nullptr;
    if (po.validate && c.env.make_api) {
        vnode = c.env.make_api(node_url_of(c, qv), why);
        node = vnode.get();
    }
    c2w::secure::SecureString token;
    const std::string tf = token_file_of(c, qv);
    bool have_token = false;
    if (node && !tf.empty()) {
        have_token = sched::TokenFile::read(tf, token, why);
        if (!have_token) c.out() << "notice: dry run without a usable token file: " << why << "\n";
    }
    const PreflightReport rep =
        run_preflight(in, po, src.dashd.get(), src.c2pool.get(), node, have_token ? &token : nullptr);
    token.clear();
    c.out() << rep.text();
    summary = rep.lines.empty() ? std::string("preflight") : rep.lines.back();
    if (!rep.ok) return sc::kExitAttention;
    if (rep.forced) forced_reason = po.force_reason;
    return sc::kExitOk;
}

int cmd_preflight(Ctx& c, const std::vector<std::string>& v)
{
    Opt o;
    std::string why;
    if (!parse(v, 1, kPreflightFlags, join({kPreflightValued, {"--hex", "--manifest"}}), {}, o, why)) return usage(c, why);
    if (!o.pos.empty()) return usage(c, "usage: preflight takes no positional argument (got '" + o.pos[0] + "')");
    const std::string* hp = o.one("--hex");
    if (!hp) return usage(c, "usage: preflight needs --hex FILE");
    std::string hex_text, manifest_text;
    if (!read_file(*hp, hex_text, why)) return refuse(c, why);
    std::string mp;
    if (const std::string* m = o.one("--manifest")) mp = *m;
    else {
        mp = *hp;
        if (mp.size() > 4 && mp.compare(mp.size() - 4, 4, ".hex") == 0) mp.resize(mp.size() - 4);
        mp += ".manifest.json";
    }
    if (!read_file(mp, manifest_text, why)) return refuse(c, why + " (preflight needs the manifest)");
    std::string forced, summary;
    return run_preflight_cmd(c, o, hex_text, manifest_text, forced, summary);
}

// ── watch ────────────────────────────────────────────────────────────────────

int cmd_watch(Ctx& c, const std::vector<std::string>& v)
{
    Opt o;
    std::string why;
    if (!parse(v, 1, {"--allow-single-source", "--once", "--testnet"},
               join({kSourceValued, {"--address", "--min-mature", "--min-value", "--min-conf", "--dust-floor", "--state",
                                     "--interval-blocks"}}),
               {"--address"}, o, why))
        return usage(c, why);
    if (!o.pos.empty()) return usage(c, "usage: watch takes no positional argument (got '" + o.pos[0] + "')");
    const std::vector<std::string> addresses = o.all("--address");
    if (addresses.empty()) return usage(c, "usage: watch needs --address ADDR (up to 16)");
    WatchPolicy pol;
    PlanParams pp;
    int64_t n = 0, interval = 50;
    if (const std::string* s = o.one("--min-mature")) {
        if (!parse_i64(*s, 1, 1000000, n)) return usage(c, "usage: --min-mature must be >= 1");
        pol.min_mature = static_cast<size_t>(n);
    }
    if (const std::string* s = o.one("--min-value")) {
        if (!parse_i64(*s, 0, c2w::dash::kMaxMoney, n)) return usage(c, "usage: --min-value must be >= 0 duffs");
        pol.min_value = n;
        if (!o.has("--min-mature")) pol.min_mature = SIZE_MAX;
    }
    if (const std::string* s = o.one("--min-conf")) {
        if (!parse_i64(*s, 1, 1000000, n)) return usage(c, "usage: --min-conf must be >= 1");
        pp.min_confirmations = n;
    }
    if (const std::string* s = o.one("--dust-floor")) {
        if (!parse_i64(*s, 0, c2w::dash::kMaxMoney, n)) return usage(c, "usage: --dust-floor must be >= 0 duffs");
        pp.dust_floor = n;
    }
    if (const std::string* s = o.one("--interval-blocks")) {
        if (!parse_i64(*s, 1, 100000, interval)) return usage(c, "usage: --interval-blocks must be 1..100000");
    }
    const QueueView qv0 = read_queue(c);
    SourceCfg s;
    if (!source_cfg(c, o, qv0, false, s, why)) return usage(c, why);
    const bool testnet = testnet_of(o, qv0);
    std::string state_path;
    if (const std::string* p = o.one("--state")) state_path = *p;
    else {
        const size_t slash = c.queue_path.find_last_of('/');
        state_path = (slash == std::string::npos ? std::string(".") : c.queue_path.substr(0, slash)) + "/watch.json";
    }
    for (;;) {
        Sources src;
        if (!make_sources(c, s, src, why)) return refuse(c, why);
        const QueueView qv = read_queue(c);
        ScanResult r;
        try {
            r = do_scan(src, s, addresses, scan_options(c, testnet));
        } catch (const ScanRefusal& e) {
            if (e.cause() == cause::kCancelled) return refuse(c, e.what());
            c.err() << "watch: scan refused: " << e.what() << "\n";
            if (o.has("--once")) return sc::kExitAttention;
        }
        if (!r.imports.empty()) {
            WatchState st;
            if (!load_watch_state(state_path, testnet ? "testnet" : "mainnet", st, why)) return refuse(c, why);
            const auto queued = qv.present ? queued_outpoints(qv.q) : std::map<Outpoint, std::string>{};
            c.out() << sched::format_utc(c.now()) << " tip " << r.tip_height << " via " << r.source << "\n";
            for (const UtxoImport& imp : r.imports) {
                Classification cls;
                try {
                    cls = classify(imp, r.mempool_spent, queued, classify_params_of(pp));
                } catch (const ScanRefusal& e) {
                    c.err() << imp.address << ": " << e.what() << "\n";
                    continue;
                }
                const WatchStep stp = watch_step(st.entry(imp.address), cls, pol);
                c.out() << imp.address << ": " << stp.mature << " mature (" << c2w::dash::format_dash(stp.mature_value)
                        << " DASH), " << cls.immature.size() << " immature, " << cls.dust.size() << " dust, "
                        << cls.queued.size() << " queued; "
                        << (stp.first_scan ? "first scan, " : "") << stp.arrivals.size() << " new\n";
                for (const ImmatureRow& im : stp.arriving_immature)
                    c.out() << "  new " << im.utxo.txid << ":" << im.utxo.vout << " " << c2w::dash::format_dash(im.utxo.satoshis)
                            << " DASH spendable from " << im.spendable_from_height << " (" << im.matures_in << " blocks, "
                            << im.eta << ")\n";
                if (stp.alert) {
                    c.out() << "ALERT maturity: " << stp.alert_text << "\n";
                    if (qv.present) {
                        const std::string at = sched::format_utc(c.now());
                        if (!sched::edit_queue_file(
                                c.queue_path,
                                [&](sched::Queue& q, std::string&) {
                                    sched::add_alert(q, at, "maturity", stp.alert_text);
                                    return true;
                                },
                                why, false))
                            c.err() << "watch: the alert was not recorded in the queue: " << why << "\n";
                    } else {
                        c.out() << "(no queue at " << c.queue_path << ": the alert is printed only)\n";
                    }
                }
            }
            if (!save_watch_state(state_path, st, why)) return refuse(c, why);
        }
        if (o.has("--once")) return sc::kExitOk;
        // The next scan in about `interval` blocks (2.6 min each).
        if (c.env.sleep_ms) c.env.sleep_ms(interval * sched::kSecondsPerBlock * 1000);
        if (c.env.stop_requested && c.env.stop_requested()) return sc::kExitOk;
    }
}

} // namespace

bool is_scan_command(const std::string& cmd)
{
    return cmd == "scan" || cmd == "plan" || cmd == "preflight" || cmd == "watch";
}

int run(const std::vector<std::string>& v, sched::cli::Env& env, const sched::CliOverrides& g, const std::string& queue_path)
{
    Ctx c{env, g, queue_path};
    std::string why;
    if (secret_by_value(v, why)) return usage(c, why);
    const std::string& cmd = v.at(0);
    if (cmd == "scan") return cmd_scan(c, v);
    if (cmd == "plan") return cmd_plan(c, v);
    if (cmd == "preflight") return cmd_preflight(c, v);
    if (cmd == "watch") return cmd_watch(c, v);
    return usage(c, "usage: unknown scan command '" + cmd + "'");
}

bool split_add_preflight(const std::vector<std::string>& add_args, std::vector<std::string>& rest, AddPreflight& pf,
                         std::string& why)
{
    pf = AddPreflight{};
    rest.clear();
    if (secret_by_value(add_args, why)) return false;
    for (size_t i = 0; i < add_args.size(); ++i) {
        const std::string& t = add_args[i];
        const size_t eq = t.find('=');
        const std::string name = t.rfind("--", 0) == 0 ? (eq == std::string::npos ? t : t.substr(0, eq)) : std::string();
        if (name == "--preflight") {
            if (eq != std::string::npos) {
                why = "usage: --preflight takes no value";
                return false;
            }
            pf.requested = true;
            continue;
        }
        if (name == "--no-validate") {
            pf.args.push_back(t);
            continue;
        }
        if (kPreflightValued.count(name)) {
            pf.args.push_back(t);
            if (eq == std::string::npos) {
                if (i + 1 >= add_args.size()) {
                    why = "usage: " + name + " needs a value";
                    return false;
                }
                pf.args.push_back(add_args[++i]);
            }
            continue;
        }
        rest.push_back(t);
    }
    if (!pf.requested && !pf.args.empty()) {
        why = "usage: " + pf.args[0] + " belongs to add --preflight";
        return false;
    }
    return true;
}

int preflight_for_add(const AddPreflight& pf, const std::string& hex_text, const std::optional<std::string>& manifest_text,
                      sched::cli::Env& env, const sched::CliOverrides& g, const std::string& queue_path,
                      std::string& forced_reason, std::string& summary)
{
    Ctx c{env, g, queue_path};
    Opt o;
    std::string why;
    std::vector<std::string> v = {"preflight"};
    v.insert(v.end(), pf.args.begin(), pf.args.end());
    if (!parse(v, 1, kPreflightFlags, kPreflightValued, {}, o, why)) return usage(c, why);
    if (!manifest_text) return refuse(c, "add --preflight needs the manifest (it checks the inputs the manifest names)");
    c.out() << "preflight before add:\n";
    return run_preflight_cmd(c, o, hex_text, *manifest_text, forced_reason, summary);
}

const char* usage_text()
{
    return R"(scan & plan (key-free; never signs, arms or submits):
  scan --address ADDR [--address ADDR]... [--source dashd|c2pool|both]
       [--dashd-url URL --dashd-auth-file PATH] [--allow-single-source] [--testnet]
       [--out NAME] [--overwrite] [--emit-c2wu [--derivation-index I]] [PLAN OPTIONS]
        read the UTXOs (dashd getaddressutxos / scantxoutset, the node's /api/utxo/scan, or both
        cross-checked at one tip), classify them and plan with the signer's own planner; writes
        NAME.utxos.json (the signer's export v1), NAME.scanplan.json (advisory sidecar),
        NAME.report.txt (the add lines expected after signing) [and NAME.c2wu.hex].
        Ctrl-C cancels: a running scantxoutset is aborted, a node scan request is dropped.
  plan --utxos FILE [--out NAME] [--overwrite] [--emit-c2wu ...] [PLAN OPTIONS]
        re-plan an export file (no source is read)
  plan --stage2 --utxos S1.utxos.json --scanplan S1.scanplan.json --stage1-hex S1.hex
       [--landing-height H] [--out NAME] [--overwrite]
        two-stage collateral: verify the signed stage 1 against its plan and write the stage-2
        intake (heights PROJECTED; its manifest is queued only with --after-parent for every parent)
  preflight --hex FILE [--manifest FILE] [--utxos FILE] [--scanplan FILE]
       [--source dashd|c2pool|both|none] [--dashd-url URL --dashd-auth-file PATH]
       [--no-validate] [--force "<reason>"]
        before add: structure, reconciliation with the export / sidecar, every input still
        unspent, and the node's dry run (POST /api/tx-inject/validate; skipped with a notice when
        the node has no such route). --force turns a dry-run cause or a plan-digest mismatch
        into a warning, never a spent input. Also as: add ... --preflight [these options]
  watch --address ADDR... [SOURCE OPTIONS] [--min-mature N] [--min-value DUFFS] [--min-conf N]
       [--dust-floor N] [--state FILE] [--once] [--interval-blocks N]
        new UTXOs since the last scan with their maturity ETA, and one queue alert ("maturity")
        when a batch-worth has matured (default 100 UTXOs); every N blocks (default 50)
  PLAN OPTIONS: --mode consolidate|collateral  --fee-mode inject|relay  --fee-rate N
       --destination ADDR --destination-confirm ADDR  --target-height H  --min-conf N
       --dust-floor N  --max-inputs N  --input-limit N  --key-encoding unknown|compressed|uncompressed
       --gov-hash HEX  --change-address ADDR
  There is no --dashd-auth VALUE: the dashd .cookie or a user:password line lives in a 0600 file.
  --dashd-url is loopback http only (reach a remote dashd with ssh -L).
)";
}

} // namespace c2w::companion::scan::cli
