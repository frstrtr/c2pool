// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the c2wallet-qt companion INJECT SCHEDULER core (K1-K27; K22 is
// folded into K19). A scripted fake node (FakeNode: tip, mempool, retained
// block bodies, the tx-inject status, the submit gate and the two-phase config
// apply) and a fake clock drive the Qt-free core end to end. No network, no Qt.
//
// Fixtures: manifest inputs use rows of the public export fixture
// family/bitcoin/dash/tests/fixtures/xdgf-getaddressutxos-tip2563986.json
// (txid, outputIndex, script, satoshis) with the heights each test needs; the
// signed txs are synthetic, structurally valid legacy txs (the scheduler never
// runs scripts). The control token fixture lives in a 0600 temp file.

#include "../sched/ArmPolicy.hpp"
#include "../sched/ChainView.hpp"
#include "../sched/Clock.hpp"
#include "../sched/Config.hpp"
#include "../sched/InjectQueue.hpp"
#include "../sched/NodeApi.hpp"
#include "../sched/Scheduler.hpp"
#include "../sched/SubmitOutcome.hpp"
#include "../sched/TokenFile.hpp"
#include "../sched/Triggers.hpp"
#include "../sched/Runner.hpp"
#include "../sched/SchedCli.hpp"

#include "../../family/bitcoin/dash/InjectMaturity.hpp"

#include "Digest.hpp"
#include "TransferContainer.hpp"
#include "ValidateSeam.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

extern char** environ;

using namespace c2w::companion::sched;
namespace art = c2w::artifact;
using nj = nlohmann::ordered_json;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

static const char* kToken = "SCHED-KAT-TOKEN-0123456789abcdef0123456789abcdef";
static const char* kNonce = "f00dfeedcafebabe0011223344556677";
static std::vector<std::string> g_tmpfiles;

static int64_t T(const char* s)
{
    int64_t t = 0;
    std::string why;
    if (!parse_utc(s, t, why)) std::printf("  bad fixture time %s\n", s);
    return t;
}

static size_t count_of(const std::string& hay, const std::string& needle)
{
    if (needle.empty()) return 0;
    size_t n = 0;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) ++n;
    return n;
}

// Any 20-char window of the token (or the whole nonce) in `s`?
static bool leaks_secret(const std::string& s)
{
    const std::string tok = kToken;
    for (size_t i = 0; i + 20 <= tok.size(); ++i)
        if (s.find(tok.substr(i, 20)) != std::string::npos) return true;
    return s.find(kNonce) != std::string::npos;
}

static std::string make_file(const std::string& content, mode_t mode)
{
    char tmpl[] = "/tmp/c2w-sched-kat-XXXXXX";
    const int fd = ::mkstemp(tmpl);
    if (fd < 0) return {};
    if (::write(fd, content.data(), content.size()) != static_cast<ssize_t>(content.size())) std::printf("  short write\n");
    ::fchmod(fd, mode);
    ::close(fd);
    g_tmpfiles.push_back(tmpl);
    return tmpl;
}

// ── synthetic signed txs ────────────────────────────────────────────────────

static std::string hexb(const std::vector<uint8_t>& v) { return art::to_hex(v); }

static void put_varint(std::vector<uint8_t>& o, uint64_t n)
{
    if (n < 0xfd) { o.push_back(static_cast<uint8_t>(n)); return; }
    if (n <= 0xffff) { o.push_back(0xfd); o.push_back(n & 0xff); o.push_back((n >> 8) & 0xff); return; }
    o.push_back(0xfe);
    for (int i = 0; i < 4; ++i) o.push_back((n >> (8 * i)) & 0xff);
}

static void put_le(std::vector<uint8_t>& o, uint64_t v, int n)
{
    for (int i = 0; i < n; ++i) o.push_back((v >> (8 * i)) & 0xff);
}

// A structurally valid legacy tx. `sig_len` 0 => unsigned (empty scriptSig).
static std::string make_tx(uint32_t seed, size_t nin = 1, size_t nout = 1, size_t sig_len = 106)
{
    std::vector<uint8_t> t;
    put_le(t, 2, 4);
    put_varint(t, nin);
    for (size_t i = 0; i < nin; ++i) {
        std::vector<uint8_t> pre = {static_cast<uint8_t>(seed), static_cast<uint8_t>(seed >> 8),
                                    static_cast<uint8_t>(seed >> 16), static_cast<uint8_t>(i), static_cast<uint8_t>(i >> 8)};
        const art::Hash32 h = art::sha256(pre);
        t.insert(t.end(), h.begin(), h.end());
        put_le(t, static_cast<uint32_t>(i), 4);
        put_varint(t, sig_len);
        for (size_t k = 0; k < sig_len; ++k) t.push_back(static_cast<uint8_t>(0x44 + ((seed + k) % 3)));
        put_le(t, 0xffffffffu, 4);
    }
    put_varint(t, nout);
    for (size_t i = 0; i < nout; ++i) {
        put_le(t, 1000 + i, 8);
        t.push_back(25);
        const uint8_t spk[] = {0x76, 0xa9, 0x14, 0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94, 0x7e,
                               0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a, 0xd9, 0xaf, 0x3c, 0x61, 0x88, 0xac};
        t.insert(t.end(), spk, spk + 25);
    }
    put_le(t, 0, 4);
    return hexb(t);
}

static std::string txid_of(const std::string& hex) { return art::crossgap_txid(hex); }

// ── manifest fixture ────────────────────────────────────────────────────────

struct MIn {
    std::string txid;
    int64_t vout = 7;
    int64_t value = 36490;
    std::optional<int64_t> height;
    bool coinbase = true;
};

// Rows of xdgf-getaddressutxos-tip2563986.json.
static const char* kFixtureTxids[] = {
    "665710f4833e0d3b4c2ce93b971e5fe04315fe244d3c53c926db511a8dde1b9b",
    "27a7df11dc6623f5973c2c520366948528fb87d3e7b1da7d9f9a2708bff7e7db",
    "a241f99503a5aa3f1755c4ef55ab885503b43c1d967799d6d351ba7e1f26bbb4",
};

static MIn fin(int i, std::optional<int64_t> height, bool coinbase = true)
{
    MIn m;
    m.txid = kFixtureTxids[i % 3];
    m.height = height;
    m.coinbase = coinbase;
    return m;
}

struct Art {
    std::string hex_text;
    std::string manifest;
    std::vector<std::string> txids;
};

struct ManifestOpts {
    std::optional<int64_t> safe_override;
    bool safe_null = false;
    std::optional<int64_t> youngest_override;
    std::string fee_mode = "inject-zero-fee";
    int64_t fee = 0;
    std::string network = "mainnet";
    std::optional<std::string> txid_override;
};

static Art build(const std::vector<std::string>& txs, const std::vector<std::vector<MIn>>& inputs,
                 const ManifestOpts& o = {})
{
    Art a;
    art::SignedContainer sc;
    sc.tx_hexes = txs;
    a.hex_text = sc.emit();
    nj m = nj::object();
    m["schema"] = "c2wallet-inject-manifest/1";
    m["coin"] = "dash";
    m["network"] = o.network;
    m["mode"] = "consolidate";
    m["fee_mode"] = o.fee_mode;
    m["hex_file_sha256"] =
        art::to_hex(art::sha256(reinterpret_cast<const uint8_t*>(a.hex_text.data()), a.hex_text.size()));
    m["tx_count"] = txs.size();
    nj jtxs = nj::array();
    int64_t safe = 0, youngest = 0;
    bool unknown = false;
    for (size_t i = 0; i < txs.size(); ++i) {
        a.txids.push_back(txid_of(txs[i]));
        nj t = nj::object();
        t["txid"] = (i == 0 && o.txid_override) ? *o.txid_override : a.txids.back();
        t["size"] = txs[i].size() / 2;
        t["vin"] = inputs[i].size();
        t["vout"] = 1;
        t["value_out"] = 60963705;
        t["fee"] = o.fee;
        nj ins = nj::array();
        for (const MIn& in : inputs[i]) {
            nj ij = nj::object();
            ij["txid"] = in.txid;
            ij["vout"] = in.vout;
            ij["value"] = in.value;
            ij["script_hex"] = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
            ij["height"] = in.height ? nj(*in.height) : nj(nullptr);
            ij["coinbase"] = in.coinbase;
            ins.push_back(ij);
            if (!in.height) unknown = true;
            else {
                safe = std::max(safe, *in.height + (in.coinbase ? 100 : 1));
                youngest = std::max(youngest, *in.height);
            }
        }
        t["inputs"] = ins;
        jtxs.push_back(t);
    }
    m["txs"] = jtxs;
    nj mat = nj::object();
    mat["intake"] = "c2wallet-utxo-export/1";
    mat["min_confirmations"] = 101;
    mat["youngest_input_height"] = o.youngest_override ? nj(*o.youngest_override) : (unknown ? nj(nullptr) : nj(youngest));
    if (o.safe_null) mat["safe_from_height"] = nullptr;
    else if (o.safe_override) mat["safe_from_height"] = *o.safe_override;
    else mat["safe_from_height"] = unknown ? nj(nullptr) : nj(safe);
    m["maturity"] = mat;
    a.manifest = m.dump(2) + "\n";
    return a;
}

static EnqueueRequest req_for(const Art& a)
{
    EnqueueRequest r;
    r.hex_text = a.hex_text;
    r.hex_path = "sweep.hex";
    r.manifest_text = a.manifest;
    r.manifest_path = "sweep.manifest.json";
    return r;
}

// ── fake clock + fake node ──────────────────────────────────────────────────

struct FakeClock : Clock {
    int64_t t = 0;
    int64_t mono = 1000;
    int64_t now_unix() const override { return t; }
    int64_t monotonic_ms() const override { return mono; }
};

struct Req {
    std::string method, path, body;
};

struct FakeBlock {
    std::string hash;
    std::vector<std::string> txids;
    bool body = true;
};

struct FakeNode : NodeApi {
    const FakeClock* clock = nullptr;
    bool down = false;
    bool synced = true;
    std::string blocked_by = "headers-behind";
    int64_t tip = 2565300;
    bool wired = true, enabled = true, control_plane = true;
    std::string token = kToken;
    int64_t pool_entries = 0, pool_bytes = 0, pool_max_entries = 1024, pool_max_bytes = 400000;
    int64_t rl_in_window = 0, rl_max = 200, rl_window = 60;
    std::set<std::string> mempool;
    std::map<std::string, int64_t> time_added;
    std::map<std::string, int64_t> expiry; // txid -> expiry_height (0 = none)
    bool explorer = true;                   // false: --no-explorer
    bool cl_exposed = false;                // getblockchaininfo carries "bestchainlock"
    std::optional<int64_t> cl_height;       // the best ChainLock (null when exposed without one)
    std::map<int64_t, FakeBlock> blocks;
    int64_t salt = 0;
    std::string issued_nonce;
    std::deque<std::pair<std::string, HttpReply>> script; // "METHOD path-prefix" -> reply (consumed)
    std::vector<Req> log;

    static HttpReply reply(int st, const nj& j) { return HttpReply{true, st, j.dump(), ""}; }

    std::string synth_hash(int64_t h, int64_t s) const
    {
        char buf[80];
        std::snprintf(buf, sizeof(buf), "%032llx%032llx", static_cast<unsigned long long>(s + 7),
                      static_cast<unsigned long long>(h));
        return buf;
    }
    std::string hash_at(int64_t h) const
    {
        auto it = blocks.find(h);
        return it != blocks.end() ? it->second.hash : synth_hash(h, 0);
    }
    // The node's reaper on every tip advance: reconcile_inject_pool() calls
    // reap_expired(tip + 1), which drops entries with tip + 1 > expiry_height
    // (node_coin_state.hpp, tx_inject_pool.hpp), from the pool and the mempool.
    void reap()
    {
        for (auto it = mempool.begin(); it != mempool.end();) {
            auto e = expiry.find(*it);
            if (e != expiry.end() && e->second != 0 && tip + 1 > e->second) it = mempool.erase(it);
            else ++it;
        }
    }
    void mine(const std::vector<std::string>& txids = {})
    {
        ++tip;
        blocks[tip] = FakeBlock{synth_hash(tip, salt), txids, true};
        for (const auto& t : txids) mempool.erase(t);
        reap();
    }
    void advance(int n)
    {
        for (int i = 0; i < n; ++i) mine();
    }
    void reorg(int64_t h)
    {
        ++salt;
        blocks[h] = FakeBlock{synth_hash(h, salt + 100), {}, true};
    }
    bool in_blocks(const std::string& txid) const
    {
        for (const auto& b : blocks)
            if (b.first <= tip)
                for (const auto& t : b.second.txids)
                    if (t == txid) return true;
        return false;
    }
    size_t count(const std::string& method, const std::string& prefix) const
    {
        size_t n = 0;
        for (const auto& r : log)
            if (r.method == method && r.path.rfind(prefix, 0) == 0) ++n;
        return n;
    }
    std::vector<std::string> bodies(const std::string& path) const
    {
        std::vector<std::string> out;
        for (const auto& r : log)
            if (r.method == "POST" && r.path == path) out.push_back(r.body);
        return out;
    }

    std::optional<HttpReply> scripted(const std::string& method, const std::string& path)
    {
        for (auto it = script.begin(); it != script.end(); ++it) {
            const std::string key = method + " ";
            if (it->first.rfind(key, 0) == 0 && path.rfind(it->first.substr(key.size()), 0) == 0) {
                HttpReply r = it->second;
                script.erase(it);
                return r;
            }
        }
        return std::nullopt;
    }

    HttpReply get(const std::string& path) override
    {
        log.push_back({"GET", path, ""});
        if (auto r = scripted("GET", path)) return *r;
        if (down) return HttpReply{false, 0, "", "connection refused"};
        if (path == route::kStatus) {
            nj j = nj::object();
            j["wired"] = wired;
            j["enabled"] = enabled;
            j["updated_at"] = wired ? 1 : 0;
            j["pool"] = {{"entries", pool_entries}, {"bytes", pool_bytes}, {"max_entries", pool_max_entries},
                         {"max_total_bytes", pool_max_bytes}, {"max_tx_bytes", 100000}};
            j["rate_limit"] = {{"local", {{"count_refused", 0}, {"bytes_refused", 0}, {"in_window", rl_in_window},
                                          {"bytes_in_window", 0}}},
                               {"peers", {{"count_refused", 0}, {"bytes_refused", 0}, {"in_window", 0},
                                          {"bytes_in_window", 0}}},
                               {"caps", {{"max_per_window", rl_max}, {"max_bytes_per_window", 8388608},
                                         {"window_sec", rl_window}}}};
            return reply(200, j);
        }
        if (!explorer && path.rfind("/api/explorer/", 0) == 0)
            return reply(404, nj{{"error", "Explorer not enabled"}});
        if (path == route::kChainInfo) {
            nj j = nj::object();
            j["chain"] = "main";
            j["synced"] = synced;
            if (synced) {
                j["blocks"] = tip;
                j["headers"] = tip;
                j["bestblockhash"] = hash_at(tip);
                if (cl_exposed)
                    j["bestchainlock"] = cl_height ? nj{{"height", *cl_height}, {"blockhash", hash_at(*cl_height)}}
                                                   : nj(nullptr);
            } else {
                j["sync_blocked_by"] = blocked_by;
                j["stale"] = {{"tip_height", tip}};
                j["unavailable"] = {{"blocks", blocked_by}};
            }
            return reply(200, j);
        }
        if (path == route::kRawMempool) {
            nj a = nj::array();
            for (const auto& t : mempool) a.push_back(t);
            return reply(200, a);
        }
        const std::string me = route::kMempoolEntry;
        if (path.rfind(me, 0) == 0) {
            const std::string txid = path.substr(me.size());
            if (!mempool.count(txid)) return reply(200, nj{{"error", "Transaction not in mempool"}});
            return reply(200, nj{{"txid", txid}, {"time_added", time_added[txid]}, {"size", 200}});
        }
        const std::string gb = route::kBlockAtHeight;
        if (path.rfind(gb, 0) == 0) {
            const int64_t h = std::stoll(path.substr(gb.size()));
            if (h > tip || h < 1) return reply(200, nj{{"error", "height out of range"}, {"code", "BAD_PARAMS"}});
            auto it = blocks.find(h);
            nj j = nj::object();
            j["hash"] = hash_at(h);
            j["height"] = h;
            if (it == blocks.end() || it->second.body) {
                nj txs = nj::array();
                txs.push_back(nj{{"txid", synth_hash(h, 999)}}); // coinbase
                if (it != blocks.end())
                    for (const auto& t : it->second.txids) txs.push_back(nj{{"txid", t}});
                j["tx"] = txs;
                j["nTx"] = txs.size();
            }
            return reply(200, j);
        }
        const std::string bh = route::kBlockHash;
        if (path.rfind(bh, 0) == 0) {
            const int64_t h = std::stoll(path.substr(bh.size()));
            if (h > tip || h < 1) return reply(200, nj{{"error", "height above tip"}});
            return HttpReply{true, 200, "\"" + hash_at(h) + "\"", ""};
        }
        return reply(200, nj{{"error", "Unknown explorer endpoint"}});
    }

    HttpReply post_json(const std::string& path, const std::string& body) override
    {
        log.push_back({"POST", path, body});
        if (auto r = scripted("POST", path)) return *r;
        if (down) return HttpReply{false, 0, "", "connection refused"};
        const nj b = nj::parse(body, nullptr, false);
        const std::string presented =
            b.is_object() && b.contains("control_token") && b["control_token"].is_string() ? b["control_token"].get<std::string>()
                                                                                             : "";
        if (path == route::kSubmit) {
            if (presented != token) return reply(403, nj{{"ok", false}, {"cause", "missing or invalid control token"}});
            const std::string raw = b.value("raw_tx", "");
            const std::string txid = txid_of(raw);
            if (!enabled)
                return reply(409, nj{{"ok", false}, {"cause", "inject-disabled"}, {"txid", txid}, {"armed", false}});
            if (mempool.count(txid))
                return reply(422, nj{{"ok", false}, {"cause", "inject-already-known"}, {"txid", txid}, {"armed", true}});
            if (in_blocks(txid))
                return reply(422,
                             nj{{"ok", false}, {"cause", "inject-already-confirmed"}, {"txid", txid}, {"armed", true}});
            mempool.insert(txid);
            time_added[txid] = clock ? clock->t : 0;
            expiry[txid] = b.contains("expiry_height") && b["expiry_height"].is_number_integer()
                               ? b["expiry_height"].get<int64_t>()
                               : 0;
            return reply(200, nj{{"ok", true}, {"cause", "ok"}, {"txid", txid}, {"armed", true}});
        }
        if (path == route::kConfigApply) {
            if (!control_plane) return reply(503, nj{{"status", "not_armed"}, {"armed", false}, {"applied", false}});
            if (presented != token) return reply(403, nj{{"status", "no_token"}, {"applied", false}});
            const std::string v = b.contains("changes") ? b["changes"].value("embedded.tx_inject", "") : "";
            if (!b.contains("money_nonce")) {
                issued_nonce = kNonce;
                return reply(200, nj{{"status", "need_confirm"}, {"need_confirm", true}, {"money_nonce", kNonce},
                                     {"money_keys", nj::array({"embedded.tx_inject"})}, {"applied", false}});
            }
            if (b["money_nonce"] == issued_nonce && !issued_nonce.empty()) {
                issued_nonce.clear();
                enabled = v == "true";
                return reply(200, nj{{"status", "applied"}, {"applied", true},
                                     {"applied_keys", nj::array({"embedded.tx_inject"})}});
            }
            return reply(409, nj{{"status", "money_gate"}, {"applied", false}, {"error", "nonce mismatch"}});
        }
        return reply(404, nj{{"error", "no route"}});
    }
    const char* name() const override { return "fake-node"; }
};

struct CaptureJournal : JournalSink {
    std::vector<std::string> lines;
    void line(const std::string& t) override { lines.push_back(t); }
    std::string all() const
    {
        std::string s;
        for (const auto& l : lines) s += l + "\n";
        return s;
    }
};

// One scheduler world: clock, node, queue, token file, journal, persistence.
struct World {
    FakeClock clock;
    FakeNode node;
    Queue q;
    CaptureJournal sink;
    std::string token_path;
    std::string last_persisted;
    int64_t persist_count = 0;
    SchedulerOptions opt;
    std::unique_ptr<Scheduler> s;

    explicit World(SchedulerOptions o = {}) : opt(std::move(o))
    {
        clock.t = T("2026-11-02T00:10:12Z");
        node.clock = &clock;
        token_path = make_file(std::string(kToken) + "\n", 0600);
        q.node.token_file = token_path;
        rebuild();
    }
    void rebuild()
    {
        s = std::make_unique<Scheduler>(q, node, clock, sink, opt);
        s->set_persist([this](const Queue& qq, std::string&) {
            last_persisted = queue_to_json(qq);
            ++persist_count;
            return true;
        });
    }
    TickReport tick(int64_t advance = 15)
    {
        clock.t += advance;
        return s->tick();
    }
    Item& item(size_t i = 0) { return q.items[i]; }
    std::string add(const Art& a, EnqueueRequest r)
    {
        const EnqueueResult er = enqueue(q, r, clock.t);
        if (!er.ok) std::printf("  enqueue refused: %s\n", er.why.c_str());
        return er.ok ? er.ids.back() : std::string();
    }
    std::string add(const Art& a) { return add(a, req_for(a)); }
};

static Art simple(uint32_t seed, int64_t h0 = 2565145, bool coinbase = true)
{
    return build({make_tx(seed)}, {{fin(seed, h0, coinbase)}});
}

static ChainSnapshot tipat(int64_t h) { return ChainSnapshot{true, h, ""}; }
static ParentStatus no_parent(const std::string&) { return {}; }

// ─────────────────────────────────────────────────────────────────────────────

static void k1_maturity_boundary()
{
    namespace m = c2w::dash::maturity;
    CHECK(m::spendable_from_height(2565145, true) == 2565245, "K1: h0=2565145 coinbase -> spendable in 2565245");
    CHECK(m::fires_at_tip(2565245) == 2565244, "K1: S=2565245 fires at tip 2565244");
    World w;
    const Art a = simple(1);
    w.add(a);
    CHECK(w.q.items.size() == 1, "K1: enqueued");
    const Item& it = w.item();
    CHECK(it.triggers.maturity.enabled && it.triggers.maturity.safe_from_height == 2565245 &&
              it.triggers.maturity.youngest_input_height == 2565145,
          "K1: maturity from manifest.maturity.safe_from_height (cross-checked)");
    CHECK(maturity_fire_tip(it.triggers.maturity) == 2565244, "K1: fire tip S-1");
    CHECK(!evaluate(it, tipat(2565243), w.clock.t, no_parent).ready, "K1: tip S-2 waits");
    CHECK(evaluate(it, tipat(2565244), w.clock.t, no_parent).ready, "K1: tip S-1 fires");
    CHECK(evaluate(it, tipat(2565245), w.clock.t, no_parent).ready, "K1: tip S fires");
    const Verdict v = evaluate(it, tipat(2565100), w.clock.t, no_parent);
    CHECK(v.why().find("2565244") != std::string::npos && v.why().find("144 blocks ~6 h 14 m") != std::string::npos,
          "K1: why names the fire tip and the ETA (144 blocks ~6 h 14 m)");

    // Through the scheduler: no submit at S-2, submit at S-1.
    w.node.tip = 2565243;
    w.tick();
    CHECK(w.item().state == State::Waiting && w.node.count("POST", route::kSubmit) == 0, "K1: tick at S-2 -> waiting, no POST");
    w.node.tip = 2565244;
    w.tick();
    CHECK(w.node.count("POST", route::kSubmit) == 1 && w.item().state == State::Admitted, "K1: tick at S-1 -> submitted, admitted");
    CHECK(!w.item().attempts.empty() && w.item().attempts.back().expiry_height == 2565244 + 576,
          "K1: expiry_height = tip + expiry_blocks");
}

static void k2_maturity_unknown_never_auto()
{
    World w;
    ManifestOpts o;
    o.safe_null = true;
    const Art a = build({make_tx(2)}, {{fin(0, 2565145)}}, o);
    EnqueueRequest r = req_for(a);
    EnqueueResult er = enqueue(w.q, r, w.clock.t);
    CHECK(!er.ok && er.why.find("maturity is unknown") != std::string::npos && w.q.items.empty(),
          "K2: safe_from_height null -> enqueue refused without an override");

    ManifestOpts os;
    os.safe_override = 2565245; // the manifest claims a height; one input does not carry one
    const Art b = build({make_tx(3)}, {{fin(0, 2565145), fin(1, std::nullopt)}}, os);
    er = enqueue(w.q, req_for(b), w.clock.t);
    CHECK(!er.ok && w.q.items.empty(), "K2: an input with height null -> refused without an override");

    EnqueueRequest rb = req_for(b);
    rb.not_before_height = 2565400;
    er = enqueue(w.q, rb, w.clock.t);
    CHECK(er.ok && w.q.items.size() == 1, "K2: with --not-before-height -> accepted");
    const Item& it = w.item();
    CHECK(!it.triggers.maturity.enabled && it.triggers.maturity.inputs_with_unknown_height == 1 &&
              it.triggers.not_before_height == 2565400,
          "K2: maturity disabled, unknown inputs counted, height trigger only");
    CHECK(!evaluate(it, tipat(2565399), w.clock.t, no_parent).ready &&
              evaluate(it, tipat(2565400), w.clock.t, no_parent).ready,
          "K2: the trigger is not_before_height only");

    EnqueueRequest ra = req_for(a);
    ra.inputs_known_mature_consent = "inputs are 2 years old (operator G)";
    er = enqueue(w.q, ra, w.clock.t);
    CHECK(er.ok && !w.item(1).triggers.maturity.enabled &&
              w.item(1).triggers.maturity.override_consent == std::string("inputs are 2 years old (operator G)") &&
              evaluate(w.item(1), tipat(1), w.clock.t, no_parent).ready,
          "K2: explicit override recorded with its consent text");

    EnqueueRequest bare;
    bare.hex_text = art::SignedContainer{{make_tx(4)}}.emit();
    er = enqueue(w.q, bare, w.clock.t);
    CHECK(!er.ok && er.why.find("bare hex") != std::string::npos, "K2: bare .hex without override -> refused");
}

static void k3_noncoinbase_inputs()
{
    World w;
    const Art a = build({make_tx(5)}, {{fin(0, 2565000, false), fin(1, 2565010, false)}});
    w.add(a);
    const Item& it = w.item();
    CHECK(it.triggers.maturity.safe_from_height == 2565011, "K3: S = max(h + 1) for known non-coinbase inputs");
    CHECK(!evaluate(it, tipat(2565009), w.clock.t, no_parent).ready &&
              evaluate(it, tipat(2565010), w.clock.t, no_parent).ready,
          "K3: ready at tip >= max(h)");
}

static void k4_manifest_cross_check()
{
    World w;
    ManifestOpts o;
    o.safe_override = 2565244;
    const Art a = build({make_tx(6)}, {{fin(0, 2565145)}}, o);
    EnqueueResult er = enqueue(w.q, req_for(a), w.clock.t);
    CHECK(!er.ok && er.why.find("manifest maturity mismatch") != std::string::npos, "K4: safe_from_height vs inputs mismatch refused");

    ManifestOpts oy;
    oy.youngest_override = 2565144;
    er = enqueue(w.q, req_for(build({make_tx(6)}, {{fin(0, 2565145)}}, oy)), w.clock.t);
    CHECK(!er.ok && er.why.find("youngest_input_height") != std::string::npos, "K4: youngest_input_height mismatch refused");

    const Art good = simple(7);
    EnqueueRequest r = req_for(good);
    r.hex_text = art::SignedContainer{{make_tx(8)}}.emit();
    er = enqueue(w.q, r, w.clock.t);
    CHECK(!er.ok && er.why.find("sha256") != std::string::npos, "K4: hex sha256 != hex_file_sha256 refused");

    ManifestOpts ot;
    ot.txid_override = std::string(64, 'a');
    er = enqueue(w.q, req_for(build({make_tx(9)}, {{fin(0, 2565145)}}, ot)), w.clock.t);
    CHECK(!er.ok && er.why.find("does not match the manifest") != std::string::npos, "K4: line txid != txs[i].txid refused");

    ManifestOpts on;
    on.network = "testnet";
    er = enqueue(w.q, req_for(build({make_tx(9)}, {{fin(0, 2565145)}}, on)), w.clock.t);
    CHECK(!er.ok && er.why.find("testnet") != std::string::npos, "K4: manifest for another network refused");
    CHECK(w.q.items.empty(), "K4: every refusal left the queue unchanged");

    // Multi-tx manifest: maturity is cross-checked over every tx's inputs.
    const Art two = build({make_tx(10), make_tx(11)}, {{fin(0, 2565000)}, {fin(1, 2565145)}});
    er = enqueue(w.q, req_for(two), w.clock.t);
    CHECK(er.ok && er.ids.size() == 2 && w.item(0).triggers.maturity.safe_from_height == 2565245 &&
              w.item(1).tx.source.line == 2,
          "K4: two-line hex -> two items, maturity over all inputs");
}

static void k5_not_before_height_and_time()
{
    int64_t t = 0;
    std::string why;
    CHECK(parse_utc("2026-11-05T10:00:00Z", t, why) && format_utc(t) == "2026-11-05T10:00:00Z", "K5: UTC parse/format round trip");
    CHECK(!parse_utc("2026-11-05T10:00:00", t, why) && why.find("trailing Z") != std::string::npos, "K5: naive timestamp refused");
    CHECK(!parse_utc("2026-11-05T10:00:00+03:00", t, why), "K5: offset timestamp refused");
    CHECK(!parse_utc("2026-02-30T00:00:00Z", t, why) && !parse_utc("2025-02-29T00:00:00Z", t, why) &&
              parse_utc("2028-02-29T00:00:00Z", t, why),
          "K5: calendar validated (leap years)");

    World w;
    const Art a = simple(12);
    EnqueueRequest r = req_for(a);
    r.not_before_time = "2026-11-05T10:00:00";
    CHECK(!enqueue(w.q, r, w.clock.t).ok, "K5: enqueue with a naive not_before_time refused");
    r.not_before_time = "2026-11-05T10:00:00Z";
    r.not_before_height = 2565500;
    w.add(a, r);
    const Item& it = w.item();
    const int64_t when = T("2026-11-05T10:00:00Z");
    CHECK(!evaluate(it, tipat(2565499), when, no_parent).ready, "K5: height below -> waits");
    CHECK(!evaluate(it, tipat(2565500), when - 1, no_parent).ready, "K5: time before -> waits");
    CHECK(evaluate(it, tipat(2565500), when, no_parent).ready, "K5: height at + time at -> ready");
}

static void k6_after_parent_confirmations()
{
    SchedulerOptions so;
    so.reorg_check_every = 1;
    World w(so);
    const Art pa = simple(20);
    w.add(pa);
    const std::string ptx = pa.txids[0];
    const Art ca = simple(21);
    EnqueueRequest cr = req_for(ca);
    cr.after_parent = {{ptx, 2}};
    w.add(ca, cr);
    w.tick();
    CHECK(w.item(0).state == State::Admitted && w.item(1).state == State::Waiting, "K6: parent submitted, child waits");
    CHECK(w.item(1).why.find("not mined yet") != std::string::npos, "K6: parent unseen -> child waiting");
    w.node.mine({ptx});
    const int64_t H = w.node.tip;
    w.tick();
    CHECK(w.item(0).state == State::Mined && w.item(0).node.mined_height == H, "K6: parent mined at H");
    CHECK(w.item(1).state == State::Waiting && w.item(1).why.find("1/2 confirmations") != std::string::npos,
          "K6: tip-H+1 = 1 < 2 -> waiting");
    w.node.mine();
    w.tick();
    CHECK(w.item(1).state == State::Admitted && w.node.count("POST", route::kSubmit) == 2, "K6: 2 >= 2 -> child ready and submitted");

    // Reorg drops the parent's block before the child fires.
    World r(so);
    r.add(pa);
    EnqueueRequest cr3 = req_for(ca);
    cr3.after_parent = {{ptx, 3}};
    r.add(ca, cr3);
    r.tick();
    r.node.mine({ptx});
    const int64_t H2 = r.node.tip;
    r.tick();
    r.node.mine();
    r.tick();
    CHECK(r.item(0).state == State::Mined && r.item(1).state == State::Waiting, "K6: 2/3 confirmations -> waiting");
    r.node.reorg(H2);
    r.tick();
    bool saw = false;
    for (const auto& e : r.item(0).journal)
        if (e.event == "state" && e.detail.rfind("mined -> waiting", 0) == 0) saw = true;
    CHECK(saw, "K6: getblockhash at H changed -> parent back to waiting");
    CHECK(r.item(1).state == State::Waiting && r.item(1).why.find("not mined yet") != std::string::npos,
          "K6: child waiting again (parent not mined)");
}

static void k7_all_of_combination()
{
    World w;
    const Art a = simple(30);
    EnqueueRequest r = req_for(a);
    r.not_before_height = 2565260;
    r.not_before_time = "2026-11-03T00:00:00Z";
    const std::string foreign = std::string(63, 'b') + "c";
    r.after_parent = {{foreign, 1}};
    w.add(a, r);
    const Item& it = w.item();
    CHECK(w.q.tracked.size() == 1 && w.q.tracked[0].txid == foreign, "K7: foreign parent tracked");
    const int64_t now = T("2026-11-02T12:00:00Z");
    Verdict v = evaluate(it, tipat(2565200), now, no_parent);
    CHECK(!v.ready && v.unmet.size() == 4, "K7: all four conditions unmet");
    CHECK(v.unmet[0].kind == TriggerKind::Maturity && v.unmet[1].kind == TriggerKind::Height &&
              v.unmet[2].kind == TriggerKind::Time && v.unmet[3].kind == TriggerKind::Parent,
          "K7: order maturity -> height -> time -> parents");
    CHECK(v.unmet[0].eta_blocks == 44 && v.unmet[1].eta_blocks == 60 && v.unmet[2].eta_time == T("2026-11-03T00:00:00Z"),
          "K7: per-condition ETAs");
    const std::string why = v.why();
    CHECK(why.find("maturity:") < why.find("height:") && why.find("height:") < why.find("time:") &&
              why.find("time:") < why.find("parent "),
          "K7: why lists each unmet condition in order");
    auto mined_parent = [&](const std::string& t) {
        ParentStatus p;
        p.known = true;
        p.mined = t == foreign;
        p.mined_height = 2565250;
        p.mined_hash = std::string(64, 'e');
        p.block_still_at_height = true; // the block at 2565250 is still the parent's
        return p;
    };
    v = evaluate(it, tipat(2565260), now, mined_parent);
    CHECK(!v.ready && v.unmet.size() == 1 && v.unmet[0].kind == TriggerKind::Time, "K7: any unmet -> waiting");
    v = evaluate(it, tipat(2565260), T("2026-11-03T00:00:00Z"), mined_parent);
    CHECK(v.ready && v.why().empty(), "K7: all met -> ready");
}

static void k8_disarmed_never_arms_without_consent()
{
    World w;
    w.add(simple(40));
    w.node.script.push_back({"POST /api/tx-inject/submit",
                             FakeNode::reply(409, nj{{"ok", false}, {"cause", "inject-disabled"}, {"armed", false}})});
    w.tick();
    CHECK(w.item().state == State::BlockedNotArmed, "K8: 409 inject-disabled -> blocked_not_armed");
    w.node.enabled = false;
    for (int i = 0; i < 10; ++i) w.tick(60);
    CHECK(w.node.count("POST", route::kConfigApply) == 0, "K8: 10 ticks enabled:false -> zero POSTs to /api/config/apply");
    CHECK(w.node.count("POST", route::kSubmit) == 1 && w.item().state == State::BlockedNotArmed,
          "K8: no submit while disarmed; still blocked");
    CHECK(w.item().why.find("--embedded-tx-inject") != std::string::npos, "K8: why names the standing-arm flag");
    w.node.enabled = true;
    w.tick();
    CHECK(w.node.count("POST", route::kSubmit) == 2 && w.item().state == State::Admitted, "K8: enabled:true -> resubmit -> admitted");
}

static void k9_refusal_cause_table()
{
    struct Row {
        const char* cause;
        int http;
        State s;
        RetryClass r;
        bool alert;
    };
    const Row rows[] = {
        {"ok", 200, State::Admitted, RetryClass::None, false},
        {"inject-already-known", 422, State::Admitted, RetryClass::None, false},
        {"inject-pool-duplicate", 422, State::Admitted, RetryClass::None, false},
        {"inject-already-confirmed", 422, State::Mined, RetryClass::None, false},
        {"inject-disabled", 409, State::BlockedNotArmed, RetryClass::Arm, false},
        {"inject-rate-limited-count", 422, State::Ready, RetryClass::RateWindow, false},
        {"inject-rate-limited-bytes", 422, State::Ready, RetryClass::RateWindow, false},
        {"inject-pool-full", 422, State::Ready, RetryClass::PoolFull, false},
        {"inject-pool-total-bytes-exceeded", 422, State::Ready, RetryClass::PoolFull, false},
        {"inject-script-check-unarmed", 422, State::BlockedNode, RetryClass::Slow, false},
        {"inject-unpriceable", 422, State::Ready, RetryClass::Unpriceable, false},
        {"inject-oversize", 422, State::Refused, RetryClass::None, false},
        {"inject-pool-oversize", 422, State::Refused, RetryClass::None, false},
        {"inject-type-unsupported", 422, State::Refused, RetryClass::None, false},
        {"inject-bad-txns-version-or-type", 422, State::Refused, RetryClass::None, false},
        {"inject-bip68-unsupported", 422, State::Refused, RetryClass::None, false},
        {"inject-bad-txns-vout-range", 422, State::Refused, RetryClass::None, false},
        {"inject-spent-shaped-output", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-too-many-inputs", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-too-many-outputs", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-scriptsig-too-large", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-total-scriptsig-too-large", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-too-many-sigops", 422, State::Refused, RetryClass::None, false},
        {"inject-sandbox-unknown", 422, State::BlockedNode, RetryClass::Operator, true},
        {"inject-unknown", 422, State::BlockedNode, RetryClass::Operator, true},
        {"inject-pool-unknown", 422, State::BlockedNode, RetryClass::Operator, true},
        {"inject-rate-limited-unknown", 422, State::BlockedNode, RetryClass::Operator, true},
        {"inject-rate-limited-peers-unknown", 422, State::BlockedNode, RetryClass::Operator, true},
        {"inject-rate-limited-peers-count", 422, State::Ready, RetryClass::RateWindow, false},
        {"inject-rate-limited-peers-bytes", 422, State::Ready, RetryClass::RateWindow, false},
        {"inject-script-invalid", 422, State::Refused, RetryClass::None, false},
        {"inject-fee-above-max", 422, State::Refused, RetryClass::None, false},
        {"inject-immature-coinbase-input", 422, State::Waiting, RetryClass::None, true},
        {"inject-prevout-missing", 422, State::Refused, RetryClass::None, false},
        {"inject-prevout-spent", 422, State::Refused, RetryClass::None, false},
        {"inject-oracle-unavailable", 422, State::Ready, RetryClass::Retry5m, false},
        {"inject-some-future-cause", 422, State::BlockedNode, RetryClass::Operator, true},
    };
    int good = 0;
    for (const Row& r : rows) {
        const Outcome o = classify_cause(r.cause, r.http);
        if (o.next == r.s && o.retry == r.r && o.alert == r.alert) ++good;
        else std::printf("  K9 row %s -> %s/%s\n", r.cause, state_name(o.next), retry_class_name(o.retry));
    }
    CHECK(good == static_cast<int>(sizeof(rows) / sizeof(rows[0])), "K9: every §6 cause maps to its state + retry class");
    CHECK(classify_cause("inject-immature-coinbase-input", 422).scheduler_bug, "K9: immature = scheduler bug alert");

    // Through a full reply: cause + armed + txid echo.
    HttpReply rep{true, 422, nj{{"ok", false}, {"cause", "inject-pool-full"}, {"txid", "ab"}, {"armed", true}}.dump(), ""};
    const Outcome o = classify_submit(rep, "ab");
    CHECK(o.next == State::Ready && o.armed == true && o.txid_echo == std::string("ab"), "K9: reply fields carried");
    HttpReply okrep{true, 200, nj{{"ok", true}, {"cause", "ok"}, {"txid", "cd"}, {"armed", true}}.dump(), ""};
    CHECK(classify_submit(okrep, "ab").next == State::Refused, "K9: 200 ok with another txid -> refused (txid mismatch)");

    // Unpriceable: retried 3 times at 10 min, refused on the 4th.
    World w;
    w.add(simple(50));
    for (int i = 0; i < 4; ++i)
        w.node.script.push_back({"POST /api/tx-inject/submit",
                                 FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-unpriceable"}})});
    w.tick();
    CHECK(w.item().state == State::Ready && w.item().retry.not_before == w.clock.t + 600, "K9: unpriceable 1/3 -> ready, 600 s");
    w.tick(300);
    CHECK(w.node.count("POST", route::kSubmit) == 1, "K9: no retry before 600 s");
    w.tick(300);
    w.tick(600);
    CHECK(w.node.count("POST", route::kSubmit) == 3 && w.item().state == State::Ready, "K9: unpriceable 3/3 still ready");
    w.tick(600);
    CHECK(w.node.count("POST", route::kSubmit) == 4 && w.item().state == State::Refused, "K9: 4th unpriceable -> refused");
}

static void k10_http_outcomes()
{
    CHECK(backoff_seconds(RetryClass::Backoff, 1) == 30 && backoff_seconds(RetryClass::Backoff, 2) == 60 &&
              backoff_seconds(RetryClass::Backoff, 3) == 120 && backoff_seconds(RetryClass::Backoff, 4) == 300 &&
              backoff_seconds(RetryClass::Backoff, 9) == 300,
          "K10: backoff 30/60/120/300/300");
    {
        World w;
        w.add(simple(60));
        for (int i = 0; i < 5; ++i)
            w.node.script.push_back({"POST /api/tx-inject/submit", HttpReply{false, 0, "", "connection refused"}});
        std::vector<int64_t> waits;
        int64_t step = 15;
        for (int i = 0; i < 5; ++i) {
            w.tick(step);
            waits.push_back(w.item().retry.not_before.value_or(0) - w.clock.t);
            step = waits.back();
        }
        CHECK(waits == std::vector<int64_t>({30, 60, 120, 300, 300}) && w.item().state == State::Ready &&
                  w.node.count("POST", route::kSubmit) == 5,
              "K10: connect refused -> ready with backoff 30/60/120/300/300");
        w.tick(120);
        CHECK(w.node.count("POST", route::kSubmit) == 5, "K10: no POST inside the back-off");
        w.tick(180);
        CHECK(w.item().state == State::Admitted, "K10: node back -> admitted at the gate");

        // A node that answers nothing at all: the tip is unknown, the item waits.
        World d;
        d.add(simple(67));
        d.node.down = true;
        d.tick();
        CHECK(d.item().state == State::Waiting && d.item().why.find("unreachable") != std::string::npos &&
                  d.node.count("POST", route::kSubmit) == 0,
              "K10: node down -> waiting (tip unknown: unreachable), no POST");
    }
    {
        World w;
        w.add(simple(61));
        w.node.script.push_back({"POST /api/tx-inject/submit", HttpReply{false, 0, "", "connection reset"}});
        w.tick();
        CHECK(w.item().state == State::Ready && w.item().retry.cls == RetryClass::Backoff &&
                  w.item().attempts.back().http == 0,
              "K10: transport error on the POST -> ready + backoff, attempt http 0");
    }
    {
        World w;
        w.add(simple(62));
        w.node.token = "SCHED-KAT-OTHER-TOKEN-00000000000000000000000000";
        w.tick();
        CHECK(w.item().state == State::BlockedToken, "K10: 403 -> blocked_token");
        w.tick();
        w.tick();
        CHECK(w.node.count("POST", route::kSubmit) == 1, "K10: blocked_token does not retry while the file is unchanged");
        w.node.token = kToken;
        struct timespec ts[2] = {{1000000, 0}, {1000000, 0}};
        ::utimensat(AT_FDCWD, w.token_path.c_str(), ts, 0);
        w.tick();
        CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kSubmit) == 2,
              "K10: token file mtime changed -> ready -> admitted");
    }
    {
        World w;
        w.add(simple(63));
        w.node.script.push_back({"POST /api/tx-inject/submit",
                                 FakeNode::reply(503, nj{{"armed", false}, {"error", "tx-inject submit not wired"}})});
        w.tick();
        CHECK(w.item().state == State::BlockedNode && w.item().retry.not_before == w.clock.t + 300, "K10: 503 -> blocked_node, 5 min");
        w.tick(120);
        CHECK(w.node.count("POST", route::kSubmit) == 1, "K10: no retry inside 5 min");
        w.tick(180);
        CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kSubmit) == 2, "K10: after 5 min -> resubmit");
    }
    {
        World w;
        const Art a = simple(64);
        w.add(a);
        w.node.script.push_back({"POST /api/tx-inject/submit",
                                 FakeNode::reply(504, nj{{"ok", false}, {"timed_out", true}, {"cause", "submit dispatch timed out"}})});
        w.tick();
        CHECK(w.item().state == State::SubmittedUnknown, "K10: 504 -> submitted_unknown");
        w.node.mempool.insert(a.txids[0]);
        w.node.time_added[a.txids[0]] = w.clock.t;
        w.tick();
        CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kSubmit) == 1,
              "K10: 504 then in the mempool -> admitted without a resubmit");
    }
    {
        World w;
        w.add(simple(65));
        w.node.script.push_back({"POST /api/tx-inject/submit", FakeNode::reply(504, nj{{"ok", false}, {"timed_out", true}})});
        w.tick();
        w.tick();
        w.tick();
        CHECK(w.item().state == State::SubmittedUnknown && w.node.count("POST", route::kSubmit) == 1, "K10: absent 2 polls -> still unknown");
        w.tick();
        CHECK(w.node.count("POST", route::kSubmit) == 2 && w.item().state == State::Admitted,
              "K10: absent after 3 polls -> resubmit (idempotent)");
    }
    {
        World w;
        w.add(simple(66));
        w.node.script.push_back({"POST /api/tx-inject/submit",
                                 FakeNode::reply(400, nj{{"ok", false}, {"cause", "tx parse failed: x"}})});
        w.tick();
        CHECK(w.item().state == State::Refused && !w.q.alerts.empty() && w.q.alerts.back().kind == "scheduler_bug",
              "K10: 400 -> refused + scheduler-bug alert");
    }
}

static void k11_restart_resume()
{
    World a;
    a.add(simple(70));
    a.node.script.push_back({"POST /api/tx-inject/submit", FakeNode::reply(504, nj{{"ok", false}, {"timed_out", true}})});
    const TickReport r1 = a.tick();
    a.tick();
    CHECK(a.persist_count >= r1.transitions + 1 && a.item().state == State::SubmittedUnknown &&
              a.item().retry.unknown_polls == 1,
          "K11: every transition persisted; mid 504 poll");
    const std::string saved = a.last_persisted;
    CHECK(saved == queue_to_json(a.q), "K11: the last persisted file is the in-memory queue");

    // Fork the world: B loads the saved file into a fresh Scheduler.
    World b;
    b.clock = a.clock;
    b.node = a.node;
    b.node.clock = &b.clock;
    std::string why;
    CHECK(queue_from_json(saved, b.q, why), "K11: saved queue loads");
    b.q.node.token_file = a.q.node.token_file;
    b.rebuild();
    const size_t att = b.item().attempts.size(), jr = b.item().journal.size();
    CHECK(att == a.item().attempts.size() && jr == a.item().journal.size(), "K11: attempts/journal preserved");
    a.tick();
    b.tick();
    CHECK(a.item().state == b.item().state && a.item().retry.unknown_polls == b.item().retry.unknown_polls,
          "K11: identical next transition");
    a.tick();
    b.tick();
    CHECK(queue_to_json(a.q) == queue_to_json(b.q), "K11: identical queue after the resumed ticks");

    // An admitted item re-checks the mempool first after a restart.
    World c;
    const Art art2 = simple(71);
    c.add(art2);
    c.tick();
    CHECK(c.item().state == State::Admitted, "K11: admitted");
    const std::string snap = queue_to_json(c.q);
    World d;
    d.node = c.node;
    d.node.clock = &d.clock;
    d.clock = c.clock;
    queue_from_json(snap, d.q, why);
    d.q.node.token_file = c.q.node.token_file;
    d.rebuild();
    d.node.log.clear();
    d.tick();
    size_t first_mp = 999, first_post = 999;
    for (size_t i = 0; i < d.node.log.size(); ++i) {
        if (first_mp == 999 && d.node.log[i].path == route::kRawMempool) first_mp = i;
        if (first_post == 999 && d.node.log[i].method == "POST") first_post = i;
    }
    CHECK(first_mp != 999 && first_post == 999 && d.item().state == State::IsHold,
          "K11: restarted admitted item re-checks the mempool, no resubmit");
}

static void k12_token_never_persisted_or_logged()
{
    World w;
    std::string why;
    CHECK(arm::record_consent(w.q.arm_policy, true, false, "allow the scheduler to arm (operator G, KAT)", w.clock.t, why),
          "K12: consent recorded");
    w.node.enabled = false;
    const Art a = simple(80);
    w.add(a);
    w.tick();
    CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kConfigApply) == 2, "K12: armed + submitted");
    w.tick(700);
    w.node.mine({a.txids[0]});
    w.tick();
    const std::string qjson = queue_to_json(w.q);
    const std::string path = make_file("", 0600);
    CHECK(save_queue_file(path, w.q, why), "K12: queue saved");
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    CHECK(ss.str() == qjson, "K12: saved file = codec output");
    CHECK(!leaks_secret(qjson) && !leaks_secret(ss.str()), "K12: queue file has no token / nonce substring");
    CHECK(!leaks_secret(w.sink.all()), "K12: journal sink has no token / nonce substring");
    std::string attempts;
    for (const auto& at : w.item().attempts) attempts += at.cause + at.txid_echo + at.at;
    for (const auto& e : w.item().journal) attempts += e.detail;
    CHECK(!leaks_secret(attempts), "K12: attempts + item journal clean");
    const auto subs = w.node.bodies(route::kSubmit);
    const auto apps = w.node.bodies(route::kConfigApply);
    bool once = !subs.empty() && apps.size() == 2;
    for (const auto& b : subs) once = once && count_of(b, kToken) == 1;
    for (const auto& b : apps) once = once && count_of(b, kToken) == 1;
    CHECK(once, "K12: each submit / apply body carries the token exactly once");
    CHECK(count_of(apps[0], kNonce) == 0 && count_of(apps[1], kNonce) == 1, "K12: the nonce only in the confirm body");

    CliOverrides co;
    CHECK(!parse_cli_overrides({"run", "--token", "abc"}, co, why) && why.find("--token-file") != std::string::npos,
          "K12: --token VALUE is a usage error");
    CHECK(!parse_cli_overrides({"--token=abc"}, co, why), "K12: --token=VALUE is a usage error");
    CHECK(parse_cli_overrides({"run", "--token-file", "/x/t", "--queue=/x/q.json", "--poll-sec", "15", "--once"}, co, why) &&
              co.token_file == std::string("/x/t") && co.queue == std::string("/x/q.json") && co.poll_sec == 15 &&
              co.rest == std::vector<std::string>({"run", "--once"}),
          "K12: --token-file PATH and the shared options parse");

    // TokenFile mirrors the node's loader rules.
    c2w::secure::SecureString tok;
    CHECK(TokenFile::read(w.token_path, tok, why) && tok.size() == std::strlen(kToken) &&
              std::memcmp(tok.bytes(), kToken, tok.size()) == 0,
          "K12: 0600 token file read + trimmed");
    const std::string loose = make_file(std::string(kToken) + "\n", 0644);
    CHECK(!TokenFile::read(loose, tok, why) && why.find("0600") != std::string::npos && tok.empty(), "K12: mode 0644 refused");
    const std::string shortf = make_file("short-token\n", 0600);
    CHECK(!TokenFile::read(shortf, tok, why) && why.find("32-128") != std::string::npos, "K12: short token refused");
    const std::string spaced = make_file("SCHED-KAT-TOKEN-0123456789 abcdef0123456789abcdef\n", 0600);
    CHECK(!TokenFile::read(spaced, tok, why) && why.find("interior whitespace") != std::string::npos, "K12: interior whitespace refused");
    const std::string link = w.token_path + ".lnk";
    if (::symlink(w.token_path.c_str(), link.c_str()) == 0) g_tmpfiles.push_back(link);
    CHECK(!TokenFile::read(link, tok, why) && why.find("symlink") != std::string::npos, "K12: symlink refused");
    CHECK(contains_secret(std::string("x") + kToken, tok) == false, "K12: belt sees nothing once the buffer is cleared");
}

static void k13_idempotent_resubmit()
{
    World w;
    const Art a = simple(90);
    w.add(a);
    w.tick();
    for (int i = 0; i < 20; ++i) w.tick(60);
    CHECK(w.node.count("POST", route::kSubmit) == 1 && w.item().state == State::Riding,
          "K13: admitted item never POSTs again while in the mempool");

    World k;
    const Art b = simple(91);
    k.add(b);
    k.tick();
    k.node.mempool.erase(b.txids[0]);
    k.tick();
    CHECK(k.item().state == State::Dropped, "K13: left the mempool -> dropped");
    k.node.script.push_back({"POST /api/tx-inject/submit",
                             FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-already-known"}, {"txid", b.txids[0]}})});
    k.tick();
    CHECK(k.item().state == State::Admitted && k.node.count("POST", route::kSubmit) == 2,
          "K13: resubmit answered inject-already-known -> admitted");

    World m;
    const Art c = simple(92);
    m.add(c);
    m.node.script.push_back({"POST /api/tx-inject/submit",
                             FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-already-confirmed"}, {"txid", c.txids[0]}})});
    m.tick();
    CHECK(m.item().state == State::Mined, "K13: resubmit answered inject-already-confirmed -> mined");
}

static void k14_instantsend_hold()
{
    World w;
    const Art a = simple(100);
    w.add(a);
    w.tick();
    const int64_t t = w.node.time_added[a.txids[0]];
    CHECK(w.item().state == State::Admitted, "K14: admitted");
    w.tick();
    CHECK(w.item().state == State::IsHold && w.item().node.time_added == t, "K14: in the mempool -> is_hold, time_added recorded");
    CHECK(w.item().why.find("600 s") != std::string::npos && w.item().why.find("mempool.hpp:223") != std::string::npos &&
              w.item().why.find(format_utc(t + 600)) != std::string::npos,
          "K14: why names the 600 s rule and the ride time");
    w.clock.t = t + 599 - 15;
    w.tick();
    CHECK(w.item().state == State::IsHold, "K14: t+599 still is_hold");
    w.clock.t = t + 600 - 15;
    w.tick();
    CHECK(w.item().state == State::Riding && w.item().why.find("riding (inferred)") != std::string::npos, "K14: t+600 -> riding");
    CHECK(w.node.count("GET", route::kMempoolEntry) == 1, "K14: getmempoolentry asked once");
}

static void k15_mined_detection()
{
    World w;
    const Art a = simple(110);
    EnqueueRequest r = req_for(a);
    r.expiry_blocks = 2;
    w.add(a, r);
    w.tick();
    w.tick();
    w.node.mine({a.txids[0]});
    w.node.log.clear();
    w.tick();
    CHECK(w.item().state == State::Mined && w.item().node.mined_height == w.node.tip &&
              w.item().node.mined_hash == w.node.blocks[w.node.tip].hash && w.item().node.confirmations == 1,
          "K15: getblock scan finds it -> mined, hash recorded, 1 confirmation");
    CHECK(w.node.count("GET", route::kBlockAtHeight) == 1, "K15: newest-first scan: one getblock in the common case");
    w.node.advance(2);
    w.tick();
    CHECK(w.item().state == State::Mined && w.item().node.confirmations == 3, "K15: confirmations follow the tip");
    w.node.advance(3);
    w.tick();
    CHECK(w.item().state == State::Confirmed && w.item().node.confirmations == 6, "K15: past expiry_height but mined -> confirmed, not expired");
}

static void k16_dropped_and_resubmit()
{
    World w;
    const Art a = simple(120);
    w.add(a);
    w.tick();
    for (int round = 1; round <= 3; ++round) {
        w.node.mempool.erase(a.txids[0]);
        w.tick();
        CHECK(w.item().state == State::Dropped, "K16: left the mempool, no block -> dropped");
        w.tick();
        CHECK(w.item().state == State::Admitted && w.item().retry.resubmits == round, "K16: resubmit n/3 -> admitted");
    }
    w.node.mempool.erase(a.txids[0]);
    w.tick();
    w.tick();
    w.tick();
    CHECK(w.item().state == State::Dropped && is_terminal(w.item()) && w.node.count("POST", route::kSubmit) == 4,
          "K16: at auto_resubmit_max -> terminal, no further POST");

    // K16b: down for longer than the body window; the resubmit is the oracle.
    World b;
    const Art c = simple(121);
    b.add(c);
    b.tick();
    b.node.mempool.erase(c.txids[0]);
    b.node.mine({c.txids[0]});
    b.node.advance(400);
    b.tick();
    CHECK(b.item().state == State::Dropped, "K16b: block outside the 288 window -> dropped");
    b.tick();
    CHECK(b.item().state == State::Mined, "K16b: resubmit answered inject-already-confirmed -> mined");
    b.tick();
    CHECK(b.item().state == State::Mined && b.item().node.mined_height_unknown &&
              b.item().why.find("mined (height unknown)") != std::string::npos,
          "K16b: mined (height unknown)");
    CHECK(!b.q.alerts.empty() && b.q.alerts.back().kind == "mined_unverified" &&
              b.item().node.probe_at_height == b.node.tip + 6,
          "K16b/L1: one alert (verify with dash-cli); re-probe scheduled after the display threshold");
    const size_t posts = b.node.count("POST", route::kSubmit);
    b.node.advance(5);
    b.tick();
    CHECK(b.item().state == State::Mined && b.node.count("POST", route::kSubmit) == posts, "K16b/L1: no probe before the threshold");
    b.node.advance(1);
    b.tick();
    CHECK(b.item().state == State::Confirmed && is_terminal(b.item()) && b.node.count("POST", route::kSubmit) == posts + 1 &&
              b.item().why.find("confirmed by probe") != std::string::npos,
          "K16b/L1: the probe still answers already-confirmed -> confirmed (terminal)");
    b.tick();
    CHECK(b.node.count("POST", route::kSubmit) == posts + 1, "K16b/L1: no POST after confirmed");

    // The inference was wrong: the probe is accepted -> normal tracking.
    World c2;
    const Art d = simple(122);
    c2.add(d);
    c2.node.script.push_back({"POST /api/tx-inject/submit",
                              FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-already-confirmed"}, {"txid", d.txids[0]}})});
    c2.tick();
    c2.tick();
    CHECK(c2.item().state == State::Mined && c2.item().node.mined_height_unknown, "K16b/L1: already-confirmed, no block found");
    c2.node.advance(6);
    c2.tick();
    CHECK(c2.item().state == State::Admitted && c2.node.mempool.count(d.txids[0]),
          "K16b/L1: a probe answered ok -> admitted (the tx was not mined; it is injected now)");
}

static void k17_expiry_and_renew()
{
    for (int renew = 0; renew < 2; ++renew) {
        World w;
        const Art a = simple(130 + renew);
        EnqueueRequest r = req_for(a);
        r.expiry_blocks = 5;
        r.auto_renew = renew == 1;
        w.add(a, r);
        w.tick();
        const int64_t exp = *w.item().node.expiry_height;
        CHECK(exp == w.node.tip + 5, "K17: expiry_height = tip + 5");
        w.node.mempool.erase(a.txids[0]);
        w.node.advance(6);
        w.tick();
        CHECK(w.item().state == State::Expired, "K17: tip > expiry_height, not mined -> expired");
        w.tick();
        if (!renew) {
            CHECK(is_terminal(w.item()) && w.node.count("POST", route::kSubmit) == 1, "K17: no auto_renew -> terminal");
        } else {
            CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kSubmit) == 2 &&
                      w.item().attempts.back().expiry_height == w.node.tip + 5,
                  "K17: auto_renew -> ready with a fresh expiry");
        }
    }

    // M1: the node reaps at tip >= expiry_height (reap_expired(tip + 1) drops
    // tip + 1 > expiry). Walk the boundary one block at a time.
    {
        World w;
        const Art a = simple(132);
        EnqueueRequest r = req_for(a);
        r.expiry_blocks = 4;
        w.add(a, r);
        w.tick();
        const int64_t E = *w.item().node.expiry_height;
        w.node.advance(static_cast<int>(E - 1 - w.node.tip)); // tip = E - 1: expiry at tip + 1
        CHECK(w.node.tip == E - 1 && w.node.mempool.count(a.txids[0]), "K17/M1: fake node keeps it at tip = E - 1");
        w.tick();
        CHECK(w.item().state == State::IsHold || w.item().state == State::Riding, "K17/M1: expiry at tip + 1 -> still admitted");
        w.node.mine(); // tip = E: the node reaps it
        CHECK(w.node.tip == E && !w.node.mempool.count(a.txids[0]), "K17/M1: fake node reaps at tip = E like the node");
        w.tick();
        CHECK(w.item().state == State::Expired && w.item().why.find(">= expiry_height") != std::string::npos,
              "K17/M1: expiry at tip -> expired (not dropped)");
        for (int i = 0; i < 4; ++i) w.tick(60);
        CHECK(w.item().state == State::Expired && is_terminal(w.item()) && w.node.count("POST", route::kSubmit) == 1 &&
                  w.item().retry.resubmits == 0,
              "K17/M1: auto_renew=false never resubmits");
    }
    {
        World w; // expiry at tip - 1: two blocks between ticks
        const Art a = simple(133);
        EnqueueRequest r = req_for(a);
        r.expiry_blocks = 3;
        w.add(a, r);
        w.tick();
        const int64_t E = *w.item().node.expiry_height;
        w.node.advance(static_cast<int>(E + 1 - w.node.tip));
        w.tick();
        CHECK(w.node.tip == E + 1 && w.item().state == State::Expired, "K17/M1: expiry at tip - 1 -> expired");
    }
    {
        World w; // mined in the block at height E itself (template built at tip E - 1)
        const Art a = simple(134);
        EnqueueRequest r = req_for(a);
        r.expiry_blocks = 3;
        w.add(a, r);
        w.tick();
        const int64_t E = *w.item().node.expiry_height;
        w.node.advance(static_cast<int>(E - 1 - w.node.tip));
        w.node.mine({a.txids[0]});
        w.tick();
        CHECK(w.node.tip == E && w.item().state == State::Mined && w.item().node.mined_height == E,
              "K17/M1: mined in block E -> mined, not expired");
    }
}

static void k18_loopback_only_node_url()
{
    std::string why;
    const char* bad[] = {"http://10.0.0.5:8080", "http://node.example:8080", "https://127.0.0.1:8080",
                         "http://127.0.0.1:8080/api", "http://user@127.0.0.1:8080", "http://127.0.0.2:8080",
                         "http://[::2]:8080", "http://127.0.0.1:0", "http://127.0.0.1:99999", "ftp://127.0.0.1"};
    int refused = 0;
    for (const char* u : bad) refused += validate_node_url(u, why) ? 0 : 1;
    CHECK(refused == static_cast<int>(sizeof(bad) / sizeof(bad[0])), "K18: remote / TLS / path / bad port URLs refused");
    CHECK(validate_node_url("http://127.0.0.1:18080", why) && validate_node_url("http://[::1]:8080", why) &&
              validate_node_url("http://localhost:8080", why) && validate_node_url("http://127.0.0.1", why),
          "K18: loopback URLs accepted");
    Queue q;
    q.node.url = "http://10.0.0.5:8080";
    Queue back;
    CHECK(!queue_from_json(queue_to_json(q), back, why) && why.find("127.0.0.1") != std::string::npos,
          "K18: a queue file with a remote node.url is refused at load");
    CliOverrides co;
    CHECK(!parse_cli_overrides({"--node-url", "http://192.168.1.5:8080"}, co, why), "K18: --node-url remote refused");
}

static void k19_queue_round_trip()
{
    World w;
    w.add(simple(140));
    const Art b = simple(141);
    EnqueueRequest r = req_for(b);
    r.not_before_time = "2026-12-01T00:00:00Z";
    r.after_parent = {{std::string(64, 'd'), 2}};
    w.add(b, r);
    w.node.script.push_back({"POST /api/tx-inject/submit", FakeNode::reply(504, nj{{"ok", false}, {"timed_out", true}})});
    w.tick();
    w.tick();
    const std::string t1 = queue_to_json(w.q);
    CHECK(t1.rfind("{\n  \"schema\": \"c2wallet-inject-queue/1\",\n  \"coin\": \"dash\"", 0) == 0,
          "K19: fixed key order, 2-space indent");
    Queue q2;
    std::string why;
    CHECK(queue_from_json(t1, q2, why) && queue_to_json(q2) == t1, "K19: load -> save byte-identical");
    const std::string path = make_file("", 0600);
    Queue q3;
    CHECK(save_queue_file(path, w.q, why) && load_queue_file(path, q3, why) && queue_to_json(q3) == t1,
          "K19: file save/load byte-identical");

    std::string other = t1;
    other.replace(other.find("c2wallet-inject-queue/1"), 23, "c2wallet-inject-queue/9");
    CHECK(!queue_from_json(other, q2, why) && why.find("unknown schema") != std::string::npos, "K19: unknown schema refused");

    Queue c;
    c.arm_policy.auto_arm = true;
    CHECK(!queue_from_json(queue_to_json(c), q2, why) && why.find("consented_at") != std::string::npos,
          "K19/K22: auto_arm:true without consented_at refused");
    Queue d = w.q;
    d.items[0].submit.allow_auto_arm = true;
    CHECK(!queue_from_json(queue_to_json(d), q2, why), "K19/K22: per-item allow_auto_arm:true without consent refused");
    c.arm_policy.consented_at = "2026-11-02T00:12:00Z";
    c.arm_policy.consent_text = "operator consent";
    CHECK(queue_from_json(queue_to_json(c), q2, why) && q2.arm_policy.auto_arm, "K19/K22: with consented_at accepted");
    CHECK(!queue_from_json("{\"schema\":\"c2wallet-inject-queue/1\",\"items\":[{\"id\":\"x\"}]}", q2, why),
          "K19: malformed item refused");
    std::string deep(200, '[');
    CHECK(!queue_from_json(deep, q2, why) && why.find("nesting") != std::string::npos, "K19: nesting bomb refused");
    Queue e = w.q;
    e.items[1].id = e.items[0].id;
    CHECK(!queue_from_json(queue_to_json(e), q2, why) && why.find("duplicate id") != std::string::npos, "K19: duplicate id refused");
}

static void k20_parent_auto_discovery()
{
    World w;
    const std::string ptx_hex = make_tx(150);
    const Art pa = build({ptx_hex}, {{fin(0, 2565145)}});
    w.add(pa);
    const std::string ptx = pa.txids[0];
    MIn from_parent;
    from_parent.txid = ptx;
    from_parent.vout = 0;
    from_parent.height = std::nullopt; // the parent is not mined yet
    from_parent.coinbase = false;
    const Art ca = build({make_tx(151)}, {{from_parent}});
    EnqueueRequest r = req_for(ca);
    r.not_before_height = 1; // the input height is unknown until the parent lands
    const EnqueueResult er = enqueue(w.q, r, w.clock.t);
    CHECK(er.ok && w.item(1).triggers.after_parent.size() == 1 && w.item(1).triggers.after_parent[0].txid == ptx &&
              w.item(1).triggers.after_parent[0].min_confirmations == 1 && !er.notes.empty(),
          "K20: input txid of a queued item pre-fills after_parent (N=1 default)");
    CHECK(w.q.tracked.empty(), "K20: a queued parent shares its record (no foreign tracking)");

    w.item(0).state = State::Refused;
    const Art cb = build({make_tx(152)}, {{from_parent}});
    EnqueueRequest r2 = req_for(cb);
    r2.not_before_height = 1;
    EnqueueResult er2 = enqueue(w.q, r2, w.clock.t);
    CHECK(!er2.ok && er2.why.find("not going to be mined") != std::string::npos && w.q.items.size() == 2,
          "K20: parent refused -> child enqueue refused");
    std::string why;
    CHECK(requeue_item(w.q, w.item(0).id, w.clock.t, why) && w.item(0).state == State::Waiting, "K20: parent re-queued");
    er2 = enqueue(w.q, r2, w.clock.t);
    CHECK(er2.ok && w.q.items.size() == 3, "K20: child accepted after the parent is re-queued");
}

static void k21_preflight_caps()
{
    std::string why;
    CHECK(preflight_raw_tx(make_tx(160), txid_of(make_tx(160)), why), "K21: a valid signed tx passes");
    CHECK(!preflight_raw_tx(make_tx(161, 2, 1, 50001), "", why) && why.find("100000") != std::string::npos, "K21: size > 100000 refused");
    CHECK(!preflight_raw_tx(make_tx(162, 1001, 1, 2), "", why) && why.find("vin 1001") != std::string::npos, "K21: vin > 1000 refused");
    CHECK(!preflight_raw_tx(make_tx(163, 1, 1001), "", why) && why.find("vout 1001") != std::string::npos, "K21: vout > 1000 refused");
    CHECK(!preflight_raw_tx(make_tx(164, 1, 1, 0), "", why) && why.find("not a signed tx") != std::string::npos,
          "K21: empty scriptSig (unsigned) refused");
    CHECK(!preflight_raw_tx("43325755" + make_tx(165), "", why), "K21: C2WU container magic refused");
    CHECK(!preflight_raw_tx(make_tx(166), std::string(64, '0'), why) && why.find("txid mismatch") != std::string::npos,
          "K21: recomputed txid must equal the stored one");

    World w;
    const Art u = build({make_tx(167, 1, 1, 0)}, {{fin(0, 2565145)}});
    CHECK(!enqueue(w.q, req_for(u), w.clock.t).ok && w.q.items.empty(), "K21: unsigned tx refused at enqueue");

    // A tampered queue item never reaches the node.
    w.add(simple(168));
    const std::string bad = make_tx(169, 1, 1, 0);
    w.item().tx.raw_tx = bad;
    w.item().tx.txid = txid_of(bad);
    w.tick();
    CHECK(w.item().state == State::Refused && w.item().why.find("no POST") != std::string::npos &&
              w.node.count("POST", route::kSubmit) == 0,
          "K21: unsigned raw_tx in the queue -> refused locally, no POST");
}

static void k23_auto_arm_two_phase()
{
    World w;
    std::string why;
    arm::record_consent(w.q.arm_policy, true, false, "allow the scheduler to arm the node for this queue (KAT)", w.clock.t, why);
    w.node.enabled = false;
    w.add(simple(170));
    w.tick();
    const auto apps = w.node.bodies(route::kConfigApply);
    CHECK(apps.size() == 2, "K23: two POSTs to /api/config/apply");
    if (apps.size() == 2) {
        const std::string& b1 = apps[0];
        const std::string& b2 = apps[1];
        CHECK(b1.find("money_nonce") == std::string::npos && b1.find("\"embedded.tx_inject\":\"true\"") != std::string::npos,
              "K23: phase 1 = the diff, no nonce");
        CHECK(b2.substr(0, b1.size() - 1) == b1.substr(0, b1.size() - 1) &&
                  b2.substr(b1.size() - 1) == std::string(",\"money_nonce\":\"") + kNonce + "\"}",
              "K23: phase 2 = the same diff + money_nonce, nothing else differs");
    }
    size_t last_apply = 0, first_submit = 0;
    for (size_t i = 0; i < w.node.log.size(); ++i) {
        if (w.node.log[i].path == route::kConfigApply) last_apply = i;
        if (w.node.log[i].path == route::kSubmit && !first_submit) first_submit = i;
    }
    CHECK(w.node.enabled && first_submit > last_apply && w.item().state == State::Admitted,
          "K23: status enabled:true -> submit in the same tick -> admitted");
    bool armed_line = false;
    for (const auto& e : w.item().journal)
        if (e.detail.find("ARMED by scheduler (consent " + *w.q.arm_policy.consented_at) != std::string::npos) armed_line = true;
    CHECK(armed_line && w.q.arm_policy.armed_by_scheduler_at.has_value(), "K23: journal ARMED by scheduler (consent ...)");
}

static void k24_auto_arm_failures()
{
    auto consented = [](World& w) {
        std::string why;
        arm::record_consent(w.q.arm_policy, true, false, "allow auto-arm (KAT)", w.clock.t, why);
        w.node.enabled = false;
    };
    {
        World w;
        consented(w);
        w.node.control_plane = false;
        w.add(simple(180));
        w.tick();
        CHECK(w.item().state == State::BlockedNode && w.node.count("POST", route::kConfigApply) == 1 &&
                  w.item().why.find("--control-plane-token-file") != std::string::npos,
              "K24: 503 not_armed -> blocked_node");
    }
    {
        World w;
        consented(w);
        w.node.token = "SCHED-KAT-OTHER-TOKEN-00000000000000000000000000";
        w.add(simple(181));
        w.tick();
        CHECK(w.item().state == State::BlockedToken && w.node.count("POST", route::kConfigApply) == 1, "K24: 403 -> blocked_token");
    }
    {
        World w;
        consented(w);
        w.add(simple(182));
        w.node.script.push_back({"POST /api/config/apply",
                                 FakeNode::reply(200, nj{{"status", "need_confirm"}, {"money_nonce", kNonce},
                                                         {"money_keys", nj::array({"embedded.tx_inject"})}})});
        w.node.script.push_back({"POST /api/config/apply",
                                 FakeNode::reply(409, nj{{"status", "money_gate"}, {"error", "nonce mismatch"}})});
        w.tick();
        CHECK(w.q.arm_policy.suspended_reason.has_value() && !w.q.alerts.empty() &&
                  w.q.alerts.back().kind == "money_gate" && w.item().state == State::BlockedNotArmed,
              "K24: 409 money_gate -> auto-arm suspended + alert");
        for (int i = 0; i < 5; ++i) w.tick(900);
        CHECK(w.node.count("POST", route::kConfigApply) == 2 && w.node.count("POST", route::kSubmit) == 0,
              "K24: no further apply POSTs after money_gate");
        CHECK(!leaks_secret(queue_to_json(w.q)), "K24: nonce never persisted");
    }
    {
        World w;
        consented(w);
        w.add(simple(183));
        w.node.script.push_back(
            {"POST /api/config/apply",
             FakeNode::reply(200, nj{{"status", "need_confirm"}, {"money_nonce", kNonce},
                                     {"money_keys", nj::array({"embedded.tx_inject", "payout.address"})}})});
        w.tick();
        CHECK(w.node.count("POST", route::kConfigApply) == 1 && w.item().state == State::BlockedNode &&
                  w.q.alerts.back().kind == "arm_protocol",
              "K24: money_keys != [embedded.tx_inject] -> abort, no confirm POST");
    }
    {
        World w;
        consented(w);
        w.add(simple(184));
        w.node.script.push_back({"POST /api/config/apply", HttpReply{false, 0, "", "connection refused"}});
        w.tick();
        w.tick(60);
        CHECK(w.node.count("POST", route::kConfigApply) == 1 && w.item().state == State::BlockedNotArmed,
              "K24: at most one arm attempt per 10 minutes");
        w.tick(600);
        CHECK(w.node.count("POST", route::kConfigApply) == 3 && w.item().state == State::Admitted, "K24: retried after 10 minutes");
    }
}

static void k25_auto_disarm_when_idle()
{
    for (int on = 0; on < 2; ++on) {
        World w;
        std::string why;
        arm::record_consent(w.q.arm_policy, true, on == 1, "allow auto-arm and auto-disarm (KAT)", w.clock.t, why);
        w.node.enabled = false;
        const Art a = simple(190 + on);
        w.add(a);
        w.tick();
        CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kConfigApply) == 2, "K25: armed + admitted");
        w.tick(700);
        w.tick();
        CHECK(w.item().state == State::Riding && w.node.count("POST", route::kConfigApply) == 2, "K25: item riding -> no disarm");
        w.node.mine({a.txids[0]});
        w.tick();
        w.tick();
        w.tick();
        if (on) {
            const auto apps = w.node.bodies(route::kConfigApply);
            CHECK(apps.size() == 4 && apps[2].find("\"embedded.tx_inject\":\"false\"") != std::string::npos &&
                      !w.node.enabled && !w.q.arm_policy.armed_by_scheduler_at,
                  "K25: all items mined -> two-phase \"false\" applied once");
            bool alert = false;
            for (const auto& al : w.q.alerts) alert = alert || al.kind == "disarmed";
            CHECK(!alert, "K25: our own disarm raises no disarm alert");
        } else {
            CHECK(w.node.count("POST", route::kConfigApply) == 2 && w.node.enabled, "K25: option off -> never disarms");
        }
    }
}

static void k26_disarm_detection_alert()
{
    for (int consent = 0; consent < 2; ++consent) {
        World w;
        std::string why;
        if (consent) arm::record_consent(w.q.arm_policy, true, false, "allow auto-arm (KAT)", w.clock.t, why);
        const Art a = simple(200 + consent);
        w.add(a);
        w.tick();
        w.tick();
        CHECK(w.item().state == State::IsHold, "K26: in the mempool");
        // Node restart: arm lost, mempool empty.
        w.node.enabled = false;
        w.node.wired = false;
        w.node.mempool.clear();
        w.tick();
        w.tick();
        w.tick(700);
        w.tick();
        int disarmed = 0;
        for (const auto& al : w.q.alerts) disarmed += al.kind == "disarmed" ? 1 : 0;
        CHECK(disarmed == 1, "K26: enabled true -> false raises the alert once");
        if (!consent) {
            CHECK(w.item().state == State::BlockedNotArmed && w.node.count("POST", route::kConfigApply) == 0,
                  "K26: admitted item re-checked -> dropped -> blocked_not_armed; no arm without consent");
        } else {
            CHECK(w.node.count("POST", route::kConfigApply) == 2 && w.node.count("POST", route::kSubmit) == 2 &&
                      (w.item().state == State::Admitted || w.item().state == State::IsHold ||
                       w.item().state == State::Riding),
                  "K26: with consent the scheduler re-arms and resubmits");
        }
    }
}

static void k27_tip_unknown_waits()
{
    World w;
    w.node.synced = false;
    w.node.blocked_by = "headers-behind-by-12";
    w.add(simple(210));
    w.tick();
    CHECK(w.item().state == State::Waiting && w.item().why.find("sync_blocked_by=headers-behind-by-12") != std::string::npos &&
              w.node.count("POST", route::kSubmit) == 0,
          "K27: not synced -> height triggers wait, why names sync_blocked_by, no submit");

    World t;
    t.node.synced = false;
    const Art a = simple(211);
    EnqueueRequest r;
    r.hex_text = a.hex_text;
    r.inputs_known_mature_consent = "inputs known mature (KAT)";
    r.not_before_time = "2026-11-02T00:00:00Z";
    t.add(a, r);
    t.tick();
    CHECK(t.item().state == State::Ready && t.item().why.find("cannot compute expiry_height") != std::string::npos &&
              t.node.count("POST", route::kSubmit) == 0,
          "K27: time-only trigger with the tip unknown -> ready but no submit (no expiry)");
    t.node.synced = true;
    t.tick();
    CHECK(t.item().state == State::Admitted, "K27: synced again -> submitted");
}

static void misc_operator_edits_and_status()
{
    World w;
    w.add(simple(220));
    std::string why;
    const std::string id = w.item().id;
    CHECK(w.item().id.rfind("q-20261102-", 0) == 0, "edits: id q-YYYYMMDD-NNN");
    CHECK(pause_item(w.q, id, w.clock.t, why) && w.item().state == State::Paused, "edits: pause");
    w.tick();
    CHECK(w.node.count("POST", route::kSubmit) == 0 && w.item().state == State::Paused, "edits: paused item frozen");
    CHECK(!remove_item(w.q, "nope", why), "edits: remove unknown id refused");
    CHECK(resume_item(w.q, id, w.clock.t, why) && w.item().state == State::Waiting, "edits: resume -> waiting");
    w.tick();
    CHECK(w.item().state == State::Admitted, "edits: resumed item submits");
    CHECK(!remove_item(w.q, id, why), "edits: a live item cannot be removed without pausing");

    // Pool full -> waits one tick, no POST burned; local rate budget -> waits the window.
    World p;
    p.add(simple(221));
    p.node.pool_entries = 1024;
    p.tick();
    CHECK(p.item().state == State::Ready && p.node.count("POST", route::kSubmit) == 0 &&
              p.item().why.find("pool full") != std::string::npos,
          "status: pool full -> no POST");
    p.node.pool_entries = 0;
    p.node.rl_in_window = 200;
    p.tick();
    CHECK(p.node.count("POST", route::kSubmit) == 0 && p.item().retry.not_before == p.clock.t + 60, "status: rate budget -> wait window");
    p.node.rl_in_window = 0;
    p.tick(60);
    CHECK(p.item().state == State::Admitted, "status: budget back -> submitted");

    // Exposure text exists for the consent dialog (S5).
    CHECK(std::string(arm::exposure_text()).find("reward path") != std::string::npos, "arm: exposure text");
    // A relay-fee manifest pre-fills max_fee with the tx fee.
    ManifestOpts ro;
    ro.fee_mode = "relay";
    ro.fee = 2711;
    World f;
    f.add(build({make_tx(222)}, {{fin(0, 2565145)}}, ro));
    CHECK(f.item().submit.max_fee == 2711, "enqueue: relay fee -> max_fee prefilled");
    f.tick();
    CHECK(f.node.bodies(route::kSubmit).back().find("\"max_fee\":2711") != std::string::npos, "submit: max_fee in the body");
}


// ── VERIFY-S1 follow-ups ─────────────────────────────────────────────────────

// M2: a foreign parent (not a queue item) found by the body scan, through the
// mempool short-cut, and across a reorg of its block.
static void k6b_foreign_parent_tracking()
{
    SchedulerOptions so;
    so.reorg_check_every = 1;
    const std::string F = txid_of(make_tx(300));
    {
        // Mined before the child was queued, inside the body window.
        World w(so);
        w.node.blocks[w.node.tip - 10] = FakeBlock{w.node.synth_hash(w.node.tip - 10, 3), {F}, true};
        const Art c = simple(301);
        EnqueueRequest r = req_for(c);
        r.after_parent = {{F, 1}};
        w.add(c, r);
        CHECK(w.q.tracked.size() == 1 && !w.q.tracked[0].window_scanned, "K6b: foreign parent tracked at enqueue");
        w.tick();
        CHECK(w.q.tracked[0].mined_height == w.node.tip - 10 && w.q.tracked[0].window_scanned &&
                  w.q.tracked[0].first_requested_height == w.node.tip,
              "K6b: first tick scans the body window and finds the parent");
        CHECK(w.item().state == State::Admitted, "K6b: parent mined (11 confs >= 1) -> child submitted");
    }
    {
        // In the mempool first, then mined, then reorged out and mined again.
        World w(so);
        w.node.mempool.insert(F);
        const Art c = simple(302);
        EnqueueRequest r = req_for(c);
        r.after_parent = {{F, 2}};
        w.add(c, r);
        w.tick();
        CHECK(!w.q.tracked[0].mined_height && w.q.tracked[0].scan_from_height == w.node.tip + 1 &&
                  w.node.count("GET", route::kBlockAtHeight) == 0,
              "K6b: parent in the mempool -> no scan, scan_from = tip + 1");
        CHECK(w.item().state == State::Waiting && w.item().why.find("foreign parent") != std::string::npos,
              "K6b: child waits on the foreign parent");
        w.node.mine({F});
        const int64_t H = w.node.tip;
        w.node.log.clear();
        w.tick();
        CHECK(w.q.tracked[0].mined_height == H && w.node.count("GET", route::kBlockAtHeight) == 1,
              "K6b: parent leaves the mempool -> one getblock finds it at H");
        CHECK(w.item().state == State::Waiting && w.item().why.find("1/2 confirmations") != std::string::npos,
              "K6b: child needs 2 confirmations");
        w.node.reorg(H);
        w.tick();
        CHECK(!w.q.tracked[0].mined_height && w.q.tracked[0].scan_from_height == H && w.item().state == State::Waiting,
              "K6b: reorg of H -> foreign parent reset, rescan from H, child waiting");
        w.node.blocks[H + 1] = FakeBlock{w.node.synth_hash(H + 1, 5), {F}, true};
        w.node.tip = H + 1;
        w.tick();
        CHECK(w.q.tracked[0].mined_height == H + 1, "K6b: re-mined at H + 1 -> found again");
        w.node.mine();
        w.tick();
        CHECK(w.item().state == State::Admitted, "K6b: 2 confirmations -> child submitted");
        const size_t gets = w.node.count("GET", route::kBlockAtHeight);
        w.item().state = State::Refused; // no live child: the record is no longer scanned
        w.q.tracked[0].mined_height.reset();
        w.node.mine();
        w.tick();
        CHECK(w.node.count("GET", route::kBlockAtHeight) == gets, "K6b: no live child -> no scan");
    }
}

// M2: a crash after the persisted "submitting" transition, before the reply.
static void k11b_resume_from_submitting()
{
    for (int reached = 0; reached < 2; ++reached) {
        World a;
        std::vector<std::string> snaps;
        a.s->set_persist([&](const Queue& qq, std::string&) {
            snaps.push_back(queue_to_json(qq));
            return true;
        });
        const Art art = simple(310 + reached);
        a.add(art);
        a.tick();
        std::string on_disk;
        for (const auto& sn : snaps)
            if (sn.find("\"state\": \"submitting\"") != std::string::npos) on_disk = sn;
        CHECK(!on_disk.empty(), "K11b: the submitting state is on disk before the POST");
        World b;
        std::string why;
        CHECK(queue_from_json(on_disk, b.q, why) && b.item().state == State::Submitting, "K11b: loads as submitting");
        b.q.node.token_file = a.q.node.token_file;
        b.rebuild();
        if (reached) {
            b.node.mempool.insert(art.txids[0]);
            b.node.time_added[art.txids[0]] = b.clock.t;
        }
        b.tick();
        if (reached) {
            CHECK(b.item().state == State::Admitted && b.node.count("POST", route::kSubmit) == 0,
                  "K11b: POST had landed -> submitted_unknown -> admitted, no resubmit");
        } else {
            CHECK(b.item().state == State::SubmittedUnknown && b.item().retry.unknown_polls == 1 &&
                      b.node.count("POST", route::kSubmit) == 0,
                  "K11b: POST lost -> submitted_unknown, polling");
            b.tick();
            b.tick();
            CHECK(b.item().state == State::Admitted && b.node.count("POST", route::kSubmit) == 1,
                  "K11b: absent after 3 polls -> one resubmit");
        }
    }
}

// M2: mined -> admitted when a reorg drops the block and the node re-admits.
static void k15b_reorg_readmitted()
{
    SchedulerOptions so;
    so.reorg_check_every = 1;
    World w(so);
    const Art a = simple(320);
    w.add(a);
    w.tick();
    w.node.mine({a.txids[0]});
    const int64_t H = w.node.tip;
    w.tick();
    CHECK(w.item().state == State::Mined && w.item().node.mined_height == H, "K15b: mined at H");
    w.node.reorg(H);
    w.node.mempool.insert(a.txids[0]); // the node re-admitted the inject after the rewind
    w.tick();
    CHECK(w.item().state == State::Admitted && !w.item().node.mined_height &&
              w.item().why.find("re-admitted") != std::string::npos && w.node.count("POST", route::kSubmit) == 1,
          "K15b: block hash at H changed + tx back in the mempool -> admitted, no resubmit");
    w.tick();
    CHECK(w.item().state == State::IsHold || w.item().state == State::Riding, "K15b: tracked again from the mempool");
}

// M2: detect_disarm moves ready items to blocked_not_armed.
static void k26b_disarm_moves_ready()
{
    World w;
    w.add(simple(330));
    w.node.script.push_back({"POST /api/tx-inject/submit", HttpReply{false, 0, "", "connection reset"}});
    w.tick();
    CHECK(w.item().state == State::Ready && w.item().retry.not_before == w.clock.t + 30 && w.q.runner.last_enabled == true,
          "K26b: ready inside a back-off, node armed");
    w.node.enabled = false;
    w.tick(5);
    bool moved = false;
    for (const auto& e : w.item().journal)
        if (e.event == "state" && e.detail.rfind("ready -> blocked_not_armed: blocked: node disarmed", 0) == 0) moved = true;
    CHECK(moved && w.item().state == State::BlockedNotArmed && w.node.count("POST", route::kSubmit) == 1,
          "K26b: enabled true -> false moves the ready item to blocked_not_armed");
    int disarmed = 0;
    for (const auto& al : w.q.alerts) disarmed += al.kind == "disarmed";
    CHECK(disarmed == 1, "K26b: one disarm alert");
}

// M2: a 422 inject-rate-limited-* through the scheduler.
static void k9b_rate_limited_through_scheduler()
{
    World w;
    w.add(simple(340));
    w.node.script.push_back({"POST /api/tx-inject/submit",
                             FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-rate-limited-count"}})});
    w.tick();
    CHECK(w.item().state == State::Ready && w.item().retry.cls == RetryClass::RateWindow &&
              w.item().retry.not_before == w.clock.t + 75,
          "K9b: 422 rate-limited -> ready, retry after window_sec + 15");
    w.tick(60);
    CHECK(w.node.count("POST", route::kSubmit) == 1, "K9b: no POST inside the window");
    w.tick(15);
    CHECK(w.item().state == State::Admitted && w.node.count("POST", route::kSubmit) == 2, "K9b: after the window -> admitted");
}

// L3: fee-above-max is the operator's ceiling, not a signer error.
static void k9c_fee_above_max()
{
    const Outcome o = classify_cause("inject-fee-above-max", 422);
    CHECK(o.next == State::Refused && o.why.find("submit.max_fee") != std::string::npos &&
              o.why.find("No re-sign") != std::string::npos && o.why.find("signer must rebuild") == std::string::npos,
          "K9c/L3: fee-above-max names max_fee, does not blame the signer");
    World w;
    w.add(simple(350));
    w.node.script.push_back({"POST /api/tx-inject/submit",
                             FakeNode::reply(422, nj{{"ok", false}, {"cause", "inject-fee-above-max"}})});
    w.tick();
    std::string why;
    CHECK(w.item().state == State::Refused, "K9c/L3: refused");
    CHECK(set_submit_max_fee(w.q, w.item().id, 2711, w.clock.t, why) && requeue_item(w.q, w.item().id, w.clock.t, why),
          "K9c/L3: raise max_fee + re-queue (no re-sign)");
    w.tick();
    CHECK(w.item().state == State::Admitted && w.node.bodies(route::kSubmit).back().find("\"max_fee\":2711") != std::string::npos,
          "K9c/L3: resubmitted with the new ceiling");
    CHECK(!set_submit_max_fee(w.q, w.item().id, 1, w.clock.t, why), "K9c/L3: max_fee is not edited in flight");
}

// L4: a node without the explorer raises one visible alert.
static void k27b_explorer_disabled_alert()
{
    World w;
    w.node.explorer = false;
    w.add(simple(360));
    w.tick();
    w.tick();
    w.tick();
    int n = 0;
    for (const auto& al : w.q.alerts) n += al.kind == "explorer_disabled";
    CHECK(n == 1 && w.q.runner.explorer_off && w.item().state == State::Waiting &&
              w.item().why.find("--no-explorer") != std::string::npos && w.node.count("POST", route::kSubmit) == 0,
          "K27b/L4: --no-explorer -> one alert, items wait with the flag named, no submit");
    w.node.explorer = true;
    w.tick();
    CHECK(!w.q.runner.explorer_off && w.item().state == State::Admitted, "K27b/L4: explorer back -> cleared, submitted");
}

// L6: the cause table against the node vocabulary, string for string.
static void k9d_node_vocabulary()
{
    size_t n = 0;
    const char* const* names = node_cause_names(n);
    // Master c7a3bd0cd, copied from the node sources (see SubmitOutcome.hpp).
    const char* master[] = {
        "ok", "inject-disabled", "inject-type-unsupported", "inject-oversize", "inject-script-check-unarmed",
        "inject-already-known", "inject-already-confirmed", "inject-unpriceable", "inject-bip68-unsupported",
        "inject-bad-txns-vout-range", "inject-bad-txns-version-or-type", "inject-fee-above-max",
        "inject-script-invalid", "inject-spent-shaped-output", "inject-unknown", "inject-pool-duplicate",
        "inject-pool-full", "inject-pool-total-bytes-exceeded", "inject-pool-oversize", "inject-pool-unknown",
        "inject-rate-limited-count", "inject-rate-limited-bytes", "inject-rate-limited-unknown",
        "inject-rate-limited-peers-count", "inject-rate-limited-peers-bytes", "inject-rate-limited-peers-unknown",
        "inject-sandbox-too-many-inputs", "inject-sandbox-too-many-outputs", "inject-sandbox-scriptsig-too-large",
        "inject-sandbox-total-scriptsig-too-large", "inject-sandbox-too-many-sigops", "inject-sandbox-unknown",
    };
    std::set<std::string> ours(names, names + n), want(std::begin(master), std::end(master));
    CHECK(ours == want, "K9d/L6: scheduler vocabulary == master node vocabulary (32 names)");
    int recognized = 0;
    for (size_t i = 0; i < n; ++i) recognized += classify_cause(names[i], 422).recognized ? 1 : 0;
    CHECK(recognized == static_cast<int>(n) && !classify_cause("inject-some-future-cause", 422).recognized,
          "K9d/L6: every node name is recognized; a future name is not");

    // Drift tripwire: every "inject-*" string in this tree's node headers must
    // be in the vocabulary (after a merge with master these are master's).
    int files = 0, found = 0, missing = 0;
#ifdef C2POOL_NODE_COIN_DIR
    for (const char* f : {"node_coin_state.hpp", "mempool.hpp", "tx_inject_pool.hpp", "inject_rate_limiter.hpp",
                          "inject_sandbox.hpp"}) {
        std::ifstream in(std::string(C2POOL_NODE_COIN_DIR) + "/" + f);
        if (!in) continue;
        ++files;
        std::stringstream ss;
        ss << in.rdbuf();
        const std::string text = ss.str();
        for (size_t p = text.find("\"inject-"); p != std::string::npos; p = text.find("\"inject-", p + 1)) {
            const size_t e = text.find('"', p + 1);
            if (e == std::string::npos) break;
            const std::string name = text.substr(p + 1, e - p - 1);
            if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") != std::string::npos) continue;
            ++found;
            if (!ours.count(name)) {
                ++missing;
                std::printf("  node cause not in the scheduler vocabulary: %s (%s)\n", name.c_str(), f);
            }
        }
    }
#endif
    std::printf("  K9d: %d node headers scanned, %d cause strings, %d missing\n", files, found, missing);
    CHECK(missing == 0, "K9d/L6: no node cause string outside the scheduler vocabulary");
}

// ── parent finality (operator requirement 2026-11-02) ───────────────────────

// A parent + child pair: the child's after_parent names the parent with N.
struct Pair {
    std::string ptx, ctx;
};
static Pair add_pair(World& w, uint32_t seed, int64_t n = 1, bool allow_unconfirmed = false)
{
    const Art pa = simple(seed);
    w.add(pa);
    const Art ca = simple(seed + 1);
    EnqueueRequest cr = req_for(ca);
    cr.after_parent = {{pa.txids[0], n}};
    cr.allow_unconfirmed_parent = allow_unconfirmed;
    w.add(ca, cr);
    return {pa.txids[0], ca.txids[0]};
}

// Submit POSTs that carried the child's raw tx.
static size_t child_posts(const World& w, const std::string& ctx)
{
    const Item* c = find_item_by_txid(w.q, ctx);
    size_t n = 0;
    if (!c) return n;
    for (const auto& b : w.node.bodies(route::kSubmit))
        if (b.find(c->tx.raw_tx) != std::string::npos) ++n;
    return n;
}

// K28a: no bestchainlock on the node -> N is raised to 2 with a named reason.
static void k28a_chainlock_absent_fallback()
{
    World w;
    const Pair p = add_pair(w, 400);
    w.tick();
    w.node.mine({p.ptx});
    const int64_t H = w.node.tip;
    w.tick();
    CHECK(w.item(0).state == State::Mined && w.item(0).node.mined_height == H, "K28a: parent mined at H");
    CHECK(w.item(1).state == State::Waiting &&
              w.item(1).why.find("ChainLock not exposed by node; waiting for 2 confirmations") != std::string::npos &&
              w.item(1).why.find("1/2 confirmations") != std::string::npos,
          "K28a: N=1 but no ChainLock oracle -> waits for 2 confirmations, reason named");
    CHECK(child_posts(w, p.ctx) == 0, "K28a: no child POST at 1 confirmation");
    w.node.mine();
    w.tick();
    CHECK(w.item(1).state == State::Admitted && child_posts(w, p.ctx) == 1, "K28a: 2 confirmations -> child submitted");

    // An explicit N above the fallback still applies.
    World x;
    const Pair q = add_pair(x, 402, 3);
    x.tick();
    x.node.mine({q.ptx});
    x.node.mine();
    x.tick();
    CHECK(x.item(1).state == State::Waiting && x.item(1).why.find("2/3 confirmations") != std::string::npos,
          "K28a: N=3 > fallback -> 2/3 waits");
    x.node.mine();
    x.tick();
    CHECK(x.item(1).state == State::Admitted, "K28a: N=3 reached -> child submitted");

    // Pure evaluation: the fallback depends only on the node not exposing the field.
    const Item& it = x.item(1);
    auto mined_at = [&](int64_t h) {
        return [h](const std::string&) {
            ParentStatus ps;
            ps.known = true;
            ps.mined = true;
            ps.mined_height = h;
            ps.mined_hash = std::string(64, 'a');
            ps.block_still_at_height = true;
            return ps;
        };
    };
    Item one = it;
    one.triggers.after_parent[0].min_confirmations = 1;
    one.triggers.maturity.enabled = false;
    one.triggers.not_before_height = 1;
    ChainSnapshot c = tipat(2565400);
    CHECK(!evaluate(one, c, 0, mined_at(2565400)).ready, "K28a: pure: 1 conf, no CL field -> waits");
    CHECK(evaluate(one, c, 0, mined_at(2565399)).ready, "K28a: pure: 2 confs, no CL field -> final");
    c.chainlock_exposed = true;
    c.chainlock_height = 2565400;
    CHECK(evaluate(one, c, 0, mined_at(2565400)).ready, "K28a: pure: CL at the parent's height, N=1 -> final at 1 conf");
}

// K28b: bestchainlock exposed -> mined is not enough; the ChainLock must
// reach the parent's height, and the child fires in the tick it does.
static void k28b_chainlock_present()
{
    World w;
    w.node.cl_exposed = true;
    w.node.cl_height = w.node.tip;
    const Pair p = add_pair(w, 410);
    w.tick();
    w.node.mine({p.ptx});
    const int64_t H = w.node.tip;
    w.node.cl_height = H - 1;
    w.tick();
    CHECK(w.item(0).state == State::Mined && w.item(1).state == State::Waiting &&
              w.item(1).why.find("not final yet: bestchainlock height " + std::to_string(H - 1) + " < " +
                                 std::to_string(H)) != std::string::npos,
          "K28b: parent mined, ChainLock below it -> child waits, reason names the ChainLock");
    w.node.advance(4);
    w.tick();
    CHECK(w.item(1).state == State::Waiting && child_posts(w, p.ctx) == 0,
          "K28b: 5 confirmations but no ChainLock on the parent's block -> still waits");
    CHECK(w.item(1).why.find("ChainLock not exposed") == std::string::npos, "K28b: no fallback text when the field exists");
    w.node.cl_height = H;
    const TickReport r = w.tick();
    CHECK(w.item(1).state == State::Admitted && child_posts(w, p.ctx) == 1 && r.submits == 1,
          "K28b: ChainLock reaches H -> child fires in the same tick");

    // Exposed but null: no usable ChainLock -> wait (no fallback to a count).
    World n;
    n.node.cl_exposed = true;
    n.node.cl_height.reset();
    const Pair q = add_pair(n, 412);
    n.tick();
    n.node.mine({q.ptx});
    n.node.advance(6);
    n.tick();
    CHECK(n.item(1).state == State::Waiting && n.item(1).why.find("no ChainLock yet") != std::string::npos,
          "K28b: bestchainlock null -> waits, never falls back to a confirmation count");
    n.node.cl_height = n.node.tip;
    n.tick();
    CHECK(n.item(1).state == State::Admitted, "K28b: ChainLock above H -> final (block at H verified) -> submitted");
    CHECK(n.node.count("GET", route::kBlockHash) >= 1, "K28b: CL above H -> getblockhash verifies the block at H");

    // A malformed field is treated as exposed-without-ChainLock.
    World m;
    const Pair r2 = add_pair(m, 414);
    m.tick();
    m.node.mine({r2.ptx});
    m.node.advance(3);
    m.node.script.push_back({"GET /api/explorer/getblockchaininfo",
                             FakeNode::reply(200, nj{{"synced", true}, {"blocks", m.node.tip}, {"bestchainlock", "x"}})});
    m.tick();
    CHECK(m.item(1).state == State::Waiting && m.item(1).why.find("not {height, blockhash}") != std::string::npos,
          "K28b: malformed bestchainlock -> waits with the shape named");
}

// K28c: the parent's block is reorged out before it is ChainLocked -> the
// child never fires on the stale record, through either verification path.
static void k28c_reorg_before_chainlock()
{
    SchedulerOptions lazy;
    lazy.reorg_check_every = 1000; // the parent's own reorg check stays quiet: the child's check must catch it
    {
        World w(lazy);
        w.node.cl_exposed = true;
        w.node.cl_height = w.node.tip;
        const Pair p = add_pair(w, 420);
        w.tick();
        w.node.mine({p.ptx});
        const int64_t H = w.node.tip;
        w.node.cl_height = H - 1;
        w.tick();
        CHECK(w.item(0).state == State::Mined && w.item(1).state == State::Waiting, "K28c: mined, not ChainLocked");
        w.node.reorg(H);       // block H replaced, without the parent
        w.node.cl_height = H;  // ...and the ChainLock lands on the replacement
        w.tick();
        CHECK(w.item(1).state == State::Waiting && child_posts(w, p.ctx) == 0 &&
                  w.item(1).why.find("no longer on the node's chain") != std::string::npos,
              "K28c: ChainLock at H is another block -> child does not fire");
        w.node.mine();
        w.node.cl_height = w.node.tip; // ChainLock above H: the getblockhash path
        w.tick();
        CHECK(w.item(1).state == State::Waiting && child_posts(w, p.ctx) == 0,
              "K28c: ChainLock above H, block at H changed -> child still does not fire");
    }
    {
        // With the parent's own reorg check on, the parent returns to waiting,
        // is resubmitted, and the child fires only once it is final again.
        SchedulerOptions eager;
        eager.reorg_check_every = 1;
        World w(eager);
        w.node.cl_exposed = true;
        w.node.cl_height = w.node.tip;
        const Pair p = add_pair(w, 422);
        w.tick();
        w.node.mine({p.ptx});
        const int64_t H = w.node.tip;
        w.node.cl_height = H - 1;
        w.tick();
        w.node.reorg(H);
        w.tick();
        CHECK(w.item(0).state == State::Admitted && w.item(1).state == State::Waiting && child_posts(w, p.ctx) == 0,
              "K28c: parent reorged out -> resubmitted; child waits (parent not mined)");
        w.node.mine({p.ptx});
        const int64_t H2 = w.node.tip;
        w.tick();
        CHECK(w.item(0).node.mined_height == H2 && w.item(1).state == State::Waiting, "K28c: parent re-mined, not final");
        w.node.cl_height = H2;
        w.tick();
        CHECK(w.item(1).state == State::Admitted && child_posts(w, p.ctx) == 1, "K28c: parent final again -> child fires");
    }
}

// K28d: allow_unconfirmed_parent defaults to false; only the explicit opt-in
// lets a mempool parent fire the child.
static void k28d_allow_unconfirmed_parent()
{
    World w;
    const Pair p = add_pair(w, 430);
    CHECK(!w.item(1).triggers.allow_unconfirmed_parent, "K28d: default false");
    CHECK(queue_to_json(w.q).find("\"allow_unconfirmed_parent\": false") != std::string::npos,
          "K28d: persisted explicitly as false");
    for (int i = 0; i < 7; ++i) w.tick(120);
    CHECK(w.item(0).state == State::Riding && w.node.mempool.count(p.ptx) == 1, "K28d: parent riding in the node mempool");
    CHECK(w.item(1).state == State::Waiting && child_posts(w, p.ctx) == 0 &&
              w.item(1).why.find("never rides an unconfirmed parent") != std::string::npos,
          "K28d: parent in the mempool -> child waits without the opt-in");

    World o;
    const Pair q = add_pair(o, 432, 1, /*allow_unconfirmed=*/true);
    CHECK(o.item(1).triggers.allow_unconfirmed_parent &&
              queue_to_json(o.q).find("\"allow_unconfirmed_parent\": true") != std::string::npos,
          "K28d: opt-in recorded");
    o.tick(); // the parent is submitted and enters the mempool; the child follows in the same tick
    CHECK(o.item(0).state == State::Admitted && o.item(1).state == State::Admitted && child_posts(o, q.ctx) == 1,
          "K28d: opt-in -> child fires while the parent is only in the mempool");
    bool noted = false;
    for (const auto& e : o.item(1).journal)
        if (e.event == "allow_unconfirmed_parent") noted = true;
    CHECK(noted, "K28d: the opt-in is journaled at enqueue");
    Queue back;
    std::string why;
    CHECK(queue_from_json(queue_to_json(o.q), back, why) && back.items[1].triggers.allow_unconfirmed_parent,
          "K28d: opt-in survives a round trip");
}

// K28e: the parent's block is reorged out AFTER the child was submitted and
// mined -> both return to waiting; the child is resubmitted only once its
// parent is final again (no ChainLock oracle: 2 confirmations).
static void k28e_reorg_after_child_submitted()
{
    SchedulerOptions so;
    so.reorg_check_every = 1;
    World w(so);
    const Pair p = add_pair(w, 440);
    w.tick();
    w.node.mine({p.ptx});
    const int64_t H = w.node.tip;
    w.tick();
    w.node.mine();
    w.tick();
    CHECK(w.item(1).state == State::Admitted, "K28e: parent final (2 confs) -> child submitted");
    w.node.mine({p.ctx});
    w.tick();
    CHECK(w.item(1).state == State::Mined, "K28e: child mined");
    w.node.reorg(H);
    w.node.reorg(H + 2);
    const size_t before = child_posts(w, p.ctx);
    w.tick();
    CHECK(w.item(0).state == State::Admitted && w.item(1).state == State::Waiting && child_posts(w, p.ctx) == before,
          "K28e: both blocks reorged -> parent resubmitted, child back to waiting, no child resubmit");
    w.node.mine({p.ptx});
    w.tick();
    CHECK(w.item(1).state == State::Waiting && child_posts(w, p.ctx) == before, "K28e: parent re-mined, 1 conf -> child waits");
    w.node.mine();
    w.tick();
    CHECK(w.item(1).state == State::Admitted && child_posts(w, p.ctx) == before + 1,
          "K28e: parent final again -> child resubmitted");
}

// ── slice S2: the runner and the daemon's command line (Qt-free) ────────────

namespace cli = c2w::companion::sched::cli;

// make_api hands out a forwarder so every command talks to the one FakeNode.
struct ForwardApi : NodeApi {
    NodeApi& n;
    explicit ForwardApi(NodeApi& x) : n(x) {}
    HttpReply get(const std::string& p) override { return n.get(p); }
    HttpReply post_json(const std::string& p, const std::string& b) override { return n.post_json(p, b); }
    const char* name() const override { return "forward"; }
};

// The FakeNode with a hook on submit POSTs (an operator edit "during" a tick).
struct HookApi : NodeApi {
    NodeApi& n;
    std::function<void()> on_submit;
    explicit HookApi(NodeApi& x) : n(x) {}
    HttpReply get(const std::string& p) override { return n.get(p); }
    HttpReply post_json(const std::string& p, const std::string& b) override
    {
        if (p == route::kSubmit && on_submit) {
            auto f = std::move(on_submit);
            on_submit = nullptr;
            f();
        }
        return n.post_json(p, b);
    }
    const char* name() const override { return "hook"; }
};

static std::string make_dir()
{
    char tmpl[] = "/tmp/c2w-cli-kat-XXXXXX";
    const char* d = ::mkdtemp(tmpl);
    return d ? std::string(d) : std::string();
}

static void write_text(const std::string& path, const std::string& text)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << text;
}

static std::string slurp(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

struct CliWorld {
    FakeClock clock;
    FakeNode node;
    std::ostringstream out, err;
    std::string all_output; // every command's stdout + stderr
    std::vector<std::vector<std::string>> argvs;
    std::string dir, queue, token;
    cli::Env env;
    int sleeps = 0, max_sleeps = 0;
    std::function<void(int)> on_sleep;

    CliWorld()
    {
        clock.t = T("2026-11-02T00:10:12Z");
        node.clock = &clock;
        dir = make_dir();
        queue = dir + "/data/c2wallet-qt/companion/queue.json";
        token = dir + "/control.token";
        write_text(token, std::string(kToken) + "\n");
        ::chmod(token.c_str(), 0600);
        env.out = &out;
        env.err = &err;
        env.clock = &clock;
        env.make_api = [this](const std::string&, std::string&) -> std::unique_ptr<NodeApi> {
            return std::make_unique<ForwardApi>(node);
        };
        env.sleep_ms = [this](int64_t ms) {
            clock.t += ms / 1000;
            ++sleeps;
            if (on_sleep) on_sleep(sleeps);
        };
        env.stop_requested = [this] { return sleeps >= max_sleeps; };
    }
    int run(std::vector<std::string> a)
    {
        argvs.push_back(a);
        out.str("");
        err.str("");
        a.insert(a.begin(), {"--queue", queue});
        const int rc = cli::run(a, env);
        all_output += out.str() + err.str();
        return rc;
    }
    int init() { return run({"--node-url", "http://127.0.0.1:8080", "--token-file", token, "init"}); }
    std::string put(const std::string& name, const Art& a, bool manifest = true)
    {
        write_text(dir + "/" + name + ".hex", a.hex_text);
        if (manifest) write_text(dir + "/" + name + ".manifest.json", a.manifest);
        return dir + "/" + name + ".hex";
    }
    Queue load()
    {
        Queue q;
        std::string why;
        if (!load_queue_file(queue, q, why)) std::printf("  load failed: %s\n", why.c_str());
        return q;
    }
};

// K29: argv rules: no --token VALUE, loopback URL, strict option parsing.
static void k29_cli_parsing()
{
    CliWorld w;
    CHECK(w.run({"--token", kToken, "list"}) == cli::kExitUsage && w.err.str().find("--token-file") != std::string::npos,
          "K29: --token VALUE is a usage error naming --token-file");
    CHECK(w.run({std::string("--token=") + kToken, "status"}) == cli::kExitUsage, "K29: --token=VALUE too");
    w.all_output.clear(); // those two carried the token in argv on purpose
    w.argvs.clear();
    CHECK(w.run({"--node-url", "http://10.0.0.5:8080", "init"}) == cli::kExitUsage, "K29: non-loopback --node-url refused");
    CHECK(w.run({}) == cli::kExitUsage && w.err.str().find("usage:") != std::string::npos, "K29: no command -> usage");
    CHECK(w.run({"help"}) == cli::kExitOk && w.out.str().find("arm-policy") != std::string::npos, "K29: help");
    CHECK(w.run({"frobnicate"}) == cli::kExitUsage, "K29: unknown command");
    CHECK(w.run({"add"}) == cli::kExitUsage && w.err.str().find("--hex") != std::string::npos, "K29: add needs --hex");
    const std::string hex = w.put("p", simple(500));
    CHECK(w.run({"add", "--hex", hex, "--bogus"}) == cli::kExitUsage, "K29: unknown option");
    CHECK(w.run({"add", "--hex", hex, "--after-parent", "zz"}) == cli::kExitUsage, "K29: --after-parent needs a txid");
    CHECK(w.run({"add", "--hex", hex, "--after-parent", std::string(64, 'a') + ":0"}) == cli::kExitUsage,
          "K29: --after-parent TXID:0 refused");
    CHECK(w.run({"add", "--hex", hex, "--not-before-time", "2026-11-03T00:00:00"}) == cli::kExitUsage,
          "K29: --not-before-time without Z refused");
    CHECK(w.run({"add", "--hex", hex, "--manifest", "x", "--no-manifest"}) == cli::kExitUsage, "K29: conflicting manifest flags");
    CHECK(w.run({"add", "--hex", hex, "--allow-auto-arm", "maybe"}) == cli::kExitUsage, "K29: --allow-auto-arm yes|no");
    CHECK(w.run({"list"}) == cli::kExitQueue, "K29: list without a queue -> exit 3");
    if (::geteuid() != 0) {
        const std::vector<std::string> a = {"--queue", "/etc/c2w-kat-queue.json", "add", "--hex", hex};
        CHECK(cli::run(a, w.env) == cli::kExitUsage && ::access("/etc/c2w-kat-queue.json", F_OK) != 0,
              "K29: editing a queue in a directory owned by another user is refused");
    }
}

// K30: init, add (manifest auto-located, bare hex with --h0, after_parent
// TXID:N, heights, times, opt-in flags), list and show.
static void k30_cli_add_list_show()
{
    CliWorld w;
    CHECK(w.init() == cli::kExitOk && w.out.str().find("(created)") != std::string::npos &&
              w.out.str().find("readable by this user") != std::string::npos,
          "K30: init creates the queue and checks the token file");
    Queue q = w.load();
    CHECK(q.node.url == "http://127.0.0.1:8080" && q.node.token_file == w.token && !q.arm_policy.auto_arm &&
              !q.arm_policy.consented_at,
          "K30: node config recorded, no auto-arm consent by default");

    const Art pa = simple(510);
    const std::string ph = w.put("parent", pa);
    CHECK(w.run({"add", "--hex", ph}) == cli::kExitOk && w.out.str().find("manifest: auto-located") != std::string::npos &&
              w.out.str().find("submit at tip >= 2565244") != std::string::npos,
          "K30: add uses the sibling manifest; prints the maturity fire tip");
    const std::string ptx = pa.txids[0];

    const Art ca = simple(511);
    const std::string ch = w.put("child", ca, /*manifest=*/false);
    std::string up = ptx;
    for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    CHECK(w.run({"add", "--hex", ch, "--label", "collateral", "--after-parent", up + ":3", "--not-before-height", "2565310",
                 "--not-before-time", "2026-11-02T06:00:00Z", "--h0", "2565200"}) == cli::kExitOk,
          "K30: add a bare-hex child with after_parent TXID:N, heights, time and an explicit h0");
    q = w.load();
    const Item& c = q.items.back();
    CHECK(c.label == "collateral" && c.triggers.after_parent.size() == 1 && c.triggers.after_parent[0].txid == ptx &&
              c.triggers.after_parent[0].min_confirmations == 3 && c.triggers.not_before_height == 2565310 &&
              c.triggers.not_before_time == std::string("2026-11-02T06:00:00Z") && c.triggers.maturity.enabled &&
              c.triggers.maturity.safe_from_height == 2565300 &&
              c.triggers.maturity.source.find("operator h0=2565200") != std::string::npos &&
              !c.triggers.allow_unconfirmed_parent,
          "K30: the child's triggers as given (txid lower-cased, h0 -> S = h0 + 100)");
    CHECK(w.out.str().find("final (ChainLocked") != std::string::npos, "K30: add explains the parent finality rule");

    const std::string oh = w.put("other", simple(512), false);
    CHECK(w.run({"add", "--hex", oh}) == cli::kExitAttention && w.err.str().find("maturity is unknown") != std::string::npos,
          "K30: bare hex without --h0 / --not-before-height refused (exit 1)");
    CHECK(w.run({"add", "--hex", oh, "--h0", "2565145", "--allow-auto-arm", "yes"}) == cli::kExitAttention &&
              w.err.str().find("consent") != std::string::npos,
          "K30: --allow-auto-arm yes without a recorded consent refused");
    CHECK(w.run({"add", "--hex", oh, "--h0", "2565145", "--after-parent", ptx, "--allow-unconfirmed-parent", "--pause"}) ==
              cli::kExitOk,
          "K30: add with --allow-unconfirmed-parent and --pause");
    q = w.load();
    CHECK(q.items.size() == 3 && q.items[2].triggers.after_parent[0].min_confirmations == 1 &&
              q.items[2].triggers.allow_unconfirmed_parent && q.items[2].paused,
          "K30: default N = 1; the opt-in and the pause are recorded");

    CHECK(w.run({"list"}) == cli::kExitOk, "K30: list");
    const std::string l = w.out.str();
    CHECK(l.find(q.items[0].id) != std::string::npos && l.find(q.items[1].id) != std::string::npos &&
              l.find("why:") != std::string::npos && l.find("NOT RUNNING") != std::string::npos,
          "K30: list shows every item with its reason and the runner state");
    CHECK(w.run({"show", q.items[1].id}) == cli::kExitOk && w.out.str().find("after parent") != std::string::npos &&
              w.out.str().find("not_before_time: 2026-11-02T06:00:00Z") != std::string::npos,
          "K30: show prints the triggers");
    CHECK(w.run({"show", ptx.substr(0, 10)}) == cli::kExitOk && w.out.str().find(q.items[0].id) != std::string::npos,
          "K30: show by txid prefix");
    CHECK(w.run({"show", "q-nope"}) == cli::kExitAttention, "K30: show of an unknown id refused");
}

// K31: auto-arm consent is recorded only explicitly, timestamped, with its
// text; auto-disarm stays off unless given; revocation is checked.
static void k31_cli_arm_policy()
{
    CliWorld w;
    w.init();
    CHECK(w.run({"arm-policy"}) == cli::kExitOk && w.out.str().find("no consent recorded") != std::string::npos &&
              w.out.str().find("reward path") != std::string::npos,
          "K31: arm-policy without options prints the policy and the exposure text");
    CHECK(w.run({"arm-policy", "--auto-arm", "yes"}) == cli::kExitUsage && w.err.str().find("--consent") != std::string::npos,
          "K31: auto-arm without a consent text is a usage error");
    CHECK(w.run({"arm-policy", "--auto-arm", "yes", "--consent", ""}) == cli::kExitUsage, "K31: an empty consent text too");
    CHECK(!w.load().arm_policy.auto_arm, "K31: nothing recorded by the refusals");
    w.clock.t += 60;
    CHECK(w.run({"arm-policy", "--auto-arm", "yes", "--consent", "hotel queue: operator G, 2026-11-02"}) == cli::kExitOk,
          "K31: consent recorded");
    Queue q = w.load();
    CHECK(q.arm_policy.auto_arm && !q.arm_policy.auto_disarm_when_idle &&
              q.arm_policy.consented_at == format_utc(w.clock.t) &&
              q.arm_policy.consent_text == std::string("hotel queue: operator G, 2026-11-02"),
          "K31: auto_arm with consented_at = now and the text; auto-disarm off");
    CHECK(w.out.str().find("reward path") != std::string::npos, "K31: the exposure text is restated on consent");

    const std::string h = w.put("a", simple(520));
    CHECK(w.run({"add", "--hex", h, "--allow-auto-arm", "yes"}) == cli::kExitOk, "K31: per-item allow_auto_arm under consent");
    CHECK(w.run({"arm-policy", "--auto-arm", "no"}) == cli::kExitAttention &&
              w.err.str().find("allow_auto_arm") != std::string::npos && w.load().arm_policy.auto_arm,
          "K31: revoking while an item widens auto-arm is refused, the queue unchanged");
    CHECK(w.run({"set-arm-policy", "--auto-disarm-when-idle", "yes", "--consent", "disarm too"}) == cli::kExitOk &&
              w.load().arm_policy.auto_disarm_when_idle,
          "K31: alias set-arm-policy; auto-disarm only when given");
    const std::string id = w.load().items[0].id;
    w.run({"pause", id});
    w.run({"rm", id});
    CHECK(w.run({"arm-policy", "--auto-arm", "no", "--auto-disarm-when-idle", "no"}) == cli::kExitOk, "K31: revoke");
    q = w.load();
    CHECK(!q.arm_policy.auto_arm && !q.arm_policy.auto_disarm_when_idle && !q.arm_policy.consented_at &&
              !q.arm_policy.consent_text,
          "K31: revocation clears the consent record");
}

// K32: run --once, then a Runner in this process while the CLI edits the
// file: adds, pauses, resumes and removals land at the next step; an edit
// made during a tick keeps the operator's version.
static void k32_cli_run_and_merge()
{
    CliWorld w;
    w.init();
    const std::string ha = w.put("a", simple(530));
    w.run({"add", "--hex", ha, "--label", "A"});
    CHECK(w.run({"run", "--once"}) == cli::kExitOk && w.node.count("POST", route::kSubmit) == 1,
          "K32: run --once submits the ready item");
    CHECK(w.out.str().find("runner: start") != std::string::npos && w.out.str().find("token file usable") != std::string::npos &&
              w.out.str().find("waiting -> ready") != std::string::npos,
          "K32: the run logs its start and the transitions");
    CHECK(w.load().items[0].state == State::Admitted, "K32: persisted as admitted");

    Queue q = w.load();
    ForwardApi fwd(w.node);
    CaptureJournal sink;
    SchedulerOptions so;
    so.token_file = w.token;
    Runner r(w.queue, q, fwd, w.clock, sink, so);
    const std::string hb = w.put("b", simple(531));
    w.run({"add", "--hex", hb, "--label", "B", "--pause"});
    w.clock.t += 15;
    Runner::Step s = r.step();
    const std::string idb = w.load().items[1].id;
    CHECK(s.ticked && r.queue().items.size() == 2 && r.queue().items[1].paused &&
              w.node.count("POST", route::kSubmit) == 1,
          "K32: an item added while the runner lives is merged; paused -> no submit");
    w.run({"resume", idb});
    w.clock.t += 15;
    r.step();
    CHECK(w.node.count("POST", route::kSubmit) == 2 && w.load().items[1].state == State::Admitted,
          "K32: resume lands at the next step -> submitted");

    // An operator pause during the tick (the hook runs inside the submit POST).
    const std::string hc = w.put("c", simple(532));
    const std::string hd = w.put("d", simple(533));
    w.run({"add", "--hex", hc, "--label", "C"});
    w.run({"add", "--hex", hd, "--label", "D"});
    const std::string idd = w.load().items[3].id;
    HookApi hook(w.node);
    Runner r2(w.queue, w.load(), hook, w.clock, sink, so);
    hook.on_submit = [&] { w.run({"pause", idd}); };
    w.clock.t += 15;
    r2.step();
    Queue after = w.load();
    CHECK(after.items[2].state == State::Admitted && after.items[3].paused && after.items[3].rev == 1,
          "K32: mid-tick operator pause survives the runner's persist (higher rev wins), C admitted");
    w.clock.t += 15;
    r2.step();
    CHECK(r2.queue().items[3].paused && w.load().items[3].paused, "K32: the runner adopts the pause at its next step");
    CHECK(w.run({"rm", idd}) == cli::kExitOk, "K32: rm of the paused item");
    w.clock.t += 15;
    r2.step();
    CHECK(r2.queue().items.size() == 3 && w.load().items.size() == 3, "K32: the removal is merged, not resurrected");
    CHECK(w.run({"rm", after.items[2].id}) == cli::kExitAttention && w.err.str().find("pause it first") != std::string::npos,
          "K32: a live item cannot be removed without a pause");
}

// K33: one runner per queue.
static void k33_cli_single_instance()
{
    CliWorld w;
    w.init();
    QueueLock held;
    std::string why;
    CHECK(held.acquire(runner_lock_base(w.queue), false, why), "K33: test holds the runner lock");
    CHECK(runner_lock_held(w.queue), "K33: runner_lock_held sees it");
    CHECK(w.run({"run", "--once"}) == cli::kExitLock && w.err.str().find("lock held") != std::string::npos,
          "K33: a second runner exits 4");
    held.release();
    CHECK(!runner_lock_held(w.queue) && w.run({"run", "--once"}) == cli::kExitOk, "K33: free again -> runs");
}

// K34: status exit codes for monitoring, alert acknowledgement, the arm source.
static void k34_cli_status()
{
    CliWorld w;
    w.init();
    w.run({"add", "--hex", w.put("a", simple(540))});
    w.node.enabled = false;
    w.run({"run", "--once"});
    CHECK(w.load().items[0].state == State::BlockedNotArmed, "K34: no consent, node disarmed -> blocked_not_armed");
    CHECK(w.run({"status"}) == cli::kExitAttention, "K34: status exit 1");
    const std::string s1 = w.out.str();
    CHECK(s1.find("ARM     none (enabled=false)") != std::string::npos && s1.find("blocked_not_armed") != std::string::npos &&
              s1.find("no usable consent") != std::string::npos && s1.find("pending alert") != std::string::npos &&
              s1.find("no runner holds the queue") != std::string::npos,
          "K34: status names the arm state, the blocked item, the alert and the missing runner");
    w.node.enabled = true;
    w.clock.t += 15;
    w.run({"run", "--once"});
    QueueLock held;
    std::string why;
    held.acquire(runner_lock_base(w.queue), false, why);
    CHECK(w.run({"status"}) == cli::kExitAttention && w.out.str().find("ARM     standing") != std::string::npos,
          "K34: armed again (standing); the old alert is still pending");
    CHECK(w.run({"ack-alerts"}) == cli::kExitOk && w.out.str().find("acknowledged") != std::string::npos, "K34: ack-alerts");
    CHECK(w.run({"status"}) == cli::kExitOk && w.out.str().find("RESULT  OK") != std::string::npos,
          "K34: runner holds the queue, fresh tick, nothing blocked, alerts read -> exit 0");
    w.clock.t += 1000;
    CHECK(w.run({"status"}) == cli::kExitAttention && w.out.str().find("older than") != std::string::npos,
          "K34: a stale runner tick needs attention");
    w.clock.t -= 1000;
    w.node.down = true;
    CHECK(w.run({"status"}) == cli::kExitAttention && w.out.str().find("unreachable") != std::string::npos,
          "K34: node unreachable -> exit 1");
    w.node.down = false;
    w.node.cl_exposed = true;
    w.node.cl_height = w.node.tip - 1;
    w.run({"status"});
    CHECK(w.out.str().find("ChainLock " + std::to_string(w.node.tip - 1)) != std::string::npos,
          "K34: status reports the node's ChainLock when exposed");
}

// K35: the token never reaches argv, the environment, any output or the file.
static void k35_cli_token_hygiene()
{
    CliWorld w;
    w.init();
    w.run({"arm-policy", "--auto-arm", "yes", "--consent", "kat consent"});
    w.run({"add", "--hex", w.put("a", simple(550))});
    w.node.enabled = false; // the run arms the node (two-phase) and submits
    w.run({"run", "--once"});
    w.run({"list"});
    w.run({"status"});
    CHECK(w.node.count("POST", route::kConfigApply) == 2 && w.node.count("POST", route::kSubmit) == 1,
          "K35: the run armed (2 apply POSTs) and submitted");
    CHECK(!leaks_secret(w.all_output), "K35: no token or nonce in any command's stdout/stderr");
    CHECK(!leaks_secret(slurp(w.queue)), "K35: none in the queue file");
    std::string args;
    for (const auto& a : w.argvs)
        for (const auto& x : a) args += x + " ";
    CHECK(!leaks_secret(args), "K35: none in any argv");
    bool env_leak = false;
    for (char** e = environ; e && *e; ++e)
        if (leaks_secret(*e)) env_leak = true;
    CHECK(!env_leak, "K35: none in the environment");
    for (const auto& b : w.node.bodies(route::kSubmit))
        CHECK(count_of(b, kToken) == 1, "K35: the submit body carries it exactly once");
}

// K36: the run loop over a node restart: with the standing arm (unit flag) the
// dropped item is simply resubmitted; without it the disarm is alerted and the
// recorded consent re-arms the node (two-phase) before the resubmit.
static void k36_run_loop_restart_and_disarm()
{
    for (const bool standing : {true, false}) {
        CliWorld w;
        w.init();
        if (!standing) w.run({"arm-policy", "--auto-arm", "yes", "--consent", "hotel queue consent"});
        w.run({"add", "--hex", w.put("a", simple(standing ? 560 : 561))});
        w.max_sleeps = 4;
        w.on_sleep = [&](int n) {
            if (n == 1) { // the node restarts between tick 1 and tick 2
                w.node.mempool.clear();
                w.node.wired = !standing ? false : true;
                w.node.enabled = standing;
            }
        };
        CHECK(w.run({"--poll-sec", "15", "run"}) == cli::kExitOk, "K36: the loop stops cleanly on request");
        const std::string log = w.out.str();
        const Item it = w.load().items[0];
        CHECK(w.sleeps == 4 && log.find("runner: stop") != std::string::npos, "K36: ticks, sleeps, stop");
        CHECK(it.state == State::Admitted || it.state == State::IsHold, "K36: resubmitted after the restart");
        CHECK(it.retry.resubmits == 1 && w.node.count("POST", route::kSubmit) == 2, "K36: exactly one resubmit");
        if (standing) {
            CHECK(w.node.count("POST", route::kConfigApply) == 0 && log.find("ALERT disarmed") == std::string::npos,
                  "K36: standing arm survives the restart: no alert, no apply");
        } else {
            CHECK(log.find("ALERT disarmed") != std::string::npos && log.find("ARMED by scheduler") != std::string::npos &&
                      w.node.count("POST", route::kConfigApply) == 2 && w.node.enabled,
                  "K36: runtime disarm after the restart: alerted, re-armed with the recorded consent");
        }
    }
    // Without consent the disarm leaves the item blocked and alerted.
    CliWorld w;
    w.init();
    w.run({"add", "--hex", w.put("a", simple(562))});
    w.max_sleeps = 3;
    w.on_sleep = [&](int n) {
        if (n == 1) {
            w.node.mempool.clear();
            w.node.enabled = false;
        }
    };
    w.run({"run"});
    CHECK(w.load().items[0].state == State::BlockedNotArmed && w.node.count("POST", route::kConfigApply) == 0 &&
              w.out.str().find("ALERT disarmed") != std::string::npos,
          "K36: no consent -> blocked_not_armed, alerted, never arms");
}

// K37: list re-reads the IS-hold clock at the time it runs.
static void k37_cli_list_is_hold_eta()
{
    CliWorld w;
    w.init();
    w.run({"add", "--hex", w.put("a", simple(570))});
    w.run({"run", "--once"});
    const int64_t t0 = w.clock.t;
    w.clock.t += 15;
    w.run({"run", "--once"});
    CHECK(w.load().items[0].state == State::IsHold, "K37: is_hold");
    w.clock.t += 100;
    w.run({"list"});
    CHECK(w.out.str().find("IS-hold ends ~" + format_utc(t0 + 600)) != std::string::npos &&
              w.out.str().find("(in ~9 m") != std::string::npos,
          "K37: list shows the IS-hold end and the time left");
    w.clock.t = t0 + 700;
    w.run({"list"});
    CHECK(w.out.str().find("IS-hold elapsed at") != std::string::npos, "K37: after the hold, list says it elapsed");
}

// K38: the merge rule in isolation.
static void k38_merge_rule()
{
    World w;
    const std::string a = w.add(simple(580)), b = w.add(simple(581)), d = w.add(simple(582));
    Queue mem = w.q;
    find_item(mem, a)->state = State::Admitted;    // the runner's progress
    mem.arm_policy.armed_by_scheduler_at = "2026-11-02T00:00:00Z";
    Queue disk = w.q;
    std::string why;
    pause_item(disk, b, w.clock.t, why);           // operator edit: rev 1
    disk.items.erase(std::remove_if(disk.items.begin(), disk.items.end(), [&](const Item& i) { return i.id == d; }),
                     disk.items.end());            // removed by the operator
    const std::string c = std::string("q-x");
    Item extra = disk.items[0];
    extra.id = c;
    extra.tx.txid = std::string(64, '7');
    disk.items.push_back(extra);                   // added by the operator
    disk.tracked.push_back(Tracked{std::string(64, '8')});
    arm::record_consent(disk.arm_policy, true, false, "operator", w.clock.t, why);
    Queue m = merge_runner_view(mem, disk);
    CHECK(m.items.size() == 3 && find_item(m, a)->state == State::Admitted, "K38: runner state kept at the same rev");
    CHECK(find_item(m, b)->paused && find_item(m, b)->rev == 1, "K38: operator edit (higher rev) wins");
    CHECK(!find_item(m, d) && find_item(m, c), "K38: removed item dropped, added item taken");
    CHECK(m.arm_policy.auto_arm && m.arm_policy.consent_text == std::string("operator") &&
              m.arm_policy.armed_by_scheduler_at == std::string("2026-11-02T00:00:00Z"),
          "K38: re-recorded consent taken from the file; the runner keeps its own arm record");
    CHECK(find_tracked(m, std::string(64, '8')) != nullptr, "K38: tracked parents merged");
    Queue persisted;
    CHECK(queue_from_json(queue_to_json(m), persisted, why) &&
              queue_to_json(merge_runner_view(m, persisted)) == queue_to_json(m),
          "K38: merging with its own persisted copy is idempotent");
}

// K39: --h0 with a manifest can only delay maturity.
static void k39_explicit_h0_with_manifest()
{
    World w;
    const Art a = simple(590); // manifest S = 2565245
    EnqueueRequest r = req_for(a);
    r.explicit_h0 = 2565200;
    const EnqueueResult e1 = enqueue(w.q, r, w.clock.t);
    CHECK(e1.ok && w.item(0).triggers.maturity.safe_from_height == 2565300 &&
              w.item(0).triggers.maturity.source.find("later than manifest") != std::string::npos,
          "K39: a later h0 raises S to h0 + 100");
    World x;
    EnqueueRequest r2 = req_for(simple(591));
    r2.explicit_h0 = 2565100;
    CHECK(enqueue(x.q, r2, x.clock.t).ok && x.item(0).triggers.maturity.safe_from_height == 2565245 &&
              x.item(0).triggers.maturity.source.find("is not later") != std::string::npos,
          "K39: an earlier h0 never lowers the manifest's S");
    EnqueueRequest r3 = req_for(simple(592));
    r3.explicit_h0 = 0;
    CHECK(!enqueue(x.q, r3, x.clock.t).ok, "K39: h0 must be > 0");
}

int main()
{
    k1_maturity_boundary();
    k2_maturity_unknown_never_auto();
    k3_noncoinbase_inputs();
    k4_manifest_cross_check();
    k5_not_before_height_and_time();
    k6_after_parent_confirmations();
    k7_all_of_combination();
    k8_disarmed_never_arms_without_consent();
    k9_refusal_cause_table();
    k10_http_outcomes();
    k11_restart_resume();
    k12_token_never_persisted_or_logged();
    k13_idempotent_resubmit();
    k14_instantsend_hold();
    k15_mined_detection();
    k16_dropped_and_resubmit();
    k17_expiry_and_renew();
    k18_loopback_only_node_url();
    k19_queue_round_trip();
    k20_parent_auto_discovery();
    k21_preflight_caps();
    k23_auto_arm_two_phase();
    k24_auto_arm_failures();
    k25_auto_disarm_when_idle();
    k26_disarm_detection_alert();
    k27_tip_unknown_waits();
    misc_operator_edits_and_status();
    k6b_foreign_parent_tracking();
    k11b_resume_from_submitting();
    k15b_reorg_readmitted();
    k26b_disarm_moves_ready();
    k9b_rate_limited_through_scheduler();
    k9c_fee_above_max();
    k27b_explorer_disabled_alert();
    k9d_node_vocabulary();
    k28a_chainlock_absent_fallback();
    k28b_chainlock_present();
    k28c_reorg_before_chainlock();
    k28d_allow_unconfirmed_parent();
    k28e_reorg_after_child_submitted();
    k29_cli_parsing();
    k30_cli_add_list_show();
    k31_cli_arm_policy();
    k32_cli_run_and_merge();
    k33_cli_single_instance();
    k34_cli_status();
    k35_cli_token_hygiene();
    k36_run_loop_restart_and_disarm();
    k37_cli_list_is_hold_eta();
    k38_merge_rule();
    k39_explicit_h0_with_manifest();

    for (const auto& f : g_tmpfiles) {
        ::unlink(f.c_str());
        ::unlink((f + ".lock").c_str());
    }
    std::printf("\n== inject scheduler KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
