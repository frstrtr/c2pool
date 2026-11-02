// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for slice S-C's operator commands: scan, plan (incl. --stage2),
// preflight, watch and add --preflight, driven through sched::cli::run (the
// daemon's own entry point) with scripted transports: FakeDashd behind the
// dashd seam, FakeUtxoNode behind the node seam (the N1 scan and the N3 dry
// run), a fixed clock and a temporary directory. No network, no Qt, no key;
// ci/check_key_free.sh runs over this binary.
//
//   C1 credentials by value are usage errors      C6 watch: one maturity alert per crossing
//   C2 loopback-only dashd / node URLs            C7 plan --stage2 and the add fence (M1)
//   C3 usage errors                               C8 Ctrl-C during scantxoutset: abort
//   C4 scan end to end writes the file set        C9 the dashd credentials file rules
//   C5 preflight / add --preflight (spent input, dry-run cause, --force journaled)

#include "../scan/Classifier.hpp"
#include "../scan/Planner.hpp"
#include "../scan/RpcAuth.hpp"
#include "../scan/ScanFiles.hpp"

#include "../sched/Clock.hpp"
#include "../sched/InjectQueue.hpp"
#include "../sched/SchedCli.hpp"

#include "TransferContainer.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sstream>

#include <sys/stat.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

#include "scan_fakes.hpp"

using namespace scan_kat;
using oj = nlohmann::ordered_json;

static const char* kGov = "4f1c1cb8ed7f2a6bd9e4f9cbb5f24bd7d0f9e4ad14af9f1e1c2a0b6e7d3c5a91";
static const char* kTokenText = "SCAN-CLI-KAT-TOKEN-0123456789abcdef01234567";
static const std::string kDashdUrl = "http://127.0.0.1:9998";
static const std::string kNodeUrl = "http://127.0.0.1:8080";

static void put(const std::string& path, const std::string& text, mode_t mode = 0600)
{
    ::unlink(path.c_str());
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f) {
        std::fwrite(text.data(), 1, text.size(), f);
        std::fclose(f);
    }
    ::chmod(path.c_str(), mode);
}

static bool present(const std::string& path) { return std::filesystem::exists(path); }

struct RpcRef : RpcApi {
    FakeDashd* d;
    explicit RpcRef(FakeDashd* x) : d(x) {}
    RpcReply call(const std::string& m, const std::string& p) override { return d->call(m, p); }
    RpcReply call_long(const std::string& m, const std::string& p, const CancelCheck& c,
                       const std::function<void()>& on_cancel) override
    {
        return d->call_long(m, p, c, on_cancel);
    }
    const char* name() const override { return "fake-dashd-ref"; }
};

struct NodeRef : sched::NodeApi {
    FakeUtxoNode* n;
    explicit NodeRef(FakeUtxoNode* x) : n(x) {}
    sched::HttpReply get(const std::string& p) override { return n->get(p); }
    sched::HttpReply post_json(const std::string& p, const std::string& b) override { return n->post_json(p, b); }
    const char* name() const override { return "fake-node-ref"; }
};

struct FixedClock : sched::Clock {
    int64_t t = 1793600000;
    int64_t now_unix() const override { return t; }
    int64_t monotonic_ms() const override { return t * 1000; }
};

struct World {
    FakeDashd dashd;
    FakeUtxoNode node;
    FixedClock clock;
    std::ostringstream out, err;
    std::string dir, auth, token, queue;
    std::vector<std::string> rpc_urls, rpc_auth;
    bool cancel = false;

    World()
    {
        char tmpl[] = "/tmp/c2w-scan-cli-XXXXXX";
        dir = ::mkdtemp(tmpl) ? std::string(tmpl) : std::string("/tmp");
        auth = dir + "/dashd.auth";
        put(auth, "__cookie__:0123456789abcdef0123456789abcdef\n");
        token = dir + "/control.token";
        put(token, std::string(kTokenText) + "\n");
        queue = dir + "/queue.json";
        dashd.rows = fixture_rows();
        node.rows = fixture_rows();
    }
    ~World() { std::filesystem::remove_all(dir); }

    int run(const std::vector<std::string>& args)
    {
        out.str("");
        err.str("");
        sched::cli::Env env;
        env.out = &out;
        env.err = &err;
        env.clock = &clock;
        env.make_api = [this](const std::string&, std::string&) -> std::unique_ptr<sched::NodeApi> {
            return std::make_unique<NodeRef>(&node);
        };
        env.make_rpc = [this](const std::string& url, const std::string& a, std::string&) -> std::unique_ptr<RpcApi> {
            rpc_urls.push_back(url);
            rpc_auth.push_back(a);
            return std::make_unique<RpcRef>(&dashd);
        };
        env.sleep_ms = [](int64_t) {};
        env.stop_requested = [this] { return cancel; };
        env.default_queue_path = queue;
        return sched::cli::run(args, env);
    }
    std::vector<std::string> dashd_args() const
    {
        return {"--dashd-url", kDashdUrl, "--dashd-auth-file", auth};
    }
    std::string all() const { return out.str() + err.str(); }
};

static std::vector<std::string> cat(std::vector<std::string> a, const std::vector<std::string>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

static std::string slurp(const std::string& p) { return read_file(p); }

// ── C1 / C2 / C3 ────────────────────────────────────────────────────────────
static void c1_c2_c3_usage()
{
    std::printf("[C1-C3 credentials by value, loopback only, usage errors]\n");
    World w;
    CHECK(w.run({"scan", "--address", kXdgf, "--dashd-auth", "s3cret"}) == 2 &&
              w.err.str().find("no --dashd-auth VALUE") != std::string::npos && w.rpc_urls.empty() && w.dashd.calls.empty(),
          "C1: scan --dashd-auth VALUE refused before anything runs");
    CHECK(w.run({"scan", "--address", kXdgf, "--rpcpassword=x"}) == 2, "C1: --rpcpassword=VALUE refused");
    CHECK(w.run({"preflight", "--hex", "x.hex", "--dashd-password", "x"}) == 2, "C1: preflight --dashd-password refused");
    CHECK(w.run({"add", "--hex", "x.hex", "--preflight", "--dashd-auth=x"}) == 2, "C1: add --preflight --dashd-auth= refused");
    CHECK(w.err.str().find("s3cret") == std::string::npos, "C1: the value is never echoed");

    CHECK(w.run(cat({"scan", "--address", kXdgf, "--source", "dashd", "--dashd-url", "http://10.0.0.5:9998", "--dashd-auth-file", w.auth}, {})) == 2 &&
              w.err.str().find("--dashd-url") != std::string::npos && w.rpc_urls.empty(),
          "C2: a non-loopback dashd URL refused");
    CHECK(w.run({"scan", "--address", kXdgf, "--source", "dashd", "--dashd-url", "https://127.0.0.1:9998", "--dashd-auth-file", w.auth}) == 2,
          "C2: https (TLS on loopback) refused");
    CHECK(w.run({"--node-url", "http://192.168.1.5:8080", "scan", "--address", kXdgf}) == 2, "C2: a non-loopback node URL refused");

    CHECK(w.run({"scan"}) == 2, "C3: scan without --address");
    CHECK(w.run({"scan", "--address", kXdgf, "--source", "dashd"}) == 2, "C3: --source dashd without --dashd-url");
    CHECK(w.run({"scan", "--address", kXdgf, "--source", "bogus"}) == 2, "C3: unknown source");
    CHECK(w.run({"scan", "--address", kXdgf, "--destination", kOther}) == 2 &&
              w.err.str().find("typed twice") != std::string::npos,
          "C3: an external destination needs --destination-confirm");
    CHECK(w.run({"scan", "--address", kXdgf, "--destination", kOther, "--destination-confirm", kXdgf}) == 2,
          "C3: a confirm that differs is refused");
    CHECK(w.run({"plan", "--stage2", "--mode", "collateral"}) == 2, "C3: plan --stage2 takes its parameters from the sidecar");
    CHECK(w.run({"add", "--hex", "x.hex", "--utxos", "u.json"}) == 2, "C3: preflight options without --preflight");
    CHECK(w.run({"help"}) == 0 && w.out.str().find("scan --address ADDR") != std::string::npos &&
              w.out.str().find("There is no --dashd-auth VALUE") != std::string::npos,
          "C3: help lists the scan commands");
}

// ── C4 ──────────────────────────────────────────────────────────────────────
static void c4_scan_end_to_end()
{
    std::printf("[C4 scan end to end: both sources -> utxos / scanplan / report / c2wu]\n");
    World w;
    const std::string base = w.dir + "/xdgf";
    const auto args = cat(cat({"--node-url", kNodeUrl, "scan", "--address", kXdgf, "--source", "both"}, w.dashd_args()),
                          {"--out", base, "--emit-c2wu", "--key-encoding", "compressed"});
    CHECK(w.run(args) == 0, "scan exits 0");
    CHECK(w.rpc_urls == std::vector<std::string>{kDashdUrl} && w.rpc_auth == std::vector<std::string>{w.auth},
          "the dashd transport got the URL and the credentials FILE (never a value)");
    CHECK(w.out.str().find("via both (cross-checked)") != std::string::npos, "cross-checked scan reported");
    CHECK(present(base + ".utxos.json") && present(base + ".scanplan.json") && present(base + ".report.txt") &&
              present(base + ".c2wu.hex"),
          "the four files exist");
    dash::UtxoImport imp;
    CHECK(runs([&] { imp = dash::parse_utxo_export_v1(slurp(base + ".utxos.json"), false); }, "parse") &&
              imp.utxos.size() == 170 && imp.coinbase_flags,
          "the export imports in the signer (170 rows, flags known)");
    const oj sp = oj::parse(slurp(base + ".scanplan.json"));
    CHECK(sp["source"]["kind"] == "both" && sp["source"]["cross_checked"] == true && sp["expected"]["tx_count"] == 1 &&
              sp["utxos_file_sha256"] == sha_hex(slurp(base + ".utxos.json")) && sp["params"]["key_encoding"] == "compressed",
          "the sidecar: both sources, bound to the export, the stated key encoding");
    const std::string rep = slurp(base + ".report.txt");
    CHECK(rep.find("add --hex xdgf.hex --manifest xdgf.manifest.json") != std::string::npos, "the report prints the add line");
    std::string err;
    const std::string c2wu_line = slurp(base + ".c2wu.hex").substr(0, slurp(base + ".c2wu.hex").find('\n'));
    CHECK(art::UnsignedContainer::from_hex(c2wu_line, err).has_value(), "the C2WU container parses");
    CHECK(w.run(args) == 1 && w.err.str().find("exists") != std::string::npos, "a second scan does not overwrite");
    CHECK(w.run(cat(args, {"--overwrite"})) == 0, "--overwrite replaces them");
    // A node that cannot serve: refused unless a single source is allowed.
    w.node.mode = "accrual";
    const auto single = cat(cat({"scan", "--address", kXdgf, "--source", "both"}, w.dashd_args()), {"--out", w.dir + "/one"});
    CHECK(w.run(single) == 1 && w.err.str().find("scan-node-utxo-not-full") != std::string::npos, "node not full: refused");
    CHECK(w.run(cat(single, {"--allow-single-source"})) == 0 &&
              oj::parse(slurp(w.dir + "/one.scanplan.json"))["source"]["cross_checked"] == false,
          "--allow-single-source: written with cross_checked false");
}

// ── C5 ──────────────────────────────────────────────────────────────────────
static void c5_preflight_and_add()
{
    std::printf("[C5 preflight and add --preflight]\n");
    World w;
    const std::string base = w.dir + "/xdgf";
    CHECK(w.run(cat(cat({"scan", "--address", kXdgf, "--source", "dashd"}, w.dashd_args()), {"--out", base})) == 0, "scanned");
    PlanParams pp;
    const ScanPlan plan = make_plan(dash::parse_utxo_export_v1(slurp(base + ".utxos.json"), false), pp);
    CHECK(oj::parse(slurp(base + ".scanplan.json"))["expected"]["plan_id"] == plan.plan_id, "the test re-derives the CLI's plan");
    const std::string line = fake_signed(plan.batches.at(0));
    put(base + ".hex", line + "\n", 0644);
    put(base + ".manifest.json", manifest_for(plan, line + "\n", {line}), 0644);
    w.node.post_handler = [](const std::string&, const std::string& b) { return validate_reply(b); };
    const auto pre = cat(cat({"--node-url", kNodeUrl, "--token-file", w.token, "preflight", "--hex", base + ".hex", "--utxos",
                              base + ".utxos.json", "--scanplan", base + ".scanplan.json", "--source", "dashd"},
                             w.dashd_args()),
                         {});
    CHECK(w.run(pre) == 0 && w.out.str().find("preflight: PASS") != std::string::npos && w.node.posts.size() == 1,
          "a clean pair passes (dry run posted once)");
    const dash::Utxo& in0 = plan.batches[0].inputs[0];
    w.dashd.spent.insert({in0.txid, in0.vout});
    CHECK(w.run(pre) == 1 && w.out.str().find("REFUSED: input " + in0.txid) != std::string::npos, "a spent input refuses");
    CHECK(w.run(cat(pre, {"--force", "operator says so"})) == 1, "--force does not pass a spent input");
    w.dashd.spent.clear();
    w.node.post_handler = [](const std::string&, const std::string& b) { return validate_reply(b, "inject-input-spent-in-mempool"); };
    CHECK(w.run(pre) == 1 && w.out.str().find("dry run inject-input-spent-in-mempool") != std::string::npos,
          "a non-ok dry run refuses");
    CHECK(w.run(cat(pre, {"--force", "checked the pool tx by hand"})) == 0 && w.out.str().find("FORCED") != std::string::npos,
          "--force passes it with a warning");
    // L1: --source none and a node that does not answer: not a PASS.
    w.node.post_handler = [](const std::string&, const std::string&) { return sched::HttpReply{false, 0, "", "connection refused"}; };
    const std::vector<std::string> none = {"--node-url", kNodeUrl, "--token-file", w.token, "preflight", "--hex",
                                           base + ".hex", "--source", "none"};
    CHECK(w.run(none) == 1 && w.out.str().find("UNKNOWN: (d)") != std::string::npos &&
              w.out.str().find("preflight: FAILED") != std::string::npos,
          "L1: --source none with a dead node: FAILED (UNKNOWN)");
    CHECK(w.run(cat(none, {"--force", "node restarting, checked by hand"})) == 0 &&
              w.out.str().find("preflight: PASS (forced) (checks run: a)") != std::string::npos,
          "L1: forced with a reason; the PASS line says only (a) ran");
    w.node.post_handler = [](const std::string&, const std::string& b) { return validate_reply(b, "inject-input-spent-in-mempool"); };

    // add --preflight: refused -> nothing queued; forced -> queued with the reason journaled.
    CHECK(w.run({"--queue", w.queue, "--node-url", kNodeUrl, "--token-file", w.token, "init"}) == 0, "queue created");
    const auto add = cat(cat({"--queue", w.queue, "--node-url", kNodeUrl, "--token-file", w.token, "add", "--hex",
                              base + ".hex", "--label", "kat", "--preflight", "--utxos", base + ".utxos.json",
                              "--scanplan", base + ".scanplan.json", "--source", "dashd"},
                             w.dashd_args()),
                         {});
    sched::Queue q;
    std::string why;
    CHECK(w.run(add) == 1 && w.err.str().find("nothing was queued") != std::string::npos &&
              sched::load_queue_file(w.queue, q, why) && q.items.empty(),
          "add --preflight refused by the dry run: nothing queued");
    CHECK(w.run(cat(add, {"--force", "checked the pool tx by hand"})) == 0 && sched::load_queue_file(w.queue, q, why) &&
              q.items.size() == 1,
          "add --preflight --force: queued");
    bool forced = false, pre_ok = false;
    for (const auto& je : q.items.at(0).journal) {
        forced |= je.event == "preflight_forced" && je.detail.find("checked the pool tx by hand") != std::string::npos;
        pre_ok |= je.event == "preflight";
    }
    CHECK(forced && pre_ok, "the preflight and the operator's reason are journaled on the item");
    CHECK(q.arm_policy.auto_arm == false && !q.arm_policy.consented_at, "add --preflight never touches the arm policy");
}

// ── C6 ──────────────────────────────────────────────────────────────────────
static size_t maturity_alerts(const std::string& queue)
{
    sched::Queue q;
    std::string why;
    if (!sched::load_queue_file(queue, q, why)) return 999;
    size_t n = 0;
    for (const auto& a : q.alerts) n += a.kind == "maturity";
    return n;
}

static void c6_watch()
{
    std::printf("[C6 watch: arrivals and one maturity alert per crossing]\n");
    World w;
    CHECK(w.run({"--queue", w.queue, "--node-url", kNodeUrl, "init"}) == 0, "queue created");
    const auto watch = std::vector<std::string>{"--queue", w.queue, "--node-url", kNodeUrl, "watch", "--address", kXdgf,
                                                "--source", "c2pool", "--once"};
    CHECK(w.run(watch) == 0 && w.out.str().find("ALERT maturity: " + std::string(kXdgf) + ": 128 mature") != std::string::npos &&
              maturity_alerts(w.queue) == 1,
          "first scan: 128 mature >= 100: one queue alert");
    CHECK(present(w.dir + "/watch.json"), "the state file sits beside the queue");
    CHECK(w.run(watch) == 0 && w.out.str().find("ALERT") == std::string::npos && w.out.str().find("queued; 0 new") != std::string::npos &&
              maturity_alerts(w.queue) == 1,
          "second scan: nothing new, no second alert");
    const auto rows = w.node.rows;
    w.node.rows = synthetic_rows(kXdgf, 5, 50000, 2500000);
    CHECK(w.run(watch) == 0 && maturity_alerts(w.queue) == 1, "after a sweep: below the policy, no alert");
    w.node.rows = rows;
    CHECK(w.run(watch) == 0 && maturity_alerts(w.queue) == 2, "the next crossing: the second alert");
    CHECK(w.run({"--queue", w.queue, "status"}) == 1, "status reports the pending alert");
}

// ── C7 ──────────────────────────────────────────────────────────────────────
static void c7_stage2()
{
    std::printf("[C7 plan --stage2 and the stage-2 fence of add (M1)]\n");
    World w;
    const int64_t tip = 2600000;
    put(w.dir + "/big.utxos.json", write_export_v1(import_of(synthetic_rows(kXdgf, 700, 200000, 2500000), tip)), 0644);
    const std::string s1 = w.dir + "/s1", s2 = w.dir + "/s2";
    CHECK(w.run({"plan", "--utxos", w.dir + "/big.utxos.json", "--mode", "collateral", "--gov-hash", kGov, "--out", s1}) == 0,
          "stage 1 planned from the export");
    const oj sp1 = oj::parse(slurp(s1 + ".scanplan.json"));
    CHECK(sp1["expected"]["two_stage"] == true && sp1["expected"]["batches"][2]["heights_projected"] == true,
          "two stages; the stage-2 batch marked projected");
    PlanParams coll;
    coll.mode = PlanMode::Collateral;
    coll.gov_hash = kGov;
    const ScanPlan plan1 = make_plan(dash::parse_utxo_export_v1(slurp(s1 + ".utxos.json"), false), coll);
    const std::string t1 = fake_signed(plan1.batches.at(0)), t2 = fake_signed(plan1.batches.at(1));
    put(s1 + ".hex", t1 + "\n" + t2 + "\n", 0644);
    const auto stage2 = std::vector<std::string>{"plan", "--stage2", "--utxos", s1 + ".utxos.json", "--scanplan",
                                                 s1 + ".scanplan.json", "--stage1-hex", s1 + ".hex", "--landing-height",
                                                 "2600002", "--out", s2};
    CHECK(w.run(stage2) == 0, "plan --stage2 writes the stage-2 set");
    const dash::UtxoImport imp2 = dash::parse_utxo_export_v1(slurp(s2 + ".utxos.json"), false);
    CHECK(imp2.tip_hash == "projected:2600002" && imp2.utxos.size() == 2 && imp2.utxos[0].txid == art::crossgap_txid(t1),
          "the intake: the two stage-1 txids, projected");
    CHECK(slurp(s2 + ".report.txt").find("HEIGHTS ARE PROJECTED") != std::string::npos &&
              oj::parse(slurp(s2 + ".scanplan.json"))["source"]["heights_projected"] == true,
          "report and sidecar say the heights are projected");
    // A stage-1 hex that is not the planned stage 1 is refused.
    const auto& b0 = plan1.batches.at(0);
    put(s1 + ".bad.hex", fake_signed(b0.inputs, {{b0.value_out - 1, b0.outputs[0].second}}) + "\n" + t2 + "\n", 0644);
    auto bad = stage2;
    bad[7] = s1 + ".bad.hex";
    bad.back() = w.dir + "/s2bad";
    CHECK(w.run(bad) == 1 && w.err.str().find("not the planned stage-1 batch") != std::string::npos,
          "a tampered stage-1 tx is refused");
    // The signed stage-2 pair queues only behind both parents.
    PlanParams coll2 = coll;
    const ScanPlan plan2 = make_plan(imp2, coll2);
    const std::string l2 = fake_signed(plan2.batches.at(0));
    put(s2 + ".hex", l2 + "\n", 0644);
    put(s2 + ".manifest.json", manifest_for(plan2, l2 + "\n", {l2}), 0644);
    CHECK(w.run({"--queue", w.queue, "add", "--hex", s2 + ".hex"}) == 1 && w.err.str().find("projected") != std::string::npos,
          "add without --after-parent: refused");
    CHECK(w.run({"--queue", w.queue, "add", "--hex", s2 + ".hex", "--no-manifest", "--inputs-known-mature", "trust me"}) == 1 &&
              w.err.str().find("projected") != std::string::npos,
          "M-A: add --no-manifest --inputs-known-mature: still refused (the manifest beside the hex marks it)");
    CHECK(w.run({"--queue", w.queue, "add", "--hex", s2 + ".hex", "--no-manifest", "--not-before-height", "2600010"}) == 1,
          "M-A: add --no-manifest --not-before-height: still refused");
    CHECK(w.run({"--queue", w.queue, "add", "--hex", s2 + ".hex", "--after-parent", art::crossgap_txid(t1), "--after-parent",
                 art::crossgap_txid(t2)}) == 0,
          "add with both parents: queued");
}

// ── C8 ──────────────────────────────────────────────────────────────────────
static void c8_cancel()
{
    std::printf("[C8 Ctrl-C during scantxoutset: the scan is aborted]\n");
    World w;
    w.dashd.addressindex = false;
    w.dashd.long_hook = [&w](FakeDashd&) { w.cancel = true; };
    CHECK(w.run(cat(cat({"scan", "--address", kXdgf, "--source", "dashd"}, w.dashd_args()), {"--out", w.dir + "/c"})) == 1 &&
              w.err.str().find("scan-cancelled") != std::string::npos && w.dashd.aborts == 1 && !present(w.dir + "/c.utxos.json"),
          "refused as cancelled, scantxoutset aborted, nothing written");
}

// ── C9 ──────────────────────────────────────────────────────────────────────
static void c9_credentials_file()
{
    std::printf("[C9 the dashd credentials file]\n");
    World w;
    const std::string f = w.dir + "/auth";
    c2w::secure::SecureString s;
    std::string why;
    put(f, "rpcuser:rpc-password-1\n", 0600);
    CHECK(read_rpc_auth_file(f, s, why) && s.size() == std::string("rpcuser:rpc-password-1").size(), "0600 user:password reads");
    put(f, "rpcuser:pw\n", 0400);
    CHECK(read_rpc_auth_file(f, s, why), "0400 reads");
    put(f, "rpcuser:pw\n", 0644);
    CHECK(!read_rpc_auth_file(f, s, why) && why.find("group or other") != std::string::npos && s.empty(), "0644 refused");
    put(f, "nocolon\n", 0600);
    CHECK(!read_rpc_auth_file(f, s, why) && why.find("user:password") != std::string::npos, "no colon refused");
    put(f, ":pw\n", 0600);
    CHECK(!read_rpc_auth_file(f, s, why), "empty user refused");
    put(f, "user:\n", 0600);
    CHECK(!read_rpc_auth_file(f, s, why), "empty password refused");
    put(f, "user:pass word\n", 0600);
    CHECK(!read_rpc_auth_file(f, s, why) && why.find("whitespace") != std::string::npos, "whitespace refused");
    put(f, "user:pw\n", 0600);
    const std::string link = w.dir + "/auth.link";
    CHECK(::symlink(f.c_str(), link.c_str()) == 0 && !read_rpc_auth_file(link, s, why) && why.find("symlink") != std::string::npos,
          "a symlink refused");
    CHECK(!read_rpc_auth_file(w.dir + "/missing", s, why), "a missing file refused");
    CHECK(why.find("pw") == std::string::npos, "no refusal quotes the content");
    const c2w::secure::SecureString a(std::string("Aladdin:opensesame"));
    const c2w::secure::SecureString b = basic_auth_value(a);
    CHECK(std::string(reinterpret_cast<const char*>(b.bytes()), b.size()) == "QWxhZGRpbjpvcGVuc2VzYW1l",
          "basic_auth_value is base64 (RFC 7617)");
    const c2w::secure::SecureString c = basic_auth_value(c2w::secure::SecureString(std::string("__cookie__:ab")));
    CHECK(std::string(reinterpret_cast<const char*>(c.bytes()), c.size()) == "X19jb29raWVfXzphYg==", "padding");
}

int main()
{
    std::printf("=== companion scan & plan CLI KATs (C1-C9) ===\n");
    c1_c2_c3_usage();
    c4_scan_end_to_end();
    c5_preflight_and_add();
    c6_watch();
    c7_stage2();
    c8_cancel();
    c9_credentials_file();
    std::printf("\n== scan CLI KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
