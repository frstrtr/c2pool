// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the companion's Scan & Plan core (slice S-B, K1-K16). No network,
// no Qt, no key: the binary links the key-free companion library (and through
// it the key-free c2wallet-dash-plan), and ci/check_key_free.sh runs over it
// as companion_scan_key_free_guard.
//
// Fixtures:
//   * the REAL dashd getaddressutxos capture of XdgF55... at tip 2563986
//     (family/bitcoin/dash/tests/fixtures, 170 rows) drives FakeDashd and
//     FakeUtxoNode. Coinbase flags follow tests/mock_dash_cli.py (outputIndex
//     1 = non-coinbase), the tip hash is the mock's.
//   * SYNTHESISED shapes, marked as such where they are built: the
//     scantxoutset reply FakeDashd serves (from the same rows, the field set of
//     the real capture below and the RPC help text) and the c2pool
//     /api/utxo/scan reply FakeUtxoNode serves (the N1 shape of the design;
//     the endpoint is a separate node slice).
//   * the REAL recorded read-only dashd session from vm210 (Dash Core 23.1.7,
//     no addressindex: getaddressutxos -32600, scantxoutset, gettxout per row)
//     at tip 2565514, replayed by ReplayRpc (K2b).
//
// `--write-mock-export OUT` writes the export of the mock_dash_cli.py chain
// view (ctest companion_scan_export_parity compares it byte for byte with
// tools/export_utxos.py run against that mock).

#include "../scan/Classifier.hpp"
#include "../scan/CrossCheck.hpp"
#include "../scan/Planner.hpp"
#include "../scan/RpcApi.hpp"
#include "../scan/ScanFiles.hpp"
#include "../scan/ScanTypes.hpp"
#include "../scan/SourceC2pool.hpp"
#include "../scan/SourceDashd.hpp"

#include "../sched/InjectQueue.hpp"
#include "../sched/NodeApi.hpp"

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"
#include "TransferContainer.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using oj = nlohmann::ordered_json;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

#include "scan_fakes.hpp"

#ifndef C2W_SCAN_FIXTURE_DIR
#error "C2W_SCAN_FIXTURE_DIR must point at companion/tests/fixtures"
#endif

using namespace scan_kat;

static std::string g_k1_export; // the reference export bytes (K1)

// ── K1 ──────────────────────────────────────────────────────────────────────
static void k1_export_v1_round_trip()
{
    std::printf("[K1 getaddressutxos fixture -> export v1 -> the signer's parse_utxo_export_v1]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    ScanResult r;
    CHECK(runs([&] { r = dashd_scan(d); }, "scan"), "dashd scan runs");
    CHECK(r.source == kSourceDashdIndex, "source dashd-addressindex");
    CHECK(r.tip_height == kTip && r.tip_hash == tip_hash_of(kTip), "tip from the chainInfo object");
    CHECK(r.imports.size() == 1 && r.imports[0].utxos.size() == 170, "170 rows");
    CHECK(r.mempool_spent.empty(), "nothing spent in the mempool");
    CHECK(d.count("getaddressutxos") == 1 && d.count("getblockcount") == 1 && d.count("gettxout") == 170,
          "one stable read, one gettxout per row");
    const dash::UtxoImport& imp = r.imports.at(0);
    CHECK(imp.coinbase_flags && imp.total == 60963705 && imp.address == kXdgf, "flags known, total, address");
    bool sorted = true;
    for (size_t i = 1; i < imp.utxos.size(); ++i)
        if (std::tie(imp.utxos[i - 1].height, imp.utxos[i - 1].txid, imp.utxos[i - 1].vout) >=
            std::tie(imp.utxos[i].height, imp.utxos[i].txid, imp.utxos[i].vout))
            sorted = false;
    CHECK(sorted, "rows sorted by (height, txid, vout)");
    size_t noncb = 0;
    for (const auto& u : imp.utxos) noncb += (u.coinbase == false);
    CHECK(noncb == 1, "coinbase flags from gettxout (one non-coinbase row)");

    g_k1_export = export_of(r);
    dash::UtxoImport back;
    CHECK(runs([&] { back = dash::parse_utxo_export_v1(g_k1_export, false); }, "parse_utxo_export_v1"),
          "the signer's export-v1 importer accepts it");
    CHECK(back.source == dash::UtxoSource::ExportV1 && back.coinbase_flags, "export v1, coinbase flags present");
    CHECK(back.tip_height == kTip && back.tip_hash == tip_hash_of(kTip) && back.address == kXdgf, "tip and address");
    CHECK(same_rows(back.utxos, imp.utxos), "equal rows (txid, vout, satoshis, height, confirmations, coinbase, script)");
    CHECK(back.total == imp.total, "equal total");
    dash::UtxoImport auto_back;
    CHECK(runs([&] { auto_back = dash::parse_utxo_json(g_k1_export, 0, false); }, "parse_utxo_json") &&
              auto_back.source == dash::UtxoSource::ExportV1 && same_rows(auto_back.utxos, imp.utxos),
          "the auto-detecting intake (PageDashInject stage 1) reads it as export v1");
    CHECK(g_k1_export.rfind("{\n \"schema\": \"c2wallet-utxo-export/1\",\n \"coin\": \"dash\",\n", 0) == 0 &&
              g_k1_export.back() == '}',
          "export_utxos.py layout (indent 1, no trailing newline)");
    CHECK(refuses([&] { (void)write_export_v1(dash::UtxoImport{}); }, cause::kNothingToExport),
          "an empty import is not exported");
}

// ── K16 ─────────────────────────────────────────────────────────────────────
static void k16_index_or_output_index()
{
    std::printf("[K16 getaddressutxos: the help text's `index` and the real `outputIndex` both parse]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    d.index_field = "index";
    ScanResult r;
    CHECK(runs([&] { r = dashd_scan(d); }, "scan"), "scan with `index` runs");
    CHECK(!g_k1_export.empty() && export_of(r) == g_k1_export, "identical export bytes");
    FakeDashd bare;
    bare.rows = fixture_rows();
    bare.chain_info = false;
    ScanResult b;
    CHECK(runs([&] { b = dashd_scan(bare); }, "scan"), "a dashd ignoring chainInfo (bare array) still scans");
    CHECK(export_of(b) == g_k1_export && bare.count("getblockhash") == 1, "identical bytes; tip hash by getblockhash");
}

// ── K2 ──────────────────────────────────────────────────────────────────────
static void k2_scantxoutset_fallback()
{
    std::printf("[K2 no addressindex (-32600) -> scantxoutset (SYNTHESISED from the same rows) -> identical export]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    d.addressindex = false;
    ScanResult r;
    CHECK(runs([&] { r = dashd_scan(d); }, "scan"), "scan runs");
    CHECK(r.source == kSourceDashdScan, "source dashd-scantxoutset");
    CHECK(r.warning.find("-32600") != std::string::npos, "the fallback is named");
    CHECK(r.dashd_detail == "dashd scantxoutset txouts=4530592", "detail");
    CHECK(d.count("scantxoutset") == 1 && d.count("getbestblockhash") == 1, "one scan, tip re-read after it");
    CHECK(export_of(r) == g_k1_export, "byte-identical to the addressindex export");

    FakeDashd moved;
    moved.rows = fixture_rows();
    moved.addressindex = false;
    int scans = 0;
    moved.hook = [&](FakeDashd& f, const std::string& m) {
        if (m == "getbestblockhash" && ++scans == 1) ++f.tip; // a block arrives under the first scan
    };
    ScanResult r2;
    CHECK(runs([&] { r2 = dashd_scan(moved); }, "scan"), "a tip moved under the scan: retried once");
    CHECK(moved.count("scantxoutset") == 2 && r2.tip_height == kTip + 1, "second scan at the new tip");
    FakeDashd always;
    always.rows = fixture_rows();
    always.addressindex = false;
    always.hook = [](FakeDashd& f, const std::string& m) { if (m == "getbestblockhash") ++f.tip; };
    CHECK(refuses([&] { dashd_scan(always); }, cause::kTipUnstable), "a tip moving under every scan refuses");
    CHECK(always.count("scantxoutset") == 2, "after one retry");
}

// ── K2b ─────────────────────────────────────────────────────────────────────
static void k2b_real_vm210_session()
{
    std::printf("[K2b the REAL recorded vm210 session (23.1.7, no addressindex) replayed]\n");
    ReplayRpc rpc(std::string(C2W_SCAN_FIXTURE_DIR) + "/xdgf-dashd-scantxoutset-session-vm210-tip2565514.json");
    SourceDashd s(rpc);
    ScanResult r;
    CHECK(runs([&] { r = s.scan({kXdgf}, ScanOptions{}); }, "scan"), "the recorded session scans");
    CHECK(rpc.unrecorded == 0, "every call the source made was recorded on vm210");
    CHECK(r.source == kSourceDashdScan && r.tip_height == 2565514, "scantxoutset at tip 2565514");
    CHECK(r.tip_hash == rpc.doc()["calls"][3]["result"].get<std::string>(), "tip hash = getbestblockhash");
    CHECK(r.dashd_detail.rfind("dashd scantxoutset txouts=", 0) == 0, "txouts recorded");
    const dash::UtxoImport& imp = r.imports.at(0);
    CHECK(imp.utxos.size() == 16 && imp.total == 11223569, "16 rows, 0.11223569 DASH");
    size_t cb = 0, one_duff = 0;
    for (const auto& u : imp.utxos) {
        cb += u.coinbase == true;
        one_duff += u.satoshis == 1;
    }
    CHECK(cb == 15 && one_duff == 15, "15 one-duff coinbase donation outputs + 1 non-coinbase change output");
    dash::UtxoImport back;
    CHECK(runs([&] { back = dash::parse_utxo_export_v1(export_of(r), false); }, "parse"), "export parses in the signer");
    CHECK(same_rows(back.utxos, imp.utxos), "equal rows");
    Classification c = classify(imp, r.mempool_spent, {}, ClassifyParams{});
    CHECK(c.mature.size() == 1 && c.dust.size() == 15 && c.immature.empty(), "1 mature (non-coinbase, 1 conf rule) / 15 dust");
    ScanPlan p;
    CHECK(runs([&] { p = make_plan(c.exportable, PlanParams{}); }, "plan"), "plans");
    CHECK(p.batches.size() == 1 && p.batches[0].vin == 1 && p.batches[0].value_out == 11223554,
          "one batch: the 0.11223554 change output alone");
}

// ── K3 ──────────────────────────────────────────────────────────────────────
static void k3_c2pool_n1_shape()
{
    std::printf("[K3 c2pool /api/utxo/scan (SYNTHESISED N1 shape) -> identical export; node postures]\n");
    FakeUtxoNode n;
    n.rows = fixture_rows();
    SourceC2pool s(n);
    ScanResult r;
    CHECK(runs([&] { r = s.scan({kXdgf}, ScanOptions{}); }, "scan"), "scan runs");
    CHECK(n.paths.size() == 1 && n.paths[0] == "/api/utxo/scan?address=" + std::string(kXdgf) + "&exclude_mempool_spent=1",
          "the N1 request path");
    CHECK(r.source == kSourceC2pool && r.c2pool_detail == "utxo full serving coins=4531254", "source and posture");
    CHECK(export_of(r) == g_k1_export, "byte-identical to the dashd export");

    auto refusal = [&](std::function<void(FakeUtxoNode&)> set, const char* cause_name) {
        FakeUtxoNode m;
        m.rows = fixture_rows();
        set(m);
        SourceC2pool src(m);
        return refuses([&] { src.scan({kXdgf}, ScanOptions{}); }, cause_name);
    };
    CHECK(refusal([](FakeUtxoNode& m) { m.mode = "accrual"; }, cause::kNodeUtxoNotFull), "accrual view refused");
    CHECK(refusal([](FakeUtxoNode& m) { m.state = "withheld"; }, cause::kNodeUtxoNotFull), "withheld refused");
    CHECK(refusal([](FakeUtxoNode& m) { m.status = 409; m.error_body = R"({"ok":false,"error":"utxo-set-catching-up"})"; },
                  cause::kNodeUtxoNotFull),
          "409 utxo-set-catching-up refused");
    CHECK(refusal([](FakeUtxoNode& m) { m.status = 404; m.error_body = "Not Found"; }, cause::kNodeNoRoute),
          "an older node without the route");
    CHECK(refusal([](FakeUtxoNode& m) { m.status = 403; m.error_body = R"({"error":"utxo-scan-local-only"})"; },
                  cause::kNodeRefused),
          "403 local-only");
    CHECK(refusal([](FakeUtxoNode& m) { m.status = 429; m.error_body = R"({"error":"utxo-scan-rate"})"; }, cause::kNodeRefused),
          "429 rate");
    CHECK(refusal([](FakeUtxoNode& m) { m.truncated = true; }, cause::kTruncated), "a truncated set is never exported");
    CHECK(refusal([](FakeUtxoNode& m) { m.echo_script_override = kXdgfScript + std::string("00"); }, cause::kSourceInconsistent),
          "the node matched another script");
    CHECK(refusal([](FakeUtxoNode& m) { m.total_value_delta = 1; }, cause::kSourceInconsistent), "total_value disagrees");
    CHECK(refusal([](FakeUtxoNode& m) { m.tip_moved_times = 3; }, cause::kTipUnstable), "tip_moved three times refuses");
    FakeUtxoNode m2;
    m2.rows = fixture_rows();
    m2.tip_moved_times = 2;
    SourceC2pool s2(m2);
    ScanResult r2;
    CHECK(runs([&] { r2 = s2.scan({kXdgf}, ScanOptions{}); }, "scan") && m2.paths.size() == 3 &&
              export_of(r2) == g_k1_export,
          "tip_moved twice: the third read is used");
}

// ── K4 / K5 ─────────────────────────────────────────────────────────────────
static void k4_both_equal()
{
    std::printf("[K4 both sources equal -> cross_checked]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    FakeUtxoNode n;
    n.rows = fixture_rows();
    SourceDashd sd(d);
    SourceC2pool sc(n);
    ScanResult r;
    CHECK(runs([&] { r = scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, "scan_both"), "runs");
    CHECK(r.cross_checked && r.source == kSourceBoth, "cross_checked, source both");
    CHECK(r.dashd_detail == "dashd addressindex" && r.c2pool_detail == "utxo full serving coins=4531254", "both details");
    CHECK(export_of(r) == g_k1_export, "identical export");
}

static void k5_one_value_altered()
{
    std::printf("[K5 one value altered on one side -> scan-source-mismatch naming the outpoint]\n");
    const std::vector<Row> rows = fixture_rows();
    FakeDashd d;
    d.rows = rows;
    FakeUtxoNode n;
    n.rows = rows;
    const Outpoint o{rows[10].txid, rows[10].vout};
    n.value_override[o] = rows[10].sat + 1;
    SourceDashd sd(d);
    SourceC2pool sc(n);
    std::string what;
    CHECK(refuses([&] { scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, cause::kSourceMismatch, &what),
          "refused");
    CHECK(what.find(outpoint_str(o) + " value " + std::to_string(rows[10].sat) + " != " + std::to_string(rows[10].sat + 1)) !=
              std::string::npos,
          "the outpoint and both values are named");

    FakeUtxoNode missing;
    missing.rows = rows;
    missing.rows.erase(missing.rows.begin() + 3);
    SourceC2pool sm(missing);
    FakeDashd d2;
    d2.rows = rows;
    SourceDashd sd2(d2);
    CHECK(refuses([&] { scan_both(sd2, sm, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, cause::kSourceMismatch, &what) &&
              what.find(rows[3].txid + ":" + std::to_string(rows[3].vout) + " only in dashd-addressindex") != std::string::npos,
          "a row only one side reports is named");
}

// ── K6 / K7 ─────────────────────────────────────────────────────────────────
static void k6_tips_converge()
{
    std::printf("[K6 tips differ, then converge on a re-read]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    FakeUtxoNode n;
    n.rows = fixture_rows();
    n.tip = kTip - 1;
    n.hook = [](FakeUtxoNode& m) { if (m.paths.size() == 2) m.tip = kTip; }; // the node catches up
    SourceDashd sd(d);
    SourceC2pool sc(n);
    ScanResult r;
    CHECK(runs([&] { r = scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, "scan_both"), "runs");
    CHECK(r.cross_checked && r.tip_height == kTip && n.paths.size() == 2 && d.count("getaddressutxos") == 1,
          "the lagging node was re-read once; dashd was not");

    // dashd's own tip loop: the tip moves between the list and getblockcount.
    FakeDashd m;
    m.rows = fixture_rows();
    int counts = 0;
    m.hook = [&](FakeDashd& f, const std::string& meth) { if (meth == "getblockcount" && ++counts == 1) ++f.tip; };
    ScanResult r2;
    CHECK(runs([&] { r2 = dashd_scan(m); }, "scan") && m.count("getaddressutxos") == 2 && r2.tip_height == kTip + 1,
          "dashd: a moved tip re-reads the list");
    // a block arrives during the gettxout pass: gettxout's bestblock moves.
    FakeDashd g;
    g.rows = fixture_rows();
    int gets = 0;
    g.hook = [&](FakeDashd& f, const std::string& meth) { if (meth == "gettxout" && ++gets == 50) ++f.tip; };
    ScanResult r3;
    CHECK(runs([&] { r3 = dashd_scan(g); }, "scan") && g.count("getaddressutxos") == 2 && r3.tip_height == kTip + 1 &&
              r3.imports[0].utxos.size() == 170,
          "dashd: a tip moved under gettxout repeats the scan");
    FakeDashd never;
    never.rows = fixture_rows();
    never.hook = [](FakeDashd& f, const std::string& meth) { if (meth == "getblockcount") ++f.tip; };
    CHECK(refuses([&] { dashd_scan(never); }, cause::kTipUnstable) && never.count("getaddressutxos") == 5,
          "dashd: five moving reads refuse");
}

static void k7_tips_never_converge()
{
    std::printf("[K7 tips never converge -> scan-tips-differ]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    FakeUtxoNode n;
    n.rows = fixture_rows();
    n.tip = kTip - 1;
    SourceDashd sd(d);
    SourceC2pool sc(n);
    std::string what;
    CHECK(refuses([&] { scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, cause::kTipsDiffer, &what),
          "refused");
    CHECK(n.paths.size() == 4 && what.find(std::to_string(kTip - 1)) != std::string::npos, "after 3 re-reads, both tips named");
    // A node that cannot serve a scan: refused unless a single source is allowed.
    FakeUtxoNode off;
    off.rows = fixture_rows();
    off.mode = "accrual";
    SourceC2pool so(off);
    FakeDashd d2;
    d2.rows = fixture_rows();
    SourceDashd sd2(d2);
    CHECK(refuses([&] { scan_both(sd2, so, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, cause::kNodeUtxoNotFull),
          "node not full: refused by default");
    CrossCheckOptions single;
    single.allow_single_source = true;
    ScanResult r;
    CHECK(runs([&] { r = scan_both(sd2, so, {kXdgf}, ScanOptions{}, single); }, "single") && !r.cross_checked &&
              r.warning.find("single source: c2pool unavailable") != std::string::npos && export_of(r) == g_k1_export,
          "allowed single source: dashd alone, cross_checked false, said so");
    CHECK(refuses([&] {
              FakeUtxoNode bad;
              bad.rows = fixture_rows();
              bad.value_override[{bad.rows[0].txid, bad.rows[0].vout}] = 5;
              SourceC2pool sb(bad);
              FakeDashd d3;
              d3.rows = fixture_rows();
              SourceDashd sd3(d3);
              scan_both(sd3, sb, {kXdgf}, ScanOptions{}, single);
          }, cause::kSourceMismatch),
          "a disagreement is never downgraded to a single source");
}

// ── K8 / K9 ─────────────────────────────────────────────────────────────────
static void k8_mempool_spent()
{
    std::printf("[K8 gettxout null -> mempool_spent, not exported]\n");
    const std::vector<Row> rows = fixture_rows();
    const Outpoint o = mock_spent_row(rows);
    FakeDashd d;
    d.rows = rows;
    d.spent.insert(o);
    ScanResult r;
    CHECK(runs([&] { r = dashd_scan(d); }, "scan"), "scan runs");
    CHECK(r.mempool_spent.size() == 1 && r.mempool_spent[0] == o, "listed in mempool_spent");
    const std::string ex = export_of(r);
    CHECK(r.imports[0].utxos.size() == 169 && ex.find(o.txid) == std::string::npos, "not in the export");
    const Classification c = classify(r.imports[0], r.mempool_spent, {}, ClassifyParams{});
    CHECK(c.mempool_spent.size() == 1, "the classification lists it");
    const ScanPlan p = make_plan(c.exportable, PlanParams{});
    const std::string side = write_scan_plan(r, c, p, ex, FeeAdvice{});
    CHECK(side.find("\"mempool_spent\": [\n      {\n        \"txid\": \"" + o.txid + "\"") != std::string::npos,
          "the sidecar lists it");

    // Both sources: the node already excludes it; or only one side saw the spend.
    FakeUtxoNode n;
    n.rows = rows;
    n.spent.insert(o);
    SourceDashd sd(d);
    SourceC2pool sc(n);
    ScanResult b;
    CHECK(runs([&] { b = scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, "both") && b.cross_checked &&
              b.imports[0].utxos.size() == 169,
          "both sides saw the spend: equal");
    FakeDashd d2;
    d2.rows = rows;
    FakeUtxoNode n2;
    n2.rows = rows;
    n2.spent.insert(o);
    SourceDashd sd2(d2);
    SourceC2pool sc2(n2);
    ScanResult b2;
    CHECK(runs([&] { b2 = scan_both(sd2, sc2, {kXdgf}, ScanOptions{}, CrossCheckOptions{}); }, "both") &&
              b2.cross_checked && b2.imports[0].utxos.size() == 169 && b2.mempool_spent.size() == 1,
          "only the node's mempool saw it: the union is removed from both, then equal");
}

static void k9_gettxout_disagrees()
{
    std::printf("[K9 gettxout value / script != the index row -> refuse]\n");
    const std::vector<Row> rows = fixture_rows();
    FakeDashd d;
    d.rows = rows;
    d.value_override[{rows[7].txid, rows[7].vout}] = rows[7].sat - 1;
    std::string what;
    CHECK(refuses([&] { dashd_scan(d); }, cause::kSourceInconsistent, &what) && what.find("value") != std::string::npos,
          "value mismatch refuses the whole scan");
    FakeDashd s;
    s.rows = rows;
    s.script_override[{rows[7].txid, rows[7].vout}] = script_of(kOther);
    CHECK(refuses([&] { dashd_scan(s); }, cause::kSourceInconsistent, &what) && what.find("scriptPubKey") != std::string::npos,
          "script mismatch refuses");
    FakeDashd t;
    t.rows = rows;
    t.chain = "test";
    CHECK(refuses([&] { dashd_scan(t); }, cause::kWrongNetwork), "a testnet dashd for a mainnet scan refuses");
    FakeDashd a401;
    a401.rows = rows;
    a401.bare_http_status = 401;
    CHECK(refuses([&] { dashd_scan(a401); }, cause::kAuthRefused, &what) && what.find("cookie") != std::string::npos,
          "HTTP 401 without a JSON-RPC body: scan-auth-refused, pointing at the credentials");
    FakeDashd a403;
    a403.rows = rows;
    a403.bare_http_status = 403;
    CHECK(refuses([&] { dashd_scan(a403); }, cause::kAuthRefused), "HTTP 403 (rpcallowip): scan-auth-refused");
    FakeDashd a500;
    a500.rows = rows;
    a500.bare_http_status = 500;
    CHECK(refuses([&] { dashd_scan(a500); }, cause::kBadReply), "HTTP 500 without a body stays scan-bad-reply");
    FakeDashd f;
    f.rows = rows;
    Row foreign = rows[0];
    foreign.txid = sha_hex("foreign row");
    foreign.script = script_of(kOther); // listed for XdgF, pays another script
    f.rows.push_back(foreign);
    CHECK(refuses([&] { dashd_scan(f); }, cause::kForeignScript), "a row paying an unrequested script refuses");
    CHECK(refuses([&] { dashd_scan(d, {kXdgf, kXdgf}); }, cause::kBadAddress), "a duplicate address refuses");
    CHECK(refuses([&] { dashd_scan(d, {"yQfVzZf3yRmS5xYv9qNH3kVqZ8kC5wF5tX"}); }, cause::kBadAddress),
          "a non-mainnet / corrupt address refuses");
    std::vector<std::string> many(17);
    for (size_t i = 0; i < many.size(); ++i) many[i] = kXdgf;
    CHECK(refuses([&] { dashd_scan(d, many); }, cause::kBadAddress), "more than 16 addresses refuse");

    // Two addresses in one scan: one import per address.
    FakeDashd two;
    two.rows = rows;
    for (const Row& r : synthetic_rows(kOther, 3, 50000, 2500000)) two.rows.push_back(r);
    ScanResult r2;
    CHECK(runs([&] { r2 = dashd_scan(two, {kOther, kXdgf}); }, "scan") && r2.imports.size() == 2 &&
              r2.imports[0].address == kOther && r2.imports[0].utxos.size() == 3 && r2.imports[1].utxos.size() == 170,
          "two addresses: two imports in request order");
}

// ── K10 / K11 ───────────────────────────────────────────────────────────────
static void k10_classification()
{
    std::printf("[K10 classification at tip 2563986, and with 20 rows immature (ETA strings)]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    const ScanResult r = dashd_scan(d);
    const Classification c = classify(r.imports[0], r.mempool_spent, {}, ClassifyParams{});
    CHECK(c.target_height == kTip + 2, "target tip + 2");
    CHECK(c.mature.size() == 128 && c.immature.empty() && c.dust.size() == 42, "128 mature / 0 immature / 42 dust");
    CHECK(c.exportable.utxos.size() == 170, "the export keeps dust and immature rows (the signer screens them)");

    // The same rows held to min_confirmations 2000: the 20 youngest non-dust
    // coinbase rows (heights 2562226..2563881) cannot be spent at tip + 2.
    ClassifyParams strict;
    strict.min_confirmations = 2000;
    const Classification s = classify(r.imports[0], r.mempool_spent, {}, strict);
    CHECK(s.immature.size() == 20 && s.mature.size() == 108 && s.dust.size() == 42, "108 mature / 20 immature / 42 dust");
    const ImmatureRow& first = s.immature.front();
    const ImmatureRow& last = s.immature.back();
    CHECK(first.utxo.height == 2562226 && first.matures_in == 238 && first.eta == "~10 h 18 m", "oldest: 238 blocks, ~10 h 18 m");
    CHECK(last.utxo.height == 2563881 && last.matures_in == 1893 && last.eta == "~3 d 10 h", "youngest: 1893 blocks, ~3 d 10 h");
    CHECK(first.spendable_from_height == 2562326 && first.utxo.confirmations == kTip - 2562226 + 1,
          "consensus spendable_from = h0 + 100; confirmations as of the scan tip");

    ClassifyParams relay;
    relay.fee_mode = dash::FeeMode::Relay;
    relay.fee_rate_per_byte = 100;
    CHECK(classify(r.imports[0], r.mempool_spent, {}, relay).uneconomic.empty(),
          "relay at 100 duffs/B: every fixture row (>= 35443 duffs) pays for its own input");
    const dash::UtxoImport small = import_of(synthetic_rows(kXdgf, 5, 15000, 2500000), 2600000);
    CHECK(classify(small, {}, {}, relay).uneconomic.size() == 5 && classify(small, {}, {}, ClassifyParams{}).uneconomic.empty(),
          "15000-duff rows are uneconomic at 100 duffs/B x 181 B (relay only)");
}

// L3: the consensus coinbase floor on the companion path, at the real tip.
static void k10b_consensus_maturity_floor()
{
    std::printf("[K10b coinbase younger than 100 blocks at tip 2563986: the consensus floor, end to end]\n");
    std::vector<Row> rows = fixture_rows();
    auto row = [&](const char* tag, int64_t height, bool coinbase, int64_t sat) {
        Row r;
        r.address = kXdgf;
        r.txid = sha_hex(std::string("K10b ") + tag);
        r.vout = 0;
        r.script = kXdgfScript;
        r.sat = sat;
        r.height = height;
        r.coinbase = coinbase;
        rows.push_back(r);
        return Outpoint{r.txid, 0};
    };
    const Outpoint young_cb = row("coinbase 50 blocks", kTip - 50, true, 500000);
    const Outpoint young_tx = row("non-coinbase 50 blocks", kTip - 50, false, 400000);
    const Outpoint edge_cb = row("coinbase 98 blocks", kTip - 98, true, 300000);
    FakeDashd d;
    d.rows = rows;
    const ScanResult r = dashd_scan(d);
    const dash::UtxoImport& imp = r.imports.at(0);
    CHECK(imp.utxos.size() == 173, "173 rows at the real tip");
    auto find_imm = [](const Classification& c, const Outpoint& o) -> const ImmatureRow* {
        for (const ImmatureRow& x : c.immature)
            if (x.utxo.txid == o.txid && x.utxo.vout == o.vout) return &x;
        return nullptr;
    };
    auto is_mature = [](const Classification& c, const Outpoint& o) {
        for (const dash::Utxo& u : c.mature)
            if (u.txid == o.txid && u.vout == o.vout) return true;
        return false;
    };
    // Default (min_confirmations 101, target tip + 2): the 50-block coinbase
    // needs 101 - 52 = 49 more blocks; the 98-block one is one block short.
    const Classification def = classify(imp, r.mempool_spent, {}, ClassifyParams{});
    const ImmatureRow* a = find_imm(def, young_cb);
    const ImmatureRow* e = find_imm(def, edge_cb);
    CHECK(def.immature.size() == 2 && a && e, "two coinbase rows immature at the default rule");
    CHECK(a && a->matures_in == 49 && a->spendable_from_height == kTip + 50 && a->eta == "~2 h 7 m" &&
              a->utxo.confirmations == 51,
          "50-block coinbase: 49 blocks, spendable from h0 + 100, ~2 h 7 m, 51 confirmations at the tip");
    CHECK(e && e->matures_in == 1, "98-block coinbase: one block short of the 101 default");
    CHECK(is_mature(def, young_tx), "the 50-block non-coinbase row is mature (one confirmation)");
    // min_confirmations 1: the operator cannot lower a coinbase below the
    // consensus 100 — the 50-block coinbase still waits (100 - 52 = 48),
    // the 98-block one lands exactly at h0 + 100 = target.
    ClassifyParams one;
    one.min_confirmations = 1;
    const Classification low = classify(imp, r.mempool_spent, {}, one);
    const ImmatureRow* a1 = find_imm(low, young_cb);
    CHECK(low.immature.size() == 1 && a1 && a1->matures_in == 48, "min_confirmations 1: the coinbase floor of 100 holds");
    CHECK(is_mature(low, edge_cb), "98-block coinbase is spendable in block h0 + 100 = the target");
    // The plan (the signer's path) agrees with the classification.
    const ScanPlan p = make_plan(def.exportable, PlanParams{});
    bool has_young_cb = false, has_young_tx = false;
    for (const PlannedBatch& b : p.batches)
        for (const dash::Utxo& u : b.inputs) {
            has_young_cb |= u.txid == young_cb.txid;
            has_young_tx |= u.txid == young_tx.txid;
        }
    CHECK(!has_young_cb && has_young_tx && p.batches.at(0).vin == 129, "the plan spends the non-coinbase row, not the young coinbase");
    // L1: a target at or below the tip is its own refusal.
    ClassifyParams at_tip;
    at_tip.target_height = kTip;
    CHECK(refuses([&] { classify(imp, r.mempool_spent, {}, at_tip); }, cause::kBadTarget),
          "classify: target == tip is scan-bad-target");
    PlanParams pt;
    pt.target_height = kTip - 1;
    CHECK(refuses([&] { make_plan(def.exportable, pt); }, cause::kBadTarget), "plan: target below the tip is scan-bad-target");
    ClassifyParams neg;
    neg.dust_floor = -1;
    CHECK(refuses([&] { classify(imp, r.mempool_spent, {}, neg); }, cause::kBadParams), "a negative dust floor is scan-bad-params");
}

// A structurally valid signed legacy tx spending `ins`.
static std::string tx_spending(const std::vector<Outpoint>& ins)
{
    std::vector<uint8_t> t = {2, 0, 0, 0, static_cast<uint8_t>(ins.size())};
    for (const Outpoint& o : ins) {
        auto txid = *art::from_hex(o.txid);
        std::reverse(txid.begin(), txid.end());
        t.insert(t.end(), txid.begin(), txid.end());
        for (int i = 0; i < 4; ++i) t.push_back(static_cast<uint8_t>(o.vout >> (8 * i)));
        t.push_back(106);
        for (int i = 0; i < 106; ++i) t.push_back(0x44);
        for (int i = 0; i < 4; ++i) t.push_back(0xff);
    }
    t.push_back(1);
    for (int i = 0; i < 8; ++i) t.push_back(i == 1 ? 1 : 0);
    const auto spk = *art::from_hex(kXdgfScript);
    t.push_back(static_cast<uint8_t>(spk.size()));
    t.insert(t.end(), spk.begin(), spk.end());
    for (int i = 0; i < 4; ++i) t.push_back(0);
    return art::to_hex(t);
}

static void k11_queued_skip()
{
    std::printf("[K11 inputs of a queued, unfinished item are skipped]\n");
    const std::vector<Row> rows = fixture_rows();
    FakeDashd d;
    d.rows = rows;
    const ScanResult r = dashd_scan(d);
    const Outpoint a{rows[0].txid, rows[0].vout}, b{rows[1].txid, rows[1].vout}, c{rows[2].txid, rows[2].vout};
    sched::Queue q;
    sched::Item live;
    live.id = "it-live";
    live.state = sched::State::Waiting;
    live.tx.raw_tx = tx_spending({a, b});
    sched::Item done;
    done.id = "it-done";
    done.state = sched::State::Confirmed;
    done.tx.raw_tx = tx_spending({c});
    q.items = {live, done};
    CHECK(tx_prevouts(live.tx.raw_tx).size() == 2 && tx_prevouts(live.tx.raw_tx)[0] == a, "prevouts parsed (display order)");
    const auto qo = queued_outpoints(q);
    CHECK(qo.size() == 2 && qo.at(a) == "it-live" && !qo.count(c), "only the non-terminal item's inputs count");
    const Classification cl = classify(r.imports[0], r.mempool_spent, qo, ClassifyParams{});
    CHECK(cl.queued.size() == 2 && cl.queued[0].item_id == "it-live", "two rows skipped, the item named");
    CHECK(cl.exportable.utxos.size() == 168 && cl.mature.size() == 126, "the export and the plan leave them out");
    const ScanPlan p = make_plan(cl.exportable, PlanParams{});
    bool clean = true;
    for (const auto& u : p.batches[0].inputs)
        if ((u.txid == a.txid && u.vout == a.vout) || (u.txid == b.txid && u.vout == b.vout)) clean = false;
    CHECK(clean && p.batches[0].vin == 126, "no planned input is queued");
    const std::string ex = write_export_v1(cl.exportable);
    CHECK(ex.find(a.txid) == std::string::npos && ex.find(c.txid) != std::string::npos, "export: queued out, finished in");
}

// ── K12 / K13 ───────────────────────────────────────────────────────────────
static dash::SweepBatchPlan signer_plan(const dash::UtxoImport& imp, dash::PubkeyEncoding enc, size_t max_inputs)
{
    // The signer model's consolidate path, inlined (DashInjectModel::Impl::run_plan).
    const auto ts = dash::rescreen_at_height(imp.utxos, dash::addr_to_h160(imp.address, false), imp.tip_height,
                                             imp.tip_height + 2, dash::kDefaultMinConf, 1000, true);
    dash::SweepRequest req;
    req.funding_address = imp.address;
    req.utxos = ts.screen.spendable;
    req.utxos.insert(req.utxos.end(), ts.screen.immature.begin(), ts.screen.immature.end());
    req.utxos.insert(req.utxos.end(), ts.screen.dust.begin(), ts.screen.dust.end());
    req.dust_floor = 1000;
    req.max_inputs_per_tx = max_inputs;
    req.key_encoding = enc;
    return dash::plan_sweep(req);
}

static void k12_plan_digests_stable()
{
    std::printf("[K12 plan digests stable across runs; equal to the signer path's bytes]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    const ScanResult r = dashd_scan(d);
    const Classification c = classify(r.imports[0], r.mempool_spent, {}, ClassifyParams{});
    PlanParams pp;
    pp.key_encoding = dash::PubkeyEncoding::Compressed;
    const ScanPlan a = make_plan(c.exportable, pp);
    const ScanPlan b = make_plan(c.exportable, pp);
    CHECK(a.plan_id.size() == 64 && a.plan_id == b.plan_id, "plan_id reproduces");
    CHECK(a.batches.size() == 1 && b.batches.size() == 1 && a.batches[0].unsigned_sha256d == b.batches[0].unsigned_sha256d &&
              a.batches[0].inputs_sha256 == b.batches[0].inputs_sha256,
          "digests reproduce");
    CHECK(a.batches[0].vin == 128 && a.batches[0].value_out == 60963663 && a.batches[0].fee == 0 &&
              a.batches[0].est_signed_bytes == 19116,
          "1 batch, 128 inputs, 60963663, fee 0, 19116 B");
    const dash::SweepBatchPlan sp = signer_plan(c.exportable, dash::PubkeyEncoding::Compressed, 1000);
    CHECK(sp.txs.size() == 1 && a.batches[0].unsigned_tx == sp.txs[0].unsigned_tx &&
              a.batches[0].unsigned_sha256d == art::sha256d_display(sp.txs[0].unsigned_tx),
          "the companion's bytes and digest are the signer path's");
    CHECK(a.batches[0].inputs_sha256 == inputs_digest(sp.txs[0].inputs), "inputs digest over the same set");
    CHECK(a.safe_from_height == 2563981 && a.youngest_input_height == 2563881, "safe_from 2563981, youngest 2563881");

    PlanParams split = pp;
    split.max_inputs_per_tx = 85;
    const ScanPlan s = make_plan(c.exportable, split);
    CHECK(s.batches.size() == 2 && s.batches[0].vin == 85 && s.batches[1].vin == 43 && s.plan_id != a.plan_id,
          "max_inputs_per_tx 85: 85 + 43, another plan_id");
    const dash::SweepBatchPlan sp85 = signer_plan(c.exportable, dash::PubkeyEncoding::Compressed, 85);
    CHECK(sp85.txs.size() == 2 && s.batches[1].unsigned_tx == sp85.txs[1].unsigned_tx, "split bytes equal the signer path's");
    dash::UtxoImport other_tip = c.exportable;
    other_tip.tip_hash = tip_hash_of(kTip + 7);
    CHECK(make_plan(other_tip, pp).plan_id != a.plan_id, "another tip hash, another plan_id");
    PlanParams unk;
    const ScanPlan u = make_plan(c.exportable, unk);
    CHECK(u.batches[0].unsigned_sha256d == a.batches[0].unsigned_sha256d && u.batches[0].est_signed_bytes == 23212 &&
              u.plan_id != a.plan_id,
          "unknown encoding: same unsigned bytes, 181 B/input estimate, its own plan_id");
    PlanParams relay;
    relay.fee_mode = dash::FeeMode::Relay;
    relay.fee_rate_per_byte = 1;
    relay.key_encoding = dash::PubkeyEncoding::Compressed;
    const ScanPlan rl = make_plan(c.exportable, relay);
    CHECK(rl.batches[0].fee == 19116 && rl.batches[0].value_out == 60963663 - 19116, "relay 1 duff/B: fee = est bytes");
    CHECK(refuses([&] { PlanParams bad; bad.fee_mode = dash::FeeMode::Relay; bad.fee_rate_per_byte = 101; make_plan(c.exportable, bad); },
                  cause::kPlanRefused),
          "a relay rate above 100 duffs/B is the planner's refusal");
    PlanParams lim = pp;
    lim.input_limit = 10;
    const ScanPlan l = make_plan(c.exportable, lim);
    CHECK(l.batches[0].vin == 10 && l.not_selected == 118, "input_limit 10: the 10 oldest, 118 left out");
}

static void k13_sidecar_deterministic()
{
    std::printf("[K13 the sidecar: deterministic bytes, bound to the export]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    FakeUtxoNode n;
    n.rows = fixture_rows();
    SourceDashd sd(d);
    SourceC2pool sc(n);
    const ScanResult r = scan_both(sd, sc, {kXdgf}, ScanOptions{}, CrossCheckOptions{});
    const Classification c = classify(r.imports[0], r.mempool_spent, {}, ClassifyParams{});
    PlanParams pp;
    pp.max_inputs_per_tx = 600;
    pp.key_encoding = dash::PubkeyEncoding::Compressed;
    const ScanPlan p = make_plan(c.exportable, pp);
    const std::string ex = write_export_v1(c.exportable);
    NodePosture np;
    np.armed = true;
    np.utxo_full_serving = true;
    np.pool_free_bytes = 400000;
    const FeeAdvice adv = advise_fee_mode(np, p);
    CHECK(adv.fee_mode == "inject-zero-fee" && adv.reason == "node armed, utxo full serving, pool free 400000 B", "advice");
    const std::string s1 = write_scan_plan(r, c, p, ex, adv);
    const std::string s2 = write_scan_plan(r, c, make_plan(c.exportable, pp), write_export_v1(c.exportable), adv);
    CHECK(s1 == s2, "two runs, identical bytes");
    oj j;
    CHECK(runs([&] { j = oj::parse(s1); }, "parse"), "the sidecar is JSON");
    std::vector<std::string> keys;
    for (auto it = j.begin(); it != j.end(); ++it) keys.push_back(it.key());
    CHECK((keys == std::vector<std::string>{"schema", "coin", "network", "address", "utxos_file_sha256", "source", "classify",
                                            "params", "expected", "advice", "generated_by"}),
          "fixed key order");
    CHECK(j["schema"] == kScanPlanSchema && j["utxos_file_sha256"] == sha_hex(ex), "schema; bound to the export by sha256");
    CHECK(j["source"]["kind"] == "both" && j["source"]["cross_checked"] == true && j["source"]["tip_height"] == kTip,
          "source block");
    CHECK(j["classify"]["mature"] == 128 && j["classify"]["dust"] == 42 && j["classify"]["dust_floor"] == 1000,
          "classify block");
    CHECK(j["params"]["max_inputs_per_tx"] == 600 && j["params"]["key_encoding"] == "compressed" &&
              j["params"]["target_height"] == kTip + 2 && j["params"]["gov_hash"].is_null(),
          "params block");
    CHECK(j["expected"]["plan_id"] == p.plan_id && j["expected"]["tx_count"] == 1 &&
              j["expected"]["batches"][0]["unsigned_sha256d"] == p.batches[0].unsigned_sha256d &&
              j["expected"]["batches"][0]["est_signed_bytes"] == 19116 && j["expected"]["total_in"] == 60963663,
          "expected block");
    CHECK(s1.back() == '\n' && s1.find("\"generated_by\": \"c2wallet-qt-companion scan\"") != std::string::npos,
          "trailing newline; generator named");
    CHECK(s1.find("elapsed") == std::string::npos && s1.find("time") == std::string::npos, "no clock value in the file");
    const FeeAdvice none = advise_fee_mode(NodePosture{}, p);
    CHECK(none.fee_mode.empty() && oj::parse(write_scan_plan(r, c, p, ex, none))["advice"]["fee_mode"].is_null(),
          "unknown node posture: no advice");
    np.armed = false;
    CHECK(advise_fee_mode(np, p).fee_mode == "relay", "a disarmed node: relay");
    const std::string rep = write_report(r, c, p, adv, "xdgf-2563986");
    CHECK(rep.find("add --hex xdgf-2563986.hex --manifest xdgf-2563986.manifest.json --label \"consolidate XdgF55 1/1 plan " +
                   p.plan_id.substr(0, 8) + "\"") != std::string::npos,
          "the report prints the schedd add line");
}

// ── K14 ─────────────────────────────────────────────────────────────────────
static const char* kGovHash = "4f1c1cb8ed7f2a6bd9e4f9cbb5f24bd7d0f9e4ad14af9f1e1c2a0b6e7d3c5a91";

static void k14_two_stage_collateral()
{
    std::printf("[K14 collateral: one tx when it fits, two stages when it does not]\n");
    const int64_t tip = 2600000;
    PlanParams coll;
    coll.mode = PlanMode::Collateral;
    coll.gov_hash = kGovHash;
    // Fits: 12 x 0.1 DASH -> burn 1 DASH + change 0.2 DASH.
    const dash::UtxoImport small = import_of(synthetic_rows(kXdgf, 12, 10000000, 2500000), tip);
    ScanPlan one;
    CHECK(runs([&] { one = make_plan(small, coll); }, "plan"), "collateral planned");
    CHECK(!one.two_stage && one.batches.size() == 1 && one.batches[0].vin == 12 && one.batches[0].value_out == 120000000 &&
              one.batches[0].fee == 0,
          "one tx, 12 inputs, zero fee");
    CHECK(one.batches[0].outputs.size() == 2 && one.batches[0].outputs[0].first == 100000000 &&
              one.batches[0].outputs[0].second.size() == 34 && one.batches[0].outputs[0].second[0] == 0x6a &&
              one.batches[0].outputs[1].first == 20000000,
          "output 0 burns 1 DASH to OP_RETURN <hash>, output 1 the change");
    // Too many inputs for one tx: 700 x 0.002 DASH = 1.4 DASH.
    const dash::UtxoImport big = import_of(synthetic_rows(kXdgf, 700, 200000, 2500000), tip);
    ScanPlan two;
    CHECK(runs([&] { two = make_plan(big, coll); }, "plan"), "two-stage planned");
    CHECK(two.two_stage && two.batches.size() == 3, "stage 1: two batches; stage 2: one");
    CHECK(two.batches[0].vin == 552 && two.batches[1].vin == 148 && two.batches[0].depends_on.empty(),
          "stage 1 split at 552 inputs (unknown encoding, 181 B/input), independent batches");
    const PlannedBatch& s2 = two.batches[2];
    CHECK(s2.index == 3 && (s2.depends_on == std::vector<int>{1, 2}) && s2.vin == 2 && s2.value_out == 140000000 &&
              s2.unsigned_sha256d.empty() && s2.inputs.empty(),
          "stage 2 depends_on [1, 2], spends their 2 outputs, digest unknown until stage 1 is signed");
    const std::string side = write_scan_plan(ScanResult{}, classify(big, {}, {}, ClassifyParams{}), two,
                                             write_export_v1(big), FeeAdvice{});
    const oj j = oj::parse(side);
    CHECK(j["expected"]["two_stage"] == true && j["expected"]["batches"][2]["depends_on"] == oj::array({1, 2}) &&
              j["expected"]["batches"][2]["unsigned_sha256d"].is_null(),
          "the sidecar carries depends_on and a null stage-2 digest");
    CHECK(write_report(ScanResult{}, classify(big, {}, {}, ClassifyParams{}), two, FeeAdvice{}, "gov")
                  .find("--after-parent <stage-1 txid 1>:1 --after-parent <stage-1 txid 2>:1") != std::string::npos,
          "the report's stage-2 add line waits for both parents");

    const std::vector<std::string> txids = {sha_hex("stage-1 tx 1"), sha_hex("stage-1 tx 2")};
    std::string s2x;
    CHECK(runs([&] { s2x = stage2_export(two, txids, tip + 2); }, "stage2_export"), "stage-2 intake written");
    dash::UtxoImport back;
    CHECK(runs([&] { back = dash::parse_utxo_export_v1(s2x, false); }, "parse"), "the signer imports it");
    CHECK(back.utxos.size() == 2 && back.coinbase_flags && back.utxos[0].coinbase == false &&
              back.utxos[0].satoshis == two.batches[0].value_out && back.utxos[1].txid == txids[1] && back.utxos[1].vout == 0 &&
              back.tip_height == tip + 2 && back.utxos[0].confirmations == 1 && back.tip_hash.empty(),
          "stage-1 outputs, coinbase false, dated at the landing height");
    ScanPlan fin;
    CHECK(runs([&] { fin = make_plan(back, coll); }, "plan") && !fin.two_stage && fin.batches.size() == 1 &&
              fin.batches[0].vin == 2 && fin.batches[0].outputs[1].first == 40000000,
          "stage 2 then plans as one collateral tx (non-coinbase: one confirmation)");
    CHECK(refuses([&] { stage2_export(two, {txids[0]}, tip + 2); }, cause::kPlanRefused), "the txid count must match stage 1");
    CHECK(refuses([&] { stage2_export(one, {txids[0]}, tip + 2); }, cause::kUnsupported), "a one-stage plan has no stage 2");

    FakeDashd d;
    d.rows = fixture_rows();
    const dash::UtxoImport fx = dashd_scan(d).imports[0];
    std::string what;
    CHECK(refuses([&] { make_plan(fx, coll); }, cause::kPlanRefused, &what) && what.find("INSUFFICIENT") != std::string::npos,
          "the fixture's 0.6 DASH cannot fund a collateral");
    PlanParams rel = coll;
    rel.fee_mode = dash::FeeMode::Relay;
    rel.fee_rate_per_byte = 1;
    CHECK(refuses([&] { make_plan(small, rel); }, cause::kUnsupported), "a relay collateral is left to the signer");
}

// ── K15 ─────────────────────────────────────────────────────────────────────
static void k15_c2wu()
{
    std::printf("[K15 C2WU containers per batch: size and from_hex round trip]\n");
    FakeDashd d;
    d.rows = fixture_rows();
    const ScanResult r = dashd_scan(d);
    PlanParams pp;
    pp.key_encoding = dash::PubkeyEncoding::Compressed;
    const ScanPlan p = make_plan(classify(r.imports[0], {}, {}, ClassifyParams{}).exportable, pp);
    std::string err;
    const std::vector<std::string> hx = emit_c2wu(p, 0u, err);
    CHECK(err.empty() && hx.size() == 1, "one container");
    // Pinned by running the test (the design estimated about 15 kB / 75 kB).
    CHECK(hx.size() == 1 && hx[0].size() / 2 == 16614, "128 inputs with derivation hints: 16614 B");
    std::optional<art::UnsignedContainer> c;
    if (!hx.empty()) c = art::UnsignedContainer::from_hex(hx[0], err);
    CHECK(c.has_value() && c->has_digest, "from_hex parses it (digest verified)");
    CHECK(c && c->unsigned_tx == p.batches[0].unsigned_tx && c->unsigned_txid_display() == p.batches[0].unsigned_sha256d,
          "embedded unsigned tx = the plan's bytes; the cross-gap digest = the sidecar's");
    CHECK(c && c->inputs.size() == 128 && c->inputs[0].amount == p.batches[0].inputs[0].satoshis &&
              art::to_hex(c->inputs[0].script_pubkey) == kXdgfScript && c->inputs[0].derivation_hint == "m/44'/5'/0'/0/0" &&
              c->coin == "dash" && c->network_version == 0x4c,
          "per-input amount, script and derivation hint");

    const dash::UtxoImport wide = import_of(synthetic_rows(kXdgf, 670, 100000, 2500000), 2600000);
    const ScanPlan w = make_plan(wide, pp);
    const std::vector<std::string> wx = emit_c2wu(w, std::nullopt, err);
    CHECK(w.batches.size() == 1 && wx.size() == 1 && wx[0].size() / 2 == 76484,
          "670 inputs (no hints): 76484 B, under the 100 kB ceiling");
    PlanParams coll;
    coll.mode = PlanMode::Collateral;
    coll.gov_hash = kGovHash;
    const ScanPlan two = make_plan(import_of(synthetic_rows(kXdgf, 700, 200000, 2500000), 2600000), coll);
    CHECK(emit_c2wu(two, std::nullopt, err).empty() && err.find("stage-2") != std::string::npos,
          "a stage-2 batch has no container yet");
}

// ── the export_utxos.py parity hook ─────────────────────────────────────────
static int write_mock_export(const char* out)
{
    // The chain view tests/mock_dash_cli.py serves: tip 2563986 with its block
    // hash, the first row spent in the mempool, outputIndex 1 non-coinbase.
    const std::vector<Row> rows = fixture_rows();
    FakeDashd d;
    d.rows = rows;
    d.spent.insert(mock_spent_row(rows));
    try {
        const ScanResult r = dashd_scan(d);
        std::ofstream f(out, std::ios::binary);
        f << write_export_v1(r.imports.at(0));
        return f ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("REFUSED: %s\n", e.what());
        return 1;
    }
}

int main(int argc, char** argv)
{
    if (argc >= 3 && std::strcmp(argv[1], "--write-mock-export") == 0) return write_mock_export(argv[2]);
    std::printf("=== companion scan & plan KATs (K1-K16) ===\n");
    k1_export_v1_round_trip();
    k16_index_or_output_index();
    k2_scantxoutset_fallback();
    k2b_real_vm210_session();
    k3_c2pool_n1_shape();
    k4_both_equal();
    k5_one_value_altered();
    k6_tips_converge();
    k7_tips_never_converge();
    k8_mempool_spent();
    k9_gettxout_disagrees();
    k10_classification();
    k10b_consensus_maturity_floor();
    k11_queued_skip();
    k12_plan_digests_stable();
    k13_sidecar_deterministic();
    k14_two_stage_collateral();
    k15_c2wu();
    std::printf("\n== scan KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
