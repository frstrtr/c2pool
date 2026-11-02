// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The companion's scan output through the SIGNER's own code — the round-trip
// proof for slice S-B. The companion side (scan, classify, plan, the export
// and the sidecar) runs exactly as in test_scan.cpp; the signer side is
// DashInjectModel, the std-only model behind PageDashInject:
//
//   R1  <name>.utxos.json -> import (the page's auto-detecting stage 1)
//       -> rescreen -> plan with the sidecar's parameters: every batch's vin,
//       value_out, fee, est_signed_bytes, inputs digest and unsigned sha256d
//       equal the sidecar's (key encoding unknown, the stage-3 plan)
//   R2  the same with a key bound (the public test WIF, compressed): the
//       model's re-plan equals the compressed-encoding sidecar; sign; every
//       manifest input is a row of the export with equal value, script,
//       height and coinbase flag (design §4.2 b); the signed hex + manifest
//       enqueue in the companion's scheduler
//   R3  a split plan (max_inputs_per_tx 85): both batches equal
//   R4  a one-tx governance collateral: the signer's plan_collateral bytes
//       equal the companion's
//   R5  the stage-2 intake of a two-stage collateral imports and plans in the
//       signer; its bytes equal the companion's plan of the same intake
//
// Test binary only: it links the key-bearing DASH libraries next to the
// companion, so the key-free guard is not (and must not be) run over it.
// The fixture rows are the public XdgF55 capture re-addressed to the public
// test key's address (m/44'/5'/0'/0/0 of the BIP39 test mnemonic).

#include "../scan/Classifier.hpp"
#include "../scan/CrossCheck.hpp"
#include "../scan/Planner.hpp"
#include "../scan/ScanFiles.hpp"
#include "../scan/SourceC2pool.hpp"
#include "../scan/SourceDashd.hpp"

#include "../sched/InjectQueue.hpp"

#include "../../family/bitcoin/dash/DashInjectModel.hpp"
#include "../../family/bitcoin/dash/InjectManifest.hpp"
#include "../../family/bitcoin/dash/tests/inject_vectors.hpp"
#include "../../family/bitcoin/dash/tests/s2_vectors.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <string>
#include <vector>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

#include "scan_fakes.hpp"

using namespace scan_kat;
namespace testvec = c2w::dash::testvec;

static std::vector<Row> rows_for(const std::string& addr)
{
    std::vector<Row> v = fixture_rows();
    for (Row& r : v) {
        r.address = addr;
        r.script = script_of(addr);
    }
    return v;
}

struct CompanionOut {
    ScanResult scan;
    Classification cls;
    ScanPlan plan;
    std::string export_text;
    std::string sidecar_text;
    nj sidecar;
};

static CompanionOut companion(const std::vector<Row>& rows, int64_t tip, const PlanParams& pp)
{
    FakeDashd d;
    d.rows = rows;
    d.tip = tip;
    FakeUtxoNode n;
    n.rows = rows;
    n.tip = tip;
    SourceDashd sd(d);
    SourceC2pool sc(n);
    CompanionOut o;
    o.scan = scan_both(sd, sc, {rows[0].address}, ScanOptions{}, CrossCheckOptions{});
    o.cls = classify(o.scan.imports.at(0), o.scan.mempool_spent, {}, ClassifyParams{});
    o.plan = make_plan(o.cls.exportable, pp);
    o.export_text = write_export_v1(o.cls.exportable);
    o.sidecar_text = write_scan_plan(o.scan, o.cls, o.plan, o.export_text, FeeAdvice{});
    o.sidecar = nj::parse(o.sidecar_text);
    return o;
}

// Drive the model with the sidecar's parameters (what S-D's pre-fill does).
static void model_plan(dash::DashInjectModel& m, const CompanionOut& o)
{
    m.import_utxos(o.export_text);
    const nj& p = o.sidecar["params"];
    dash::ScreenParams sp;
    sp.target_height = p["target_height"];
    sp.min_confirmations = p["min_confirmations"];
    sp.dust_floor = p["dust_floor"];
    m.rescreen(sp);
    dash::PlanParams mp;
    mp.mode = p["mode"] == "collateral" ? dash::OutputMode::Collateral : dash::OutputMode::Consolidate;
    mp.fee_mode = p["fee_mode"] == "relay" ? dash::FeeMode::Relay : dash::FeeMode::InjectOnlyZeroFee;
    mp.fee_rate_per_byte = p["fee_rate_duffs_per_byte"];
    mp.destination = p["destination"];
    mp.max_inputs_per_tx = mp.mode == dash::OutputMode::Collateral ? 0 : p["max_inputs_per_tx"].get<size_t>();
    mp.input_limit = p["input_limit"];
    if (!p["gov_hash"].is_null()) mp.gov_hash_display = p["gov_hash"];
    mp.change_address = p["change_address"];
    m.plan(mp);
}

// The model's sweep batches against the sidecar's expected block.
static bool sweep_matches(const dash::DashInjectModel& m, const nj& expected, std::string& why)
{
    const dash::SweepBatchPlan* sp = m.sweep_plan();
    if (!sp) { why = "no sweep plan"; return false; }
    const nj& b = expected["batches"];
    if (sp->txs.size() != b.size() || expected["tx_count"] != sp->txs.size()) {
        why = "tx count " + std::to_string(sp->txs.size()) + " vs " + b.dump();
        return false;
    }
    for (size_t i = 0; i < sp->txs.size(); ++i) {
        const dash::SweepTxPlan& t = sp->txs[i];
        const nj& e = b[i];
        if (e["vin"] != t.inputs.size() || e["value_out"] != t.value_out || e["fee"] != t.fee ||
            e["est_signed_bytes"] != t.est_signed_bytes ||
            e["unsigned_sha256d"] != art::sha256d_display(t.unsigned_tx) || e["inputs_sha256"] != inputs_digest(t.inputs)) {
            why = "batch " + std::to_string(i + 1) + " differs: " + e.dump();
            return false;
        }
    }
    return true;
}

static void r1_import_screen_plan()
{
    std::printf("[R1 export + sidecar -> DashInjectModel import / screen / plan (unknown key encoding)]\n");
    const CompanionOut o = companion(rows_for(testvec::kPyParityAddress), kTip, PlanParams{});
    CHECK(o.scan.cross_checked && o.sidecar["utxos_file_sha256"] == sha_hex(o.export_text), "cross-checked; sidecar bound");
    dash::DashInjectModel m;
    std::string why;
    CHECK(runs([&] { model_plan(m, o); }, "model"), "the model imports, screens and plans the export");
    const dash::UtxoImport& imp = m.utxo_import();
    CHECK(imp.source == dash::UtxoSource::ExportV1 && imp.coinbase_flags && imp.address == testvec::kPyParityAddress,
          "stage 1 reads it as export v1 with every coinbase flag known");
    CHECK(same_rows(imp.utxos, o.cls.exportable.utxos) && imp.tip_hash == o.cls.exportable.tip_hash,
          "the signer holds exactly the scanned rows");
    CHECK(m.import_card().find("coinbase flags:  present") != std::string::npos, "the import card says so");
    CHECK(m.target_screen().screen.spendable.size() == o.cls.mature.size() &&
              m.target_screen().screen.dust.size() == o.cls.dust.size() &&
              m.target_screen().screen.immature.size() == o.cls.immature.size(),
          "the signer's screen = the companion's classification (128 / 42 / 0)");
    CHECK(sweep_matches(m, o.sidecar["expected"], why), why.empty() ? "the signer's plan = the sidecar" : why.c_str());
    CHECK(m.plan_safe_from_height() == o.sidecar["expected"]["safe_from_height"], "safe_from_height agrees");
}

static void r2_key_sign_manifest_enqueue()
{
    std::printf("[R2 key bound (compressed): re-plan = sidecar; sign; manifest inputs = export rows; enqueue]\n");
    PlanParams pp;
    pp.key_encoding = dash::PubkeyEncoding::Compressed;
    const CompanionOut o = companion(rows_for(testvec::kPyParityAddress), kTip, pp);
    dash::DashInjectModel m;
    std::string why;
    CHECK(runs([&] { model_plan(m, o); }, "model"), "planned");
    dash::KeyInput k;
    k.source = dash::KeySource::Wif;
    k.secret = testvec::kK7Wif;
    CHECK(runs([&] { m.load_key(k); }, "load_key"), "the public test key binds to the funding address");
    CHECK(sweep_matches(m, o.sidecar["expected"], why), why.empty() ? "re-plan with the compressed key = the sidecar" : why.c_str());
    CHECK(runs([&] {
              m.set_gate(true, false, dash::kSpendWord);
              m.sign();
          }, "sign"),
          "signed");
    const nj man = nj::parse(m.manifest_json());
    std::map<Outpoint, dash::Utxo> rows;
    for (const dash::Utxo& u : o.cls.exportable.utxos) rows[{u.txid, u.vout}] = u;
    size_t checked = 0;
    bool all = true;
    for (const nj& tx : man["txs"])
        for (const nj& in : tx["inputs"]) {
            const auto it = rows.find({in["txid"].get<std::string>(), in["vout"].get<uint32_t>()});
            ++checked;
            if (it == rows.end() || in["value"] != it->second.satoshis || in["script_hex"] != it->second.script_pubkey_hex ||
                in["height"] != it->second.height || in["coinbase"] != it->second.coinbase.value())
                all = false;
        }
    CHECK(all && checked == 128, "every manifest input is an export row with equal value / script / height / coinbase");
    CHECK(man["maturity"]["coinbase_flags_known"] == true && man["maturity"]["screen_tip_hash"] == o.scan.tip_hash,
          "the manifest records known coinbase flags and the scanned tip");
    sched::Queue q;
    sched::EnqueueRequest req;
    req.hex_text = m.inject_file();
    req.hex_path = "kat.hex";
    req.manifest_text = m.manifest_json();
    req.manifest_path = "kat.manifest.json";
    req.label = "consolidate " + o.plan.plan_id.substr(0, 8);
    const sched::EnqueueResult er = sched::enqueue(q, req, 1793600000);
    CHECK(er.ok && er.ids.size() == 1, er.ok ? "the signed pair enqueues in the companion scheduler" : er.why.c_str());
    CHECK(er.ok && q.items[0].triggers.maturity.safe_from_height == o.plan.safe_from_height,
          "the scheduler's maturity trigger = the plan's safe_from_height");
}

static void r3_split()
{
    std::printf("[R3 split plan (max_inputs_per_tx 85)]\n");
    PlanParams pp;
    pp.max_inputs_per_tx = 85;
    const CompanionOut o = companion(rows_for(testvec::kPyParityAddress), kTip, pp);
    dash::DashInjectModel m;
    std::string why;
    CHECK(runs([&] { model_plan(m, o); }, "model") && o.plan.batches.size() == 2, "planned, two batches");
    CHECK(sweep_matches(m, o.sidecar["expected"], why), why.empty() ? "both batches equal" : why.c_str());
}

static const char* kGov = "4f1c1cb8ed7f2a6bd9e4f9cbb5f24bd7d0f9e4ad14af9f1e1c2a0b6e7d3c5a91";

static void r4_collateral_one_tx()
{
    std::printf("[R4 governance collateral, one tx: plan_collateral's bytes = the companion's]\n");
    PlanParams pp;
    pp.mode = PlanMode::Collateral;
    pp.gov_hash = kGov;
    const CompanionOut o = companion(synthetic_rows(testvec::kPyParityAddress, 12, 10000000, 2500000), 2600000, pp);
    dash::DashInjectModel m;
    CHECK(runs([&] { model_plan(m, o); }, "model"), "the model plans the collateral");
    const dash::CollateralPlan* cp = m.collateral_plan();
    CHECK(cp && !o.plan.two_stage && o.plan.batches.size() == 1, "one tx on both sides");
    CHECK(cp && o.sidecar["expected"]["batches"][0]["unsigned_sha256d"] == art::sha256d_display(cp->unsigned_tx) &&
              cp->est_signed_bytes == o.plan.batches[0].est_signed_bytes && cp->selected.size() == 12 &&
              cp->change == 20000000 && cp->fee == 0,
          "equal unsigned bytes, size estimate, inputs, change and zero fee");
}

static void r5_two_stage_intake()
{
    std::printf("[R5 two-stage collateral: the stage-2 intake through the signer]\n");
    PlanParams pp;
    pp.mode = PlanMode::Collateral;
    pp.gov_hash = kGov;
    const CompanionOut o = companion(synthetic_rows(testvec::kPyParityAddress, 700, 200000, 2500000), 2600000, pp);
    CHECK(o.plan.two_stage && o.plan.batches.size() == 3, "two stages");
    dash::DashInjectModel s1;
    std::string why;
    CHECK(runs([&] {
              s1.import_utxos(o.export_text);
              s1.rescreen({});
              dash::PlanParams c;
              c.max_inputs_per_tx = 0;
              s1.plan(c);
          }, "stage 1"),
          "stage 1 consolidates in the signer");
    // Stage 1 is planned with the funding address as destination; the signer's
    // consolidate default is the same.
    const dash::SweepBatchPlan* sp = s1.sweep_plan();
    CHECK(sp && sp->txs.size() == 2 && sp->txs[0].unsigned_tx == o.plan.batches[0].unsigned_tx &&
              sp->txs[1].unsigned_tx == o.plan.batches[1].unsigned_tx,
          "the signer's stage-1 bytes = the companion's");
    const std::vector<std::string> txids = {sha_hex("R5 stage-1 tx 1"), sha_hex("R5 stage-1 tx 2")};
    const std::string intake = stage2_export(o.plan, txids, 2600002);
    dash::DashInjectModel s2;
    CHECK(runs([&] {
              s2.import_utxos(intake);
              s2.rescreen({});
              dash::PlanParams c;
              c.mode = dash::OutputMode::Collateral;
              c.gov_hash_display = kGov;
              s2.plan(c);
          }, "stage 2"),
          "the stage-2 intake imports, screens (non-coinbase) and plans as a collateral in the signer");
    const dash::CollateralPlan* cp = s2.collateral_plan();
    PlanParams c2 = pp;
    const ScanPlan mine = make_plan(dash::parse_utxo_export_v1(intake, false), c2);
    CHECK(cp && cp->selected.size() == 2 && mine.batches.size() == 1 &&
              art::sha256d_display(cp->unsigned_tx) == mine.batches[0].unsigned_sha256d && cp->change == 40000000,
          "the signer's stage-2 collateral bytes = the companion's plan of the same intake");
}

int main()
{
    std::printf("=== scan -> signer round trip (DashInjectModel) ===\n");
    r1_import_screen_plan();
    r2_key_sign_manifest_enqueue();
    r3_split();
    r4_collateral_one_tx();
    r5_two_stage_intake();
    std::printf("\n== round trip: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
