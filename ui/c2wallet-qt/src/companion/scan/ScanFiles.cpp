// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ScanFiles.hpp"

#include "../Produce.hpp"
#include "../sched/Json.hpp"

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"

#include <algorithm>

namespace c2w::companion::scan {

namespace {

using J = sched::json::J;
using c2w::dash::Utxo;

std::string sha256_hex(const std::string& s)
{
    return c2w::artifact::to_hex(c2w::artifact::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

J str_or_null(const std::string& s) { return s.empty() ? J(nullptr) : J(s); }
J int_or_null(int64_t v) { return v == 0 ? J(nullptr) : J(v); }

std::string short_addr(const std::string& a) { return a.substr(0, std::min<size_t>(6, a.size())); }

} // namespace

std::string write_export_v1(const c2w::dash::UtxoImport& imp)
{
    if (imp.utxos.empty())
        throw ScanRefusal(cause::kNothingToExport, "no UTXO left for " + imp.address + ": nothing to export");
    // Field set, order and layout of tools/export_utxos.py.
    J doc = J::object();
    doc["schema"] = c2w::dash::kUtxoExportSchema;
    doc["coin"] = "dash";
    doc["network"] = imp.testnet ? "testnet" : "mainnet";
    doc["address"] = imp.address;
    doc["tip_height"] = imp.tip_height;
    doc["tip_hash"] = imp.tip_hash;
    J rows = J::array();
    for (const Utxo& u : imp.utxos) {
        J r = J::object();
        r["txid"] = u.txid;
        r["vout"] = u.vout;
        r["satoshis"] = u.satoshis;
        r["height"] = u.height;
        r["confirmations"] = imp.tip_height - u.height + 1;
        r["coinbase"] = u.coinbase.value_or(true);
        r["scriptPubKey"] = u.script_pubkey_hex;
        rows.push_back(std::move(r));
    }
    doc["utxos"] = std::move(rows);
    // json.dump(doc, f, indent=1): one-space indent, ", "-free item separator,
    // ": " key separator, no trailing newline.
    return doc.dump(1, ' ', false, J::error_handler_t::replace);
}

FeeAdvice advise_fee_mode(const NodePosture& node, const ScanPlan& plan)
{
    FeeAdvice a;
    a.posture = node;
    size_t est_total = 0;
    for (const PlannedBatch& b : plan.batches) est_total += b.est_signed_bytes;
    if (!node.armed || !node.utxo_full_serving || !node.pool_free_bytes) {
        a.reason = "node posture not read (armed / utxo full serving / pool free): no advice";
        return a;
    }
    if (!*node.armed) {
        a.fee_mode = "relay";
        a.reason = "the node's inject lane is not armed";
    } else if (!*node.utxo_full_serving) {
        a.fee_mode = "relay";
        a.reason = "the node does not serve the full UTXO set (it cannot resolve historic inputs)";
    } else if (*node.pool_free_bytes < static_cast<int64_t>(est_total)) {
        a.fee_mode = "relay";
        a.reason = "the node's inject pool has " + std::to_string(*node.pool_free_bytes) + " B free, the plan needs " +
                   std::to_string(est_total) + " B (or submit in rounds)";
    } else {
        a.fee_mode = "inject-zero-fee";
        a.reason = "node armed, utxo full serving, pool free " + std::to_string(*node.pool_free_bytes) + " B";
    }
    return a;
}

std::string write_scan_plan(const ScanResult& scan, const Classification& cls, const ScanPlan& plan,
                            const std::string& utxos_file, const FeeAdvice& advice)
{
    J doc = J::object();
    doc["schema"] = kScanPlanSchema;
    doc["coin"] = "dash";
    doc["network"] = plan.testnet ? "testnet" : "mainnet";
    doc["address"] = plan.address;
    doc["utxos_file_sha256"] = sha256_hex(utxos_file);

    J src = J::object();
    src["kind"] = scan.source;
    src["tip_height"] = plan.tip_height;
    src["tip_hash"] = plan.tip_hash;
    src["cross_checked"] = scan.cross_checked;
    src["dashd"] = str_or_null(scan.dashd_detail);
    src["c2pool"] = str_or_null(scan.c2pool_detail);
    doc["source"] = std::move(src);

    J cl = J::object();
    cl["target_height"] = cls.target_height;
    cl["mature"] = cls.mature.size();
    J imm = J::array();
    for (const ImmatureRow& r : cls.immature) {
        J o = J::object();
        o["txid"] = r.utxo.txid;
        o["vout"] = r.utxo.vout;
        o["value"] = r.utxo.satoshis;
        o["height"] = r.utxo.height;
        o["coinbase"] = r.utxo.coinbase.value_or(true);
        o["spendable_from_height"] = r.spendable_from_height;
        o["eta_blocks"] = r.matures_in;
        imm.push_back(std::move(o));
    }
    cl["immature"] = std::move(imm);
    cl["dust"] = cls.dust.size();
    cl["dust_floor"] = cls.params.dust_floor;
    J q = J::array();
    for (const QueuedRow& r : cls.queued) {
        J o = J::object();
        o["txid"] = r.utxo.txid;
        o["vout"] = r.utxo.vout;
        o["value"] = r.utxo.satoshis;
        o["item_id"] = r.item_id;
        q.push_back(std::move(o));
    }
    cl["queued"] = std::move(q);
    J ms = J::array();
    for (const Outpoint& o : cls.mempool_spent) ms.push_back(J{{"txid", o.txid}, {"vout", o.vout}});
    cl["mempool_spent"] = std::move(ms);
    cl["uneconomic"] = cls.uneconomic.size();
    doc["classify"] = std::move(cl);

    const PlanParams& p = plan.params;
    J pr = J::object();
    pr["mode"] = plan_mode_name(p.mode);
    pr["fee_mode"] = fee_mode_name(p.fee_mode);
    pr["fee_rate_duffs_per_byte"] = p.fee_rate_per_byte;
    pr["destination"] = p.destination;
    pr["target_height"] = p.target_height;
    pr["min_confirmations"] = p.min_confirmations;
    pr["dust_floor"] = p.dust_floor;
    pr["max_inputs_per_tx"] = p.max_inputs_per_tx;
    pr["input_limit"] = p.input_limit;
    pr["key_encoding"] = key_encoding_name(p.key_encoding);
    pr["gov_hash"] = str_or_null(lower(p.gov_hash));
    pr["change_address"] = p.change_address;
    doc["params"] = std::move(pr);

    J ex = J::object();
    ex["plan_id"] = plan.plan_id;
    ex["tx_count"] = plan.batches.size();
    ex["two_stage"] = plan.two_stage;
    ex["total_in"] = plan.total_in;
    ex["total_fee"] = plan.total_fee;
    ex["not_selected"] = plan.not_selected;
    ex["safe_from_height"] = int_or_null(plan.safe_from_height);
    ex["youngest_input_height"] = int_or_null(plan.youngest_input_height);
    J batches = J::array();
    for (const PlannedBatch& b : plan.batches) {
        J o = J::object();
        o["index"] = b.index;
        o["depends_on"] = b.depends_on;
        o["vin"] = b.vin;
        o["value_out"] = b.value_out;
        o["fee"] = b.fee;
        o["est_signed_bytes"] = b.est_signed_bytes;
        o["unsigned_sha256d"] = str_or_null(b.unsigned_sha256d);
        o["inputs_sha256"] = str_or_null(b.inputs_sha256);
        batches.push_back(std::move(o));
    }
    ex["batches"] = std::move(batches);
    doc["expected"] = std::move(ex);

    J adv = J::object();
    adv["fee_mode"] = str_or_null(advice.fee_mode);
    adv["reason"] = advice.reason;
    adv["node_armed"] = sched::json::opt(advice.posture.armed);
    adv["node_utxo_full"] = sched::json::opt(advice.posture.utxo_full_serving);
    adv["pool_free_bytes"] = sched::json::opt(advice.posture.pool_free_bytes);
    doc["advice"] = std::move(adv);
    doc["generated_by"] = "c2wallet-qt-companion scan";
    return doc.dump(2, ' ', false, J::error_handler_t::replace) + "\n";
}

std::string write_report(const ScanResult& scan, const Classification& cls, const ScanPlan& plan,
                         const FeeAdvice& advice, const std::string& name)
{
    using c2w::dash::format_dash;
    std::string s;
    s += "c2wallet-qt companion: scan & plan report\n";
    s += "address:        " + plan.address + (plan.testnet ? " (testnet)\n" : " (mainnet)\n");
    s += "source:         " + scan.source + (scan.cross_checked ? " (cross-checked)" : " (single source, NOT cross-checked)") +
         "\n";
    if (!scan.dashd_detail.empty()) s += "  dashd:        " + scan.dashd_detail + "\n";
    if (!scan.c2pool_detail.empty()) s += "  c2pool:       " + scan.c2pool_detail + "\n";
    if (!scan.warning.empty()) s += "  warning:      " + scan.warning + "\n";
    s += "tip:            " + std::to_string(plan.tip_height) + " " + plan.tip_hash + "\n";
    s += "target height:  " + std::to_string(cls.target_height) + "\n";
    int64_t mature_v = 0, dust_v = 0, imm_v = 0;
    for (const Utxo& u : cls.mature) mature_v += u.satoshis;
    for (const Utxo& u : cls.dust) dust_v += u.satoshis;
    for (const ImmatureRow& r : cls.immature) imm_v += r.utxo.satoshis;
    s += "mature:         " + std::to_string(cls.mature.size()) + " UTXOs, " + format_dash(mature_v) + " DASH\n";
    s += "immature:       " + std::to_string(cls.immature.size()) + " UTXOs, " + format_dash(imm_v) + " DASH\n";
    s += "dust (< " + std::to_string(cls.params.dust_floor) + "):    " + std::to_string(cls.dust.size()) + " UTXOs, " +
         format_dash(dust_v) + " DASH (never spent)\n";
    s += "queued:         " + std::to_string(cls.queued.size()) + " UTXOs (inputs of queued, unfinished items)\n";
    for (const QueuedRow& r : cls.queued) s += "  " + r.utxo.txid + ":" + std::to_string(r.utxo.vout) + "  item " + r.item_id + "\n";
    s += "mempool-spent:  " + std::to_string(cls.mempool_spent.size()) + " (excluded)\n";
    for (const Outpoint& o : cls.mempool_spent) s += "  " + outpoint_str(o) + "\n";
    if (!cls.uneconomic.empty())
        s += "uneconomic:     " + std::to_string(cls.uneconomic.size()) +
             " mature UTXO(s) carry less than the relay fee of their own input\n";
    if (!cls.immature.empty()) {
        s += "\nimmature, oldest-maturing first (blocks until a plan may spend it, ETA at 2.6 min/block):\n";
        for (const ImmatureRow& r : cls.immature)
            s += "  " + r.utxo.txid + ":" + std::to_string(r.utxo.vout) + "  " + format_dash(r.utxo.satoshis) +
                 " DASH  h " + std::to_string(r.utxo.height) + "  spendable from " +
                 std::to_string(r.spendable_from_height) + "  in " + std::to_string(r.matures_in) + " blocks, " +
                 r.eta + "\n";
    }
    s += "\nplan " + plan.plan_id + "\n";
    s += std::string("mode ") + plan_mode_name(plan.params.mode) + ", " + fee_mode_name(plan.params.fee_mode) +
         ", key encoding " + key_encoding_name(plan.params.key_encoding) + ", " +
         std::to_string(plan.batches.size()) + " tx(s)" + (plan.two_stage ? " in two stages" : "") + "\n";
    for (const PlannedBatch& b : plan.batches) {
        s += "  batch " + std::to_string(b.index) + ": " + std::to_string(b.vin) + " inputs -> " +
             format_dash(b.value_out) + " DASH, fee " + std::to_string(b.fee) + ", est " +
             std::to_string(b.est_signed_bytes) + " B";
        if (!b.depends_on.empty()) {
            s += ", spends the output(s) of batch";
            for (int d : b.depends_on) s += " " + std::to_string(d);
        }
        s += "\n";
        if (!b.unsigned_sha256d.empty()) s += "    unsigned sha256d " + b.unsigned_sha256d + "\n";
    }
    for (const std::string& w : plan.warnings) s += "WARNING: " + w + "\n";
    s += "\n" + plan.summary;
    s += "\nfee advice: " + (advice.fee_mode.empty() ? std::string("none") : advice.fee_mode) + " (" + advice.reason +
         ")\n";

    s += "\nafter signing in the offline signer (it writes " + name + ".hex and " + name + ".manifest.json):\n";
    const std::string tag = std::string(plan_mode_name(plan.params.mode)) + " " + short_addr(plan.address);
    const size_t n = plan.batches.size();
    for (const PlannedBatch& b : plan.batches) {
        std::string line = "c2wallet-qt-schedd --queue Q --node-url http://127.0.0.1:8080 --token-file T \\\n  add --hex " +
                           name + ".hex --manifest " + name + ".manifest.json";
        if (n > 1) line += " --line " + std::to_string(b.index);
        line += " --label \"" + tag + " " + std::to_string(b.index) + "/" + std::to_string(n) + " plan " +
                plan.plan_id.substr(0, 8) + "\"";
        if (plan.youngest_input_height > 0 && plan.tip_height - plan.youngest_input_height + 1 < 100)
            line += " --maturity-slack 1";
        if (!plan.two_stage && b.index >= 5)
            line += " --not-before-height " + std::to_string(plan.tip_height + 8 * b.index);
        if (plan.safe_from_height > plan.tip_height + 2)
            line += " --expiry-blocks " + std::to_string(plan.safe_from_height - plan.tip_height + 576);
        for (int d : b.depends_on) line += " --after-parent <stage-1 txid " + std::to_string(d) + ">:1";
        if (!b.depends_on.empty())
            line = "# stage 2: write its intake from the stage-1 txids, re-plan it in the signer, then\n" + line;
        s += line + "\n";
    }
    return s;
}

std::vector<std::string> emit_c2wu(const ScanPlan& plan, std::optional<uint32_t> derivation_index, std::string& err)
{
    err.clear();
    std::vector<std::string> out;
    for (const PlannedBatch& b : plan.batches) {
        if (b.inputs.empty() || b.unsigned_tx.empty()) {
            err = "batch " + std::to_string(b.index) + " is a stage-2 tx whose inputs do not exist yet";
            return {};
        }
        FundingData fd;
        fd.coin = "dash";
        fd.network_version = c2w::dash::p2pkh_version(plan.testnet);
        fd.algebra = c2w::artifact::SighashAlgebra::Legacy;
        fd.tx_version = 2;
        fd.locktime = 0;
        for (const Utxo& u : b.inputs) {
            FundingInput in;
            auto txid = c2w::artifact::from_hex(u.txid);
            auto spk = c2w::artifact::from_hex(u.script_pubkey_hex);
            if (!txid || txid->size() != 32 || !spk) {
                err = "batch " + std::to_string(b.index) + ": malformed input " + u.txid;
                return {};
            }
            std::reverse(txid->begin(), txid->end()); // display -> internal order
            std::copy(txid->begin(), txid->end(), in.prevout_txid.begin());
            in.prevout_index = u.vout;
            in.script_pubkey = *spk;
            in.amount = u.satoshis;
            if (derivation_index)
                in.derivation_hint = std::string("m/44'/") + (plan.testnet ? "1" : "5") + "'/0'/0/" +
                                     std::to_string(*derivation_index);
            in.sequence = 0xffffffffu;
            fd.inputs.push_back(std::move(in));
        }
        for (const auto& [value, spk] : b.outputs) fd.outputs.push_back({value, spk});
        if (serialize_unsigned_tx(fd) != b.unsigned_tx) {
            err = "batch " + std::to_string(b.index) + ": the container's unsigned tx differs from the plan's bytes";
            return {};
        }
        std::string hex = produce_unsigned_hex(fd, err);
        if (hex.empty()) {
            err = "batch " + std::to_string(b.index) + ": " + err;
            return {};
        }
        out.push_back(std::move(hex));
    }
    return out;
}

} // namespace c2w::companion::scan
