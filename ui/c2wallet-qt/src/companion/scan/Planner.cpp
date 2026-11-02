// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Planner.hpp"

#include "ScanFiles.hpp" // write_export_v1 (stage-2 intake)

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"
#include "../../family/bitcoin/dash/GovCollateral.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"

#include <algorithm>
#include <tuple>

namespace c2w::companion::scan {

using c2w::dash::Utxo;
using c2w::dash::UtxoImport;
namespace caps = c2w::dash::caps;

const char* plan_mode_name(PlanMode m)
{
    return m == PlanMode::Collateral ? "collateral" : "consolidate";
}

const char* fee_mode_name(c2w::dash::FeeMode m)
{
    return m == c2w::dash::FeeMode::Relay ? "relay" : "inject-zero-fee";
}

const char* key_encoding_name(c2w::dash::PubkeyEncoding e)
{
    switch (e) {
    case c2w::dash::PubkeyEncoding::Compressed: return "compressed";
    case c2w::dash::PubkeyEncoding::Uncompressed: return "uncompressed";
    case c2w::dash::PubkeyEncoding::Unknown: break;
    }
    return "unknown";
}

namespace {

std::string sha256_hex(const std::string& s)
{
    return c2w::artifact::to_hex(c2w::artifact::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

std::vector<Outpoint> sorted_outpoints(const std::vector<Utxo>& inputs)
{
    std::vector<Outpoint> v;
    v.reserve(inputs.size());
    for (const Utxo& u : inputs) v.push_back({lower(u.txid), u.vout});
    std::sort(v.begin(), v.end());
    return v;
}

PlannedBatch batch_of(int index, std::vector<Utxo> inputs,
                      std::vector<std::pair<int64_t, std::vector<uint8_t>>> outputs, int64_t fee,
                      std::vector<uint8_t> unsigned_tx, size_t est)
{
    PlannedBatch b;
    b.index = index;
    b.vin = inputs.size();
    for (const auto& o : outputs) b.value_out += o.first;
    b.fee = fee;
    b.est_signed_bytes = est;
    b.unsigned_sha256d = c2w::artifact::sha256d_display(unsigned_tx);
    b.inputs_sha256 = inputs_digest(inputs);
    b.inputs = std::move(inputs);
    b.outputs = std::move(outputs);
    b.unsigned_tx = std::move(unsigned_tx);
    return b;
}

std::string plan_identity_text(const ScanPlan& p)
{
    const PlanParams& q = p.params;
    std::string t = "c2wallet-scan-plan/1 plan_id\n";
    t += std::string("network=") + (p.testnet ? "testnet" : "mainnet") + "\n";
    t += "address=" + p.address + "\n";
    t += "tip_height=" + std::to_string(p.tip_height) + "\n";
    t += "tip_hash=" + p.tip_hash + "\n";
    t += std::string("mode=") + plan_mode_name(q.mode) + "\n";
    t += std::string("fee_mode=") + fee_mode_name(q.fee_mode) + "\n";
    t += "fee_rate_duffs_per_byte=" + std::to_string(q.fee_rate_per_byte) + "\n";
    t += "destination=" + p.destination + "\n";
    t += "target_height=" + std::to_string(q.target_height) + "\n";
    t += "min_confirmations=" + std::to_string(q.min_confirmations) + "\n";
    t += "dust_floor=" + std::to_string(q.dust_floor) + "\n";
    t += "max_inputs_per_tx=" + std::to_string(q.max_inputs_per_tx) + "\n";
    t += "input_limit=" + std::to_string(q.input_limit) + "\n";
    t += std::string("key_encoding=") + key_encoding_name(q.key_encoding) + "\n";
    t += "gov_hash=" + lower(q.gov_hash) + "\n";
    t += "change_address=" + q.change_address + "\n";
    t += "two_stage=" + std::string(p.two_stage ? "1" : "0") + "\n";
    t += "inputs:\n";
    std::vector<Utxo> all;
    for (const PlannedBatch& b : p.batches) all.insert(all.end(), b.inputs.begin(), b.inputs.end());
    for (const Outpoint& o : sorted_outpoints(all)) t += outpoint_str(o) + "\n";
    return t;
}

[[noreturn]] void refuse(const std::string& why) { throw ScanRefusal(cause::kPlanRefused, why); }

} // namespace

std::string inputs_digest(const std::vector<Utxo>& inputs)
{
    std::string t;
    for (const Outpoint& o : sorted_outpoints(inputs)) t += outpoint_str(o) + "\n";
    return sha256_hex(t);
}

ScanPlan make_plan(const UtxoImport& ex, const PlanParams& in)
{
    ScanPlan plan;
    plan.address = ex.address;
    plan.testnet = ex.testnet;
    plan.tip_height = ex.tip_height;
    plan.tip_hash = ex.tip_hash;
    PlanParams p = in;
    if (p.target_height == 0) p.target_height = ex.tip_height + 2;
    const bool collateral = p.mode == PlanMode::Collateral;
    const bool relay = p.fee_mode == c2w::dash::FeeMode::Relay;
    try {
        if (collateral) {
            if (relay)
                throw ScanRefusal(cause::kUnsupported, "a relay (fee-paying) collateral is planned in the signer; the "
                                                       "companion plans the zero-fee inject collateral only");
            if (p.max_inputs_per_tx != 0) refuse("a collateral is ONE tx and is never split: max_inputs_per_tx must be 0");
            if (!p.destination.empty()) refuse("a collateral takes a change address, not a destination");
            if (p.gov_hash.size() != 64) refuse("a collateral needs the 64-hex gov hash `gobject check` prints");
        } else if (!p.gov_hash.empty() || !p.change_address.empty()) {
            refuse("a consolidation takes a destination, not a gov hash or change address");
        }
        if (p.target_height <= ex.tip_height)
            throw ScanRefusal(cause::kBadTarget, "target height " + std::to_string(p.target_height) +
                                                     " is not above the scan tip " + std::to_string(ex.tip_height));
        if (p.min_confirmations < 1 || p.dust_floor < 0)
            throw ScanRefusal(cause::kBadParams, "min_confirmations must be >= 1 and dust_floor >= 0");

        const std::array<uint8_t, 20> h160 = c2w::dash::addr_to_h160(ex.address, ex.testnet);
        const c2w::dash::TargetScreen ts = c2w::dash::rescreen_at_height(
            ex.utxos, h160, ex.tip_height, p.target_height, p.min_confirmations, p.dust_floor, true);

        // The mature inputs, optionally capped to the N oldest (the model's rule).
        std::vector<Utxo> pick = ts.screen.spendable;
        if (p.input_limit > 0 && p.input_limit < pick.size()) {
            std::stable_sort(pick.begin(), pick.end(), [](const Utxo& a, const Utxo& b) {
                return std::tie(a.height, a.txid, a.vout) < std::tie(b.height, b.txid, b.vout);
            });
            plan.not_selected = pick.size() - p.input_limit;
            pick.resize(p.input_limit);
        }
        plan.safe_from_height = c2w::dash::safe_from_height(pick, ex.tip_height);
        for (const Utxo& u : pick) plan.youngest_input_height = std::max(plan.youngest_input_height, u.height);

        // plan_sweep re-screens what it is given; offer it the immature and
        // dust rows too, exactly as the model does, so its summary matches.
        std::vector<Utxo> offered = pick;
        offered.insert(offered.end(), ts.screen.immature.begin(), ts.screen.immature.end());
        offered.insert(offered.end(), ts.screen.dust.begin(), ts.screen.dust.end());
        auto sweep_request = [&](size_t max_inputs) {
            c2w::dash::SweepRequest r;
            r.funding_address = ex.address;
            r.destination_address = collateral ? std::string() : p.destination;
            r.utxos = offered;
            r.min_confirmations = p.min_confirmations;
            r.dust_floor = p.dust_floor;
            r.testnet = ex.testnet;
            r.max_inputs_per_tx = max_inputs;
            r.key_encoding = p.key_encoding;
            r.fee_mode = p.fee_mode;
            r.fee_rate_per_byte = relay ? p.fee_rate_per_byte : 0;
            return r;
        };
        auto take_sweep = [&](const c2w::dash::SweepBatchPlan& sp) {
            for (const c2w::dash::SweepTxPlan& tx : sp.txs)
                plan.batches.push_back(batch_of(static_cast<int>(plan.batches.size()) + 1, tx.inputs,
                                                {{tx.value_out, tx.dest_spk}}, tx.fee, tx.unsigned_tx,
                                                tx.est_signed_bytes));
            plan.total_in = sp.total_in;
            plan.total_fee = sp.total_fee;
            plan.summary = sp.summary;
        };

        if (!collateral) {
            if (p.max_inputs_per_tx == 0) p.max_inputs_per_tx = caps::kMaxInjectInputs;
            const c2w::dash::SweepBatchPlan sp = c2w::dash::plan_sweep(sweep_request(p.max_inputs_per_tx));
            plan.destination = sp.destination_address;
            take_sweep(sp);
            if (plan.batches.size() > caps::kFullBatchesPerPool)
                plan.warnings.push_back(std::to_string(plan.batches.size()) + " batches: one node's inject pool holds " +
                                        std::to_string(caps::kFullBatchesPerPool) +
                                        " full batches; stagger the adds (--not-before-height) or let the "
                                        "scheduler's pool-full retry do it");
        } else {
            if (pick.empty())
                refuse("nothing mature: " + std::to_string(ts.screen.immature.size()) + " immature, " +
                       std::to_string(ts.screen.dust.size()) + " dust at target " + std::to_string(p.target_height));
            int64_t total = 0;
            for (const Utxo& u : pick) total += u.satoshis;
            if (total < c2w::dash::kGovernanceProposalFee)
                refuse("INSUFFICIENT: mature " + c2w::dash::format_dash(total) + " DASH < 1.00000000 (short " +
                       c2w::dash::format_dash(c2w::dash::kGovernanceProposalFee - total) + " DASH) at target height " +
                       std::to_string(p.target_height));
            plan.destination = p.change_address.empty() ? ex.address : p.change_address;
            const std::array<uint8_t, 25> change_spk =
                c2w::dash::p2pkh_script(c2w::dash::addr_to_h160(plan.destination, ex.testnet));
            const std::vector<uint8_t> burn =
                c2w::dash::collateral_op_return_script(c2w::dash::gov_hash_from_display(p.gov_hash));
            const int64_t change = total - c2w::dash::kGovernanceProposalFee;
            std::vector<std::pair<int64_t, std::vector<uint8_t>>> outs = {{c2w::dash::kGovernanceProposalFee, burn}};
            if (change > 0) outs.push_back({change, std::vector<uint8_t>(change_spk.begin(), change_spk.end())});

            // plan_collateral's inject branch: sweep_all, sorted by outpoint, fee 0.
            std::vector<Utxo> inputs = pick;
            c2w::dash::sort_by_outpoint(inputs);
            std::vector<uint8_t> utx = c2w::dash::serialize_unsigned_legacy_tx(inputs, outs);
            const size_t est = c2w::dash::est_signed_size(utx.size(), inputs.size(), p.key_encoding);
            if (inputs.size() <= caps::kMaxInjectInputs && est <= caps::kMaxInjectTxBytes) {
                plan.batches.push_back(batch_of(1, std::move(inputs), outs, 0, std::move(utx), est));
                plan.total_in = total;
                plan.summary = "governance collateral (inject, zero fee): " + std::to_string(pick.size()) +
                               " inputs, " + c2w::dash::format_dash(total) + " DASH in, burn 1.00000000 DASH, change " +
                               c2w::dash::format_dash(change) + " DASH -> " + plan.destination + ", est signed " +
                               std::to_string(est) + " B\n";
            } else {
                // Two stages: consolidate to the funding address, then the
                // collateral spends the stage-1 outputs.
                plan.two_stage = true;
                const c2w::dash::SweepBatchPlan sp = c2w::dash::plan_sweep(sweep_request(caps::kMaxInjectInputs));
                take_sweep(sp);
                const int k = static_cast<int>(plan.batches.size());
                std::vector<Utxo> placeholders(static_cast<size_t>(k));
                for (Utxo& u : placeholders) u.txid = std::string(64, '0');
                const std::vector<uint8_t> shape = c2w::dash::serialize_unsigned_legacy_tx(placeholders, outs);
                PlannedBatch s2;
                s2.index = k + 1;
                for (int i = 1; i <= k; ++i) s2.depends_on.push_back(i);
                s2.vin = static_cast<size_t>(k);
                s2.value_out = total;
                s2.fee = 0;
                s2.est_signed_bytes = c2w::dash::est_signed_size(shape.size(), s2.vin, p.key_encoding);
                s2.outputs = outs;
                plan.batches.push_back(std::move(s2));
                plan.warnings.push_back("the collateral does not fit one inject tx (" + std::to_string(pick.size()) +
                                        " inputs, est " + std::to_string(est) +
                                        " B): two stages; sign stage 1, then write the stage-2 intake from its txids");
                plan.summary += "stage 2: governance collateral spending the " + std::to_string(k) +
                                " stage-1 output(s): burn 1.00000000 DASH, change " + c2w::dash::format_dash(change) +
                                " DASH -> " + plan.destination + "\n";
            }
        }
    } catch (const c2w::dash::DashAbort& e) {
        refuse(e.what());
    }
    plan.params = p;
    plan.plan_id = sha256_hex(plan_identity_text(plan));
    return plan;
}

std::string stage2_export(const ScanPlan& plan, const std::vector<std::string>& stage1_txids, int64_t landing_height)
{
    if (!plan.two_stage)
        throw ScanRefusal(cause::kUnsupported, "stage2_export: the plan has one stage");
    const size_t k = plan.batches.size() - 1;
    if (stage1_txids.size() != k)
        throw ScanRefusal(cause::kPlanRefused, "stage 1 has " + std::to_string(k) + " batch(es), " +
                                                   std::to_string(stage1_txids.size()) + " txid(s) given");
    if (landing_height <= plan.tip_height)
        throw ScanRefusal(cause::kPlanRefused, "the stage-1 landing height must be above the scan tip " +
                                                   std::to_string(plan.tip_height));
    const std::array<uint8_t, 25> spk = c2w::dash::p2pkh_script(c2w::dash::addr_to_h160(plan.address, plan.testnet));
    UtxoImport imp;
    imp.source = c2w::dash::UtxoSource::ExportV1;
    imp.address = plan.address;
    imp.testnet = plan.testnet;
    imp.tip_height = landing_height;
    imp.coinbase_flags = true;
    for (size_t i = 0; i < k; ++i) {
        if (!is_hex64(stage1_txids[i]))
            throw ScanRefusal(cause::kPlanRefused, "stage-1 txid " + std::to_string(i + 1) + " is not 64 hex characters");
        Utxo u;
        u.txid = lower(stage1_txids[i]);
        u.vout = 0;
        u.satoshis = plan.batches[i].value_out;
        u.height = landing_height;
        u.confirmations = 1;
        u.coinbase = false;
        u.script_pubkey_hex = c2w::artifact::to_hex(spk.data(), spk.size());
        imp.total += u.satoshis;
        imp.utxos.push_back(std::move(u));
    }
    return write_export_v1(imp);
}

} // namespace c2w::companion::scan
