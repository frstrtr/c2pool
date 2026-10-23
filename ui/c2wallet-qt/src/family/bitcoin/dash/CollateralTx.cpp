// SPDX-License-Identifier: AGPL-3.0-or-later
#include "CollateralTx.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "GovCollateral.hpp"
#include "SweepTx.hpp"    // std-only: serialize_unsigned_legacy_tx / est_signed_size
#include "UtxoIntake.hpp" // std-only: screen_utxos / describe_skipped / format_dash

#include "../hdkeys/HexUtil.hpp" // std-only decl; from_hex/to_hex live in the hdkeys .a

// The M3-A signing core (vendored dashscript closure). Only this TU and
// SweepSign.cpp pull it — kept off the btclibs closure so the two vendored
// uint256/hash trees never meet in one translation unit.
#include "../signer/Scripts.hpp"
#include "../signer/Signer.hpp"

#include <algorithm>
#include <sstream>

namespace c2w::dash {

namespace {

using signer::Bytes;

size_t compact_size_len(uint64_t n)
{
    if (n < 0xFD) return 1;
    if (n <= 0xFFFF) return 3;
    if (n <= 0xFFFFFFFFull) return 5;
    return 9;
}

// Worst-case P2PKH legacy-tx size (matches dash_collateral_tx.py estimate_size):
// 4 version + cs(nin) + nin*148 + cs(nout) + 43 (OP_RETURN out) + 34 (change) + 4.
size_t estimate_size(size_t n_inputs, bool with_change)
{
    const size_t n_out = with_change ? 2 : 1;
    return 4 + compact_size_len(n_inputs) + n_inputs * 148 + compact_size_len(n_out) + 43 +
           (with_change ? 34 : 0) + 4;
}

int64_t fee_for(size_t bytes, int64_t feerate_per_kb)
{
    const int64_t f = (static_cast<int64_t>(bytes) * feerate_per_kb + 999) / 1000;
    return f < 1000 ? 1000 : f;
}

Bytes h160_bytes(const std::array<uint8_t, 20>& h) { return Bytes(h.begin(), h.end()); }

struct Selection {
    std::vector<Utxo> selected;
    int64_t fee = 0;
    int64_t change = 0;
};

Selection select_coins(std::vector<Utxo> utxos, int64_t feerate_per_kb)
{
    std::sort(utxos.begin(), utxos.end(),
              [](const Utxo& a, const Utxo& b) { return a.satoshis > b.satoshis; });
    Selection sel;
    int64_t total = 0;
    for (const Utxo& u : utxos) {
        sel.selected.push_back(u);
        total += u.satoshis;
        const int64_t fee = fee_for(estimate_size(sel.selected.size(), true), feerate_per_kb);
        const int64_t need = kGovernanceProposalFee + fee;
        if (total >= need) {
            const int64_t change = total - need;
            if (change < kDustDuffs) {
                const int64_t fee_nc =
                    fee_for(estimate_size(sel.selected.size(), false), feerate_per_kb);
                if (total - kGovernanceProposalFee >= fee_nc) {
                    sel.fee = total - kGovernanceProposalFee;
                    sel.change = 0;
                    return sel;
                }
                continue; // need one more input
            }
            sel.fee = fee;
            sel.change = change;
            return sel;
        }
    }
    throw DashAbort("INSUFFICIENT FUNDS: mature UTXOs do not cover 1 DASH collateral + fee. "
                    "Nothing was signed.");
}

// sweep_all: every spendable UTXO goes in. Inject mode pays no fee and gives
// the change everything above the burn; Relay mode pays fee_rate for the whole
// set and folds a sub-dust change into the fee, as select_coins does.
Selection sweep_coins(std::vector<Utxo> inputs, bool inject, int64_t feerate_per_kb,
                      size_t skipped_immature, size_t skipped_dust)
{
    Selection sel;
    int64_t total = 0;
    for (const Utxo& u : inputs) {
        if (__builtin_add_overflow(total, u.satoshis, &total) || total > kMaxMoney)
            throw DashAbort("UTXO total exceeds MAX_MONEY — the UTXO amounts are not real");
    }
    sel.selected = std::move(inputs);
    const std::string skipped = std::to_string(skipped_immature) + " immature and " +
                                std::to_string(skipped_dust) + " dust UTXOs were skipped";
    if (inject) {
        if (total < kGovernanceProposalFee)
            throw DashAbort("INSUFFICIENT: mature " + format_dash(total) +
                            " DASH < 1.00000000 (short " +
                            format_dash(kGovernanceProposalFee - total) + " DASH); " + skipped +
                            ". Nothing was signed.");
        sel.fee = 0;
        sel.change = total - kGovernanceProposalFee;
        return sel;
    }
    const size_t n = sel.selected.size();
    const int64_t fee = fee_for(estimate_size(n, true), feerate_per_kb);
    if (total >= kGovernanceProposalFee + fee) {
        sel.fee = fee;
        sel.change = total - kGovernanceProposalFee - fee;
        if (sel.change < kDustDuffs) {
            sel.fee += sel.change;
            sel.change = 0;
        }
        return sel;
    }
    const int64_t fee_nc = fee_for(estimate_size(n, false), feerate_per_kb);
    if (total >= kGovernanceProposalFee + fee_nc) {
        sel.fee = total - kGovernanceProposalFee;
        sel.change = 0;
        return sel;
    }
    throw DashAbort("INSUFFICIENT FUNDS: mature UTXOs do not cover 1 DASH collateral + fee; " +
                    skipped + ". Nothing was signed.");
}

} // namespace

CollateralPlan plan_collateral(const CollateralRequest& req)
{
    const bool inject = req.fee_mode == FeeMode::InjectOnlyZeroFee;
    if (inject) {
        if (req.fee_rate != 0)
            throw DashAbort("INJECT-ONLY zero-fee mode needs fee_rate 0 (got " +
                            std::to_string(req.fee_rate) +
                            " duffs/kB); a fee-paying collateral is FeeMode::Relay");
        if (!req.sweep_all)
            throw DashAbort("INJECT-ONLY zero-fee mode needs sweep_all: every mature UTXO goes "
                            "in and the change takes the rest, so the fee is exactly 0");
    } else {
        if (req.fee_rate == 0)
            throw DashAbort("zero fee is inject-only; set FeeMode::InjectOnlyZeroFee (Dash Core "
                            "peers will not relay a zero-fee tx)");
        if (req.fee_rate < 100 || req.fee_rate > 100000)
            throw DashAbort("fee-rate is outside the sane range [100, 100000] duffs/kB");
    }
    if (req.dust_floor < 0)
        throw DashAbort("dust_floor must be >= 0");

    // Direct mode takes the hash as given; the object fields are then optional,
    // and when present they must reproduce it.
    const bool direct = !req.gov_hash_display.empty();
    const bool have_object = !direct || req.time_ != 0 || !req.data_hex.empty();
    if (have_object) {
        if (req.time_ <= 1400000000)
            throw DashAbort("time does not look like a recent unix epoch");
        if (req.revision < 1)
            throw DashAbort("revision must be >= 1");
    }

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(req.funding_address, req.testnet);
    const std::string change_addr =
        req.change_address.empty() ? req.funding_address : req.change_address;
    const std::array<uint8_t, 20> change_h160 = addr_to_h160(change_addr, req.testnet);

    CollateralPlan plan;
    plan.testnet = req.testnet;
    plan.funding_address = req.funding_address;
    plan.change_address = change_addr;
    plan.fee_mode = req.fee_mode;

    if (have_object)
        plan.gov_hash_internal =
            gov_object_hash(req.parent_hash_hex, req.revision, req.time_, req.data_hex);
    if (direct) {
        const std::array<uint8_t, 32> given = gov_hash_from_display(req.gov_hash_display);
        if (have_object && given != plan.gov_hash_internal)
            throw DashAbort("hash derived from time/data " +
                            gov_hash_display(plan.gov_hash_internal) + " != gov_hash_display " +
                            gov_hash_display(given) +
                            " — the OP_RETURN would commit to the WRONG object");
        plan.gov_hash_internal = given;
    }
    plan.gov_hash_display = gov_hash_display(plan.gov_hash_internal);
    if (!req.expected_hash_display.empty()) {
        std::string want = req.expected_hash_display;
        for (char& c : want)
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (want != plan.gov_hash_display)
            throw DashAbort("derived collateral hash " + plan.gov_hash_display +
                            " != expected-hash " + want +
                            " — the OP_RETURN would commit to the WRONG object");
    }
    plan.op_return_script = collateral_op_return_script(plan.gov_hash_internal);

    // Inject mode and sweep_all are strict: every UTXO must carry its
    // scriptPubKey and no outpoint may appear twice. The classic Relay selection
    // keeps its optional scriptPubKey.
    const UtxoScreen screen = screen_utxos(req.utxos, funding_h160, req.min_confirmations,
                                           req.dust_floor, inject || req.sweep_all);
    plan.skipped_immature = screen.immature;
    plan.skipped_dust = screen.dust.size();

    Selection sel;
    if (!req.sweep_all) {
        // The classic Relay selection, unchanged: largest-first, minimal set.
        if (screen.spendable.empty())
            throw DashAbort("no spendable UTXOs after maturity filtering");
        sel = select_coins(screen.spendable, req.fee_rate);
    } else {
        if (screen.spendable.empty())
            throw DashAbort("no spendable UTXOs: every UTXO is immature (" +
                            std::to_string(screen.immature.size()) + ") or dust (" +
                            std::to_string(screen.dust.size()) + "). Nothing was signed.");
        std::vector<Utxo> inputs = screen.spendable;
        if (!req.preserve_input_order) sort_by_outpoint(inputs);
        sel = sweep_coins(std::move(inputs), inject, req.fee_rate, screen.immature.size(),
                          screen.dust.size());
    }
    plan.selected = sel.selected;
    plan.fee = sel.fee;
    plan.change = sel.change;
    for (const Utxo& u : plan.selected) plan.total_in += u.satoshis;

    (void)change_h160;

    // The exact bytes sign_collateral will sign, and their worst-case signed size.
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> outputs = {
        {kGovernanceProposalFee, plan.op_return_script}};
    if (plan.change > 0) {
        const std::array<uint8_t, 25> cs = p2pkh_script(change_h160);
        outputs.push_back({plan.change, std::vector<uint8_t>(cs.begin(), cs.end())});
    }
    plan.unsigned_tx = serialize_unsigned_legacy_tx(plan.selected, outputs);
    plan.est_signed_bytes =
        est_signed_size(plan.unsigned_tx.size(), plan.selected.size(), req.key_encoding);

    // A collateral is ONE tx: over the node's inject caps it is refused, never split.
    const bool extended = inject || req.sweep_all;
    if (extended) {
        if (plan.selected.size() > caps::kMaxInjectInputs)
            throw DashAbort(std::to_string(plan.selected.size()) +
                            " inputs exceed the node's inject cap of " +
                            std::to_string(caps::kMaxInjectInputs) +
                            ". A collateral is one tx and is never split: raise dust_floor or "
                            "consolidate first (SweepTx). Nothing was signed.");
        if (plan.est_signed_bytes > caps::kMaxInjectTxBytes)
            throw DashAbort("estimated signed size " + std::to_string(plan.est_signed_bytes) +
                            " B exceeds the node's " + std::to_string(caps::kMaxInjectTxBytes) +
                            " B cap. A collateral is one tx and is never split: raise "
                            "dust_floor or consolidate first (SweepTx). Nothing was signed.");
    }

    std::ostringstream s;
    s << "======================================================================\n";
    s << "DASH GOVERNANCE COLLATERAL TX -- DRY-RUN SUMMARY ("
      << (req.testnet ? "TESTNET" : "MAINNET") << ")\n";
    s << "======================================================================\n";
    s << "collateral hash:   " << plan.gov_hash_display << "\n";
    s << "                   (the <collateral-hash> argument of `gobject submit`)\n";
    s << "OP_RETURN script:  " << hdkeys::to_hex(plan.op_return_script) << "\n";
    s << "inputs (" << plan.selected.size() << "):\n";
    for (const Utxo& u : plan.selected)
        s << "  " << u.txid << ":" << u.vout << "  " << format_dash(u.satoshis) << " DASH  ("
          << u.confirmations << " conf)\n";
    s << "total in:          " << format_dash(plan.total_in) << " DASH\n";
    s << "output 0 (BURN):   " << format_dash(kGovernanceProposalFee)
      << " DASH  OP_RETURN <collateral hash>\n";
    if (plan.change > 0)
        s << "output 1 (change): " << format_dash(plan.change) << " DASH  -> " << change_addr
          << "\n";
    else if (inject)
        s << "output 1:          (no change output; the inputs are exactly 1 DASH)\n";
    else
        s << "output 1:          (no change output; sub-dust remainder folded into fee)\n";
    if (inject)
        s << "fee 0.00000000 (INJECT-ONLY: Dash Core peers will not relay; rides only a c2pool "
             "block)\n";
    else
        s << "fee:               " << format_dash(plan.fee) << " DASH (" << plan.fee
          << " duffs)\n";
    if (extended) {
        s << "est signed " << plan.est_signed_bytes << "/" << caps::kMaxInjectTxBytes << " B\n";
        s << describe_skipped(screen, req.min_confirmations, req.dust_floor);
        s << "NOTE: legacy sighash commits no input amounts. If a UTXO amount above is\n"
             "      understated the difference becomes block fee; if it is overstated the\n"
             "      node refuses the tx.\n";
    }
    s << "----------------------------------------------------------------------\n";
    s << "WARNING: this transaction SPENDS REAL FUNDS and irreversibly BURNS 1 DASH.\n";
    s << "======================================================================\n";
    plan.summary = s.str();

    return plan;
}

SignedTx sign_collateral(const CollateralPlan& plan, const FoundKey& key, bool confirm_spend)
{
    // The typed-SPEND gate in library form: never auto-sign.
    if (!confirm_spend)
        throw DashAbort("not confirmed (confirm_spend=false); nothing was signed");
    if (key.address != plan.funding_address)
        throw DashAbort("the supplied key is for " + key.address + ", not the funding address " +
                        plan.funding_address + " — refusing to sign");

    const bool inject = plan.fee_mode == FeeMode::InjectOnlyZeroFee;
    if (plan.fee == 0 && !inject)
        throw DashAbort("zero fee is inject-only and this plan is not FeeMode::InjectOnlyZeroFee "
                        "— refusing to sign");
    if (inject && plan.fee != 0)
        throw DashAbort("an INJECT-ONLY plan must pay a fee of exactly 0 — refusing to sign");
    if (inject && plan.selected.size() > caps::kMaxInjectInputs)
        throw DashAbort("the plan exceeds the node's inject input cap — refusing to sign");

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(plan.funding_address, plan.testnet);
    if (signer::hash160(key.pub) != h160_bytes(funding_h160))
        throw DashAbort("the supplied key's pubkey does not hash to the funding address — "
                        "refusing to sign");
    const CScript funding_spk = signer::p2pkh_from_h160(h160_bytes(funding_h160));

    signer::Signer s(2, 0); // Dash classic (type-0) tx, version 2
    for (const Utxo& u : plan.selected) {
        uint256 prev;
        prev.SetHex(u.txid.c_str());
        s.add_input(prev, u.vout, u.satoshis, funding_spk, caps::kSequenceFinal);
    }
    s.add_output(kGovernanceProposalFee,
                 CScript(plan.op_return_script.begin(), plan.op_return_script.end()));
    if (plan.change > 0) {
        const std::array<uint8_t, 20> change_h160 =
            addr_to_h160(plan.change_address, plan.testnet);
        s.add_output(plan.change, signer::p2pkh_from_h160(h160_bytes(change_h160)));
    }

    // Sign exactly what the dry run showed: the skeleton must be the plan's bytes.
    if (s.serialize(false) != plan.unsigned_tx)
        throw DashAbort("the tx about to be signed is not the planned one (plan.unsigned_tx) — "
                        "refusing to sign");

    // Legacy P2PKH sighash scriptCode = the funding scriptPubKey; the M3-A signer
    // owns RFC6979/low-S/DER and the SIGHASH_ALL preimage.
    for (size_t i = 0; i < plan.selected.size(); ++i) {
        Bytes sig = s.make_legacy_sig(i, funding_spk, key.priv, SIGHASH_ALL);
        if (sig.empty())
            throw DashAbort("signing input " + std::to_string(i) + " failed");
        CScript scriptsig;
        scriptsig << sig << key.pub; // <sig‖hashtype> <pubkey>
        s.set_scriptsig(i, scriptsig);
    }

    // Self-verify EVERY input through the vendored interpreter + oversize refusal.
    Bytes out;
    std::string err;
    if (!s.finalize(out, err))
        throw DashAbort("self-verify / oversize gate FAILED before emit: " + err);
    if (inject && out.size() > caps::kMaxInjectTxBytes)
        throw DashAbort("signed size " + std::to_string(out.size()) + " B exceeds the node's " +
                        std::to_string(caps::kMaxInjectTxBytes) + " B inject cap");

    SignedTx tx;
    tx.hex = hdkeys::to_hex(out);
    tx.txid = s.txid().GetHex();
    tx.size = out.size();
    return tx;
}

} // namespace c2w::dash
