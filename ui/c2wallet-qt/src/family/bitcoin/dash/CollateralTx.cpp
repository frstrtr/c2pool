// SPDX-License-Identifier: AGPL-3.0-or-later
#include "CollateralTx.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "GovCollateral.hpp"

#include "../hdkeys/HexUtil.hpp" // std-only decl; from_hex/to_hex live in the hdkeys .a

// The M3-A signing core (vendored dashscript closure). This is the ONLY DASH TU
// that pulls it — kept off the btclibs closure so the two vendored uint256/hash
// trees never meet in one translation unit.
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

std::string dash_amount(int64_t duffs)
{
    std::ostringstream o;
    o << (duffs / kCoin) << '.';
    std::ostringstream frac;
    frac.width(8);
    frac.fill('0');
    frac << (duffs % kCoin);
    o << frac.str();
    return o.str();
}

std::vector<Utxo> normalize_utxos(const std::vector<Utxo>& raw,
                                  const std::array<uint8_t, 20>& funding_h160,
                                  int64_t min_conf,
                                  int& skipped_immature)
{
    const std::array<uint8_t, 25> want_script = p2pkh_script(funding_h160);
    std::vector<Utxo> out;
    skipped_immature = 0;
    for (const Utxo& u : raw) {
        if (u.txid.size() != 64 || !hdkeys::from_hex(u.txid))
            throw DashAbort("malformed UTXO entry: bad txid");
        if (u.satoshis < 0)
            throw DashAbort("malformed UTXO entry: negative value");
        if (!u.script_pubkey_hex.empty()) {
            auto spk = hdkeys::from_hex(u.script_pubkey_hex);
            if (!spk)
                throw DashAbort("malformed UTXO entry: scriptPubKey is not hex");
            if (spk->size() != want_script.size() ||
                !std::equal(spk->begin(), spk->end(), want_script.begin()))
                throw DashAbort("UTXO " + u.txid + " scriptPubKey does NOT pay the funding "
                                "address — refusing to touch it");
        }
        if (u.confirmations < min_conf) {
            ++skipped_immature;
            continue;
        }
        out.push_back(u);
    }
    return out;
}

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

} // namespace

CollateralPlan plan_collateral(const CollateralRequest& req)
{
    if (req.fee_rate < 100 || req.fee_rate > 100000)
        throw DashAbort("fee-rate is outside the sane range [100, 100000] duffs/kB");
    if (req.time_ <= 1400000000)
        throw DashAbort("time does not look like a recent unix epoch");
    if (req.revision < 1)
        throw DashAbort("revision must be >= 1");

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(req.funding_address, req.testnet);
    const std::string change_addr =
        req.change_address.empty() ? req.funding_address : req.change_address;
    const std::array<uint8_t, 20> change_h160 = addr_to_h160(change_addr, req.testnet);

    CollateralPlan plan;
    plan.testnet = req.testnet;
    plan.funding_address = req.funding_address;
    plan.change_address = change_addr;

    plan.gov_hash_internal =
        gov_object_hash(req.parent_hash_hex, req.revision, req.time_, req.data_hex);
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

    int skipped = 0;
    std::vector<Utxo> mature =
        normalize_utxos(req.utxos, funding_h160, req.min_confirmations, skipped);
    if (mature.empty())
        throw DashAbort("no spendable UTXOs after maturity filtering");

    Selection sel = select_coins(mature, req.fee_rate);
    plan.selected = sel.selected;
    plan.fee = sel.fee;
    plan.change = sel.change;
    for (const Utxo& u : plan.selected) plan.total_in += u.satoshis;

    (void)change_h160;

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
        s << "  " << u.txid << ":" << u.vout << "  " << dash_amount(u.satoshis) << " DASH  ("
          << u.confirmations << " conf)\n";
    s << "total in:          " << dash_amount(plan.total_in) << " DASH\n";
    s << "output 0 (BURN):   " << dash_amount(kGovernanceProposalFee)
      << " DASH  OP_RETURN <collateral hash>\n";
    if (plan.change > 0)
        s << "output 1 (change): " << dash_amount(plan.change) << " DASH  -> " << change_addr
          << "\n";
    else
        s << "output 1:          (no change output; sub-dust remainder folded into fee)\n";
    s << "fee:               " << dash_amount(plan.fee) << " DASH (" << plan.fee << " duffs)\n";
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

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(plan.funding_address, plan.testnet);
    const CScript funding_spk = signer::p2pkh_from_h160(h160_bytes(funding_h160));

    signer::Signer s(2, 0); // Dash classic (type-0) tx, version 2
    for (const Utxo& u : plan.selected) {
        uint256 prev;
        prev.SetHex(u.txid.c_str());
        s.add_input(prev, u.vout, u.satoshis, funding_spk);
    }
    s.add_output(kGovernanceProposalFee,
                 CScript(plan.op_return_script.begin(), plan.op_return_script.end()));
    if (plan.change > 0) {
        const std::array<uint8_t, 20> change_h160 =
            addr_to_h160(plan.change_address, plan.testnet);
        s.add_output(plan.change, signer::p2pkh_from_h160(h160_bytes(change_h160)));
    }

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

    SignedTx tx;
    tx.hex = hdkeys::to_hex(out);
    tx.txid = s.txid().GetHex();
    tx.size = out.size();
    return tx;
}

} // namespace c2w::dash
