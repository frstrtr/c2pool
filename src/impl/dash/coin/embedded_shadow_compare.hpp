// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH Embedded-vs-dashd block-template SHADOW-COMPARE DIAGNOSTIC
/// (--embedded-shadow-compare).
///
/// ══ WHAT THIS IS (and, emphatically, WHAT IT IS NOT) ════════════════════════
/// A pure OBSERVABILITY probe. On every block-template SERVE resolution (the
/// same trigger that produces the template a miner mines) it best-effort obtains
/// dashd's getblocktemplate for the SAME height and field-compares the two, then
/// LOGS one self-describing [SHADOW] line and bumps a counter. That is the whole
/// contract.
///
/// THIS IS NOT A SERVE GATE. It never selects, blocks, delays, re-orders, or
/// alters the template that gets served. It is deliberately SEPARATE from the
/// EmbeddedOracleShadow graduation gate (embedded_oracle_shadow.hpp): that one is
/// tip-triggered and drives a revocable "safe to disable dashd" verdict; THIS one
/// is serve-triggered, keeps no graduation state, and makes no claim beyond "at
/// height H, the field-by-field diff between what we served and what dashd would
/// have served looks like <X>". A [SHADOW] MISMATCH is DIAGNOSTIC EVIDENCE, not
/// proof of a bad served block (see the SEMANTIC note below).
///
/// ══ HOT-PATH DISCIPLINE (hard invariant) ════════════════════════════════════
/// The dashd oracle fetch is ALWAYS off the miner-facing path. on_serve() only
/// ENQUEUES a copy of the just-resolved template (coalescing to the newest) and
/// returns; a dedicated worker thread runs the dashd RPC + compare + log. The
/// serve path therefore NEVER waits on the oracle: if dashd is slow, hung, or
/// absent the miner-facing response is completely unaffected and the worker
/// simply logs `no-oracle` for that sample. Nothing this class does can add
/// latency to, or change the bytes of, the served template.
///
/// ══ DEFAULT OFF / DAEMONLESS ════════════════════════════════════════════════
/// Only meaningful when a dashd RPC oracle is reachable (the getblocktemplate
/// closure is bound). In pure-daemonless production no oracle is bound, so the
/// probe is never constructed and this is a strict no-op. Flag-gated
/// (--embedded-shadow-compare), default false.
///
/// ══ SEMANTIC — why a MISMATCH is not a served-block bug ══════════════════════
/// Two legitimate ways the compare can diverge WITHOUT anything wrong being
/// served:
///   (1) The fail-closed serve gate may have REFUSED the embedded arm at this
///       height (source == DashdFallback). Then the embedded fields we log are a
///       template that was NEVER served — a divergence here proves the gate did
///       its job, not that a bad block went out.
///   (2) dashd's template can legitimately differ in TX SELECTION (separate
///       mempool), which perturbs fee-dependent amounts and the tx-set. Those are
///       NOT validity-bearing for the coinbase-commitment fields.
///   (3) merkleRootMNList is TX-SET-DEPENDENT (the h=2516756 false-positive
///       class): the consensus rule (dashcore CalcCbTxMerkleRootMNList) derives
///       the committed root from the MN list AFTER folding in the block's OWN
///       ProTx special txs (types 1-4: ProReg/ProUpServ/ProUpReg/ProUpRev).
///       When the embedded arm serves coinbase-only and dashd's template carries
///       a mempool ProTx (at 2516756: a ProUpServTx revive), the two templates
///       are committing to DIFFERENT tx sets, so their roots legitimately
///       diverge — each is correct FOR ITS OWN BLOCK. Comparing them as if they
///       answered the same question is the false positive. The compare below
///       therefore only treats a merkleRootMNList divergence as
///       commitment-bearing when both templates fold the SAME ProTx set; a
///       divergence under DIFFERENT ProTx folds is surfaced as the benign
///       verdict MATCH-MODULO-MEMPOOL-PROTX with its own counter.
/// The single high-value signal — the ONLY combination that would indicate a real
/// validity problem — is: the embedded arm was SERVED (not refused) at height H
/// AND a CONSENSUS-COMMITMENT field (coinbase payee, merkleRootMNList under the
/// SAME ProTx fold, or merkleRootQuorums) diverged from dashd. That combination
/// is surfaced distinctly as `[SHADOW] h=H SERVED-MISMATCH ...` so it stands out
/// from the benign mismatch noise.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Header-only so the pure
/// evaluate()/diff logic is KAT-pinnable without a live node or a thread.

#include <impl/dash/coin/work_source.hpp>       // WorkSource
#include <impl/dash/coin/rpc_data.hpp>          // DashWorkData, PackedPayment
#include <impl/dash/coin/mempool_validity_gate.hpp>  // THE serve-flag gate (testmempoolaccept)
#include <impl/dash/coin/vendor/cbtx.hpp>       // vendor::CCbTx, vendor::parse_cbtx

#include <core/log.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ─────────────────────────────────────────────────────────────────────────────
// Pure comparison layer (no thread, no RPC, no node) — KAT-pinnable.
// ─────────────────────────────────────────────────────────────────────────────

/// One diverging field. `commitment` marks the consensus-commitment trio
/// (payee / merkleRootMNList / merkleRootQuorums) whose divergence — when the
/// embedded arm was SERVED — is the real-validity-problem signal.
/// `modulo_mempool_protx` marks a merkleRootMNList divergence that is explained
/// by the two templates folding DIFFERENT ProTx sets (semantic note (3)): the
/// roots answer different questions, so the divergence is benign-by-derivation
/// and is deliberately NOT commitment-bearing.
struct ShadowFieldDiff {
    std::string field;
    std::string embedded;
    std::string dashd;
    bool        commitment{false};
    bool        modulo_mempool_protx{false};
};
/// Which set on OUR side the measurement used.
///   Served    — the transactions actually in the template.
///   Candidate — what selection WOULD have chosen, recorded while the served
///               body is deliberately coinbase-only. This is the mode the
///               enable-the-flag gate must be evaluated in, because a
///               measurement over the served set reads 0% by construction
///               while the flag is off.
enum class ShadowTxSetMode { Served, Candidate, None };

inline const char* shadow_txset_mode_name(ShadowTxSetMode m)
{
    switch (m) {
        case ShadowTxSetMode::Served:    return "served";
        case ShadowTxSetMode::Candidate: return "candidate";
        default:                         return "none";
    }
}

/// ── THE MEMPOOL COVERAGE MEASUREMENT (phase-1 mempool ingest) ────────────
///
/// While dashd is still present, its template's tx set is a free, per-block
/// answer key for our own mempool. This is the cheapest possible proof that
/// our ingest is working.
///
/// ⚠ THIS IS A COVERAGE MEASUREMENT, NOT THE SERVE-FLAG GATE. It used to be
/// both: `ours_only == 0` was the stated condition for ever turning
/// --embedded-serve-mempool-txs on. Set membership is the wrong question in
/// two directions at once —
///   * UNREACHABLE: two independently-connected nodes never hold identical
///     mempools. MEASURED on the production hotel over 6056 samples,
///     ours_only == 0 in 91.2% and > 0 in 8.8%, mean 65.3 when non-zero, max
///     287; over the LAST 200 samples it was zero only 37% of the time.
///   * BLIND to the case that costs money: FEWER transactions than dashd but
///     INVALID ones. A strict subset passes `ours_only == 0` and can still
///     mint a rejected block.
/// The gate is now TRANSACTION VALIDITY, asked of dashd directly with
/// testmempoolaccept — see mempool_validity_gate.hpp. `ours_only` keeps being
/// measured and printed as an INFORMATIONAL coverage statistic and blocks
/// nothing.
///
/// The two directions are still not symmetric, as INFORMATION:
///   * dashd-only  — transactions dashd had and we did not. Pure REVENUE loss;
///     the coverage number the whole mempool project is trying to move.
///   * ours-only   — transactions WE selected and dashd's template did not
///     carry. Reads as "our view is ahead of, or simply different from, this
///     one dashd's" — worth watching as a trend, never a pass/fail.
/// Diagnostic only — nothing in the served decision reads this.
struct ShadowTxSetDiff
{
    ShadowTxSetMode mode{ShadowTxSetMode::None};
    size_t ours{0};
    size_t theirs{0};
    size_t both{0};
    size_t dashd_only{0};   // revenue we are leaving on the table
    size_t ours_only{0};    // INFORMATIONAL coverage statistic — NOT a gate

    // ── PER-TX FEE AGREEMENT — the VALUATION half ────────────────────────
    // Membership (above) proves we HAVE the transaction. It says nothing
    // about whether we priced it correctly, and valuation is the half that
    // can cost a block: the coinbase may claim at most subsidy + fees, so
    // OVERSTATING a fee is `bad-cb-amount` and the whole block is rejected,
    // while understating merely forfeits the difference.
    //
    // For every tx in BOTH sets we compare our fee against dashd's. That is a
    // direct, free, per-height proof that the prevout VALUES our UTXO view
    // holds are right for exactly the coins a template actually spends —
    // which is strictly less than, and much cheaper than, proving the whole
    // chainstate with hash_serialized_2.
    size_t fee_agree{0};
    size_t fee_understated{0};   // ours < dashd's: forfeits money, block valid
    size_t fee_overstated{0};    // ours > dashd's: BLOCK-LOSING. must stay 0.
    size_t fee_unknown{0};       // a side did not report a fee for a shared tx
    int64_t worst_overstatement{0};   // duffs, max(ours - theirs)
    std::string worst_overstated_txid;
    /// theirs == 0 means dashd's own template was coinbase-only: there was no
    /// fee to capture at this height, so the coverage ratio is undefined
    /// rather than 0% (counting it as a miss would slander the ingest lane).
    bool coverage_defined() const { return theirs != 0; }
    double coverage_pct() const
    {
        return coverage_defined() ? (100.0 * static_cast<double>(both)
                                     / static_cast<double>(theirs)) : 0.0;
    }
};

inline ShadowTxSetDiff shadow_tx_set_diff(const DashWorkData& embedded,
                                          const DashWorkData& dashd)
{
    // txid -> fee, but ONLY when the parallel vectors are aligned. When they
    // are not, report EMPTY rather than guessing: an unaligned WorkData would
    // otherwise manufacture a coverage number out of nothing, and a fabricated
    // measurement is worse than a missing one. A fee is carried as optional
    // separately from membership, because m_tx_fees may legitimately be
    // shorter (e.g. a builder that pushed hashes but no fee for a class it
    // does not price) and a MISSING fee must never read as a fee of zero —
    // zero would silently look like perfect agreement on a free transaction.
    auto index = [](const DashWorkData& w) {
        std::map<std::string, std::optional<uint64_t>> out;
        if (w.m_tx_hashes.size() != w.m_txs.size()) return out;
        for (size_t i = 0; i < w.m_tx_hashes.size(); ++i) {
            std::optional<uint64_t> fee;
            if (i < w.m_tx_fees.size()) fee = w.m_tx_fees[i];
            out.emplace(w.m_tx_hashes[i].GetHex(), fee);
        }
        return out;
    };
    // OUR side: the served set when there is one, otherwise the candidate set.
    // Preference order matters — a template that actually served transactions
    // must be measured on what it served, never on what it might have chosen.
    auto our_index = [&index](const DashWorkData& w) {
        auto served = index(w);
        if (!served.empty()) return std::make_pair(served, ShadowTxSetMode::Served);
        std::map<std::string, std::optional<uint64_t>> cand;
        for (size_t i = 0; i < w.m_txset_candidates.size(); ++i) {
            std::optional<uint64_t> fee;
            if (i < w.m_txset_candidate_fees.size())
                fee = w.m_txset_candidate_fees[i];
            cand.emplace(w.m_txset_candidates[i].GetHex(), fee);
        }
        return std::make_pair(cand, cand.empty() ? ShadowTxSetMode::None
                                                 : ShadowTxSetMode::Candidate);
    };
    const auto [e, e_mode] = our_index(embedded);
    const auto d = index(dashd);
    ShadowTxSetDiff r;
    r.mode = e_mode;
    r.ours = e.size();
    r.theirs = d.size();
    for (const auto& [txid, our_fee] : e) {
        auto it = d.find(txid);
        if (it == d.end()) { ++r.ours_only; continue; }
        ++r.both;
        if (!our_fee || !it->second) { ++r.fee_unknown; continue; }
        const uint64_t ours_f = *our_fee, theirs_f = *it->second;
        if (ours_f == theirs_f) { ++r.fee_agree; continue; }
        if (ours_f < theirs_f) { ++r.fee_understated; continue; }
        ++r.fee_overstated;
        const int64_t over = static_cast<int64_t>(ours_f - theirs_f);
        if (over > r.worst_overstatement) {
            r.worst_overstatement    = over;
            r.worst_overstated_txid  = txid;
        }
    }
    r.dashd_only = r.theirs - r.both;
    return r;
}



/// The verdict for one served height. MatchModuloMempoolProTx is the benign
/// verdict for "every divergence is the tx-set-dependent merkleRootMNList case"
/// — distinct from Match (nothing diverged) and from Mismatch (something else
/// did), each with its own counter, so the h=2516756 class stops masquerading
/// as SERVED-MISMATCH without becoming invisible.
struct ShadowOutcome {
    enum class Kind { NoOracle, Match, MatchModuloMempoolProTx, Mismatch };
    Kind                        kind{Kind::NoOracle};
    uint32_t                    height{0};
    bool                        served{false};   // source == WorkSource::Embedded
    std::string                 no_oracle_reason;
    std::vector<ShadowFieldDiff> diffs;          // diverging fields only
    bool                        served_mismatch{false}; // served && a commitment field diverged
    /// Mempool coverage vs dashd for this height (phase-1 ingest measurement).
    /// Zeroed on the no-oracle paths, where there is nothing to compare.
    ShadowTxSetDiff             tx_set;
    std::vector<std::string>    log_lines;        // the [SHADOW] lines, ready to emit
};

/// Counters, surfaced the way the existing gate markers surface: named tallies a
/// monitor/dashboard can read, plus a per-field breakdown keyed
/// "shadow-mismatch-<field>".
struct ShadowCounters {
    uint64_t shadow_match{0};
    uint64_t shadow_no_oracle{0};
    uint64_t shadow_served_mismatch{0};
    // The h=2516756 benign class: merkleRootMNList diverged ONLY because the
    // two templates fold different ProTx sets. Its own tally — benign must not
    // hide in shadow_match, and must never inflate served-mismatch.
    uint64_t shadow_match_modulo_mempool_protx{0};
    std::map<std::string, uint64_t> shadow_mismatch_by_field;   // field -> count

    void apply(const ShadowOutcome& o) {
        switch (o.kind) {
        case ShadowOutcome::Kind::NoOracle: shadow_no_oracle++; break;
        case ShadowOutcome::Kind::Match:    shadow_match++;     break;
        case ShadowOutcome::Kind::MatchModuloMempoolProTx:
            shadow_match_modulo_mempool_protx++;
            break;
        case ShadowOutcome::Kind::Mismatch:
            // A modulo diff riding along in a genuine Mismatch is still the
            // benign class — count it under its own key, not as a mismatch.
            for (const auto& d : o.diffs) {
                if (d.modulo_mempool_protx) shadow_match_modulo_mempool_protx++;
                else                        shadow_mismatch_by_field[d.field]++;
            }
            if (o.served_mismatch) shadow_served_mismatch++;
            break;
        }
    }
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["shadow-match"]           = shadow_match;
        j["shadow-no-oracle"]       = shadow_no_oracle;
        j["shadow-served-mismatch"] = shadow_served_mismatch;
        j["shadow-match-modulo-mempool-protx"] = shadow_match_modulo_mempool_protx;
        nlohmann::json byf = nlohmann::json::object();
        for (const auto& kv : shadow_mismatch_by_field)
            byf["shadow-mismatch-" + kv.first] = kv.second;
        j["shadow-mismatch-by-field"] = byf;
        return j;
    }
};

/// The ProTx FOLD of a template's tx set: a canonical (sorted) fingerprint of
/// the MN-list-affecting special txs (types 1-4) the template commits to.
/// merkleRootMNList is derived from the MN list AFTER these are applied
/// (dashcore CalcCbTxMerkleRootMNList), so two templates' roots are only
/// comparable when their folds are EQUAL — equal folds means the validator
/// rule was run over the same inputs, and a divergence is then a real root
/// bug. Identified by txid when the parallel m_tx_hashes vector is aligned;
/// the type+index fallback (mis-populated WorkData) deliberately errs toward
/// folds-DIFFER, i.e. toward the benign verdict, never toward a false
/// SERVED-MISMATCH.
inline std::vector<std::string> shadow_protx_fold(const DashWorkData& wd) {
    std::vector<std::string> fold;
    const bool hashes_aligned = (wd.m_tx_hashes.size() == wd.m_txs.size());
    for (std::size_t i = 0; i < wd.m_txs.size(); ++i) {
        const uint16_t t = wd.m_txs[i].type;
        if (t < 1 || t > 4) continue;   // only ProTx types feed the MN-list fold
        if (hashes_aligned)
            fold.push_back(wd.m_tx_hashes[i].GetHex());
        else
            fold.push_back("type" + std::to_string(t) + "#" + std::to_string(i));
    }
    std::sort(fold.begin(), fold.end());
    return fold;
}

/// First non-platform-burn payee ("!6a" is the DASH platform credit-pool
/// OP_RETURN burn, not a real payee) — the masternode payee identity.
inline std::string shadow_mn_payee(const std::vector<PackedPayment>& pps) {
    for (const auto& p : pps)
        if (p.payee != "!6a") return p.payee;
    return "(none)";
}

/// Pure evaluate: given the SERVED template, whether the embedded arm produced it
/// (source), and dashd's template for the SAME height (nullopt == oracle
/// unavailable / did not arrive in time / tip-skew), produce the outcome + the
/// exact [SHADOW] log lines. No side effects: does not read or mutate anything
/// beyond its arguments, so a reviewer can see the served template is untouched.
inline ShadowOutcome shadow_evaluate(WorkSource source,
                                     const DashWorkData& embedded,
                                     const std::optional<DashWorkData>& dashd_opt) {
    ShadowOutcome o;
    o.height = embedded.m_height;
    o.served = (source == WorkSource::Embedded);

    if (!dashd_opt) {
        o.kind = ShadowOutcome::Kind::NoOracle;
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height) + " no-oracle");
        return o;
    }
    const DashWorkData& dashd = *dashd_opt;

    // Same-height alignment is a precondition to compare at all: a template for a
    // DIFFERENT height is not the oracle for THIS one. Treat tip-skew as
    // "no oracle for this height" rather than false-flagging every field.
    if (dashd.m_height != embedded.m_height) {
        o.kind = ShadowOutcome::Kind::NoOracle;
        o.no_oracle_reason = "tip-skew(dashd_h=" + std::to_string(dashd.m_height) + ")";
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height)
                              + " no-oracle reason=" + o.no_oracle_reason);
        return o;
    }

    // ── MEMPOOL COVERAGE, measured against dashd's own set ───────────────
    // Emitted for every compared height, whether or not anything diverges:
    // the number only means something as a series.
    //
    // ⚠ THE "ours" SIDE IS ONLY OURS WHEN THE EMBEDDED ARM PRODUCED IT.
    // `embedded` here is the SERVED template. When the gate declined and the
    // node served the dashd-fallback arm, that argument IS dashd's template,
    // and diffing it against a fresh dashd template compares dashd with
    // itself — which reports a flawless ours=11 dashd=11 coverage=100%
    // fee_agree=11 while our own mempool holds one transaction. Live-observed
    // on the first soak run (h=2517157, gate cause=utxo-immature), and it is
    // exactly the kind of self-confirming number that gets quoted as evidence.
    // Membership and fee agreement are therefore measured ONLY when the
    // embedded arm actually built the thing being measured; otherwise the line
    // says why there is no measurement, and the counters stay zero.
    if (!o.served) {
        o.log_lines.push_back(
            "[SHADOW-TXSET] h=" + std::to_string(o.height)
            + " no-measurement reason=served-by-dashd-fallback"
              " (the 'ours' side would be dashd's own template — comparing it"
              " with dashd would report a fabricated 100%)");
    } else {
    o.tx_set = shadow_tx_set_diff(embedded, dashd);
    {
        std::string l = "[SHADOW-TXSET] h=" + std::to_string(o.height)
                      + " mode=" + shadow_txset_mode_name(o.tx_set.mode)
                      + " ours=" + std::to_string(o.tx_set.ours)
                      + " dashd=" + std::to_string(o.tx_set.theirs)
                      + " both=" + std::to_string(o.tx_set.both)
                      + " dashd_only=" + std::to_string(o.tx_set.dashd_only)
                      + " ours_only=" + std::to_string(o.tx_set.ours_only);
        l += o.tx_set.coverage_defined()
                 ? " coverage=" + std::to_string(
                       static_cast<int>(o.tx_set.coverage_pct() + 0.5)) + "%"
                 : " coverage=n/a(dashd-template-was-coinbase-only)";
        // The VALUATION half, always reported alongside membership: a soak
        // that compares only tx SETS proves membership, not pricing, and
        // pricing is the half that can cost a block.
        l += " fee_agree=" + std::to_string(o.tx_set.fee_agree)
           + " fee_under=" + std::to_string(o.tx_set.fee_understated)
           + " fee_over=" + std::to_string(o.tx_set.fee_overstated)
           + " fee_unknown=" + std::to_string(o.tx_set.fee_unknown);
        if (o.tx_set.ours_only)
            l += " ours_only_note=INFORMATIONAL (coverage statistic, NOT a"
                 " gate: two independently-connected mempools never coincide,"
                 " and a strict subset can still be invalid — serving is gated"
                 " on dashd testmempoolaccept validity, see [MEMPOOL-VALIDITY])";
        if (o.tx_set.fee_overstated)
            l += " ⚠⚠ FEE OVERSTATED on " + std::to_string(o.tx_set.fee_overstated)
               + " tx (worst +" + std::to_string(o.tx_set.worst_overstatement)
               + " duffs, " + o.tx_set.worst_overstated_txid.substr(0, 16)
               + ") — a coinbase claiming more than subsidy+fees is"
                 " bad-cb-amount and the block is REJECTED; do NOT enable"
                 " --embedded-serve-mempool-txs";
        o.log_lines.push_back(std::move(l));
    }
    }

    auto add = [&](const char* field, bool commitment,
                   const std::string& e, const std::string& d) {
        if (e != d) o.diffs.push_back({field, e, d, commitment});
    };

    // ── Consensus-commitment trio (validity-bearing for the SERVED signal) ────
    add("payee", /*commitment=*/true,
        shadow_mn_payee(embedded.m_packed_payments),
        shadow_mn_payee(dashd.m_packed_payments));

    vendor::CCbTx ecb, dcb;
    const bool eok = vendor::parse_cbtx(embedded.m_coinbase_payload, ecb);
    const bool dok = vendor::parse_cbtx(dashd.m_coinbase_payload, dcb);
    if (eok && dok) {
        // merkleRootMNList is TX-SET-DEPENDENT (semantic note (3), the
        // h=2516756 false-positive class): the validator derives it from the
        // MN list AFTER folding the block's own ProTx txs, so the two roots
        // only answer the SAME question when both templates fold the same
        // ProTx set. Equal folds + diverging roots = real root bug
        // (commitment-bearing, SERVED-MISMATCH eligible). Different folds
        // (e.g. embedded coinbase-only vs dashd carrying a mempool
        // ProUpServTx revive) = each root correct for its own block —
        // benign, marked modulo_mempool_protx, never commitment-bearing.
        // merkleRootMNList is TX-SET-DEPENDENT (semantic note (3), the
        // h=2516756 false-positive class): the validator derives it from the
        // MN list AFTER folding the block's own ProTx txs, so the two roots
        // only answer the SAME question when both templates fold the same
        // ProTx set. Equal folds + diverging roots = real root bug
        // (commitment-bearing, SERVED-MISMATCH eligible). Different folds
        // (e.g. embedded coinbase-only vs dashd carrying a mempool
        // ProUpServTx revive) = each root correct for its own block —
        // benign, marked modulo_mempool_protx, never commitment-bearing.
        if (ecb.merkleRootMNList != dcb.merkleRootMNList) {
            const bool same_protx_fold =
                shadow_protx_fold(embedded) == shadow_protx_fold(dashd);
            ShadowFieldDiff d{"merkleRootMNList",
                              ecb.merkleRootMNList.GetHex(),
                              dcb.merkleRootMNList.GetHex(),
                              /*commitment=*/same_protx_fold,
                              /*modulo_mempool_protx=*/!same_protx_fold};
            o.diffs.push_back(std::move(d));
        }
        add("merkleRootQuorums", /*commitment=*/true,
            ecb.merkleRootQuorums.GetHex(), dcb.merkleRootQuorums.GetHex());
        add("cbtx_version", /*commitment=*/false,
            std::to_string(ecb.nVersion), std::to_string(dcb.nVersion));
        add("cbtx_height",  /*commitment=*/false,
            std::to_string(ecb.nHeight),  std::to_string(dcb.nHeight));
    } else {
        // A CbTx we cannot parse is itself a divergence worth logging (but not a
        // commitment-trio member: we cannot read the roots to judge them).
        add("cbtx_parse", /*commitment=*/false,
            eok ? "ok" : "fail", dok ? "ok" : "fail");
    }

    // Coinbase scriptSig height (BIP34). At serve-resolution the assembled
    // coinbase input is not yet materialized in DashWorkData — the coinbase
    // builder BIP34-encodes the block height (m_height) into the scriptSig. So we
    // compare the height VALUE that will be encoded, which is exactly the
    // validity-bearing quantity a scriptSig-height check would catch.
    add("scriptsig_height", /*commitment=*/false,
        std::to_string(embedded.m_height), std::to_string(dashd.m_height));

    if (o.diffs.empty()) {
        o.kind = ShadowOutcome::Kind::Match;
        o.log_lines.push_back("[SHADOW] h=" + std::to_string(o.height) + " MATCH");
        return o;
    }

    // When EVERY divergence is the tx-set-dependent merkleRootMNList case the
    // whole sample is the benign verdict, by its own name — the two templates
    // agree on everything that answers the same question.
    const bool all_modulo = std::all_of(
        o.diffs.begin(), o.diffs.end(),
        [](const ShadowFieldDiff& d) { return d.modulo_mempool_protx; });
    if (all_modulo) {
        o.kind = ShadowOutcome::Kind::MatchModuloMempoolProTx;
        for (const auto& d : o.diffs)
            o.log_lines.push_back(
                std::string("[SHADOW] h=") + std::to_string(o.height)
                + " MATCH-MODULO-MEMPOOL-PROTX field=" + d.field
                + " embedded=" + d.embedded
                + " dashd=" + d.dashd
                + " (roots fold different ProTx sets — each correct for its own block)");
        return o;
    }

    o.kind = ShadowOutcome::Kind::Mismatch;
    for (const auto& d : o.diffs)
        if (d.commitment && o.served) o.served_mismatch = true;

    // One line per diverging field. The served + commitment combination is the
    // ONLY real-validity-problem signal, so it gets the distinct SERVED-MISMATCH
    // marker; a tx-set-dependent root divergence riding along keeps its benign
    // MATCH-MODULO marker; every other divergence is benign-until-proven and
    // gets MISMATCH.
    for (const auto& d : o.diffs) {
        const bool served_bad = o.served && d.commitment;
        const char* marker = d.modulo_mempool_protx ? " MATCH-MODULO-MEMPOOL-PROTX"
                           : served_bad             ? " SERVED-MISMATCH"
                                                    : " MISMATCH";
        o.log_lines.push_back(
            std::string("[SHADOW] h=") + std::to_string(o.height)
            + marker
            + " field=" + d.field
            + " embedded=" + d.embedded
            + " dashd=" + d.dashd);
    }
    return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime driver. Enqueue-only on the serve path; a worker thread does the RPC +
// compare + log so the miner-facing response never waits on dashd.
// ─────────────────────────────────────────────────────────────────────────────
class EmbeddedShadowCompare {
public:
    /// Returns dashd's getblocktemplate as a DashWorkData for the current tip,
    /// or nullopt on any failure/absence (so a slow/hung/missing dashd degrades
    /// to a `no-oracle` log line, never a stall). Bound in main_dash.cpp.
    using OracleFn = std::function<std::optional<DashWorkData>()>;

    /// dashd `testmempoolaccept` for ONE raw transaction hex -> the single
    /// result object, or a null json on any failure/absence. Optional: unbound
    /// leaves the MEMPOOL VALIDITY GATE unevaluated (and therefore CLOSED),
    /// which is the correct reading of "we could not ask".
    using AcceptFn = std::function<nlohmann::json(const std::string& raw_tx_hex)>;

    explicit EmbeddedShadowCompare(OracleFn oracle, AcceptFn accept = nullptr)
        : oracle_(std::move(oracle)), accept_(std::move(accept)) {
        LOG_INFO << "[SHADOW] embedded-vs-dashd shadow-compare ARMED (diagnostic "
                    "only; NOT a serve gate; oracle fetch off the hot path)";
        if (accept_)
            LOG_INFO << "[MEMPOOL-VALIDITY] gate ARMED: every transaction we"
                        " would serve is put to dashd testmempoolaccept."
                        " Condition to arm --embedded-serve-mempool-txs = ZERO"
                        " INVALID over "
                     << MempoolValidityGate::kCleanHeightsRequired
                     << " consecutive evidence-bearing DISTINCT heights (>=25h"
                        " at DASH's 2.625 min/block; this probe fires ~5-6x per"
                        " block and repeats do NOT advance the window)."
                        " ours_only is INFORMATIONAL and"
                        " gates nothing. This gate arms NOTHING by itself --"
                        " the flag stays an operator decision";
        worker_ = std::thread([this] { worker_loop(); });
    }

    ~EmbeddedShadowCompare() {
        { std::lock_guard<std::mutex> lk(q_mu_); stop_ = true; }
        q_cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    EmbeddedShadowCompare(const EmbeddedShadowCompare&) = delete;
    EmbeddedShadowCompare& operator=(const EmbeddedShadowCompare&) = delete;

    /// SERVE-PATH ENTRY. ENQUEUE ONLY — copies the just-resolved template + the
    /// arm that produced it and returns immediately. NEVER blocks the caller and
    /// NEVER touches `served`. Coalesces to the newest pending job (a shadow
    /// samples serves; a skipped intermediate is a coverage gap, never a wrong
    /// count). Safe to call whether the resolved arm was Embedded or fallback.
    void on_serve(WorkSource source, const DashWorkData& served) {
        {
            std::lock_guard<std::mutex> lk(q_mu_);
            pending_ = std::make_pair(source, served);   // copy
        }
        q_cv_.notify_one();
    }

    nlohmann::json stats_json() const {
        std::lock_guard<std::mutex> lk(mu_);
        nlohmann::json j = counters_.to_json();
        j["mode"] = "embedded-shadow-compare";
        j["note"] = "diagnostic only — NOT a serve gate";
        // The serve-FLAG readiness verdict. Still not a serve gate: it decides
        // whether --embedded-serve-mempool-txs MAY be armed, never what is
        // served at this instant.
        j["mempool-validity-gate"] = accept_
            ? validity_.to_json()
            : nlohmann::json{{"gate", "CLOSED"},
                             {"reason", "no dashd testmempoolaccept oracle bound"}};
        return j;
    }

private:
    void worker_loop() {
        for (;;) {
            std::pair<WorkSource, DashWorkData> job;
            {
                std::unique_lock<std::mutex> lk(q_mu_);
                q_cv_.wait(lk, [this] { return stop_ || pending_.has_value(); });
                if (stop_ && !pending_.has_value()) return;
                job = std::move(*pending_);
                pending_.reset();
            }
            try { process(job.first, job.second); }
            catch (const std::exception& e) {
                LOG_WARNING << "[SHADOW] worker exception: " << e.what();
            }
        }
    }

    void process(WorkSource source, const DashWorkData& served) {
        // The dashd oracle RPC runs HERE, on the worker thread — off the hot
        // path. A throw/absence maps to nullopt -> a `no-oracle` sample.
        std::optional<DashWorkData> dashd;
        if (oracle_) {
            try { dashd = oracle_(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[SHADOW] oracle threw: " << e.what() << " — no-oracle";
                dashd.reset();
            }
        }
        // If the oracle returned an empty set-gap template (unarmed fallback:
        // m_height==0 / null prev), treat it as no-oracle rather than diffing
        // every field against zeros.
        if (dashd && (dashd->m_bits == 0 || dashd->m_previous_block.IsNull()))
            dashd.reset();

        const ShadowOutcome o = shadow_evaluate(source, served, dashd);

        for (const auto& line : o.log_lines) {
            if (o.served_mismatch) LOG_WARNING << line;   // the real-problem signal
            else                   LOG_INFO    << line;
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            counters_.apply(o);
        }
        probe_validity(served);
    }

    /// THE MEMPOOL VALIDITY GATE, on the SAME worker thread as the oracle
    /// fetch — off the miner-facing path by construction. One
    /// testmempoolaccept per transaction we would serve (Dash Core's
    /// testmempoolaccept takes exactly one raw transaction per call), three-
    /// valued classification, then the sustained-window verdict.
    ///
    /// This CANNOT change what is served. Its only outputs are log lines, the
    /// counters, and a readiness verdict on a DEFAULT-OFF flag.
    void probe_validity(const DashWorkData& w) {
        if (!accept_) return;
        const auto set = mempool_probe_set(w);

        std::vector<nlohmann::json> answers;
        answers.reserve(set.size());
        for (const auto& t : set) {
            nlohmann::json a;
            try { a = accept_(t.raw_hex); }
            catch (const std::exception& e) {
                LOG_WARNING << "[MEMPOOL-VALIDITY] testmempoolaccept threw for"
                               " txid=" << t.txid << ": " << e.what()
                            << " — counted UNPROBED, never VALID";
                a = nlohmann::json();
            }
            answers.push_back(std::move(a));
        }

        const auto sample = mempool_validity_sample(w.m_height, set, answers);
        std::lock_guard<std::mutex> lk(mu_);
        validity_.apply(sample);
        for (const auto& line : mempool_validity_log_lines(sample, validity_)) {
            if (sample.invalid > 0) LOG_WARNING << line;   // the refusal
            else                    LOG_INFO    << line;
        }
    }

    OracleFn oracle_;
    AcceptFn accept_;

    mutable std::mutex mu_;          // guards counters_ + validity_
    ShadowCounters     counters_;
    MempoolValidityGate validity_;

    std::thread             worker_;
    std::mutex              q_mu_;
    std::condition_variable q_cv_;
    std::optional<std::pair<WorkSource, DashWorkData>> pending_;
    bool                    stop_{false};
};

} // namespace coin
} // namespace dash
