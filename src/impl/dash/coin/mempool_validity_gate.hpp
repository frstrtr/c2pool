// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH MEMPOOL **VALIDITY** GATE — the condition that decides when
/// --embedded-serve-mempool-txs may be turned on.
///
/// ══ WHAT THIS REPLACES, AND WHY ═════════════════════════════════════════════
/// The previous condition was a SET-MEMBERSHIP test: `ours_only == 0` in the
/// [SHADOW-TXSET] comparison against dashd's template (embedded_shadow_compare.
/// hpp). It is wrong in two directions at once.
///
///   (1) UNREACHABLE. `ours_only` is "transactions in OUR selection that are
///       absent from dashd's template". Two independently-connected nodes never
///       hold identical mempools: relay is gossip, admission is per-node policy
///       over a per-node UTXO view, and each side's template is a snapshot taken
///       at a different instant. MEASURED on the production hotel over 6056
///       samples: ours_only == 0 in 91.2% of them, > 0 in 8.8%, and when
///       non-zero its MEAN is 65.3 with a max of 287. Over the LAST 200 samples
///       it was zero only 37% of the time. A gate whose passing condition is a
///       coincidence is not a gate.
///
///   (2) BLIND TO THE CASE THAT COSTS MONEY. `ours_only == 0` says our set is a
///       SUBSET of dashd's. It does NOT say the members are acceptable: a
///       strict subset can still contain a transaction dashd would refuse
///       (double-spend of a coin our partial UTXO view still shows unspent, a
///       non-final tx, a policy-rejected script), and mining it costs the whole
///       block. The set-membership test passes and the block is still rejected.
///       The "strict subset, therefore safe" shortcut does not even hold on the
///       measurements above.
///
/// ══ THE CONDITION IMPLEMENTED HERE ══════════════════════════════════════════
/// For every transaction we hold AND WOULD SERVE, ask dashd's
/// `testmempoolaccept` and apply THREE-VALUED logic:
///
///     allowed == true                                        -> VALID
///     allowed == false && reason == "txn-already-in-mempool"  -> ALSO VALID
///     allowed == false && any other reason                    -> INVALID,
///                                                                and a defect
///
/// "already in mempool" is dashd telling us it ALREADY HOLDS this transaction —
/// the strongest possible statement that the transaction is acceptable to it.
/// It is exempted by NAME, verbatim, and nothing else is: no reason-prefix
/// matching, no "looks benign" family. A widening of the exemption set is a
/// widening of the gate and must be argued on its own.
///
/// ══ HARD GATE ══════════════════════════════════════════════════════════════
/// ZERO INVALID over a SUSTAINED window of kCleanHeightsRequired consecutive
/// EVIDENCE-BEARING heights (see below). One INVALID anywhere in the run resets
/// the run to zero. The gate is a READINESS verdict on a FLAG, not a serve
/// decision: nothing in this header can change, delay, or re-order a served
/// template. --embedded-serve-mempool-txs remains DEFAULT-OFF; this file
/// changes the condition under which it may be armed.
///
/// ══ EVIDENCE-BEARING, and why a height with no transactions does not count ══
/// A height where our probe set was empty (empty mempool, coinbase-only
/// candidate set) produced NO observation of validity. Counting it as "clean"
/// would let 576 empty heights open the gate on zero evidence — the same
/// unreachable/vacuous failure the old condition had, with the sign flipped.
/// Such heights therefore neither ADVANCE the clean run nor RESET it: they are
/// counted separately as `heights_without_evidence` and are visible in the log.
///
/// ══ ours_only IS NOW INFORMATIONAL ══════════════════════════════════════════
/// It keeps being measured and keeps being printed — as a COVERAGE STATISTIC.
/// It no longer blocks anything. See embedded_shadow_compare.hpp.
///
/// ══ WHY testmempoolaccept IS PROBED ONE TRANSACTION AT A TIME ═══════════════
/// Dash Core's `testmempoolaccept` takes an array that must contain exactly one
/// raw transaction (the pre-package-relay shape). A single-transaction probe
/// cannot see a parent that is in OUR probe set but not yet in dashd's mempool,
/// so such a child answers `missing-inputs` — an artefact of the probe, not a
/// defect of the transaction: a block carrying parent AND child together is
/// perfectly valid, and our selection is topological (mempool.hpp G1) so the
/// parent IS in the same template. Those, and ONLY those, are classified
/// Unprobed: the caller supplies a per-entry `depends_on_in_set_parent` flag
/// computed at build time from the actual vins, so the exemption is a FACT
/// about the set, never an inference from the reason string alone.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Header-only so the pure
/// classify/aggregate logic is KAT-pinnable without a live node or a daemon.

#include <impl/dash/coin/rpc_data.hpp>       // DashWorkData

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// dashd's reject-reason for "I already hold this transaction", verbatim
/// (Dash Core validation.cpp: TxValidationResult TX_CONFLICT,
/// "txn-already-in-mempool"). The ONE exempted reason. Compared for EQUALITY.
inline constexpr const char* kAlreadyInMempoolReason = "txn-already-in-mempool";

/// The reject-reason family a SINGLE-transaction probe produces for a child
/// whose parent is in the same template but not in dashd's mempool. Only ever
/// consulted together with a build-time `depends_on_in_set_parent` fact.
inline bool is_missing_inputs_reason(const std::string& reason)
{
    return reason == "missing-inputs"
        || reason == "bad-txns-inputs-missingorspent";
}

/// Three-valued logic, plus the honest fourth state for "no answer".
/// Unprobed is NEVER counted as valid and NEVER counted as a defect: it is the
/// absence of a measurement, and it advances nothing.
enum class MempoolAcceptVerdict : uint8_t {
    Valid,              // allowed == true
    AlreadyInMempool,   // allowed == false, reason == txn-already-in-mempool
    Invalid,            // allowed == false, any other reason -> A DEFECT
    Unprobed            // no answer, or an in-set-parent probe artefact
};

inline const char* mempool_accept_verdict_name(MempoolAcceptVerdict v)
{
    switch (v) {
        case MempoolAcceptVerdict::Valid:            return "VALID";
        case MempoolAcceptVerdict::AlreadyInMempool: return "ALSO-VALID(already-in-mempool)";
        case MempoolAcceptVerdict::Invalid:          return "INVALID";
        default:                                     return "UNPROBED";
    }
}

struct MempoolAcceptResult {
    std::string          txid;
    MempoolAcceptVerdict verdict{MempoolAcceptVerdict::Unprobed};
    /// dashd's reject-reason VERBATIM (empty when allowed). Never paraphrased:
    /// the operator has to be able to grep dashd's own string.
    std::string          reason;
    /// Why an Unprobed is unprobed, when it is not simply "no answer".
    std::string          unprobed_cause;
};

/// One transaction of the probe set: what we would serve, in selection
/// (topological) order.
struct MempoolProbeTx {
    std::string txid;
    std::string raw_hex;
    /// TRUE when this transaction spends an output of an EARLIER member of the
    /// same probe set. Computed at template-build time from the real vins, not
    /// guessed from a reject string.
    bool        depends_on_in_set_parent{false};
};

/// PURE. dashd's testmempoolaccept answer for ONE transaction -> the verdict.
/// `entry` is the single result object (`{"txid":..,"allowed":..,
/// "reject-reason":..}`); a null/non-object entry means the probe produced no
/// answer (RPC blip, daemon absent) and yields Unprobed.
inline MempoolAcceptResult classify_mempool_accept(const MempoolProbeTx& tx,
                                                   const nlohmann::json& entry)
{
    MempoolAcceptResult r;
    r.txid = tx.txid;

    if (!entry.is_object() || !entry.contains("allowed")
        || !entry["allowed"].is_boolean()) {
        r.verdict        = MempoolAcceptVerdict::Unprobed;
        r.unprobed_cause = "no-answer";
        return r;
    }

    if (entry["allowed"].get<bool>()) {
        r.verdict = MempoolAcceptVerdict::Valid;
        return r;
    }

    if (entry.contains("reject-reason") && entry["reject-reason"].is_string())
        r.reason = entry["reject-reason"].get<std::string>();

    if (r.reason == kAlreadyInMempoolReason) {
        r.verdict = MempoolAcceptVerdict::AlreadyInMempool;
        return r;
    }

    // The ONLY excused rejection beyond the named one: a child probed alone
    // whose parent rides the SAME template. Requires the build-time fact.
    if (tx.depends_on_in_set_parent && is_missing_inputs_reason(r.reason)) {
        r.verdict        = MempoolAcceptVerdict::Unprobed;
        r.unprobed_cause = "in-set-parent(single-tx-probe-cannot-see-it)";
        return r;
    }

    r.verdict = MempoolAcceptVerdict::Invalid;
    return r;
}

/// One height's worth of probing.
struct MempoolValiditySample {
    uint32_t height{0};
    size_t   probed{0};
    size_t   valid{0};
    size_t   already_in_mempool{0};
    size_t   invalid{0};
    size_t   unprobed{0};
    /// The defects, verbatim — txid + dashd's reason. These are what the
    /// refusal line prints.
    std::vector<MempoolAcceptResult> invalids;

    /// A height that actually OBSERVED validity. A height whose probe set was
    /// empty, or whose every entry came back Unprobed, observed nothing.
    bool evidence_bearing() const
    {
        return (valid + already_in_mempool + invalid) > 0;
    }
    bool clean() const { return evidence_bearing() && invalid == 0; }
};

/// PURE. Classify a whole probe set against the per-transaction answers.
/// `answers[i]` is dashd's result object for `set[i]`; a shorter answers vector
/// means the remaining entries got no answer (Unprobed), never a pass.
inline MempoolValiditySample
mempool_validity_sample(uint32_t height,
                        const std::vector<MempoolProbeTx>& set,
                        const std::vector<nlohmann::json>& answers)
{
    MempoolValiditySample s;
    s.height = height;
    s.probed = set.size();
    for (size_t i = 0; i < set.size(); ++i) {
        const nlohmann::json& a = (i < answers.size()) ? answers[i]
                                                       : nlohmann::json();
        const MempoolAcceptResult r = classify_mempool_accept(set[i], a);
        switch (r.verdict) {
            case MempoolAcceptVerdict::Valid:            ++s.valid; break;
            case MempoolAcceptVerdict::AlreadyInMempool: ++s.already_in_mempool; break;
            case MempoolAcceptVerdict::Invalid:
                ++s.invalid;
                s.invalids.push_back(r);
                break;
            default:                                     ++s.unprobed; break;
        }
    }
    return s;
}

/// THE HARD GATE.
///
/// kCleanHeightsRequired = 576 CONSECUTIVE EVIDENCE-BEARING heights with ZERO
/// INVALID. Justification, in full, because a threshold without one is a
/// number somebody made up:
///
///   * DURATION. DASH mainnet targets 2.625 min/block, so 576 blocks is
///     ~25.2 hours — one full day plus a margin. That is the shortest window
///     that contains every DAILY period in mempool composition: the fee/traffic
///     diurnal cycle, at least one full DKG mining window for each active LLMQ
///     type, and at least one ChainLock-less stretch. A shorter window can be
///     passed by a quiet night.
///   * STATISTICAL POWER. Evidence-bearing heights on the hotel carry a mean of
///     ~30 selectable transactions, so 576 of them is ~1.7e4 transaction
///     probes. Zero events in n trials bounds the true per-transaction invalid
///     rate at 3/n (rule of three, 95%) = ~1.7e-4. At ~30 transactions per
///     template that is a <=0.5% chance that any given template we build
///     carries a rejectable transaction — roughly one at-risk block per 190
///     mined. THAT IS THE RESIDUAL, stated rather than implied; it is not zero,
///     and the number is why the window is 576 and not 100.
///   * REACHABILITY. Unlike `ours_only == 0`, this condition is satisfiable by
///     a correct node: it asks dashd whether OUR transactions are acceptable,
///     not whether dashd's mempool coincides with ours.
///
/// The window is stated in BLOCKS, not hours, because the evidence is per
/// TEMPLATE HEIGHT; hours are the derived reading.
struct MempoolValidityGate {
    static constexpr uint64_t kCleanHeightsRequired = 576;

    uint64_t required{kCleanHeightsRequired};

    uint64_t heights_seen{0};
    uint64_t heights_with_evidence{0};
    uint64_t heights_without_evidence{0};
    uint64_t consecutive_clean{0};
    uint64_t best_consecutive_clean{0};

    uint64_t txs_probed{0};
    uint64_t txs_valid{0};
    uint64_t txs_already_in_mempool{0};
    uint64_t txs_invalid{0};
    uint64_t txs_unprobed{0};

    uint32_t    last_invalid_height{0};
    std::string last_invalid_txid;
    std::string last_invalid_reason;

    /// TRUE == the condition for arming --embedded-serve-mempool-txs is met.
    /// It does NOT arm anything; the flag stays an operator decision.
    bool open() const { return consecutive_clean >= required; }

    void apply(const MempoolValiditySample& s)
    {
        ++heights_seen;
        txs_probed             += s.probed;
        txs_valid              += s.valid;
        txs_already_in_mempool += s.already_in_mempool;
        txs_invalid            += s.invalid;
        txs_unprobed           += s.unprobed;

        if (!s.evidence_bearing()) {
            // Neither advances nor resets — it is not evidence in either
            // direction. Said out loud so a long quiet stretch cannot be
            // mistaken for progress toward the threshold.
            ++heights_without_evidence;
            return;
        }
        ++heights_with_evidence;

        if (s.invalid > 0) {
            const auto& first = s.invalids.front();
            last_invalid_height = s.height;
            last_invalid_txid   = first.txid;
            last_invalid_reason = first.reason;
            consecutive_clean   = 0;      // the run dies on ONE defect
            return;
        }
        ++consecutive_clean;
        if (consecutive_clean > best_consecutive_clean)
            best_consecutive_clean = consecutive_clean;
    }

    nlohmann::json to_json() const
    {
        nlohmann::json j;
        j["gate"]                      = open() ? "OPEN" : "CLOSED";
        j["clean-heights-required"]    = required;
        j["consecutive-clean-heights"] = consecutive_clean;
        j["best-consecutive-clean-heights"] = best_consecutive_clean;
        j["heights-seen"]              = heights_seen;
        j["heights-with-evidence"]     = heights_with_evidence;
        j["heights-without-evidence"]  = heights_without_evidence;
        j["txs-probed"]                = txs_probed;
        j["txs-valid"]                 = txs_valid;
        j["txs-already-in-mempool"]    = txs_already_in_mempool;
        j["txs-invalid"]               = txs_invalid;
        j["txs-unprobed"]              = txs_unprobed;
        j["last-invalid-height"]       = last_invalid_height;
        j["last-invalid-txid"]         = last_invalid_txid;
        j["last-invalid-reason"]       = last_invalid_reason;
        j["ours-only"] = "INFORMATIONAL — coverage statistic, not a gate";
        return j;
    }
};

/// PURE. The lines this sample emits. The REFUSAL lines carry, per #1038/#1039
/// serve-gate discipline, the TXID, dashd's REASON STRING, and the THRESHOLD —
/// a decline that does not name its own cause and bound is a silent decline.
inline std::vector<std::string>
mempool_validity_log_lines(const MempoolValiditySample& s,
                           const MempoolValidityGate& g)
{
    std::vector<std::string> out;
    const std::string h = std::to_string(s.height);

    for (const auto& d : s.invalids) {
        out.push_back(
            "[MEMPOOL-VALIDITY] h=" + h + " REFUSED cause=tx-invalid"
            " txid=" + d.txid
            + " reason=" + (d.reason.empty() ? std::string("(none-given)") : d.reason)
            + " threshold=" + std::to_string(g.required)
            + "-consecutive-clean-heights"
              " clean_run=" + std::to_string(g.consecutive_clean) + "/"
            + std::to_string(g.required)
            + " — dashd's testmempoolaccept says this transaction is NOT"
              " acceptable; serving it can cost a whole block."
              " --embedded-serve-mempool-txs stays OFF and the clean run"
              " RESETS to 0");
    }

    std::string l = "[MEMPOOL-VALIDITY] h=" + h
        + " probed="    + std::to_string(s.probed)
        + " valid="     + std::to_string(s.valid)
        + " already_in_mempool=" + std::to_string(s.already_in_mempool)
        + " invalid="   + std::to_string(s.invalid)
        + " unprobed="  + std::to_string(s.unprobed)
        + " clean_run=" + std::to_string(g.consecutive_clean) + "/"
        + std::to_string(g.required)
        + " gate=" + (g.open() ? "OPEN" : "CLOSED");
    if (!s.evidence_bearing())
        l += " (no-evidence: nothing to probe at this height — the run neither"
             " advances nor resets)";
    out.push_back(std::move(l));
    return out;
}

/// The MEMPOOL-SOURCED transactions this template would serve, assembled from
/// whichever half of the template carries them:
///
///   * SERVING (--embedded-serve-mempool-txs ON): the contiguous mempool range
///     of the served body, [m_mempool_tx_first_index, +m_mempool_tx_count).
///     Referenced by index rather than copied — the money path must not grow a
///     second copy of the block body for a diagnostic.
///   * NOT SERVING (the default, and the case the gate exists to decide): the
///     CANDIDATE set — what selection WOULD have chosen — with its own wire hex.
///
/// Consensus-mandatory type-6 quorum-commitment txs and pinned local txs are
/// EXCLUDED by construction: neither is mempool-sourced, and both are rejected
/// by relay policy on purpose (a zero-fee pin especially), so probing them
/// would manufacture INVALID verdicts out of correct behaviour.
inline std::vector<MempoolProbeTx> mempool_probe_set(const DashWorkData& w)
{
    std::vector<MempoolProbeTx> out;

    if (w.m_mempool_tx_count > 0) {
        const size_t first = w.m_mempool_tx_first_index;
        const size_t n     = w.m_mempool_tx_count;
        if (first + n > w.m_tx_hashes.size() || first + n > w.m_tx_data_hex.size())
            return out;   // mis-populated WorkData: report NOTHING, never guess
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            MempoolProbeTx t;
            t.txid    = w.m_tx_hashes[first + i].GetHex();
            t.raw_hex = w.m_tx_data_hex[first + i];
            t.depends_on_in_set_parent =
                (i < w.m_mempool_probe_depends_in_set.size())
                && (w.m_mempool_probe_depends_in_set[i] != 0);
            out.push_back(std::move(t));
        }
        return out;
    }

    if (w.m_txset_candidates.size() != w.m_txset_candidate_data_hex.size())
        return out;       // unaligned: a fabricated probe set is worse than none
    out.reserve(w.m_txset_candidates.size());
    for (size_t i = 0; i < w.m_txset_candidates.size(); ++i) {
        MempoolProbeTx t;
        t.txid    = w.m_txset_candidates[i].GetHex();
        t.raw_hex = w.m_txset_candidate_data_hex[i];
        t.depends_on_in_set_parent =
            (i < w.m_mempool_probe_depends_in_set.size())
            && (w.m_mempool_probe_depends_in_set[i] != 0);
        out.push_back(std::move(t));
    }
    return out;
}

} // namespace coin
} // namespace dash
