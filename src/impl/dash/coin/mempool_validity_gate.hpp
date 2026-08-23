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
/// EVIDENCE-BEARING, DISTINCT heights (see both qualifiers below). One INVALID
/// anywhere in the run resets the run to zero. The gate is a READINESS verdict
/// on a FLAG, not a serve decision: nothing in this header can change, delay,
/// or re-order a served template. --embedded-serve-mempool-txs remains
/// DEFAULT-OFF; this file changes the condition under which it may be armed.
///
/// ══ EVIDENCE-BEARING, and why a height with no transactions does not count ══
/// A height where our probe set was empty (empty mempool, coinbase-only
/// candidate set) produced NO observation of validity. Counting it as "clean"
/// would let 576 empty heights open the gate on zero evidence — the same
/// unreachable/vacuous failure the old condition had, with the sign flipped.
/// Such samples therefore neither ADVANCE the clean run nor RESET it: they are
/// counted separately as `samples_without_evidence` and are visible in the log.
///
/// ══ DISTINCT, and why a SAMPLE is not a HEIGHT ══════════════════════════════
/// apply() is fed ONE SAMPLE PER PROBE RUN, and a probe run is NOT a block.
/// probe_validity() runs from process(), process() runs from on_serve, and
/// on_serve fires on EVERY template re-source: every work-generation bump plus
/// a 30 s staleness re-poll (stratum/work_source.cpp kStaleAfter). DASH targets
/// 157.5 s/block, so roughly FIVE TO SIX samples land on ONE height.
///
/// Counting samples would therefore have made 576 counter ticks mean ~110 real
/// heights — about 4.8 hours, not the ~25.2 hours the threshold is argued
/// from — and a node parked on a FROZEN TIP could tick the counter to 576
/// without ever advancing a block. That is precisely the "a shorter window can
/// be passed by a quiet night" failure the threshold exists to exclude, so the
/// window counts DISTINCT heights and the cursor is MONOTONE.
///
/// The rule is DELIBERATELY ASYMMETRIC, and the asymmetry is the point:
///
///   * A sample at a height that does NOT advance the cursor (a repeat of the
///     last counted height, or a rollback below it) contributes NO new
///     evidence: it cannot advance `consecutive_clean`, cannot raise
///     `heights_with_evidence`, and its transactions are not added to the
///     independent-trial totals. It is counted as `samples_repeat_height`.
///   * That same sample CAN STILL KILL THE RUN. An INVALID is an OBSERVED
///     DEFECT whenever it is observed — the mempool at one height is not
///     constant, and a conflicting spend that arrives between two probes of
///     the same height is exactly the event that costs a block. Ignoring it
///     because "we already counted this height" would trade over-counting
///     clean evidence for under-counting defects: one blindness for another.
///
/// So a repeat can only ever HURT the run, never help it. Everything the
/// non-advancing samples DID see stays visible in `samples_seen`,
/// `samples_repeat_height` and `repeat_txs_probed` — dropped from the window
/// arithmetic, never dropped from the record.
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
/// "txn-already-in-mempool"). The ONE unconditionally-exempted reason.
/// Compared for EQUALITY.
inline constexpr const char* kAlreadyInMempoolReason = "txn-already-in-mempool";

/// dashd's reject-reason for "this transaction is ALREADY CONFIRMED in my
/// active chain", verbatim (Dash Core MemPoolAccept::PreChecks: a tx whose
/// outputs are already present as coins in dashd's UTXO view —
/// `HaveCoin(COutPoint(hash, out))` — returns TX_CONFLICT "txn-already-known").
/// This is a CONDITIONAL exemption, not an unconditional one: it is benign
/// ONLY when the block that confirmed the tx is one WE HAVE NOT YET CONNECTED
/// (propagation Window 1 — our tip is h-1, someone else mined h and dashd
/// connected it before we did; from our tip the tx is a valid UNCONFIRMED tx
/// and our template is a valid fork competitor at height h, never an orphan).
/// It is a genuine DEFECT only when dashd sits on OUR parent (or behind) and
/// still reports the tx confirmed — i.e. it was confirmed at or below OUR
/// serve-tip while we still serve it (the intra-node eviction-lag class,
/// "Window 2"). The caller supplies the tip context (classify_mempool_accept's
/// `dashd_ahead_of_serve_height`), which alone decides which case applies.
/// Compared for EQUALITY.
inline constexpr const char* kAlreadyConfirmedReason = "txn-already-known";

/// The ONE reject-reason that can mean ONLY "I do not know this input" — the
/// answer a SINGLE-transaction probe gets for a child whose parent rides the
/// same template but has not reached dashd's mempool. Only ever consulted
/// together with a build-time `depends_on_in_set_parent` fact.
inline bool is_unknown_input_only_reason(const std::string& reason)
{
    return reason == "missing-inputs";
}

/// The reject-reason that CONFLATES a missing input with a SPENT one, and says
/// so in its own name. NEVER exempted — see the note on the exemption below.
inline bool is_missing_or_spent_reason(const std::string& reason)
{
    return reason == "bad-txns-inputs-missingorspent";
}

/// Three-valued logic, plus the honest fourth state for "no answer".
/// Unprobed is NEVER counted as valid and NEVER counted as a defect: it is the
/// absence of a measurement, and it advances nothing.
enum class MempoolAcceptVerdict : uint8_t {
    Valid,              // allowed == true
    AlreadyInMempool,   // allowed == false, reason == txn-already-in-mempool
    ConfirmedAhead,     // reason == txn-already-known AND dashd is ahead of our
                        // serve-tip -> benign propagation (Window 1). NOT a
                        // defect and NOT evidence: it neither resets nor
                        // advances the readiness run.
    Invalid,            // allowed == false, any other reason -> A DEFECT
    Unprobed            // no answer, or an in-set-parent probe artefact
};

inline const char* mempool_accept_verdict_name(MempoolAcceptVerdict v)
{
    switch (v) {
        case MempoolAcceptVerdict::Valid:            return "VALID";
        case MempoolAcceptVerdict::AlreadyInMempool: return "ALSO-VALID(already-in-mempool)";
        case MempoolAcceptVerdict::ConfirmedAhead:   return "PROPAGATION(confirmed-in-not-yet-connected-block)";
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
///
/// `dashd_ahead_of_serve_height` is the sample-level tip context: TRUE when
/// dashd's chain tip is STRICTLY AHEAD of the block WE built the probed
/// template for (dashd's next-block height > our served height). It is
/// consulted for EXACTLY ONE reason string — "txn-already-known" — to separate
/// benign propagation (Window 1: dashd already connected a block we have not)
/// from a genuine intra-node staleness defect (Window 2: dashd sits on our
/// parent and still holds the tx confirmed at/below our serve-tip). It changes
/// NOTHING for any other reason: every real reject stays a reject. Defaulting
/// to FALSE preserves the pre-tip-context behaviour (already-known -> INVALID)
/// for callers that cannot supply it — the conservative, gate-CLOSED direction.
inline MempoolAcceptResult classify_mempool_accept(const MempoolProbeTx& tx,
                                                   const nlohmann::json& entry,
                                                   bool dashd_ahead_of_serve_height = false)
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

    // dashd says the tx is ALREADY CONFIRMED in its chain ("txn-already-known").
    // Whether that is a defect depends ENTIRELY on WHICH block confirmed it,
    // which the tip context decides (see kAlreadyConfirmedReason). dashd AHEAD
    // of our serve-tip => it was confirmed in a block we have not connected =>
    // benign propagation (Window 1): our template is a valid fork competitor at
    // our height, so this must NOT reset the readiness run. dashd NOT ahead
    // (on our parent, or behind) => confirmed at/below OUR serve-tip while we
    // still serve it => a genuine current-tip staleness defect (Window 2) =>
    // falls through to INVALID and resets, exactly as a served already-mined tx
    // should. This is the ONLY reason whose disposition the tip context can
    // change; the field-measured invalids were 23/23 this class, all Window 1.
    if (r.reason == kAlreadyConfirmedReason) {
        if (dashd_ahead_of_serve_height) {
            r.verdict        = MempoolAcceptVerdict::ConfirmedAhead;
            r.unprobed_cause = "confirmed-in-block-we-have-not-connected(propagation)";
            return r;
        }
        // else: dashd on our parent or behind -> a real at/below-serve-tip
        // defect; fall through to INVALID below.
    }

    // The ONLY excused rejection beyond the named one: a child probed alone
    // whose parent rides the SAME template. Requires the build-time fact AND a
    // reason that can mean nothing else.
    //
    // WHY `bad-txns-inputs-missingorspent` IS **NOT** IN HERE.
    // `depends_on_in_set_parent` is a fact about the TRANSACTION, not about the
    // INPUT that failed, and testmempoolaccept never names WHICH outpoint it
    // refused. So a recorded dependency does not imply the failing input was
    // the in-set parent: a transaction spending ONE in-set parent output AND
    // ONE genuinely double-spent output carries the flag and is a real defect —
    // the exact loss this gate exists to prevent, classified as UNPROBED and
    // waved through.
    //
    // A per-INPUT fix is NOT AVAILABLE from the data dashd gives us. Even with
    // the full per-input in-set map on our side, the answer is a bare reason
    // string with no outpoint, so nothing can attribute the failure to a
    // specific input. The exemption is therefore NARROWED instead, to the one
    // reason whose meaning is unambiguous: "missing-inputs" = "this input is
    // not known to me". `bad-txns-inputs-missingorspent` conflates unknown with
    // SPENT in its own name and is now INVALID even with the flag set.
    //
    // The cost is stated rather than hidden: an in-set-parent child that dashd
    // answers with the conflating reason will now RESET the clean run. That
    // fails toward a CLOSED gate on ambiguous evidence, which is the direction
    // a gate is allowed to be wrong in. The residual the narrow exemption still
    // carries is likewise per-transaction: a tx spending an in-set parent AND
    // an input dashd does not know for an unrelated reason. That case is not a
    // double-spend, and our selection is topological (mempool.hpp G1), so every
    // in-our-mempool ancestor rides the same template.
    if (tx.depends_on_in_set_parent && is_unknown_input_only_reason(r.reason)) {
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
    /// Benign propagation (Window 1): dashd reported the tx already-CONFIRMED in
    /// a block WE HAVE NOT YET CONNECTED. Neither a defect nor evidence — it is
    /// counted here only so the log/JSON can say how much of the "already-known"
    /// traffic was the propagation transient rather than a real staleness.
    size_t   confirmed_ahead{0};
    /// The defects, verbatim — txid + dashd's reason. These are what the
    /// refusal line prints.
    std::vector<MempoolAcceptResult> invalids;

    /// A height that actually OBSERVED validity. A height whose probe set was
    /// empty, or whose every entry came back Unprobed / ConfirmedAhead,
    /// observed nothing about CURRENT-TIP validity — a ConfirmedAhead answer is
    /// dashd speaking from a NEWER tip than the one we probed for, so it is not
    /// evidence either way (see the tip-context note on kAlreadyConfirmedReason).
    bool evidence_bearing() const
    {
        return (valid + already_in_mempool + invalid) > 0;
    }
    bool clean() const { return evidence_bearing() && invalid == 0; }
};

/// PURE. Classify a whole probe set against the per-transaction answers.
/// `answers[i]` is dashd's result object for `set[i]`; a shorter answers vector
/// means the remaining entries got no answer (Unprobed), never a pass.
///
/// `dashd_ahead_of_serve_height` is the sample-level tip context threaded into
/// each per-tx classification (see classify_mempool_accept). It ONLY affects
/// the "txn-already-known" reason: dashd-ahead makes that a benign
/// ConfirmedAhead (propagation Window 1, no reset), dashd-not-ahead keeps it a
/// current-tip Invalid. Defaults FALSE so legacy/test callers get the pre-
/// tip-context behaviour unchanged.
inline MempoolValiditySample
mempool_validity_sample(uint32_t height,
                        const std::vector<MempoolProbeTx>& set,
                        const std::vector<nlohmann::json>& answers,
                        bool dashd_ahead_of_serve_height = false)
{
    MempoolValiditySample s;
    s.height = height;
    s.probed = set.size();
    for (size_t i = 0; i < set.size(); ++i) {
        const nlohmann::json& a = (i < answers.size()) ? answers[i]
                                                       : nlohmann::json();
        const MempoolAcceptResult r =
            classify_mempool_accept(set[i], a, dashd_ahead_of_serve_height);
        switch (r.verdict) {
            case MempoolAcceptVerdict::Valid:            ++s.valid; break;
            case MempoolAcceptVerdict::AlreadyInMempool: ++s.already_in_mempool; break;
            case MempoolAcceptVerdict::ConfirmedAhead:   ++s.confirmed_ahead; break;
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
///   * DURATION. DASH mainnet targets 2.625 min/block, so 576 DISTINCT heights
///     is AT LEAST ~25.2 hours — one full day plus a margin, and longer
///     whenever heights go by without evidence. That is the shortest window
///     that contains every DAILY period in mempool composition: the fee/traffic
///     diurnal cycle, at least one full DKG mining window for each active LLMQ
///     type, and at least one ChainLock-less stretch. A shorter window can be
///     passed by a quiet night. This bound holds ONLY because the counter
///     advances per distinct height; counting samples would have made the same
///     576 mean ~110 heights (~4.8 h), because the probe fires ~5-6 times per
///     block — see "DISTINCT" at the top of this file.
///   * STATISTICAL POWER, stated at the unit the window actually counts. Zero
///     INVALID heights in 576 evidence-bearing heights bounds the per-HEIGHT
///     rate at 3/576 (rule of three, 95%) = 5.2e-3: at most a ~0.52% chance
///     that any given template we build carries a rejectable transaction,
///     roughly ONE AT-RISK BLOCK PER 192 MINED. THAT IS THE RESIDUAL, stated
///     rather than implied; it is not zero, and it is why the window is 576 and
///     not 100.
///
///     The per-HEIGHT rate is the honest form of this claim, and the per-
///     TRANSACTION form is deliberately NOT made. Evidence-bearing heights on
///     the hotel carry a mean of ~30 selectable transactions, so the window
///     does accumulate ~1.7e4 probes — but they are not 1.7e4 INDEPENDENT
///     trials: a transaction that sits in the mempool for several blocks is
///     re-probed at each of them. Only the HEIGHTS are separated by a fresh
///     tip, a fresh selection and a fresh mempool, so only the height-level
///     bound is claimed. (Before the distinct-height fix the counter's true
///     unit was ~110 heights, which bounds the per-template rate at 3/110 =
///     2.7% — one at-risk block per 37, 5.2x worse than the number the
///     threshold was argued from.)
///   * REACHABILITY. Unlike `ours_only == 0`, this condition is satisfiable by
///     a correct node: it asks dashd whether OUR transactions are acceptable,
///     not whether dashd's mempool coincides with ours.
///
/// The window is stated in BLOCKS, not hours, because the evidence is per
/// TEMPLATE HEIGHT; hours are the derived reading.
struct MempoolValidityGate {
    static constexpr uint64_t kCleanHeightsRequired = 576;

    /// What the LAST applied sample did to the window. Named so a log reader
    /// never has to infer it from two counters moving.
    enum class SampleDisposition : uint8_t {
        None,           // nothing applied yet
        Counted,        // new height, evidence-bearing: the window moved
        RepeatHeight,   // at/below the counted cursor: no new evidence
        NoEvidence      // nothing to probe, or every answer was Unprobed
    };

    static const char* disposition_name(SampleDisposition d)
    {
        switch (d) {
            case SampleDisposition::Counted:      return "COUNTED";
            case SampleDisposition::RepeatHeight: return "REPEAT-HEIGHT(no-advance)";
            case SampleDisposition::NoEvidence:   return "NO-EVIDENCE(no-advance)";
            default:                              return "NONE";
        }
    }

    uint64_t required{kCleanHeightsRequired};

    /// THE MONOTONE HEIGHT CURSOR. Only a sample ABOVE it can advance the
    /// window, and only an evidence-bearing sample moves it — so a height whose
    /// first probe found nothing is not burned, and a rollback cannot make the
    /// window count the same block twice.
    uint32_t last_counted_height{0};
    bool     has_counted_height{false};

    /// Every apply() call: the PROBE cadence, ~5-6 per block. NOT a height.
    uint64_t samples_seen{0};
    /// ... of which landed at/below the cursor and so advanced nothing.
    uint64_t samples_repeat_height{0};
    /// ... of which observed no validity at all.
    uint64_t samples_without_evidence{0};

    /// THE WINDOW'S UNIT: distinct evidence-bearing heights.
    uint64_t heights_with_evidence{0};
    uint64_t consecutive_clean{0};
    uint64_t best_consecutive_clean{0};

    /// Transaction totals over the COUNTED samples only — one observation per
    /// transaction per height, which is what the power argument is entitled to
    /// read. Re-probes are kept apart in `repeat_txs_probed` so nothing is
    /// hidden, only kept out of the arithmetic.
    uint64_t txs_probed{0};
    uint64_t txs_valid{0};
    uint64_t txs_already_in_mempool{0};
    uint64_t txs_unprobed{0};
    /// Benign propagation transients (already-CONFIRMED in a block we have not
    /// yet connected) seen over every applied sample. NOT defects, NOT
    /// evidence — this counter exists so the operator can see how much of the
    /// "already-known" traffic the tip context reclassified out of the invalid
    /// bucket. A large value here with consecutive_clean advancing is the whole
    /// point: propagation no longer stalls the readiness run.
    uint64_t txs_confirmed_ahead{0};
    uint64_t repeat_txs_probed{0};

    /// DEFECTS ARE COUNTED WHEREVER THEY ARE OBSERVED — counted sample or
    /// repeat. See the asymmetry note at the top of this file.
    uint64_t txs_invalid{0};

    uint32_t    last_invalid_height{0};
    std::string last_invalid_txid;
    std::string last_invalid_reason;

    SampleDisposition last_disposition{SampleDisposition::None};

    /// TRUE == the condition for arming --embedded-serve-mempool-txs is met.
    /// It does NOT arm anything; the flag stays an operator decision.
    bool open() const { return consecutive_clean >= required; }

    void apply(const MempoolValiditySample& s)
    {
        ++samples_seen;

        if (!s.evidence_bearing()) {
            // Neither advances nor resets — it is not evidence in either
            // direction. Said out loud so a long quiet stretch cannot be
            // mistaken for progress toward the threshold. The cursor is NOT
            // moved: a later probe of this same height that DOES find
            // transactions is the first evidence there, and must count.
            ++samples_without_evidence;
            txs_unprobed        += s.unprobed;
            txs_confirmed_ahead += s.confirmed_ahead;
            last_disposition     = SampleDisposition::NoEvidence;
            return;
        }

        // A DEFECT KILLS THE RUN WHEREVER IT IS SEEN — before the distinct-
        // height test, deliberately. The mempool at one height is not constant;
        // a conflicting spend arriving between two probes of the same height is
        // exactly the event that costs a block. A repeat may only ever HURT.
        if (s.invalid > 0) {
            txs_invalid        += s.invalid;
            const auto& first   = s.invalids.front();
            last_invalid_height = s.height;
            last_invalid_txid   = first.txid;
            last_invalid_reason = first.reason;
            consecutive_clean   = 0;      // the run dies on ONE defect
        }

        const bool advances = !has_counted_height || s.height > last_counted_height;
        if (!advances) {
            // No new evidence: the window has already banked this height. The
            // reset above (if any) still stands.
            ++samples_repeat_height;
            repeat_txs_probed += s.probed;
            last_disposition   = SampleDisposition::RepeatHeight;
            return;
        }

        last_counted_height = s.height;
        has_counted_height  = true;
        ++heights_with_evidence;
        txs_probed             += s.probed;
        txs_valid              += s.valid;
        txs_already_in_mempool += s.already_in_mempool;
        txs_unprobed           += s.unprobed;
        txs_confirmed_ahead    += s.confirmed_ahead;
        last_disposition        = SampleDisposition::Counted;

        if (s.invalid > 0) return;        // already reset above

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
        j["heights-with-evidence"]     = heights_with_evidence;
        j["last-counted-height"]       = last_counted_height;
        // The window's unit is a HEIGHT; these three say how many PROBES it
        // took and how many of them the window was entitled to count, so a
        // reader can never mistake probe cadence for progress.
        j["samples-seen"]              = samples_seen;
        j["samples-repeat-height"]     = samples_repeat_height;
        j["samples-without-evidence"]  = samples_without_evidence;
        j["last-sample-disposition"]   = disposition_name(last_disposition);
        j["txs-probed"]                = txs_probed;
        j["txs-probed-repeat-height"]  = repeat_txs_probed;
        j["txs-valid"]                 = txs_valid;
        j["txs-already-in-mempool"]    = txs_already_in_mempool;
        j["txs-invalid"]               = txs_invalid;
        j["txs-unprobed"]              = txs_unprobed;
        j["txs-confirmed-ahead-propagation"] = txs_confirmed_ahead;
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
        + " confirmed_ahead=" + std::to_string(s.confirmed_ahead)
        + " unprobed="  + std::to_string(s.unprobed)
        + " clean_run=" + std::to_string(g.consecutive_clean) + "/"
        + std::to_string(g.required)
        + " heights_with_evidence=" + std::to_string(g.heights_with_evidence)
        + " sample=" + MempoolValidityGate::disposition_name(g.last_disposition)
        + " gate=" + (g.open() ? "OPEN" : "CLOSED");
    if (!s.evidence_bearing())
        l += s.confirmed_ahead > 0
             ? " (no-evidence: every probed tx is already CONFIRMED in a block we"
               " have not yet connected — benign propagation Window 1, dashd is"
               " ahead of the height we built for; the run neither advances nor"
               " resets, and this is NOT a staleness defect)"
             : " (no-evidence: nothing to probe at this height — the run neither"
               " advances nor resets)";
    else if (g.last_disposition == MempoolValidityGate::SampleDisposition::RepeatHeight)
        l += " (repeat-height: h<=" + std::to_string(g.last_counted_height)
           + " is already banked — the probe fires ~5-6x per block, so this"
             " sample is NOT new evidence and does NOT advance the window;"
             " an INVALID on it would still RESET the run)";
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
