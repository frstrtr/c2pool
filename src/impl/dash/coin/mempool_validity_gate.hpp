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
/// "txn-already-in-mempool"). The ONE exempted reason. Compared for EQUALITY.
inline constexpr const char* kAlreadyInMempoolReason = "txn-already-in-mempool";

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

/// dashd's reject-reason for "I already hold this transaction as a CONFIRMED
/// tx on my own chain", verbatim (Dash Core validation.cpp:854: TX_CONFLICT,
/// "txn-already-known"). It is returned when a HaveCoinInCache probe over the
/// transaction's OWN outputs succeeds while an input HaveCoin fails: dashd is
/// telling us the tx is ALREADY CONFIRMED in its UTXO set (its outputs exist),
/// not that an input is unknown. It is non-punishable (net_processing.cpp
/// MaybePunishNodeForTx: TX_CONFLICT falls to `break`, misbehaviour 0), exactly
/// like the other propagation-class reasons. Compared for EQUALITY only — NO
/// prefix matching, per this file's discipline.
inline bool is_confirmed_tx_reason(const std::string& reason)
{
    return reason == "txn-already-known";
}

/// Three-valued logic, plus TWO honest "no verdict" states.
/// Unprobed is NEVER counted as valid and NEVER counted as a defect: it is the
/// absence of a measurement, and it advances nothing. PendingPropagation is the
/// Window-1 analog (see the enumerator note): dashd's probe-time tip is AHEAD of
/// the serve parent this template was built on, and a "missing-inputs" answer at
/// that skew is the ahead-block having already spent/confirmed the very inputs
/// (or txs) our still-valid fork template offered — a PROBE TIMING ARTEFACT, not
/// a defect of the transaction. It, too, advances nothing and resets nothing.
enum class MempoolAcceptVerdict : uint8_t {
    Valid,              // allowed == true
    AlreadyInMempool,   // allowed == false, reason == txn-already-in-mempool
    Invalid,            // allowed == false, any other reason -> A DEFECT
    Unprobed,           // no answer, or an in-set-parent probe artefact
    PendingPropagation  // missing-inputs at a dashd-AHEAD-of-serve-parent skew
                        // (Window-1: valid on our fork; the probe is stale) —
                        // NEVER a defect, NEVER counted valid, advances nothing
};

inline const char* mempool_accept_verdict_name(MempoolAcceptVerdict v)
{
    switch (v) {
        case MempoolAcceptVerdict::Valid:            return "VALID";
        case MempoolAcceptVerdict::AlreadyInMempool: return "ALSO-VALID(already-in-mempool)";
        case MempoolAcceptVerdict::Invalid:          return "INVALID";
        case MempoolAcceptVerdict::PendingPropagation:
            return "PENDING-PROPAGATION(dashd-ahead-window-1)";
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

    /// TRUE when dashd's probe-time tip is STRICTLY AHEAD of the serve parent
    /// this template was built on — a FACT (a height comparison: dashd's GBT
    /// height > our template height), NOT an inference from any reject string.
    /// The probe runs asynchronously on a worker thread; between the instant we
    /// built the template at OUR tip and the instant dashd answered, dashd can
    /// have connected one or more blocks. At that skew a "missing-inputs" answer
    /// is the Window-1 propagation artefact: the ahead block already spent or
    /// confirmed the very inputs (or the very txs) our still-valid fork template
    /// offered, so dashd — probing against its newer view — cannot see them.
    /// dashd's own testmempoolaccept detects the already-confirmed case only
    /// best-effort (HaveCoinInCache over the tx OUTPUTS) and, once those outputs
    /// are flushed or spent, falls through to the same "missing-inputs" string;
    /// the field is how we recover the class dashd's string conflated. Set by
    /// the probe caller (embedded_shadow_compare.hpp) from dashd's GBT height.
    bool        dashd_ahead_of_serve_height{false};
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

    // WINDOW-1 PROPAGATION (the #1318 successor; the h=2526495 incident class).
    // A "missing-inputs" answer while dashd's probe-time tip is STRICTLY AHEAD of
    // the serve parent this template was built on is a PROBE-TIMING ARTEFACT, not
    // a defect: dashd connected one or more blocks after we built, and that ahead
    // block already spent/confirmed the inputs (or the txs themselves — both of
    // the h=2526495 leak txs, 8c4efd9c… and 81109abf…, were CONFIRMED IN BLOCK
    // 2526495 itself, the exact height our template competed for). Such a tx is
    // VALID ON OUR FORK; dashd, probing against its newer view, cannot see it.
    // The FACT is `dashd_ahead_of_serve_height` — a height comparison the caller
    // supplies, never a string inference — so the exemption cannot widen on a
    // reason alone. It is DELIBERATELY NARROW:
    //
    //   * Only "missing-inputs" qualifies. `bad-txns-inputs-missingorspent`
    //     stays INVALID even under the ahead skew (see the note above): that
    //     reason conflates unknown-with-SPENT in its own name and is the exact
    //     bad-cb / double-spend loss vector; failing it toward a CLOSED gate on
    //     ambiguous evidence is the direction a gate is allowed to be wrong in.
    //   * It advances NOTHING and resets NOTHING — like Unprobed, it is the
    //     absence of a usable measurement, not evidence in either direction. It
    //     is counted separately (`pending_propagation`) so the class stays
    //     visible and MEASURABLE (our-serve-parent vs dashd-tip skew), which is
    //     precisely what a demoted-to-measurement gate needs to prove that OUR
    //     self-validation verdict == dashd-clean once the skew resolves.
    //
    // Since this gate is a MEASUREMENT (it no longer decides what is served —
    // work_source.cpp self-validates the served set from OUR OWN state), the
    // cost of this classification is confidence accounting, never a served
    // block: a genuine defect that happened to coincide with an ahead skew is
    // caught by the serve-time internal-consistency referee (tx_serve_referee.
    // hpp), which shares the selector's spent-aware UTXO view and runs on EVERY
    // armed embedded template independent of dashd.
    //
    // The SAME Window-1 logic covers dashd's "txn-already-known" reason under
    // the ahead skew. That reason (validation.cpp:854) means dashd found the
    // transaction's OWN outputs already in its UTXO set: the tx is CONFIRMED on
    // dashd's chain. When dashd's probe-time tip is STRICTLY AHEAD of our serve
    // parent, that confirmation lives in the ahead block(s) our still-valid fork
    // template competed for — the tx is VALID ON OUR FORK, and dashd, probing
    // against its newer view, reports it as already-confirmed. This is the proven
    // h=2526495 class (both leak txs were CONFIRMED IN BLOCK 2526495 itself). Like
    // the missing-inputs arm it is FACT-gated on `dashd_ahead_of_serve_height`,
    // never on the reason alone, and it advances NOTHING and resets NOTHING.
    //
    // REWARD-SAFE FAIL-CLOSED: WITHOUT the ahead skew, "txn-already-known" means
    // the tx is confirmed in OUR OWN ancestry — a genuine double-inclusion that
    // would cost the block — so it falls through to Invalid below and RESETS the
    // clean run, flagging a selector/ingest eviction miss. The gate is only ever
    // widened in the one direction (ahead skew) where the tx is provably valid on
    // our fork; on ambiguous or non-skewed evidence it stays CLOSED.
    if ((is_unknown_input_only_reason(r.reason) || is_confirmed_tx_reason(r.reason))
        && tx.dashd_ahead_of_serve_height) {
        r.verdict        = MempoolAcceptVerdict::PendingPropagation;
        r.unprobed_cause = is_confirmed_tx_reason(r.reason)
            ? "confirmed-in-dashd-ahead-block(window-1)"
            : "dashd-ahead-of-serve-parent(window-1-propagation)";
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
    /// Window-1 propagation artefacts: dashd-ahead + missing-inputs. Neither
    /// evidence of validity nor a defect — tracked so the skew class is visible.
    size_t   pending_propagation{0};
    /// The defects, verbatim — txid + dashd's reason. These are what the
    /// refusal line prints.
    std::vector<MempoolAcceptResult> invalids;

    /// A height that actually OBSERVED validity. A height whose probe set was
    /// empty, or whose every entry came back Unprobed / PendingPropagation,
    /// observed nothing. PendingPropagation is EXCLUDED here for the same reason
    /// Unprobed is: it is the absence of a usable measurement, so it must not
    /// let a skew-only height count toward the clean window.
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
            case MempoolAcceptVerdict::PendingPropagation:
                ++s.pending_propagation;
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
    uint64_t repeat_txs_probed{0};

    /// Window-1 propagation artefacts observed anywhere (dashd-ahead skew +
    /// missing-inputs). Accrued on EVERY apply() regardless of disposition so
    /// the skew class is fully visible; it advances nothing and resets nothing.
    /// This is the demoted gate's CONFIDENCE evidence that the class dashd's
    /// string conflated is benign and resolves as our tip catches up.
    uint64_t txs_pending_propagation{0};

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

        // Window-1 propagation artefacts accrue unconditionally: they are
        // measurement, not evidence, so they are counted before the evidence
        // gate and never touch consecutive_clean in either direction.
        txs_pending_propagation += s.pending_propagation;

        if (!s.evidence_bearing()) {
            // Neither advances nor resets — it is not evidence in either
            // direction. Said out loud so a long quiet stretch cannot be
            // mistaken for progress toward the threshold. The cursor is NOT
            // moved: a later probe of this same height that DOES find
            // transactions is the first evidence there, and must count.
            ++samples_without_evidence;
            txs_unprobed     += s.unprobed;
            last_disposition  = SampleDisposition::NoEvidence;
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
        j["txs-pending-propagation"]   = txs_pending_propagation;
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
        + " pending_propagation=" + std::to_string(s.pending_propagation)
        + " clean_run=" + std::to_string(g.consecutive_clean) + "/"
        + std::to_string(g.required)
        + " heights_with_evidence=" + std::to_string(g.heights_with_evidence)
        + " sample=" + MempoolValidityGate::disposition_name(g.last_disposition)
        + " gate=" + (g.open() ? "OPEN" : "CLOSED");
    if (!s.evidence_bearing())
        l += " (no-evidence: nothing to probe at this height — the run neither"
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
