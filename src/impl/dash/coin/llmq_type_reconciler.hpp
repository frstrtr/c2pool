// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// LLMQ-TYPE RECONCILER — the negative-capable backstop for enabled_llmqs().
///
/// WHY THIS EXISTS (mainnet, discovered 2026-08-03, shipped-wrong for months):
/// `enabled_llmqs(Mainnet)` listed LLMQ_50_60 (type 1). dashd's consensus
/// requirement is not the chainparams AddLLMQ list but that list FILTERED
/// through the runtime `IsQuorumTypeEnabled` predicate, which disables
/// LLMQ_50_60 on mainnet at every height >= DIP0024QuorumsHeight (1738698).
/// So c2pool emitted a mandatory type-1 slot every 24-block DKG cycle that
/// NOTHING could ever satisfy: `has_mined` false forever (no such commitment
/// is ever mined), no qfcommit ever relayed, and the per-height completeness
/// gate therefore failed the WHOLE height closed at every height whose phase
/// lands in [10,18] — a permanent 9-in-24 structural outage.
///
/// THE REASON IT SURVIVED IS THE POINT OF THIS FILE. Every refusal it caused
/// was indistinguishable from a refusal that is CORRECT: the log said
/// "no-commitment-cached ... window=[...] remaining=N -> WHOLE height fails
/// closed", which is exactly what a genuine cold-start relay gap says. The
/// difference between "required but NONEXISTENT" and "required but NOT YET
/// ARRIVED" is invisible at any single height — the second one looks like
/// patience, and patience is the correct posture, so the operator waits. The
/// only thing that separates them is TIME plus the negative: a type that is
/// required and has NEVER, across whole DKG cycles, been observed in a mined
/// commitment while OTHER required types were plainly being mined.
///
/// SO THIS CHECK IS BUILT TO BE ABLE TO FAIL. A check that cannot produce a
/// negative is not evidence. `reconcile()` returns a verdict PER required
/// type, and two of the five verdicts are defects:
///
///   * NeverObserved — we require it, the observation window covers a full
///     DKG cycle of that type, other required types WERE observed mined in
///     that same window, and this one produced zero sightings. That is the
///     defect above, named, and it is reachable: feeding a mainnet-shaped
///     observation stream with type 1 in the required set produces it.
///   * UnexpectedType — the chain mines a type we do NOT require. This is the
///     SAME class of error in the opposite direction (upstream ADDS a type, or
///     re-enables one) and is the half a one-directional check would miss:
///     the symptom there is bad-qc-missing on a block we thought was complete.
///
/// and three are not:
///
///   * Observed — required and seen. The healthy state.
///   * Unevaluated — not enough observation yet. The HONEST value for a
///     bootstrap that has not run long enough. It is never silently rendered
///     as "fine"; `defects()` excludes it and `verdict_name()` prints it.
///   * StaleSightings — a non-required type that WAS sighted but whose every
///     sighting has aged out of its retention window. See mode 2 below.
///
/// FALSE-POSITIVE DISCIPLINE. Slandering a type would be as bad as missing
/// one, so promoting silence to NeverObserved requires POSITIVE proof that the
/// observation channel was live: `kCorroborationRequired` — at least one OTHER
/// required type must have been observed. Without that, a drained/bootstrapping
/// QuorumManager (which reports nothing for ANY type) stays Unevaluated for
/// every type rather than indicting all of them. Absence is only evidence when
/// presence was demonstrable on the same channel.
///
/// THE OBSERVATION SOURCE is the mnlistdiff-fed QuorumManager active set. Per
/// dkg_commitments.hpp that set IS dashd's
/// GetMinedAndActiveCommitmentsUntilBlock(tip) — i.e. MINED commitments, which
/// is precisely "which llmqTypes actually appear in mined qcTx". It is also
/// already current at every template build, so the reconciler needs no new
/// wire traffic and reaches a verdict inside one DKG cycle of the fastest
/// type (24 blocks) rather than never.
///
/// A note on why a SINGLE tip sample is already nearly conclusive, and why we
/// still do not act on one: an enabled non-rotated type holds
/// signingActiveQuorumCount quorums active (24 for the interval-24 types,
/// spanning 576 blocks of history), so a current active set contains EVERY
/// enabled type. One sample would therefore be enough — except during our own
/// SML bootstrap, when the set is legitimately partial. `kMinObservations`
/// plus the corroboration rule buy that distinction cheaply.
///
/// TWO FALSE-POSITIVE MODES THE FIRST SHIP CARRIED (both on the
/// MINED-BUT-NOT-REQUIRED side; both fixed here, both regression-pinned in
/// test_dash_dkg_commitments.cpp):
///
///   1. ZERO-WIDTH WINDOW. observe() runs once per template build, which is
///      MANY times per block, so kMinObservations calls accumulate at a
///      single tip height and the UnexpectedType branch — which gated only on
///      the observation COUNT, never the window WIDTH — could indict before
///      any real observation window existed. The required-side verdicts
///      always demanded a full DKG cycle of span; the unexpected side now
///      demands the same (its own cycle when the type is in the known params
///      table, the largest known cycle otherwise).
///
///   2. SELF-REFRESHING STALE ENTRY (measured 2026-08-04, two independent
///      soaks): `[LLMQ-TYPE-RECONCILE] type=1 MINED-BUT-NOT-REQUIRED` rang
///      continuously with sightings == observations EXACTLY (1408==1408,
///      895==895) while ZERO type-1 qfcommits existed in ~12 h of chain —
///      impossible for real evidence, guaranteed for a bookkeeping loop.
///      observe() stamped every entry PRESENT in the local active set with
///      the CURRENT TIP height, never the quorum's own height, so one stale
///      local entry (type 1 — a set mainnet cannot even mine, see
///      reference above) re-registered as a fresh sighting at every sample,
///      forever. An alarm that cannot decay carries no information. Now each
///      entry is dated by ITS OWN height — mining_height when the [QC-MINED]
///      scanner has seen the qfcommit tx, else the height at which WE first
///      saw that (type, quorumHash) — and an entry older than its type's
///      active-quorum retention window (dkgInterval ×
///      signingActiveQuorumCount, the span the chain itself keeps a quorum
///      active) is NOT a sighting. A stale entry therefore ages OUT, the
///      per-type last-sighting height freezes, and once it trails the tip by
///      more than one DKG cycle the verdict decays to StaleSightings — a
///      named non-defect — and the alarm CLEARS. A genuinely mined type
///      keeps producing in-retention entries, so its alarm never decays.
///
///   3. RESTART RESURRECTION OF AN UNDATED ENTRY (measured 2026-08-06, hotel
///      reserve node, issue #1164): mode 2's first-seen dating lives in
///      memory, so a process restart re-dates every scanner-undated entry as
///      fresh — and a bogus never-mined entry that mnlistdiff/qrinfo keeps
///      delivering (a full-span chain sweep showed ZERO type-1 commitments
///      on-chain while the alarm cited that exact span) rings for a whole
///      retention window (576 blocks for type 1) after EVERY restart,
///      indefinitely. The fix is evidentiary, not another timer: the
///      UnexpectedType indictment now requires at least one sighting whose
///      entry the [QC-MINED] scanner actually dated (mined_height known).
///      DELIVERY IS NOT MINING. A genuinely upstream-added type is mined
///      every cycle and gets scanner-dated within one, so the real defect
///      still fires; an entry no one can date stays Unevaluated with reason
///      "delivered-but-never-scanner-dated" — visible, never alarming.

#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/quorum_manager.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

enum class LlmqTypeVerdict : uint8_t {
    Unevaluated = 0,   // insufficient observation — the honest "don't know"
    Observed,          // required AND seen in mined commitments
    NeverObserved,     // required, span sufficient, corroborated, ZERO sightings
    UnexpectedType,    // mined on-chain but NOT in our required set — LIVE
                       // evidence: sighted within the last DKG cycle
    StaleSightings,    // NOT required, WAS sighted, but every sighting has
                       // aged out: no in-retention entry for over one DKG
                       // cycle. Either a stale local cache entry that aged
                       // out (the measured 2026-08-04 mode) or a type the
                       // chain genuinely stopped mining. NOT a defect —
                       // stale evidence must not keep an alarm ringing.
};

inline const char* llmq_type_verdict_name(LlmqTypeVerdict v)
{
    switch (v) {
        case LlmqTypeVerdict::Unevaluated:    return "unevaluated";
        case LlmqTypeVerdict::Observed:       return "observed";
        case LlmqTypeVerdict::NeverObserved:  return "REQUIRED-BUT-NEVER-OBSERVED";
        case LlmqTypeVerdict::UnexpectedType: return "MINED-BUT-NOT-REQUIRED";
        case LlmqTypeVerdict::StaleSightings: return "stale-sightings-aged-out";
    }
    return "unevaluated";
}

/// True for the verdicts that are DEFECTS — a type table that disagrees with
/// the chain, in either direction.
inline bool is_llmq_type_defect(LlmqTypeVerdict v)
{
    return v == LlmqTypeVerdict::NeverObserved
        || v == LlmqTypeVerdict::UnexpectedType;
}

struct LlmqTypeFinding {
    uint8_t         llmq_type{0};
    LlmqTypeVerdict verdict{LlmqTypeVerdict::Unevaluated};
    bool            required{false};      // present in enabled_llmqs(net)
    /// Observations in which the type appeared via at least one entry INSIDE
    /// its retention window. An entry whose quorum aged out of retention is
    /// NOT a sighting — that is the whole difference between evidence and a
    /// stale cache echo (see header, mode 2).
    uint64_t        sightings{0};
    uint32_t        first_height{0};      // 0 == never observed anything
    uint32_t        last_height{0};
    uint32_t        span_heights{0};      // last - first
    uint32_t        dkg_interval{0};      // 0 for a non-required type
    /// Why a verdict stayed Unevaluated — never guessed, never blank.
    const char*     pending_reason{"n/a"};
};

/// One active-set entry as the reconciler consumes it. The quorum's OWN
/// height is the load-bearing field: stamping sightings with the current tip
/// instead of it is exactly the self-refreshing-stale-entry defect (header,
/// mode 2).
struct LlmqEntryObservation {
    uint8_t  llmq_type{0};
    /// Identity for first-seen dating. Null == no identity: the caller is
    /// asserting the type is mined as of the observed tip (test feeds).
    uint256  quorum_hash{};
    /// The quorum's own mined height. 0 == unknown (mnlistdiff delivered the
    /// entry but the [QC-MINED] scanner has not seen its qfcommit tx) — the
    /// entry is then dated by when WE first saw this (type, quorumHash).
    uint32_t mined_height{0};
};

class LlmqTypeReconciler {
public:
    /// Minimum number of observe() calls before ANY promotion out of
    /// Unevaluated. Guards against a single degenerate sample.
    static constexpr uint32_t kMinObservations = 8;
    /// A required type is only indicted once the observation window spans at
    /// least this many of ITS OWN full DKG cycles. One is enough: the type is
    /// mined once per dkgInterval, so a complete cycle with zero sightings is
    /// already a completed experiment.
    static constexpr uint32_t kMinCyclesCovered = 1;
    /// ...and only if at least one OTHER required type was observed, proving
    /// the channel was live. See FALSE-POSITIVE DISCIPLINE above.
    static constexpr bool kCorroborationRequired = true;
    /// DKG cycle assumed for a type ABSENT from the known params table (an
    /// upstream-added type we have no row for): the largest known interval
    /// (llmq_400_85, 576), so the unexpected-side span gate errs toward
    /// waiting, never toward a premature indictment.
    static constexpr uint32_t kFallbackDkgInterval = 576;
    /// Retention assumed for a type absent from the table: the largest
    /// dkgInterval x signingActiveQuorumCount product among known types
    /// (llmq_60_75, 288 x 32). Overestimating retention only delays aging —
    /// it can never fabricate a sighting.
    static constexpr uint32_t kFallbackRetention = 9216;

    /// Full params row for ANY type dashcore defines at this pin — including
    /// types the runtime predicate disables (enabled_llmqs() would not have
    /// them; the 2026-08-04 stale entry was exactly such a type).
    static const LlmqParamsView* known_llmq_params(uint8_t t)
    {
        static const LlmqParamsView kAll[] = {
            kLlmq50_60, kLlmq60_75, kLlmq400_60, kLlmq400_85,
            kLlmq100_67, kLlmq25_67};
        for (const auto& p : kAll)
            if (p.type == t) return &p;
        return nullptr;
    }

    static uint32_t dkg_interval_for(uint8_t t)
    {
        const auto* p = known_llmq_params(t);
        return p ? p->dkg_interval : kFallbackDkgInterval;
    }

    /// The chain's own active-quorum retention window for a type: a mined
    /// quorum stays in the active set for signingActiveQuorumCount DKG cycles
    /// before newer quorums push it out. An entry older than this cannot be
    /// a currently-active quorum — it is a stale local cache echo.
    static uint32_t retention_for(uint8_t t)
    {
        const auto* p = known_llmq_params(t);
        return p ? p->dkg_interval * p->signing_active_quorum_count
                 : kFallbackRetention;
    }

    explicit LlmqTypeReconciler(LlmqNetwork net) : m_net(net) {}

    /// Record the active-set entries as of `tip`. A type registers ONE
    /// sighting per call (set semantics, not a quorum count) and ONLY via
    /// entries whose own height is inside the type's retention window —
    /// an entry the chain would already have aged out is a stale local echo,
    /// not evidence (header, mode 2). Entry dating, most-truthful-first:
    ///   1. mined_height when known (the [QC-MINED] scanner saw the qfcommit);
    ///   2. else the tip at which WE first saw this (type, quorumHash) — a
    ///      stale leftover dates from our first sample and can only age;
    ///   3. else (no identity at all) the observed tip — the caller asserts
    ///      freshness, which is what the types-only test feed means.
    void observe(uint32_t tip_height,
                 const std::vector<LlmqEntryObservation>& entries)
    {
        ++m_observations;
        if (m_first_height == 0 || tip_height < m_first_height)
            m_first_height = tip_height;
        if (tip_height > m_last_height) m_last_height = tip_height;

        std::set<uint8_t> present;   // types with >=1 IN-RETENTION entry
        std::set<uint8_t> confirmed; // ...of which >=1 is scanner-dated
        std::map<std::pair<uint8_t, uint256>, uint32_t> first_seen_next;
        for (const auto& e : entries) {
            uint32_t own_h = e.mined_height;
            const bool scanner_dated = (own_h != 0);
            if (own_h == 0 && !e.quorum_hash.IsNull()) {
                const auto key = std::make_pair(e.llmq_type, e.quorum_hash);
                auto it = m_first_seen.find(key);
                own_h = (it != m_first_seen.end()) ? it->second : tip_height;
                // Keep the record even for an aged-out entry — dropping it
                // while the entry is still served would re-date the entry
                // as fresh and resurrect the self-refresh loop cyclically.
                first_seen_next.emplace(key, own_h);
            }
            if (own_h == 0) own_h = tip_height;   // no identity: asserted fresh
            if (tip_height > own_h
                && tip_height - own_h > retention_for(e.llmq_type))
                continue;                          // aged out — NOT a sighting
            present.insert(e.llmq_type);
            if (scanner_dated) confirmed.insert(e.llmq_type);
        }
        // Records for entries no longer served are dropped here, bounding the
        // map by the live active-set size. If such an entry ever reappears it
        // is a NEW mnlistdiff insertion and fresh dating is the honest read.
        m_first_seen.swap(first_seen_next);

        for (uint8_t t : present) {
            auto& s = m_seen[t];
            ++s.sightings;
            if (s.first_height == 0 || tip_height < s.first_height)
                s.first_height = tip_height;
            if (tip_height > s.last_height) s.last_height = tip_height;
            if (confirmed.count(t)) {
                ++s.scanner_confirmed;
                if (tip_height > s.last_confirmed_height)
                    s.last_confirmed_height = tip_height;
            }
        }
    }

    /// Types-only feed (tests, hand-built streams). No entry identity, so
    /// each listed type is asserted mined as of `tip` — staleness cannot be
    /// judged and is not: that is the CALLER'S claim to get right.
    void observe(uint32_t tip_height, const std::vector<uint8_t>& mined_types)
    {
        std::vector<LlmqEntryObservation> es;
        es.reserve(mined_types.size());
        for (uint8_t t : mined_types)
            es.push_back(LlmqEntryObservation{t, uint256{}, tip_height});
        observe(tip_height, es);
    }

    /// The production overload: the mnlistdiff-fed active set IS dashd's
    /// mined-and-active commitment set (dkg_commitments.hpp header note).
    /// Each entry carries its own (type, quorumHash, mining_height) so the
    /// core observe() can date it — passing types alone is what let a stale
    /// entry re-register forever (header, mode 2).
    void observe(uint32_t tip_height, const QuorumManager& qmgr)
    {
        std::vector<LlmqEntryObservation> es;
        es.reserve(qmgr.active_entries().size());
        for (const auto& e : qmgr.active_entries())
            es.push_back(LlmqEntryObservation{
                e.key.llmqType, e.key.quorumHash, e.mining_height});
        observe(tip_height, es);
    }

    uint32_t observations() const { return m_observations; }
    uint32_t span_heights() const
    {
        return m_last_height > m_first_height
            ? (m_last_height - m_first_height) : 0u;
    }

    /// One finding per required type, plus one per observed-but-not-required
    /// type. Deterministically ordered by llmqType so logs are diffable.
    std::vector<LlmqTypeFinding> reconcile() const
    {
        const auto& required = enabled_llmqs(m_net);

        // Corroboration: did ANY required type actually show up? Without this
        // the channel itself may simply be empty, and an empty channel is not
        // evidence about any particular type.
        bool corroborated = false;
        for (const auto& p : required) {
            auto it = m_seen.find(p.type);
            if (it != m_seen.end() && it->second.sightings > 0) {
                corroborated = true;
                break;
            }
        }

        std::map<uint8_t, LlmqTypeFinding> out;

        for (const auto& p : required) {
            LlmqTypeFinding f;
            f.llmq_type    = p.type;
            f.required     = true;
            f.dkg_interval = p.dkg_interval;
            auto it = m_seen.find(p.type);
            if (it != m_seen.end()) {
                f.sightings    = it->second.sightings;
                f.first_height = it->second.first_height;
                f.last_height  = it->second.last_height;
            }
            f.span_heights = span_heights();

            if (f.sightings > 0) {
                f.verdict = LlmqTypeVerdict::Observed;
            } else if (m_observations < kMinObservations) {
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "too-few-observations";
            } else if (p.dkg_interval == 0
                       || f.span_heights < p.dkg_interval * kMinCyclesCovered) {
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "span-shorter-than-one-dkg-cycle";
            } else if (kCorroborationRequired && !corroborated) {
                // Nothing at all was observed on this channel — indicting a
                // type here would be slander, not a finding.
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "no-required-type-observed-anywhere";
            } else {
                f.verdict = LlmqTypeVerdict::NeverObserved;
                f.pending_reason = "n/a";
            }
            out[p.type] = f;
        }

        // The other direction: a type the chain mines that we do not require.
        // The indictment discipline mirrors the required side: enough
        // observations AND a real window at least one DKG cycle wide (a
        // zero-width window — many samples at one tip — proves nothing,
        // header mode 1) AND the evidence must be LIVE — sighted within the
        // last cycle. Sightings that all aged out decay to StaleSightings
        // and the alarm clears (header, mode 2).
        for (const auto& [t, s] : m_seen) {
            if (out.count(t) != 0) continue;   // required, already handled
            LlmqTypeFinding f;
            f.llmq_type    = t;
            f.required     = false;
            f.sightings    = s.sightings;
            f.first_height = s.first_height;
            f.last_height  = s.last_height;
            f.span_heights = span_heights();
            const uint32_t cycle = dkg_interval_for(t);
            if (m_observations < kMinObservations) {
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "too-few-observations";
            } else if (f.span_heights < cycle * kMinCyclesCovered) {
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "span-shorter-than-one-dkg-cycle";
            } else if (m_last_height - s.last_height > cycle) {
                // A genuinely mined type has in-retention entries at EVERY
                // sample, so its last sighting rides the tip. A last
                // sighting more than one full cycle behind means every
                // entry aged out of retention: stale evidence, not a
                // current disagreement with the chain.
                f.verdict = LlmqTypeVerdict::StaleSightings;
                f.pending_reason = "n/a";
            } else if (s.scanner_confirmed == 0) {
                // MODE 3 (measured 2026-08-06, hotel reserve node): the entry
                // is SERVED (mnlistdiff/qrinfo delivered it) but the
                // [QC-MINED] scanner has never dated its qfcommit, and a
                // full-span chain sweep showed ZERO commitments of the type
                // on-chain. Delivery is not mining. Without one scanner-dated
                // entry the "MINED"-but-not-required indictment has no mined
                // evidence at all — and because this reconciler is in-memory,
                // every restart re-dated the undated entry as fresh and the
                // alarm resurrected for a whole retention window (576 blocks
                // for type 1), surviving restarts indefinitely. A genuinely
                // upstream-added type is mined every cycle, so the scanner
                // dates it within one cycle and the indictment still fires.
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "delivered-but-never-scanner-dated";
            } else {
                f.verdict = LlmqTypeVerdict::UnexpectedType;
                f.pending_reason = "n/a";
            }
            out[t] = f;
        }

        std::vector<LlmqTypeFinding> v;
        v.reserve(out.size());
        for (const auto& [t, f] : out) v.push_back(f);
        return v;
    }

    /// Only the findings that are defects. EMPTY IS A REAL RESULT — it means
    /// the table agrees with the chain as far as the evidence goes, not that
    /// nothing was checked (use observations()/span_heights() for that).
    std::vector<LlmqTypeFinding> defects() const
    {
        std::vector<LlmqTypeFinding> v;
        for (auto& f : reconcile())
            if (is_llmq_type_defect(f.verdict)) v.push_back(f);
        return v;
    }

    /// A LOUD one-line rendering, naming every offending type. Empty string
    /// when there is nothing to say — callers must not log a bare "ok".
    std::string format_defects() const
    {
        auto d = defects();
        if (d.empty()) return {};
        std::string s = "[LLMQ-TYPE-RECONCILE] ENABLED-SET DISAGREES WITH THE"
                        " CHAIN — ";
        s += (m_net == LlmqNetwork::Mainnet ? "mainnet" : "testnet");
        s += " observations=" + std::to_string(m_observations)
           + " span=" + std::to_string(span_heights()) + "b"
           + " heights=[" + std::to_string(m_first_height) + ","
           + std::to_string(m_last_height) + "]";
        for (const auto& f : d) {
            s += " | type=" + std::to_string(static_cast<int>(f.llmq_type))
               + " " + llmq_type_verdict_name(f.verdict)
               + " required=" + (f.required ? "yes" : "no")
               + " sightings=" + std::to_string(f.sightings);
            if (f.required)
                s += " dkg_interval=" + std::to_string(f.dkg_interval);
        }
        if (std::any_of(d.begin(), d.end(), [](const LlmqTypeFinding& f) {
                return f.verdict == LlmqTypeVerdict::NeverObserved; })) {
            s += " || a REQUIRED type that is never mined makes every DKG"
                 " mining-window height of that type PERMANENTLY unserveable"
                 " (the slot can never be satisfied). Re-derive"
                 " enabled_llmqs() from dashd's IsQuorumTypeEnabled predicate"
                 " at our serve floor — NOT from the chainparams AddLLMQ list.";
        }
        if (std::any_of(d.begin(), d.end(), [](const LlmqTypeFinding& f) {
                return f.verdict == LlmqTypeVerdict::UnexpectedType; })) {
            s += " || a MINED type we do not require means our blocks omit a"
                 " mandatory commitment (bad-qc-missing). Re-derive"
                 " enabled_llmqs() before the next window height.";
        }
        return s;
    }

    /// The DEFECT SHAPE — the finding set with every volatile counter
    /// stripped: type + verdict + required, and nothing else.
    ///
    /// WHY THIS EXISTS. format_defects() embeds `observations=`, `span=`,
    /// `heights=[first,last]` and per-type `sightings=`, ALL of which move on
    /// every template build. A caller that dedups on "has the sentence
    /// changed" therefore re-logs on EVERY observation even when the finding
    /// is identical — the sentence cannot help but change. Measured
    /// 2026-08-04: 205k+ [LLMQ-TYPE-RECONCILE] lines in a single run, which
    /// buried every other diagnostic in the log. Keying on this shape dedups
    /// on the thing an operator actually cares about (WHICH types are wrong),
    /// while a genuinely new offending type still changes the key and is
    /// reported immediately. Empty when there is nothing wrong.
    std::string defect_shape() const
    {
        auto d = defects();
        if (d.empty()) return {};
        std::string k;
        for (const auto& f : d) {
            k += std::to_string(static_cast<int>(f.llmq_type));
            k += ':';
            k += llmq_type_verdict_name(f.verdict);
            k += f.required ? ":req;" : ":opt;";
        }
        return k;
    }

    void reset()
    {
        m_seen.clear();
        m_first_seen.clear();
        m_observations = 0;
        m_first_height = 0;
        m_last_height  = 0;
    }

private:
    struct Sighting {
        uint64_t sightings{0};
        uint32_t first_height{0};
        uint32_t last_height{0};
        /// Sightings backed by an entry whose qfcommit the [QC-MINED] scanner
        /// actually dated (mined_height known). Only these can indict an
        /// UnexpectedType — see mode 3 in the header.
        uint64_t scanner_confirmed{0};
        uint32_t last_confirmed_height{0};
    };

    LlmqNetwork m_net;
    std::map<uint8_t, Sighting> m_seen;
    /// First tip at which each identity-bearing, mined_height-unknown entry
    /// was observed — the dating proxy for entries the [QC-MINED] scanner has
    /// not dated. Pruned every observe() to the entries currently served.
    std::map<std::pair<uint8_t, uint256>, uint32_t> m_first_seen;
    uint32_t m_observations{0};
    uint32_t m_first_height{0};
    uint32_t m_last_height{0};
};

} // namespace coin
} // namespace dash
