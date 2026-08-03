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
/// type, and two of the four verdicts are defects:
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
/// and two are not:
///
///   * Observed — required and seen. The healthy state.
///   * Unevaluated — not enough observation yet. The HONEST value for a
///     bootstrap that has not run long enough. It is never silently rendered
///     as "fine"; `defects()` excludes it and `verdict_name()` prints it.
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

#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/quorum_manager.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

enum class LlmqTypeVerdict : uint8_t {
    Unevaluated = 0,   // insufficient observation — the honest "don't know"
    Observed,          // required AND seen in mined commitments
    NeverObserved,     // required, span sufficient, corroborated, ZERO sightings
    UnexpectedType,    // mined on-chain but NOT in our required set
};

inline const char* llmq_type_verdict_name(LlmqTypeVerdict v)
{
    switch (v) {
        case LlmqTypeVerdict::Unevaluated:    return "unevaluated";
        case LlmqTypeVerdict::Observed:       return "observed";
        case LlmqTypeVerdict::NeverObserved:  return "REQUIRED-BUT-NEVER-OBSERVED";
        case LlmqTypeVerdict::UnexpectedType: return "MINED-BUT-NOT-REQUIRED";
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
    uint64_t        sightings{0};         // observations in which it appeared
    uint32_t        first_height{0};      // 0 == never observed anything
    uint32_t        last_height{0};
    uint32_t        span_heights{0};      // last - first
    uint32_t        dkg_interval{0};      // 0 for a non-required type
    /// Why a verdict stayed Unevaluated — never guessed, never blank.
    const char*     pending_reason{"n/a"};
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

    explicit LlmqTypeReconciler(LlmqNetwork net) : m_net(net) {}

    /// Record the set of llmqTypes present in MINED commitments as of `tip`.
    /// Duplicate types within one call count once (this is a set observation,
    /// not a count of quorums).
    void observe(uint32_t tip_height, const std::vector<uint8_t>& mined_types)
    {
        ++m_observations;
        if (m_first_height == 0 || tip_height < m_first_height)
            m_first_height = tip_height;
        if (tip_height > m_last_height) m_last_height = tip_height;

        std::set<uint8_t> uniq(mined_types.begin(), mined_types.end());
        for (uint8_t t : uniq) {
            auto& s = m_seen[t];
            ++s.sightings;
            if (s.first_height == 0 || tip_height < s.first_height)
                s.first_height = tip_height;
            if (tip_height > s.last_height) s.last_height = tip_height;
        }
    }

    /// The production overload: the mnlistdiff-fed active set IS dashd's
    /// mined-and-active commitment set (dkg_commitments.hpp header note).
    void observe(uint32_t tip_height, const QuorumManager& qmgr)
    {
        std::vector<uint8_t> types;
        types.reserve(qmgr.active_entries().size());
        for (const auto& e : qmgr.active_entries())
            types.push_back(e.key.llmqType);
        observe(tip_height, types);
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
        for (const auto& [t, s] : m_seen) {
            if (out.count(t) != 0) continue;   // required, already handled
            LlmqTypeFinding f;
            f.llmq_type    = t;
            f.required     = false;
            f.sightings    = s.sightings;
            f.first_height = s.first_height;
            f.last_height  = s.last_height;
            f.span_heights = span_heights();
            if (m_observations < kMinObservations) {
                f.verdict = LlmqTypeVerdict::Unevaluated;
                f.pending_reason = "too-few-observations";
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

    void reset()
    {
        m_seen.clear();
        m_observations = 0;
        m_first_height = 0;
        m_last_height  = 0;
    }

private:
    struct Sighting {
        uint64_t sightings{0};
        uint32_t first_height{0};
        uint32_t last_height{0};
    };

    LlmqNetwork m_net;
    std::map<uint8_t, Sighting> m_seen;
    uint32_t m_observations{0};
    uint32_t m_first_height{0};
    uint32_t m_last_height{0};
};

} // namespace coin
} // namespace dash
