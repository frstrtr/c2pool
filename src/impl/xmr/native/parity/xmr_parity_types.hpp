// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_types.hpp
//
// C6, the value layer: what an ARM SAID, and what the comparator is allowed to
// do with it.
//
// THE ONE IDEA IN THIS FILE. Every number an arm reports is carried as an `Obs`
// -- a rendered value plus a PRESENT flag -- and never as a bare integer. That
// is not decoration. The failure this whole component exists to prevent is a
// parity run that reports agreement because it compared nothing: a field that
// the daemon stopped returning, a snapshot the native arm could not build, a
// probe that never fired. Every one of those arrives as a zero if the field is
// a `std::uint64_t`, and zero compares equal to zero.
//
// So absence is a FIRST-CLASS VALUE here, it is distinguishable from every real
// number including zero, and the comparator in xmr_parity_comparator.hpp is
// written so that absence can never travel down the path that ends in CLEAN.
//
// The second idea: fields are looked up BY NAME against a frozen table
// (SeamSpec), not read off a struct. A struct field that nobody compares is
// invisible; a table row that nobody answers is a hole the comparator can see
// and count. That is what makes "did we actually compare the three seams?" a
// question with an arithmetic answer rather than a code review.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/parity.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::parity {

// ---------------------------------------------------------------------------
// Comparator version. BUMP ON ANY SEMANTIC CHANGE to the tables below or to the
// comparison rules: the graduation ledger is keyed on this number precisely so
// that a new comparator can never inherit an old comparator's clean streak.
// ---------------------------------------------------------------------------
// Version 2 (M1): the P-POOL seam joined the table set. Nothing in the P-TIP,
// P-TPL or P-SUB tables changed, and the bump is not about them -- it is about
// the LEDGER KEY. A run graduated by a comparator that never asked what the
// transaction pool held is not evidence about a comparator that does, so the
// key moves and every streak starts again.
inline constexpr std::uint32_t COMPARATOR_VERSION = 2;

// ---------------------------------------------------------------------------
// Regimes -- how a field is judged. Named after the plan's determinism table.
// ---------------------------------------------------------------------------
enum class Regime : std::uint8_t {
    // Part of the sample's identity. A mismatch means the two arms are talking
    // about different blocks: the sample is VOID, not failed.
    AlignmentKey = 0,
    // Must be byte-identical. A mismatch is a parity FAILURE.
    Equality,
    // Recomputed from the sample itself and required to hold. A violation is a
    // failure of OUR OWN arithmetic and is a FAILURE even if both arms agree.
    Invariant,
    // A bound rather than a value (a timestamp inside its window).
    Constraint,
    // Reported, never a gate. Coverage deltas live here -- the DASH lesson that
    // an "ours_only == 0" gate is unreachable and blind.
    Measurement,
    // Different by construction; recorded so that nobody re-adds it as a gate.
    NotComparable,
};

inline const char* to_string(Regime r) noexcept {
    switch (r) {
        case Regime::AlignmentKey:  return "ALIGNMENT-KEY";
        case Regime::Equality:      return "EQUALITY";
        case Regime::Invariant:     return "INVARIANT";
        case Regime::Constraint:    return "CONSTRAINT";
        case Regime::Measurement:   return "MEASUREMENT";
        case Regime::NotComparable: return "NOT-COMPARABLE";
    }
    return "?";
}

inline const char* to_string(ProbeKind k) noexcept {
    switch (k) {
        case ProbeKind::Tip:      return "TIP";
        case ProbeKind::Template: return "TEMPLATE";
        case ProbeKind::Submit:   return "SUBMIT";
        case ProbeKind::Pool:     return "POOL";
    }
    return "?";
}

inline const char* to_string(ParityVerdict v) noexcept {
    switch (v) {
        case ParityVerdict::Void:           return "VOID";
        case ParityVerdict::Clean:          return "CLEAN";
        case ParityVerdict::Fail:           return "FAIL";
        case ParityVerdict::ServedMismatch: return "SERVED-MISMATCH";
    }
    return "?";
}

inline const char* to_string(HeightClass c) noexcept {
    switch (c) {
        case HeightClass::Steady:       return "Steady";
        case HeightClass::EpochEdge:    return "EpochEdge";
        case HeightClass::Reorg:        return "Reorg";
        case HeightClass::HardForkEdge: return "HardForkEdge";
        case HeightClass::PenaltyZone:  return "PenaltyZone";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Obs -- one observed value, or the explicit absence of one.
//
// `value` is a RENDERING, not the number. Every field in every seam therefore
// compares the same way (string equality) and prints the same way, and the
// rendering functions below are the only place a type-specific formatting rule
// lives. A u128 renders as "hi:lo" so that a top64 carry can never be lost in a
// decimal truncation.
// ---------------------------------------------------------------------------
struct Obs {
    bool        present = false;
    std::string value;

    static Obs absent() { return Obs{}; }

    static Obs text(std::string v) {
        Obs o; o.present = true; o.value = std::move(v); return o;
    }
    static Obs u64(std::uint64_t v) {
        char b[24];
        std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
        return text(b);
    }
    static Obs u128(const U128& d) {
        char b[48];
        std::snprintf(b, sizeof(b), "%llu:%llu",
                      static_cast<unsigned long long>(d.hi),
                      static_cast<unsigned long long>(d.lo));
        return text(b);
    }
    static Obs id(const Hash& h) {
        static const char* dig = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (std::uint8_t b : h) { s.push_back(dig[b >> 4]); s.push_back(dig[b & 0x0f]); }
        return text(std::move(s));
    }
    static Obs boolean(bool v) { return text(v ? "true" : "false"); }

    // The rendering used in a diff report for something that was never
    // observed. It is deliberately not a number, so it can never be mistaken
    // for one in a log line.
    static const char* absent_marker() noexcept { return "<absent>"; }

    const std::string& render() const {
        static const std::string kAbsent = absent_marker();
        return present ? value : kAbsent;
    }
};

// A zero-valued Obs is a REAL observation of zero and must stay distinct from
// absence; these two helpers exist so a reader of the comparator never has to
// re-derive that.
inline bool is_absent(const Obs& o) noexcept { return !o.present; }
inline bool same_value(const Obs& a, const Obs& b) noexcept {
    return a.present && b.present && a.value == b.value;
}

// ---------------------------------------------------------------------------
// FieldSet -- what one arm said, keyed by field name.
//
// A name that was never set() is absent, exactly like a name that was set to
// Obs::absent(). Both are holes; neither is agreement.
// ---------------------------------------------------------------------------
class FieldSet {
public:
    void set(const char* name, Obs o) {
        for (auto& kv : v_) {
            if (kv.first == name) { kv.second = std::move(o); return; }
        }
        v_.emplace_back(std::string(name), std::move(o));
    }

    // Never returns null: an unknown name is an absent Obs, which is the same
    // thing the comparator must do with a known-but-unanswered one.
    const Obs& get(const char* name) const {
        static const Obs kAbsent;
        for (const auto& kv : v_) if (kv.first == name) return kv.second;
        return kAbsent;
    }

    bool answered(const char* name) const { return get(name).present; }
    std::size_t size() const noexcept { return v_.size(); }
    const std::vector<std::pair<std::string, Obs>>& all() const noexcept { return v_; }

private:
    std::vector<std::pair<std::string, Obs>> v_;
};

// ---------------------------------------------------------------------------
// One arm's answer for one seam at one point in the chain.
//
// `have` is the difference between "the arm answered" and "the arm was asked".
// An arm that could not answer at all yields a VOID sample -- there is nothing
// to judge. An arm that answered but left a required field empty is a
// different, worse thing, and the comparator treats it as such.
// ---------------------------------------------------------------------------
struct ArmObservation {
    bool          have = false;      // did this arm produce an answer at all
    std::string   arm;               // "native" / "monerod"
    std::uint64_t height = 0;        // alignment key part 1
    Hash          prev_id{};         // alignment key part 2
    FieldSet      fields;
    std::string   why;               // when !have: why not, in the arm's words
};

// ---------------------------------------------------------------------------
// The frozen field tables (comparator version 1).
//
// `required` marks an EQUALITY field whose absence is a FAILURE rather than a
// hole: the arm answered, so it owed this number. A required field also carries
// a per-field coverage counter in the ledger, which is what stops a field that
// is never comparable from being silently graduated over.
// ---------------------------------------------------------------------------
struct FieldSpec {
    const char* name;
    Regime      regime;
    bool        required;   // meaningful for Equality; ignored otherwise
    // Set for the revocation sentinels of plan section 3.5: a mismatch here does
    // not merely fail the sample, it revokes graduation immediately.
    bool        sentinel;
};

struct SeamSpec {
    ProbeKind        kind;
    const FieldSpec* fields;
    std::size_t      count;

    std::size_t required_equality_count() const {
        std::size_t n = 0;
        for (std::size_t i = 0; i < count; ++i)
            if (fields[i].regime == Regime::Equality && fields[i].required) ++n;
        return n;
    }
};

// --- P-TIP ------------------------------------------------------------------
// The native chain index's tip against monerod's own (get_info +
// get_last_block_header). cumulative_difficulty is the one that matters most:
// it is chain STATE, it is not in any header, and it is what fork choice runs
// on. If it agrees over a sustained window, the native index walked the same
// chain the daemon did and did the same arithmetic on the way.
inline constexpr FieldSpec TIP_FIELDS[] = {
    {"height",                Regime::AlignmentKey,  false, false},
    {"id",                    Regime::Equality,      true,  false},
    {"prev_id",               Regime::Equality,      true,  false},
    {"cumulative_difficulty", Regime::Equality,      true,  true },
    {"difficulty",            Regime::Equality,      true,  true },
    {"timestamp",             Regime::Equality,      true,  false},
    {"reward",                Regime::Equality,      true,  false},
    {"block_weight",          Regime::Equality,      true,  false},
    {"long_term_weight",      Regime::Equality,      true,  false},
    {"major_version",         Regime::Equality,      true,  true },
    {"lag_ms",                Regime::Measurement,   false, false},
};

// --- P-TPL ------------------------------------------------------------------
// The seven get_miner_data fields, plus the two the assembler consumes that
// monerod does not return (median_timestamp is DERIVED -- monerod exposes no
// RPC for it -- so it is a Constraint on our own side, not an Equality).
//
// The coinbase bytes are deliberately NOT here: monerod's get_block_template
// mints a random transaction key and a single output, so its coinbase differs
// from the option-B settlement coinbase BY DESIGN. Listing it as
// NotComparable is how that stays a recorded decision instead of a bug someone
// re-files every six months.
inline constexpr FieldSpec TEMPLATE_FIELDS[] = {
    {"height",                  Regime::AlignmentKey,  false, false},
    {"prev_id",                 Regime::Equality,      true,  false},
    {"major_version",           Regime::Equality,      true,  true },
    {"difficulty",              Regime::Equality,      true,  true },
    {"seed_hash",               Regime::Equality,      true,  true },
    {"median_weight",           Regime::Equality,      true,  true },
    {"already_generated_coins", Regime::Equality,      true,  true },
    {"median_timestamp",        Regime::Constraint,    false, false},
    {"tx_backlog_count",        Regime::Measurement,   false, false},
    {"coinbase_bytes",          Regime::NotComparable, false, false},
};

// --- P-SUB ------------------------------------------------------------------
// Submit has no field table: its judgement is over the relay verdict as a
// whole (see judge_submit). The spec exists so the seam enumerates uniformly.
inline constexpr FieldSpec SUBMIT_FIELDS[] = {
    {"block_id",         Regime::AlignmentKey, false, false},
    {"daemon_accepted",  Regime::Equality,     true,  true },
    {"confirmed_on_chain", Regime::Equality,   true,  true },
    {"p2p_peers_sent",   Regime::Measurement,  false, false},
};

// --- P-POOL -----------------------------------------------------------------
// ONE TRANSACTION, held by both pools, as each side measured it.
//
// The alignment key is the transaction id, and it is the reason the other three
// fields mean anything. A Monero transaction id is the triple hash over the
// three measured byte spans that make up the whole blob, so two pools that
// report the same id are holding the same bytes -- which turns "weight, fee and
// blob_size agree" from three coincidences into three INDEPENDENT DERIVATIONS
// from one input agreeing. That is the claim M1 exists to make: the native pool
// does monerod's arithmetic, over the wire, without asking it.
//
//   * weight is the one that can actually be got wrong. It is not a length: for
//     a Bulletproof+ transaction it is the blob size plus a clawback term over
//     the padded proof size, and it is what the block-weight limit and the fee
//     are denominated in. A wrong weight is a wrong template.
//   * fee is read out of the rct base, not out of any field a sender supplies.
//   * blob_size is the cheap one and is here precisely because it is cheap: a
//     weight that agrees while the size does not would mean the two sides are
//     measuring different bytes under the same id, which is the one failure the
//     id-as-key argument above cannot see by itself.
//
// Both weight and fee are SENTINELS: they are what the assembler selects and
// pays on, so a single disagreement is not a sample to be averaged away, it is
// a reason to stop trusting the pool.
//
// pool_size / peers / evidence are MEASUREMENTS. The set differences do not
// appear here at all; they belong to the set comparison that produced the
// sample, not to the transaction.
inline constexpr FieldSpec POOL_FIELDS[] = {
    {"tx_id",     Regime::AlignmentKey, false, false},
    {"weight",    Regime::Equality,     true,  true },
    {"fee",       Regime::Equality,     true,  true },
    {"blob_size", Regime::Equality,     true,  false},
    {"peers",     Regime::Measurement,  false, false},
    {"evidence",  Regime::Measurement,  false, false},
};

inline constexpr SeamSpec TIP_SEAM{ProbeKind::Tip, TIP_FIELDS,
                                   sizeof(TIP_FIELDS) / sizeof(TIP_FIELDS[0])};
inline constexpr SeamSpec TEMPLATE_SEAM{ProbeKind::Template, TEMPLATE_FIELDS,
                                        sizeof(TEMPLATE_FIELDS) / sizeof(TEMPLATE_FIELDS[0])};
inline constexpr SeamSpec SUBMIT_SEAM{ProbeKind::Submit, SUBMIT_FIELDS,
                                      sizeof(SUBMIT_FIELDS) / sizeof(SUBMIT_FIELDS[0])};
inline constexpr SeamSpec POOL_SEAM{ProbeKind::Pool, POOL_FIELDS,
                                    sizeof(POOL_FIELDS) / sizeof(POOL_FIELDS[0])};

inline const SeamSpec& seam_spec(ProbeKind k) {
    switch (k) {
        case ProbeKind::Tip:      return TIP_SEAM;
        case ProbeKind::Template: return TEMPLATE_SEAM;
        case ProbeKind::Submit:   return SUBMIT_SEAM;
        case ProbeKind::Pool:     return POOL_SEAM;
    }
    return TIP_SEAM;
}

// ---------------------------------------------------------------------------
// SeamResult -- a ParitySample plus the arithmetic that produced it.
//
// The counters are the point. `equality_compared` is how many required EQUALITY
// fields actually got compared; `equality_absent` is how many were owed and not
// answered. A CLEAN verdict with equality_compared < required is not reachable
// by construction (see the comparator), and the ledger records the counters so
// that the claim survives into the verdict report.
// ---------------------------------------------------------------------------
struct SeamResult {
    ParitySample sample;

    std::size_t equality_required = 0;
    std::size_t equality_compared = 0;
    std::size_t equality_equal    = 0;
    std::size_t equality_differed = 0;
    std::size_t equality_absent   = 0;

    std::size_t invariants_checked = 0;
    std::size_t invariants_failed  = 0;
    std::size_t constraints_checked = 0;
    std::size_t constraints_failed  = 0;

    // Names of the required fields nobody answered; carried so the report can
    // say WHICH comparison went missing rather than only that one did.
    std::vector<std::string> absent_required;

    // Set when a sentinel field differed: the ledger revokes on this, it does
    // not merely count it.
    bool        sentinel_tripped = false;
    std::string sentinel_why;

    bool clean() const noexcept { return sample.verdict == ParityVerdict::Clean; }
    bool judged() const noexcept { return sample.verdict != ParityVerdict::Void; }
};

// ---------------------------------------------------------------------------
// Height classification. `Steady` is the default and is always present, so a
// sample is never classless -- a sample with no class would be invisible to
// every per-class coverage requirement, which is the same blindness in a
// different disguise.
// ---------------------------------------------------------------------------
struct ClassifierInputs {
    std::uint64_t height          = 0;
    std::uint64_t epoch_blocks    = 2048;  // RandomX seed epoch
    std::uint64_t epoch_lag       = 64;    // rx_seedheight lag
    bool          after_reorg     = false;
    bool          hardfork_edge   = false; // major_version changed at this height
    std::uint64_t block_weight    = 0;
    std::uint64_t effective_median = 0;    // 0 = unknown, no PenaltyZone claim
};

inline std::vector<HeightClass> classify(const ClassifierInputs& in) {
    std::vector<HeightClass> out;
    out.push_back(HeightClass::Steady);

    if (in.epoch_blocks != 0) {
        const std::uint64_t into = in.height % in.epoch_blocks;
        // Within the lag on either side of a boundary: the seed for the block
        // being mined is about to change, or just did.
        if (into <= in.epoch_lag || into >= in.epoch_blocks - in.epoch_lag)
            out.push_back(HeightClass::EpochEdge);
    }
    if (in.after_reorg)   out.push_back(HeightClass::Reorg);
    if (in.hardfork_edge) out.push_back(HeightClass::HardForkEdge);
    if (in.effective_median != 0 && in.block_weight > in.effective_median)
        out.push_back(HeightClass::PenaltyZone);
    return out;
}

inline bool has_class(const std::vector<HeightClass>& v, HeightClass c) {
    for (HeightClass x : v) if (x == c) return true;
    return false;
}

} // namespace c2pool::xmr::native::parity
