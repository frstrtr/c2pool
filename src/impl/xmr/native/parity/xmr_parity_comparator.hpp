// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_comparator.hpp
//
// C6, the judge: the frozen determinism table applied to two arms' answers.
//
// THE NON-VACUITY RULE, stated once and enforced structurally below:
//
//     A sample reaches CLEAN only if every REQUIRED EQUALITY field in its seam
//     was answered by BOTH arms and every one of them matched.
//
// Everything else is a consequence:
//
//   * an arm that produced no answer      -> VOID (nothing to judge)
//   * arms aligned on different blocks    -> VOID (different questions)
//   * a seam with no required comparison  -> VOID ("agreement" over an empty
//                                            set is not agreement)
//   * an arm that ANSWERED but left a required field empty -> FAIL. This is the
//     case the rule exists for. The arm was asked and replied; a field it owed
//     and did not produce is a real divergence in what the two sides can say,
//     not a transport hiccup -- a transport hiccup yields no answer at all and
//     lands in the VOID branch above.
//
// And VOID is never counted as agreement anywhere: it has its own counter, the
// graduation policy caps the VOID RATE, and per-field coverage requires each
// required field to have been genuinely compared a minimum number of times. A
// field that is never comparable therefore blocks graduation instead of being
// invisible to it.
//
// SCOPE FENCE: src/impl/xmr/ only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/relay.hpp"
#include "impl/xmr/native/parity/xmr_parity_types.hpp"

namespace c2pool::xmr::native::parity {

// A single-sided check the caller already evaluated: an INVARIANT recomputed
// over the sample (exact-sum reward), or a CONSTRAINT (template timestamp
// inside its window). Both are ours to get right, so a violation FAILS the
// sample even when the two arms agree with each other.
struct NamedCheck {
    std::string name;
    bool        ok = false;
    std::string detail;
};

struct CompareOptions {
    ClassifierInputs classes;

    // Template seam only. `served` (the first argument to compare_seam) is the
    // ARTEFACT -- exactly what went out to the miners, carried through on_serve
    // rather than re-read, because a re-read differs from what was served
    // whenever the backlog moved in between and would make SERVED-MISMATCH
    // unprovable.
    //
    // This is the SERVING ARM'S OWN ANSWER, supplied only while that arm's epoch
    // has not moved. A difference between the two is SERVED-MISMATCH: we served
    // something the arm that was supposed to have produced it would not have
    // produced. It outranks FAIL because it is worse -- a FAIL means the two
    // arms disagree, this means our own output matches neither.
    const ArmObservation* serving_arm_cross_check = nullptr;

    std::vector<NamedCheck> invariants;
    std::vector<NamedCheck> constraints;

    // Free-form, appears in the sample note. Provenance for a captured run.
    std::string context;
};

namespace detail {

inline void push_diff(SeamResult& r, const char* field, const Obs& served, const Obs& shadow) {
    FieldDiff d;
    d.field  = field;
    d.served = served.render();
    d.shadow = shadow.render();
    r.sample.fields.push_back(std::move(d));
}

inline SeamResult void_sample(ProbeKind kind, const ArmObservation& served,
                              std::string why, const std::vector<HeightClass>& cls) {
    SeamResult r;
    r.sample.kind    = kind;
    r.sample.height  = served.height;
    r.sample.prev_id = served.prev_id;
    r.sample.verdict = ParityVerdict::Void;
    r.sample.classes = cls;
    r.sample.note    = std::move(why);
    return r;
}

} // namespace detail

// ---------------------------------------------------------------------------
// compare_seam -- P-TIP and P-TPL.
// ---------------------------------------------------------------------------
inline SeamResult compare_seam(const SeamSpec&        spec,
                               const ArmObservation&  served,
                               const ArmObservation&  shadow,
                               const CompareOptions&  opt = {}) {
    const std::vector<HeightClass> cls = classify(opt.classes);

    // (1) Did both arms answer at all?
    if (!served.have) {
        return detail::void_sample(spec.kind, served,
            "no observation from serving arm '" + served.arm + "'"
                + (served.why.empty() ? std::string() : (": " + served.why)), cls);
    }
    if (!shadow.have) {
        return detail::void_sample(spec.kind, served,
            "no observation from shadow arm '" + shadow.arm + "'"
                + (shadow.why.empty() ? std::string() : (": " + shadow.why)), cls);
    }

    SeamResult r;
    r.sample.kind    = spec.kind;
    r.sample.height  = served.height;
    r.sample.prev_id = served.prev_id;
    r.sample.classes = cls;
    r.equality_required = spec.required_equality_count();

    // (2) A seam that requires no comparison cannot produce agreement. This is
    // the structural guard: it makes "the table was emptied" a VOID rather than
    // a silent stream of CLEANs.
    if (r.equality_required == 0) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note    = "seam has no required EQUALITY field; refusing to call that agreement";
        return r;
    }

    // (3) Alignment. Different tips are different questions, not a failure.
    if (served.height != shadow.height) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note    = "alignment: height " + Obs::u64(served.height).value
                         + " vs " + Obs::u64(shadow.height).value;
        detail::push_diff(r, "height", Obs::u64(served.height), Obs::u64(shadow.height));
        return r;
    }
    if (served.prev_id != shadow.prev_id) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note    = "alignment: prev_id differs (arms are on different tips)";
        detail::push_diff(r, "prev_id_key", Obs::id(served.prev_id), Obs::id(shadow.prev_id));
        return r;
    }
    for (std::size_t i = 0; i < spec.count; ++i) {
        const FieldSpec& f = spec.fields[i];
        if (f.regime != Regime::AlignmentKey) continue;
        const Obs& a = served.fields.get(f.name);
        const Obs& b = shadow.fields.get(f.name);
        if (is_absent(a) && is_absent(b)) continue;          // neither side keys on it
        if (!same_value(a, b)) {
            r.sample.verdict = ParityVerdict::Void;
            r.sample.note    = std::string("alignment: ") + f.name + " does not match";
            detail::push_diff(r, f.name, a, b);
            return r;
        }
    }

    // (4) The EQUALITY sweep.
    for (std::size_t i = 0; i < spec.count; ++i) {
        const FieldSpec& f = spec.fields[i];
        if (f.regime == Regime::Measurement || f.regime == Regime::NotComparable) {
            // Recorded when both sides differ, so a coverage delta is visible
            // in the report -- and never scored.
            const Obs& a = served.fields.get(f.name);
            const Obs& b = shadow.fields.get(f.name);
            if ((a.present || b.present) && !same_value(a, b))
                detail::push_diff(r, f.name, a, b);
            continue;
        }
        if (f.regime != Regime::Equality) continue;

        const Obs& a = served.fields.get(f.name);
        const Obs& b = shadow.fields.get(f.name);

        if (is_absent(a) || is_absent(b)) {
            if (!f.required) continue;                 // optional: a real hole, not a gate
            ++r.equality_absent;
            r.absent_required.push_back(f.name);
            detail::push_diff(r, f.name, a, b);
            if (f.sentinel) {
                r.sentinel_tripped = true;
                r.sentinel_why = std::string("sentinel field '") + f.name + "' was not answered";
            }
            continue;
        }

        ++r.equality_compared;
        if (a.value == b.value) {
            ++r.equality_equal;
        } else {
            ++r.equality_differed;
            detail::push_diff(r, f.name, a, b);
            if (f.sentinel) {
                r.sentinel_tripped = true;
                r.sentinel_why = std::string("sentinel field '") + f.name + "' differed: "
                               + a.value + " vs " + b.value;
            }
        }
    }

    // (5) INVARIANTs and CONSTRAINTs -- our own arithmetic, judged on its own.
    for (const NamedCheck& c : opt.invariants) {
        ++r.invariants_checked;
        if (!c.ok) {
            ++r.invariants_failed;
            FieldDiff d;
            d.field  = c.name;
            d.served = c.detail.empty() ? std::string("violated") : c.detail;
            d.shadow = "INVARIANT";
            r.sample.fields.push_back(std::move(d));
        }
    }
    for (const NamedCheck& c : opt.constraints) {
        ++r.constraints_checked;
        if (!c.ok) {
            ++r.constraints_failed;
            FieldDiff d;
            d.field  = c.name;
            d.served = c.detail.empty() ? std::string("out of bounds") : c.detail;
            d.shadow = "CONSTRAINT";
            r.sample.fields.push_back(std::move(d));
        }
    }

    // (6) SERVED-MISMATCH: did what we actually served match the arm that was
    // supposed to have produced it? Checked before FAIL because it outranks it.
    if (opt.serving_arm_cross_check != nullptr && opt.serving_arm_cross_check->have) {
        const ArmObservation& arm = *opt.serving_arm_cross_check;
        bool mismatch = false;
        if (arm.height != served.height || arm.prev_id != served.prev_id) {
            mismatch = true;
            detail::push_diff(r, "cross_check.height", Obs::u64(served.height), Obs::u64(arm.height));
        } else {
            for (std::size_t i = 0; i < spec.count; ++i) {
                const FieldSpec& f = spec.fields[i];
                if (f.regime != Regime::Equality || !f.required) continue;
                const Obs& out = served.fields.get(f.name);   // what went out
                const Obs& own = arm.fields.get(f.name);      // what the arm says
                if (is_absent(out) || is_absent(own) || out.value != own.value) {
                    mismatch = true;
                    const std::string label = std::string("cross_check.") + f.name;
                    detail::push_diff(r, label.c_str(), out, own);
                }
            }
        }
        if (mismatch) {
            r.sample.verdict = ParityVerdict::ServedMismatch;
            r.sample.note = "what was SERVED does not match the arm that produced it"
                            + (opt.context.empty() ? std::string() : (" [" + opt.context + "]"));
            return r;
        }
    }

    // (7) The verdict.
    const bool any_fail = r.equality_differed > 0 || r.equality_absent > 0
                       || r.invariants_failed > 0 || r.constraints_failed > 0;
    if (any_fail) {
        r.sample.verdict = ParityVerdict::Fail;
        std::string note;
        if (r.equality_differed)  note += Obs::u64(r.equality_differed).value + " field(s) differed; ";
        if (r.equality_absent) {
            note += Obs::u64(r.equality_absent).value + " required field(s) not answered (";
            for (std::size_t i = 0; i < r.absent_required.size(); ++i) {
                if (i) note += ",";
                note += r.absent_required[i];
            }
            note += "); ";
        }
        if (r.invariants_failed)  note += Obs::u64(r.invariants_failed).value + " invariant(s) violated; ";
        if (r.constraints_failed) note += Obs::u64(r.constraints_failed).value + " constraint(s) violated; ";
        if (!opt.context.empty()) note += "[" + opt.context + "]";
        r.sample.note = std::move(note);
        return r;
    }

    // (8) Belt and braces. Nothing above can reach here with an incomplete
    // sweep -- an absent required field FAILS -- but the invariant that CLEAN
    // implies a complete comparison is the whole point of this component, so it
    // is asserted here rather than left to be re-derived by a reader.
    if (r.equality_compared < r.equality_required) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note = "incomplete comparison: " + Obs::u64(r.equality_compared).value
                      + " of " + Obs::u64(r.equality_required).value
                      + " required fields compared; NOT scored as agreement";
        return r;
    }

    r.sample.verdict = ParityVerdict::Clean;
    r.sample.note = Obs::u64(r.equality_compared).value + " field(s) equal"
                  + (opt.context.empty() ? std::string() : (" [" + opt.context + "]"));
    return r;
}

// ---------------------------------------------------------------------------
// P-SUB.
//
// Monero gives a pool no template-proposal call and no per-reason submit_block
// answer, so "was our block accepted?" has exactly two independent oracles:
//
//   ARM B  the daemon's own submit_block verdict;
//   CHAIN  the block turning up on OUR OWN verified chain at that height, with
//          that id -- which is the network's verdict, not ours.
//
// Only ARMED oracles are required. A P2P-only configuration has no daemon and
// must still be judgeable; a node with no confirmation watch must still be
// judgeable from the daemon. What is NOT allowed is zero oracles: relaying a
// block to N peers is not evidence that anybody accepted it, so a verdict with
// no acceptance oracle is VOID, never CLEAN.
//
// Per-field coverage in the ledger is what stops a demotion decision resting on
// one oracle: graduation requires both `daemon_accepted` and
// `confirmed_on_chain` to have been genuinely compared, whatever any single
// sample could see.
// ---------------------------------------------------------------------------
struct SubmitEvidence {
    // Is a confirmation watch running at all? (Not "did it confirm yet".)
    bool          confirmation_watch_armed = false;
    bool          confirmed                = false;
    std::uint64_t confirm_height           = 0;
    Hash          confirmed_id{};   // the id that actually landed at that height

    // Plan section 3.5 sentinel: the daemon refused our block AND a different
    // block landed at the same height within 60 s. That distinguishes "our
    // block was structurally bad" from "we merely lost the race".
    bool          other_block_landed_within_60s = false;

    std::uint64_t height = 0;
};

inline SeamResult judge_submit(const BlockRelayVerdict& v,
                               const SubmitEvidence&    ev,
                               const CompareOptions&    opt = {}) {
    SeamResult r;
    r.sample.kind    = ProbeKind::Submit;
    r.sample.height  = ev.height;
    r.sample.classes = classify(opt.classes);

    ArmObservation ours;   // only used to render ids in diffs
    ours.height = ev.height;

    bool fail = false;
    std::string note;

    // --- the relay itself. A find that reached nobody is a lost block, and a
    // component that lets that pass silently is the thing the DASH
    // never-silent-drop rule exists to forbid.
    if (!v.reached_network()) {
        fail = true;
        note += "block reached no arm (" + (v.why.empty() ? std::string("no reason given") : v.why) + "); ";
        detail::push_diff(r, "reached_network", Obs::boolean(false), Obs::boolean(true));
    }

    // --- oracle 1: the daemon.
    if (v.daemon_armed) {
        ++r.equality_required;
        if (v.daemon_rejected) {
            ++r.equality_compared;
            ++r.equality_differed;
            fail = true;
            note += "daemon REJECTED the block; ";
            detail::push_diff(r, "daemon_accepted", Obs::boolean(false), Obs::boolean(true));
            if (ev.other_block_landed_within_60s) {
                r.sentinel_tripped = true;
                r.sentinel_why = "daemon rejected our block while a different block landed at the "
                                 "same height within 60 s: the block was bad, not merely raced";
            }
        } else if (v.daemon_accepted) {
            ++r.equality_compared;
            ++r.equality_equal;
        } else {
            ++r.equality_absent;
            r.absent_required.push_back("daemon_accepted");
            detail::push_diff(r, "daemon_accepted", Obs::absent(), Obs::boolean(true));
            note += "daemon arm was armed but never reported; ";
        }
    }

    // --- oracle 2: our own verified chain.
    if (ev.confirmation_watch_armed) {
        ++r.equality_required;
        if (!ev.confirmed) {
            ++r.equality_absent;
            r.absent_required.push_back("confirmed_on_chain");
            detail::push_diff(r, "confirmed_on_chain", Obs::absent(), Obs::boolean(true));
            note += "confirmation watch armed but the block has not confirmed; ";
        } else if (ev.confirmed_id != v.block_id) {
            ++r.equality_compared;
            ++r.equality_differed;
            fail = true;
            r.sentinel_tripped = true;
            r.sentinel_why = "a DIFFERENT block id confirmed at our height";
            note += "a different block confirmed at that height; ";
            detail::push_diff(r, "confirmed_on_chain", Obs::id(ev.confirmed_id), Obs::id(v.block_id));
        } else {
            ++r.equality_compared;
            ++r.equality_equal;
        }
    }

    // Measurement, never a gate.
    if (v.p2p_peers_sent > 0)
        r.sample.note = "p2p_peers_sent=" + Obs::u64(v.p2p_peers_sent).value + "; ";

    if (r.equality_required == 0) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note += "no acceptance oracle was armed: relaying to "
                       + Obs::u64(v.p2p_peers_sent).value
                       + " peer(s) is not evidence that anybody accepted the block";
        return r;
    }
    if (fail) {
        r.sample.verdict = ParityVerdict::Fail;
        r.sample.note += note;
        return r;
    }
    if (r.equality_compared < r.equality_required) {
        r.sample.verdict = ParityVerdict::Void;
        r.sample.note += "incomplete: " + Obs::u64(r.equality_compared).value + " of "
                       + Obs::u64(r.equality_required).value
                       + " armed acceptance oracle(s) reported; NOT scored as agreement";
        return r;
    }

    r.sample.prev_id = v.block_id;   // the submit seam keys on the block id
    r.sample.verdict = ParityVerdict::Clean;
    r.sample.note += Obs::u64(r.equality_compared).value + " acceptance oracle(s) agreed"
                   + (v.landed_first.empty() ? std::string() : (", landed_first=" + v.landed_first));
    return r;
}

} // namespace c2pool::xmr::native::parity
