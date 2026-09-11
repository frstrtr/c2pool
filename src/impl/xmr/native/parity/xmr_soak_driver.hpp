// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_soak_driver.hpp
//
// M4, the harness: the thing that RUNS the soak, as opposed to the thing that
// records it.
//
// C6 built the judge (compare_seam), the intake (ArmObservation), and the C6
// ledger. What nothing built is the loop around them -- and the loop is where
// the M4 claim is either earned or quietly not made:
//
//   * SOMETHING HAS TO DRIVE P-TPL. on_tip fires by itself, because the chain
//     index publishes a tip event at every height. on_serve does not: it is
//     called by whoever serves a template, and in the node harness nobody did.
//     A soak that only followed tips would run up a long streak having never
//     once compared a template -- and "P-TPL CLEAN on every sample" is half of
//     what M4 says. So the driver PULLS a template from the configured serving
//     arm on its own cadence and hands it to the oracle as the served artefact.
//     That is also why the threshold set carries min_template_clean: the cheap
//     seam must not be allowed to carry the expensive one.
//
//   * THE POSTURE HAS TO BE EXACT. ArmResolver::serving() falls back to the
//     other arm when the configured one is not ready, which is the correct
//     production behaviour and is fatal to a parity claim: a leg that silently
//     served monerod for an hour is not evidence about the native arm. So the
//     driver resolves the posture's arm STRICTLY -- arm(posture), no fallback --
//     and an unready arm produces no sample, which the ledger counts as a
//     no-sample drain rather than as calm.
//
//   * AND SOMETHING HAS TO BE ABLE TO REFUSE. A soak harness that has never
//     been seen to say no is not a gate. TipFaultInjection below is the
//     negative control: a decorator around the native arm's tip observer that
//     perturbs ONE required EQUALITY field by ONE UNIT, on demand, after a
//     chosen number of samples. It is the same mutation xmr_native_parity_kat
//     already pins offline ("perturb each required field, it must FAIL"), but
//     applied LIVE, through the real observer, the real comparator and the real
//     ledger, so that "the streak resets and graduation is refused" is a thing
//     the harness was watched doing rather than a thing the code says it does.
//     It is DISARMED unless a flag names a field, it lives in the harness path
//     only, and it stamps every perturbed sample's note so a transcript can
//     never be mistaken for an honest one.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/parity/xmr_graduation_ledger.hpp"
#include "impl/xmr/native/parity/xmr_tip_observer.hpp"
#include "impl/xmr/native/parity/xmr_parity_types.hpp"

namespace c2pool::xmr::native::parity {

// ---------------------------------------------------------------------------
// One line of the soak transcript: a verdict WITH the context that makes it
// readable six hours later. A bare verdict stream is unfalsifiable.
// ---------------------------------------------------------------------------
struct SoakEntry {
    SoakPosture   posture = SoakPosture::ServeMonerodShadowNative;
    ProbeKind     seam    = ProbeKind::Tip;
    ParityVerdict verdict = ParityVerdict::Void;
    std::uint64_t height  = 0;
    // Named at_unix rather than `unix`: GCC defines `unix` as a macro outside
    // strict-ANSI mode, and CMake's cxx_std_20 asks for gnu++20 by default.
    std::uint64_t at_unix = 0;
    std::uint64_t clean_run_after = 0;   // the streak this sample left behind
    std::size_t   field_diffs = 0;
    std::string   note;
    std::string   first_diff;            // "field served=X shadow=Y", or empty

    std::string render() const {
        std::ostringstream o;
        o << "[M4-SOAK] " << posture_tag(posture)
          << " seam=" << to_string(seam)
          << " h=" << height
          << " verdict=" << to_string(verdict)
          << " streak=" << clean_run_after
          << " unix=" << at_unix;
        if (field_diffs) o << " diffs=" << field_diffs;
        if (!first_diff.empty()) o << " [" << first_diff << "]";
        if (!note.empty()) o << " note=\"" << note << "\"";
        return o.str();
    }
};

// ---------------------------------------------------------------------------
// SoakDriver
//
// Owns nothing it did not create: the oracle, the arms and the node stay the
// caller's. It is given batches of SeamResults (whatever ParityOracle::drain()
// produced) and turns them into ledger movement, a transcript and a verdict.
// ---------------------------------------------------------------------------
class SoakDriver {
public:
    struct Config {
        SoakPosture   posture = SoakPosture::ServeMonerodShadowNative;
        std::string   ledger_path;
        // Persist after this many recorded samples. 0 = only on demand.
        std::uint64_t autosave_every = 16;
        // How much transcript to keep in memory. The interesting part of a soak
        // is always the tail plus the failures, and both are kept: failures are
        // held in their own list so a long clean run cannot push them out.
        std::size_t   transcript_cap = 256;
        std::size_t   failure_cap    = 64;
    };

    SoakDriver(M4GraduationLedger& ledger, Config cfg)
        : ledger_(ledger), cfg_(std::move(cfg)) {}

    const Config&            config() const noexcept { return cfg_; }
    SoakPosture              posture() const noexcept { return cfg_.posture; }
    const M4GraduationLedger& ledger() const noexcept { return ledger_; }

    const std::deque<SoakEntry>&  transcript() const noexcept { return tail_; }
    const std::vector<SoakEntry>& failures()   const noexcept { return failures_; }
    std::uint64_t recorded() const noexcept { return recorded_; }
    std::uint64_t drains()   const noexcept { return drains_; }

    // One drain's worth of samples. `unix_now` is the caller's clock: the whole
    // component is clock-free so a KAT can drive 72 hours in microseconds.
    //
    // Returns the lines it produced, so a tool can print them without the
    // driver owning a log sink.
    std::vector<std::string> ingest(const std::vector<SeamResult>& batch,
                                    std::uint64_t unix_now) {
        std::vector<std::string> lines;
        ++drains_;
        if (batch.empty()) {
            ledger_.note_no_sample(cfg_.posture);
            return lines;
        }
        for (const SeamResult& r : batch) {
            // P-POOL is M1's seam and has its own tally; it is not part of the
            // M4 two-posture criterion and must not silently pad a streak.
            if (r.sample.kind == ProbeKind::Pool) continue;
            ledger_.record(cfg_.posture, r, unix_now);
            ++recorded_;

            SoakEntry e;
            e.posture = cfg_.posture;
            e.seam    = r.sample.kind;
            e.verdict = r.sample.verdict;
            e.height  = r.sample.height;
            e.at_unix = unix_now;
            e.clean_run_after = ledger_.leg(cfg_.posture).clean_run;
            e.field_diffs     = r.sample.fields.size();
            e.note            = r.sample.note;
            if (!r.sample.fields.empty()) {
                const FieldDiff& d = r.sample.fields.front();
                e.first_diff = d.field + " served=" + d.served + " shadow=" + d.shadow;
            }
            lines.push_back(e.render());
            if (r.sample.verdict == ParityVerdict::Fail ||
                r.sample.verdict == ParityVerdict::ServedMismatch) {
                if (failures_.size() < cfg_.failure_cap) failures_.push_back(e);
            }
            tail_.push_back(std::move(e));
            while (tail_.size() > cfg_.transcript_cap) tail_.pop_front();
        }
        if (cfg_.autosave_every && recorded_ % cfg_.autosave_every == 0) save();
        return lines;
    }

    bool save(std::string* why = nullptr) {
        if (cfg_.ledger_path.empty()) { if (why) *why = "no ledger path"; return false; }
        return ledger_.save(cfg_.ledger_path, why);
    }

    // One line a script can grep, and it says the WHOLE truth: the state, the
    // posture that was actually run, and a shortfall when there is one.
    //
    // The shortfall shown is THIS POSTURE'S wherever one exists. The other
    // leg's is a fact about a run that has not happened yet, and printing it
    // beside this run's numbers reads as a comment on them -- which is how a
    // reader ends up looking for the wrong failure.
    std::string verdict_line() const {
        const PostureLeg& L = ledger_.leg(cfg_.posture);
        const std::vector<std::string> all = ledger_.shortfalls();
        const std::string mine = std::string(posture_tag(cfg_.posture)) + ":";
        std::vector<std::string> sf;
        for (const std::string& s : all)
            if (s.compare(0, mine.size(), mine) == 0) sf.push_back(s);
        if (sf.empty()) sf = all;
        std::ostringstream o;
        o << "M4-VERDICT: " << (ledger_.graduated() ? "GRADUATED" : "NOT-GRADUATED")
          << " posture=" << posture_tag(cfg_.posture)
          << " state=" << to_string(ledger_.state())
          << " streak=" << L.clean_run
          << " blocks=" << L.run_blocks
          << " span=" << L.run_seconds() << "s"
          << " tip=" << L.run_tip_clean
          << " tpl=" << L.run_tmpl_clean
          << " clean=" << L.clean
          << " fail=" << L.fail
          << " mismatch=" << L.served_mismatch
          << " void=" << L.voided
          << " resets=" << L.resets
          << " qualified=" << (L.qualified ? 1 : 0)
          << " legs_qualified="
          << ((ledger_.leg(SoakPosture::ServeMonerodShadowNative).qualified ? 1 : 0)
            + (ledger_.leg(SoakPosture::ServeNativeShadowMonerod).qualified ? 1 : 0))
          << "/2";
        if (!sf.empty()) o << " shortfall=\"" << sf.front() << "\"";
        return o.str();
    }

private:
    M4GraduationLedger&    ledger_;
    Config                 cfg_;
    std::deque<SoakEntry>  tail_;
    std::vector<SoakEntry> failures_;
    std::uint64_t          recorded_ = 0;
    std::uint64_t          drains_   = 0;
};

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROL.
//
// A fault injector for the native arm's tip observation. It is HARNESS-ONLY and
// exists for one reason: to make the refusal path something that was observed
// rather than something that is asserted. Disarmed unless `field` is set.
//
// It perturbs by ONE UNIT (numeric fields) or by flipping the last nibble (hex
// ids), which is the smallest change that can possibly be wrong -- a large
// perturbation would also be caught by a sloppier judge and would prove less.
//
// `absent` is the OTHER half of the same control: instead of a wrong value, the
// field simply stops being answered. A comparator that skipped an unanswered
// required field would read CLEAN on that, which is the exact vacuity C6 was
// built against, so the harness can drive it live too.
// ---------------------------------------------------------------------------
struct TipFaultInjection {
    std::string   field;              // "" = disarmed
    std::uint64_t after_samples = 0;  // arm only after this many observations
    std::uint64_t for_samples   = 0;  // 0 = forever once armed
    bool          absent        = false;  // remove the field instead of perturbing it

    bool armed() const noexcept { return !field.empty(); }
};

class PerturbingTipObserver final : public ITipObserver {
public:
    PerturbingTipObserver(ITipObserver& inner, TipFaultInjection fault)
        : inner_(inner), fault_(std::move(fault)) {}

    ArmObservation observe() override {
        ArmObservation o = inner_.observe();
        if (!fault_.armed() || !o.have) return o;
        ++seen_;
        if (seen_ <= fault_.after_samples) return o;
        if (fault_.for_samples != 0 && seen_ > fault_.after_samples + fault_.for_samples)
            return o;

        const Obs& cur = o.fields.get(fault_.field.c_str());
        if (!cur.present) return o;      // nothing to perturb; say so by doing nothing

        ++injected_;
        if (fault_.absent) {
            o.fields.set(fault_.field.c_str(), Obs::absent());
            o.why = "HARNESS FAULT INJECTION: field '" + fault_.field + "' withheld";
            return o;
        }
        o.fields.set(fault_.field.c_str(), Obs::text(perturb(cur.value)));
        o.why = "HARNESS FAULT INJECTION: field '" + fault_.field + "' perturbed by one unit";
        return o;
    }

    std::uint64_t observations() const noexcept { return seen_; }
    std::uint64_t injected()     const noexcept { return injected_; }

    // "12345" -> "12346";  "10:5" -> "10:6";  a 64-char hex id -> last nibble
    // flipped; anything else gets a suffix, which still differs and still fails.
    static std::string perturb(const std::string& v) {
        if (v.empty()) return "1";
        const bool hex_id = v.size() == 64 &&
            v.find_first_not_of("0123456789abcdef") == std::string::npos;
        if (hex_id) {
            std::string out = v;
            out.back() = (out.back() == '0') ? '1' : '0';
            return out;
        }
        // Decimal, or the "hi:lo" u128 rendering: bump the last run of digits.
        std::size_t end = v.size();
        while (end > 0 && (v[end - 1] < '0' || v[end - 1] > '9')) --end;
        if (end == 0) return v + "-perturbed";
        std::size_t begin = end;
        while (begin > 0 && v[begin - 1] >= '0' && v[begin - 1] <= '9') --begin;
        const std::string digits = v.substr(begin, end - begin);
        // Increment the decimal string in place; no 64-bit parse, so a 128-bit
        // rendering perturbs correctly too.
        std::string bumped = digits;
        int i = static_cast<int>(bumped.size()) - 1;
        for (; i >= 0; --i) {
            if (bumped[static_cast<std::size_t>(i)] != '9') {
                ++bumped[static_cast<std::size_t>(i)];
                break;
            }
            bumped[static_cast<std::size_t>(i)] = '0';
        }
        if (i < 0) bumped.insert(bumped.begin(), '1');
        return v.substr(0, begin) + bumped + v.substr(end);
    }

private:
    ITipObserver&     inner_;
    TipFaultInjection fault_;
    std::uint64_t     seen_     = 0;
    std::uint64_t     injected_ = 0;
};

} // namespace c2pool::xmr::native::parity
