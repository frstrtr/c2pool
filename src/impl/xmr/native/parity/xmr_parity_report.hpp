// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_report.hpp
//
// C6, the output: the per-seam diff report and the parity verdict.
//
// Two audiences, two shapes. The LINES are for the log: one per sample, prefixed
// [XMR-PARITY], with the diffs inline, so a divergence is greppable at the
// moment it happens. The VERDICT is for the operator deciding whether monerod
// may be demoted: three seams, their counters, the per-field coverage table and,
// when the answer is no, the explicit list of what is still missing.
//
// The per-field coverage table is the part worth keeping honest. "TIP: 2200
// samples, 2200 clean" tells you nothing about whether cumulative_difficulty was
// ever among the things compared. The table says, per field, how many times it
// was compared, how many times it agreed, and how many times nobody answered --
// and a field with `compared 0` is printed as a BLOCKER, not as a blank.
//
// SCOPE FENCE: src/impl/xmr/ only.
// ---------------------------------------------------------------------------
#pragma once

#include <sstream>
#include <string>
#include <vector>

#include "impl/xmr/native/parity/xmr_parity_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_types.hpp"

namespace c2pool::xmr::native::parity {

inline std::string classes_string(const std::vector<HeightClass>& v) {
    std::string s;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) s.push_back('+');
        s += to_string(v[i]);
    }
    return s.empty() ? std::string("-") : s;
}

// One log line per sample, plus one indented line per differing field.
inline std::string render_sample(const SeamResult& r) {
    std::ostringstream o;
    o << "[XMR-PARITY] seam=" << to_string(r.sample.kind)
      << " h=" << r.sample.height
      << " verdict=" << to_string(r.sample.verdict)
      << " classes=" << classes_string(r.sample.classes)
      << " compared=" << r.equality_compared << "/" << r.equality_required;
    if (r.equality_absent)  o << " absent=" << r.equality_absent;
    if (r.equality_differed) o << " differed=" << r.equality_differed;
    if (!r.sample.note.empty()) o << " note=\"" << r.sample.note << "\"";
    o << "\n";
    for (const FieldDiff& d : r.sample.fields) {
        o << "             " << d.field
          << " served=" << d.served << " shadow=" << d.shadow << "\n";
    }
    if (r.sentinel_tripped)
        o << "             SENTINEL " << r.sentinel_why << "\n";
    return o.str();
}

// The unconditional heartbeat. A probe that produced nothing has to be as loud
// as one that produced a diff, or a dead probe reads as a quiet one.
inline std::string heartbeat_line(const GraduationLedger& led,
                                  std::uint64_t attempts,
                                  std::uint64_t interval_s) {
    const ParityCoverage c = led.coverage();
    std::ostringstream o;
    o << "[XMR-PARITY] HEARTBEAT status="
      << (c.samples == 0 ? "NO-SAMPLES" : "SAMPLING")
      << " attempts=" << attempts
      << " samples=" << c.samples
      << " clean=" << c.clean
      << " fail=" << c.fail
      << " served_mismatch=" << c.served_mismatch
      << " void=" << c.voided
      << " no_sample_streak=" << c.no_samples_streak
      << " state=" << to_string(led.state())
      << " window_s=" << interval_s;
    return o.str();
}

namespace detail {

inline void seam_row(std::ostringstream& o, const GraduationLedger& led, ProbeKind k) {
    const SeamCounters&    s    = led.seam(k);
    const SeamRequirement& need = led.policy().for_seam(k);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f%%", s.void_rate() * 100.0);
    o << "  " << to_string(k)
      << "  judged=" << s.samples << "/" << need.min_samples
      << "  clean=" << s.clean
      << "  fail=" << s.fail
      << "  served_mismatch=" << s.served_mismatch
      << "  void=" << s.voided << " (" << buf << ")"
      << "  streak=" << s.clean_streak << "/" << need.min_clean_streak
      << "  best=" << s.best_clean_streak << "\n";
}

} // namespace detail

// The full parity verdict.
inline std::string render_verdict(const GraduationLedger& led, std::uint64_t unix_now = 0) {
    std::ostringstream o;
    const GraduationKey& k = led.key();

    o << "================ XMR NATIVE PARITY VERDICT ================\n";
    o << "key         : " << key_string(k) << "\n";
    o << "state       : " << to_string(led.state()) << "\n";
    o << "window      : first=" << led.first_sample_unix()
      << " last=" << led.last_sample_unix()
      << " span_s=" << ((led.first_sample_unix() && led.last_sample_unix() > led.first_sample_unix())
                        ? (led.last_sample_unix() - led.first_sample_unix()) : 0)
      << " need=" << led.policy().min_window_seconds << "\n";
    o << "\n-- seams --\n";
    detail::seam_row(o, led, ProbeKind::Tip);
    detail::seam_row(o, led, ProbeKind::Template);
    detail::seam_row(o, led, ProbeKind::Submit);

    o << "\n-- required field coverage (need "
      << led.policy().min_field_comparisons << " comparison(s) each) --\n";
    for (const std::string& name : GraduationLedger::required_field_names()) {
        auto it = led.fields().find(name);
        const FieldCounters fc = (it == led.fields().end()) ? FieldCounters{} : it->second;
        o << "  " << name;
        for (std::size_t i = name.size(); i < 26; ++i) o << ' ';
        o << " compared=" << fc.compared
          << "  equal=" << fc.equal
          << "  differed=" << fc.differed
          << "  absent=" << fc.absent;
        if (fc.compared == 0)
            o << "   <== BLOCKER: never compared, so nothing here is evidence about it";
        else if (fc.compared < led.policy().min_field_comparisons)
            o << "   <== under the floor";
        o << "\n";
    }

    o << "\n-- height classes --\n";
    for (const auto& kv : led.classes()) {
        o << "  " << to_string(static_cast<HeightClass>(kv.first))
          << "  samples=" << kv.second.samples
          << "  clean=" << kv.second.clean
          << "  fail=" << kv.second.fail
          << "  void=" << kv.second.voided << "\n";
    }

    if (!led.revocations().empty()) {
        o << "\n-- revocations --\n";
        for (const auto& r : led.revocations())
            o << "  unix=" << r.first << "  " << r.second << "\n";
    }

    const std::vector<std::string> missing = led.shortfalls(unix_now);
    o << "\n-- gate --\n";
    if (missing.empty()) {
        o << "  GRADUATED: all three seams green over the required window.\n"
             "  monerod may be demoted to optional for THIS key only; any sentinel revokes it.\n";
    } else {
        o << "  NOT GRADUATED. monerod stays required. Outstanding:\n";
        for (const std::string& m : missing) o << "    * " << m << "\n";
    }
    o << "===========================================================\n";
    return o.str();
}

} // namespace c2pool::xmr::native::parity
