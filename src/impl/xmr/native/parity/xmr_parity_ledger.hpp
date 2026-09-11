// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_ledger.hpp
//
// C6, the record: the revocable graduation ledger. This is the artefact the M4
// gate is read off, and the reason "monerod is optional now" is a fact about a
// file rather than a recollection about a soak.
//
// FOUR THINGS IT REFUSES TO DO, each one a way a parity claim has gone wrong
// before (the DASH embedded-oracle post-mortems are the source of all four):
//
//  1. It never inherits. The ledger is HARD-KEYED to
//     {c2pool_commit, comparator_version, monerod_version, net}. Change any of
//     the four and the streak starts at zero, because a streak earned by other
//     code against another daemon on another network is not evidence about this
//     one. A ledger loaded under a different key is discarded, loudly.
//
//  2. It never counts silence as success. VOID has its own counter, the policy
//     caps the void RATE, and -- the part that actually bites -- graduation
//     requires PER-FIELD coverage: every required EQUALITY field must have been
//     genuinely compared min_field_comparisons times. A field that is never
//     answered cannot be graduated over; it blocks.
//
//  3. It never graduates on one seam. All three seams (TIP, TEMPLATE, SUBMIT)
//     carry their own sample floor and clean-streak floor. Two green seams and
//     one that never fired is exactly the shape of a false pass.
//
//  4. It never graduates instantly. A sustained WINDOW is required, in wall
//     time, on top of the counts: a thousand samples in ten minutes is not a
//     day of agreement.
//
// GRADUATED is revocable at any moment by a single sentinel, and revocation is
// terminal for the key -- there is no path back except a new key (new commit,
// new comparator, new daemon, new net), which is the same statement as "the
// experiment has to be re-run".
//
// SCOPE FENCE: src/impl/xmr/ only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "impl/xmr/native/parity/xmr_parity_types.hpp"
#include "impl/xmr/node/minijson.hpp"

namespace c2pool::xmr::native::parity {

namespace mj = ::c2pool::xmr::node::minijson;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
struct SeamRequirement {
    std::uint64_t min_samples     = 0;   // judged (non-VOID) samples
    std::uint64_t min_clean_streak = 0;  // consecutive CLEAN, current streak
};

struct GraduationPolicy {
    SeamRequirement tip;
    SeamRequirement tmpl;
    SeamRequirement submit;

    // Every required EQUALITY field in every seam must have been compared this
    // many times. This is the anti-vacuity floor.
    std::uint64_t min_field_comparisons = 64;

    // VOID rate ceiling, over judged + void samples.
    double max_void_rate = 0.05;

    // Wall-clock span between the first and the most recent sample.
    std::uint64_t min_window_seconds = 72 * 3600;

    // Classes that must each have contributed at least
    // min_samples_per_required_class CLEAN samples.
    std::vector<HeightClass> required_classes{HeightClass::Steady, HeightClass::EpochEdge};
    std::uint64_t min_samples_per_required_class = 1;

    const SeamRequirement& for_seam(ProbeKind k) const {
        switch (k) {
            case ProbeKind::Tip:      return tip;
            case ProbeKind::Template: return tmpl;
            case ProbeKind::Submit:   return submit;
        }
        return tip;
    }

    // The M4 gate on stagenet: the numbers the plan's section 3.6 asks for.
    static GraduationPolicy stagenet_m4() {
        GraduationPolicy p;
        p.tip    = {2200, 720};
        p.tmpl   = {720,  240};
        p.submit = {3,    3};
        p.min_field_comparisons = 720;
        p.max_void_rate         = 0.05;
        p.min_window_seconds    = 72 * 3600;
        p.required_classes = {HeightClass::Steady, HeightClass::EpochEdge, HeightClass::Reorg};
        p.min_samples_per_required_class = 1;
        return p;
    }

    // The regtest / KAT shape: same STRUCTURE, small numbers. Deliberately not
    // "no requirements": a harness that graduates on nothing proves nothing.
    static GraduationPolicy regtest_fast() {
        GraduationPolicy p;
        p.tip    = {20, 10};
        p.tmpl   = {2,  2};
        p.submit = {1,  1};
        p.min_field_comparisons = 10;
        p.max_void_rate         = 0.20;
        p.min_window_seconds    = 60;
        p.required_classes = {HeightClass::Steady, HeightClass::EpochEdge};
        p.min_samples_per_required_class = 1;
        return p;
    }
};

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------
struct FieldCounters {
    std::uint64_t compared = 0;
    std::uint64_t equal    = 0;
    std::uint64_t differed = 0;
    std::uint64_t absent   = 0;
};

struct SeamCounters {
    std::uint64_t samples          = 0;   // judged: CLEAN + FAIL + SERVED-MISMATCH
    std::uint64_t clean            = 0;
    std::uint64_t fail             = 0;
    std::uint64_t served_mismatch  = 0;
    std::uint64_t voided           = 0;
    std::uint64_t clean_streak     = 0;
    std::uint64_t best_clean_streak = 0;
    std::uint64_t last_sample_unix = 0;

    double void_rate() const {
        const std::uint64_t total = samples + voided;
        return total == 0 ? 1.0 : static_cast<double>(voided) / static_cast<double>(total);
    }
};

struct ClassCounters {
    std::uint64_t samples = 0;
    std::uint64_t clean   = 0;
    std::uint64_t fail    = 0;
    std::uint64_t voided  = 0;
};

inline bool same_key(const GraduationKey& a, const GraduationKey& b) {
    return a.c2pool_commit == b.c2pool_commit
        && a.comparator_version == b.comparator_version
        && a.monerod_version == b.monerod_version
        && a.net == b.net;
}

inline std::string key_string(const GraduationKey& k) {
    return k.c2pool_commit + "|v" + Obs::u64(k.comparator_version).value + "|"
         + k.monerod_version + "|" + k.net;
}

// ---------------------------------------------------------------------------
// GraduationLedger
// ---------------------------------------------------------------------------
class GraduationLedger {
public:
    GraduationLedger() = default;
    GraduationLedger(GraduationKey key, GraduationPolicy policy)
        : key_(std::move(key)), policy_(std::move(policy)) {
        key_.comparator_version = COMPARATOR_VERSION;
    }

    const GraduationKey&    key()    const noexcept { return key_; }
    const GraduationPolicy& policy() const noexcept { return policy_; }
    GraduationState         state()  const noexcept { return state_; }

    const SeamCounters& seam(ProbeKind k) const { return seams_[static_cast<std::size_t>(k)]; }
    const std::map<std::string, FieldCounters>& fields() const noexcept { return fields_; }
    const std::map<std::uint8_t, ClassCounters>& classes() const noexcept { return classes_; }
    const std::vector<std::pair<std::uint64_t, std::string>>& revocations() const noexcept {
        return revocations_;
    }
    std::uint64_t first_sample_unix() const noexcept { return first_unix_; }
    std::uint64_t last_sample_unix()  const noexcept { return last_unix_; }

    // Aggregate coverage in the contract's shape.
    ParityCoverage coverage() const {
        ParityCoverage c;
        for (const SeamCounters& s : seams_) {
            c.samples         += s.samples + s.voided;
            c.clean           += s.clean;
            c.fail            += s.fail;
            c.served_mismatch += s.served_mismatch;
            c.voided          += s.voided;
        }
        auto cls = [&](HeightClass h) -> std::uint64_t {
            auto it = classes_.find(static_cast<std::uint8_t>(h));
            return it == classes_.end() ? 0 : it->second.samples;
        };
        c.epoch_edges_seen  = cls(HeightClass::EpochEdge);
        c.reorgs_seen       = cls(HeightClass::Reorg);
        c.no_samples_streak = no_samples_streak_;
        return c;
    }

    // -----------------------------------------------------------------------
    // record -- the only way a number in here changes.
    // -----------------------------------------------------------------------
    void record(const SeamResult& r, std::uint64_t unix_now) {
        const std::size_t si = static_cast<std::size_t>(r.sample.kind);
        SeamCounters& s = seams_[si];

        if (first_unix_ == 0 || unix_now < first_unix_) first_unix_ = unix_now;
        if (unix_now > last_unix_) last_unix_ = unix_now;
        s.last_sample_unix = unix_now;
        no_samples_streak_ = 0;

        switch (r.sample.verdict) {
            case ParityVerdict::Clean:
                ++s.samples; ++s.clean; ++s.clean_streak;
                if (s.clean_streak > s.best_clean_streak) s.best_clean_streak = s.clean_streak;
                break;
            case ParityVerdict::Fail:
                ++s.samples; ++s.fail; s.clean_streak = 0;
                break;
            case ParityVerdict::ServedMismatch:
                ++s.samples; ++s.served_mismatch; s.clean_streak = 0;
                break;
            case ParityVerdict::Void:
                // NOT a sample. A VOID resets nothing and proves nothing; it is
                // counted only so the void RATE can be capped.
                ++s.voided;
                break;
        }

        // Per-class. VOID contributes to `voided` only, never to `clean`.
        for (HeightClass hc : r.sample.classes) {
            ClassCounters& c = classes_[static_cast<std::uint8_t>(hc)];
            if (r.sample.verdict == ParityVerdict::Void) { ++c.voided; continue; }
            ++c.samples;
            if (r.sample.verdict == ParityVerdict::Clean) ++c.clean; else ++c.fail;
        }

        // Per-field coverage, from the sweep counters and the diff list. Only
        // fields that were genuinely compared move `compared`.
        record_fields_(r);

        if (r.sentinel_tripped)
            revoke(r.sentinel_why.empty() ? std::string("sentinel tripped") : r.sentinel_why, unix_now);
        else if (r.sample.verdict == ParityVerdict::ServedMismatch)
            revoke("SERVED-MISMATCH at height " + Obs::u64(r.sample.height).value, unix_now);

        if (state_ != GraduationState::Revoked) evaluate_(unix_now);
    }

    // A probe that fired and produced nothing. Not an error and not a sample:
    // it is what the heartbeat counts so that "no samples" is visible as a
    // rising number instead of as calm.
    void note_no_sample() { ++no_samples_streak_; }
    std::uint64_t no_samples_streak() const noexcept { return no_samples_streak_; }

    void revoke(const std::string& why, std::uint64_t unix_now = 0) {
        if (state_ == GraduationState::Revoked && !revocations_.empty()) {
            revocations_.emplace_back(unix_now, why);
            return;
        }
        state_ = GraduationState::Revoked;
        revocations_.emplace_back(unix_now, why);
    }

    // Why is this not graduated? Empty when it is. The list is the operator's
    // to-do, and it is derived, never stored.
    std::vector<std::string> shortfalls(std::uint64_t unix_now = 0) const {
        std::vector<std::string> out;
        if (state_ == GraduationState::Revoked) {
            out.push_back("REVOKED: " + (revocations_.empty() ? std::string("unknown")
                                                              : revocations_.back().second));
            return out;
        }
        const ProbeKind kinds[3] = {ProbeKind::Tip, ProbeKind::Template, ProbeKind::Submit};
        for (ProbeKind k : kinds) {
            const SeamCounters& s = seam(k);
            const SeamRequirement& need = policy_.for_seam(k);
            if (s.samples < need.min_samples)
                out.push_back(std::string(to_string(k)) + ": " + Obs::u64(s.samples).value
                            + " judged sample(s), need " + Obs::u64(need.min_samples).value);
            if (s.clean_streak < need.min_clean_streak)
                out.push_back(std::string(to_string(k)) + ": clean streak "
                            + Obs::u64(s.clean_streak).value + ", need "
                            + Obs::u64(need.min_clean_streak).value);
            if (s.samples + s.voided > 0 && s.void_rate() > policy_.max_void_rate)
                out.push_back(std::string(to_string(k)) + ": void rate too high ("
                            + Obs::u64(s.voided).value + " of "
                            + Obs::u64(s.samples + s.voided).value + ")");
        }
        for (const std::string& f : required_field_names()) {
            auto it = fields_.find(f);
            const std::uint64_t n = (it == fields_.end()) ? 0 : it->second.compared;
            if (n < policy_.min_field_comparisons)
                out.push_back("field '" + f + "': compared " + Obs::u64(n).value
                            + " time(s), need " + Obs::u64(policy_.min_field_comparisons).value);
        }
        for (HeightClass hc : policy_.required_classes) {
            auto it = classes_.find(static_cast<std::uint8_t>(hc));
            const std::uint64_t n = (it == classes_.end()) ? 0 : it->second.clean;
            if (n < policy_.min_samples_per_required_class)
                out.push_back(std::string("class ") + to_string(hc) + ": "
                            + Obs::u64(n).value + " clean sample(s), need "
                            + Obs::u64(policy_.min_samples_per_required_class).value);
        }
        const std::uint64_t now = unix_now ? unix_now : last_unix_;
        const std::uint64_t span = (first_unix_ && now > first_unix_) ? (now - first_unix_) : 0;
        if (span < policy_.min_window_seconds)
            out.push_back("window: " + Obs::u64(span).value + " s observed, need "
                        + Obs::u64(policy_.min_window_seconds).value + " s");
        return out;
    }

    // Every required EQUALITY field across the three seams, by name.
    static std::vector<std::string> required_field_names() {
        std::vector<std::string> out;
        const SeamSpec* specs[3] = {&TIP_SEAM, &TEMPLATE_SEAM, &SUBMIT_SEAM};
        for (const SeamSpec* sp : specs)
            for (std::size_t i = 0; i < sp->count; ++i)
                if (sp->fields[i].regime == Regime::Equality && sp->fields[i].required)
                    out.push_back(sp->fields[i].name);
        return out;
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------
    std::string to_json() const {
        std::ostringstream o;
        o << "{\n";
        o << "  \"key\": {\"c2pool_commit\": \"" << esc(key_.c2pool_commit)
          << "\", \"comparator_version\": " << key_.comparator_version
          << ", \"monerod_version\": \"" << esc(key_.monerod_version)
          << "\", \"net\": \"" << esc(key_.net) << "\"},\n";
        o << "  \"state\": \"" << to_string(state_) << "\",\n";
        o << "  \"first_sample_unix\": " << first_unix_ << ",\n";
        o << "  \"last_sample_unix\": " << last_unix_ << ",\n";
        o << "  \"no_samples_streak\": " << no_samples_streak_ << ",\n";
        o << "  \"seams\": {";
        const ProbeKind kinds[3] = {ProbeKind::Tip, ProbeKind::Template, ProbeKind::Submit};
        for (std::size_t i = 0; i < 3; ++i) {
            const SeamCounters& s = seams_[static_cast<std::size_t>(kinds[i])];
            if (i) o << ",";
            o << "\n    \"" << to_string(kinds[i]) << "\": {"
              << "\"samples\": " << s.samples << ", \"clean\": " << s.clean
              << ", \"fail\": " << s.fail << ", \"served_mismatch\": " << s.served_mismatch
              << ", \"void\": " << s.voided << ", \"clean_streak\": " << s.clean_streak
              << ", \"best_clean_streak\": " << s.best_clean_streak
              << ", \"last_sample_unix\": " << s.last_sample_unix << "}";
        }
        o << "\n  },\n";
        o << "  \"fields\": {";
        bool first = true;
        for (const auto& kv : fields_) {
            if (!first) o << ",";
            first = false;
            o << "\n    \"" << esc(kv.first) << "\": {"
              << "\"compared\": " << kv.second.compared
              << ", \"equal\": " << kv.second.equal
              << ", \"differed\": " << kv.second.differed
              << ", \"absent\": " << kv.second.absent << "}";
        }
        o << "\n  },\n";
        o << "  \"classes\": {";
        first = true;
        for (const auto& kv : classes_) {
            if (!first) o << ",";
            first = false;
            o << "\n    \"" << to_string(static_cast<HeightClass>(kv.first)) << "\": {"
              << "\"samples\": " << kv.second.samples
              << ", \"clean\": " << kv.second.clean
              << ", \"fail\": " << kv.second.fail
              << ", \"void\": " << kv.second.voided << "}";
        }
        o << "\n  },\n";
        o << "  \"revocations\": [";
        for (std::size_t i = 0; i < revocations_.size(); ++i) {
            if (i) o << ",";
            o << "\n    {\"unix\": " << revocations_[i].first
              << ", \"why\": \"" << esc(revocations_[i].second) << "\"}";
        }
        o << "\n  ]\n}\n";
        return o.str();
    }

    // Loads counters ONLY when the key matches. A ledger written by other code,
    // another comparator, another daemon or another network is discarded and
    // `why` says so -- inheriting it is exactly the mistake the key exists to
    // prevent.
    bool from_json(const std::string& text, std::string* why = nullptr) {
        mj::Value root;
        if (!mj::parse(text.data(), text.size(), root) || !root.is_object()) {
            if (why) *why = "parity ledger: not valid JSON";
            return false;
        }
        const mj::Value& k = root["key"];
        GraduationKey loaded;
        loaded.c2pool_commit     = k["c2pool_commit"].as_string();
        loaded.comparator_version = static_cast<std::uint32_t>(k["comparator_version"].as_u64());
        loaded.monerod_version   = k["monerod_version"].as_string();
        loaded.net               = k["net"].as_string();
        if (!same_key(loaded, key_)) {
            if (why) *why = "parity ledger: key mismatch (" + key_string(loaded)
                          + " on disk, " + key_string(key_) + " running): discarded, streak restarts";
            return false;
        }

        const std::string st = root["state"].as_string();
        state_ = (st == "Graduated")   ? GraduationState::Graduated
               : (st == "Revoked")     ? GraduationState::Revoked
               : (st == "Observing")   ? GraduationState::Observing
                                       : GraduationState::Ungraduated;
        first_unix_        = root["first_sample_unix"].as_u64();
        last_unix_         = root["last_sample_unix"].as_u64();
        no_samples_streak_ = root["no_samples_streak"].as_u64();

        const ProbeKind kinds[3] = {ProbeKind::Tip, ProbeKind::Template, ProbeKind::Submit};
        const mj::Value& sm = root["seams"];
        for (ProbeKind kk : kinds) {
            const mj::Value& s = sm[to_string(kk)];
            SeamCounters& c = seams_[static_cast<std::size_t>(kk)];
            c.samples           = s["samples"].as_u64();
            c.clean             = s["clean"].as_u64();
            c.fail              = s["fail"].as_u64();
            c.served_mismatch   = s["served_mismatch"].as_u64();
            c.voided            = s["void"].as_u64();
            c.clean_streak      = s["clean_streak"].as_u64();
            c.best_clean_streak = s["best_clean_streak"].as_u64();
            c.last_sample_unix  = s["last_sample_unix"].as_u64();
        }
        fields_.clear();
        const mj::Value& fs = root["fields"];
        if (fs.is_object()) {
            for (const auto& kv : fs.obj) {
                FieldCounters fc;
                fc.compared = kv.second["compared"].as_u64();
                fc.equal    = kv.second["equal"].as_u64();
                fc.differed = kv.second["differed"].as_u64();
                fc.absent   = kv.second["absent"].as_u64();
                fields_[kv.first] = fc;
            }
        }
        classes_.clear();
        const mj::Value& cs = root["classes"];
        if (cs.is_object()) {
            for (const auto& kv : cs.obj) {
                ClassCounters cc;
                cc.samples = kv.second["samples"].as_u64();
                cc.clean   = kv.second["clean"].as_u64();
                cc.fail    = kv.second["fail"].as_u64();
                cc.voided  = kv.second["void"].as_u64();
                classes_[class_from_name_(kv.first)] = cc;
            }
        }
        revocations_.clear();
        const mj::Value& rv = root["revocations"];
        if (rv.is_array())
            for (const mj::Value& e : rv.arr)
                revocations_.emplace_back(e["unix"].as_u64(), e["why"].as_string());
        if (why) why->clear();
        return true;
    }

    bool save(const std::string& path, std::string* why = nullptr) const {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { if (why) *why = "parity ledger: cannot open '" + path + "' for writing"; return false; }
        const std::string t = to_json();
        f.write(t.data(), static_cast<std::streamsize>(t.size()));
        if (!f.good()) { if (why) *why = "parity ledger: write failed on '" + path + "'"; return false; }
        return true;
    }

    // A missing file is NOT an error: an un-run experiment is ungraduated, which
    // is the fail-closed answer already. A CORRUPT or foreign file is reported.
    bool load(const std::string& path, std::string* why = nullptr) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { if (why) why->clear(); return false; }
        std::ostringstream ss;
        ss << f.rdbuf();
        return from_json(ss.str(), why);
    }

    // The conventional location: <config>/<net>/xmr_parity_ledger.json
    static std::string default_path(const std::string& config_dir, const std::string& net) {
        std::string p = config_dir;
        if (!p.empty() && p.back() != '/') p.push_back('/');
        return p + net + "/xmr_parity_ledger.json";
    }

private:
    void record_fields_(const SeamResult& r) {
        // Which required fields were named as absent?
        for (const std::string& n : r.absent_required) ++fields_[n].absent;

        // Which required fields appear in the diff list (and were not absent)?
        std::vector<std::string> differed;
        for (const FieldDiff& d : r.sample.fields) {
            if (d.served == Obs::absent_marker() || d.shadow == Obs::absent_marker()) continue;
            if (d.shadow == "INVARIANT" || d.shadow == "CONSTRAINT") continue;
            differed.push_back(d.field);
        }

        const SeamSpec& sp = seam_spec(r.sample.kind);
        // The submit seam's required set is decided per sample (only ARMED
        // oracles are required), so it is driven off the counters instead of
        // the table. Everything the sweep compared and did not flag is equal.
        if (r.sample.kind == ProbeKind::Submit) {
            for (const std::string& n : differed) { ++fields_[n].compared; ++fields_[n].differed; }
            // The oracles that compared cleanly are those compared minus those
            // that differed; name them from the diff-free side of the table.
            std::uint64_t clean_left = (r.equality_compared > r.equality_differed)
                                     ? (r.equality_compared - r.equality_differed) : 0;
            const char* order[2] = {"daemon_accepted", "confirmed_on_chain"};
            for (const char* n : order) {
                if (clean_left == 0) break;
                bool named = false;
                for (const std::string& d : differed) if (d == n) named = true;
                for (const std::string& a : r.absent_required) if (a == n) named = true;
                if (named) continue;
                ++fields_[n].compared; ++fields_[n].equal;
                --clean_left;
            }
            return;
        }

        for (std::size_t i = 0; i < sp.count; ++i) {
            const FieldSpec& f = sp.fields[i];
            if (f.regime != Regime::Equality || !f.required) continue;
            bool was_absent = false;
            for (const std::string& a : r.absent_required) if (a == f.name) was_absent = true;
            if (was_absent) continue;                      // already counted
            if (r.sample.verdict == ParityVerdict::Void) continue;  // never compared
            bool was_diff = false;
            for (const std::string& d : differed) if (d == f.name) was_diff = true;
            FieldCounters& fc = fields_[f.name];
            ++fc.compared;
            if (was_diff) ++fc.differed; else ++fc.equal;
        }
    }

    void evaluate_(std::uint64_t unix_now) {
        if (state_ == GraduationState::Revoked) return;
        const bool ok = shortfalls(unix_now).empty();
        if (ok) state_ = GraduationState::Graduated;
        else if (state_ == GraduationState::Graduated) state_ = GraduationState::Observing;
        else state_ = (last_unix_ != 0) ? GraduationState::Observing : GraduationState::Ungraduated;
    }

    static std::uint8_t class_from_name_(const std::string& n) {
        if (n == "EpochEdge")    return static_cast<std::uint8_t>(HeightClass::EpochEdge);
        if (n == "Reorg")        return static_cast<std::uint8_t>(HeightClass::Reorg);
        if (n == "HardForkEdge") return static_cast<std::uint8_t>(HeightClass::HardForkEdge);
        if (n == "PenaltyZone")  return static_cast<std::uint8_t>(HeightClass::PenaltyZone);
        return static_cast<std::uint8_t>(HeightClass::Steady);
    }

    static std::string esc(const std::string& s) {
        std::string o;
        o.reserve(s.size() + 8);
        for (char c : s) {
            if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
            else if (c == '\n') o += "\\n";
            else if (static_cast<unsigned char>(c) < 0x20) o += ' ';
            else o.push_back(c);
        }
        return o;
    }

    GraduationKey    key_{};
    GraduationPolicy policy_{};
    GraduationState  state_ = GraduationState::Ungraduated;

    SeamCounters seams_[3]{};
    std::map<std::string, FieldCounters>  fields_;
    std::map<std::uint8_t, ClassCounters> classes_;
    std::vector<std::pair<std::uint64_t, std::string>> revocations_;

    std::uint64_t first_unix_ = 0;
    std::uint64_t last_unix_  = 0;
    std::uint64_t no_samples_streak_ = 0;
};

} // namespace c2pool::xmr::native::parity
