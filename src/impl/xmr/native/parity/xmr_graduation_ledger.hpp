// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_graduation_ledger.hpp
//
// M4, the record: the TWO-POSTURE graduation ledger.
//
// C6's GraduationLedger (xmr_parity_ledger.hpp) answers "have the seams agreed
// enough, for long enough, over enough classes?". It is per-seam and per-field,
// and it is right about all of that. What it does not carry is the shape the M4
// gate is actually written in, which is not about seams at all:
//
//     serve = monerod / shadow = native   for a sustained window, every sample
//                                         CLEAN, then
//     serve = native  / shadow = monerod  for a sustained window, every sample
//                                         CLEAN.
//
// TWO LEGS, AND THE SECOND ONE IS THE POINT. The first leg says the native node
// would have said what the daemon said. The second says the pool ran on what
// the native node said and the daemon still agreed -- which is the only one of
// the two that is evidence about DEMOTING the daemon, because it is the only
// one in which the native arm's answer had consequences. A harness that soaked
// only the first leg would be measuring a passenger.
//
// A LEG IS A STREAK, AND A STREAK IS FRAGILE BY CONSTRUCTION:
//
//   * CLEAN accrues it -- one more sample, possibly one more block, more wall
//     clock.
//   * FAIL and SERVED-MISMATCH RESET it to zero and clear the leg's
//     qualification if it had one. There is no averaging, no "mostly clean",
//     no budget of allowed failures. The M4 criterion is every sample.
//   * VOID neither accrues nor resets -- there was nothing to judge -- but a
//     RUN of consecutive VOIDs past `max_void_run` resets the streak anyway,
//     with its own reason. That is the DASH lesson in its sharpest form: a leg
//     that has stopped producing judgeable samples is not a leg quietly holding
//     its streak, it is a probe that stopped firing, and letting it coast would
//     make silence indistinguishable from agreement.
//
// AND IT NEVER INHERITS. The key is {c2pool_commit, comparator_version,
// monerod_version, net}, exactly as C6's is, and for the same reason: a streak
// earned by other code, under a judge that looked at a different table, against
// another daemon, on another network, is not evidence about this one. A ledger
// on disk whose key differs is DISCARDED, loudly, and both legs start at zero.
// COMPARATOR_VERSION is stamped from the header rather than taken from the
// caller, so "the ledger says v2 but the comparator is v3" cannot be spelled.
//
// WHAT `blocks` COUNTS, stated because a soak threshold denominated in blocks
// has to mean something exact: the number of samples in the current run whose
// height was strictly ABOVE every height seen so far in that run. Forward
// progress only. A reorg walks the tip backwards and contributes no block to
// the count, which is the conservative direction -- it can only make a 720-block
// claim harder to earn, never easier. The run's height span (lo..hi) is carried
// beside it so a reader can see both numbers rather than trust one.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// Header-only, no clock of its own -- the caller supplies unix time, so a KAT
// drives 72 hours in microseconds. STL only apart from save(), which reaches
// for fsync where the platform has one; see the comment there.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// save() replaces the file by rename, and flushes the replacement to the disk
// first where the platform offers a way to. That is the ONE non-STL thing in
// this header, it is confined to save(), and it degrades to "rename only" --
// still untearable, merely not power-cut-proof -- where the header is absent.
#if defined(__unix__) || defined(__APPLE__)
#  include <fcntl.h>
#  include <unistd.h>
#  define XMR_M4_LEDGER_HAVE_FSYNC 1
#endif

// C6's ledger, for `same_key` and `key_string`. The four-part key means exactly
// what it means there, and a second spelling of "are these the same
// experiment?" is a divergence waiting to happen. It is an STL-only include
// (parity types plus minijson), so this header stays STL-only too.
#include "impl/xmr/native/parity/xmr_parity_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_types.hpp"
#include "impl/xmr/node/minijson.hpp"

namespace c2pool::xmr::native::parity {

namespace mj4 = ::c2pool::xmr::node::minijson;

// ---------------------------------------------------------------------------
// Which way round the arms are wired for this leg.
//
// The names say BOTH halves on purpose. "serve=native" alone leaves the reader
// to remember what the other arm is doing, and the whole claim is about the
// pair.
// ---------------------------------------------------------------------------
enum class SoakPosture : std::uint8_t {
    ServeMonerodShadowNative = 0,   // leg 1: the daemon serves, we shadow it
    ServeNativeShadowMonerod = 1,   // leg 2: we serve, the daemon judges us
};

inline const char* to_string(SoakPosture p) noexcept {
    switch (p) {
        case SoakPosture::ServeMonerodShadowNative: return "serve=monerod/shadow=native";
        case SoakPosture::ServeNativeShadowMonerod: return "serve=native/shadow=monerod";
    }
    return "?";
}

// The short spelling used as a JSON key and on the command line.
inline const char* posture_tag(SoakPosture p) noexcept {
    return p == SoakPosture::ServeNativeShadowMonerod ? "serve-native" : "serve-monerod";
}

inline bool parse_posture(const std::string& s, SoakPosture& out) {
    if (s == "serve-monerod" || s == "monerod") { out = SoakPosture::ServeMonerodShadowNative; return true; }
    if (s == "serve-native"  || s == "native")  { out = SoakPosture::ServeNativeShadowMonerod; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// What a leg has to achieve.
//
// `min_tip_clean` and `min_template_clean` are not decoration, and they are the
// reason a single `min_clean_samples` would not do. P-TIP fires on every block;
// P-TPL only when a template is served. A leg driven by tip events alone would
// run up a 720-sample streak having never once compared a template -- and P-TPL
// is the seam the M4 criterion actually names. Requiring CLEAN samples from
// BOTH seams inside the same run is what stops the cheap seam from carrying the
// expensive one.
// ---------------------------------------------------------------------------
struct SoakThresholds {
    std::uint64_t min_clean_samples = 0;   // consecutive CLEAN samples in the run
    std::uint64_t min_blocks        = 0;   // forward height steps inside the run
    std::uint64_t min_seconds       = 0;   // wall clock spanned by the run
    std::uint64_t min_tip_clean     = 0;   // of which, P-TIP samples
    std::uint64_t min_template_clean = 0;  // of which, P-TPL samples
    // Consecutive VOIDs tolerated before the run is declared stalled and reset.
    // 0 means "no cap", which is only ever right for a unit test that drives
    // the machine by hand.
    std::uint64_t max_void_run     = 0;

    // THE REAL GATE, from the plan's M4 row: >= 72 h and >= 720 blocks per
    // posture with every sample CLEAN. Nothing scaled, nothing rounded.
    static SoakThresholds stagenet_m4() {
        SoakThresholds t;
        t.min_seconds        = 72 * 3600;
        t.min_blocks         = 720;
        t.min_clean_samples  = 720;
        t.min_tip_clean      = 720;
        t.min_template_clean = 240;
        t.max_void_run       = 64;
        return t;
    }

    // The regtest shape: the SAME STRUCTURE with small numbers, so a mini-soak
    // exercises every branch the stagenet run will. Deliberately not "no
    // thresholds" -- a harness that graduates on nothing proves nothing, which
    // is the failure this whole component exists to make impossible.
    static SoakThresholds regtest_mini() {
        SoakThresholds t;
        t.min_seconds        = 20;
        t.min_blocks         = 4;
        t.min_clean_samples  = 8;
        t.min_tip_clean      = 4;
        t.min_template_clean = 2;
        t.max_void_run       = 32;
        return t;
    }
};

// ---------------------------------------------------------------------------
// One posture's state: the current run, and the lifetime tally around it.
// ---------------------------------------------------------------------------
struct PostureLeg {
    // --- the current run ---
    std::uint64_t clean_run      = 0;   // consecutive CLEAN samples
    std::uint64_t run_blocks     = 0;   // forward height steps inside the run
    std::uint64_t run_first_unix = 0;
    std::uint64_t run_last_unix  = 0;
    std::uint64_t run_height_lo  = 0;
    std::uint64_t run_height_hi  = 0;
    std::uint64_t run_tip_clean  = 0;
    std::uint64_t run_tmpl_clean = 0;
    std::uint64_t void_run       = 0;   // consecutive VOIDs since the last judged sample

    // --- lifetime ---
    std::uint64_t samples         = 0;  // judged: CLEAN + FAIL + SERVED-MISMATCH
    std::uint64_t clean           = 0;
    std::uint64_t fail            = 0;
    std::uint64_t served_mismatch = 0;
    std::uint64_t voided          = 0;
    std::uint64_t resets          = 0;
    std::uint64_t first_unix      = 0;
    std::uint64_t last_unix       = 0;

    // --- the best this leg ever reached, and whether it stands NOW ---
    std::uint64_t best_clean_run = 0;
    std::uint64_t best_blocks    = 0;
    std::uint64_t best_seconds   = 0;
    // Sticky only while nothing has gone wrong since: a single FAIL clears it.
    bool          qualified      = false;
    std::uint64_t qualified_unix = 0;

    std::string   last_reset_why;

    std::uint64_t run_seconds() const noexcept {
        return (run_first_unix != 0 && run_last_unix > run_first_unix)
                 ? (run_last_unix - run_first_unix) : 0;
    }

    bool meets(const SoakThresholds& t) const noexcept {
        return clean_run  >= t.min_clean_samples
            && run_blocks >= t.min_blocks
            && run_seconds() >= t.min_seconds
            && run_tip_clean  >= t.min_tip_clean
            && run_tmpl_clean >= t.min_template_clean;
    }
};

// ---------------------------------------------------------------------------
// M4GraduationLedger
// ---------------------------------------------------------------------------
class M4GraduationLedger {
public:
    M4GraduationLedger() = default;
    M4GraduationLedger(GraduationKey key, SoakThresholds thr)
        : key_(std::move(key)), thr_(thr) {
        // Stamped, never accepted from the caller. See the header note.
        key_.comparator_version = COMPARATOR_VERSION;
    }

    const GraduationKey&  key()        const noexcept { return key_; }
    const SoakThresholds& thresholds() const noexcept { return thr_; }
    GraduationState       state()      const noexcept { return state_; }
    std::uint64_t         graduated_unix() const noexcept { return graduated_unix_; }
    std::uint64_t         first_sample_unix() const noexcept { return first_unix_; }
    std::uint64_t         last_sample_unix()  const noexcept { return last_unix_; }

    const PostureLeg& leg(SoakPosture p) const noexcept {
        return legs_[static_cast<std::size_t>(p)];
    }
    const std::vector<std::pair<std::uint64_t, std::string>>& revocations() const noexcept {
        return revocations_;
    }

    // The daemon version is not known until the daemon has answered once, and
    // re-keying mid-soak would silently restart the experiment. So it is BOUND
    // on first sight and frozen: a later change of the observed version is a
    // different daemon and revokes, it does not quietly re-key.
    void bind_monerod_version(const std::string& v, std::uint64_t unix_now) {
        if (v.empty()) return;
        if (key_.monerod_version.empty() || key_.monerod_version == "unknown") {
            key_.monerod_version = v;
            return;
        }
        if (key_.monerod_version != v)
            revoke("monerod version changed under the soak: '" + key_.monerod_version
                   + "' -> '" + v + "'", unix_now);
    }

    // -----------------------------------------------------------------------
    // record -- the only way a number in here moves.
    //
    // `height` is the sample's own height; VOID samples carry one too but it is
    // not used, because a VOID advances nothing.
    // -----------------------------------------------------------------------
    void record(SoakPosture posture, const SeamResult& r, std::uint64_t unix_now) {
        PostureLeg& L = legs_[static_cast<std::size_t>(posture)];

        if (first_unix_ == 0 || unix_now < first_unix_) first_unix_ = unix_now;
        if (unix_now > last_unix_) last_unix_ = unix_now;
        if (L.first_unix == 0 || unix_now < L.first_unix) L.first_unix = unix_now;
        if (unix_now > L.last_unix) L.last_unix = unix_now;

        switch (r.sample.verdict) {
            case ParityVerdict::Clean:
                L.void_run = 0;
                ++L.samples; ++L.clean;
                accrue_(L, r, unix_now);
                break;
            case ParityVerdict::Fail:
                L.void_run = 0;
                ++L.samples; ++L.fail;
                reset_(L, posture, "P-" + std::string(seam_short(r.sample.kind))
                                 + " FAIL at height " + Obs::u64(r.sample.height).value
                                 + (r.sample.note.empty() ? std::string() : (": " + r.sample.note)),
                       unix_now);
                break;
            case ParityVerdict::ServedMismatch:
                L.void_run = 0;
                ++L.samples; ++L.served_mismatch;
                reset_(L, posture, "SERVED-MISMATCH at height "
                                 + Obs::u64(r.sample.height).value, unix_now);
                // The worst verdict there is: what went out matched neither arm.
                // It does not merely reset a streak, it revokes the key.
                revoke("SERVED-MISMATCH in posture " + std::string(to_string(posture))
                       + " at height " + Obs::u64(r.sample.height).value, unix_now);
                break;
            case ParityVerdict::Void:
                ++L.voided; ++L.void_run;
                if (thr_.max_void_run != 0 && L.void_run > thr_.max_void_run && L.clean_run != 0)
                    reset_(L, posture, Obs::u64(L.void_run).value
                                     + " consecutive VOID sample(s): the leg stopped producing "
                                       "judgeable samples, which is not agreement",
                           unix_now);
                break;
        }

        if (r.sentinel_tripped)
            revoke(r.sentinel_why.empty() ? std::string("sentinel tripped") : r.sentinel_why,
                   unix_now);

        evaluate_(unix_now);
    }

    // A probe that fired and produced nothing at all. Distinct from a VOID
    // sample: there was not even an attempt to compare. It is counted so that
    // "the soak went quiet" reads as a rising number rather than as calm, and
    // it never touches a streak.
    void note_no_sample(SoakPosture posture) {
        ++no_sample_drains_[static_cast<std::size_t>(posture)];
    }
    std::uint64_t no_sample_drains(SoakPosture p) const noexcept {
        return no_sample_drains_[static_cast<std::size_t>(p)];
    }

    void revoke(const std::string& why, std::uint64_t unix_now = 0) {
        state_ = GraduationState::Revoked;
        revocations_.emplace_back(unix_now, why);
    }

    // GRADUATED means: this key, both legs, full streak, zero non-CLEAN inside
    // either. Anything else is a list of reasons why not.
    bool graduated() const noexcept { return state_ == GraduationState::Graduated; }

    std::vector<std::string> shortfalls() const {
        std::vector<std::string> out;
        if (state_ == GraduationState::Revoked) {
            out.push_back("REVOKED: " + (revocations_.empty() ? std::string("unknown")
                                                              : revocations_.back().second));
            return out;
        }
        if (key_.c2pool_commit.empty())
            out.push_back("key: no c2pool commit recorded (graduation must name the code it judged)");
        if (key_.monerod_version.empty() || key_.monerod_version == "unknown")
            out.push_back("key: monerod version not observed yet");
        if (key_.net.empty())
            out.push_back("key: no network recorded");

        const SoakPosture ps[2] = {SoakPosture::ServeMonerodShadowNative,
                                   SoakPosture::ServeNativeShadowMonerod};
        for (SoakPosture p : ps) {
            const PostureLeg& L = leg(p);
            if (L.qualified) continue;
            const std::string tag = std::string(posture_tag(p));
            if (L.clean_run < thr_.min_clean_samples)
                out.push_back(tag + ": clean streak " + Obs::u64(L.clean_run).value
                            + ", need " + Obs::u64(thr_.min_clean_samples).value);
            if (L.run_blocks < thr_.min_blocks)
                out.push_back(tag + ": " + Obs::u64(L.run_blocks).value
                            + " block(s) in the streak, need " + Obs::u64(thr_.min_blocks).value);
            if (L.run_seconds() < thr_.min_seconds)
                out.push_back(tag + ": streak spans " + Obs::u64(L.run_seconds()).value
                            + " s, need " + Obs::u64(thr_.min_seconds).value + " s");
            if (L.run_tip_clean < thr_.min_tip_clean)
                out.push_back(tag + ": " + Obs::u64(L.run_tip_clean).value
                            + " clean P-TIP sample(s) in the streak, need "
                            + Obs::u64(thr_.min_tip_clean).value);
            if (L.run_tmpl_clean < thr_.min_template_clean)
                out.push_back(tag + ": " + Obs::u64(L.run_tmpl_clean).value
                            + " clean P-TPL sample(s) in the streak, need "
                            + Obs::u64(thr_.min_template_clean).value);
            if (!L.last_reset_why.empty())
                out.push_back(tag + ": last streak reset -- " + L.last_reset_why);
        }
        return out;
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------
    std::string to_json() const {
        std::ostringstream o;
        o << "{\n";
        o << "  \"schema\": \"xmr-m4-graduation/1\",\n";
        o << "  \"key\": {\"c2pool_commit\": \"" << esc(key_.c2pool_commit)
          << "\", \"comparator_version\": " << key_.comparator_version
          << ", \"monerod_version\": \"" << esc(key_.monerod_version)
          << "\", \"net\": \"" << esc(key_.net) << "\"},\n";
        o << "  \"state\": \"" << to_string(state_) << "\",\n";
        o << "  \"graduated_unix\": " << graduated_unix_ << ",\n";
        o << "  \"first_sample_unix\": " << first_unix_ << ",\n";
        o << "  \"last_sample_unix\": " << last_unix_ << ",\n";
        o << "  \"thresholds\": {\"min_clean_samples\": " << thr_.min_clean_samples
          << ", \"min_blocks\": " << thr_.min_blocks
          << ", \"min_seconds\": " << thr_.min_seconds
          << ", \"min_tip_clean\": " << thr_.min_tip_clean
          << ", \"min_template_clean\": " << thr_.min_template_clean
          << ", \"max_void_run\": " << thr_.max_void_run << "},\n";
        o << "  \"legs\": {";
        const SoakPosture ps[2] = {SoakPosture::ServeMonerodShadowNative,
                                   SoakPosture::ServeNativeShadowMonerod};
        for (std::size_t i = 0; i < 2; ++i) {
            const PostureLeg& L = leg(ps[i]);
            if (i) o << ",";
            o << "\n    \"" << posture_tag(ps[i]) << "\": {"
              << "\"clean_run\": " << L.clean_run
              << ", \"run_blocks\": " << L.run_blocks
              << ", \"run_first_unix\": " << L.run_first_unix
              << ", \"run_last_unix\": " << L.run_last_unix
              << ", \"run_height_lo\": " << L.run_height_lo
              << ", \"run_height_hi\": " << L.run_height_hi
              << ", \"run_tip_clean\": " << L.run_tip_clean
              << ", \"run_tmpl_clean\": " << L.run_tmpl_clean
              << ", \"void_run\": " << L.void_run
              << ", \"samples\": " << L.samples
              << ", \"clean\": " << L.clean
              << ", \"fail\": " << L.fail
              << ", \"served_mismatch\": " << L.served_mismatch
              << ", \"void\": " << L.voided
              << ", \"resets\": " << L.resets
              << ", \"first_unix\": " << L.first_unix
              << ", \"last_unix\": " << L.last_unix
              << ", \"best_clean_run\": " << L.best_clean_run
              << ", \"best_blocks\": " << L.best_blocks
              << ", \"best_seconds\": " << L.best_seconds
              << ", \"qualified\": " << (L.qualified ? "true" : "false")
              << ", \"qualified_unix\": " << L.qualified_unix
              << ", \"no_sample_drains\": " << no_sample_drains_[static_cast<std::size_t>(ps[i])]
              << ", \"last_reset_why\": \"" << esc(L.last_reset_why) << "\"}";
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

    // Loads ONLY when the key matches. A foreign ledger is discarded and `why`
    // says which of the four keys moved. This is the M1 lesson made mechanical:
    // the comparator bump from 2 to 3 must not carry a streak across.
    bool from_json(const std::string& text, std::string* why = nullptr) {
        mj4::Value root;
        if (!mj4::parse(text.data(), text.size(), root) || !root.is_object()) {
            if (why) *why = "m4 ledger: not valid JSON";
            return false;
        }
        const mj4::Value& k = root["key"];
        GraduationKey loaded;
        loaded.c2pool_commit      = k["c2pool_commit"].as_string();
        loaded.comparator_version = static_cast<std::uint32_t>(k["comparator_version"].as_u64());
        loaded.monerod_version    = k["monerod_version"].as_string();
        loaded.net                = k["net"].as_string();

        // The running key may not have seen the daemon yet. An unbound version
        // adopts what is on disk rather than refusing to load against itself;
        // every other field must match exactly.
        GraduationKey running = key_;
        if (running.monerod_version.empty() || running.monerod_version == "unknown")
            running.monerod_version = loaded.monerod_version;
        if (!same_key(loaded, running)) {
            if (why) *why = "m4 ledger: key mismatch (" + key_string(loaded)
                          + " on disk, " + key_string(key_)
                          + " running): discarded, both posture streaks restart";
            return false;
        }
        key_.monerod_version = running.monerod_version;

        const std::string st = root["state"].as_string();
        state_ = (st == "Graduated") ? GraduationState::Graduated
               : (st == "Revoked")   ? GraduationState::Revoked
               : (st == "Observing") ? GraduationState::Observing
                                     : GraduationState::Ungraduated;
        graduated_unix_ = root["graduated_unix"].as_u64();
        first_unix_     = root["first_sample_unix"].as_u64();
        last_unix_      = root["last_sample_unix"].as_u64();

        const SoakPosture ps[2] = {SoakPosture::ServeMonerodShadowNative,
                                   SoakPosture::ServeNativeShadowMonerod};
        const mj4::Value& legs = root["legs"];
        for (SoakPosture p : ps) {
            const mj4::Value& v = legs[posture_tag(p)];
            PostureLeg& L = legs_[static_cast<std::size_t>(p)];
            L.clean_run      = v["clean_run"].as_u64();
            L.run_blocks     = v["run_blocks"].as_u64();
            L.run_first_unix = v["run_first_unix"].as_u64();
            L.run_last_unix  = v["run_last_unix"].as_u64();
            L.run_height_lo  = v["run_height_lo"].as_u64();
            L.run_height_hi  = v["run_height_hi"].as_u64();
            L.run_tip_clean  = v["run_tip_clean"].as_u64();
            L.run_tmpl_clean = v["run_tmpl_clean"].as_u64();
            L.void_run       = v["void_run"].as_u64();
            L.samples        = v["samples"].as_u64();
            L.clean          = v["clean"].as_u64();
            L.fail           = v["fail"].as_u64();
            L.served_mismatch = v["served_mismatch"].as_u64();
            L.voided         = v["void"].as_u64();
            L.resets         = v["resets"].as_u64();
            L.first_unix     = v["first_unix"].as_u64();
            L.last_unix      = v["last_unix"].as_u64();
            L.best_clean_run = v["best_clean_run"].as_u64();
            L.best_blocks    = v["best_blocks"].as_u64();
            L.best_seconds   = v["best_seconds"].as_u64();
            L.qualified      = v["qualified"].as_bool(false);
            L.qualified_unix = v["qualified_unix"].as_u64();
            L.last_reset_why = v["last_reset_why"].as_string();
            no_sample_drains_[static_cast<std::size_t>(p)] = v["no_sample_drains"].as_u64();
        }
        revocations_.clear();
        const mj4::Value& rv = root["revocations"];
        if (rv.is_array())
            for (const mj4::Value& e : rv.arr)
                revocations_.emplace_back(e["unix"].as_u64(), e["why"].as_string());

        // The state on disk is a CACHE of a decision, never the decision. It is
        // re-derived from the loaded counters here, so a file that says
        // "Graduated" over legs that did not qualify -- a hand-edit, a partial
        // write, a future field this build does not read -- is corrected rather
        // than believed. A genuinely graduated ledger re-derives to Graduated
        // and keeps its stamp; a revoked one stays revoked, which evaluate_
        // refuses to touch.
        evaluate_(last_unix_);
        if (why) why->clear();
        return true;
    }

    // WRITE ELSEWHERE, THEN RENAME. The ledger is not a log that can lose its
    // tail: it is the entire artefact of a leg, and by the end of a 72 h posture
    // it is the only place three days of soaking exist. A truncating in-place
    // write puts that at the mercy of the instant between `trunc` and the last
    // byte -- and this file is rewritten every `autosave_every` samples, for
    // days, under a watchdog whose whole job is to kill and restart the writer.
    // Landing in that window would not corrupt one sample, it would leave a
    // half-written file that load() rejects as "not valid JSON" and start the
    // streak from zero, silently, with no way to tell that from a genuine reset.
    //
    // rename(2) within a directory is atomic, so a reader -- the next process,
    // the watchdog, a human with `cat` -- sees the whole previous ledger or the
    // whole new one and never a splice of the two. The fsync before it is what
    // makes that true across a power cut rather than only across a crash.
    bool save(const std::string& path, std::string* why = nullptr) const {
        const std::string tmp = path + ".tmp";
        const std::string t   = to_json();
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) {
                if (why) *why = "m4 ledger: cannot open '" + tmp + "' for writing";
                return false;
            }
            f.write(t.data(), static_cast<std::streamsize>(t.size()));
            f.flush();
            if (!f.good()) {
                if (why) *why = "m4 ledger: write failed on '" + tmp + "'";
                f.close();
                std::remove(tmp.c_str());
                return false;
            }
        }
#if defined(XMR_M4_LEDGER_HAVE_FSYNC)
        // Best effort by design: a platform that cannot fsync still gets the
        // untearable rename below, which is the property the soak depends on.
        if (const int fd = ::open(tmp.c_str(), O_RDONLY); fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
#endif
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            if (why) *why = "m4 ledger: cannot rename '" + tmp + "' onto '" + path + "'";
            std::remove(tmp.c_str());
            return false;
        }
#if defined(XMR_M4_LEDGER_HAVE_FSYNC)
        // And the directory entry, so the rename itself survives the same cut.
        const std::size_t slash = path.find_last_of('/');
        const std::string dir   = (slash == std::string::npos) ? std::string(".")
                                                               : path.substr(0, slash ? slash : 1);
        if (const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY); dfd >= 0) {
            ::fsync(dfd);
            ::close(dfd);
        }
#endif
        return true;
    }

    // A missing file is NOT an error: an un-run experiment is ungraduated,
    // which is already the fail-closed answer. A corrupt or foreign one is.
    bool load(const std::string& path, std::string* why = nullptr) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { if (why) why->clear(); return false; }
        std::ostringstream ss;
        ss << f.rdbuf();
        return from_json(ss.str(), why);
    }

    // -----------------------------------------------------------------------
    // The operator's line. Everything a reader needs to decide whether to
    // believe it, including the numbers that are NOT yet met.
    // -----------------------------------------------------------------------
    std::string report() const {
        std::ostringstream o;
        o << "=== M4 graduation ledger ===\n";
        o << "key            : commit=" << (key_.c2pool_commit.empty() ? "-" : key_.c2pool_commit)
          << " comparator=v" << key_.comparator_version
          << " monerod=" << (key_.monerod_version.empty() ? "-" : key_.monerod_version)
          << " net=" << key_.net << "\n";
        o << "thresholds     : per posture -- clean>=" << thr_.min_clean_samples
          << " blocks>=" << thr_.min_blocks
          << " seconds>=" << thr_.min_seconds
          << " tip>=" << thr_.min_tip_clean
          << " tpl>=" << thr_.min_template_clean
          << " void_run<=" << thr_.max_void_run << "\n";
        const SoakPosture ps[2] = {SoakPosture::ServeMonerodShadowNative,
                                   SoakPosture::ServeNativeShadowMonerod};
        for (SoakPosture p : ps) {
            const PostureLeg& L = leg(p);
            std::string tag = posture_tag(p);
            while (tag.size() < 14) tag.push_back(' ');
            o << "leg " << tag
              << ": streak=" << L.clean_run
              << " blocks=" << L.run_blocks
              << " span=" << L.run_seconds() << "s"
              << " tip=" << L.run_tip_clean << " tpl=" << L.run_tmpl_clean
              << " heights=" << L.run_height_lo << ".." << L.run_height_hi
              << " | lifetime clean=" << L.clean << " fail=" << L.fail
              << " mismatch=" << L.served_mismatch << " void=" << L.voided
              << " resets=" << L.resets
              << " no_sample_drains=" << no_sample_drains_[static_cast<std::size_t>(p)]
              << " | qualified=" << (L.qualified ? "yes" : "no") << "\n";
            if (!L.last_reset_why.empty())
                o << "               last reset: " << L.last_reset_why << "\n";
        }
        for (const auto& rv : revocations_)
            o << "revocation     : unix=" << rv.first << " " << rv.second << "\n";
        o << "state          : " << to_string(state_) << "\n";
        const std::vector<std::string> sf = shortfalls();
        for (const std::string& s : sf) o << "shortfall      : " << s << "\n";
        return o.str();
    }

    static const char* seam_short(ProbeKind k) noexcept { return to_string(k); }

private:
    void accrue_(PostureLeg& L, const SeamResult& r, std::uint64_t unix_now) {
        if (L.clean_run == 0) {
            L.run_first_unix = unix_now;
            L.run_height_lo  = r.sample.height;
            L.run_height_hi  = r.sample.height;
            L.run_blocks     = 0;
            L.run_tip_clean  = 0;
            L.run_tmpl_clean = 0;
        } else if (r.sample.height > L.run_height_hi) {
            // Forward progress only; see the header note on what `blocks` counts.
            ++L.run_blocks;
            L.run_height_hi = r.sample.height;
        }
        if (r.sample.height < L.run_height_lo && r.sample.height != 0)
            L.run_height_lo = r.sample.height;
        L.run_last_unix = unix_now;
        ++L.clean_run;
        if (r.sample.kind == ProbeKind::Tip)           ++L.run_tip_clean;
        else if (r.sample.kind == ProbeKind::Template) ++L.run_tmpl_clean;

        if (L.clean_run  > L.best_clean_run) L.best_clean_run = L.clean_run;
        if (L.run_blocks > L.best_blocks)    L.best_blocks    = L.run_blocks;
        if (L.run_seconds() > L.best_seconds) L.best_seconds  = L.run_seconds();
    }

    void reset_(PostureLeg& L, SoakPosture p, std::string why, std::uint64_t unix_now) {
        const bool had_qualification = L.qualified;
        L.clean_run = 0;
        L.run_blocks = 0;
        L.run_first_unix = 0;
        L.run_last_unix  = 0;
        L.run_height_lo  = 0;
        L.run_height_hi  = 0;
        L.run_tip_clean  = 0;
        L.run_tmpl_clean = 0;
        L.void_run = 0;
        ++L.resets;
        L.last_reset_why = why;
        // Qualification is not a trophy. The M4 criterion is every sample in
        // the window, so a leg that has just failed no longer has a window.
        L.qualified = false;
        L.qualified_unix = 0;
        if (had_qualification)
            revocations_.emplace_back(unix_now, "posture " + std::string(posture_tag(p))
                                              + " lost its qualification: " + why);
    }

    void evaluate_(std::uint64_t unix_now) {
        if (state_ == GraduationState::Revoked) return;
        for (std::size_t i = 0; i < 2; ++i) {
            PostureLeg& L = legs_[i];
            if (!L.qualified && L.meets(thr_)) {
                L.qualified = true;
                L.qualified_unix = unix_now;
            }
        }
        const bool key_ok = !key_.c2pool_commit.empty() && !key_.net.empty()
                         && !key_.monerod_version.empty() && key_.monerod_version != "unknown"
                         && key_.comparator_version == COMPARATOR_VERSION;
        const bool both = legs_[0].qualified && legs_[1].qualified;
        if (key_ok && both) {
            if (state_ != GraduationState::Graduated) graduated_unix_ = unix_now;
            state_ = GraduationState::Graduated;
        } else {
            state_ = (last_unix_ != 0) ? GraduationState::Observing
                                       : GraduationState::Ungraduated;
        }
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

    GraduationKey   key_{};
    SoakThresholds  thr_{};
    GraduationState state_ = GraduationState::Ungraduated;
    PostureLeg      legs_[2]{};
    std::uint64_t   no_sample_drains_[2]{0, 0};
    std::vector<std::pair<std::uint64_t, std::string>> revocations_;
    std::uint64_t   first_unix_     = 0;
    std::uint64_t   last_unix_      = 0;
    std::uint64_t   graduated_unix_ = 0;
};

} // namespace c2pool::xmr::native::parity
