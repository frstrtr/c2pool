// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_parity_oracle.hpp
//
// C6, the component: ParityOracle, the IParityOracle of contracts/parity.hpp.
//
// It runs BESIDE a real monerod during bring-up and answers one question, over
// and over, for as long as the pool is up:
//
//     would the native node have said exactly what the daemon said?
//
// Three seams, because those are the three places the answer being "no" costs
// something real:
//   TIP      -- a wrong tip means every template after it is built on sand.
//   TEMPLATE -- a wrong window means miners grind bytes the network will reject.
//   SUBMIT   -- a block nobody accepted is a find that paid nobody.
//
// THREE STRUCTURAL RULES, all of them scar tissue from the DASH shadow-compare
// incident of last August, and all of them enforced here rather than advised:
//
//   1. NOTHING RUNS ON THE HOT PATH. on_tip / on_serve / on_submit copy their
//      argument into a slot and return. All comparison happens in drain(),
//      which the owner calls from its own worker. A slow or broken oracle can
//      therefore not slow, block or change a share.
//
//   2. SILENCE IS LOUD. `attempts` counts every drain whether or not it found
//      anything; a drain that produced no sample bumps a no-sample streak; and
//      heartbeat() emits status=NO-SAMPLES on its interval regardless. The
//      failure mode being designed out is a probe that quietly stopped firing
//      and read, for weeks, as agreement.
//
//   3. VOID IS NOT AGREEMENT. It has its own counter, it never touches a clean
//      streak, and the ledger's per-field coverage floor means a comparison
//      that never happens BLOCKS graduation rather than being invisible to it.
//
// The tip probe COALESCES (only the newest tip matters; an oracle that queues
// behind a burst of blocks is measuring its own queue). The template probe
// coalesces for the same reason. SUBMIT DOES NOT COALESCE: every found block is
// its own irreplaceable sample and dropping one to save a copy would be absurd.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/native/contracts/parity.hpp"
#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_parity_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_report.hpp"
#include "impl/xmr/native/parity/xmr_parity_sources.hpp"

namespace c2pool::xmr::native::parity {

struct ParityOracleConfig {
    // Emit a heartbeat at least this often, sample or no sample.
    std::uint64_t heartbeat_interval_s = 300;
    // Persist the ledger after this many recorded samples (0 = never; the owner
    // calls save() itself).
    std::uint64_t autosave_every = 64;
    std::string   ledger_path;

    // RandomX epoch geometry, for the height classifier.
    std::uint64_t epoch_blocks = 2048;
    std::uint64_t epoch_lag    = 64;

    // How far the native tip may trail the daemon before the lag is reported as
    // a problem in the sample note (plan section 3.5: > 60 s with peers is a
    // revocation sentinel; the oracle only reports, the operator's policy
    // decides, because "with >= 3 peers" is C1's fact, not C6's).
    std::uint64_t tip_lag_warn_s = 60;
};

class ParityOracle final : public IParityOracle {
public:
    using LogSink   = std::function<void(const std::string&)>;
    using ClockFn   = std::function<std::uint64_t()>;   // unix seconds

    struct Deps {
        ITipObserver*     native_tip  = nullptr;
        ITipObserver*     monerod_tip = nullptr;
        // The C4 arms. `served` is the one the miners are served from; `shadow`
        // is read only here. Either may be null -- a node with no daemon has no
        // monerod arm -- and the seam then produces VOID samples, never CLEAN.
        IMinerDataSource* served_arm  = nullptr;
        IMinerDataSource* shadow_arm  = nullptr;
    };

    ParityOracle(Deps deps, GraduationKey key, GraduationPolicy policy,
                 ParityOracleConfig cfg = {}, ClockFn clock = {}, LogSink log = {})
        : deps_(deps),
          ledger_(std::move(key), std::move(policy)),
          cfg_(std::move(cfg)),
          clock_(std::move(clock)),
          log_(std::move(log)) {
        if (!cfg_.ledger_path.empty()) {
            std::string why;
            if (!ledger_.load(cfg_.ledger_path, &why) && !why.empty()) emit_("[XMR-PARITY] " + why);
        }
    }

    // -----------------------------------------------------------------------
    // IParityOracle -- all three are enqueue-and-return.
    // -----------------------------------------------------------------------
    void on_tip(const node::MainchainEvent& ev, const char* side) override {
        std::lock_guard<std::mutex> lk(mtx_);
        TipTrigger t;
        t.event    = ev;
        t.side     = side ? side : "?";
        t.at_unix  = now_();
        t.after_reorg = (ev.kind == node::MainchainEventKind::Reorg);
        // Coalesce: only the newest tip is interesting, and the FIRST side that
        // reported this height is remembered so the lag is measurable.
        if (tip_pending_ && tip_pending_->event.block.height == ev.block.height) {
            tip_pending_->after_reorg = tip_pending_->after_reorg || t.after_reorg;
            tip_pending_->latest_at   = t.at_unix;
            return;
        }
        t.latest_at = t.at_unix;
        tip_pending_ = std::move(t);
    }

    void on_serve(const MinerDataEpoch&  epoch,
                  const node::MinerData& served,
                  const char*            served_arm) override {
        std::lock_guard<std::mutex> lk(mtx_);
        ServeTrigger s;
        s.epoch    = epoch;
        s.served   = served;          // the ARTEFACT, carried, never re-read
        s.arm      = served_arm ? served_arm : "?";
        s.at_unix  = now_();
        serve_pending_ = std::move(s); // coalesce to newest
    }

    void on_submit(const BlockRelayVerdict& v) override {
        std::lock_guard<std::mutex> lk(mtx_);
        SubmitTrigger s;
        s.verdict = v;
        s.at_unix = now_();
        submits_.push_back(std::move(s)); // NEVER coalesced
        if (submits_.size() > 256) submits_.pop_front();
    }

    GraduationState state()    const override { std::lock_guard<std::mutex> lk(mtx_); return ledger_.state(); }
    ParityCoverage  coverage() const override { std::lock_guard<std::mutex> lk(mtx_); return ledger_.coverage(); }

    void revoke(const std::string& why) override {
        std::lock_guard<std::mutex> lk(mtx_);
        ledger_.revoke(why, now_());
        emit_("[XMR-PARITY] REVOKED " + why);
        save_locked_();
    }

    // -----------------------------------------------------------------------
    // The worker side. Call from a thread that is allowed to be slow.
    //
    // Supplying evidence for a pending submit: the confirmation watch answers
    // later than the relay does, so the owner sets it before the drain that
    // should judge that block. A submit with no evidence and no daemon arm is
    // VOID, which is the honest answer -- relaying to peers is not acceptance.
    // -----------------------------------------------------------------------
    void set_submit_evidence(const Hash& block_id, const SubmitEvidence& ev) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (SubmitTrigger& s : submits_)
            if (s.verdict.block_id == block_id) s.evidence = ev;
    }

    // Runs every pending comparison. Returns the samples it produced, newest
    // last, so a caller can render or assert on them.
    std::vector<SeamResult> drain() {
        std::vector<SeamResult> out;
        std::optional<TipTrigger>    tip;
        std::optional<ServeTrigger>  serve;
        std::deque<SubmitTrigger>    subs;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            ++attempts_;
            tip.swap(tip_pending_);
            serve.swap(serve_pending_);
            subs.swap(submits_);
        }

        if (tip)   { if (auto r = run_tip_(*tip))      out.push_back(std::move(*r)); }
        if (serve) { if (auto r = run_template_(*serve)) out.push_back(std::move(*r)); }
        for (const SubmitTrigger& s : subs) out.push_back(run_submit_(s));

        std::lock_guard<std::mutex> lk(mtx_);
        if (out.empty()) {
            ledger_.note_no_sample();
        } else {
            const std::uint64_t t = now_();
            for (const SeamResult& r : out) {
                ledger_.record(r, t);
                emit_(render_sample(r));
                ++recorded_;
            }
            if (cfg_.autosave_every && recorded_ % cfg_.autosave_every == 0) save_locked_();
        }
        maybe_heartbeat_locked_();
        return out;
    }

    // -----------------------------------------------------------------------
    // Reading the verdict.
    // -----------------------------------------------------------------------
    const GraduationLedger& ledger() const noexcept { return ledger_; }
    GraduationLedger&       ledger()       noexcept { return ledger_; }
    std::uint64_t           attempts() const { std::lock_guard<std::mutex> lk(mtx_); return attempts_; }

    std::string verdict_report() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return render_verdict(ledger_, now_());
    }

    bool save(std::string* why = nullptr) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cfg_.ledger_path.empty()) { if (why) *why = "no ledger path configured"; return false; }
        return ledger_.save(cfg_.ledger_path, why);
    }

    // "Is the native node allowed to serve on its own?" -- the one question the
    // rest of the pool asks this component. Fail-closed by construction.
    bool graduated() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return ledger_.state() == GraduationState::Graduated;
    }

private:
    struct TipTrigger {
        node::MainchainEvent event{};
        std::string          side;
        std::uint64_t        at_unix   = 0;   // when the FIRST side reported it
        std::uint64_t        latest_at = 0;   // when the last side did
        bool                 after_reorg = false;
    };
    struct ServeTrigger {
        MinerDataEpoch  epoch{};
        node::MinerData served{};
        std::string     arm;
        std::uint64_t   at_unix = 0;
    };
    struct SubmitTrigger {
        BlockRelayVerdict verdict{};
        SubmitEvidence    evidence{};
        std::uint64_t     at_unix = 0;
    };

    std::uint64_t now_() const { return clock_ ? clock_() : 0; }

    void emit_(const std::string& line) const { if (log_) log_(line); }

    void save_locked_() {
        if (cfg_.ledger_path.empty()) return;
        std::string why;
        if (!ledger_.save(cfg_.ledger_path, &why) && !why.empty()) emit_("[XMR-PARITY] " + why);
    }

    void maybe_heartbeat_locked_() {
        const std::uint64_t t = now_();
        if (last_heartbeat_ != 0 && t < last_heartbeat_ + cfg_.heartbeat_interval_s) return;
        last_heartbeat_ = t;
        emit_(heartbeat_line(ledger_, attempts_, cfg_.heartbeat_interval_s));
    }

    ClassifierInputs classes_for_(std::uint64_t height, bool after_reorg,
                                  bool hardfork_edge,
                                  std::uint64_t block_weight,
                                  std::uint64_t effective_median) const {
        ClassifierInputs c;
        c.height           = height;
        c.epoch_blocks     = cfg_.epoch_blocks;
        c.epoch_lag        = cfg_.epoch_lag;
        c.after_reorg      = after_reorg;
        c.hardfork_edge    = hardfork_edge;
        c.block_weight     = block_weight;
        c.effective_median = effective_median;
        return c;
    }

    // --- P-TIP ---------------------------------------------------------------
    std::optional<SeamResult> run_tip_(const TipTrigger& t) {
        ArmObservation native = deps_.native_tip
            ? deps_.native_tip->observe()
            : no_observation("native", "no native tip observer configured");
        ArmObservation daemon = deps_.monerod_tip
            ? deps_.monerod_tip->observe()
            : no_observation("monerod", "no monerod tip observer configured");

        std::uint64_t weight = 0;
        const Obs& w = native.fields.get("block_weight");
        if (w.present) weight = std::strtoull(w.value.c_str(), nullptr, 10);

        bool hf_edge = false;
        const Obs& nv = native.fields.get("major_version");
        if (nv.present) {
            const std::uint64_t v = std::strtoull(nv.value.c_str(), nullptr, 10);
            if (last_major_ != 0 && v != last_major_) hf_edge = true;
            last_major_ = v;
        }

        CompareOptions opt;
        opt.classes = classes_for_(native.have ? native.height : t.event.block.height,
                                   t.after_reorg, hf_edge, weight, effective_median_());
        opt.context = "P-TIP first=" + t.side;

        if (native.have) last_tip_height_ = native.height;

        SeamResult r = compare_seam(TIP_SEAM, native, daemon, opt);

        // Lag is a MEASUREMENT: it appears in the note, it never scores.
        if (t.latest_at > t.at_unix) {
            const std::uint64_t lag = t.latest_at - t.at_unix;
            r.sample.note += " lag_s=" + Obs::u64(lag).value;
            if (lag > cfg_.tip_lag_warn_s)
                r.sample.note += " (over the " + Obs::u64(cfg_.tip_lag_warn_s).value + " s warn line)";
        }
        return r;
    }

    std::uint64_t effective_median_() const {
        // Only the native side can answer this, and only the concrete observer
        // knows it. A 0 means "unknown", which suppresses the PenaltyZone claim
        // rather than inventing one.
        if (auto* cv = dynamic_cast<ChainViewTipObserver*>(deps_.native_tip)) return cv->effective_median();
        return 0;
    }

    // --- P-TPL ---------------------------------------------------------------
    std::optional<SeamResult> run_template_(const ServeTrigger& s) {
        // What went out. This is the served side, verbatim.
        ArmObservation served = template_observation(s.arm.c_str(), s.served);

        // The shadow arm's own answer right now. If its tip has moved the
        // alignment key catches it and the sample is VOID.
        ArmObservation shadow = no_observation("shadow", "no shadow arm configured");
        if (deps_.shadow_arm) {
            std::string why;
            if (auto md = deps_.shadow_arm->snapshot(&why))
                shadow = template_observation(deps_.shadow_arm->name(), *md);
            else
                shadow = no_observation(deps_.shadow_arm->name(),
                                        why.empty() ? "shadow arm has no snapshot" : why);
        }

        // The cross-check: the SERVING arm's own answer, but only while its
        // epoch has not moved. Re-reading a moved epoch would compare two
        // different templates and call the difference a mismatch.
        ArmObservation cross;
        bool have_cross = false;
        if (deps_.served_arm && deps_.served_arm->epoch() == s.epoch) {
            std::string why;
            if (auto md = deps_.served_arm->snapshot(&why)) {
                cross = template_observation(deps_.served_arm->name(), *md);
                have_cross = true;
            }
        }

        CompareOptions opt;
        opt.classes = classes_for_(s.served.height, /*after_reorg=*/false,
                                   /*hardfork_edge=*/false, 0, 0);
        opt.context = "P-TPL served_by=" + s.arm;
        if (have_cross) opt.serving_arm_cross_check = &cross;

        // The one INVARIANT this seam can check without the assembler: the
        // template's median timestamp must be a real number when the native arm
        // produced it (monerod does not report one, which is why it is not an
        // EQUALITY row). A native arm that serves a zero here has lost its
        // 60-block window and would build a template monerod rejects.
        if (s.arm == "native") {
            NamedCheck c;
            c.name = "median_timestamp_present";
            c.ok   = s.served.median_timestamp != 0;
            c.detail = "native arm served median_timestamp=0 (60-block window lost)";
            opt.constraints.push_back(std::move(c));
        }

        return compare_seam(TEMPLATE_SEAM, served, shadow, opt);
    }

    // --- P-SUB ---------------------------------------------------------------
    SeamResult run_submit_(const SubmitTrigger& s) {
        CompareOptions opt;
        SubmitEvidence ev = s.evidence;
        if (ev.height == 0) ev.height = last_tip_height_;
        opt.classes = classes_for_(ev.height, false, false, 0, 0);
        opt.context = "P-SUB";
        return judge_submit(s.verdict, ev, opt);
    }

    Deps                deps_{};
    mutable std::mutex  mtx_;
    GraduationLedger    ledger_;
    ParityOracleConfig  cfg_;
    ClockFn             clock_;
    LogSink             log_;

    std::optional<TipTrigger>   tip_pending_;
    std::optional<ServeTrigger> serve_pending_;
    std::deque<SubmitTrigger>   submits_;

    std::uint64_t attempts_       = 0;
    std::uint64_t recorded_       = 0;
    std::uint64_t last_heartbeat_ = 0;
    std::uint64_t last_major_     = 0;
    std::uint64_t last_tip_height_ = 0;
};

} // namespace c2pool::xmr::native::parity
