// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// AutoRatchet: autonomous share version transition state machine.
//
// Manages V35 → V36 (and future) share format transitions without manual
// operator coordination. Persists state to JSON file so restarts don't
// regress once the network has confirmed a new version.
//
// State machine:
//
//   VOTING -------(95% desired_version >= target)------> ACTIVATED
//     ^                                                      |
//     |---(<50% desired_version >= target)---<                |
//                                                            |
//     (sustained 2*CHAIN_LENGTH at 95% new-format shares)    |
//                                                            v
//   VOTING <--(follows old network, keeps voting)------- CONFIRMED
//     ^                                                      |
//     |---(<50% votes, network genuinely old)---<            |
//                                                            |
//                       (permanent on restart)               |
//                       CONFIRMED <--------------------------+
//
// C++ implementation of the p2pool-v36 AutoRatchet design.

#include "config_pool.hpp"
#include "share_tracker.hpp"
#include <core/log.hpp>

#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <set>
#include <sstream>
#include <string>

namespace ltc
{

enum class RatchetState : uint8_t
{
    VOTING    = 0,  // producing old-format shares, voting for upgrade
    ACTIVATED = 1,  // producing new-format shares, monitoring support
    CONFIRMED = 2   // permanent: new format confirmed, survives restart
};

inline const char* ratchet_state_str(RatchetState s)
{
    switch (s) {
    case RatchetState::VOTING:    return "VOTING";
    case RatchetState::ACTIVATED: return "ACTIVATED";
    case RatchetState::CONFIRMED: return "CONFIRMED";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// OBSERVABILITY ONLY (no consensus surface).
//
// VOTING -> ACTIVATED has FOUR conditions. Until 08-02 a node stuck in VOTING
// logged only `state=VOTING` and, for two of the four, nothing at all: the two
// refusal lines lived INSIDE the `full_window && vote_pct >= 95` branch, so a
// window that was merely under-filled or under-voted produced total silence.
// A live LTC prod node sat like that for >10h while the dashboard showed 95.31%,
// and answering "why" required reading this source.
//
// RatchetBlocker names the FIRST unmet condition in evaluation order so the log
// is greppable and unambiguous — exactly one name, never a list of maybes.
// ---------------------------------------------------------------------------
enum class RatchetBlocker : uint8_t
{
    NONE           = 0,  // all four conditions met — activation proceeds
    WINDOW_FILL    = 1,  // (1) total < chain_length
    VOTE_PCT       = 2,  // (2) vote_pct < ACTIVATION_THRESHOLD
    TAIL_WORK      = 3,  // (3) oldest 10% carries < SWITCH_THRESHOLD% of WORK signalling
    SELF_VOTE_ONLY = 4   // (4) distinct non-self YES-vote authors < MIN_DISTINCT_NONSELF_AUTHORS
};

inline const char* ratchet_blocker_str(RatchetBlocker b)
{
    switch (b) {
    case RatchetBlocker::NONE:           return "none";
    case RatchetBlocker::WINDOW_FILL:    return "window-fill";
    case RatchetBlocker::VOTE_PCT:       return "vote-pct";
    case RatchetBlocker::TAIL_WORK:      return "tail-work";
    case RatchetBlocker::SELF_VOTE_ONLY: return "self-vote-only";
    }
    return "unknown";
}

// Tri-state for condition (3). The work-weighted tail guard is EXPENSIVE (it
// walks the oldest 10% of the window and tallies uint288 work weights) and the
// live path only measures it once conditions (1) and (2) already hold. When an
// earlier condition blocks, the tail is NOT_MEASURED and must be reported as
// `n/a` — a zero that silently means "not measured" is precisely the trap this
// whole change exists to remove.
enum class RatchetTail : uint8_t { NOT_MEASURED = 0, FAIL = 1, PASS = 2 };

class AutoRatchet
{
public:
    // Thresholds (matching Python reference)
    static constexpr int ACTIVATION_THRESHOLD   = 95;  // % votes to activate
    static constexpr int DEACTIVATION_THRESHOLD = 50;  // % below which to revert
    static constexpr int CONFIRMATION_MULTIPLIER = 2;  // confirm after 2x CHAIN_LENGTH
    static constexpr int SWITCH_THRESHOLD = 60;        // % required for format switch in validation
    // Mode-2 self-vote guard (07-28): minimum number of DISTINCT non-self
    // share authors whose YES-votes must back a 95% window before the ratchet
    // may ACTIVATE. Closes the second false-activation mode — a pool mining
    // ALONE driving its own desired_version to 95% and ratcheting itself into
    // V36 with zero external consent. 1 = "at least one externally-originated
    // yes-vote": the tightest bar that still permits the intended 2-node prod
    // crossing (voidbind + G2 dest), while rejecting a 100%-self window.
    static constexpr int MIN_DISTINCT_NONSELF_AUTHORS = 1;

    explicit AutoRatchet(const std::string& state_file_path = "",
                         int64_t target_version = 36)
        : state_file_(state_file_path)
        , target_version_(target_version)
    {
        load();
    }

    RatchetState state() const { return state_; }
    int64_t target_version() const { return target_version_; }

    /// OBSERVABILITY ONLY — pure, side-effect-free, no consensus surface.
    ///
    /// Names the FIRST unmet VOTING->ACTIVATED condition in the SAME order the
    /// live state machine evaluates them:
    ///   1. window-fill     total >= chain_length
    ///   2. vote-pct        vote_pct >= ACTIVATION_THRESHOLD (95)
    ///   3. tail-work       oldest 10% of the window carries >= SWITCH_THRESHOLD
    ///                      (60) percent of WORK signalling the target (WEIGHT,
    ///                      not head-count)
    ///   4. self-vote-only  distinct_nonself_authors >= MIN_DISTINCT_NONSELF_AUTHORS
    ///
    /// Returns NONE when all four hold. `tail` is a tri-state: NOT_MEASURED is
    /// treated as blocking on (3), which is unreachable from the live caller
    /// (it always measures the tail once (1) and (2) hold) but keeps this
    /// function total, so it can never report "activate" off an unmeasured tail.
    static RatchetBlocker first_unmet(bool full_window,
                                      int vote_pct,
                                      RatchetTail tail,
                                      int distinct_nonself_authors)
    {
        if (!full_window)                             return RatchetBlocker::WINDOW_FILL;
        if (vote_pct < ACTIVATION_THRESHOLD)          return RatchetBlocker::VOTE_PCT;
        if (tail != RatchetTail::PASS)                return RatchetBlocker::TAIL_WORK;
        if (distinct_nonself_authors < MIN_DISTINCT_NONSELF_AUTHORS)
            return RatchetBlocker::SELF_VOTE_ONLY;
        return RatchetBlocker::NONE;
    }

    /// Determine which share version to produce based on network state.
    /// Returns (share_version, desired_version_to_vote).
    ///
    /// current_version: the version we're currently producing (e.g. 36)
    /// target_version: the version we want to upgrade to (e.g. 37)
    std::pair<int64_t, int64_t> get_share_version(
        ShareTracker& tracker,
        const uint256& best_share_hash)
    {
        const int64_t current_version = target_version_ - 1; // e.g. 36
        const uint32_t chain_length = PoolConfig::chain_length();
        const uint32_t confirmation_window = chain_length * CONFIRMATION_MULTIPLIER;

        // No chain — use persisted state for bootstrap
        if (best_share_hash.IsNull() ||
            !tracker.chain.contains(best_share_hash) ||
            tracker.chain.get_height(best_share_hash) < 1)
        {
            if (state_ == RatchetState::CONFIRMED)
                return {target_version_, target_version_};
            return {current_version, target_version_};
        }

        // Count votes and actual new-format shares in window.
        // p2pool uses tracker.get_height() (chain depth) for both sampling
        // and confirmation counting. This matches data.py:2488,2576.
        int32_t height = tracker.chain.get_height(best_share_hash);
        int32_t sample = std::min(height, static_cast<int32_t>(chain_length));

        int32_t target_votes = 0;   // shares voting desired_version >= target
        int32_t target_shares = 0;  // shares actually IN target format
        int32_t total = 0;

        // Mode-2 self-vote guard: distinct NON-SELF origins among the YES-votes
        // in the activation window. "self" reuses node.cpp's canonical is_local
        // test — a locally minted share carries peer_addr == NetService{"0.0.0.0",0}
        // or the default NetService{}; a network share carries the relaying peer.
        // peer_addr is transient reception metadata, NOT part of the share hash,
        // so reading it here is consensus-neutral (see the ACTIVATE branch note).
        std::set<NetService> nonself_voting_authors;

        // OBSERVABILITY: depth (distance from the tip, 0 = tip) of the SHALLOWEST
        // — i.e. newest — share in the sample that does NOT signal the target.
        // Feeds the tail-guard ETA below. -1 = no such share in the sample.
        int32_t newest_nonsignal_depth = -1;

        auto chain_view = tracker.chain.get_chain(best_share_hash, sample);
        for (auto [hash, data] : chain_view)
        {
            ++total;
            const int32_t depth = total - 1;
            data.share.invoke([&](auto* obj) {
                if (static_cast<int64_t>(obj->m_desired_version) >= target_version_) {
                    ++target_votes;
                    const bool is_local = (obj->peer_addr == NetService{"0.0.0.0", 0} ||
                                           obj->peer_addr == NetService{});
                    if (!is_local)
                        nonself_voting_authors.insert(obj->peer_addr);
                }
                else if (newest_nonsignal_depth < 0) {
                    newest_nonsignal_depth = depth;   // get_chain walks tip -> parents
                }
                if (static_cast<int64_t>(std::remove_pointer_t<decltype(obj)>::version) >= target_version_)
                    ++target_shares;
            });
        }

        if (total == 0)
        {
            if (state_ == RatchetState::CONFIRMED)
                return {target_version_, target_version_};
            return {current_version, target_version_};
        }

        int vote_pct = (target_votes * 100) / total;
        int share_pct = (target_shares * 100) / total;
        bool full_window = (total >= static_cast<int32_t>(chain_length));

        // --- State transitions ---
        auto old_state = state_;

        if (state_ == RatchetState::VOTING)
        {
            // OBSERVABILITY scratch — carried out of the (possibly skipped)
            // measurement branch so the single explain-line below always has
            // the numbers that justify whatever it names.
            RatchetTail tail_state = RatchetTail::NOT_MEASURED;
            int tail_pct = -1;          // -1 => not measured => printed as n/a
            int32_t eta_shares = -1;    // -1 => not computable => omitted
            const int distinct_nonself_authors_obs =
                static_cast<int>(nonself_voting_authors.size());

            if (full_window && vote_pct >= ACTIVATION_THRESHOLD)
            {
                // Tail guard: oldest 10% of window must have >= 60% signaling
                // (jtoomim rule). Prevents activation before the entire PPLNS
                // window has transitioned — p2pool check() rejects V36 shares
                // when the oldest 10% has < 60% signaling.
                // WORK-WEIGHTED tail guard (mint<->accept coupling). The
                // consensus accept gate (share_check step 2 / p2pool check()
                // data.py:1399) keys the 60% switch rule off
                // get_desired_version_counts, which in canonical p2pool
                // (data.py:2651) weights each share by
                // target_to_average_attempts(target) -- i.e. WORK, not a flat
                // head-count. AutoRatchet must evaluate the SAME work-weighted
                // 60% rule over the SAME [9/10*CL, CL] window before it
                // activates; otherwise a 95%-by-COUNT activation can outrun the
                // 60%-by-WORK accept gate under heterogeneous hashrate, the node
                // mints a V36 boundary share that every peer rejects, and the
                // crossing wedges. The weighted tally makes activation strictly
                // imply the accept gate, so a minted boundary share can never be
                // rejected.
                uint32_t tail_start = (chain_length * 9) / 10;
                uint32_t tail_size  = chain_length / 10;
                auto tail_ancestor = tracker.chain.get_nth_parent_key(best_share_hash, tail_start);
                auto tail_weights = tracker.get_desired_version_weights(tail_ancestor, tail_size);

                // mapped_type is the work-weight accumulator (uint288); default 0.
                decltype(tail_weights)::mapped_type tail_target{}, tail_total{};
                for (auto& [ver, w] : tail_weights) {
                    tail_total = tail_total + w;
                    if (static_cast<int64_t>(ver) >= target_version_)
                        tail_target = tail_target + w;
                }
                // Canonical: counts.get(VERSION,0) < sum(counts)*60//100
                bool tail_ok = !(tail_target * uint32_t(100) < tail_total * uint32_t(SWITCH_THRESHOLD));

                // --- Mode-2 self-vote guard (07-28) ------------------------
                // Refuse to ACTIVATE on a self-authored window. The 07-14 guard
                // closed mode 1 (absence counted as a vote); this closes mode 2:
                // a pool mining ALONE can drive its own desired_version to 95%
                // and ratchet itself into V36 with ZERO external consent (the
                // contabo "72.25% on a ~100%-self window" incident). Require the
                // 95% YES-votes to originate from >= MIN_DISTINCT_NONSELF_AUTHORS
                // distinct non-self peers.
                //
                // CONSENSUS-NEUTRAL: reads peer_addr (transient reception
                // metadata, never serialized into the share hash) and only gates
                // when THIS node starts MINTING V36. The accept/validity path
                // keys v36_active off the share's OWN version
                // (share_check.hpp: v36_active = (share_ver >= 36)), NOT the
                // ratchet state — so a stricter activation can only DELAY our own
                // mint, never change the validity or work of any existing share.
                //
                // FAIL-SAFE: after a restart mid-VOTING, reconstructed shares may
                // carry an empty peer_addr and transiently understate external
                // authors — that DELAYS activation, never causes a false one.
                const int distinct_nonself_authors = static_cast<int>(nonself_voting_authors.size());
                const bool multi_party = distinct_nonself_authors >= MIN_DISTINCT_NONSELF_AUTHORS;

                // --- OBSERVABILITY ONLY from here to the `if (!tail_ok)` ------
                tail_state = tail_ok ? RatchetTail::PASS : RatchetTail::FAIL;
                // Largest p in [0,100] with tail_target*100 >= tail_total*p, i.e.
                // the floor'd work-weighted signalling percentage of the tail.
                // uint288 has no division, and this only runs once conditions (1)
                // and (2) already hold, so a 101-step descent is free. Measured
                // whether the guard passes or fails — `n/a` is reserved for the
                // case where the tail was genuinely never looked at.
                tail_pct = 0;
                if (!tail_total.IsNull()) {
                    for (int p = 100; p >= 0; --p) {
                        if (!(tail_target * uint32_t(100) < tail_total * uint32_t(p))) {
                            tail_pct = p;
                            break;
                        }
                    }
                }
                if (!tail_ok) {
                    // ETA: how many further shares until the tail window has
                    // rolled entirely past today's non-signalling shares.
                    //
                    // The tail is always depths [tail_start, tail_start+tail_size)
                    // from the tip. A share now at depth d sits at depth d+k after
                    // k new shares, so it has LEFT the tail once
                    // k >= tail_start + tail_size - d. Every share currently
                    // shallower than the tail will still pass through it, so the
                    // binding one is the SHALLOWEST non-signalling share, at depth
                    // newest_nonsignal_depth. Hence:
                    //
                    //     eta_shares = (tail_start + tail_size) - newest_nonsignal_depth
                    //
                    // ASSUMPTION, stated in the log as `<=`: every share minted
                    // from here on signals the target. It is therefore an UPPER
                    // bound — the 60%-by-work gate can clear earlier, since it
                    // needs 60%, not 100%. If the sample holds no non-signalling
                    // share at all the number is not derivable and we print none
                    // rather than a guess.
                    const int32_t tail_end = static_cast<int32_t>(tail_start + tail_size);
                    if (newest_nonsignal_depth >= 0 && newest_nonsignal_depth < tail_end)
                        eta_shares = tail_end - newest_nonsignal_depth;
                }
                // --- end observability ---------------------------------------

                if (!tail_ok) {
                    // Don't transition yet — explained by the single line below.
                }
                else if (!multi_party) {
                    // Don't transition yet — explained by the single line below.
                }
                else
                {
                state_ = RatchetState::ACTIVATED;
                activated_at_ = now_seconds();
                activated_height_ = height;
                // Credit retroactive shares for late-joining nodes
                // p2pool data.py:2535: retroactive = max(0, height - net.CHAIN_LENGTH)
                int32_t retroactive = std::max(0, height - static_cast<int32_t>(chain_length));
                confirm_count_ = retroactive;
                last_seen_height_ = height;

                LOG_INFO << "[AutoRatchet] VOTING -> ACTIVATED ("
                         << vote_pct << "% of " << total << " shares vote V"
                         << target_version_ << ", window=" << chain_length
                         << ", retroactive=" << retroactive << ")";

                // Skip to CONFIRMED if chain is already deep enough
                if (retroactive >= static_cast<int32_t>(confirmation_window) &&
                    share_pct >= ACTIVATION_THRESHOLD)
                {
                    state_ = RatchetState::CONFIRMED;
                    confirmed_at_ = now_seconds();
                    LOG_INFO << "[AutoRatchet] VOTING -> CONFIRMED (retroactive: "
                             << retroactive << " >= " << confirmation_window << ")";
                }
                save();
                } // else (tail guard passed)
            }

            // OBSERVABILITY ONLY — one greppable line per evaluation naming the
            // FIRST unmet condition, with the measurement AND the threshold that
            // justifies it. Rate-limited: on CHANGE of blocked-by, plus a
            // heartbeat every VOTING_EXPLAIN_HEARTBEAT evaluations. Emits
            // nothing once nothing blocks (the ACTIVATED transition above speaks
            // for itself).
            if (state_ == RatchetState::VOTING)
            {
                const RatchetBlocker blocker = first_unmet(
                    full_window, vote_pct, tail_state, distinct_nonself_authors_obs);
                log_voting_block(blocker, total, chain_length, vote_pct, tail_pct,
                                 distinct_nonself_authors_obs, eta_shares);
            }
        }
        else if (state_ == RatchetState::ACTIVATED)
        {
            if (full_window && vote_pct < DEACTIVATION_THRESHOLD)
            {
                // Network genuinely reverted
                state_ = RatchetState::VOTING;
                activated_at_ = 0;
                activated_height_ = 0;
                confirm_count_ = 0;
                last_seen_height_ = 0;
                LOG_INFO << "[AutoRatchet] ACTIVATED -> VOTING ("
                         << vote_pct << "% < " << DEACTIVATION_THRESHOLD << "% threshold)";
                save();
            }
            else if (activated_height_ > 0)
            {
                // Track cumulative height increases using chain depth.
                // p2pool data.py:2576: uses tracker.get_height() (chain depth).
                if (last_seen_height_ > 0 && height > last_seen_height_)
                    confirm_count_ += (height - last_seen_height_);
                last_seen_height_ = height;

                {
                    static int ac_log = 0;
                    if (ac_log++ % 20 == 0)
                        LOG_INFO << "[AutoRatchet] ACTIVATED: vote=" << vote_pct
                                 << "% share=" << share_pct << "% full=" << (full_window ? "True" : "False")
                                 << " height=" << height
                                 << " confirm=" << confirm_count_ << "/" << confirmation_window;
                }

                if (confirm_count_ >= static_cast<int32_t>(confirmation_window) &&
                    share_pct >= ACTIVATION_THRESHOLD)
                {
                    state_ = RatchetState::CONFIRMED;
                    confirmed_at_ = now_seconds();
                    LOG_INFO << "[AutoRatchet] ACTIVATED -> CONFIRMED ("
                             << confirm_count_ << " cumulative shares, "
                             << share_pct << "% V" << target_version_ << ")";
                    save();
                }
            }
        }
        else if (state_ == RatchetState::CONFIRMED)
        {
            // CONFIRMED is permanent, but respect network consensus
            if (full_window && vote_pct < DEACTIVATION_THRESHOLD)
            {
                LOG_WARNING << "[AutoRatchet] CONFIRMED but network is "
                            << (100 - vote_pct) << "% old version — following consensus";
                return {current_version, target_version_};
            }
        }

        if (old_state != state_)
        {
            LOG_INFO << "[AutoRatchet] State: " << ratchet_state_str(old_state)
                     << " -> " << ratchet_state_str(state_);
        }

        // Output
        if (state_ == RatchetState::ACTIVATED || state_ == RatchetState::CONFIRMED)
            return {target_version_, target_version_};
        else
            return {current_version, target_version_};
    }

    // F10: validate_version_switch was removed — it was dead (0 callers) and
    // diverged from canonical p2pool (it weighted by flat COUNT with a `>=`
    // sum, vs canonical's PPLNS-weighted EXACT-version 60% rule). The single
    // source of truth for the version-switch gate is now share_check step 2,
    // which calls ShareTracker::get_desired_version_weights and matches
    // p2pool check() (data.py:1396-1414) exactly. The VOTING tail guard above
    // is ALSO work-weighted: it calls ShareTracker::get_desired_version_weights
    // over the oldest 10% of the window and couples activation to that same
    // check()-phase 60% accept gate (mint<->accept coupling). It is NOT
    // count-based -- a flat-count tail guard would let a 95%-by-count activation
    // outrun the 60%-by-work accept gate and wedge the crossing.

public:
    // Heartbeat period for the VOTING explain-line, in evaluations. The ratchet
    // is evaluated once per share, so this bounds the line to roughly one per
    // 60 shares (~15 min at LTC's 15s share period) when nothing is changing.
    static constexpr int VOTING_EXPLAIN_HEARTBEAT = 60;

private:
    std::string state_file_;
    int64_t target_version_;
    RatchetState state_ = RatchetState::VOTING;
    int64_t activated_at_ = 0;
    int32_t activated_height_ = 0;
    int64_t confirmed_at_ = 0;
    int32_t confirm_count_ = 0;
    int32_t last_seen_height_ = 0;

    // OBSERVABILITY ONLY — VOTING explain-line rate limiter. Per-instance, not
    // a function-local static: a function-local static in this header-inline
    // method is shared across every AutoRatchet in the process.
    RatchetBlocker last_blocker_ = RatchetBlocker::NONE;
    bool blocker_logged_once_ = false;
    int evals_since_block_log_ = 0;

    /// OBSERVABILITY ONLY. Emits at most one line naming exactly ONE blocking
    /// condition, always carrying the measured value AND its threshold.
    void log_voting_block(RatchetBlocker blocker,
                          int32_t total, uint32_t chain_length,
                          int vote_pct, int tail_pct,
                          int distinct_nonself_authors,
                          int32_t eta_shares)
    {
        if (blocker == RatchetBlocker::NONE) {
            // Nothing blocks: reset the limiter so the next block re-announces.
            last_blocker_ = RatchetBlocker::NONE;
            blocker_logged_once_ = false;
            evals_since_block_log_ = 0;
            return;
        }

        const bool changed = (!blocker_logged_once_ || blocker != last_blocker_);
        if (!changed && ++evals_since_block_log_ < VOTING_EXPLAIN_HEARTBEAT)
            return;
        last_blocker_ = blocker;
        blocker_logged_once_ = true;
        evals_since_block_log_ = 0;

        std::ostringstream line;
        line << "[AutoRatchet] VOTING blocked-by=" << ratchet_blocker_str(blocker)
             << " window=" << total << "/" << chain_length
             << " vote=" << vote_pct << "% (need " << ACTIVATION_THRESHOLD << ")"
             << " tail10%work=";
        if (tail_pct < 0) line << "n/a";              // NOT measured — never "0"
        else              line << tail_pct << "%";
        line << " (need " << SWITCH_THRESHOLD << ")"
             << " nonself_authors=" << distinct_nonself_authors
             << " (need " << MIN_DISTINCT_NONSELF_AUTHORS << ")";

        // ETA is emitted ONLY for the tail guard, and only when derivable.
        if (blocker == RatchetBlocker::TAIL_WORK && eta_shares > 0) {
            const uint32_t period = PoolConfig::share_period();
            line << " eta_shares<=" << eta_shares;
            if (period > 0) {
                const double hours =
                    (static_cast<double>(eta_shares) * static_cast<double>(period)) / 3600.0;
                std::ostringstream h;
                h.setf(std::ios::fixed, std::ios::floatfield);
                h.precision(1);
                h << hours;
                line << " eta<=" << h.str() << "h";
            }
        }
        LOG_INFO << line.str();
    }

    static int64_t now_seconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void load()
    {
        if (state_file_.empty()) return;
        try {
            std::ifstream f(state_file_);
            if (!f.is_open()) return;
            nlohmann::json j;
            f >> j;
            std::string s = j.value("state", "voting");
            if (s == "activated") state_ = RatchetState::ACTIVATED;
            else if (s == "confirmed") state_ = RatchetState::CONFIRMED;
            else state_ = RatchetState::VOTING;
            activated_at_ = j.value("activated_at", int64_t(0));
            activated_height_ = j.value("activated_height", int32_t(0));
            confirmed_at_ = j.value("confirmed_at", int64_t(0));
            confirm_count_ = j.value("confirm_count", int32_t(0));
            LOG_INFO << "[AutoRatchet] Loaded state: " << ratchet_state_str(state_)
                     << " (target=V" << target_version_
                     << " confirmed_at=" << confirmed_at_
                     << " confirm_count=" << confirm_count_ << ")";
        } catch (const std::exception& e) {
            LOG_WARNING << "[AutoRatchet] Failed to load state: " << e.what();
        }
    }

    void save()
    {
        if (state_file_.empty()) return;
        try {
            nlohmann::json j;
            switch (state_) {
            case RatchetState::VOTING:    j["state"] = "voting"; break;
            case RatchetState::ACTIVATED: j["state"] = "activated"; break;
            case RatchetState::CONFIRMED: j["state"] = "confirmed"; break;
            }
            j["activated_at"] = activated_at_;
            j["activated_height"] = activated_height_;
            j["confirmed_at"] = confirmed_at_;
            j["confirm_count"] = confirm_count_;
            j["target_version"] = target_version_;

            std::ofstream f(state_file_);
            f << j.dump(2);
        } catch (const std::exception& e) {
            LOG_WARNING << "[AutoRatchet] Failed to save state: " << e.what();
        }
    }
};

} // namespace ltc