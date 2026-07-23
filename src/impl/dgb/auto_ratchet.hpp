// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// AutoRatchet: autonomous share version transition state machine (DGB port).
//
// Manages DGB's <baseline> -> V36 share format transition without manual
// operator coordination. Persists state to JSON so restarts don't regress
// once the network has confirmed a new version.
//
// State machine (identical shape to ltc::AutoRatchet — bucket-2 v36-native
// shared structure, standardized cross-coin toward the v37 unified form):
//
//   VOTING -------(95% desired_version >= target)------> ACTIVATED
//     ^                                                      |
//     |---(<50% desired_version >= target)---<              |
//                                                            |
//     (sustained 2*CHAIN_LENGTH at 95% new-format shares)    |
//                                                            v
//   VOTING <--(follows old network, keeps voting)------- CONFIRMED
//     ^                                                      |
//     |---(<50% votes, network genuinely old)---<           |
//                       (permanent on restart)               |
//                       CONFIRMED <--------------------------+
//
// C++ implementation of the p2pool-v36 AutoRatchet design, mirroring
// src/impl/ltc/auto_ratchet.hpp.
//
// DGB DIVERGENCE FROM LTC (per operator 2026-06-17 re-scope): DGB's
// VOTING-state output version is a CONSTRUCTOR PARAMETER (base_version_), NOT
// the ltc hardcode `target_version_ - 1`. The "older than LTC" axis is the P2P
// PROTOCOL version (p2p.py VERSION=3501 vs LTC 3503), not the share version.
// BASELINE RESOLVED 2026-06-21: oracle frstrtr/p2pool-dgb-scrypt @22761e7
// mints share VERSION=35 (data.py:636, SUCCESSOR=None) => base_version=35.
// The production wire-in pins this constant in auto_ratchet_wire.hpp
// (make_dgb_ratchet); this module keeps the parameter explicit so the v37
// unified shape stays clean. The compile default (target-1) only applies to
// bare AutoRatchet(...) construction in tests.

#include "config_pool.hpp"
#include "share_tracker.hpp"
#include <core/log.hpp>

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <utility>

namespace dgb
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

class AutoRatchet
{
public:
    // Thresholds (matching Python reference — bucket-2 standardized).
    static constexpr int ACTIVATION_THRESHOLD   = 95;  // % votes to activate
    static constexpr int DEACTIVATION_THRESHOLD = 50;  // % below which to revert
    static constexpr int CONFIRMATION_MULTIPLIER = 2;  // confirm after 2x CHAIN_LENGTH
    static constexpr int SWITCH_THRESHOLD = 60;        // % required for format switch in validation

    // base_version: the share version DGB mints while VOTING. DGB-specific —
    // see file header. Defaults to target_version-1 only as a compile default.
    explicit AutoRatchet(const std::string& state_file_path = "",
                         int64_t target_version = 36,
                         int64_t base_version = -1)
        : state_file_(state_file_path)
        , target_version_(target_version)
        , base_version_(base_version >= 0 ? base_version : target_version - 1)
    {
        load();
    }

    RatchetState state() const { return state_; }
    int64_t target_version() const { return target_version_; }
    int64_t base_version() const { return base_version_; }

    /// Determine which share version to produce based on network state.
    /// Returns (share_version, desired_version_to_vote).
    std::pair<int64_t, int64_t> get_share_version(
        ShareTracker& tracker,
        const uint256& best_share_hash)
    {
        const int64_t current_version = base_version_; // DGB: oracle baseline, NOT target-1
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

        auto chain_view = tracker.chain.get_chain(best_share_hash, sample);
        for (auto [hash, data] : chain_view)
        {
            ++total;
            data.share.invoke([&](auto* obj) {
                if (static_cast<int64_t>(obj->m_desired_version) >= target_version_)
                    ++target_votes;
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
            if (full_window && vote_pct >= ACTIVATION_THRESHOLD)
            {
                // WORK-WEIGHTED tail guard (mint<->accept coupling). The
                // consensus accept gate (share_check step 2 / p2pool check()
                // data.py:1399) keys the 60% switch rule off
                // get_desired_version_counts, which in canonical p2pool
                // (data.py:2651) weights each share by
                // target_to_average_attempts(target) -- i.e. WORK, not a flat
                // head-count. AutoRatchet must evaluate the SAME work-weighted
                // 60% rule over the SAME [9/10*CL, CL] window before it
                // activates; otherwise a 95%-by-COUNT activation can outrun the
                // 60%-by-WORK accept gate, the node mints a V36 boundary share
                // every peer rejects, and the crossing wedges. (DGB accept gate
                // already work-weighted: #249/#289.)
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

                if (!tail_ok) {
                    static int tail_log = 0;
                    if (tail_log++ % 20 == 0)
                        LOG_INFO << "[AutoRatchet] VOTING: full window " << vote_pct
                                 << "% >= " << ACTIVATION_THRESHOLD << "% but oldest 10% work-weighted V"
                                 << target_version_ << " desire < " << SWITCH_THRESHOLD << "%) — waiting";
                    // Don't transition yet
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

    // F10 (per ltc): validate_version_switch is intentionally absent — the
    // single source of truth for the version-switch gate is share_check step 2,
    // which calls ShareTracker::get_desired_version_weights and matches p2pool
    // check() (data.py:1396-1414) exactly. The VOTING tail guard above stays
    // inline and work-weighted (mint<->accept coupling).

private:
    std::string state_file_;
    int64_t target_version_;
    int64_t base_version_;
    RatchetState state_ = RatchetState::VOTING;
    int64_t activated_at_ = 0;
    int32_t activated_height_ = 0;
    int64_t confirmed_at_ = 0;
    int32_t confirm_count_ = 0;
    int32_t last_seen_height_ = 0;

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
                     << " base=V" << base_version_
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
            j["base_version"] = base_version_;

            std::ofstream f(state_file_);
            f << j.dump(2);
        } catch (const std::exception& e) {
            LOG_WARNING << "[AutoRatchet] Failed to save state: " << e.what();
        }
    }
};

} // namespace dgb