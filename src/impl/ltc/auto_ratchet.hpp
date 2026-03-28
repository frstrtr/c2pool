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
// Port of p2pool-v36 data.py AutoRatchet (lines 2109-2344).

#include "config_pool.hpp"
#include "share_tracker.hpp"
#include <core/log.hpp>

#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdint>
#include <fstream>
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

class AutoRatchet
{
public:
    // Thresholds (matching Python reference)
    static constexpr int ACTIVATION_THRESHOLD   = 95;  // % votes to activate
    static constexpr int DEACTIVATION_THRESHOLD = 50;  // % below which to revert
    static constexpr int CONFIRMATION_MULTIPLIER = 2;  // confirm after 2x CHAIN_LENGTH
    static constexpr int SWITCH_THRESHOLD = 60;        // % required for format switch in validation

    explicit AutoRatchet(const std::string& state_file_path = "",
                         int64_t target_version = 36)
        : state_file_(state_file_path)
        , target_version_(target_version)
    {
        load();
    }

    RatchetState state() const { return state_; }
    int64_t target_version() const { return target_version_; }

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

        // Count votes and actual new-format shares in window
        int32_t height = tracker.chain.get_height(best_share_hash);

        // Use absheight (monotonically increasing) for confirm_count tracking.
        // chain.get_height() returns chain DEPTH which plateaus after pruning
        // at ~CHAIN_LENGTH, preventing confirm_count from ever reaching 800.
        int32_t abs_height = 0;
        if (tracker.chain.contains(best_share_hash)) {
            tracker.chain.get(best_share_hash).share.invoke([&](auto* obj) {
                abs_height = static_cast<int32_t>(obj->m_absheight);
            });
        }
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
                state_ = RatchetState::ACTIVATED;
                activated_at_ = now_seconds();
                activated_height_ = abs_height;
                // Credit retroactive shares for late-joining nodes
                int32_t retroactive = std::max(0, abs_height - static_cast<int32_t>(chain_length));
                confirm_count_ = retroactive;
                last_seen_height_ = abs_height;

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
                // Track cumulative height increases using absheight (monotonic).
                // chain depth (get_height) plateaus at ~CHAIN_LENGTH after pruning,
                // preventing confirm_count from reaching 800. absheight always grows.
                if (last_seen_height_ > 0 && abs_height > last_seen_height_)
                    confirm_count_ += (abs_height - last_seen_height_);
                last_seen_height_ = abs_height;

                {
                    static int ac_log = 0;
                    if (ac_log++ % 20 == 0)
                        LOG_INFO << "[AutoRatchet] ACTIVATED: vote=" << vote_pct
                                 << "% share=" << share_pct << "% full=" << (full_window ? "True" : "False")
                                 << " height=" << abs_height
                                 << " confirm=" << confirm_count_ << "/" << confirmation_window
                                 << " chain_depth=" << height;
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

    /// Validate a version switch between consecutive shares.
    /// Returns empty string if valid, error message if invalid.
    /// Implements the 60% switch rule from Python check() method.
    static std::string validate_version_switch(
        int64_t share_version, int64_t prev_version,
        ShareTracker& tracker, const uint256& prev_hash)
    {
        // Same version — always ok
        if (share_version == prev_version)
            return {};

        int32_t height = tracker.chain.get_height(prev_hash);
        uint32_t chain_length = PoolConfig::chain_length();

        if (height < static_cast<int32_t>(chain_length))
        {
            // Not enough history for version switch
            if (share_version > prev_version)
                return "version switch without enough history";
            return {}; // downgrade ok without history
        }

        // Upgrade: requires 60% in sampling window [CHAIN_LENGTH*9/10, CHAIN_LENGTH]
        if (share_version == prev_version + 1)
        {
            uint32_t window_start = (chain_length * 9) / 10;
            uint32_t window_size = chain_length / 10;
            auto ancestor = tracker.chain.get_nth_parent_key(prev_hash, window_start);
            auto counts = tracker.get_desired_version_counts(ancestor, window_size);

            int64_t new_ver_count = 0;
            int64_t total_count = 0;
            for (auto& [ver, cnt] : counts)
            {
                total_count += cnt;
                if (ver >= share_version)
                    new_ver_count += cnt;
            }

            if (total_count > 0 && new_ver_count * 100 < total_count * SWITCH_THRESHOLD)
                return "version switch without enough hash power upgraded ("
                       + std::to_string(new_ver_count * 100 / total_count)
                       + "% < " + std::to_string(SWITCH_THRESHOLD) + "%)";
            return {};
        }

        // Downgrade by 1 (AutoRatchet deactivation): allowed
        if (share_version == prev_version - 1)
            return {};

        // Multi-version jump: not allowed
        return "invalid version jump from " + std::to_string(prev_version)
             + " to " + std::to_string(share_version);
    }

private:
    std::string state_file_;
    int64_t target_version_;
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
