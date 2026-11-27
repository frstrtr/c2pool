// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Rate limit for the "Stratum connection refused" WARN lines, one instance per
// refusal reason (core::StratumServer: the node cap, the per-IP cap). A client
// reconnecting against a full node logged one line per attempt -- 264k in one
// field log. The first refusal after a quiet window is logged at once, in
// full; later ones are counted, and at most one summary line per window says
// how many there were and which peer sent the most. The server's refusal
// counters are separate and still count every refusal.
#ifndef C2POOL_CORE_STRATUM_REFUSAL_LOG_HPP
#define C2POOL_CORE_STRATUM_REFUSAL_LOG_HPP

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace core {

// Not thread-safe: the server uses it on its io thread.
class RefusalLogLimiter {
public:
    using clock = std::chrono::steady_clock;

    explicit RefusalLogLimiter(clock::duration window = std::chrono::seconds(10))
        : window_(window) {}

    void set_window(clock::duration window) { window_ = window; }

    // One refusal from peer_ip. true: no line in the last window, so log this
    // one now in full. false: it is counted into the pending summary.
    // `detail` describes the reason as of this refusal ("node at miner cap
    // 100/100"); the summary carries the latest one. Call flush() first, so a
    // due summary goes out before a new window starts counting.
    bool record(clock::time_point now, const std::string& peer_ip, const std::string& detail)
    {
        if (pending_ == 0 && (!last_line_ || now - *last_line_ >= window_)) {
            last_line_ = now;
            return true;
        }
        ++pending_;
        // At most kMaxPendingPeers distinct peers are told apart; the rest
        // (a flood from many addresses) are counted together as "other".
        if (pending_peers_.size() < kMaxPendingPeers || pending_peers_.count(peer_ip))
            ++pending_peers_[peer_ip];
        else
            ++pending_other_;
        pending_detail_ = detail;
        return false;
    }

    // The summary of the refusals counted since the last line, once a window
    // has passed since that line; nullopt if nothing is pending or it is not
    // due yet. Emitting it starts a new window.
    std::optional<std::string> flush(clock::time_point now)
    {
        if (pending_ == 0 || !last_line_ || now - *last_line_ < window_)
            return std::nullopt;
        const auto top = top_peer();
        const long secs = std::lround(std::chrono::duration<double>(now - *last_line_).count());
        std::string s = std::to_string(pending_) + " more in the last " + std::to_string(secs)
                      + " s (" + pending_detail_ + ", top peer " + top.first + " x"
                      + std::to_string(top.second)
                      + (pending_other_ ? ", " + std::to_string(pending_other_) + " from other peers"
                                        : std::string{})
                      + ")";
        last_line_ = now;
        pending_ = 0;
        pending_peers_.clear();
        pending_other_ = 0;
        pending_detail_.clear();
        return s;
    }

    // When the pending summary is due; nullopt when nothing is pending.
    std::optional<clock::time_point> due() const
    {
        if (pending_ == 0 || !last_line_) return std::nullopt;
        return *last_line_ + window_;
    }

    uint64_t pending() const { return pending_; }
    /// Distinct peers told apart in the pending summary (at most
    /// kMaxPendingPeers).
    std::size_t pending_peers() const { return pending_peers_.size(); }
    static constexpr std::size_t kMaxPendingPeers = 1024;

private:
    // The peer with the most pending refusals (the lowest address on a tie).
    std::pair<std::string, uint64_t> top_peer() const
    {
        std::pair<std::string, uint64_t> best{"?", 0};
        for (const auto& [ip, n] : pending_peers_)
            if (n > best.second) best = {ip.empty() ? std::string("?") : ip, n};
        return best;
    }

    clock::duration window_;
    std::optional<clock::time_point> last_line_;   // the last line logged (full or summary)
    uint64_t pending_ = 0;
    std::map<std::string, uint64_t> pending_peers_;
    uint64_t pending_other_ = 0;   // past kMaxPendingPeers distinct peers
    std::string pending_detail_;
};

} // namespace core

#endif // C2POOL_CORE_STRATUM_REFUSAL_LOG_HPP
