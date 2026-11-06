// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// drain_controller.hpp: DASH staged ramp-down on exit (#866 action 2, coin side).
//
// Why: issue #866. p2pool-dash clips every share timestamp to prev+1..prev+39
// (data.py:239-242), and the retarget divides by those embedded stamps. When a
// large miner leaves abruptly, the floor stays far above what the remaining
// pool can sustain, and real cadence goes past 39 s/share. That is the
// saturation that built the 6.8 h share-clock lag seen on 2026-07-26. An exit
// spread over one TARGET_LOOKBEHIND window lets the retarget follow it down.
//
// What: an opt-in controller that sheds this node's stratum miners in N equal
// steps instead of all at once:
//   begin()   refuse new connections (core set_accepting(false)), so dropped
//             rigs cannot reconnect here, and snapshot the live session count.
//   step k    drop down to floor(initial * (N - k) / N) live sessions.
//   step N    0 live sessions. Accept stays off, and the node keeps running as
//             a share/block relay. The controller never exits the process and
//             never calls StratumServer::stop().
// The defaults are 4 steps of 25 share periods. 4 x 25 = 100 shares = one
// TARGET_LOOKBEHIND window.
//
// Policy lives HERE. The core hooks (src/core/stratum_server.hpp,
// set_accepting / drop_sessions / get_refused_draining, merged in #1870) have
// no policy. Core picks WHICH sessions to close (unauthorized first, then the
// lowest hashrate). This file decides only WHEN and HOW MANY.
//
// THREADING: begin() and step() must run on the stratum io thread. That is
// the one ioc.run() thread in main_dash; drop_sessions() requires it. Both
// check the injected on_io_thread() predicate. Off-thread calls are refused,
// logged and counted (off_thread_rejects). This check is a hard runtime check,
// not an assert(), so it stays on in Release builds. status() is safe from
// any thread: every field it reads is atomic.
//
// METRICS: core counts the connections refused while draining
// (get_refused_draining, cumulative since process start) but never logs them.
// Each step logs the refusals since the previous step and since begin(), and
// status() exposes the totals for the dashboard.
//
// Consensus-neutral: no share bytes, no timestamp stamping, no retarget code,
// and no won-block submit path. Only stratum admission and session count.
// ============================================================================

#include <core/log.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace dash::drain {

struct DrainConfig {
    uint32_t steps              = 4;    // equal ramp-down steps
    uint32_t step_share_periods = 25;   // step length, in share periods
};

// Flag bounds. A zero step count or step length would turn the drain back into
// the abrupt exit it exists to avoid, so main rejects both. The upper bounds
// only catch typos (1000 x 1000 x 20 s is about 230 days).
inline constexpr uint32_t kMaxSteps             = 1000;
inline constexpr uint32_t kMaxStepSharePeriods  = 1000;

/// Empty when cfg is usable, otherwise a one-line reason.
inline std::string validate(const DrainConfig& cfg)
{
    if (cfg.steps == 0 || cfg.steps > kMaxSteps)
        return "drain steps must be in 1.." + std::to_string(kMaxSteps);
    if (cfg.step_share_periods == 0 || cfg.step_share_periods > kMaxStepSharePeriods)
        return "drain step length must be in 1.." +
               std::to_string(kMaxStepSharePeriods) + " share periods";
    return {};
}

/// Live-session target after step k of `steps`, from `initial` sessions at
/// begin(). floor(initial * (steps - k) / steps). k == 0 gives initial, and
/// k >= steps gives 0. steps == 0 is treated as 1.
inline size_t target_after_step(size_t initial, uint32_t steps, uint32_t k)
{
    if (steps == 0) steps = 1;
    if (k >= steps) return 0;
    return static_cast<size_t>(
        (static_cast<uint64_t>(initial) * (steps - k)) / steps);
}

/// Wall-clock length of one step.
inline std::chrono::seconds step_period(const DrainConfig& cfg,
                                        uint32_t share_period_s)
{
    return std::chrono::seconds(
        static_cast<int64_t>(cfg.step_share_periods) * share_period_s);
}

enum class DrainState : uint8_t { Idle = 0, Draining = 1, Done = 2 };

inline const char* to_string(DrainState s)
{
    switch (s) {
    case DrainState::Idle:     return "idle";
    case DrainState::Draining: return "draining";
    case DrainState::Done:     return "done";
    }
    return "unknown";
}

struct DrainStatus {
    DrainState state{DrainState::Idle};
    uint32_t   step{0};                  // steps completed
    uint32_t   steps{0};
    uint64_t   initial_sessions{0};
    uint64_t   target_sessions{0};       // target after the last step
    uint64_t   dropped_total{0};
    uint64_t   refused_while_draining{0};  // new connections refused since begin()
    uint64_t   off_thread_rejects{0};
};

/// Server must provide the core::StratumServer drain surface:
///   void     set_accepting(bool)
///   size_t   get_session_count() const
///   size_t   drop_sessions(size_t)
///   uint64_t get_refused_draining() const
/// The KAT plugs in a fake. main_dash plugs in core::StratumServer.
template <class Server>
class RampDownController {
public:
    using IoThreadCheck = std::function<bool()>;

    RampDownController(Server& server, DrainConfig cfg, IoThreadCheck on_io_thread)
        : server_(server), cfg_(cfg), on_io_thread_(std::move(on_io_thread))
    {
        if (cfg_.steps == 0) cfg_.steps = 1;
    }

    /// Start the drain: refuse new connections and snapshot the live count.
    /// Returns false if a drain already started or the call is off-thread.
    bool begin()
    {
        if (!guard("begin")) return false;
        if (state_.load() != DrainState::Idle) {
            LOG_WARNING << "[DRAIN] begin ignored: already "
                        << to_string(state_.load());
            return false;
        }
        server_.set_accepting(false);
        refused_base_ = server_.get_refused_draining();
        refused_last_ = refused_base_;
        const uint64_t initial = server_.get_session_count();
        initial_.store(initial);
        target_.store(initial);
        step_.store(0);
        state_.store(DrainState::Draining);
        LOG_INFO << "[DRAIN] begin: refusing new stratum connections; "
                 << initial << " live session(s) shed over " << cfg_.steps
                 << " step(s) of " << cfg_.step_share_periods
                 << " share period(s)";
        return true;
    }

    /// Run the next step. Returns the number of sessions closed. Does nothing
    /// (returns 0) when not draining or when called off the io thread.
    size_t step()
    {
        if (!guard("step")) return 0;
        if (state_.load() != DrainState::Draining) return 0;

        const uint32_t k = step_.load() + 1;
        const uint64_t target = target_after_step(initial_.load(), cfg_.steps, k);
        // core's get_session_count() is sessions_.size(), and sessions_ is
        // pruned lazily (in notify_all and at the miner cap), so right after
        // a drop it still counts the sessions just closed. Accept is off
        // from begin(), so the live count can only fall: initial minus what
        // this drain closed is a hard ceiling. Without the cap, a stale
        // count makes a middle step close more than its share.
        const uint64_t initial  = initial_.load();
        const uint64_t dropped  = dropped_total_.load();
        const uint64_t ceiling  = initial > dropped ? initial - dropped : 0;
        const uint64_t reported = server_.get_session_count();
        const uint64_t live     = reported < ceiling ? reported : ceiling;
        const size_t closed =
            live > target ? server_.drop_sessions(static_cast<size_t>(live - target)) : 0;

        const uint64_t refused_now = server_.get_refused_draining();
        const uint64_t refused_step = refused_now - refused_last_;
        refused_last_ = refused_now;
        refused_total_.store(refused_now - refused_base_);

        dropped_total_.fetch_add(closed);
        target_.store(target);
        step_.store(k);
        if (k >= cfg_.steps) state_.store(DrainState::Done);

        LOG_INFO << "[DRAIN] step " << k << "/" << cfg_.steps << ": target "
                 << target << ", closed " << closed << " of " << live
                 << " live; refused while draining +" << refused_step
                 << " (total " << refused_total_.load() << ")";
        if (k >= cfg_.steps)
            LOG_INFO << "[DRAIN] done: new connections stay refused; node keeps"
                     << " relaying shares and blocks";
        return closed;
    }

    bool done() const { return state_.load() == DrainState::Done; }
    DrainState state() const { return state_.load(); }
    const DrainConfig& config() const { return cfg_; }

    DrainStatus status() const
    {
        DrainStatus s;
        s.state                  = state_.load();
        s.step                   = step_.load();
        s.steps                  = cfg_.steps;
        s.initial_sessions       = initial_.load();
        s.target_sessions        = target_.load();
        s.dropped_total          = dropped_total_.load();
        s.refused_while_draining = refused_total_.load();
        s.off_thread_rejects     = off_thread_rejects_.load();
        return s;
    }

private:
    bool guard(const char* what)
    {
        if (on_io_thread_ && on_io_thread_()) return true;
        off_thread_rejects_.fetch_add(1);
        LOG_ERROR << "[DRAIN] " << what
                  << " refused: not on the stratum io thread (drop_sessions"
                  << " requires it)";
        return false;
    }

    Server&       server_;
    DrainConfig   cfg_;
    IoThreadCheck on_io_thread_;

    std::atomic<DrainState> state_{DrainState::Idle};
    std::atomic<uint32_t>   step_{0};
    std::atomic<uint64_t>   initial_{0};
    std::atomic<uint64_t>   target_{0};
    std::atomic<uint64_t>   dropped_total_{0};
    std::atomic<uint64_t>   refused_total_{0};
    std::atomic<uint64_t>   off_thread_rejects_{0};
    // io-thread only (written in begin()/step(), both guarded).
    uint64_t refused_base_{0};
    uint64_t refused_last_{0};
};

/// Runs a RampDownController on an io_context timer: begin() at start(), then
/// one step() per period until done. The timer handler runs on the io thread,
/// so the controller's guard passes. ioc.stop() (plain SIGTERM) drops the
/// pending wait without running it, so a drain never delays shutdown.
template <class Server>
class RampDownScheduler {
public:
    RampDownScheduler(boost::asio::io_context& ioc,
                      RampDownController<Server>& ctl,
                      std::chrono::milliseconds period)
        : timer_(ioc), ctl_(ctl), period_(period) {}

    /// Begin the drain and arm the first step. False if begin() refused.
    bool start()
    {
        if (!ctl_.begin()) return false;
        arm();
        return true;
    }

    void cancel() { timer_.cancel(); }

private:
    void arm()
    {
        timer_.expires_after(period_);
        timer_.async_wait([this](const boost::system::error_code& ec) {
            if (ec) return;
            ctl_.step();
            if (!ctl_.done()) arm();
        });
    }

    boost::asio::steady_timer   timer_;
    RampDownController<Server>& ctl_;
    std::chrono::milliseconds   period_;
};

} // namespace dash::drain
