// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// Push clean stratum jobs when the work changes (c2pool-dgb).
//
// DGB never bumped the work generation on a new DGB tip and never called
// StratumServer::notify_all: a miner got a new job only from the 25 s
// keepalive (DGBWorkSource keepalive_notify_sec), and non-clean, so after each
// 15 s DGB block it kept hashing stale work for up to ~37 s. A bumped
// generation (best share change, fresh DOGE commitment) also waited for that
// tick.
//
// A 1 s watcher on the io context, beside the stratum server:
//   - the job prevhash (DGBWorkSource::get_current_gbt_prevhash, the same
//     source the jobs use) changed: bump the work generation and push clean
//     jobs to every session (the old work is on a dead tip);
//   - the work generation changed (new best share, new DOGE commitment): push
//     clean jobs (the old ones build on the previous best share), as the LTC
//     lane does (trigger_work_refresh -> notify_all(force_clean)).
// One push per tick at most: the tick is the debounce.
// ---------------------------------------------------------------------------

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace dgb {

/// The decision of one tick (pure, so it is pinned without a server).
class JobPushWatch {
public:
    enum class Action { none, push, bump_and_push };

    Action tick(const std::string& prevhash, uint64_t generation)
    {
        if (!primed_) {
            primed_ = true;
            prevhash_ = prevhash;
            generation_ = generation;
            return Action::none;
        }
        if (!prevhash.empty() && prevhash != prevhash_) {
            prevhash_ = prevhash;
            generation_ = generation + 1;   // the bump this action asks for
            return Action::bump_and_push;
        }
        if (generation != generation_) {
            generation_ = generation;
            return Action::push;
        }
        return Action::none;
    }

private:
    bool primed_ = false;
    std::string prevhash_;
    uint64_t generation_ = 0;
};

inline constexpr std::chrono::milliseconds kJobPushTick{1000};

/// Runs the watch on `ioc` every kJobPushTick until the returned stop handle
/// is called (or the io context stops). WorkSourceT: get_current_gbt_prevhash,
/// get_work_generation, bump_work_generation. `push(clean)` pushes the jobs
/// (main_dgb: stratum_server->notify_all(true)).
/// `before_tick` (optional) runs at the start of every tick (main_dgb: the
/// best-share cell's periodic refresh).
template <typename WorkSourceT>
std::function<void()> start_job_push_watch(boost::asio::io_context& ioc, WorkSourceT* ws,
                                           std::function<void(bool clean)> push,
                                           std::chrono::milliseconds tick = kJobPushTick,
                                           std::function<void()> before_tick = {})
{
    struct State {
        JobPushWatch watch;
        boost::asio::steady_timer timer;
        bool stopped = false;
        explicit State(boost::asio::io_context& io) : timer(io) {}
    };
    auto st = std::make_shared<State>(ioc);
    auto loop = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = loop;
    *loop = [st, ws, push, tick, weak, before_tick]() {
        if (st->stopped)
            return;
        if (before_tick)
            before_tick();
        switch (st->watch.tick(ws->get_current_gbt_prevhash(), ws->get_work_generation())) {
        case JobPushWatch::Action::bump_and_push:
            ws->bump_work_generation();
            if (push)
                push(true);
            break;
        case JobPushWatch::Action::push:
            if (push)
                push(true);
            break;
        case JobPushWatch::Action::none:
            break;
        }
        st->timer.expires_after(tick);
        st->timer.async_wait([st, weak](const boost::system::error_code& ec) {
            if (ec || st->stopped)
                return;
            if (auto f = weak.lock())
                (*f)();
        });
    };
    boost::asio::post(ioc, [loop]() { (*loop)(); });
    // The handle keeps the loop alive until stop.
    return [st, loop]() mutable {
        st->stopped = true;
        st->timer.cancel();
        loop.reset();
    };
}

} // namespace dgb
