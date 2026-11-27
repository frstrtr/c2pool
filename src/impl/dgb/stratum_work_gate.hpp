// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB stratum work gate: no work while the node has no sharechain peers or
// has lost contact with digibyted, so rigs fail over (python
// p2pool-dgb-scrypt work.py preprocess_request / get_work, stratum.py
// _send_work, which closes the connection when get_work raises):
//   - "p2pool is not connected to any peers": no sharechain peer on a PERSIST
//     network (DGB mainnet; testnet and regtest are not PERSIST);
//   - "lost contact with digibyted": the coin peer has not been seen
//     handshaken for more than 60 s (python: last_update + 60).
// While held, the work source serves no template (no job) and refuses
// mining.authorize with the reason; once a hold has lasted 15 s (about
// python's next work push) the live sessions are closed once. The share
// download and verification are not touched.
// ---------------------------------------------------------------------------

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace dgb {

inline constexpr int64_t kCoinContactLostSec = 60;         // work.py: time.time() > last_update + 60
inline constexpr int64_t kDropHeldSessionsAfterSec = 15;
inline constexpr std::chrono::milliseconds kWorkGateTick{1000};

struct WorkGateInputs {
    bool require_peers = false;        // net.PERSIST: DGB mainnet only
    size_t sharechain_peers = 0;
    bool coin_daemon = false;          // a coin peer is dialled (--coin-daemon)
    int64_t coin_contact_age_sec = 0;  // since the coin peer was last seen handshaken
};

/// The reason work is held, or empty. Python's order: peers, then contact.
inline std::string work_gate_reason(const WorkGateInputs& in)
{
    if (in.require_peers && in.sharechain_peers == 0)
        return "p2pool is not connected to any peers";
    if (in.coin_daemon && in.coin_contact_age_sec > kCoinContactLostSec)
        return "lost contact with digibyted";
    return {};
}

/// Per tick: says when a hold has lasted long enough to close the live
/// sessions (once per hold).
class WorkGateWatch {
public:
    enum class Action { none, drop_sessions };
    Action tick(const std::string& reason, int64_t now_sec)
    {
        if (reason.empty()) {
            held_since_ = -1;
            dropped_ = false;
            return Action::none;
        }
        if (held_since_ < 0)
            held_since_ = now_sec;
        if (!dropped_ && now_sec - held_since_ >= kDropHeldSessionsAfterSec) {
            dropped_ = true;
            return Action::drop_sessions;
        }
        return Action::none;
    }

private:
    int64_t held_since_ = -1;
    bool dropped_ = false;
};

/// Runs `fn` on `ioc` every `tick` until the returned stop function is called.
inline std::function<void()> start_periodic(boost::asio::io_context& ioc, std::chrono::milliseconds tick,
                                            std::function<void()> fn)
{
    struct State {
        boost::asio::steady_timer timer;
        bool stopped = false;
        explicit State(boost::asio::io_context& io) : timer(io) {}
    };
    auto st = std::make_shared<State>(ioc);
    auto loop = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak = loop;
    *loop = [st, tick, fn, weak]() {
        if (st->stopped)
            return;
        fn();
        st->timer.expires_after(tick);
        st->timer.async_wait([st, weak](const boost::system::error_code& ec) {
            if (ec || st->stopped)
                return;
            if (auto f = weak.lock())
                (*f)();
        });
    };
    boost::asio::post(ioc, [loop]() { (*loop)(); });
    return [st, loop]() mutable {
        st->stopped = true;
        st->timer.cancel();
        loop.reset();
    };
}

} // namespace dgb
