// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB stratum work gate: no work while the node cannot work for the
// sharechain, so rigs fail over (python p2pool-dgb-scrypt work.py
// preprocess_request / get_work, stratum.py _send_work, which closes the
// connection when get_work raises):
//   - "p2pool is not connected to any peers": no sharechain peer on a PERSIST
//     network (DGB mainnet; testnet and regtest are not PERSIST);
//   - "lost contact with digibyted": no servable template for more than
//     60 s (python: time.time() > last_update + 60, "lost contact with
//     bitcoind", where last_update is the last successful work fetch).
//     Contact is a servable template: the embedded chain at its tip (with
//     its dialled coin peer handshaken, so a dead peer's stale tip does not
//     count), or a getblocktemplate from digibyted. A firewalled coin peer
//     with no RPC, a failing digibyted, or an embedded chain still syncing
//     with no GBT all hold, so rigs fail over;
//   - "p2pool is downloading shares": no best share on a PERSIST network
//     (python get_work), e.g. during the revive, so rigs fail over. If the
//     revive spends its budget (64 requests) with nothing verified, this
//     holds until a restart, as python would hold with best None.
// Python authorizes and then closes the connection; this node refuses
// mining.authorize with the reason (error 24), serves no template (no job),
// and closes the live sessions once a hold has lasted 15 s (about python's
// next work push): a deliberate, equivalent deviation. The share download,
// verification and the dormant-chain revive are not touched.
// ---------------------------------------------------------------------------

#include <core/log.hpp>

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
    bool check_contact = false;        // digibyted contact is checked
    int64_t coin_contact_age_sec = 0;  // since a template was last servable
    bool best_share_null = false;      // no best share yet
};

/// The reason work is held, or empty. Python's order: peers, contact
/// (preprocess_request), then the best share (get_work).
inline std::string work_gate_reason(const WorkGateInputs& in)
{
    if (in.require_peers && in.sharechain_peers == 0)
        return "p2pool is not connected to any peers";
    if (in.check_contact && in.coin_contact_age_sec > kCoinContactLostSec)
        return "lost contact with digibyted";
    if (in.require_peers && in.best_share_null)
        return "p2pool is downloading shares";
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

/// What one gate tick observes (main_dgb fills it on the IO thread).
struct WorkGateObservation {
    bool require_peers = false;     // mainnet
    size_t sharechain_peers = 0;    // the IO-published peer snapshot
    bool coin_dialled = false;      // --coin-daemon: a coin P2P peer exists
    bool coin_handshaken = false;   // ... and its handshake is complete now
    bool embedded_serves = false;   // work comes from the embedded chain
    bool template_servable = false; // the embedded chain serves, or digibyted's GBT answers
    bool best_share_null = false;   // the stratum best-share cell is null
};

struct WorkGateState {
    int64_t last_contact = 0;       // set to the start time by the caller
    WorkGateWatch watch;
};

/// Contact with digibyted now: a servable template, and while the embedded
/// chain serves with a dialled coin peer, that peer handshaken.
inline bool digibyted_contact(const WorkGateObservation& ob)
{
    if (!ob.template_servable)
        return false;
    if (ob.embedded_serves && ob.coin_dialled)
        return ob.coin_handshaken;
    return true;
}

/// One gate tick: the reason, the work source's hold, and the live sessions
/// closed once a hold has lasted kDropHeldSessionsAfterSec. Returns the reason.
template <typename WorkSourceT, typename ServerT>
std::string work_gate_tick(WorkGateState& st, const WorkGateObservation& ob, int64_t now_sec, WorkSourceT& ws,
                           ServerT& srv)
{
    if (digibyted_contact(ob))
        st.last_contact = now_sec;
    WorkGateInputs in;
    in.require_peers = ob.require_peers;
    in.sharechain_peers = ob.sharechain_peers;
    in.check_contact = true;
    in.coin_contact_age_sec = now_sec - st.last_contact;
    in.best_share_null = ob.best_share_null;
    const std::string reason = work_gate_reason(in);
    ws.set_work_hold(reason);
    if (st.watch.tick(reason, now_sec) == WorkGateWatch::Action::drop_sessions) {
        const size_t n = srv.drop_sessions(srv.get_session_count());
        if (n)
            LOG_WARNING << "[DGB-STRATUM] closed " << n << " miner session(s): " << reason;
    }
    return reason;
}

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
