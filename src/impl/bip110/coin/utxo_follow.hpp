// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::UtxoFollower -- keeps c2pool-bip110's own UTXO view on the
// header chain's active chain, block by block. main_bip110.cpp gives it the
// view, the chain, the connect / rollback / re-anchor of the view and the coin
// peer pool's body fetch (UtxoFollowHost); the KATs drive it with fakes.
//
//   - A body (the pool's on_body_in_order) connects only if it is the active
//     chain's block right after the view's best; while the view is empty, an
//     active block at or above tip - kInFlight anchors it (an older one, such
//     as a late catch-up body, does not: it would anchor behind the tip only
//     to be re-anchored). See utxo_connect_gate.
//   - One that does not connect is kept (SideBodies, the last kKeptMax): one
//     of a branch not followed yet, one above a gap, a competing block at or
//     below the view's height. An active block at or below the view's height
//     (the view holds it) and a too-old anchor are not kept.
//   - Kept bodies are offered again after every body, on every header tip
//     change (before anything else: a branch that just became active may
//     extend the view without a rollback) and on each catch-up step; one that
//     is the next block then connects.
//   - Tip change: if the view's best left the active chain, the view is rolled
//     back to the fork, then the kept bodies connect. If the rollback fails
//     (the host's rollback leaves the view as the backing DB had it, nothing
//     half-undone), the view is SUSPENDED -- no connect until it is re-anchored
//     -- and re-anchored at once; a failed re-anchor is retried every
//     kReanchorRetrySec (on_tick), whatever the header sync.
//   - Catch-up step (the pool driver, every kCoinPoolPollSec, once header sync
//     is caught up):
//       * an empty view: the tip's body is fetched, to anchor the view;
//       * the view's best off the active chain (a view from another branch at
//         start): rolled back, else suspended and re-anchored;
//       * behind the tip by more than kReanchorGap blocks: re-anchored (wiped;
//         the tip's body is fetched to anchor it again): the view would need
//         more than kReanchorGap bodies (up to ~800 kB each under the RDTS cap)
//         and a rollback can never reach below the undo horizon
//         (BIP110_KEEP_DEPTH == kReanchorGap) anyway;
//       * behind, and its best has not moved for kStuckReanchorSec (the next
//         block's body did not come): an ERROR and a re-anchor at the tip,
//         rather than the serve gate shut until the gap passes kReanchorGap
//         (~48 h);
//       * else the active chain's next kInFlight blocks after the view's best
//         that are not kept are fetched (the pool holds a body that arrives
//         before its parent, at most kCoinPoolMaxBodyGap of them; kInFlight
//         leaves room for the tip's).
//     A block is fetched again only after kRefetchSec.
//   - fresh(): the serve gate's view term: the view's best is on the active
//     chain and at most kServeMaxLag blocks below the tip. kServeMaxLag is 0:
//     until the tip block's body is connected the mempool still holds the
//     transactions that block confirmed, so a template on the tip could carry
//     them again. A connect that makes fresh() true (the tip's body, a kept or
//     caught-up body reaching the tip, the first after a re-anchor) calls
//     on_fresh: main bumps the work generation, as the tip header did while
//     the gate was shut, so miners get the populated work.
// IO thread only, except fresh() (it reads only the host's view and chain).

#include "block.hpp"
#include "header_chain.hpp"   // block_hash
#include "utxo_side_bodies.hpp"

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace bip110::coin {

/// Where a block body stands for the view's connect.
enum class UtxoConnectGate {
    Connect,         // the active chain's next block after the view's best (or the first anchor)
    Below,           // at or below the view's best height
    NotContiguous,   // its parent is not the view's best
    NotActive,       // not the active chain's block at its height
    StaleAnchor,     // the view is empty and the block is below the anchor floor
};

inline const char* utxo_connect_gate_name(UtxoConnectGate g)
{
    switch (g) {
    case UtxoConnectGate::Connect:       return "connect";
    case UtxoConnectGate::Below:         return "at or below the view's best";
    case UtxoConnectGate::NotContiguous: return "non-contiguous";
    case UtxoConnectGate::NotActive:     return "not on the active chain";
    case UtxoConnectGate::StaleAnchor:   return "too old to anchor the view";
    }
    return "?";
}

/// view_best / view_height: the view's best (a null hash: the view is empty);
/// id / prev / height: the block's identity, parent and height; active: the
/// active chain's block at that height (nullopt: none); anchor_floor: the
/// lowest height that may anchor an empty view.
inline UtxoConnectGate utxo_connect_gate(const uint256& view_best, uint32_t view_height,
                                         const uint256& id, const uint256& prev, uint32_t height,
                                         const std::optional<uint256>& active,
                                         uint32_t anchor_floor = 0)
{
    if (!view_best.IsNull()) {
        if (height <= view_height)
            return UtxoConnectGate::Below;
        if (prev != view_best)
            return UtxoConnectGate::NotContiguous;
    } else if (height < anchor_floor) {
        return UtxoConnectGate::StaleAnchor;
    }
    if (!active || *active != id)
        return UtxoConnectGate::NotActive;
    return UtxoConnectGate::Connect;
}

/// The view's best is on the active chain (`active_at`:
/// std::optional<uint256>(uint32_t)) and at most max_lag blocks below the tip.
template <typename ActiveAt>
inline bool utxo_view_fresh(const uint256& view_best, uint32_t view_height, uint32_t tip_height,
                            const ActiveAt& active_at, uint32_t max_lag)
{
    if (view_best.IsNull() || view_height > tip_height || tip_height - view_height > max_lag)
        return false;
    const std::optional<uint256> at = active_at(view_height);
    return at && *at == view_best;
}

/// What the follower needs from main_bip110.cpp.
struct UtxoFollowHost {
    using Clock = std::chrono::steady_clock;

    /// The view's best (hash, height); a null hash: empty.
    std::function<std::pair<uint256, uint32_t>()> view;
    /// The header tip's height; the active chain's block at a height; the
    /// height of a header the chain holds.
    std::function<uint32_t()>                               tip_height;
    std::function<std::optional<uint256>(uint32_t)>         active_at;
    std::function<std::optional<uint32_t>(const uint256&)>  height_of;
    /// Connect a block utxo_connect_gate allows; true if connected.
    std::function<bool(const BlockType&, uint32_t height)>  connect;
    /// After kept bodies were connected (optional): the UTXO-based mempool
    /// passes.
    std::function<void()>                                   after_kept;
    /// A connect made the view fresh (optional): the work bump.
    std::function<void()>                                   on_fresh;
    /// Roll the view back to its fork with the active chain; true if done.
    /// On false the view must be as the backing DB had it before the call
    /// (bip110::coin::reorg_disconnect_or_discard).
    std::function<bool()>                                   rollback;
    /// Wipe the view (the next connect anchors it); true if done.
    std::function<bool()>                                   reanchor;
    /// getdata for these bodies (the coin peer pool's fetch_bodies; optional).
    std::function<void(const std::vector<uint256>&)>       fetch;
    /// The clock (optional; tests drive it).
    std::function<Clock::time_point()>                      now;
};

class UtxoFollower {
public:
    using Clock = UtxoFollowHost::Clock;

    static constexpr size_t   kKeptMax          = 8;
    static constexpr size_t   kInFlight         = 4;
    static constexpr uint32_t kReanchorGap      = 288;
    static constexpr uint32_t kServeMaxLag      = 0;
    static constexpr int64_t  kRefetchSec       = 30;
    static constexpr int64_t  kReanchorRetrySec = 60;
    static constexpr int64_t  kStuckReanchorSec = 20 * 60;

    enum class Step { None, Anchor, Fetch, Rollback, Reanchor, ReanchorFailed };
    struct CatchUp {
        Step                 step{Step::None};
        uint32_t             lag{0};
        std::vector<uint256> fetched;
    };
    enum class TipChange { None, RolledBack, RollbackFailed };

    explicit UtxoFollower(UtxoFollowHost host) : m_host(std::move(host)), m_kept(kKeptMax) {}

    /// A body for the view: connected if the gate allows, else kept (see the
    /// header); then the kept bodies. True if `block` was connected.
    bool on_body(const BlockType& block)
    {
        const Tried r = try_connect(block, /*log_skip=*/true);
        if (!r.connected && !m_suspended && r.known && keep_worthy(r))
            m_kept.keep(block);
        connect_kept();
        return r.connected;
    }

    /// The header tip changed: the kept bodies first; then, if the view's
    /// best left the active chain, the rollback to the fork and the kept
    /// bodies again; a failed rollback suspends and re-anchors the view now.
    TipChange on_tip_changed()
    {
        connect_kept();
        const auto [best, height] = view();
        if (best.IsNull() || on_active(best, height))
            return TipChange::None;
        if (m_host.rollback && m_host.rollback()) {
            connect_kept();
            return TipChange::RolledBack;
        }
        m_suspended = true;
        CatchUp ignored;
        reanchor(tip(), "a rollback to the fork failed", ignored, /*error=*/true);
        return TipChange::RollbackFailed;
    }

    /// The pool driver's tick: a suspended view's re-anchor (whatever the
    /// header sync), else the catch-up step once header sync is caught up.
    CatchUp on_tick(bool header_sync_caught_up)
    {
        if (m_suspended) {
            CatchUp out;
            out.step = reanchor(tip(), "suspended after a failed rollback", out, true)
                ? Step::Reanchor : Step::ReanchorFailed;
            return out;
        }
        return header_sync_caught_up ? catch_up() : CatchUp{};
    }

    /// One catch-up step.
    CatchUp catch_up()
    {
        CatchUp out;
        if (m_suspended) {
            out.step = reanchor(tip(), "suspended after a failed rollback", out, true)
                ? Step::Reanchor : Step::ReanchorFailed;
            return out;
        }
        const uint32_t t_h = tip();
        auto [best, height] = view();
        if (best.IsNull()) {
            out.step = Step::Anchor;
            reset_stuck();
            connect_kept();
            std::tie(best, height) = view();
            if (best.IsNull())
                fetch_heights(t_h, t_h, out);
            return out;
        }
        if (!on_active(best, height)) {
            if (m_host.rollback && m_host.rollback()) {
                out.step = Step::Rollback;
                connect_kept();
                return out;
            }
            m_suspended = true;
            out.step = reanchor(t_h, "its best is off the active chain", out, true)
                ? Step::Reanchor : Step::ReanchorFailed;
            return out;
        }
        if (height >= t_h) {
            reset_stuck();
            return out;
        }
        out.lag = t_h - height;
        if (out.lag > kReanchorGap) {
            out.step = reanchor(t_h, "too far behind the tip", out, false) ? Step::Reanchor
                                                                           : Step::ReanchorFailed;
            return out;
        }
        const auto t = now();
        if (best != m_stuck_best) {
            m_stuck_best = best;
            m_stuck_since = t;
        } else if (secs(t - m_stuck_since) >= kStuckReanchorSec) {
            LOG_ERROR << "[EMB-BIP110] UTXO view stuck at h=" << height << ": the body of block "
                      << (height + 1) << " has not come for " << secs(t - m_stuck_since)
                      << "s (" << out.lag << " behind the tip)";
            out.step = reanchor(t_h, "the next block's body is missing", out, true)
                ? Step::Reanchor : Step::ReanchorFailed;
            return out;
        }
        out.step = Step::Fetch;
        connect_kept();
        std::tie(best, height) = view();
        if (best.IsNull() || height >= t_h)
            return out;
        const uint64_t last = std::min<uint64_t>(t_h, static_cast<uint64_t>(height) + kInFlight);
        fetch_heights(height + 1, static_cast<uint32_t>(last), out);
        return out;
    }

    /// The serve gate's view term (any thread).
    bool fresh() const
    {
        const auto [best, height] = view();
        return utxo_view_fresh(best, height, tip(),
                               [this](uint32_t h) { return active_at(h); }, kServeMaxLag);
    }

    size_t kept() const { return m_kept.size(); }
    bool keeps(const uint256& id) const { return m_kept.holds(id); }
    /// No connect until a re-anchor (a rollback failed).
    bool suspended() const { return m_suspended; }

private:
    struct Tried {
        UtxoConnectGate gate{UtxoConnectGate::NotActive};
        bool            connected{false};
        bool            known{false};    // its header is in the chain
        bool            active{false};   // it is the active chain's block at its height
    };

    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    static int64_t secs(Clock::duration d)
    {
        return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(d).count());
    }

    std::pair<uint256, uint32_t> view() const
    {
        return m_host.view ? m_host.view() : std::pair<uint256, uint32_t>{};
    }

    uint32_t tip() const { return m_host.tip_height ? m_host.tip_height() : 0; }

    std::optional<uint256> active_at(uint32_t h) const
    {
        return m_host.active_at ? m_host.active_at(h) : std::nullopt;
    }

    bool on_active(const uint256& best, uint32_t height) const
    {
        const auto at = active_at(height);
        return at && *at == best;
    }

    static bool keep_worthy(const Tried& r)
    {
        switch (r.gate) {
        case UtxoConnectGate::NotContiguous:
        case UtxoConnectGate::NotActive:
            return true;
        case UtxoConnectGate::Below:
            return !r.active;   // a competing block; the active one is in the view
        case UtxoConnectGate::StaleAnchor:
        case UtxoConnectGate::Connect:
            return false;
        }
        return false;
    }

    void reset_stuck()
    {
        m_stuck_best.SetNull();
        m_stuck_since = Clock::time_point{};
    }

    Tried try_connect(const BlockType& block, bool log_skip)
    {
        Tried r;
        if (m_suspended)
            return r;
        const uint256 id = block_hash(block);
        const auto height = m_host.height_of ? m_host.height_of(id) : std::nullopt;
        if (!height)
            return r;   // header sync lagging
        r.known = true;
        const auto at = active_at(*height);
        r.active = at && *at == id;
        const auto [best, best_height] = view();
        const uint32_t t_h = tip();
        const uint32_t floor = t_h > kInFlight ? t_h - static_cast<uint32_t>(kInFlight) : 0;
        r.gate = utxo_connect_gate(best, best_height, id, block.m_previous_block, *height, at, floor);
        if (r.gate != UtxoConnectGate::Connect) {
            if (log_skip && r.gate != UtxoConnectGate::Below)
                LOG_INFO << "[EMB-BIP110] utxo-connect deferred (" << utxo_connect_gate_name(r.gate)
                         << ") h=" << *height << " hash=" << id.GetHex().substr(0, 16)
                         << " view_best=" << best.GetHex().substr(0, 16) << " h=" << best_height;
            return r;
        }
        const bool fresh_before = fresh();
        r.connected = m_host.connect && m_host.connect(block, *height);
        if (r.connected && !fresh_before && fresh() && m_host.on_fresh)
            m_host.on_fresh();
        return r;
    }

    void connect_kept()
    {
        if (m_suspended)
            return;
        const size_t n = m_kept.connect_ready(
            [this](const BlockType& b) { return try_connect(b, /*log_skip=*/false).connected; });
        if (n > 0 && m_host.after_kept)
            m_host.after_kept();
    }

    /// Fetch the active chain's blocks [from, to] that are not kept and not
    /// asked within kRefetchSec.
    void fetch_heights(uint32_t from, uint32_t to, CatchUp& out)
    {
        const auto t = now();
        for (auto it = m_asked.begin(); it != m_asked.end();)
            it = secs(t - it->second) >= kRefetchSec ? m_asked.erase(it) : std::next(it);
        for (uint64_t h = from; h <= to; ++h) {
            const auto id = active_at(static_cast<uint32_t>(h));
            if (!id)
                break;
            if (m_kept.holds(*id) || m_asked.count(*id))
                continue;
            m_asked[*id] = t;
            out.fetched.push_back(*id);
        }
        if (!out.fetched.empty() && m_host.fetch)
            m_host.fetch(out.fetched);
    }

    /// Wipe the view and fetch the tip's body to anchor it again; a failure
    /// is retried after kReanchorRetrySec. error: log as an ERROR.
    bool reanchor(uint32_t tip_h, const char* why, CatchUp& out, bool error)
    {
        const auto t = now();
        if (m_last_reanchor_fail != Clock::time_point{}
            && secs(t - m_last_reanchor_fail) < kReanchorRetrySec)
            return false;
        const auto [best, height] = view();
        if (error)
            LOG_ERROR << "[EMB-BIP110] UTXO view re-anchor: " << why << " (view h=" << height
                      << " " << best.GetHex().substr(0, 16) << ", tip h=" << tip_h << ")";
        else
            LOG_WARNING << "[EMB-BIP110] UTXO view re-anchor: " << why << " (view h=" << height
                        << " " << best.GetHex().substr(0, 16) << ", tip h=" << tip_h << ")";
        if (!m_host.reanchor || !m_host.reanchor()) {
            m_last_reanchor_fail = t;
            LOG_ERROR << "[EMB-BIP110] UTXO view re-anchor failed; retried in "
                      << kReanchorRetrySec << "s" << (m_suspended ? " (no connect until then)" : "");
            return false;
        }
        m_suspended = false;
        m_last_reanchor_fail = Clock::time_point{};
        m_kept.clear();
        m_asked.clear();
        reset_stuck();
        fetch_heights(tip_h, tip_h, out);
        return true;
    }

    UtxoFollowHost                       m_host;
    SideBodies                           m_kept;
    std::map<uint256, Clock::time_point> m_asked;
    Clock::time_point                    m_last_reanchor_fail{};
    bool                                 m_suspended{false};
    uint256                              m_stuck_best;
    Clock::time_point                    m_stuck_since{};
};

} // namespace bip110::coin
