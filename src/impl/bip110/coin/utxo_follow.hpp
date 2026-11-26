// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bip110::coin::UtxoFollower -- keeps c2pool-bip110's own UTXO view on the
// header chain's active chain, block by block. main_bip110.cpp gives it the
// view, the chain, the connect / rollback / re-anchor of the view and the coin
// peer pool's body fetch (UtxoFollowHost); the KATs drive it with fakes.
//
//   - A body (the pool's on_body_in_order) connects only if it is the active
//     chain's block right after the view's best (any active block while the
//     view is empty: the first anchor; utxo_connect_gate). One that does not
//     is kept (SideBodies, the last kKeptMax).
//   - Kept bodies are offered again after every body, on every header tip
//     change (before anything else: a branch that just became active may
//     extend the view without a rollback) and on each catch-up step; one that
//     is the next block then connects.
//   - Tip change: if the view's best left the active chain, the view is rolled
//     back to the fork, then the kept bodies connect.
//   - Catch-up step (the pool driver, every kCoinPoolPollSec, once header sync
//     is caught up):
//       * an empty view: the tip's body is fetched, to anchor the view;
//       * the view's best off the active chain (a rollback that failed, a view
//         from another branch at start): rolled back, else re-anchored;
//       * behind the tip by more than kReanchorGap blocks: re-anchored (wiped;
//         the tip's body is fetched to anchor it again): the view would need
//         more than kReanchorGap bodies (up to ~800 kB each under the RDTS cap)
//         and a rollback can never reach below the undo horizon
//         (BIP110_KEEP_DEPTH == kReanchorGap) anyway;
//       * behind by up to kReanchorGap: the active chain's next kInFlight
//         blocks after the view's best that are not kept are fetched (the
//         pool holds a body that arrives before its parent, at most
//         kCoinPoolMaxBodyGap of them; kInFlight leaves room for the tip's).
//     A block is fetched again only after kRefetchSec.
//   - fresh(): the serve gate's view term: the view's best is on the active
//     chain and at most kServeMaxLag blocks below the tip. kServeMaxLag is 0:
//     until the tip block's body is connected the mempool still holds the
//     transactions that block confirmed, so a template on the tip could carry
//     them again.
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
};

inline const char* utxo_connect_gate_name(UtxoConnectGate g)
{
    switch (g) {
    case UtxoConnectGate::Connect:       return "connect";
    case UtxoConnectGate::Below:         return "at or below the view's best";
    case UtxoConnectGate::NotContiguous: return "non-contiguous";
    case UtxoConnectGate::NotActive:     return "not on the active chain";
    }
    return "?";
}

/// view_best / view_height: the view's best (a null hash: the view is empty);
/// id / prev / height: the block's identity, parent and height; active: the
/// active chain's block at that height (nullopt: none).
inline UtxoConnectGate utxo_connect_gate(const uint256& view_best, uint32_t view_height,
                                         const uint256& id, const uint256& prev, uint32_t height,
                                         const std::optional<uint256>& active)
{
    if (!view_best.IsNull()) {
        if (height <= view_height)
            return UtxoConnectGate::Below;
        if (prev != view_best)
            return UtxoConnectGate::NotContiguous;
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
    /// Roll the view back to its fork with the active chain; true if done.
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

    static constexpr size_t   kKeptMax      = 8;
    static constexpr size_t   kInFlight     = 4;
    static constexpr uint32_t kReanchorGap  = 288;
    static constexpr uint32_t kServeMaxLag  = 0;
    static constexpr int64_t  kRefetchSec   = 30;
    static constexpr int64_t  kReanchorRetrySec = 60;

    enum class Step { None, Anchor, Fetch, Rollback, Reanchor, ReanchorFailed };
    struct CatchUp {
        Step                 step{Step::None};
        uint32_t             lag{0};
        std::vector<uint256> fetched;
    };
    enum class TipChange { None, RolledBack, RollbackFailed };

    explicit UtxoFollower(UtxoFollowHost host) : m_host(std::move(host)), m_kept(kKeptMax) {}

    /// A body for the view: connected if the gate allows, else kept (its
    /// header held); then the kept bodies. True if `block` was connected.
    bool on_body(const BlockType& block)
    {
        const bool connected = try_connect(block, /*log_skip=*/true);
        if (!connected && m_host.height_of && m_host.height_of(block_hash(block)))
            m_kept.keep(block);
        connect_kept();
        return connected;
    }

    /// The header tip changed: the kept bodies first; then, if the view's
    /// best left the active chain, the rollback to the fork and the kept
    /// bodies again.
    TipChange on_tip_changed()
    {
        connect_kept();
        const auto [best, height] = view();
        if (best.IsNull() || on_active(best, height))
            return TipChange::None;
        if (!m_host.rollback || !m_host.rollback())
            return TipChange::RollbackFailed;
        connect_kept();
        return TipChange::RolledBack;
    }

    /// One catch-up step.
    CatchUp catch_up()
    {
        CatchUp out;
        const uint32_t tip = m_host.tip_height ? m_host.tip_height() : 0;
        auto [best, height] = view();
        if (best.IsNull()) {
            out.step = Step::Anchor;
            connect_kept();
            std::tie(best, height) = view();
            if (best.IsNull())
                fetch_heights(tip, tip, out);
            return out;
        }
        if (!on_active(best, height)) {
            if (m_host.rollback && m_host.rollback()) {
                out.step = Step::Rollback;
                connect_kept();
                return out;
            }
            out.step = reanchor(tip, "its best is off the active chain", out) ? Step::Reanchor
                                                                              : Step::ReanchorFailed;
            return out;
        }
        if (height >= tip)
            return out;
        out.lag = tip - height;
        if (out.lag > kReanchorGap) {
            out.step = reanchor(tip, "too far behind the tip", out) ? Step::Reanchor
                                                                    : Step::ReanchorFailed;
            return out;
        }
        out.step = Step::Fetch;
        connect_kept();
        std::tie(best, height) = view();
        if (best.IsNull() || height >= tip)
            return out;
        const uint64_t last = std::min<uint64_t>(tip, static_cast<uint64_t>(height) + kInFlight);
        fetch_heights(height + 1, static_cast<uint32_t>(last), out);
        return out;
    }

    /// The serve gate's view term (any thread).
    bool fresh() const
    {
        const auto [best, height] = view();
        const uint32_t tip = m_host.tip_height ? m_host.tip_height() : 0;
        return utxo_view_fresh(best, height, tip,
                               [this](uint32_t h) { return active_at(h); }, kServeMaxLag);
    }

    size_t kept() const { return m_kept.size(); }
    bool keeps(const uint256& id) const { return m_kept.holds(id); }

private:
    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    static int64_t secs(Clock::duration d)
    {
        return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(d).count());
    }

    std::pair<uint256, uint32_t> view() const
    {
        return m_host.view ? m_host.view() : std::pair<uint256, uint32_t>{};
    }

    std::optional<uint256> active_at(uint32_t h) const
    {
        return m_host.active_at ? m_host.active_at(h) : std::nullopt;
    }

    bool on_active(const uint256& best, uint32_t height) const
    {
        const auto at = active_at(height);
        return at && *at == best;
    }

    bool try_connect(const BlockType& block, bool log_skip)
    {
        const uint256 id = block_hash(block);
        const auto height = m_host.height_of ? m_host.height_of(id) : std::nullopt;
        if (!height)
            return false;   // header sync lagging
        const auto [best, best_height] = view();
        const auto gate = utxo_connect_gate(best, best_height, id, block.m_previous_block, *height,
                                            active_at(*height));
        if (gate != UtxoConnectGate::Connect) {
            if (log_skip && gate != UtxoConnectGate::Below)
                LOG_INFO << "[EMB-BIP110] utxo-connect deferred (" << utxo_connect_gate_name(gate)
                         << ") h=" << *height << " hash=" << id.GetHex().substr(0, 16)
                         << " view_best=" << best.GetHex().substr(0, 16) << " h=" << best_height;
            return false;
        }
        return m_host.connect && m_host.connect(block, *height);
    }

    void connect_kept()
    {
        const size_t n = m_kept.connect_ready(
            [this](const BlockType& b) { return try_connect(b, /*log_skip=*/false); });
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

    bool reanchor(uint32_t tip, const char* why, CatchUp& out)
    {
        const auto t = now();
        if (m_last_reanchor_fail != Clock::time_point{}
            && secs(t - m_last_reanchor_fail) < kReanchorRetrySec)
            return false;
        const auto [best, height] = view();
        LOG_WARNING << "[EMB-BIP110] UTXO view re-anchor: " << why << " (view h=" << height
                    << " " << best.GetHex().substr(0, 16) << ", tip h=" << tip
                    << "); the next connected block anchors it";
        if (!m_host.reanchor || !m_host.reanchor()) {
            m_last_reanchor_fail = t;
            LOG_ERROR << "[EMB-BIP110] UTXO view re-anchor failed; retried in "
                      << kReanchorRetrySec << "s";
            return false;
        }
        m_kept.clear();
        m_asked.clear();
        fetch_heights(tip, tip, out);
        return true;
    }

    UtxoFollowHost                     m_host;
    SideBodies                         m_kept;
    std::map<uint256, Clock::time_point> m_asked;
    Clock::time_point                  m_last_reanchor_fail{};
};

} // namespace bip110::coin
