// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The sharechain best share the DGB stratum jobs build on.
//
// main_dgb never bound DGBWorkSource::set_best_share_hash_fn, so every stratum
// job froze a NULL prev share, the producer declined it and no job could ever
// carry a share the node credits. The jobs need the node's best share on the
// stratum IO thread (and the merged payout provider on the merged-mining RPC
// thread), but dgb::NodeImpl::best_share_hash() reads the tracker (verified
// chain, heads) and the peer set WITHOUT a lock: it is only safe under the
// tracker guard, on the IO thread. So the best share is kept in a small
// lock-protected cell:
//   - refreshed on the IO thread, under NodeImpl::read_tracker(), by the
//     node's single on_best_share_changed hook (NodeImpl IO phase, no tracker
//     lock held), retried a bounded number of times while the tracker is busy;
//   - read from any thread (stratum jobs, the merged payout provider) without
//     touching the tracker.
// The same hook also marks the merged payouts dirty (when --merged DOGE) and
// bumps the work generation so the miners get jobs on the new best share. It
// is the ONE binder of the single-slot on_best_share_changed.
// ---------------------------------------------------------------------------

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace dgb {

class BestShareCell {
public:
    uint256 get() const
    {
        std::lock_guard<std::mutex> l(m_);
        return v_;
    }
    void set(const uint256& v)
    {
        std::lock_guard<std::mutex> l(m_);
        v_ = v;
    }

private:
    mutable std::mutex m_;
    uint256 v_;
};

/// Sets `cell` to the node's best share, read under the node's tracker guard.
/// False (cell unchanged) when the tracker is busy. NodeT: dgb::NodeImpl
/// (read_tracker(), best_share_hash()); IO thread only (best_share_hash also
/// reads the peer set).
template <typename NodeT>
bool refresh_best_share_cell(NodeT& node, BestShareCell& cell)
{
    auto guard = node.read_tracker();
    if (!guard)
        return false;
    cell.set(node.best_share_hash());
    return true;
}

/// Tries of the best-share refresh while the tracker is busy, and the gap.
inline constexpr int kBestShareRefreshTries = 100;
inline constexpr std::chrono::milliseconds kBestShareRefreshGap{50};

/// Binds the stratum best-share source and the node's best-change hook:
///   - ws->set_best_share_hash_fn reads the cell;
///   - on a best-share change: `also_on_best` (the merged payouts dirty mark
///     under --merged DOGE, else empty), then the cell is refreshed (retried
///     on `ioc` while the tracker is busy) and the work generation bumped.
/// The cell is refreshed once now (startup, before the IO thread runs).
template <typename NodeT, typename WorkSourceT>
void wire_best_share(NodeT& node, std::shared_ptr<BestShareCell> cell, WorkSourceT* ws,
                     boost::asio::io_context& ioc, std::function<void()> also_on_best = {})
{
    refresh_best_share_cell(node, *cell);
    if (ws)
        ws->set_best_share_hash_fn([cell]() { return cell->get(); });

    auto refresh = std::make_shared<std::function<void(int)>>();
    std::weak_ptr<std::function<void(int)>> weak = refresh;
    *refresh = [&node, &ioc, cell, ws, weak](int attempt) {
        if (refresh_best_share_cell(node, *cell)) {
            if (ws)
                ws->bump_work_generation();
            return;
        }
        if (attempt + 1 >= kBestShareRefreshTries) {
            LOG_WARNING << "[DGB-STRATUM] best share not refreshed: tracker busy for "
                        << kBestShareRefreshTries << " tries; jobs keep the previous best";
            return;
        }
        auto timer = std::make_shared<boost::asio::steady_timer>(ioc, kBestShareRefreshGap);
        timer->async_wait([timer, weak, attempt](const boost::system::error_code& ec) {
            if (ec)
                return;
            if (auto f = weak.lock())
                (*f)(attempt + 1);
        });
    };
    node.set_on_best_share_changed([refresh, also_on_best]() {
        if (also_on_best)
            also_on_best();
        (*refresh)(0);
    });
}

} // namespace dgb
