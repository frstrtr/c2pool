// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB mint retries while the sharechain is busy (review 713dc77a0 #11).
//
// main_dgb's mint seam takes the tracker's exclusive lock without blocking the
// Stratum IO thread (try_to_lock). Before, a busy tracker (the compute thread
// mid-think, a payout provider holding a read guard) dropped the share: the
// miner's work was accepted and never credited. Now the mint attempt is
// retried on the IO context, every kMintRetryGap, at most kMintRetryTries
// times; the share carries the job's frozen fields, so a later mint makes the
// same share. Only a busy tracker is retried: a declined share is not.
// ---------------------------------------------------------------------------

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace dgb {

inline constexpr int kMintRetryTries = 100;
inline constexpr std::chrono::milliseconds kMintRetryGap{50};

/// `attempt`: one mint try; std::nullopt = the tracker was busy (retry), a
/// value = done (the share hash, null when the share was declined). Runs it
/// now; returns its result if it was not busy, else schedules the retries on
/// `ioc` and returns null (`*queued` = true). `on_done` (optional) gets the
/// final result of a retried mint, or a null hash after the last busy try.
inline uint256 mint_with_retry(boost::asio::io_context& ioc, std::function<std::optional<uint256>()> attempt,
                               std::function<void(const uint256&, int tries)> on_done = {},
                               bool* queued = nullptr)
{
    if (queued)
        *queued = false;
    if (auto r = attempt())
        return *r;
    if (queued)
        *queued = true;
    auto step = std::make_shared<std::function<void(int)>>();
    std::weak_ptr<std::function<void(int)>> weak = step;
    // Each pending timer owns the step (strong); the step itself holds only a
    // weak reference, so the chain frees itself after the last try.
    *step = [&ioc, attempt, on_done, weak](int tries) {
        auto self = weak.lock();
        if (!self)
            return;
        auto timer = std::make_shared<boost::asio::steady_timer>(ioc, kMintRetryGap);
        timer->async_wait([timer, attempt, on_done, self, tries](const boost::system::error_code& ec) {
            if (ec)
                return;
            if (auto r = attempt()) {
                if (on_done)
                    on_done(*r, tries + 1);
                return;
            }
            if (tries + 1 >= kMintRetryTries) {
                LOG_WARNING << "[DGB-MINT] tracker busy for " << kMintRetryTries
                            << " tries: share NOT recorded";
                if (on_done)
                    on_done(uint256(), tries + 1);
                return;
            }
            (*self)(tries + 1);
        });
    };
    (*step)(1);
    return uint256();
}

} // namespace dgb
