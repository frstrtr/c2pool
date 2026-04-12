#pragma once

/// BlockBootstrapState: Ordered block download pipeline for UTXO cold-start sync.
///
/// On a fresh install, the embedded SPV node must download N blocks (288 for
/// LTC, 1440 for DOGE) for UTXO coinbase maturity before mining can start.
///
/// Without this fix, the tip block arrives first and sets best_height to the
/// tip, causing ALL bootstrap blocks (which are below the tip) to silently
/// fail the `height > best_height` guard. The node then waits for new blocks
/// to be mined (~4 hours for both LTC and DOGE).
///
/// This struct provides ordered buffering: blocks are stored as they arrive
/// and processed in strict height order. A sliding window of requests is
/// maintained to bound memory usage and enable parallel download from
/// different peers via round-robin assignment.
///
/// Thread safety: all access must be on the io_context thread (same thread
/// as the full_block callback).

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <utility>

namespace core {
namespace coin {

template <typename BlockType>
struct BlockBootstrapState {
    bool active{false};
    uint32_t next_height{0};     // next height to process (drain from here)
    uint32_t end_height{0};      // last height to process (inclusive)
    uint32_t next_request{0};    // next height to request (sliding window)
    uint32_t processed{0};
    uint32_t total{0};
    size_t peer_rotation{0};     // round-robin counter for peer assignment

    // Buffer: height → (block, block_hash)
    // Blocks arrive out-of-order; we drain consecutive from next_height.
    std::map<uint32_t, std::pair<BlockType, uint256>> buffer;

    // Stall detection: if no progress for STALL_TIMEOUT_SEC, re-request
    // the missing block from ALL peers as a fallback.
    std::chrono::steady_clock::time_point last_drain_time{
        std::chrono::steady_clock::now()};

    // Timer-based stall check: fires every STALL_CHECK_SEC to detect stalls
    // even when no blocks arrive (event-based stall detection is insufficient
    // when peers don't respond to getdata at all).
    std::unique_ptr<boost::asio::steady_timer> stall_timer;

    static constexpr size_t WINDOW_SIZE = 16;
    static constexpr int STALL_TIMEOUT_SEC = 30;
    static constexpr int STALL_CHECK_SEC = 10;

    /// Start periodic stall check timer. Calls request_fn(hash) to
    /// broadcast-request the stalled block.
    /// label: log prefix (e.g., "EMB-LTC")
    void start_stall_timer(
        boost::asio::io_context& ioc,
        std::function<void(uint32_t height)> re_request_fn,
        const std::string& label)
    {
        stall_timer = std::make_unique<boost::asio::steady_timer>(ioc);
        schedule_stall_check(std::move(re_request_fn), label);
    }

    void stop_stall_timer()
    {
        if (stall_timer) stall_timer->cancel();
    }

private:
    void schedule_stall_check(
        std::function<void(uint32_t)> re_request_fn,
        std::string label)
    {
        if (!stall_timer || !active) return;
        stall_timer->expires_after(std::chrono::seconds(STALL_CHECK_SEC));
        stall_timer->async_wait(
            [this, fn = std::move(re_request_fn), lbl = std::move(label)]
            (const boost::system::error_code& ec) {
                if (ec || !active) return;
                auto now = std::chrono::steady_clock::now();
                auto stall = std::chrono::duration_cast<std::chrono::seconds>(
                    now - last_drain_time).count();
                if (stall >= STALL_TIMEOUT_SEC) {
                    LOG_WARNING << "[" << lbl << "] Bootstrap stall h="
                        << next_height << " (" << stall
                        << "s) — timer re-request";
                    fn(next_height);
                    last_drain_time = now;
                }
                schedule_stall_check(fn, lbl);
            });
    }
};

} // namespace coin
} // namespace core
