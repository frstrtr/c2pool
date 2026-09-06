// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Process-wide p2p wire observability — OBSERVE ONLY.
//
// WHY THIS EXISTS
// ---------------
// Before this file, not one of the 13 canonical p2pool pool-protocol message
// types emitted anything at any verbosity: no log line, no counter, no JSON
// field. "Is `remember_tx` actually moving on the wire?" could only be answered
// by reading the source and hoping. A live investigation grepped the logs for a
// message name, got zero hits, and concluded the feature was unimplemented —
// when in fact it was fully wired and running. A log-grep of zero is not
// evidence when nothing ever logs.
//
// So: one cheap relaxed atomic per (message type x direction), incremented at
// the two choke points every pool message must pass through
//   * inbound  — pool::NodeBridge::handle()   (src/pool/node.hpp)
//   * outbound — pool::Peer::write()          (src/pool/peer.hpp)
// plus a handful of gauges the coin lane publishes (known-tx pool size, last
// have_tx advert size, sharechain embedded-timestamp health), read back through
// the read-only /p2p_stats endpoint.
//
// Instrumenting the two shared choke points is deliberate: it means NO per-coin
// protocol file has to be touched, and every coin lane (btc/ltc/dgb/bch/dash/
// doge/nmc) gets the counters from the same code.
//
// CONSENSUS SAFETY: nothing here is read by share validation, minting, payout,
// coinbase construction or peer behaviour. Every member is a counter or a
// display gauge; nothing in this header can change a byte that goes on the wire.
//
// COST: one relaxed fetch_add per message, plus a length-first string_view
// compare against at most 15 short literals. Messages arrive at single-digit
// per-second rates per peer; this is not measurable.

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace core::obs
{

// The canonical p2pool pool-protocol message set. `verack` and `pong` are NOT
// part of the p2pool pool protocol (they belong to the coin-daemon p2p layer);
// they are carried here so the endpoint answers "is this type on the wire?" for
// the full operator-facing list rather than silently omitting two names. They
// read 0 on a healthy pool node — that zero is the answer, not a gap.
enum class P2PMessage : std::size_t
{
    version = 0,
    verack,
    ping,
    pong,
    addrme,
    addrs,
    getaddrs,
    shares,
    sharereq,
    sharereply,
    have_tx,
    losing_tx,
    remember_tx,
    forget_tx,
    bestblock,
    tx_inject,   // #157 M2: miner/user tx-injection over the sharechain p2p
    unknown,     // catch-all bucket; MUST stay last
    COUNT
};

inline constexpr std::size_t P2P_MESSAGE_COUNT = static_cast<std::size_t>(P2PMessage::COUNT);

inline constexpr std::array<std::string_view, P2P_MESSAGE_COUNT> P2P_MESSAGE_NAMES = {
    "version", "verack", "ping", "pong", "addrme", "addrs", "getaddrs",
    "shares", "sharereq", "sharereply",
    "have_tx", "losing_tx", "remember_tx", "forget_tx", "bestblock",
    "tx_inject",
    "unknown"
};

inline constexpr std::string_view p2p_message_name(P2PMessage m)
{
    auto i = static_cast<std::size_t>(m);
    return i < P2P_MESSAGE_COUNT ? P2P_MESSAGE_NAMES[i] : P2P_MESSAGE_NAMES[P2P_MESSAGE_COUNT - 1];
}

// Wire command fields are fixed-width and NUL-padded; RawMessage::m_command
// still carries that padding until MessageHandler::parse() strips it, and the
// inbound counter runs BEFORE parse. Trim here so "ping\0\0\0\0" matches "ping".
inline constexpr std::string_view trim_command(std::string_view cmd)
{
    const auto z = cmd.find('\0');
    return z == std::string_view::npos ? cmd : cmd.substr(0, z);
}

inline constexpr P2PMessage p2p_message_from_command(std::string_view cmd)
{
    const auto trimmed = trim_command(cmd);
    // string_view::operator== compares size first, so this is 15 cheap
    // length checks and at most one memcmp.
    for (std::size_t i = 0; i + 1 < P2P_MESSAGE_COUNT; ++i)
        if (trimmed == P2P_MESSAGE_NAMES[i])
            return static_cast<P2PMessage>(i);
    return P2PMessage::unknown;
}

// ── sharechain embedded-timestamp health (pure, KAT-able) ────────────────────
//
// Upstream p2pool clips every share's EMBEDDED timestamp into
//   [prev.timestamp + 1, prev.timestamp + 2*SHARE_PERIOD - 1]
// (p2pool data.py:239-242). When the real share cadence is faster than that
// upper bound the embedded clock SATURATES: consecutive embedded deltas all sit
// exactly on the bound, the embedded chain clock falls further and further
// behind wall-clock, and the difficulty retarget — which reads embedded
// timestamps, not wall-clock — goes blind to actual hashrate.
//
// Under saturation the aggregate gauges LIE: pool_hash_rate and min_difficulty
// are computed from that same saturated embedded history, so they report the
// decaying floor rather than the pool. The two honest early-warning signals are
// (a) tip lag against wall-clock and (b) the fraction of recent embedded deltas
// pinned to the clip bound — which is what this computes.
struct TimestampSaturation
{
    std::uint32_t samples{0};     // number of consecutive-share deltas examined
    std::uint32_t saturated{0};   // deltas exactly equal to the clip upper bound
    double fraction{0.0};         // saturated / samples (0 when samples == 0)
};

/// @param ts_newest_first embedded share timestamps walked tip-first along
///        prev_hash (index 0 = chain tip, index i+1 = parent of index i).
/// @param clip_upper_bound 2*SHARE_PERIOD - 1 for the coin (39 s on DASH).
/// N timestamps yield N-1 deltas. A delta is "saturated" when it equals the
/// bound exactly. Out-of-order pairs (child older than parent — only reachable
/// on a malformed/forked walk) count as a sample but never as saturated, so a
/// corrupt walk can never manufacture a false all-clear OR a false alarm.
inline TimestampSaturation compute_timestamp_saturation(
    const std::vector<std::uint32_t>& ts_newest_first,
    std::uint32_t clip_upper_bound)
{
    TimestampSaturation out;
    if (ts_newest_first.size() < 2 || clip_upper_bound == 0)
        return out;

    for (std::size_t i = 0; i + 1 < ts_newest_first.size(); ++i)
    {
        const std::uint32_t child  = ts_newest_first[i];
        const std::uint32_t parent = ts_newest_first[i + 1];
        ++out.samples;
        if (child >= parent && (child - parent) == clip_upper_bound)
            ++out.saturated;
    }
    if (out.samples > 0)
        out.fraction = static_cast<double>(out.saturated) / static_cast<double>(out.samples);
    return out;
}

/// Wall-clock now MINUS the tip's EMBEDDED timestamp, in seconds. Positive =
/// the embedded chain clock trails real time (6.81 HOURS was measured live on
/// DASH under saturation). Returns 0 when no tip timestamp is known.
inline std::int64_t compute_tip_lag_seconds(std::int64_t now_unix, std::uint32_t tip_embedded_timestamp)
{
    if (tip_embedded_timestamp == 0)
        return 0;
    return now_unix - static_cast<std::int64_t>(tip_embedded_timestamp);
}

// ── the counters themselves ──────────────────────────────────────────────────
struct P2PMessageStats
{
    // DELIVERABLE 1 — per-message-type, per-direction wire counters.
    std::array<std::atomic<std::uint64_t>, P2P_MESSAGE_COUNT> in{};
    std::array<std::atomic<std::uint64_t>, P2P_MESSAGE_COUNT> out{};

    // DELIVERABLE 2 — tx-pool visibility. Settles "is TXPOOL=0 on a peer
    // dashboard our pool being genuinely empty, or the advert being suppressed?"
    std::atomic<std::uint64_t> known_txs_size{0};
    // -1 = this coin lane has no m_known_txs_order recency deque (DASH does
    // not; btc/ltc/dgb do). Rendered as JSON null so an absent sidecar is never
    // confused with an empty one.
    std::atomic<std::int64_t>  known_txs_order_size{-1};
    std::atomic<std::uint64_t> last_have_tx_advert_size{0};
    std::atomic<std::uint64_t> last_losing_tx_advert_size{0};
    std::atomic<std::uint64_t> have_tx_adverts_sent{0};
    std::atomic<std::int64_t>  known_txs_updated_at{0};   // unix seconds, 0 = never

    // DELIVERABLE 3 — sharechain embedded-timestamp diagnostics.
    std::atomic<std::uint32_t> tip_embedded_timestamp{0};
    std::atomic<std::int64_t>  tip_lag_seconds{0};
    std::atomic<std::uint32_t> ts_delta_samples{0};
    std::atomic<std::uint32_t> ts_delta_saturated{0};
    std::atomic<std::uint32_t> ts_clip_upper_bound{0};    // 2*SHARE_PERIOD - 1
    std::atomic<std::int64_t>  sharechain_updated_at{0};  // unix seconds, 0 = never

    // Debug-gated per-message trace. OFF by default and never enabled by any
    // code path in-tree — an operator flips it deliberately. The counters, not
    // logs, are the hot-path mechanism.
    std::atomic<bool> trace_enabled{false};

    void count_in(std::string_view command) noexcept
    {
        in[static_cast<std::size_t>(p2p_message_from_command(command))]
            .fetch_add(1, std::memory_order_relaxed);
    }

    void count_out(std::string_view command) noexcept
    {
        out[static_cast<std::size_t>(p2p_message_from_command(command))]
            .fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t get_in(P2PMessage m) const noexcept
    {
        return in[static_cast<std::size_t>(m)].load(std::memory_order_relaxed);
    }

    std::uint64_t get_out(P2PMessage m) const noexcept
    {
        return out[static_cast<std::size_t>(m)].load(std::memory_order_relaxed);
    }

    std::uint64_t total_in() const noexcept
    {
        std::uint64_t t = 0;
        for (const auto& c : in) t += c.load(std::memory_order_relaxed);
        return t;
    }

    std::uint64_t total_out() const noexcept
    {
        std::uint64_t t = 0;
        for (const auto& c : out) t += c.load(std::memory_order_relaxed);
        return t;
    }

    /// Test-only helper; never called by the node.
    void reset() noexcept
    {
        for (auto& c : in)  c.store(0, std::memory_order_relaxed);
        for (auto& c : out) c.store(0, std::memory_order_relaxed);
        known_txs_size.store(0, std::memory_order_relaxed);
        known_txs_order_size.store(-1, std::memory_order_relaxed);
        last_have_tx_advert_size.store(0, std::memory_order_relaxed);
        last_losing_tx_advert_size.store(0, std::memory_order_relaxed);
        have_tx_adverts_sent.store(0, std::memory_order_relaxed);
        known_txs_updated_at.store(0, std::memory_order_relaxed);
        tip_embedded_timestamp.store(0, std::memory_order_relaxed);
        tip_lag_seconds.store(0, std::memory_order_relaxed);
        ts_delta_samples.store(0, std::memory_order_relaxed);
        ts_delta_saturated.store(0, std::memory_order_relaxed);
        ts_clip_upper_bound.store(0, std::memory_order_relaxed);
        sharechain_updated_at.store(0, std::memory_order_relaxed);
    }
};

/// Process-wide instance. c2pool runs ONE pool node per process (the per-coin
/// binary invariant), so a process-global is exactly per-node scope and needs no
/// plumbing through the node -> web-server seam.
inline P2PMessageStats& p2p_stats()
{
    static P2PMessageStats stats;
    return stats;
}

} // namespace core::obs
