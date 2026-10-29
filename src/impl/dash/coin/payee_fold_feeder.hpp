// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH embedded: feed the payee lane and the UTXO lane strictly in height
/// order, and fetch by header-chain position the bodies no inv announced.
///
/// THE INCIDENT (hotel reserve, 2026-10-26 22:00-22:06 MSK, build f987e4a1f).
/// A ~12 minute coin-P2P blackout lost the invs for h=2561877 and h=2561878.
/// Their headers still arrived (getheaders self-propel), so the header tip
/// moved, but the only tip-follow body request in main_dash is the new_block
/// (inv) handler: nothing ever asked for those two bodies. When 2561879's inv
/// and body landed, wire_full_block_ingest fired block_connected in ARRIVAL
/// order, MnStateMachine::apply_block saw height > cursor+1 and refused it
/// (correctly), and CoinStateMaintainer answered the refusal with a wipe and an
/// authoritative re-seed: 43 minutes without work, then a second gap four hours
/// later that forced a 12 571-block cold replay. The UTXO lane connected 2561879
/// over the same hole (utxo_lane.hpp's `height > best` guard has no continuity
/// check).
///
/// WHAT DASHD DOES. It never folds the deterministic MN list out of order and
/// never needs to: CDeterministicMNManager::ProcessBlock runs inside ConnectTip
/// (validation.cpp:3160), which ActivateBestChainStep (validation.cpp:3325)
/// drives strictly along the best chain. A body whose parent has no data is
/// kept in m_blocks_unlinked (validation.cpp:3287-3290, 3944-3954) and
/// connected when the parent arrives. Bodies are requested BY HEADER-CHAIN
/// POSITION, not by inv: PeerManagerImpl::FindNextBlocksToDownload
/// (net_processing.cpp:1417) walks the best header chain from the last
/// connected block, MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16 at a time
/// (net_processing.cpp:138) inside a BLOCK_DOWNLOAD_WINDOW of 1024
/// (net_processing.cpp:153). An inv that never arrives costs dashd nothing.
///
/// THE PORT. This is the LTC/DOGE ordered-connect rule (src/impl/ltc/coin/
/// utxo_order.hpp: utxo_connect_action Connect/Gap/Skip, ordered_buffer,
/// ordered_drain, ordered_refill) stood up for DASH as one feeder that sits
/// between Node::block_connected and its two height-ordered consumers, the
/// UTXO lane and CoinStateMaintainer::on_block_connected (the payee
/// MnStateMachine). The cursor is the payee machine's apply cursor:
///
///   * height == cursor+1          -> deliver, then drain the park map
///                                    contiguously (dashd's unlinked drain);
///   * height >  cursor+1          -> PARK (bounded, kParkCap) and request
///                                    cursor+1 .. by header-chain hash NOW —
///                                    a later body proves the earlier ones are
///                                    missing;
///   * the header tip moves past the cursor with no body (the lost-inv case)
///                                 -> after a short grace (the inv path gets
///                                    first go at its own announcement, so a
///                                    healthy node issues no duplicate getdata)
///                                    request cursor+1 .. min(tip, cursor+
///                                    kWindow) by hash; re-ask every kReaskMs
///                                    from the pool tick until the body lands;
///   * a body whose hash is not the header chain's block at its height is a
///     fork body and never parks or folds.
///
/// WHAT IT DOES NOT CHANGE. MnStateMachine::apply_block is untouched: its
/// contiguity guard still refuses a gap, and the maintainer still wipes on it —
/// the wipe stays reachable as the last-resort invariant (park overflow
/// releases the lowest parked body to the payee lane, which takes exactly
/// today's path). A payee DESYNC is a real divergence and is not this file's
/// business. The serve gate is untouched: while the cursor is behind the
/// header tip the maintainer keeps `tip-body-pending` and NodeCoinState keeps
/// `payee-stale` as the backstop, so a payee queue behind the tip never backs a
/// template.
///
/// PASSTHROUGH. With no ordered cursor (cursor fn returns 0: the payee machine
/// is unseeded, unheighted, or wiped awaiting its re-seed) every body is
/// delivered at once, in arrival order — byte-for-byte today's feed. Bodies at
/// or below the cursor are delivered at once too: the maintainer's forward
/// guard ignores them, and the UTXO lane's cold-start bootstrap is the one
/// consumer that still needs heights below the payee cursor.
///
/// FETCH-TIMING AND ORDER ONLY. The feeder decides WHEN a body reaches the
/// payee lane, never WHAT apply_block derives from it; every delivered body
/// is the header chain's block at its height and was merkle-bound by
/// wire_full_block_ingest before it got here.
///
/// FENCED: src/impl/dash only. Header-only; pulls the dash block codec.
/// Single-threaded by contract: every entry point runs on the coin io thread
/// (block_connected, the header tip-changed callback, the pool tick).

#include "block.hpp"            // BlockType / BlockHeaderType
#include "node_interface.hpp"   // dash::interfaces::BlockConnected

#include <impl/dash/crypto/hash_x11.hpp>

#include <core/events.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// What the feeder does with a body at `height` when the payee cursor is
/// `cursor`. Mirrors ltc::coin::utxo_connect_action with the DASH additions
/// (passthrough when there is no ordered cursor, fork bodies dropped).
enum class PayeeFeedAction {
    Pass,      ///< no ordered cursor, or at/below it: deliver now (today's feed)
    Deliver,   ///< height == cursor + 1: deliver, then drain the park map
    Park,      ///< height >  cursor + 1: hold it, fetch the missing heights
    DropFork,  ///< not the header chain's block at its height
};

inline const char* payee_feed_action_name(PayeeFeedAction a)
{
    switch (a) {
    case PayeeFeedAction::Pass:     return "pass";
    case PayeeFeedAction::Deliver:  return "deliver";
    case PayeeFeedAction::Park:     return "park";
    case PayeeFeedAction::DropFork: return "drop-fork";
    }
    return "unknown";
}

/// `on_best_chain`: nullopt = the header chain cannot judge the height (no
/// index entry), treated as on-chain — the same answer today's feed gives.
inline PayeeFeedAction payee_feed_action(uint32_t cursor, uint32_t height,
                                         std::optional<bool> on_best_chain)
{
    if (cursor == 0 || height <= cursor) return PayeeFeedAction::Pass;
    if (on_best_chain.has_value() && !*on_best_chain)
        return PayeeFeedAction::DropFork;
    if (height == cursor + 1) return PayeeFeedAction::Deliver;
    return PayeeFeedAction::Park;
}

class PayeeFoldFeeder {
public:
    using BlockConnected = ::dash::interfaces::BlockConnected;
    /// The payee apply cursor (MnStateMachine::last_applied_height while an
    /// authoritative height-stamped snapshot is in force). 0 = no ordered
    /// cursor: the feeder passes every body straight through.
    using CursorFn    = std::function<uint32_t()>;
    /// Best header height (0 = no header chain).
    using TipHeightFn = std::function<uint32_t()>;
    /// The header chain's block hash at `height`, if it holds one.
    using HashAtFn    = std::function<std::optional<uint256>(uint32_t)>;
    /// Ask a peer for the body `hash` (header-chain block at `height`).
    /// Returns TRUE only when the getdata left for a peer (the #138 contract).
    /// main_dash wires CoinP2PClient::request_block_tracked, so a request that
    /// is not answered is rotated to another peer by the lost-body watchdog.
    using RequestFn   = std::function<bool(const uint256& hash, uint32_t height)>;
    /// Monotonic milliseconds. Injectable for the KATs.
    using ClockFn     = std::function<int64_t()>;

    /// Bodies held ahead of a missing cursor+1. 64 blocks is ~2.7 hours of
    /// mainnet; a hole that outlives it is not a transport hiccup, and the
    /// overflow hands the lane to today's wipe + authoritative re-seed.
    static constexpr size_t   kParkCap         = 64;
    /// Heights asked for at once (net_processing.cpp:138
    /// MAX_BLOCKS_IN_TRANSIT_PER_PEER). The feeder only ever chases the few
    /// blocks between the payee cursor and the tip.
    static constexpr uint32_t kWindow          = 16;
    /// A header that arrived with no body gets this long before the feeder
    /// asks for it: the inv handler normally fetches its own announcement
    /// within ~1 s (measured median 0.77 s, p90 2.9 s on the 86406d07 soak),
    /// and asking twice for every tip block would double tip bandwidth.
    static constexpr int64_t  kFirstAskGraceMs = 5000;
    /// Re-ask interval for a height still missing (the design's 10 s; the
    /// lost-body watchdog behind request_block_tracked rotates peers on its
    /// own 10 s clock too).
    static constexpr int64_t  kReaskMs         = 10000;

    PayeeFoldFeeder() = default;
    PayeeFoldFeeder(const PayeeFoldFeeder&) = delete;
    PayeeFoldFeeder& operator=(const PayeeFoldFeeder&) = delete;

    /// THE ORDERED STREAM. The height-ordered consumers subscribe here instead
    /// of Node::block_connected (main_dash: the UTXO lane first, then the
    /// maintainer — the same relative order the two raw subscriptions had).
    Event<BlockConnected> ordered;

    void set_cursor_fn(CursorFn fn)       { m_cursor = std::move(fn); }
    void set_tip_height_fn(TipHeightFn fn){ m_tip = std::move(fn); }
    void set_hash_at_fn(HashAtFn fn)      { m_hash_at = std::move(fn); }
    void set_request_fn(RequestFn fn)     { m_request = std::move(fn); }
    void set_clock_fn(ClockFn fn)         { m_now = std::move(fn); }

    /// Intake: subscribe to Node::block_connected.
    void on_block_connected(const BlockConnected& bc)
    {
        m_inbox.push_back(bc);
        run();
    }

    /// The header tip moved (HeaderChain::set_on_tip_changed). Records the
    /// heights the payee lane now waits on; the first ask goes out after
    /// kFirstAskGraceMs from tick() unless a later body proves the gap first.
    /// This is what closes the lost-inv case: a header with no inv is still a
    /// height the feeder will fetch (FindNextBlocksToDownload by position).
    void on_tip_changed()
    {
        want_window(0, "header tip moved");
        run();
    }

    /// Pool tick (main_dash: the 3 s MN-CKPT service timer). Releases parked
    /// bodies a moved cursor now reaches, then issues the grace-expired first
    /// asks and the kReaskMs re-asks.
    void tick()
    {
        want_window(0, "pool tick");
        run();
    }

    // ── telemetry (KATs + log) ────────────────────────────────────────────
    uint32_t cursor() const          { return m_cursor ? m_cursor() : 0; }
    size_t   parked() const          { return m_park.size(); }
    bool     is_parked(uint32_t h) const { return m_park.count(h) != 0; }
    size_t   awaiting() const        { return m_asks.size(); }
    uint64_t delivered() const       { return m_delivered; }
    uint64_t delivered_from_park() const { return m_from_park; }
    uint64_t parked_total() const    { return m_parked_total; }
    uint64_t fork_drops() const      { return m_fork_drops; }
    /// ...of which bodies that were on the chain when parked and lost their
    /// height to a reorg before they could be released.
    uint64_t stale_parked_drops() const { return m_stale_parked_drops; }
    uint64_t requests() const        { return m_requests; }
    uint64_t reasks() const          { return m_reasks; }
    uint64_t dead_sends() const      { return m_dead_sends; }
    uint64_t overflows() const       { return m_overflows; }

private:
    struct Ask {
        int64_t  first_seen_ms{0};
        int64_t  last_ask_ms{0};
        uint32_t attempts{0};
    };

    int64_t now_ms() const
    {
        if (m_now) return m_now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    static uint256 body_hash(const BlockConnected& bc)
    {
        auto packed = ::pack(static_cast<const BlockHeaderType&>(bc.block));
        return ::dash::crypto::hash_x11(packed.get_span());
    }

    /// THE ONE LOOP. Every entry point queues its work and calls run(); only
    /// the outermost call does anything. A sink, or a peer answering a getdata
    /// inline (the KAT harness; a real peer answers on the next io turn), can
    /// re-enter on_block_connected from inside a delivery or a request — that
    /// body is queued here and processed after the current step, so no map
    /// is mutated under an iterator and the ordering stays the feeder's.
    void run()
    {
        if (m_busy) return;
        m_busy = true;
        for (;;) {
            if (!m_inbox.empty()) {
                BlockConnected bc = std::move(m_inbox.front());
                m_inbox.erase(m_inbox.begin());
                intake(bc);
                drain();
                continue;
            }
            if (m_window_wanted) {
                m_window_wanted = false;
                const uint32_t below = m_immediate_below;
                const char* why = m_window_why;
                m_immediate_below = 0;
                drain();
                request_window(now_ms(), below, why);
                continue;
            }
            break;
        }
        m_busy = false;
    }

    void want_window(uint32_t immediate_below, const char* why)
    {
        m_window_wanted = true;
        if (immediate_below > m_immediate_below) {
            m_immediate_below = immediate_below;
            m_window_why = why;
        } else if (m_immediate_below == 0) {
            m_window_why = why;
        }
    }

    void emit(const BlockConnected& bc)
    {
        ++m_delivered;
        ordered.happened(bc);
    }

    void intake(const BlockConnected& bc)
    {
        const uint32_t c = cursor();
        const uint32_t h = bc.height;
        std::optional<bool> on_chain;
        if (c != 0 && h > c && m_hash_at) {
            if (auto at = m_hash_at(h)) on_chain = (*at == body_hash(bc));
        }
        switch (payee_feed_action(c, h, on_chain)) {
        case PayeeFeedAction::Pass:
        case PayeeFeedAction::Deliver:
            m_asks.erase(h);
            emit(bc);
            return;
        case PayeeFeedAction::DropFork:
            ++m_fork_drops;
            LOG_WARNING << "[PAYEE-FEED] body h=" << h << " "
                        << body_hash(bc).GetHex().substr(0, 16)
                        << " is NOT the header chain's block at that height"
                           " (fork body) — not parked, not folded (cursor h="
                        << c << ")";
            return;
        case PayeeFeedAction::Park:
            break;
        }
        // A later body proves cursor+1 .. h-1 are missing: hold it and fetch
        // them now (dashd keeps the body in m_blocks_unlinked and downloads by
        // header position, validation.cpp:3944-3954 / net_processing.cpp:1417).
        const bool fresh = m_park.emplace(h, bc).second;
        m_asks.erase(h);
        if (fresh) {
            ++m_parked_total;
            LOG_WARNING << "[PAYEE-FEED] body h=" << h << " arrived AHEAD of the"
                        << " payee cursor h=" << c << " ("
                        << (h - c - 1) << " block(s) missing) — PARKED"
                        << " (parked=" << m_park.size() << "/" << kParkCap
                        << "), fetching h=" << (c + 1) << ".." << (h - 1)
                        << " by header-chain hash instead of wiping the queue";
        }
        if (m_park.size() > kParkCap) {
            overflow(c);
            return;
        }
        want_window(h, "body arrived ahead of the cursor");
    }

    /// Park window exceeded: cursor+1 has been unobtainable for longer than
    /// kParkCap later blocks. Release the LOWEST parked body to the payee lane
    /// so the maintainer takes today's fail-closed path (APPLY GAP -> wipe ->
    /// authoritative re-seed); the cursor then reads 0 and drain() flushes the
    /// rest in height order. Bounded memory, and the wipe stays reachable.
    void overflow(uint32_t c)
    {
        ++m_overflows;
        auto it = m_park.begin();
        LOG_WARNING << "[PAYEE-FEED] PARK OVERFLOW: " << m_park.size()
                    << " bodies held but h=" << (c + 1)
                    << " never arrived — releasing h=" << it->first
                    << " to the payee lane; its APPLY GAP takes the fail-closed"
                       " wipe + authoritative re-seed path";
        BlockConnected bc = std::move(it->second);
        m_park.erase(it);
        emit(bc);
    }

    /// A parked body was the header chain's block at its height when it
    /// ARRIVED (intake checks that). The chain may have reorged at that height
    /// while it waited for the hole below it to fill — a tip race at
    /// h >= cursor+2 whose loser's body parked. Nothing downstream would catch
    /// it: the maintainer binds a body only to its OWN header, and
    /// MnStateMachine::apply_block has no prev-hash linkage, so the loser would
    /// fold (and the winner then be ignored as <= cursor). Re-check at EVERY
    /// release; a body that lost its height is dropped like a fork body at
    /// intake. Cannot judge (no index entry) = the intake answer: release.
    bool parked_body_stale(uint32_t h, const BlockConnected& bc)
    {
        if (!m_hash_at) return false;
        auto at = m_hash_at(h);
        if (!at) return false;
        const uint256 have = body_hash(bc);
        if (*at == have) return false;
        ++m_fork_drops;
        ++m_stale_parked_drops;
        LOG_WARNING << "[PAYEE-FEED] parked body h=" << h << " "
                    << have.GetHex().substr(0, 16)
                    << " is no longer the header chain's block there (reorged"
                       " while parked; the chain now holds "
                    << at->GetHex().substr(0, 16)
                    << ") — DROPPED, not folded";
        return true;
    }

    /// Deliver every parked body the cursor now reaches, in height order.
    void drain()
    {
        for (;;) {
            const uint32_t c = cursor();
            if (c == 0) {
                // No ordered cursor any more (the payee lane was wiped, or never
                // seeded): fall back to today's feed — hand everything held to
                // the sinks, lowest height first, and stop chasing.
                if (!m_park.empty())
                    LOG_INFO << "[PAYEE-FEED] payee cursor gone (unseeded/wiped)"
                                " — releasing " << m_park.size()
                             << " parked body(ies) in height order";
                while (!m_park.empty()) {
                    const uint32_t h = m_park.begin()->first;
                    BlockConnected bc = std::move(m_park.begin()->second);
                    m_park.erase(m_park.begin());
                    if (parked_body_stale(h, bc)) continue;
                    ++m_from_park;
                    emit(bc);
                }
                m_asks.clear();
                return;
            }
            // Parked heights the cursor already passed (a snapshot load moved
            // it): release them in order; the payee guard ignores them and the
            // UTXO lane may still need them.
            while (!m_park.empty() && m_park.begin()->first <= c) {
                const uint32_t h = m_park.begin()->first;
                BlockConnected bc = std::move(m_park.begin()->second);
                m_park.erase(m_park.begin());
                if (parked_body_stale(h, bc)) continue;
                ++m_from_park;
                emit(bc);
            }
            auto it = m_park.find(c + 1);
            if (it == m_park.end()) break;
            BlockConnected bc = std::move(it->second);
            m_park.erase(it);
            if (parked_body_stale(c + 1, bc)) {
                // Ask for the block the header chain holds there NOW, at once
                // (a fresh first ask, not a 10 s re-ask).
                m_asks.erase(c + 1);
                want_window(c + 2, "parked body reorged out");
                break;
            }
            ++m_from_park;
            emit(bc);
            const uint32_t after = cursor();
            LOG_INFO << "[PAYEE-FEED] ordered connect: h=" << (c + 1)
                     << " folded from the park map, cursor h=" << c << " -> h="
                     << after << " (parked=" << m_park.size() << ")";
            if (after == c) break;   // the payee lane refused it; ask again later
        }
        const uint32_t c = cursor();
        while (!m_asks.empty() && m_asks.begin()->first <= c)
            m_asks.erase(m_asks.begin());
    }

    /// Ask for every height in (cursor, min(top, cursor+kWindow)] that is
    /// neither parked nor recently asked. `top` is the higher of the header
    /// tip and the highest parked body. Heights below `immediate_below` are
    /// asked at once (a later body proved them missing); the rest wait out
    /// kFirstAskGraceMs on their first ask.
    void request_window(int64_t now, uint32_t immediate_below, const char* why)
    {
        const uint32_t c = cursor();
        if (c == 0) {
            m_asks.clear();
            return;
        }
        uint32_t top = m_tip ? m_tip() : 0;
        if (!m_park.empty()) top = std::max(top, m_park.rbegin()->first);
        while (!m_asks.empty() && m_asks.begin()->first <= c)
            m_asks.erase(m_asks.begin());
        if (top <= c) return;
        const uint32_t hi = std::min<uint64_t>(top, uint64_t(c) + kWindow);
        uint32_t first_asked = 0, last_asked = 0, n = 0;
        for (uint32_t h = c + 1; h <= hi; ++h) {
            if (m_park.count(h)) continue;
            auto ins = m_asks.try_emplace(h);
            Ask& a = ins.first->second;
            if (ins.second) a.first_seen_ms = now;
            bool due;
            if (a.attempts == 0)
                due = (h < immediate_below) || (now - a.first_seen_ms >= kFirstAskGraceMs);
            else
                due = (now - a.last_ask_ms >= kReaskMs);
            if (!due || !m_request || !m_hash_at) continue;
            auto hash = m_hash_at(h);
            if (!hash) continue;   // cannot name the block; the next tick retries
            const bool sent = m_request(*hash, h);
            if (a.attempts == 0) ++m_requests; else ++m_reasks;
            if (!sent) ++m_dead_sends;
            ++a.attempts;
            a.last_ask_ms = now;
            if (n == 0) first_asked = h;
            last_asked = h;
            ++n;
        }
        if (n != 0)
            LOG_INFO << "[PAYEE-FEED] fetching " << n << " body(ies) h="
                     << first_asked << ".." << last_asked
                     << " by header-chain hash (" << why << "; payee cursor h="
                     << c << ", header tip h=" << (m_tip ? m_tip() : 0)
                     << ", parked=" << m_park.size()
                     << ", requests=" << m_requests << " reasks=" << m_reasks
                     << " dead=" << m_dead_sends << ")";
    }

    CursorFn    m_cursor;
    TipHeightFn m_tip;
    HashAtFn    m_hash_at;
    RequestFn   m_request;
    ClockFn     m_now;

    std::map<uint32_t, BlockConnected> m_park;
    std::map<uint32_t, Ask>            m_asks;
    std::vector<BlockConnected>        m_inbox;
    bool                               m_busy{false};
    bool                               m_window_wanted{false};
    uint32_t                           m_immediate_below{0};
    const char*                        m_window_why{"pool tick"};

    uint64_t m_delivered{0};
    uint64_t m_from_park{0};
    uint64_t m_parked_total{0};
    uint64_t m_fork_drops{0};
    uint64_t m_stale_parked_drops{0};
    uint64_t m_requests{0};
    uint64_t m_reasks{0};
    uint64_t m_dead_sends{0};
    uint64_t m_overflows{0};
};

} // namespace coin
} // namespace dash
