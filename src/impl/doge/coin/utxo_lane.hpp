// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the UTXO set follows the header chain's best chain, one
/// block at a time, in height order (#2070).
///
/// The DOGE full-block and tip-change handlers in main_ltc.cpp feed this
/// object; the KAT (src/impl/ltc/test/doge_utxo_lane_test.cpp) drives the
/// same object. The rules are the LTC lane's (impl/ltc/coin/utxo_order.hpp
/// and main_ltc's EMB-LTC handlers, #2058 / #2077), built from the same
/// helpers:
///   - a block is connected only as the set's best + 1, when it is the best
///     chain's block at its height and its parent is the set's best block
///     (utxo_connect_check);
///   - a block further ahead arms the ordered pipeline: it is buffered, the
///     missing heights are fetched, blocks drain in height order;
///   - a tip change whose new tip does not descend from the old one is a
///     reorg, whatever the heights (tip_change_is_reorg: the header chain
///     picks the tip by chain work, so a reorg may end higher than the old
///     tip). A reorg, a connect-point parent mismatch and the startup check
///     walk the set back by its undo records until its best block is on the
///     best chain (at most `keep` blocks; rewind_to_best_chain), then the
///     best chain is connected from there in order;
///   - when the walk can never get there (undo record missing, legacy, of
///     another block, deeper than `keep`, the set's block unknown) the set is
///     wiped and the best chain's last `keep` blocks are connected into the
///     empty set, as a cold start does.
/// Reference: dogecoind v1.14.9 src/validation.cpp ActivateBestChainStep
/// (:2437-2466): the fork point by ancestry (FindFork), disconnect down to
/// it, then connect every block of the new branch in order; MIN_BLOCKS_TO_KEEP
/// = 1440 (src/validation.h:212).
///
/// Two modes:
///   - Accrual (the rules above): a partial view born from the last `keep`
///     blocks, which cannot tell a coin it never saw from a spent one;
///   - Full: the set is built from genesis and connected strictly, as
///     dogecoind's chainstate is. It arms from height 1 (an empty set, or one
///     not built from genesis) or from best + 1 whatever the distance (no
///     jump, so no restart hole); a body spending a coin the set does not
///     hold is refused (UTXOViewCache::connect_block strict), refetched, and
///     after repeated refusals the set is left as is (heal_failures); a
///     rebuild starts again from height 1. The body's Merkle root is checked
///     against its header before anything is connected. The set's sync state
///     ('S') records anchor 0 and, once its best reaches the header chain's
///     tip, `synced`; host.completed() fires then.
///
/// Thread: one thread (the io_context the handlers run on, or the full
/// set's own pool), except stats(), which is atomic and read from the HTTP
/// thread.

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/utxo_order.hpp>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace doge {
namespace coin {

/// How the lane builds its set (see the file comment).
enum class UtxoLaneMode {
    Accrual,  // the last `keep` blocks, then forward (partial)
    Full,     // every block from genesis, strictly connected
};

/// SHA256d Merkle root of `hashes` (Core ComputeMerkleRoot: the last of an
/// odd row is paired with itself). `mutated` (optional): set when a row has
/// two equal hashes at a pair position, the CVE-2012-2459 shape (a body with
/// a duplicated tx run has the same root as the real one: Core's CheckBlock
/// refuses it as bad-txns-duplicate).
inline uint256 merkle_root_of(std::vector<uint256> hashes, bool* mutated = nullptr)
{
    if (mutated)
        *mutated = false;
    if (hashes.empty())
        return uint256();
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t i = 0; i + 1 < hashes.size(); i += 2)
                if (hashes[i] == hashes[i + 1])
                    *mutated = true;
        }
        if (hashes.size() & 1u)
            hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2)
            next.push_back(Hash(std::span<const uint8_t>(hashes[i].data(), 32),
                                std::span<const uint8_t>(hashes[i + 1].data(), 32)));
        hashes = std::move(next);
    }
    return hashes[0];
}

/// How a block is asked for.
enum class UtxoAsk {
    Broadcast,  // every peer (the cold-start window, a stalled height)
    Targeted,   // one peer, round robin (reorg / rebuild / recovery fills)
    FromPeer,   // the peer that delivered the block being handled (it has its
                // parents), else Targeted
};

/// What the lane needs from its surroundings. main_ltc.cpp wires it to the
/// DOGE HeaderChain, CoinBroadcaster and Mempool; the KAT to maps.
struct UtxoLaneHost {
    using BlockType = ltc::coin::BlockType;
    using Fill = core::coin::BlockBootstrapState<BlockType>;

    /// The header chain's tip height.
    std::function<uint32_t()> chain_height;
    /// The best chain's block hash at height h (null: no block there).
    std::function<uint256(uint32_t)> chain_hash_at;
    /// A known header's parent (nullopt: the header is unknown).
    std::function<std::optional<uint256>(const uint256&)> prev_of;
    /// A body whose header the header chain does not know yet but whose
    /// parent it knows: hand the header to the header chain (the same checks
    /// as a headers message; a new tip fires its tip change). true = taken.
    std::function<bool(const BlockType&)> add_header;
    /// Called just before add_header with a body whose header the chain does
    /// not know but whose parent it does, at the height it will take: the
    /// txs it confirmed leave the mempool BEFORE its header can move the tip,
    /// so no template is ever built on the new tip from a pool still holding
    /// them.
    std::function<void(const BlockType&, uint32_t)> clean_before_header;
    /// A body whose header and parent the header chain both do not know: the
    /// header chain is behind; ask peers for headers now (rate-limited by the
    /// host) instead of waiting for the periodic getheaders.
    std::function<void()> headers_needed;
    /// Fetch the best chain's block at height h.
    std::function<void(uint32_t, UtxoAsk)> request;
    /// A block was connected to the set. drained: by the ordered pipeline
    /// (the handler's own per-block passes did not run for it).
    std::function<void(const BlockType&, const uint256&, uint32_t, bool drained)> connected;
    /// The set was wiped for a rebuild.
    std::function<void()> wiped;
    /// Full mode: the set reached the header chain's tip (built from
    /// genesis, strictly connected): the pool may price against it.
    std::function<void()> completed;
    /// The ordered pipeline started (arm its stall timer) / stopped.
    std::function<void(Fill&)> fill_started;
    std::function<void(Fill&)> fill_stopped;

    /// Full mode, block download as Core does it (several blocks in flight
    /// per peer within a moving window, a stalling peer replaced). The peers
    /// a body may be asked from: handshaken and advertising NODE_NETWORK (a
    /// pruned node is not asked; full_block_peer()). Unset: the lane asks
    /// through `request` (one window, in order).
    std::function<std::vector<std::string>()> download_peers;
    /// Ask `peer` for the best chain's block at height h (false: not sent).
    std::function<bool(const std::string&, uint32_t)> request_from;
    /// The clock (tests drive it). Unset: std::chrono::steady_clock.
    std::function<std::chrono::steady_clock::time_point()> now;
    /// Bodies wait for headers (Core's ordering, FRESH-NODE §6.4): while it
    /// returns true the block download asks nothing (no request, no
    /// broadcast); it resumes at the next tick() once it returns false.
    /// main_ltc: the accrual Bootstrap while the anchored hash schedule runs
    /// and the header chain is not synced. Unset: never waits.
    std::function<bool()> bodies_wait;
};

/// The serialized size of a body, estimated from its parts (memory bounds:
/// the full lane's reorder buffer, the queue to its thread).
inline size_t estimate_body_bytes(const ltc::coin::BlockType& b)
{
    size_t n = 80 + 9;
    for (const auto& tx : b.m_txs) {
        n += 4 + 4 + 9 + 9;
        for (const auto& in : tx.vin)
            n += 32 + 4 + 4 + 9 + in.scriptSig.m_data.size();
        for (const auto& out : tx.vout)
            n += 8 + 9 + out.scriptPubKey.m_data.size();
    }
    return n;
}

/// A peer that serves every historical block: it advertises NODE_NETWORK
/// (bit 0). A pruned node clears it (Dogecoin 1.14) or advertises only
/// NODE_NETWORK_LIMITED (bit 10, later Core): neither is asked for the IBD.
inline bool full_block_peer(uint64_t services)
{
    constexpr uint64_t NODE_NETWORK = 1;
    return (services & NODE_NETWORK) != 0;
}

/// Counters for /local_stats ("doge_utxo"). Atomic: read from the HTTP thread.
struct UtxoLaneStats {
    std::atomic<uint64_t> connected{0};      // blocks connected to the set
    std::atomic<uint64_t> gaps{0};           // a block ahead of the set armed a fill
    std::atomic<uint64_t> reorgs{0};         // tip changes not descending from the old tip
    std::atomic<uint64_t> refused{0};        // connect-point refusals (utxo_connect_check)
    std::atomic<uint64_t> heals{0};          // walks that disconnected blocks
    std::atomic<uint64_t> disconnected{0};   // blocks those walks disconnected
    std::atomic<uint64_t> rebuilds{0};       // wipes + rebuilds
    std::atomic<uint64_t> heal_failures{0};  // the set could not be brought back (yet)
    std::atomic<uint64_t> headers_from_bodies{0};  // headers the header chain took from a body
    std::atomic<uint64_t> headers_requested{0};    // bodies whose parent was unknown too
    std::atomic<uint64_t> strict_refusals{0};  // full mode: bodies spending a coin the set does not hold
    std::atomic<uint64_t> bad_bodies{0};       // full mode: bodies whose Merkle root is not the header's
    std::atomic<uint64_t> complete{0};         // full mode: 1 once the set reached the header tip
    std::atomic<uint64_t> ibd_next_height{0};  // full mode: next height the fill connects
    std::atomic<uint64_t> ibd_rate_bps{0};     // full mode: blocks per second (last ~10 s)
    std::atomic<uint64_t> inflight{0};         // full mode: block requests outstanding
    std::atomic<uint64_t> peers_used{0};       // full mode: peers with requests outstanding
    std::atomic<uint64_t> peers_cooling{0};    // full mode: peers rotated out (stalling, bad bodies)
    std::atomic<uint64_t> stalls{0};           // full mode: peers that held the window's first block
    std::atomic<uint64_t> request_timeouts{0}; // full mode: requests unanswered for REQUEST_TIMEOUT
    std::atomic<uint64_t> buffer_bytes{0};     // full mode: bodies received, waiting to connect
    std::atomic<uint64_t> stall_timeout_ms{0}; // full mode: the current stall timeout
    std::atomic<uint64_t> stuck_retries{0};    // full mode: retries of a stuck height

    nlohmann::json to_json() const
    {
        auto v = [](const std::atomic<uint64_t>& a) { return a.load(std::memory_order_relaxed); };
        return {
            {"connected", v(connected)},       {"gaps", v(gaps)},
            {"reorgs", v(reorgs)},             {"refused", v(refused)},
            {"heals", v(heals)},               {"disconnected", v(disconnected)},
            {"rebuilds", v(rebuilds)},         {"heal_failures", v(heal_failures)},
            {"headers_from_bodies", v(headers_from_bodies)}, {"headers_requested", v(headers_requested)},
            {"strict_refusals", v(strict_refusals)}, {"bad_bodies", v(bad_bodies)},
            {"ibd_next_height", v(ibd_next_height)}, {"ibd_rate_bps", v(ibd_rate_bps)},
            {"inflight", v(inflight)},         {"peers_used", v(peers_used)},
            {"peers_cooling", v(peers_cooling)}, {"stalls", v(stalls)},
            {"request_timeouts", v(request_timeouts)}, {"buffer_bytes", v(buffer_bytes)},
            {"stall_timeout_ms", v(stall_timeout_ms)}, {"stuck_retries", v(stuck_retries)},
        };
    }
};

class UtxoLane {
public:
    using BlockType = ltc::coin::BlockType;
    using Fill = UtxoLaneHost::Fill;
    using Mode = UtxoLaneMode;

    /// Full mode, block download (Core net_processing.h): the window of
    /// heights ahead of the next to connect that may be requested
    /// (BLOCK_DOWNLOAD_WINDOW), requests outstanding per peer
    /// (MAX_BLOCKS_IN_TRANSIT_PER_PEER), the stall timeout for the window's
    /// first block (BLOCK_STALLING_TIMEOUT, doubled after each stall up to
    /// 64 s, halved again after 1,000 blocks without one).
    static constexpr size_t   FULL_WINDOW = 1024;
    static constexpr uint32_t PER_PEER_IN_FLIGHT = 16;
    static constexpr std::chrono::milliseconds STALL_TIMEOUT_MIN{2000};
    static constexpr std::chrono::milliseconds STALL_TIMEOUT_MAX{64000};
    /// A request unanswered this long goes to another peer.
    static constexpr std::chrono::seconds REQUEST_TIMEOUT{60};
    /// A stalling peer, or one that sent a bad body, is not asked this long.
    static constexpr std::chrono::seconds PEER_COOLDOWN{600};
    /// Memory bound of the bodies received but not yet connected (the
    /// reorder buffer): no new request while it holds this much. Worst case
    /// held: this + the requests in flight (<= PER_PEER_IN_FLIGHT per peer)
    /// x DOGE's 1 MB block size limit.
    static constexpr size_t   BUFFER_BYTES_MAX = 256u * 1024 * 1024;
    /// A height refused REFUSALS_MAX times is left alone this long, then
    /// fetched again (not only at a restart).
    static constexpr std::chrono::seconds STUCK_RETRY{600};
    /// Full mode: a progress line every this many connected blocks.
    static constexpr uint32_t PROGRESS_EVERY = 10'000;
    /// Full mode: refusals of one height before its body is asked from every
    /// peer, and before the set is left as is (heal_failures).
    static constexpr uint32_t REFUSALS_BROADCAST = 3;
    static constexpr uint32_t REFUSALS_MAX = 6;

    /// What on_block did with the block.
    enum class Fed {
        Pipeline,   // the ordered pipeline took it (buffered, maybe drained)
        Connected,  // connected now, as the set's next block
        Refused,    // the set's next height, but the connect-point check refused it
        Skipped,    // old, a copy, or not the best chain's block
    };
    struct FeedResult {
        Fed      fed{Fed::Skipped};
        bool     on_best_chain{false};
        uint32_t connected{0};  // blocks connected by this call
    };

    UtxoLane(core::coin::UTXOViewCache& utxo, core::coin::UTXOViewDB& db, UtxoLaneHost host,
             uint32_t keep = core::coin::DOGE_MIN_BLOCKS_TO_KEEP, Mode mode = Mode::Accrual,
             size_t window = 0)
        : m_utxo(utxo), m_db(db), m_host(std::move(host)), m_keep(keep), m_mode(mode)
        , m_tag(mode == Mode::Full ? "[EMB-DOGE] [full]" : "[EMB-DOGE]")
    {
        m_fill.window = window ? window : (mode == Mode::Full ? FULL_WINDOW : Fill::WINDOW_SIZE);
    }

    Mode mode() const { return m_mode; }

    UtxoLane(const UtxoLane&) = delete;
    UtxoLane& operator=(const UtxoLane&) = delete;

    /// The full-block handler: block `hash` at `height` (the header chain's
    /// height for it; 0 = unknown), received from `peer` ("" = unknown).
    FeedResult on_block(const BlockType& block, const uint256& hash, uint32_t height,
                        const std::string& peer = std::string())
    {
        using namespace ltc::coin;
        FeedResult r;
        uint256 at = height ? m_host.chain_hash_at(height) : uint256();
        // A body often arrives before the header chain knows its block: a
        // peer's inv is answered with the body at once, while headers come
        // with the periodic getheaders. The body carries its header; the
        // header chain takes it here, so the block is judged (and connected)
        // on this delivery instead of being dropped and fetched again once
        // the header lands.
        if (at != hash) {
            if (height && m_host.clean_before_header && !m_host.prev_of(hash)
                && m_host.prev_of(block.m_previous_block))
                m_host.clean_before_header(block, height);
            if (height && m_host.add_header && m_host.add_header(block)) {
                m_stats.headers_from_bodies.fetch_add(1, std::memory_order_relaxed);
                at = m_host.chain_hash_at(height);
            } else if (m_host.headers_needed && !m_host.prev_of(hash)
                       && !m_host.prev_of(block.m_previous_block)) {
                m_stats.headers_requested.fetch_add(1, std::memory_order_relaxed);
                m_host.headers_needed();
            }
        }
        r.on_best_chain = !at.IsNull() && at == hash;

        if (m_mode == Mode::Full) {
            delivered(height, peer);
            if (m_stuck && !retry_stuck(now())) {
                r.fed = Fed::Skipped;
                return r;
            }
            // 1. Full mode: the first block arms the fill from height 1 (or
            //    from best + 1 for a set built from genesis), whatever the
            //    distance.
            if (!m_bootstrap_done && !m_fill.active && height > 0) {
                m_bootstrap_done = true;
                if (arm_full(block, hash, height, r.on_best_chain)) {
                    r.fed = Fed::Pipeline;
                    return r;
                }
            }
        }

        // 1. Cold start: the first block above `keep` with the set empty or
        //    too far behind fetches the last `keep` blocks in order (a set too
        //    far behind starts its partial view at height - keep, the one
        //    deliberate jump: that first block passes the next-height and
        //    parent checks).
        if (m_mode == Mode::Accrual && !m_bootstrap_done && !m_fill.active && height > m_keep) {
            m_bootstrap_done = true;
            const uint32_t best = m_utxo.get_best_height();
            const uint32_t start = (best > 0 && best >= height - m_keep) ? best + 1 : height - m_keep;
            if (start < height) {
                ordered_arm(m_fill, start, height);
                m_fill.phase = "Bootstrap";
                m_jump_from = (best > 0 && start > best + 1) ? start : 0;
                if (r.on_best_chain)
                    ordered_buffer(m_fill, height, block, hash);
                const uint32_t asked = refill(UtxoAsk::Broadcast);
                LOG_INFO << "[EMB-DOGE] Bootstrap pipeline: " << m_fill.total << " blocks [" << start
                         << ".." << height << "] window=" << m_fill.window
                         << " requests=" << asked;
                started();
                r.fed = Fed::Pipeline;
                return r;
            }
            LOG_INFO << "[EMB-DOGE] UTXO warm restart: best=" << best << " — no bootstrap needed";
        }

        // 2. A fill is running: buffer the best chain's block, drain in order
        //    (each block through the connect-point check), recover from a
        //    refusal, keep the window full.
        if (m_fill.active) {
            if (r.on_best_chain)
                buffer(height, block, hash);
            const auto now = std::chrono::steady_clock::now();
            const auto stall =
                std::chrono::duration_cast<std::chrono::seconds>(now - m_fill.last_drain_time).count();
            if (bodies_wait()) {
                m_fill.last_drain_time = now;  // waiting is not a stall
            } else if (stall >= m_fill.STALL_TIMEOUT_SEC) {
                LOG_WARNING << m_tag << " " << m_fill.phase << " stall h=" << m_fill.next_height
                            << " (" << stall << "s) — broadcast fallback";
                m_host.request(m_fill.next_height, UtxoAsk::Broadcast);
                m_fill.last_drain_time = now;
            }
            r.connected = drain();
            if (m_fill.active)
                refill(m_fill.phase == "Bootstrap" ? UtxoAsk::Broadcast : UtxoAsk::Targeted);
            if (m_fill.active && ordered_done(m_fill)) {
                m_fill.active = false;
                stopped();
                LOG_INFO << m_tag << " " << m_fill.phase << " complete: " << m_fill.processed
                         << " blocks, UTXO at h=" << m_utxo.get_best_height();
            }
            maybe_complete();
            r.fed = Fed::Pipeline;
            return r;
        }

        // 3. Normal: strictly in order. A block further ahead (its parent
        //    still in flight, or never announced to us) is buffered and the
        //    missing heights are fetched; it is never connected over them.
        const uint32_t best = m_utxo.get_best_height();
        const auto act = r.on_best_chain ? utxo_connect_action(best, height) : UtxoConnect::Skip;
        if (act == UtxoConnect::Gap) {
            m_stats.gaps.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " UTXO gap: block h=" << height << " arrived with the UTXO set at h="
                        << best << " — buffering it and fetching " << best + 1 << ".." << height - 1
                        << " in order";
            ordered_arm(m_fill, best + 1, height);
            m_fill.phase = "UTXO gap fill";
            m_jump_from = 0;
            buffer(height, block, hash);
            refill(UtxoAsk::FromPeer);
            started();
            r.fed = Fed::Pipeline;
            return r;
        }
        if (act != UtxoConnect::Connect) {
            r.fed = Fed::Skipped;
            return r;
        }
        const ConnectCheck c = check(block, hash, height);
        if (c != ConnectCheck::Ok) {
            // NotBestChain here is the benign race between the best-chain
            // look-up and the check (the index moved).
            m_stats.refused.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " Block h=" << height << " " << hash.GetHex().substr(0, 16)
                        << "... not connected to the UTXO set (" << connect_check_name(c)
                        << "), UTXO at h=" << best << " "
                        << m_utxo.get_best_block().GetHex().substr(0, 16) << "...";
            // Keep this block for the refill: the drain uses it without
            // waiting for the heal's own request.
            if (c == ConnectCheck::ParentMismatch && heal(Heal::ParentMismatch, m_host.chain_height())
                && m_fill.active)
                buffer(height, block, hash);
            r.fed = Fed::Refused;
            return r;
        }
        if (m_mode == Mode::Full) {
            const FullConnect fc = connect_full(block, hash, height, false);
            if (fc != FullConnect::Connected) {
                // A bad body or a strict refusal: fetch the height again
                // through the fill (another peer), or leave the set as is.
                if (fc == FullConnect::Refused) {
                    on_strict_refusal(height);
                } else if (fc == FullConnect::BadBody) {
                    if (downloading())
                        cool_down(m_last_peer, now());
                    refetch_from_set();
                } else if (fc == FullConnect::WriteFailed) {
                    stop_stuck();
                }
                r.fed = Fed::Refused;
                return r;
            }
            r.connected = 1;
            r.fed = Fed::Connected;
            maybe_complete();
            return r;
        }
        connect(block, hash, height, false);
        r.connected = 1;
        r.fed = Fed::Connected;
        return r;
    }

    /// The tip-change handler. A reorg is any switch to a tip that does not
    /// descend from the old one: a sibling, a shorter heavier branch, and a
    /// heavier branch that ends higher than the old tip. The ancestor is found
    /// by walking back from THIS new tip (the live height index may already
    /// show a later tip). On a reorg the set is walked back to the best chain
    /// and the new branch is connected from there in order. Returns whether
    /// it was a reorg.
    bool on_tip_changed(const uint256& old_tip, uint32_t old_height, const uint256& new_tip,
                        uint32_t new_height)
    {
        const bool is_reorg = ltc::coin::tip_change_is_reorg(
            old_tip, old_height, new_height, [&](uint32_t h) {
                if (h > new_height)
                    return uint256();
                uint256 cur = new_tip;
                for (uint32_t at = new_height; at > h; --at) {
                    const auto p = m_host.prev_of(cur);
                    if (!p)
                        return uint256();
                    cur = *p;
                }
                return cur;
            });
        LOG_WARNING << m_tag << " Chain tip changed: " << old_tip.GetHex().substr(0, 16) << " (h="
                    << old_height << ") → " << new_tip.GetHex().substr(0, 16) << " (h=" << new_height
                    << ")" << (is_reorg ? " [REORG]" : "");
        if (is_reorg) {
            m_stats.reorgs.fetch_add(1, std::memory_order_relaxed);
            heal(Heal::Reorg, new_height);
        }
        return is_reorg;
    }

    /// Once at startup: a reorg whose tip was persisted but whose UTXO
    /// disconnect never ran (a crash in between) fires no tip change.
    void startup()
    {
        if (m_host.chain_height() > 0)
            heal(Heal::Startup, m_host.chain_height());
    }

    Fill& fill() { return m_fill; }
    const Fill& fill() const { return m_fill; }
    const UtxoLaneStats& stats() const { return m_stats; }

    /// Full mode: the set was left as is after repeated refusals or a write
    /// failure (heal_failures); the height is fetched again after STUCK_RETRY.
    bool stuck() const { return m_stuck; }

    /// The peers the block download has requests outstanding with, from any
    /// thread (the hash schedule asks other peers first).
    std::set<std::string> peers_in_use() const
    {
        std::lock_guard<std::mutex> lock(m_in_use_mu);
        return m_in_use;
    }

private:
    enum class Heal { Startup, Reorg, ParentMismatch };

    /// Full mode block download: a block request outstanding.
    struct InFlight {
        std::string peer;
        std::chrono::steady_clock::time_point sent;
    };

    /// What a full-mode connect did with a block.
    enum class FullConnect {
        Connected,
        BadBody,      // its transactions are not the ones its header commits to
        Refused,      // strict connect: an input the set does not hold
        WriteFailed,  // the set could not be written (the lane stops)
    };

    /// Buffer a best-chain block for the running fill. Full mode keeps the
    /// buffer within the request window: a block further ahead only extends
    /// the fill's range (it is asked for in order when the window gets there).
    void buffer(uint32_t height, const BlockType& block, const uint256& hash)
    {
        if (m_mode == Mode::Full && height >= m_fill.next_height + m_fill.window) {
            if (height > m_fill.end_height) {
                m_fill.end_height = height;
                m_fill.total = m_fill.processed + (m_fill.end_height - m_fill.next_height + 1);
            }
            return;
        }
        const bool fresh = height >= m_fill.next_height && !m_fill.buffer.count(height);
        ltc::coin::ordered_buffer(m_fill, height, block, hash);
        if (m_mode == Mode::Full && fresh && m_fill.buffer.count(height)) {
            const size_t bytes = body_bytes(block);
            m_sizes[height] = bytes;
            m_buffer_bytes += bytes;
            m_from[height] = m_last_peer;
            m_stats.buffer_bytes.store(m_buffer_bytes, std::memory_order_relaxed);
        }
    }

    static size_t body_bytes(const BlockType& b) { return estimate_body_bytes(b); }

    /// Full mode, the first block: arm the fill. A set that is empty or not
    /// built from genesis (no sync state, or another anchor) is (wiped and)
    /// started at height 1; a set built from genesis continues at best + 1,
    /// however far behind. Returns true when a fill was armed.
    bool arm_full(const BlockType& block, const uint256& hash, uint32_t height, bool on_best_chain)
    {
        const uint32_t tip = std::max(height, m_host.chain_height());
        const auto ss = m_utxo.sync_state();
        uint32_t from = 0;
        if (m_utxo.get_best_block().IsNull() || !ss.tracked() || ss.anchor_height != 0) {
            if (!start_from_genesis(ss.synced != 0))
                return false;
            from = 1;
        } else {
            from = m_utxo.get_best_height() + 1;
        }
        if (from > tip) {
            LOG_INFO << m_tag << " UTXO warm restart: best=" << from - 1 << " — no fill needed";
            return false;
        }
        ordered_arm(m_fill, from, tip);
        m_fill.phase = (from == 1 || tip - from > m_keep) ? "IBD" : "UTXO catch-up";
        m_jump_from = 0;
        if (on_best_chain)
            buffer(height, block, hash);
        mark_progress();
        const uint32_t asked = refill(UtxoAsk::Targeted);
        LOG_INFO << m_tag << " UTXO " << m_fill.phase << ": " << m_fill.total << " blocks [" << from << ".."
                 << tip << "] window=" << m_fill.window << " requests=" << asked;
        started();
        return true;
    }

    /// Full mode: an empty set with anchor 0 (wiping whatever the DB held).
    bool start_from_genesis(bool keep_synced)
    {
        if (!m_utxo.get_best_block().IsNull() || m_utxo.sync_state().tracked()) {
            LOG_WARNING << m_tag << " UTXO set at h=" << m_utxo.get_best_height()
                        << " was not built from genesis: wiping it, connecting from height 1";
            if (!m_utxo.reanchor()) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << m_tag << " UTXO wipe failed; set left at h=" << m_utxo.get_best_height();
                return false;
            }
            if (m_host.wiped)
                m_host.wiped();
        }
        core::coin::SyncState s;
        s.anchor_height = 0;
        s.strict = 1;
        s.synced = keep_synced ? 1 : 0;
        s.coins = 0;
        if (!m_utxo.set_sync_state(s)) {
            m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << m_tag << " UTXO sync state could not be written";
            return false;
        }
        m_completed = false;
        m_stats.complete.store(0, std::memory_order_relaxed);
        return true;
    }

    /// Full mode: the set reached the header chain's tip. Record `synced`
    /// and tell the host (once per run).
    void maybe_complete()
    {
        if (m_mode != Mode::Full || m_completed)
            return;
        const uint32_t tip = m_host.chain_height();
        if (!m_utxo.complete(tip, m_host.chain_hash_at(tip)))
            return;
        m_completed = true;
        m_stats.complete.store(1, std::memory_order_relaxed);
        auto s = m_utxo.sync_state();
        if (!s.synced) {
            s.synced = 1;
            if (!m_utxo.set_sync_state(s))
                LOG_ERROR << m_tag << " UTXO sync state (synced) could not be written";
        }
        LOG_INFO << m_tag << " UTXO set complete: h=" << m_utxo.get_best_height() << " coins=" << s.coins
                 << " (built from genesis, strictly connected)";
        if (m_host.completed)
            m_host.completed();
    }

    void mark_progress()
    {
        m_progress_time = std::chrono::steady_clock::now();
        m_progress_height = m_utxo.get_best_height();
        m_stats.ibd_next_height.store(m_progress_height + 1, std::memory_order_relaxed);
    }

    /// Full mode: a progress line every PROGRESS_EVERY connected blocks.
    void progress(uint32_t h)
    {
        m_stats.ibd_next_height.store(h + 1, std::memory_order_relaxed);
        if (h < m_progress_height + PROGRESS_EVERY)
            return;
        const auto now = std::chrono::steady_clock::now();
        const double secs = std::chrono::duration<double>(now - m_progress_time).count();
        const double rate = secs > 0 ? (h - m_progress_height) / secs : 0;
        const uint32_t tip = std::max(m_host.chain_height(), m_fill.end_height);
        const uint64_t eta = rate > 0 && tip > h ? static_cast<uint64_t>((tip - h) / rate) : 0;
        m_stats.ibd_rate_bps.store(static_cast<uint64_t>(rate), std::memory_order_relaxed);
        LOG_INFO << m_tag << " IBD h=" << h << " /" << tip << " coins=" << m_utxo.sync_state().coins
                 << " rate=" << static_cast<uint64_t>(rate) << "/s eta=" << eta / 3600 << "h"
                 << (eta % 3600) / 60 << "m";
        m_progress_time = now;
        m_progress_height = h;
    }

    static uint256 txid_of(const ltc::coin::MutableTransaction& tx) { return ltc::coin::compute_txid(tx); }

    void started()
    {
        if (m_host.fill_started)
            m_host.fill_started(m_fill);
    }
    void stopped()
    {
        if (m_host.fill_stopped)
            m_host.fill_stopped(m_fill);
    }

    /// The download waits for headers (UtxoLaneHost::bodies_wait).
    bool bodies_wait() const { return downloading() && m_host.bodies_wait && m_host.bodies_wait(); }

    uint32_t refill(UtxoAsk how)
    {
        if (downloading())
            return download_refill();
        return ltc::coin::ordered_refill(m_fill, [&](uint32_t h) { m_host.request(h, how); });
    }

    // ── Block download (full mode; the accrual set's Bootstrap) ──────────

    /// One peer per block, with per-request timeouts, the stalling-peer rule
    /// and cooldowns: the full set's download, and the accrual set's
    /// Bootstrap window (the last `keep` blocks of a set far behind). The
    /// Bootstrap asked every peer for every block before (VERIFY3 N-d): on a
    /// fresh node 6,700-11,000 bodies a minute, the link full for the hash
    /// schedule and the IBD beside it. The accrual set's other fills (a gap,
    /// a reorg) ask one peer already.
    bool downloading() const
    {
        if (!m_host.download_peers || !m_host.request_from)
            return false;
        return m_mode == Mode::Full || (m_fill.active && m_fill.phase == "Bootstrap");
    }

    std::chrono::steady_clock::time_point now() const
    {
        return m_host.now ? m_host.now() : std::chrono::steady_clock::now();
    }

    /// A body arrived from `peer`: its request is answered.
    void delivered(uint32_t height, const std::string& peer)
    {
        m_last_peer = peer;
        auto it = m_inflight.find(height);
        if (it == m_inflight.end())
            return;
        drop_request(it);
    }

    void drop_request(std::map<uint32_t, InFlight>::iterator it)
    {
        auto load = m_load.find(it->second.peer);
        if (load != m_load.end() && load->second > 0 && --load->second == 0)
            m_load.erase(load);
        m_inflight.erase(it);
    }

    /// Forget requests and buffered sizes the fill no longer covers (a
    /// re-arm cleared its buffer, the range moved).
    void sync_download_state()
    {
        for (auto it = m_sizes.begin(); it != m_sizes.end();) {
            if (it->first < m_fill.next_height || !m_fill.buffer.count(it->first)) {
                m_buffer_bytes -= std::min(m_buffer_bytes, it->second);
                m_from.erase(it->first);
                it = m_sizes.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (!m_fill.active || it->first < m_fill.next_height || it->first > m_fill.end_height
                || m_fill.buffer.count(it->first)) {
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
    }

    /// The peers to ask: the host's (NODE_NETWORK, handshaken) minus the ones
    /// cooling down; all of them if every one is cooling.
    std::vector<std::string> eligible_peers(std::chrono::steady_clock::time_point t)
    {
        if (m_peers.empty() || t - m_peers_at > std::chrono::seconds(1)) {
            m_peers = m_host.download_peers();
            m_peers_at = t;
            if (!m_peers.empty()) {
                m_no_peers_since = {};
            } else if (m_no_peers_since == std::chrono::steady_clock::time_point{}) {
                m_no_peers_since = t;
            } else if (t - m_no_peers_since > std::chrono::seconds(60)
                       && t - m_no_peers_logged > std::chrono::minutes(10)) {
                m_no_peers_logged = t;
                LOG_WARNING << m_tag << " IBD: no peer advertising NODE_NETWORK for "
                            << std::chrono::duration_cast<std::chrono::seconds>(t - m_no_peers_since).count()
                            << "s; nothing asked but the 30 s broadcast";
            }
        }
        for (auto it = m_cooldown.begin(); it != m_cooldown.end();)
            it = it->second <= t ? m_cooldown.erase(it) : std::next(it);
        m_stats.peers_cooling.store(m_cooldown.size(), std::memory_order_relaxed);
        std::vector<std::string> out;
        for (const auto& p : m_peers)
            if (!m_cooldown.count(p))
                out.push_back(p);
        return out.empty() ? m_peers : out;
    }

    /// Rotate `peer` out for PEER_COOLDOWN; its outstanding requests go to
    /// other peers at the next refill.
    void cool_down(const std::string& peer, std::chrono::steady_clock::time_point t)
    {
        if (peer.empty())
            return;
        m_cooldown[peer] = t + PEER_COOLDOWN;
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (it->second.peer == peer) {
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
        m_peers_at = {};
    }

    /// Keep the window full: every height from the next to connect up to
    /// window ahead that is neither buffered nor in flight is asked from the
    /// least loaded eligible peer with fewer than PER_PEER_IN_FLIGHT
    /// outstanding, while the reorder buffer is under its memory bound.
    uint32_t download_refill()
    {
        if (!m_fill.active || bodies_wait())
            return 0;
        const auto t = now();
        sync_download_state();
        auto peers = eligible_peers(t);
        uint32_t asked = 0;
        const uint64_t last = std::min<uint64_t>(m_fill.end_height, uint64_t(m_fill.next_height) + m_fill.window - 1);
        for (uint64_t hh = m_fill.next_height; hh <= last && !peers.empty(); ++hh) {
            if (m_buffer_bytes >= m_buffer_limit)
                break;
            const uint32_t h = static_cast<uint32_t>(hh);
            if (m_fill.buffer.count(h) || m_inflight.count(h))
                continue;
            // The least loaded peer with room; ties go round robin.
            std::string pick;
            uint32_t pick_load = PER_PEER_IN_FLIGHT;
            for (size_t i = 0; i < peers.size(); ++i) {
                const auto& p = peers[(m_peer_rr + i) % peers.size()];
                auto ld = m_load.find(p);
                const uint32_t l = ld == m_load.end() ? 0 : ld->second;
                if (l < pick_load) {
                    pick = p;
                    pick_load = l;
                }
            }
            if (pick.empty())
                break;  // every peer has PER_PEER_IN_FLIGHT outstanding
            ++m_peer_rr;
            if (!m_host.request_from(pick, h)) {
                peers.erase(std::remove(peers.begin(), peers.end(), pick), peers.end());
                m_peers_at = {};
                --hh;  // this height again, another peer
                continue;
            }
            m_inflight[h] = InFlight{pick, t};
            ++m_load[pick];
            ++asked;
        }
        m_stats.inflight.store(m_inflight.size(), std::memory_order_relaxed);
        m_stats.peers_used.store(m_load.size(), std::memory_order_relaxed);
        m_stats.buffer_bytes.store(m_buffer_bytes, std::memory_order_relaxed);
        publish_in_use();
        return asked;
    }

    void publish_in_use()
    {
        std::set<std::string> in_use;
        for (const auto& [p, n] : m_load)
            if (n > 0)
                in_use.insert(p);
        std::lock_guard<std::mutex> lock(m_in_use_mu);
        m_in_use.swap(in_use);
    }

public:
    /// The periodic check (main_ltc: every second, on the lane's thread).
    /// While a download runs (full mode; the accrual Bootstrap): requests
    /// unanswered for REQUEST_TIMEOUT go to other peers; a peer holding the
    /// window's first block past the stall timeout while later blocks wait
    /// (the window cannot move) is rotated out and its requests reassigned
    /// (Core's stalling-peer rule); the window is refilled. Full mode also
    /// retries a stuck height after STUCK_RETRY and updates the rate.
    void tick()
    {
        const auto t = now();
        if (m_mode == Mode::Full) {
            if (m_stuck)
                retry_stuck(t);
            update_rate(t);
        }
        if (!downloading() || !m_fill.active) {
            // No download runs: what is left of the last one is answered or
            // moot (the accrual lane drops a request only at its next refill).
            m_inflight.clear();
            m_load.clear();
            publish_in_use();
            return;
        }
        if (bodies_wait()) {
            // Nothing asked; the fill's stall timer sees no stall.
            m_fill.last_drain_time = std::chrono::steady_clock::now();
            publish_in_use();
            return;
        }
        sync_download_state();
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (t - it->second.sent > REQUEST_TIMEOUT) {
                m_stats.request_timeouts.fetch_add(1, std::memory_order_relaxed);
                m_cooldown[it->second.peer] = t + PEER_COOLDOWN;
                auto next = std::next(it);
                drop_request(it);
                it = next;
            } else {
                ++it;
            }
        }
        auto first = m_inflight.find(m_fill.next_height);
        if (first != m_inflight.end() && t - first->second.sent > m_stall_timeout) {
            // Core (FindNextBlocksToDownload): a staller only when nothing
            // more can be asked: the window is full, or the buffer at its
            // memory bound. A slow peer with room left in the window is left
            // to REQUEST_TIMEOUT.
            const uint32_t window_end = static_cast<uint32_t>(std::min<uint64_t>(
                m_fill.end_height, uint64_t(m_fill.next_height) + m_fill.window - 1));
            const size_t span = window_end - m_fill.next_height + 1;
            const bool window_waits = m_buffer_bytes >= m_buffer_limit
                || m_inflight.size() + m_fill.buffer.size() >= span;
            if (window_waits) {
                const std::string staller = first->second.peer;
                m_stats.stalls.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO << m_tag << " IBD: peer " << staller << " stalls h=" << m_fill.next_height << " ("
                         << std::chrono::duration_cast<std::chrono::milliseconds>(t - first->second.sent).count()
                         << " ms, timeout " << m_stall_timeout.count() << " ms): rotated out, its requests reassigned";
                cool_down(staller, t);
                m_stall_timeout = std::min(m_stall_timeout * 2, std::chrono::milliseconds(STALL_TIMEOUT_MAX));
                m_drained_since_stall = 0;
            }
        }
        m_stats.stall_timeout_ms.store(static_cast<uint64_t>(m_stall_timeout.count()), std::memory_order_relaxed);
        download_refill();
    }

    /// Tests: the reorder buffer's memory bound.
    void set_buffer_limit(size_t bytes) { m_buffer_limit = bytes; }

private:
    /// A stuck height (REFUSALS_MAX refusals) is fetched again once
    /// STUCK_RETRY has passed. Returns true when the lane runs again.
    bool retry_stuck(std::chrono::steady_clock::time_point t)
    {
        if (!m_stuck)
            return true;
        if (t - m_stuck_since < STUCK_RETRY)
            return false;
        m_stuck = false;
        m_refusal_count = 0;
        m_stats.stuck_retries.fetch_add(1, std::memory_order_relaxed);
        LOG_WARNING << m_tag << " UTXO set stuck at h=" << m_utxo.get_best_height() << " for "
                    << std::chrono::duration_cast<std::chrono::seconds>(t - m_stuck_since).count()
                    << "s: fetching h=" << m_utxo.get_best_height() + 1 << " again";
        refetch_from_set();
        return true;
    }

    void update_rate(std::chrono::steady_clock::time_point t)
    {
        const uint64_t c = m_stats.connected.load(std::memory_order_relaxed);
        if (m_rate_at == std::chrono::steady_clock::time_point{}) {
            m_rate_at = t;
            m_rate_connected = c;
            return;
        }
        const double secs = std::chrono::duration<double>(t - m_rate_at).count();
        if (secs < 10)
            return;
        m_stats.ibd_rate_bps.store(static_cast<uint64_t>((c - m_rate_connected) / secs), std::memory_order_relaxed);
        m_rate_at = t;
        m_rate_connected = c;
    }

    /// The check at every connect point; the cold start's deliberate jump
    /// passes the next-height and parent checks once. Full mode has no jump:
    /// an empty set takes only height 1, on genesis.
    ltc::coin::ConnectCheck check(const BlockType& b, const uint256& bh, uint32_t h)
    {
        using ltc::coin::ConnectCheck;
        if (m_mode == Mode::Full && m_utxo.get_best_block().IsNull()) {
            const uint256 at = m_host.chain_hash_at(h);
            if (at.IsNull() || at != bh)
                return ConnectCheck::NotBestChain;
            if (h != 1)
                return ConnectCheck::NotNext;
            const uint256 genesis = m_host.chain_hash_at(0);
            if (!genesis.IsNull() && b.m_previous_block != genesis)
                return ConnectCheck::ParentMismatch;
            return ConnectCheck::Ok;
        }
        auto c = ltc::coin::utxo_connect_check(m_utxo.get_best_height(), m_utxo.get_best_block(), h, bh,
                                               b.m_previous_block, m_host.chain_hash_at(h));
        if (m_jump_from != 0 && h == m_jump_from
            && (c == ConnectCheck::NotNext || c == ConnectCheck::ParentMismatch))
            c = ConnectCheck::Ok;
        return c;
    }

    void connect(const BlockType& b, const uint256& bh, uint32_t h, bool drained)
    {
        if (h == m_jump_from)
            m_jump_from = 0;
        auto undo = m_utxo.connect_block(b, h, &UtxoLane::txid_of, bh);
        m_db.put_block_undo(h, undo);
        m_utxo.flush(bh, h);
        m_utxo.prune_undo(h, m_keep);
        m_stats.connected.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO << "[EMB-DOGE] UTXO: block " << h << " hash=" << bh.GetHex().substr(0, 16)
                 << " txs=" << b.m_txs.size() << " cache=" << m_utxo.cache_size()
                 << (drained ? " (" + m_fill.phase + ")" : std::string());
        if (m_host.connected)
            m_host.connected(b, bh, h, drained);
    }

    /// Full mode: the body's Merkle root, then a strict connect. Undo records
    /// are kept (and pruned) only for the last `keep` blocks below the header
    /// tip: a deeper block is never disconnected (a deeper reorg rebuilds).
    FullConnect connect_full(const BlockType& b, const uint256& bh, uint32_t h, bool drained)
    {
        std::vector<uint256> txids;
        txids.reserve(b.m_txs.size());
        for (const auto& tx : b.m_txs)
            txids.push_back(txid_of(tx));
        bool mutated = false;
        if (txids.empty() || merkle_root_of(txids, &mutated) != b.m_merkle_root || mutated) {
            m_stats.refused.fetch_add(1, std::memory_order_relaxed);
            m_stats.bad_bodies.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " Block h=" << h << " " << bh.GetHex().substr(0, 16) << "...: "
                        << (mutated ? "duplicated transactions under the header's Merkle root (CVE-2012-2459)"
                                    : "its transactions are not the ones its header commits to (Merkle root)")
                        << "; fetching it from another peer";
            return FullConnect::BadBody;
        }
        core::coin::UTXOViewCache::StrictRefusal why;
        size_t next = 0;
        auto undo = m_utxo.connect_block(
            b, h, [&](const ltc::coin::MutableTransaction&) { return txids[next++]; }, bh, true, &why);
        if (!undo && why.spent_in_block) {
            // An output spent twice inside the body: no valid block does
            // that, so this body is not the best chain's block (a mutated or
            // forged body). The peer's fault, not the set's.
            m_stats.refused.fetch_add(1, std::memory_order_relaxed);
            m_stats.bad_bodies.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " Block h=" << h << " " << bh.GetHex().substr(0, 16) << "...: tx "
                        << why.txid.GetHex() << " spends " << why.missing.txid.GetHex() << ":"
                        << why.missing.index << " already spent in the same body; fetching it from another peer";
            return FullConnect::BadBody;
        }
        if (!undo) {
            m_stats.refused.fetch_add(1, std::memory_order_relaxed);
            m_stats.strict_refusals.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << m_tag << " Block h=" << h << " " << bh.GetHex().substr(0, 16) << "... refused: tx "
                      << why.txid.GetHex() << " (#" << why.tx_index << ") spends "
                      << why.missing.txid.GetHex() << ":" << why.missing.index
                      << ", which the UTXO set does not hold";
            return FullConnect::Refused;
        }
        const uint32_t tip = m_host.chain_height();
        const bool near_tip = h + m_keep >= tip;
        if (near_tip)
            m_db.put_block_undo(h, *undo);
        if (!m_utxo.flush(bh, h)) {
            m_utxo.discard_pending();  // the set is the DB's, at its best block
            m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << m_tag << " UTXO write failed at h=" << h << " (disk?); the lane stops, set at h="
                      << m_utxo.get_best_height();
            return FullConnect::WriteFailed;
        }
        if (near_tip)
            m_utxo.prune_undo(h, m_keep);
        m_stats.connected.fetch_add(1, std::memory_order_relaxed);
        progress(h);
        if (near_tip)
            LOG_INFO << "[EMB-DOGE] UTXO: block " << h << " hash=" << bh.GetHex().substr(0, 16)
                     << " txs=" << b.m_txs.size() << " set=full"
                     << (drained ? " (" + m_fill.phase + ")" : std::string());
        if (m_host.connected)
            m_host.connected(b, bh, h, drained);
        return FullConnect::Connected;
    }

    /// A buffered body leaves the reorder buffer (to connect): its bytes are
    /// released; returns the peer that sent it.
    std::string release_buffered(uint32_t h)
    {
        std::string peer;
        auto sz = m_sizes.find(h);
        if (sz != m_sizes.end()) {
            m_buffer_bytes -= std::min(m_buffer_bytes, sz->second);
            m_sizes.erase(sz);
        }
        auto f = m_from.find(h);
        if (f != m_from.end()) {
            peer = f->second;
            m_from.erase(f);
        }
        return peer;
    }

    /// Full mode: restart the fill at the set's next height (another peer
    /// is asked: the requests go round robin).
    void refetch_from_set()
    {
        const uint32_t best = m_utxo.get_best_height();
        const uint32_t to = std::max(m_host.chain_height(), m_fill.active ? m_fill.end_height : 0u);
        const std::string phase = m_fill.active ? m_fill.phase : std::string("UTXO refetch");
        if (to <= best)
            return;
        const bool was_active = m_fill.active;
        ordered_arm(m_fill, best + 1, to);
        m_fill.phase = phase;
        refill(UtxoAsk::Targeted);
        if (!was_active)
            started();
    }

    /// Full mode: a body spending a coin the set does not hold. The body
    /// is asked for again (another peer; from every peer from the third
    /// refusal of that height); past REFUSALS_MAX the set is left as is.
    void on_strict_refusal(uint32_t h)
    {
        if (m_refusal_height != h) {
            m_refusal_height = h;
            m_refusal_count = 0;
        }
        ++m_refusal_count;
        if (m_refusal_count >= REFUSALS_MAX) {
            m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << m_tag << " UTXO set refused h=" << h << " " << m_refusal_count
                      << " times: left as is at h=" << m_utxo.get_best_height()
                      << " (templates stay coinbase-only; fetched again in "
                      << STUCK_RETRY.count() << "s)";
            stop_stuck();
            return;
        }
        refetch_height();
        if (m_refusal_count >= REFUSALS_BROADCAST)
            m_host.request(h, UtxoAsk::Broadcast);
    }

    /// The next height again: with the block download, a height neither
    /// buffered nor in flight is asked at the next refill (from an eligible
    /// peer); otherwise the fill restarts at the set's next height.
    void refetch_height()
    {
        if (downloading() && m_fill.active)
            download_refill();
        else
            refetch_from_set();
    }

    void stop_stuck()
    {
        m_stuck = true;
        m_stuck_since = now();
        m_fill.buffer.clear();
        if (m_fill.active) {
            m_fill.active = false;
            stopped();
        }
    }

    /// Full mode's drain: ordered_drain's loop with the body checks and the
    /// strict connect between the connect-point check and the next height.
    uint32_t drain_full()
    {
        using ltc::coin::ConnectCheck;
        ltc::coin::DrainResult r;
        FullConnect failed = FullConnect::Connected;
        std::string from;
        while (m_fill.buffer.count(m_fill.next_height)) {
            auto node = m_fill.buffer.extract(m_fill.next_height);
            auto& [b, bh] = node.mapped();
            const uint32_t h = m_fill.next_height;
            from = release_buffered(h);
            const ConnectCheck c = check(b, bh, h);
            if (c != ConnectCheck::Ok) {
                r.refused = c;
                r.refused_height = h;
                break;
            }
            failed = connect_full(b, bh, h, true);
            if (failed != FullConnect::Connected) {
                r.refused_height = h;
                break;
            }
            ++m_fill.next_height;
            ++m_fill.processed;
            m_fill.last_drain_time = std::chrono::steady_clock::now();
            ++r.connected;
            if (++m_drained_since_stall >= 1000 && m_stall_timeout > STALL_TIMEOUT_MIN) {
                m_stall_timeout = std::max(m_stall_timeout / 2, std::chrono::milliseconds(STALL_TIMEOUT_MIN));
                m_drained_since_stall = 0;
            }
        }
        m_stats.buffer_bytes.store(m_buffer_bytes, std::memory_order_relaxed);
        switch (failed) {
        case FullConnect::Connected:
            break;
        case FullConnect::BadBody:
            // The peer that sent it is rotated out; the height goes to another.
            if (downloading()) {
                cool_down(from, now());
                download_refill();
            } else {
                refetch_from_set();
            }
            return r.connected;
        case FullConnect::Refused:
            on_strict_refusal(r.refused_height);
            return r.connected;
        case FullConnect::WriteFailed:
            stop_stuck();
            return r.connected;
        }
        if (r.refused == ConnectCheck::Ok)
            return r.connected;
        on_refused(r);
        return r.connected;
    }

    /// Drain the buffer in order; on a refused block restart the fill at the
    /// set's real next height, or heal a set that is on another branch.
    uint32_t drain()
    {
        using ltc::coin::ConnectCheck;
        if (m_mode == Mode::Full)
            return drain_full();
        const auto drained = ltc::coin::ordered_drain(
            m_fill, [&](const BlockType& b, const uint256& bh, uint32_t h) { return check(b, bh, h); },
            [&](const BlockType& b, const uint256& bh, uint32_t h) { connect(b, bh, h, true); });
        if (drained.refused == ConnectCheck::Ok)
            return drained.connected;
        on_refused(drained);
        return drained.connected;
    }

    /// A block the connect-point check refused during a drain.
    void on_refused(const ltc::coin::DrainResult& drained)
    {
        using ltc::coin::ConnectCheck;
        m_stats.refused.fetch_add(1, std::memory_order_relaxed);
        LOG_WARNING << m_tag << " " << m_fill.phase << ": block h=" << drained.refused_height
                    << " not connected (" << ltc::coin::connect_check_name(drained.refused)
                    << "), UTXO at h=" << m_utxo.get_best_height();
        // Restart at the set's next height, or at the pipeline's own start
        // while the set is empty / before the cold start's deliberate jump.
        const bool from_pipeline = m_utxo.get_best_block().IsNull() || m_jump_from != 0;
        const uint32_t base = from_pipeline ? (m_fill.next_height > 0 ? m_fill.next_height - 1 : 0)
                                            : m_utxo.get_best_height();
        if (drained.refused == ConnectCheck::ParentMismatch) {
            // The set itself is on another branch: walk it back to the best
            // chain and refill from there.
            if (!heal(Heal::ParentMismatch, m_host.chain_height())) {
                m_fill.active = false;
                m_fill.buffer.clear();
                stopped();
                m_jump_from = 0;
            }
        } else if (ltc::coin::ordered_recover(m_fill, drained.refused, base, m_host.chain_height())) {
            refill(UtxoAsk::Targeted);
        } else {
            stopped();
            m_jump_from = 0;
            LOG_ERROR << m_tag << " " << m_fill.phase << " stopped at h=" << m_utxo.get_best_height()
                      << " (" << ltc::coin::connect_check_name(drained.refused) << ")";
        }
    }

    /// Bring the set back onto the best chain (main_ltc's EMB-LTC utxo_heal,
    /// same rules): walk its best back by its undo records, at most `keep`
    /// blocks, until its block is the best chain's at that height; flush;
    /// then connect the best chain in order from there to target_height.
    /// Undo records go only after the flush (a crash mid-walk leaves the DB at
    /// its old best with its undo intact). When the walk can never get there
    /// the set is wiped and rebuilt from the best chain (returns true). Returns
    /// false when it cannot be brought back now (a height the header chain
    /// cannot judge), or, for a parent mismatch, when the set's best is
    /// already on the best chain (refilling would hit the same mismatch).
    bool heal(Heal kind, uint32_t target_height)
    {
        using namespace ltc::coin;
        const char* reason =
            kind == Heal::Startup ? "startup" : kind == Heal::Reorg ? "reorg" : "parent mismatch";
        const uint32_t before = m_utxo.get_best_height();
        std::vector<uint32_t> undone;
        const auto rw = rewind_to_best_chain(
            m_keep, m_host.chain_height(), before, m_utxo.get_best_block(), m_host.chain_hash_at,
            m_host.prev_of, [&](uint32_t h, const uint256& hh) {
                const auto w = disconnect_with_undo(m_db, m_utxo, h, hh);
                if (w == RewindResult::Why::None)
                    undone.push_back(h);
                return w;
            });
        if (rw.disconnected > 0) {
            if (!m_utxo.flush(rw.hash, rw.height)) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << m_tag << " UTXO flush failed after disconnecting " << rw.disconnected
                          << " blocks (" << reason << "); undo data kept, UTXO DB still at h=" << before;
                return false;
            }
            for (uint32_t h : undone)
                m_db.remove_block_undo(h);
            m_stats.heals.fetch_add(1, std::memory_order_relaxed);
            m_stats.disconnected.fetch_add(rw.disconnected, std::memory_order_relaxed);
            LOG_WARNING << m_tag << " UTXO rewound to the best chain (" << reason << "): disconnected "
                        << rw.disconnected << " blocks (h=" << before << "→" << rw.height
                        << ") best=" << rw.hash.GetHex().substr(0, 16);
        }
        if (rw.permanent() && m_mode == Mode::Full) {
            // The set cannot be walked back: rebuild it from genesis (the
            // same IBD; templates stay coinbase-only meanwhile).
            const uint32_t to = std::max(target_height, m_host.chain_height());
            LOG_ERROR << m_tag << " UTXO set cannot be brought back to the best chain (" << reason << ": "
                      << rewind_why_name(rw.why) << " at h=" << rw.height
                      << "); rebuilding it from genesis: 1.." << to;
            const bool was_synced = m_utxo.sync_state().synced != 0;
            if (!m_utxo.reanchor()) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << m_tag << " UTXO re-anchor failed (DB wipe); set left at h="
                          << m_utxo.get_best_height();
                return false;
            }
            m_stats.rebuilds.fetch_add(1, std::memory_order_relaxed);
            if (m_host.wiped)
                m_host.wiped();
            if (!start_from_genesis(was_synced))
                return false;
            ordered_arm(m_fill, 1, to);
            m_fill.phase = "IBD";
            m_jump_from = 0;
            mark_progress();
            refill(UtxoAsk::Targeted);
            started();
            return true;
        }
        if (rw.permanent()) {
            // The walk can never get further: wipe the set and connect the
            // best chain's last `keep` blocks into it, as a cold start does
            // (the mining gate closes until DOGE_MINING_GATE_DEPTH reconnect).
            const uint32_t tip = m_host.chain_height();
            const uint32_t from = utxo_rebuild_from(tip, m_keep);
            const uint32_t to = std::max(target_height, tip);
            LOG_ERROR << "[EMB-DOGE] UTXO set cannot be brought back to the best chain (" << reason
                      << ": " << rewind_why_name(rw.why) << " at h=" << rw.height
                      << "); re-anchoring: wiping the UTXO set and rebuilding " << from << ".." << to
                      << " from the best chain";
            if (!m_utxo.reanchor()) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << m_tag << " UTXO re-anchor failed (DB wipe); set left at h="
                          << m_utxo.get_best_height();
                return false;
            }
            m_stats.rebuilds.fetch_add(1, std::memory_order_relaxed);
            if (m_host.wiped)
                m_host.wiped();
            ordered_arm(m_fill, from, to);
            m_fill.phase = "UTXO rebuild";
            m_jump_from = from;
            refill(UtxoAsk::Targeted);
            started();
            return true;
        }
        if (!rw.ok) {
            m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << m_tag << " UTXO set cannot be brought back to the best chain (" << reason << ": "
                      << rewind_why_name(rw.why) << "): stuck at h=" << rw.height << " "
                      << rw.hash.GetHex().substr(0, 16) << "...";
            return false;
        }
        if (rw.disconnected == 0 && kind == Heal::ParentMismatch) {
            LOG_WARNING << m_tag << " Parent mismatch at h=" << before + 1
                        << " but the UTXO set's best is on the best chain; not refilling";
            return false;
        }
        if (rw.disconnected == 0 && kind == Heal::Startup)
            return true;
        // Full mode, a reorg near the tip while the fill is still far below
        // it: nothing the fill asked for or holds is affected; its range
        // follows the new tip.
        if (m_mode == Mode::Full && rw.disconnected == 0 && m_fill.active
            && m_fill.next_request + m_keep < target_height) {
            m_fill.end_height = target_height;
            m_fill.total = m_fill.processed + (m_fill.end_height - m_fill.next_height + 1);
            return true;
        }
        // Connect the best chain in order from the set's REAL best, whatever
        // the pipeline was doing (it may have drained past the fork and may
        // hold old-branch blocks). An empty set (cold start, nothing drained
        // yet) restarts at the pipeline's own start instead.
        const bool empty = m_utxo.get_best_block().IsNull() || (m_fill.active && m_jump_from != 0);
        const bool was_cold_start = m_fill.active && (m_fill.phase == "Bootstrap" || m_fill.phase == "IBD");
        const uint32_t best_now =
            empty ? (m_fill.active && m_fill.next_height > 0 ? m_fill.next_height - 1 : 0)
                  : m_utxo.get_best_height();
        if ((!empty || m_fill.active) && ordered_rearm_after_reorg(m_fill, best_now, target_height)) {
            if (!was_cold_start) {
                m_fill.phase = "UTXO reorg fill";
                m_jump_from = 0;
            }
            LOG_WARNING << m_tag << " UTXO reorg fill (" << reason << "): connecting " << best_now + 1
                        << ".." << target_height << " in order";
            refill(UtxoAsk::Targeted);
            started();
        }
        return true;
    }

    core::coin::UTXOViewCache& m_utxo;
    core::coin::UTXOViewDB&    m_db;
    UtxoLaneHost               m_host;
    const uint32_t             m_keep;
    const Mode                 m_mode;
    const char*                m_tag;           // log prefix
    Fill                       m_fill;
    bool                       m_bootstrap_done{false};
    uint32_t                   m_jump_from{0};  // the cold start's deliberate jump (0 = none)
    UtxoLaneStats              m_stats;
    // Full mode
    bool                       m_completed{false};   // completed() fired this run
    bool                       m_stuck{false};       // left as is (heal_failures) until STUCK_RETRY
    std::chrono::steady_clock::time_point m_stuck_since{};
    uint32_t                   m_refusal_height{0};  // the height strict connect refused last
    uint32_t                   m_refusal_count{0};   // ... and how many times in a row
    std::chrono::steady_clock::time_point m_progress_time{std::chrono::steady_clock::now()};
    uint32_t                   m_progress_height{0};
    std::chrono::steady_clock::time_point m_rate_at{};
    uint64_t                   m_rate_connected{0};
    // Full mode block download (downloading())
    std::map<uint32_t, InFlight>        m_inflight;   // height -> its request
    std::map<std::string, uint32_t>     m_load;       // peer -> requests outstanding
    std::map<std::string, std::chrono::steady_clock::time_point> m_cooldown;  // peer -> not asked until
    std::vector<std::string>            m_peers;      // the host's download peers (refreshed each second)
    std::chrono::steady_clock::time_point m_peers_at{};
    size_t                              m_peer_rr{0};
    std::chrono::steady_clock::time_point m_no_peers_since{};
    std::chrono::steady_clock::time_point m_no_peers_logged{};
    std::map<uint32_t, size_t>          m_sizes;      // buffered height -> body bytes
    std::map<uint32_t, std::string>     m_from;       // buffered height -> the peer that sent it
    std::string                         m_last_peer;  // the peer of the body being handled
    size_t                              m_buffer_bytes{0};
    size_t                              m_buffer_limit{BUFFER_BYTES_MAX};
    std::chrono::milliseconds           m_stall_timeout{STALL_TIMEOUT_MIN};
    uint32_t                            m_drained_since_stall{0};
    mutable std::mutex                  m_in_use_mu;
    std::set<std::string>               m_in_use;     // peers_in_use(): m_load's peers, for other threads
};

} // namespace coin
} // namespace doge
