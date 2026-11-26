// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// The standalone coin peer pool, for any coin whose types follow the BTC coin
// layer: a pool of outbound coin-network peers (kCoinPoolTargetPeers) drawn from
// the coin's peer manager. It replaces the single standalone header-source
// connection. coin_peer_pool.hpp instantiates it for c2pool-btc (main_btc.cpp,
// coin_peer_pool_test.cpp) and impl/bip110/coin/coin_peer_pool.hpp for
// c2pool-bip110 (main_bip110.cpp). This header holds no coin types: the `Coin`
// parameter supplies them,
//
//   struct Coin {
//       using Header = ...;   // block header (m_previous_block)
//       using Block  = ...;   // a Header with m_txs
//       using Tx     = ...;   // a relayed transaction (HasWitness())
//       // The block's identity: the hash the header chain is keyed by and
//       // that inv / getdata carry.
//       static uint256 header_hash(const Header&);
//       static uint256 txid(const Tx&);    // non-witness serialization
//       static uint256 wtxid(const Tx&);   // with witness
//   };
//
// and the pool does:
//
//   - slots: up to the target; a slot that does not complete its handshake
//     within kCoinPoolDialTimeoutSec is dropped as a failed dial, one whose
//     link stays down for kCoinPoolLostGraceSec after a handshake is dropped
//     as a disconnect (both reported to the peer manager; a handshake is
//     reported as connected once per slot); every tick refills from the
//     manager's candidates;
//   - headers: from any pooled peer. A batch that connects and carries a new
//     last header goes to the header chain path; a full batch (2000) asks its
//     sender for the next one. A small batch that does not connect, or an
//     inv of a block the chain does not have, asks that peer for headers from
//     the chain's locator: not while a getheaders to it from an announcement
//     is unanswered (kCoinPoolAskResponseSec), at most every
//     kCoinPoolAskEverySec per peer, and while catching up only the first
//     announcer of a block. An empty headers answer from a peer whose version
//     height equals the chain's height marks header sync caught up;
//   - the header-source tick (header_source_step over the whole pool, every
//     kCoinPoolTickSec): a fresh handshake asks that peer; catching up, a
//     tick without progress asks one peer (round robin); caught up, the
//     refresh asks every peer; a failover drops the pooled peer that moved
//     the tip least recently (max of its last tip-moving headers message and
//     its handshake; a peer handshaked less than kCoinPoolFailoverMinAgeSec
//     ago is not dropped) and asks the rest (one catching up, all caught up);
//   - block bodies: fetched only for a block whose header the chain holds,
//     at or above the UTXO set's best height and within kCoinPoolMaxBodyGap+1
//     of the header tip (pool_body_wanted), from its first announcer; at most
//     kCoinPoolBodiesMax tracked (room is kept for the tip's block). A body not
//     received after kCoinPoolBodyRetrySec (kCoinPoolTipBodyRetrySec for the
//     tip) is asked of another peer (pool_body_retry): kCoinPoolBodyMaxAsks
//     asks sent, then kept for a late body until kCoinPoolBodyKeepSec after
//     the first ask; the tip's block is never given up while it is the tip.
//     A body that does not match its header (body_valid) from the peer it was
//     asked of is asked of another peer at once, without using up an ask
//     (once per peer; a body nobody asked for is not followed up). A valid
//     body reaches the coin node's full_block path (mempool cleanup, work
//     refresh) once, on arrival, and the UTXO connect (on_body_in_order) in
//     chain order: one more than one block above the UTXO set's best
//     (body_best_height) waits for its parent, which is asked for, for at
//     most kCoinPoolBodyHoldSec, and after its connect the UTXO-based mempool
//     maintenance runs (after_late_connect, once per run of such connects);
//     with no other peer to ask, the peer asked last is asked again only
//     after pool_same_peer_backoff_sec or a new handshake; a gap of more than
//     kCoinPoolMaxBodyGap blocks is passed on as it is;
//     TODO: a header-tip jump of more than kCoinPoolMaxBodyGap + 1 blocks, or
//     a large headers batch (no BIP 130 announcement), fetches no body, so
//     after an outage the blocks it skipped get no mempool pass (their
//     confirmed transactions leave the mempool only as they expire);
//   - transactions: fetched from the first announcer; the others are kept,
//     and one not received after kCoinPoolTxRetrySec is asked of the next.
//     At most kCoinPoolSeenTxMax tracked, the oldest evicted first, each for
//     kCoinPoolSeenTtlSec;
//   - a won block goes to every pooled peer with a completed handshake; the
//     same bytes (SHA256d of the whole block) once per kCoinPoolRelayDedupSec;
//   - the dashboard rows: one per pooled peer with a completed handshake;
//   - on request, getdata for transactions from one pooled peer (the next one
//     each call; request_txs, one message), the keys of every slot
//     (slot_keys), and the bodies of given blocks whose headers the chain
//     holds, outside pool_body_wanted (fetch_bodies: a caller's catch-up,
//     tracked, retried and delivered in chain order like any other body);
//   - a body that does not match its header, from a peer not seen sending a
//     bad one for that block, is reported with the number of such peers
//     (on_bad_body, optional).
//
// IO-thread only, except rows() and live_count() (any thread).

#include "header_source_step.hpp"

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace btc::coin {

inline constexpr size_t  kCoinPoolTargetPeers       = 8;
inline constexpr int64_t kCoinPoolTickSec           = 12;
inline constexpr int64_t kCoinPoolPollSec           = 3;
inline constexpr int64_t kCoinPoolDialTimeoutSec    = 30;
inline constexpr int64_t kCoinPoolLostGraceSec      = 90;
inline constexpr size_t  kCoinPoolFullHeadersBatch  = 2000;
inline constexpr size_t  kCoinPoolAnnouncementMax   = 3;
inline constexpr int64_t kCoinPoolAskResponseSec    = 120;
inline constexpr int64_t kCoinPoolAskEverySec       = 2;
inline constexpr int64_t kCoinPoolFailoverMinAgeSec = 40;
inline constexpr int64_t kCoinPoolBodyRetrySec      = 20;
inline constexpr int64_t kCoinPoolTipBodyRetrySec   = 3;
inline constexpr int     kCoinPoolBodyMaxAsks       = 3;
inline constexpr int64_t kCoinPoolBodyKeepSec       = 60;
inline constexpr int64_t kCoinPoolBadBodyLogSec     = 600;
inline constexpr size_t  kCoinPoolBodiesMax         = 64;
inline constexpr int64_t kCoinPoolBodyHoldSec       = 60;
inline constexpr uint32_t kCoinPoolMaxBodyGap       = 6;
inline constexpr int64_t kCoinPoolSeenTtlSec        = 600;
inline constexpr int64_t kCoinPoolTxRetrySec        = 60;
inline constexpr size_t  kCoinPoolTxAnnouncersMax   = 8;
inline constexpr size_t  kCoinPoolSeenTxMax         = 50000;
inline constexpr int64_t kCoinPoolRelayDedupSec     = 120;

// ── Rules ────────────────────────────────────────────────────────────────────

/// New dials one tick may start: up to the target slot count.
inline size_t pool_dials_needed(size_t slots, size_t target)
{
    return slots >= target ? 0 : target - slots;
}

enum class PoolSlotVerdict { Keep, DialFailed, Disconnected };

/// since_dial_sec: since the slot was dialed; since_lost_sec: since its link
/// was seen down after a handshake.
inline PoolSlotVerdict pool_slot_verdict(bool handshaked, bool ever_handshaked,
                                         int64_t since_dial_sec, int64_t since_lost_sec)
{
    if (handshaked)
        return PoolSlotVerdict::Keep;
    if (!ever_handshaked)
        return since_dial_sec >= kCoinPoolDialTimeoutSec ? PoolSlotVerdict::DialFailed
                                                         : PoolSlotVerdict::Keep;
    return since_lost_sec >= kCoinPoolLostGraceSec ? PoolSlotVerdict::Disconnected
                                                   : PoolSlotVerdict::Keep;
}

enum class PoolHeadersVerdict { Ignore, Forward, ForwardAndContinue, AskSender };

/// A headers message: connects = its first header's parent is in the chain
/// (or it is the genesis header); last_known = the chain has its last header.
inline PoolHeadersVerdict pool_headers_verdict(size_t count, bool connects, bool last_known)
{
    if (count == 0)
        return PoolHeadersVerdict::Ignore;
    if (!connects)
        return count <= kCoinPoolAnnouncementMax ? PoolHeadersVerdict::AskSender
                                                 : PoolHeadersVerdict::Ignore;
    if (last_known)
        return PoolHeadersVerdict::Ignore;
    return count >= kCoinPoolFullHeadersBatch ? PoolHeadersVerdict::ForwardAndContinue
                                              : PoolHeadersVerdict::Forward;
}

/// A block the chain cannot place was announced by a peer: ask it? unanswered:
/// an announcement getheaders to that peer has had no headers reply;
/// since_ask_sec: since the last one to it; same_block: while catching up,
/// the block is the one the previous ask was about.
inline bool pool_announce_asks(bool unanswered, int64_t since_ask_sec,
                               bool caught_up, bool same_block)
{
    if (unanswered && since_ask_sec < kCoinPoolAskResponseSec)
        return false;
    if (since_ask_sec < kCoinPoolAskEverySec)
        return false;
    if (!caught_up && same_block)
        return false;
    return true;
}

/// A headers message with `count` entries from a peer whose version height is
/// `peer_height`: does it show header sync caught up? Only an empty answer
/// from a peer at exactly the chain's height (a higher peer that answers with
/// nothing is below its minimum chain work, or its height is wrong).
inline bool pool_empty_headers_caught_up(size_t count, uint32_t peer_height,
                                         uint32_t chain_height)
{
    return count == 0 && peer_height == chain_height;
}

/// Seconds before an asked-for block body is asked of another peer.
inline int64_t pool_body_retry_sec(bool tip)
{
    return tip ? kCoinPoolTipBodyRetrySec : kCoinPoolBodyRetrySec;
}

/// A block body asked again of the same peer (no other peer to ask) waits
/// for this long since the last ask sent: 20 s, 60 s, then 180 s, by the
/// number of such asks in a row so far. A new handshake of that peer lifts it.
inline int64_t pool_same_peer_backoff_sec(int same_asks)
{
    return same_asks <= 0 ? 20 : (same_asks == 1 ? 60 : 180);
}

enum class PoolBodyRetry { Wait, Ask, GiveUp };

/// An asked-for block body that has not arrived. asks: asks sent (a body that
/// did not match its header does not count); since_ask_sec / since_first_sec:
/// since the last / the first ask; tip: it is the header tip's block now.
/// Retries at pool_body_retry_sec until kCoinPoolBodyMaxAsks asks; then the
/// tip's block is asked again every kCoinPoolBodyRetrySec while it is the tip,
/// any other block is kept (a late body is still taken) until
/// kCoinPoolBodyKeepSec after the first ask.
inline PoolBodyRetry pool_body_retry(bool tip, int asks, int64_t since_ask_sec,
                                     int64_t since_first_sec)
{
    if (asks >= kCoinPoolBodyMaxAsks && !tip)
        return since_first_sec >= kCoinPoolBodyKeepSec ? PoolBodyRetry::GiveUp
                                                       : PoolBodyRetry::Wait;
    const int64_t delay = asks >= kCoinPoolBodyMaxAsks ? kCoinPoolBodyRetrySec
                                                       : pool_body_retry_sec(tip);
    return since_ask_sec >= delay ? PoolBodyRetry::Ask : PoolBodyRetry::Wait;
}

/// Fetch the body of a block at `height`? Only near the header tip
/// (`tip_height`; within kCoinPoolMaxBodyGap + 1) and not below the UTXO
/// set's best height (`best`; a block at that height is still fetched: a
/// competing block there needs its mempool pass). Bodies of older blocks are
/// not fetched (an inv of history cannot fill the tracked set).
inline bool pool_body_wanted(uint32_t height, uint32_t tip_height, std::optional<uint32_t> best)
{
    if (best && height < *best)
        return false;
    return static_cast<uint64_t>(height) + kCoinPoolMaxBodyGap + 1 >= tip_height;
}

enum class PoolBodyOrder { Deliver, Hold, DeliverWithGap };

/// A valid block body at `height`; `best` = the body consumer's best height
/// (nullopt: it holds nothing yet). The next one or anything at or below it
/// is delivered; up to kCoinPoolMaxBodyGap missing blocks in between it
/// waits for them; a larger gap is delivered as it is.
inline PoolBodyOrder pool_body_order(std::optional<uint32_t> best, uint32_t height)
{
    if (!best || height <= *best + 1)
        return PoolBodyOrder::Deliver;
    return height - (*best + 1) <= kCoinPoolMaxBodyGap ? PoolBodyOrder::Hold
                                                       : PoolBodyOrder::DeliverWithGap;
}

// ── Dashboard rows ───────────────────────────────────────────────────────────

/// One connected coin peer, as the dashboard shows it.
struct CoinPeerRow {
    std::string addr;           // host:port
    bool        routable{false};
    std::string subver;
    uint32_t    start_height{0};
    int64_t     conntime{0};    // seconds since the handshake
};

struct CoinPeerRows {
    nlohmann::json peers = nlohmann::json::array();
    uint32_t       max_start_height{0};
};

/// The coin sync-status "peers" array: a row per connected peer (an address
/// that is not publicly routable is shown as "private"), then an idle row per
/// candidate key that is not connected.
inline CoinPeerRows coin_peer_rows(const std::vector<CoinPeerRow>& live,
                                   const std::vector<std::string>& idle_keys)
{
    CoinPeerRows out;
    std::set<std::string> live_addrs;
    for (const auto& r : live) {
        live_addrs.insert(r.addr);
        out.max_start_height = std::max(out.max_start_height, r.start_height);
        out.peers.push_back({
            {"addr", r.routable ? r.addr : std::string("private")},
            {"subver", r.subver},
            {"startingheight", r.start_height},
            {"conntime", r.conntime},
            {"connected", true},
        });
    }
    for (const auto& key : idle_keys) {
        if (live_addrs.count(key))
            continue;
        out.peers.push_back({{"addr", key}, {"connected", false}});
    }
    return out;
}

// ── Pooled connection ────────────────────────────────────────────────────────

/// What a pooled connection reports; the pool installs these when it dials.
template <typename Coin>
struct BasicPoolPeerHooks {
    using BlockHeaderType = typename Coin::Header;
    using BlockType       = typename Coin::Block;
    using Transaction     = typename Coin::Tx;

    /// Every headers message, with its entry count (empty ones included).
    std::function<void(size_t count)>                        headers_message;
    std::function<void(const std::vector<BlockHeaderType>&)> headers;
    std::function<void(const uint256&)>                      block_announced;
    std::function<void(const Transaction&)>                  tx;
    std::function<void(const BlockType&)>                    full_block;
    /// Consulted before the getdata for an announced block / transaction.
    std::function<bool(const uint256&, bool is_block)>       fetch;
};

/// One outbound coin-network connection (a BasicNodeP2PPoolPeer in production).
class PoolPeer {
public:
    virtual ~PoolPeer() = default;
    virtual bool        handshaked() const = 0;
    virtual std::string subver() const = 0;
    virtual uint32_t    start_height() const = 0;
    virtual void        send_getheaders(const std::vector<uint256>& locator,
                                        const uint256& stop) = 0;
    /// Relay a serialized block; true iff it was written to the peer.
    virtual bool        relay_block(const std::vector<unsigned char>& block_bytes) = 0;
    /// getdata for a block body / a transaction.
    virtual void        request_block(const uint256& hash) = 0;
    virtual void        request_tx(const uint256& txid) = 0;
    /// getdata for several transactions (one message where the connection
    /// can; by default one request_tx each).
    virtual void        request_txs(const std::vector<uint256>& txids)
    {
        for (const auto& h : txids)
            request_tx(h);
    }
};

/// What the pool needs from its surroundings.
template <typename Coin>
struct BasicCoinPeerPoolHost {
    using Clock           = std::chrono::steady_clock;
    using BlockHeaderType = typename Coin::Header;
    using BlockType       = typename Coin::Block;
    using Transaction     = typename Coin::Tx;
    using PoolPeerHooks   = BasicPoolPeerHooks<Coin>;

    /// Dial `addr`; the connection reports through `hooks`. nullptr = failed.
    std::function<std::unique_ptr<PoolPeer>(const NetService& addr, PoolPeerHooks hooks)> dial;
    /// Candidate peers not in `exclude` (the peer manager's get_peers_to_connect).
    std::function<std::vector<PeerEndpoint>(const std::set<std::string>& exclude)> candidates;
    /// Peer manager reports (optional).
    std::function<void(const std::string&)> connected;
    std::function<void(const std::string&)> disconnected;
    std::function<void(const std::string&)> dial_failed;
    /// The header chain.
    std::function<bool(const uint256&)>      has_header;
    std::function<std::vector<uint256>()>    locator;
    std::function<uint32_t()>                height;
    /// Height of a header the chain holds (optional; nullopt = unknown).
    std::function<std::optional<uint32_t>(const uint256&)> header_height;
    /// The header tip's block hash (optional; unset = any block at the tip
    /// height counts as the tip).
    std::function<uint256()>                 tip;
    /// Header sync caught up (the last batch was < 2000 headers).
    std::function<bool()>                    caught_up;
    /// pool_empty_headers_caught_up held for a headers message (optional).
    std::function<void()>                    on_empty_headers;
    /// A block body matches its header (optional; unset = every body does).
    std::function<bool(const BlockType&)>    body_valid;
    /// A body that failed body_valid, from a peer that had not sent a bad
    /// one for this block, with the number of peers that have (optional).
    std::function<void(const BlockType&, size_t bad_peers)> on_bad_body;
    /// The best height of the full_block consumer (the UTXO set); nullopt
    /// while it holds no block (optional; unset = bodies go on as they come).
    std::function<std::optional<uint32_t>()> body_best_height;
    /// Into the coin node's existing paths.
    std::function<void(const std::vector<BlockHeaderType>&)> on_headers;
    std::function<void(const uint256&)>                      on_block_announced;  // optional
    std::function<void(const Transaction&)>                  on_tx;               // optional
    /// A valid block body, once, on arrival (mempool cleanup, work refresh).
    std::function<void(const BlockType&)>                    on_full_block;       // optional
    /// The same body in chain order (the UTXO connect; optional). For a body
    /// that is not held it runs before on_full_block.
    std::function<void(const BlockType&)>                    on_body_in_order;
    /// After the UTXO connect of a body whose on_full_block already ran (a
    /// held body): the UTXO-based mempool maintenance and the work refresh,
    /// once per run of such connects, with the last block connected
    /// (optional).
    std::function<void(const BlockType&)>                    after_late_connect;
    /// The clock (optional; tests drive it).
    std::function<Clock::time_point()> now;
};

template <typename Coin>
class BasicCoinPeerPool {
public:
    using BlockHeaderType  = typename Coin::Header;
    using BlockType        = typename Coin::Block;
    using Transaction      = typename Coin::Tx;
    using PoolPeerHooks    = BasicPoolPeerHooks<Coin>;
    using CoinPeerPoolHost = BasicCoinPeerPoolHost<Coin>;
    using Clock            = std::chrono::steady_clock;   // CoinPeerPoolHost::Clock

    explicit BasicCoinPeerPool(CoinPeerPoolHost host, size_t target = kCoinPoolTargetPeers,
                               std::string tag = "[BTC]")
        : m_host(std::move(host)), m_target(target), m_tag(std::move(tag))
    {
        m_last_progress = now();
        m_last_getheaders = m_last_progress;
        if (m_host.height)
            m_last_height = m_host.height();
    }

    BasicCoinPeerPool(const BasicCoinPeerPool&) = delete;
    BasicCoinPeerPool& operator=(const BasicCoinPeerPool&) = delete;

    size_t target() const { return m_target; }
    size_t slot_count() const { return m_slots.size(); }

    /// One maintenance + header-source tick (IO thread).
    void tick()
    {
        const auto t = now();
        m_last_tick = t;
        std::vector<std::string> fresh;
        observe_slots(t, fresh);
        header_source(t, fresh);
        refill(t);
        bodies(t);
        retry_txs(t);
        prune_seen(t);
        publish_rows();
    }

    /// Every kCoinPoolPollSec (IO thread): block-body retries and the ordering
    /// hold; the full tick() once kCoinPoolTickSec passed since the last one.
    void poll()
    {
        const auto t = now();
        if (m_last_tick == Clock::time_point{} || secs(t - m_last_tick) >= kCoinPoolTickSec) {
            tick();
            return;
        }
        bodies(t);
    }

    /// Relay a won block to every pooled peer with a completed handshake.
    /// Returns the number it was written to. The same bytes (SHA256d of the
    /// whole serialized block) again within kCoinPoolRelayDedupSec of a relay
    /// that reached a peer are not resent; different bytes for the same
    /// header (the stratum block and the share-chain reconstruction) both go
    /// out.
    size_t broadcast_block(const std::vector<unsigned char>& block_bytes)
    {
        const auto t = now();
        for (auto it = m_relayed.begin(); it != m_relayed.end();)
            it = secs(t - it->second.first) >= kCoinPoolRelayDedupSec ? m_relayed.erase(it)
                                                                      : std::next(it);
        const uint256 hash = Hash(std::span<const unsigned char>(block_bytes.data(),
                                                                 block_bytes.size()));
        {
            auto it = m_relayed.find(hash);
            if (it != m_relayed.end() && it->second.second > 0) {
                LOG_INFO << m_tag << " won block bytes " << hash.GetHex().substr(0, 16)
                         << " already relayed to " << it->second.second << " pooled coin peers";
                return it->second.second;
            }
        }
        size_t live = 0, sent = 0;
        for (auto& [key, s] : m_slots) {
            if (!s->peer->handshaked())
                continue;
            ++live;
            try {
                if (s->peer->relay_block(block_bytes))
                    ++sent;
            } catch (const std::exception& e) {
                LOG_WARNING << m_tag << " won block relay to coin peer " << key
                            << " failed: " << e.what();
            }
        }
        m_relayed[hash] = {t, sent};
        if (live == 0)
            LOG_WARNING << m_tag << " won block: no pooled coin peer has a completed handshake ("
                        << block_bytes.size() << " bytes not relayed by the pool)";
        else
            LOG_INFO << m_tag << " won block relayed to " << sent << "/" << live
                     << " pooled coin peers (" << block_bytes.size() << " bytes)";
        return sent;
    }

    /// getheaders from `locator` to every pooled peer with a completed
    /// handshake. Returns the number asked.
    size_t ask_all(const std::vector<uint256>& locator)
    {
        size_t n = 0;
        for (auto& [key, s] : m_slots)
            if (s->peer->handshaked()) {
                s->peer->send_getheaders(locator, uint256::ZERO);
                ++n;
            }
        return n;
    }

    /// Pooled peers with a completed handshake at the last tick (any thread).
    size_t live_count() const { return m_live.load(std::memory_order_relaxed); }

    /// The dashboard rows at the last tick (any thread).
    std::vector<CoinPeerRow> rows() const
    {
        const auto t = now();
        std::lock_guard<std::mutex> lock(m_rows_mu);
        std::vector<CoinPeerRow> out;
        out.reserve(m_rows.size());
        for (const auto& r : m_rows) {
            CoinPeerRow row = r.row;
            row.conntime = std::max<int64_t>(0, secs(t - r.since));
            out.push_back(std::move(row));
        }
        return out;
    }

    /// Block bodies / transactions tracked (tests, diagnostics).
    size_t tracked_bodies() const { return m_bodies.size(); }
    size_t tracked_txs() const { return m_txs.size(); }

    /// The key of every slot, dialing or connected (IO thread).
    std::vector<std::string> slot_keys() const
    {
        std::vector<std::string> out;
        out.reserve(m_slots.size());
        for (const auto& [key, s] : m_slots)
            out.push_back(key);
        return out;
    }

    /// getdata for `txids` from one pooled peer with a completed handshake,
    /// the next one each call (a caller's own fetches, such as the parents a
    /// mempool needs to price a transaction; not tracked, and not retried).
    /// A transaction that arrives goes to on_tx like any other. Returns the
    /// number of peers asked (0 or 1).
    size_t request_txs(const std::vector<uint256>& txids)
    {
        if (txids.empty())
            return 0;
        auto live = live_slots();
        if (live.empty())
            return 0;
        Slot* s = live[m_req_rr++ % live.size()];
        s->peer->request_txs(txids);
        return 1;
    }

    /// getdata for the bodies of `hashes`, blocks whose headers the chain
    /// holds, whatever their height (pool_body_wanted does not apply): a
    /// caller's catch-up, such as a UTXO view behind the header tip. Each is
    /// asked of a connected peer (round robin; not one that sent a body not
    /// matching its header), then tracked, retried, checked and delivered in
    /// chain order like an announced body. One pending or held is left to
    /// its own retries; one already received (and passed on) is asked again
    /// (its full_block pass does not run twice). Returns the number asked.
    size_t fetch_bodies(const std::vector<uint256>& hashes)
    {
        const auto t = now();
        size_t asked = 0;
        for (const auto& hash : hashes) {
            if (!has_header(hash) || m_held.count(hash))
                continue;
            auto it = m_bodies.find(hash);
            if (it != m_bodies.end() && !it->second.received)
                continue;   // pending: its retries run
            if (it == m_bodies.end() && !make_room_for_body(false))
                continue;
            auto live = live_slots();
            Slot* s = nullptr;
            for (size_t i = 0; i < live.size() && !s; ++i) {
                Slot* c = live[(m_body_rr + i) % live.size()];
                if (it == m_bodies.end() || !it->second.bad.count(c->id))
                    s = c;
            }
            ++m_body_rr;
            if (!s)
                continue;
            if (it == m_bodies.end()) {
                track_body(hash, *s, t);
            } else {
                Body& b = it->second;
                b.received = false;
                b.awaiting_room = false;
                b.first = t;
                b.at = t;
                b.sent = t;
                b.asked = s->id;
                b.asked_key = s->key;
                b.asked_hs = s->handshaked_at;
                b.asks = 1;
                b.same_asks = 0;
            }
            s->peer->request_block(hash);
            ++asked;
        }
        return asked;
    }

private:
    struct Slot {
        uint64_t              id{0};
        std::string           key;
        bool                  routable{false};
        std::unique_ptr<PoolPeer> peer;
        Clock::time_point     dialed_at{};
        bool                  ever_handshaked{false};
        bool                  was_handshaked{false};
        Clock::time_point     handshaked_at{};
        Clock::time_point     lost_at{};
        Clock::time_point     last_headers_at{};      // last headers message (epoch = none)
        Clock::time_point     last_tip_headers_at{};  // last one passed on (epoch = none)
        Clock::time_point     ask_sent{};             // last announcement getheaders (epoch = none)
        bool                  ask_unanswered{false};
        std::string           subver;
        uint32_t              start_height{0};
    };

    struct Body {
        Clock::time_point  first{};     // first ask
        Clock::time_point  at{};        // last ask / arrival
        uint64_t           asked{0};    // slot id asked last
        std::string        asked_key;
        int                asks{0};     // asks sent
        bool               received{false};
        bool               passed{false};        // its on_full_block ran
        bool               awaiting_room{false}; // not held (hold full): asked again once it has room
        bool               loud{false};          // several bad bodies logged
        Clock::time_point  sent{};      // last ask sent
        Clock::time_point  asked_hs{};  // the asked peer's handshake when it was asked
        int                same_asks{0};// asks in a row of the same peer
        std::set<uint64_t> bad;         // slots that sent a body not matching the header
    };

    struct Held {
        BlockType          block;
        uint32_t           height{0};
        Clock::time_point  since{};
    };

    struct TxState {
        Clock::time_point     asked_at{};
        uint64_t              asked{0};
        std::vector<uint64_t> announcers;   // not asked yet, in order
        bool                  received{false};
    };

    struct PublishedRow {
        CoinPeerRow       row;
        Clock::time_point since{};
    };

    using SlotMap = std::map<std::string, std::unique_ptr<Slot>>;

    static int64_t secs(Clock::duration d)
    {
        return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(d).count());
    }

    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    bool caught_up() const { return m_host.caught_up ? m_host.caught_up() : false; }

    uint32_t height() const { return m_host.height ? m_host.height() : 0; }

    std::vector<uint256> locator() const
    {
        return m_host.locator ? m_host.locator() : std::vector<uint256>{};
    }

    bool has_header(const uint256& h) const { return m_host.has_header && m_host.has_header(h); }

    std::optional<uint32_t> header_height(const uint256& h) const
    {
        return m_host.header_height ? m_host.header_height(h) : std::nullopt;
    }

    /// The slot `key` dialed as `id` (a dropped connection's late events
    /// find nothing).
    Slot* find(const std::string& key, uint64_t id)
    {
        auto it = m_slots.find(key);
        if (it == m_slots.end() || it->second->id != id)
            return nullptr;
        return it->second.get();
    }

    Slot* find_id(uint64_t id)
    {
        for (auto& [key, s] : m_slots)
            if (s->id == id)
                return s.get();
        return nullptr;
    }

    void report(const std::function<void(const std::string&)>& fn, const std::string& key)
    {
        if (fn)
            fn(key);
    }

    void drop(typename SlotMap::iterator it, const char* why)
    {
        Slot& s = *it->second;
        LOG_INFO << m_tag << " coin peer pool: dropping " << s.key << " (" << why << ")";
        if (s.ever_handshaked)
            report(m_host.disconnected, s.key);
        else
            report(m_host.dial_failed, s.key);
        m_slots.erase(it);
    }

    void observe_slots(Clock::time_point t, std::vector<std::string>& fresh)
    {
        for (auto it = m_slots.begin(); it != m_slots.end();) {
            Slot& s = *it->second;
            const bool hs = s.peer->handshaked();
            if (hs && !s.was_handshaked) {
                s.handshaked_at = t;
                s.subver = s.peer->subver();
                s.start_height = s.peer->start_height();
                if (!s.ever_handshaked) {
                    s.ever_handshaked = true;
                    report(m_host.connected, s.key);
                }
                LOG_INFO << m_tag << " coin peer pool: " << s.key << " handshaked (subver="
                         << s.subver << " height=" << s.start_height << ")";
                fresh.push_back(s.key);
            }
            if (!hs && s.was_handshaked)
                s.lost_at = t;
            s.was_handshaked = hs;
            const auto v = pool_slot_verdict(hs, s.ever_handshaked, secs(t - s.dialed_at),
                                             secs(t - s.lost_at));
            if (v != PoolSlotVerdict::Keep) {
                auto next = std::next(it);
                drop(it, v == PoolSlotVerdict::DialFailed ? "no handshake" : "link down");
                it = next;
                continue;
            }
            ++it;
        }
    }

    std::vector<Slot*> live_slots()
    {
        std::vector<Slot*> out;
        for (auto& [key, s] : m_slots)
            if (s->peer->handshaked())
                out.push_back(s.get());
        return out;
    }

    void ask(Slot& s, const std::vector<uint256>& loc)
    {
        s.peer->send_getheaders(loc, uint256::ZERO);
    }

    /// The failover victim: the live peer, handshaked at least
    /// kCoinPoolFailoverMinAgeSec ago, whose last tip-moving headers message
    /// (or its handshake, if later) is oldest. nullptr = none.
    Slot* failover_victim(Clock::time_point t, const std::vector<Slot*>& live)
    {
        Slot* victim = nullptr;
        Clock::time_point victim_rank{};
        for (auto* s : live) {
            if (secs(t - s->handshaked_at) < kCoinPoolFailoverMinAgeSec)
                continue;
            const auto rank = std::max(s->last_tip_headers_at, s->handshaked_at);
            if (!victim || rank < victim_rank) {
                victim = s;
                victim_rank = rank;
            }
        }
        return victim;
    }

    /// header_source_step over the whole pool: progress is the chain tip,
    /// from any peer.
    void header_source(Clock::time_point t, const std::vector<std::string>& fresh)
    {
        const uint32_t h = height();
        const bool cu = caught_up();
        const bool advanced = h > m_last_height;
        if (advanced) {
            m_last_height = h;
            m_last_progress = t;
        }
        auto live = live_slots();
        const int64_t quiet = secs(t - m_last_progress);
        const int64_t since_gh = secs(t - m_last_getheaders);
        const auto step = header_source_step(cu, !live.empty(), !fresh.empty(), advanced,
                                             quiet, since_gh);
        if (step.getheaders) {
            const auto loc = locator();
            const std::set<std::string> fresh_set(fresh.begin(), fresh.end());
            size_t asked = 0;
            for (const auto& k : fresh) {
                auto it = m_slots.find(k);
                if (it != m_slots.end()) {
                    ask(*it->second, loc);
                    ++asked;
                }
            }
            // Not caught up: the tip did not move this tick. Caught up: the
            // refresh window passed with no header.
            const bool due = cu ? (quiet >= kCaughtUpRefreshSec && since_gh >= kCaughtUpRefreshSec)
                                : !advanced;
            std::vector<Slot*> others;
            for (auto* s : live)
                if (!fresh_set.count(s->key))
                    others.push_back(s);
            if (due && !others.empty()) {
                if (cu) {
                    for (auto* s : others)
                        ask(*s, loc);
                    asked += others.size();
                } else {
                    ask(*others[m_rr++ % others.size()], loc);
                    ++asked;
                }
            }
            m_last_getheaders = t;
            LOG_INFO << m_tag << " coin peer pool getheaders to " << asked << " peer(s), locator="
                     << (loc.empty() ? std::string("-") : loc.front().GetHex().substr(0, 16))
                     << " (" << loc.size() << " hashes) chain_height=" << h
                     << " caught_up=" << cu << " live=" << live.size();
        }
        if (step.failover) {
            LOG_INFO << m_tag << " coin peer pool: no header progress for " << quiet
                     << "s (chain_height=" << h << ", caught_up=" << cu << ", live="
                     << live.size() << ")";
            m_last_progress = t;   // grace window
            if (Slot* victim = failover_victim(t, live)) {
                const std::string key = victim->key;
                drop(m_slots.find(key), "header source failover");
            }
            live = live_slots();
            if (live.empty())
                return;
            const auto loc = locator();
            if (cu) {
                for (auto* s : live)
                    ask(*s, loc);
            } else {
                ask(*live[m_rr++ % live.size()], loc);
            }
            m_last_getheaders = t;
        }
    }

    void refill(Clock::time_point t)
    {
        size_t need = pool_dials_needed(m_slots.size(), m_target);
        if (need == 0 || !m_host.candidates || !m_host.dial)
            return;
        std::set<std::string> exclude;
        for (const auto& [key, s] : m_slots)
            exclude.insert(key);
        for (const auto& ep : m_host.candidates(exclude)) {
            if (need == 0)
                break;
            const std::string key = ep.to_string();
            if (m_slots.count(key))
                continue;
            dial(ep, key, t);
            --need;
        }
    }

    void dial(const PeerEndpoint& ep, const std::string& key, Clock::time_point t)
    {
        auto slot = std::make_unique<Slot>();
        slot->id = ++m_next_id;
        slot->key = key;
        slot->routable = ep.is_routable();
        slot->dialed_at = t;
        slot->peer = m_host.dial(ep.to_net_service(), hooks(key, slot->id));
        if (!slot->peer) {
            report(m_host.dial_failed, key);
            return;
        }
        LOG_INFO << m_tag << " coin peer pool: dialing " << key << " (" << (m_slots.size() + 1)
                 << "/" << m_target << " slots)";
        m_slots.emplace(key, std::move(slot));
    }

    PoolPeerHooks hooks(const std::string& key, uint64_t id)
    {
        PoolPeerHooks hk;
        hk.headers_message = [this, key, id](size_t count) {
            on_headers_message(key, id, count);
        };
        hk.headers = [this, key, id](const std::vector<BlockHeaderType>& hdrs) {
            on_headers(key, id, hdrs);
        };
        hk.block_announced = [this, key, id](const uint256& hash) {
            on_block_announced(key, id, hash);
        };
        hk.tx = [this, key, id](const Transaction& tx) {
            on_tx(key, id, tx);
        };
        hk.full_block = [this, key, id](const BlockType& block) {
            on_full_block(key, id, block);
        };
        hk.fetch = [this, key, id](const uint256& hash, bool is_block) {
            return wants_fetch(key, id, hash, is_block);
        };
        return hk;
    }

    /// Any headers message from a pooled peer: it answered.
    void on_headers_message(const std::string& key, uint64_t id, size_t count)
    {
        Slot* s = find(key, id);
        if (!s)
            return;
        s->last_headers_at = now();
        s->ask_unanswered = false;
        if (m_host.on_empty_headers
            && pool_empty_headers_caught_up(count, s->peer->start_height(), height()))
            m_host.on_empty_headers();
    }

    void on_headers(const std::string& key, uint64_t id, const std::vector<BlockHeaderType>& hdrs)
    {
        Slot* s = find(key, id);
        if (!s || hdrs.empty())
            return;
        const uint256 last = Coin::header_hash(hdrs.back());
        const uint256& prev = hdrs.front().m_previous_block;
        const bool connects = prev.IsNull() || has_header(prev);
        const bool last_known = connects && has_header(last);
        const auto verdict = pool_headers_verdict(hdrs.size(), connects, last_known);
        switch (verdict) {
        case PoolHeadersVerdict::Ignore:
            return;
        case PoolHeadersVerdict::AskSender:
            announce(*s, last);
            return;
        case PoolHeadersVerdict::Forward:
        case PoolHeadersVerdict::ForwardAndContinue:
            break;
        }
        const uint32_t before = height();
        if (m_host.on_headers)
            m_host.on_headers(hdrs);
        Slot* again = find(key, id);
        if (!again)
            return;
        // Only a batch that moved the header tip counts for the failover rank.
        if (height() > before)
            again->last_tip_headers_at = now();
        // A full batch: the next one from the peer that sent it.
        if (verdict == PoolHeadersVerdict::ForwardAndContinue)
            again->peer->send_getheaders({last}, uint256::ZERO);
    }

    void on_block_announced(const std::string& key, uint64_t id, const uint256& hash)
    {
        Slot* s = find(key, id);
        if (!s)
            return;
        if (m_host.on_block_announced)
            m_host.on_block_announced(hash);
        if (hash.IsNull() || has_header(hash))
            return;
        announce(*s, hash);
    }

    /// getheaders from the chain's locator to the announcer of a block the
    /// chain cannot place (pool_announce_asks).
    void announce(Slot& s, const uint256& block)
    {
        const auto t = now();
        const int64_t since = s.ask_sent == Clock::time_point{}
            ? std::numeric_limits<int64_t>::max() : secs(t - s.ask_sent);
        const bool cu = caught_up();
        if (!pool_announce_asks(s.ask_unanswered, since, cu, block == m_last_announced))
            return;
        if (!cu)
            m_last_announced = block;
        s.ask_sent = t;
        s.ask_unanswered = true;
        const auto loc = locator();
        ask(s, loc);
        LOG_INFO << m_tag << " coin peer " << s.key << " announced unknown block "
                 << block.GetHex().substr(0, 16) << ": getheaders (" << loc.size()
                 << " locator hashes)";
    }

    std::optional<uint32_t> body_best() const
    {
        return m_host.body_best_height ? m_host.body_best_height() : std::nullopt;
    }

    /// The block is the header tip's block now (its hash; without the tip
    /// hook, any block at the tip height).
    bool is_tip(const uint256& hash) const
    {
        if (m_host.tip)
            return hash == m_host.tip();
        const auto hh = header_height(hash);
        return hh && *hh >= height();
    }

    bool wants_fetch(const std::string& key, uint64_t id, const uint256& hash, bool is_block)
    {
        Slot* s = find(key, id);
        if (!s)
            return false;
        const auto t = now();
        if (is_block) {
            // Only a block whose header the chain holds, near the tip
            // (pool_body_wanted): an inv of an unknown block asks for headers
            // instead, and the headers announcement fetches the body once its
            // header connects.
            const auto hh = header_height(hash);
            if (!hh || !has_header(hash) || m_bodies.count(hash)
                || !pool_body_wanted(*hh, height(), body_best())
                || !make_room_for_body(is_tip(hash)))
                return false;
            track_body(hash, *s, t);
            return true;
        }
        auto it = m_txs.find(hash);
        if (it != m_txs.end()) {
            TxState& tx = it->second;
            if (!tx.received && tx.asked != s->id
                && tx.announcers.size() < kCoinPoolTxAnnouncersMax
                && std::find(tx.announcers.begin(), tx.announcers.end(), s->id) == tx.announcers.end())
                tx.announcers.push_back(s->id);
            return false;
        }
        while (m_txs.size() >= kCoinPoolSeenTxMax && !m_tx_order.empty()) {
            m_txs.erase(m_tx_order.front().second);   // the oldest first
            m_tx_order.pop_front();
        }
        TxState tx;
        tx.asked_at = t;
        tx.asked = s->id;
        m_txs.emplace(hash, std::move(tx));
        m_tx_order.emplace_back(t, hash);
        return true;
    }

    /// Track a body asked of `s` (the first ask).
    void track_body(const uint256& hash, Slot& s, Clock::time_point t)
    {
        Body b;
        b.first = t;
        b.at = t;
        b.sent = t;
        b.asked = s.id;
        b.asked_key = s.key;
        b.asked_hs = s.handshaked_at;
        b.asks = 1;
        m_bodies.emplace(hash, std::move(b));
    }

    /// Room for one more tracked body: at the bound, drop the oldest received
    /// one; for the tip's block, else the oldest pending one that is not the
    /// tip's. False when there is none to drop.
    bool make_room_for_body(bool for_tip)
    {
        if (m_bodies.size() < kCoinPoolBodiesMax)
            return true;
        auto oldest = m_bodies.end();
        for (auto it = m_bodies.begin(); it != m_bodies.end(); ++it)
            if (it->second.received && (oldest == m_bodies.end() || it->second.at < oldest->second.at))
                oldest = it;
        if (oldest == m_bodies.end() && for_tip) {
            for (auto it = m_bodies.begin(); it != m_bodies.end(); ++it)
                if (!is_tip(it->first)
                    && (oldest == m_bodies.end() || it->second.first < oldest->second.first))
                    oldest = it;
        }
        if (oldest == m_bodies.end())
            return false;
        m_bodies.erase(oldest);
        return true;
    }

    void on_tx(const std::string& key, uint64_t id, const Transaction& tx)
    {
        if (!find(key, id))
            return;
        auto it = m_txs.find(Coin::txid(tx));
        if (it == m_txs.end() && tx.HasWitness())
            it = m_txs.find(Coin::wtxid(tx));
        if (it != m_txs.end()) {
            if (it->second.received)
                return;   // already passed on
            it->second.received = true;
            it->second.announcers.clear();
        }
        if (m_host.on_tx)
            m_host.on_tx(tx);
    }

    /// A transaction not received kCoinPoolTxRetrySec after it was asked for
    /// is asked of its next announcer still in the pool.
    void retry_txs(Clock::time_point t)
    {
        for (auto& [hash, tx] : m_txs) {
            if (tx.received || tx.announcers.empty() || secs(t - tx.asked_at) < kCoinPoolTxRetrySec)
                continue;
            while (!tx.announcers.empty()) {
                const uint64_t next = tx.announcers.front();
                tx.announcers.erase(tx.announcers.begin());
                Slot* s = find_id(next);
                if (!s || !s->peer->handshaked())
                    continue;
                s->peer->request_tx(hash);
                tx.asked = next;
                tx.asked_at = t;
                break;
            }
        }
    }

    void prune_seen(Clock::time_point t)
    {
        while (!m_tx_order.empty() && secs(t - m_tx_order.front().first) >= kCoinPoolSeenTtlSec) {
            m_txs.erase(m_tx_order.front().second);
            m_tx_order.pop_front();
        }
    }

    void on_full_block(const std::string& key, uint64_t id, const BlockType& block)
    {
        Slot* s = find(key, id);
        if (!s)
            return;
        const auto t = now();
        const uint256 hash = Coin::header_hash(block);
        auto it = m_bodies.find(hash);
        if (it == m_bodies.end() || it->second.received)
            return;   // not asked for, or already passed on
        Body& b = it->second;
        if (!has_header(hash))
            return;
        if (m_host.body_valid && !m_host.body_valid(block)) {
            const bool first_bad = b.bad.insert(s->id).second;
            if (first_bad)   // once per peer and block
                LOG_WARNING << m_tag << " coin peer " << key << " sent block "
                            << hash.GetHex().substr(0, 16)
                            << " whose body does not match its header: dropped";
            if (first_bad && m_host.on_bad_body)
                m_host.on_bad_body(block, b.bad.size());
            if (b.bad.size() >= 2 && !b.loud
                && (m_last_bad_log == Clock::time_point{}
                    || secs(t - m_last_bad_log) >= kCoinPoolBadBodyLogSec)) {
                b.loud = true;
                m_last_bad_log = t;
                LOG_ERROR << m_tag << " block " << hash.GetHex().substr(0, 16) << ": bodies from "
                          << b.bad.size() << " coin peers do not match its header -- if the"
                             " block is valid, the body check is rejecting it";
            }
            // Asked again only for the peer it was asked of, the first time
            // that peer sends a bad one (junk from others asks nobody).
            if (s->id == b.asked && first_bad)
                ask_body_again(hash, b, t, /*counts=*/false);   // not an ask used up
            return;
        }
        b.received = true;
        b.awaiting_room = false;
        b.at = t;
        deliver(hash, b, block, t);
    }

    /// Ask a block body of a live peer other than the one asked last and any
    /// that sent a body not matching the header (round robin); the one asked
    /// last when it is the only such peer, if it handshaked again since it was
    /// asked or after pool_same_peer_backoff_sec. `counts`: the ask counts
    /// toward kCoinPoolBodyMaxAsks (a retry; not the re-ask after a body that
    /// did not match). Nobody to ask: only the clock restarts.
    void ask_body_again(const uint256& hash, Body& b, Clock::time_point t, bool counts)
    {
        auto live = live_slots();
        Slot* other = nullptr;
        Slot* same = nullptr;
        for (size_t i = 0; i < live.size() && !other; ++i) {
            Slot* c = live[(m_body_rr + i) % live.size()];
            if (b.bad.count(c->id))
                continue;
            if (c->id == b.asked)
                same = c;
            else
                other = c;
        }
        bool again_same = false;
        bool reconnected = false;
        if (!other && same) {
            reconnected = same->handshaked_at != b.asked_hs;
            if (reconnected || secs(t - b.sent) >= pool_same_peer_backoff_sec(b.same_asks)) {
                other = same;
                again_same = true;
            }
        }
        ++m_body_rr;
        b.at = t;
        if (!other)
            return;
        other->peer->request_block(hash);
        if (counts)
            ++b.asks;
        LOG_INFO << m_tag << " coin peer pool: block " << hash.GetHex().substr(0, 16)
                 << " body not received from " << b.asked_key << ", asking " << other->key;
        b.asked = other->id;
        b.asked_key = other->key;
        b.asked_hs = other->handshaked_at;
        b.sent = t;
        b.same_asks = (again_same && !reconnected) ? b.same_asks + 1 : 0;
    }

    void connect_in_order(const BlockType& block)
    {
        if (m_host.on_body_in_order)
            m_host.on_body_in_order(block);
    }

    void pass_on(const BlockType& block)
    {
        if (m_host.on_full_block)
            m_host.on_full_block(block);
    }

    /// A valid body: the UTXO connect in chain order (pool_body_order), the
    /// full_block path once, now (after the connect when the body is not
    /// held).
    void deliver(const uint256& hash, Body& b, const BlockType& block, Clock::time_point t)
    {
        const auto hh = header_height(hash);
        const std::optional<uint32_t> best = body_best();
        const auto order = hh ? pool_body_order(best, *hh) : PoolBodyOrder::Deliver;
        if (order == PoolBodyOrder::Hold) {
            // Mempool cleanup and the work refresh do not wait for the parent.
            if (!b.passed) {
                pass_on(block);
                b.passed = true;
            }
            if (m_held.size() >= kCoinPoolMaxBodyGap) {
                // No room to hold it: not connected out of order either; asked
                // for again (for the connect only) once the hold has room.
                b.received = false;
                b.awaiting_room = true;
                b.at = t;
                LOG_INFO << m_tag << " coin peer pool: block " << hash.GetHex().substr(0, 16)
                         << " (height " << *hh << ") not held (" << m_held.size()
                         << " bodies already wait): asked for again when there is room";
                return;
            }
            Held held;
            held.block = block;
            held.height = *hh;
            held.since = t;
            m_held.emplace(hash, std::move(held));
            LOG_INFO << m_tag << " coin peer pool: block " << hash.GetHex().substr(0, 16)
                     << " (height " << *hh << ") waits for its parent (body best "
                     << (best ? std::to_string(*best) : std::string("-")) << ")";
            request_parent(block.m_previous_block, t);
            return;
        }
        if (order == PoolBodyOrder::DeliverWithGap)
            LOG_INFO << m_tag << " coin peer pool: block " << hash.GetHex().substr(0, 16)
                     << " (height " << (hh ? *hh : 0) << ") passed on above a gap (body best "
                     << (best ? std::to_string(*best) : std::string("-")) << ")";
        connect_in_order(block);
        const bool late = b.passed;
        if (!b.passed) {
            pass_on(block);
            b.passed = true;
        }
        // One maintenance pass for this connect and the held ones it releases.
        auto released = release_held();
        if (released)
            late_connect(*released);
        else if (late)
            late_connect(block);
    }

    void late_connect(const BlockType& block)
    {
        if (m_host.after_late_connect)
            m_host.after_late_connect(block);
    }

    /// Ask for the body of a held block's parent (a block the chain holds,
    /// not yet tracked).
    void request_parent(const uint256& parent, Clock::time_point t)
    {
        if (!has_header(parent) || m_bodies.count(parent) || !make_room_for_body(false))
            return;
        auto live = live_slots();
        if (live.empty())
            return;
        Slot* s = live[m_body_rr++ % live.size()];
        track_body(parent, *s, t);
        s->peer->request_block(parent);
    }

    /// Connect the held bodies whose parent is now connected, lowest first
    /// (their full_block pass already ran on arrival). Returns the last one
    /// connected, if any (the caller runs after_late_connect once).
    std::optional<BlockType> release_held()
    {
        std::optional<BlockType> last;
        for (;;) {
            const std::optional<uint32_t> best = body_best();
            auto pick = m_held.end();
            for (auto it = m_held.begin(); it != m_held.end(); ++it)
                if (pool_body_order(best, it->second.height) == PoolBodyOrder::Deliver
                    && (pick == m_held.end() || it->second.height < pick->second.height))
                    pick = it;
            if (pick == m_held.end())
                return last;
            BlockType block = std::move(pick->second.block);
            m_held.erase(pick);
            connect_in_order(block);
            last = std::move(block);
        }
    }

    /// Body retries (pool_body_retry), the ordering hold's time limit, the
    /// received-body TTL.
    void bodies(Clock::time_point t)
    {
        for (auto it = m_bodies.begin(); it != m_bodies.end();) {
            Body& b = it->second;
            if (b.received) {
                if (secs(t - b.at) >= kCoinPoolSeenTtlSec)
                    it = m_bodies.erase(it);
                else
                    ++it;
                continue;
            }
            if (b.awaiting_room) {
                // A valid body that found the hold full: asked again (for its
                // connect; not an ask used up) once the hold has room.
                if (m_held.size() < kCoinPoolMaxBodyGap) {
                    b.awaiting_room = false;
                    ask_body_again(it->first, b, t, /*counts=*/false);
                }
                ++it;
                continue;
            }
            switch (pool_body_retry(is_tip(it->first), b.asks, secs(t - b.at), secs(t - b.first))) {
            case PoolBodyRetry::Wait:
                ++it;
                break;
            case PoolBodyRetry::GiveUp:
                LOG_WARNING << m_tag << " coin peer pool: block " << it->first.GetHex().substr(0, 16)
                            << " body not received after " << b.asks << " asks";
                it = m_bodies.erase(it);
                break;
            case PoolBodyRetry::Ask:
                ask_body_again(it->first, b, t, /*counts=*/true);
                ++it;
                break;
            }
        }
        bool expired = false;
        for (const auto& [hash, held] : m_held)
            if (secs(t - held.since) >= kCoinPoolBodyHoldSec)
                expired = true;
        if (!expired)
            return;
        // A parent that did not come: connect the held bodies, lowest first.
        std::vector<std::pair<uint32_t, uint256>> order;
        for (const auto& [hash, held] : m_held)
            order.emplace_back(held.height, hash);
        std::sort(order.begin(), order.end());
        LOG_WARNING << m_tag << " coin peer pool: " << order.size()
                    << " block bodies connected without their parent";
        std::optional<BlockType> last;
        for (const auto& entry : order) {
            auto it = m_held.find(entry.second);
            BlockType block = std::move(it->second.block);
            m_held.erase(it);
            connect_in_order(block);
            last = std::move(block);
        }
        if (last)
            late_connect(*last);   // one maintenance pass for them all
    }

    void publish_rows()
    {
        std::vector<PublishedRow> rows;
        for (const auto& [key, s] : m_slots) {
            if (!s->peer->handshaked())
                continue;
            PublishedRow r;
            r.row.addr = s->key;
            r.row.routable = s->routable;
            r.row.subver = s->subver;
            r.row.start_height = s->start_height;
            r.since = s->handshaked_at;
            rows.push_back(std::move(r));
        }
        m_live.store(rows.size(), std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(m_rows_mu);
        m_rows = std::move(rows);
    }

    CoinPeerPoolHost m_host;
    size_t           m_target;
    std::string      m_tag;

    // IO thread only.
    SlotMap            m_slots;   // key -> slot
    uint64_t           m_next_id{0};
    size_t             m_rr{0};
    size_t             m_body_rr{0};
    size_t             m_req_rr{0};
    uint32_t           m_last_height{0};
    Clock::time_point  m_last_tick{};
    Clock::time_point  m_last_bad_log{};
    Clock::time_point  m_last_progress{};
    Clock::time_point  m_last_getheaders{};
    uint256            m_last_announced;
    std::map<uint256, Body>    m_bodies;
    std::map<uint256, Held>    m_held;
    std::map<uint256, TxState> m_txs;
    std::deque<std::pair<Clock::time_point, uint256>> m_tx_order;   // oldest first
    std::map<uint256, std::pair<Clock::time_point, size_t>> m_relayed;

    // Any thread.
    std::atomic<size_t>        m_live{0};
    mutable std::mutex         m_rows_mu;
    std::vector<PublishedRow>  m_rows;
};

} // namespace btc::coin
