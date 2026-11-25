// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// c2pool-btc without --bitcoind: a pool of outbound coin-network peers
// (kCoinPoolTargetPeers) drawn from BtcCoinPeerManager. It replaces the single
// standalone header-source connection. main_btc.cpp wires it to the header
// chain, the coin node's events and the peer manager; the KATs drive it with
// fakes (coin_peer_pool_test.cpp).
//
//   - slots: up to the target; a slot that does not complete its handshake
//     within kCoinPoolDialTimeoutSec is dropped as a failed dial, one whose
//     link stays down for kCoinPoolLostGraceSec after a handshake is dropped
//     as a disconnect (both reported to the peer manager); every tick refills
//     from the manager's candidates;
//   - headers: from any pooled peer. A batch that connects and carries a new
//     last header goes to the header chain path; a full batch (2000) asks its
//     sender for the next one. A small batch that does not connect, or an
//     inv of a block the chain does not have, asks that peer for headers from
//     the chain's locator: not while a getheaders to it from an announcement
//     is unanswered (kCoinPoolAskResponseSec), at most every
//     kCoinPoolAskEverySec per peer, and while catching up only the first
//     announcer of a block;
//   - the header-source tick (header_source_step over the whole pool): a
//     fresh handshake asks that peer; catching up, a tick without progress
//     asks one peer (round robin); caught up, the refresh asks every peer; a
//     failover drops the pooled peer whose last headers message is oldest;
//   - bodies and transactions: an announced block body or transaction is
//     fetched from its first announcer only; a block body that has not
//     arrived after kCoinPoolBodyRetrySec is asked of another peer (at most
//     kCoinPoolBodyMaxAsks asks); a block body reaches the coin node once;
//   - a won block goes to every pooled peer with a completed handshake;
//   - the dashboard rows: one per pooled peer with a completed handshake.
//
// IO-thread only, except rows() and live_count() (any thread).

#include "block.hpp"
#include "header_source_step.hpp"
#include "transaction.hpp"

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
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace btc::coin {

inline constexpr size_t  kCoinPoolTargetPeers      = 8;
inline constexpr int64_t kCoinPoolDialTimeoutSec   = 30;
inline constexpr int64_t kCoinPoolLostGraceSec     = 90;
inline constexpr size_t  kCoinPoolFullHeadersBatch = 2000;
inline constexpr size_t  kCoinPoolAnnouncementMax  = 3;
inline constexpr int64_t kCoinPoolAskResponseSec   = 120;
inline constexpr int64_t kCoinPoolAskEverySec      = 2;
inline constexpr int64_t kCoinPoolBodyRetrySec     = 20;
inline constexpr int     kCoinPoolBodyMaxAsks      = 3;
inline constexpr int64_t kCoinPoolSeenTtlSec       = 600;
inline constexpr size_t  kCoinPoolSeenTxMax        = 50000;

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
struct PoolPeerHooks {
    /// Every headers message, with its entry count (empty ones included).
    std::function<void(size_t count)>                        headers_message;
    std::function<void(const std::vector<BlockHeaderType>&)> headers;
    std::function<void(const uint256&)>                      block_announced;
    std::function<void(const Transaction&)>                  tx;
    std::function<void(const BlockType&)>                    full_block;
    /// Consulted before the getdata for an announced block / transaction.
    std::function<bool(const uint256&, bool is_block)>       fetch;
};

/// One outbound coin-network connection (NodeP2PPoolPeer in production).
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
    /// getdata for a block body.
    virtual void        request_block(const uint256& hash) = 0;
};

/// What the pool needs from its surroundings.
struct CoinPeerPoolHost {
    using Clock = std::chrono::steady_clock;

    /// Dial `addr`; the connection reports through `hooks`. nullptr = failed.
    std::function<std::unique_ptr<PoolPeer>(const NetService& addr, PoolPeerHooks hooks)> dial;
    /// Candidate peers not in `exclude` (BtcCoinPeerManager::get_peers_to_connect).
    std::function<std::vector<PeerEndpoint>(const std::set<std::string>& exclude)> candidates;
    /// Peer manager reports (optional).
    std::function<void(const std::string&)> connected;
    std::function<void(const std::string&)> disconnected;
    std::function<void(const std::string&)> dial_failed;
    /// The header chain.
    std::function<bool(const uint256&)>      has_header;
    std::function<std::vector<uint256>()>    locator;
    std::function<uint32_t()>                height;
    /// Header sync caught up (the last batch was < 2000 headers).
    std::function<bool()>                    caught_up;
    /// A pooled peer whose version height is at least the chain's answered
    /// getheaders with no headers: it has nothing after the chain's tip
    /// (a batch of 0 < 2000; optional).
    std::function<void()>                    on_empty_headers;
    /// Into the coin node's existing paths.
    std::function<void(const std::vector<BlockHeaderType>&)> on_headers;
    std::function<void(const uint256&)>                      on_block_announced;  // optional
    std::function<void(const Transaction&)>                  on_tx;               // optional
    std::function<void(const BlockType&)>                    on_full_block;       // optional
    /// The clock (optional; tests drive it).
    std::function<Clock::time_point()> now;
};

inline uint256 pool_header_hash(const BlockHeaderType& header)
{
    auto packed = pack(header);
    return Hash(packed.get_span());
}

class CoinPeerPool {
public:
    using Clock = CoinPeerPoolHost::Clock;

    explicit CoinPeerPool(CoinPeerPoolHost host, size_t target = kCoinPoolTargetPeers,
                          std::string tag = "[BTC]")
        : m_host(std::move(host)), m_target(target), m_tag(std::move(tag))
    {
        m_last_progress = now();
        m_last_getheaders = m_last_progress;
        if (m_host.height)
            m_last_height = m_host.height();
    }

    CoinPeerPool(const CoinPeerPool&) = delete;
    CoinPeerPool& operator=(const CoinPeerPool&) = delete;

    size_t target() const { return m_target; }
    size_t slot_count() const { return m_slots.size(); }

    /// One maintenance + header-source tick (IO thread).
    void tick()
    {
        const auto t = now();
        std::vector<std::string> fresh;
        observe_slots(t, fresh);
        header_source(t, fresh);
        refill(t);
        retry_bodies(t);
        prune_seen(t);
        publish_rows();
    }

    /// Relay a won block to every pooled peer with a completed handshake.
    /// Returns the number it was written to.
    size_t broadcast_block(const std::vector<unsigned char>& block_bytes)
    {
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
        Clock::time_point     last_headers_at{};  // last headers message (epoch = none)
        Clock::time_point     ask_sent{};         // last announcement getheaders (epoch = none)
        bool                  ask_unanswered{false};
        std::string           subver;
        uint32_t              start_height{0};
    };

    struct Body {
        Clock::time_point at{};       // asked / arrived
        std::string       peer;       // asked of
        int               asks{0};
        bool              received{false};
    };

    struct PublishedRow {
        CoinPeerRow       row;
        Clock::time_point since{};
    };

    static int64_t secs(Clock::duration d)
    {
        return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(d).count());
    }

    Clock::time_point now() const { return m_host.now ? m_host.now() : Clock::now(); }

    bool caught_up() const { return m_host.caught_up ? m_host.caught_up() : false; }

    std::vector<uint256> locator() const
    {
        return m_host.locator ? m_host.locator() : std::vector<uint256>{};
    }

    bool has_header(const uint256& h) const { return m_host.has_header && m_host.has_header(h); }

    /// The slot `key` dialed as `id` (a dropped connection's late events
    /// find nothing).
    Slot* find(const std::string& key, uint64_t id)
    {
        auto it = m_slots.find(key);
        if (it == m_slots.end() || it->second->id != id)
            return nullptr;
        return it->second.get();
    }

    void report(const std::function<void(const std::string&)>& fn, const std::string& key)
    {
        if (fn)
            fn(key);
    }

    void drop(std::map<std::string, std::unique_ptr<Slot>>::iterator it, const char* why)
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
            if (v == PoolSlotVerdict::DialFailed) {
                auto next = std::next(it);
                drop(it, "no handshake");
                it = next;
                continue;
            }
            if (v == PoolSlotVerdict::Disconnected) {
                auto next = std::next(it);
                drop(it, "link down");
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

    /// header_source_step over the whole pool: progress is the chain tip,
    /// from any peer.
    void header_source(Clock::time_point t, const std::vector<std::string>& fresh)
    {
        const uint32_t h = m_host.height ? m_host.height() : 0;
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
            if (live.empty())
                return;
            Slot* stalest = live.front();
            for (auto* s : live)
                if (s->last_headers_at < stalest->last_headers_at)
                    stalest = s;
            const std::string key = stalest->key;
            drop(m_slots.find(key), "header source failover");
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
            if (find(key, id) && m_host.on_tx)
                m_host.on_tx(tx);
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
        if (count == 0 && m_host.on_empty_headers
            && s->peer->start_height() >= (m_host.height ? m_host.height() : 0))
            m_host.on_empty_headers();
    }

    void on_headers(const std::string& key, uint64_t id, const std::vector<BlockHeaderType>& hdrs)
    {
        Slot* s = find(key, id);
        if (!s || hdrs.empty())
            return;
        const uint256 last = pool_header_hash(hdrs.back());
        const uint256& prev = hdrs.front().m_previous_block;
        const bool connects = prev.IsNull() || has_header(prev);
        const bool last_known = connects && has_header(last);
        switch (pool_headers_verdict(hdrs.size(), connects, last_known)) {
        case PoolHeadersVerdict::Ignore:
            return;
        case PoolHeadersVerdict::AskSender:
            announce(*s, last);
            return;
        case PoolHeadersVerdict::Forward:
            if (m_host.on_headers)
                m_host.on_headers(hdrs);
            return;
        case PoolHeadersVerdict::ForwardAndContinue:
            if (m_host.on_headers)
                m_host.on_headers(hdrs);
            // The next batch from the peer that sent this one.
            if (Slot* again = find(key, id))
                again->peer->send_getheaders({last}, uint256::ZERO);
            return;
        }
    }

    void on_block_announced(const std::string& key, uint64_t id, const uint256& hash)
    {
        if (m_host.on_block_announced)
            m_host.on_block_announced(hash);
        Slot* s = find(key, id);
        if (!s || hash.IsNull() || has_header(hash))
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

    bool wants_fetch(const std::string& key, uint64_t id, const uint256& hash, bool is_block)
    {
        if (!find(key, id))
            return false;
        const auto t = now();
        if (is_block) {
            if (m_bodies.count(hash))
                return false;
            Body b;
            b.at = t;
            b.peer = key;
            b.asks = 1;
            m_bodies.emplace(hash, std::move(b));
            return true;
        }
        if (m_seen_tx.size() >= kCoinPoolSeenTxMax)
            return true;   // over the bound until the next prune: fetch
        return m_seen_tx.emplace(hash, t).second;
    }

    void on_full_block(const std::string& key, uint64_t id, const BlockType& block)
    {
        if (!find(key, id))
            return;
        const uint256 hash = pool_header_hash(block);
        auto& b = m_bodies[hash];
        if (b.received)
            return;   // already passed on
        b.received = true;
        b.at = now();
        b.peer = key;
        if (m_host.on_full_block)
            m_host.on_full_block(block);
    }

    void retry_bodies(Clock::time_point t)
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
            if (secs(t - b.at) < kCoinPoolBodyRetrySec) {
                ++it;
                continue;
            }
            if (b.asks >= kCoinPoolBodyMaxAsks) {
                LOG_WARNING << m_tag << " coin peer pool: block " << it->first.GetHex().substr(0, 16)
                            << " body not received after " << b.asks << " asks";
                it = m_bodies.erase(it);
                continue;
            }
            Slot* other = nullptr;
            auto live = live_slots();
            for (size_t i = 0; i < live.size() && !other; ++i) {
                Slot* c = live[(m_body_rr + i) % live.size()];
                if (c->key != b.peer)
                    other = c;
            }
            ++m_body_rr;
            b.at = t;
            ++b.asks;
            if (other) {
                other->peer->request_block(it->first);
                LOG_INFO << m_tag << " coin peer pool: block " << it->first.GetHex().substr(0, 16)
                         << " body not received from " << b.peer << ", asking " << other->key;
                b.peer = other->key;
            }
            ++it;
        }
    }

    void prune_seen(Clock::time_point t)
    {
        for (auto it = m_seen_tx.begin(); it != m_seen_tx.end();)
            it = secs(t - it->second) >= kCoinPoolSeenTtlSec ? m_seen_tx.erase(it) : std::next(it);
        if (m_seen_tx.size() >= kCoinPoolSeenTxMax)
            m_seen_tx.clear();
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
    std::map<std::string, std::unique_ptr<Slot>> m_slots;   // key -> slot
    uint64_t           m_next_id{0};
    size_t             m_rr{0};
    size_t             m_body_rr{0};
    uint32_t           m_last_height{0};
    Clock::time_point  m_last_progress{};
    Clock::time_point  m_last_getheaders{};
    uint256            m_last_announced;
    std::map<uint256, Body>              m_bodies;
    std::map<uint256, Clock::time_point> m_seen_tx;

    // Any thread.
    std::atomic<size_t>        m_live{0};
    mutable std::mutex         m_rows_mu;
    std::vector<PublishedRow>  m_rows;
};

} // namespace btc::coin
