// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the best chain's block hash at every height below the
/// header chain's checkpoint.
///
/// The DOGE header chain is rooted at a fast-start checkpoint (mainnet
/// 6,160,000): it holds no header below it, so no body below it can be
/// asked for. A UTXO set built from genesis needs every one of them. The
/// schedule is built once from `headers` messages (getheaders from genesis),
/// keeping only each height's hash and its parent's, dropping the header and
/// its AuxPoW; it is not added to HeaderChain (6.16 M resident index entries
/// would cost ~1.5 GB of RAM). It lives in a LevelDB (the header chain's)
/// under
///   'H' + height (4 bytes BE) -> block hash (32 bytes) | parent hash (32 bytes)
///   'H'                       -> state (below)
/// with a small read cache.
///
/// Proof: the schedule is served only once its hash chain links, by the
/// parent hash of every header, from genesis into the configured checkpoint
/// hash at the checkpoint height. The checkpoint commits to the whole prefix
/// (a hash chain is the commitment), so scrypt and AuxPoW are not checked
/// below it. Two rules make the stored prefix a hash chain:
///   - a batch is taken only when its first header's parent is the frontier
///     (the last height stored) and each header's parent is the one before
///     it: the prefix grows only at its end, never rewinds;
///   - before the schedule is marked complete, every stored height
///     1 .. checkpoint - 1 is read back in order and each parent hash checked
///     against the height below it (genesis for height 1), the last against
///     the checkpoint header's parent. A prefix that does not link (a disk
///     fault, a bug) is discarded, never persisted as complete.
/// A batch that breaks a link, or reaches the checkpoint height with another
/// hash, is dropped (nothing of it is stored); HashScheduleSync then cuts
/// the frontier back to where it stood before the sending peer was asked
/// (truncate), so a peer's bad batches cost those batches, not the prefix.
/// The body stream proves the links again: a body whose parent is not the
/// UTXO set's best block is refused at the connect point (ParentMismatch).
///
/// HashScheduleSync drives the sync: getheaders to one peer at a time, only
/// that peer's answers fed, a stall measured by the frontier's progress.
///
/// Thread safety: every public method takes the internal mutex.

#include <impl/ltc/coin/block.hpp>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace doge {
namespace coin {

class HashSchedule {
public:
    /// What feed() did with a batch of headers.
    enum class Feed {
        Extended,  // appended; the checkpoint height is not reached yet
        Complete,  // the chain linked into the checkpoint: the schedule is proven
        NotNext,   // the batch does not continue the frontier (another request's answer): ignored
        Broken,    // a header does not link to the one before it: the batch is dropped
        Rejected,  // the checkpoint height carries another hash: the batch is dropped;
                   // the stored prefix does not link: the schedule is discarded
        Done,      // the schedule was already complete: ignored
    };

    static const char* feed_name(Feed f)
    {
        switch (f) {
        case Feed::Extended: return "extended";
        case Feed::Complete: return "complete";
        case Feed::NotNext:  return "not-next";
        case Feed::Broken:   return "broken";
        case Feed::Rejected: return "rejected";
        case Feed::Done:     return "done";
        }
        return "unknown";
    }

    /// `db` must outlive the schedule. The schedule covers heights
    /// 0 .. checkpoint_height (0 = genesis_hash, checkpoint_height =
    /// checkpoint_hash).
    HashSchedule(core::LevelDBStore& db, uint32_t checkpoint_height, const uint256& checkpoint_hash,
                 const uint256& genesis_hash)
        : m_db(db)
        , m_cp_height(checkpoint_height)
        , m_cp_hash(checkpoint_hash)
        , m_genesis(genesis_hash)
        , m_frontier_hash(genesis_hash)
    {
    }

    HashSchedule(const HashSchedule&) = delete;
    HashSchedule& operator=(const HashSchedule&) = delete;

    /// Read the persisted state. A state for another checkpoint, genesis or
    /// record version starts over at genesis.
    void load()
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<uint8_t> v;
        if (!m_db.get(state_key(), v) || v.size() != STATE_SIZE || v[0] != STATE_VERSION) {
            reset_locked();
            return;
        }
        uint256 cp_hash, genesis, frontier;
        std::memcpy(cp_hash.data(), v.data() + 1, 32);
        const uint32_t cp_height = read_u32(v.data() + 33);
        std::memcpy(genesis.data(), v.data() + 37, 32);
        const uint32_t frontier_height = read_u32(v.data() + 69);
        std::memcpy(frontier.data(), v.data() + 73, 32);
        const bool complete = v[105] != 0;
        if (cp_hash != m_cp_hash || cp_height != m_cp_height || genesis != m_genesis
            || frontier_height > m_cp_height) {
            LOG_WARNING << "[EMB-DOGE] Hash schedule: stored for checkpoint " << cp_height << " "
                        << cp_hash.GetHex().substr(0, 16) << ", configured " << m_cp_height << " "
                        << m_cp_hash.GetHex().substr(0, 16) << ": starting over";
            reset_locked();
            return;
        }
        m_frontier_height = frontier_height;
        m_frontier_hash = frontier;
        m_complete = complete;
    }

    /// The schedule linked into the checkpoint (hash_at serves).
    bool complete() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_complete;
    }

    uint32_t checkpoint_height() const { return m_cp_height; }
    uint256 checkpoint_hash() const { return m_cp_hash; }

    /// Highest height stored so far (0 = genesis only).
    uint32_t frontier_height() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_frontier_height;
    }

    uint256 frontier_hash() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_frontier_hash;
    }

    /// The best chain's block hash at `h`; null while the schedule is not
    /// proven, and above the checkpoint (the header chain serves those).
    uint256 hash_at(uint32_t h) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (!m_complete || h > m_cp_height)
            return uint256();
        if (h == 0)
            return m_genesis;
        if (h == m_cp_height)
            return m_cp_hash;
        const uint32_t chunk = h >> CHUNK_BITS;
        auto it = m_cache.find(chunk);
        if (it == m_cache.end()) {
            it = load_chunk_locked(chunk);
            if (it == m_cache.end())
                return uint256();
        }
        return it->second[h & CHUNK_MASK];
    }

    /// getheaders locator: the frontier, the ten heights below it, then
    /// back in doubling steps, ending at genesis (Core CChain::GetLocator).
    /// An honest peer has the frontier and answers from it; a peer that
    /// does not (behind, or another chain) answers from deeper, and that
    /// answer is not taken (feed: NotNext).
    std::vector<uint256> locator() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<uint256> out;
        uint32_t step = 1;
        int64_t h = m_frontier_height;
        while (h > 0) {
            const uint32_t hh = static_cast<uint32_t>(h);
            const uint256 x = hh == m_frontier_height ? m_frontier_hash : stored_locked(hh).first;
            if (!x.IsNull())
                out.push_back(x);
            if (out.size() > 10)
                step *= 2;
            h -= step;
        }
        out.push_back(m_genesis);
        return out;
    }

    /// Append a `headers` batch. Its first header's parent must be the
    /// frontier, every header's parent the one before it. The header at the
    /// checkpoint height must hash to the checkpoint, and the stored prefix
    /// must link (verify_prefix_locked): then the schedule is complete.
    /// A batch that does not start at the frontier is NotNext (ignored); one
    /// that breaks a link, or reaches the checkpoint with another hash,
    /// discards the schedule back to genesis.
    Feed feed(const std::vector<ltc::coin::BlockHeaderType>& headers)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_complete)
            return Feed::Done;
        if (headers.empty() || headers.front().m_previous_block != m_frontier_hash)
            return Feed::NotNext;
        uint32_t h = m_frontier_height;
        uint256 prev = m_frontier_hash;
        auto batch = m_db.create_batch();
        for (const auto& hdr : headers) {
            if (hdr.m_previous_block != prev) {
                LOG_WARNING << "[EMB-DOGE] Hash schedule: header at h=" << h + 1
                            << " does not link to h=" << h << ": batch dropped";
                return Feed::Broken;
            }
            const uint256 hh = Hash(pack(hdr).get_span());
            if (h + 1 == m_cp_height) {
                if (hh != m_cp_hash) {
                    LOG_WARNING << "[EMB-DOGE] Hash schedule: h=" << h + 1 << " is "
                                << hh.GetHex().substr(0, 16) << ", the checkpoint is "
                                << m_cp_hash.GetHex().substr(0, 16) << ": batch dropped";
                    return Feed::Rejected;
                }
                // Store up to the checkpoint's parent, then prove the whole
                // prefix before persisting the schedule as complete.
                if (!commit_locked(batch, h, prev))
                    return Feed::NotNext;
                if (!verify_prefix_locked(prev)) {
                    LOG_ERROR << "[EMB-DOGE] Hash schedule: the stored heights 1.." << m_cp_height - 1
                              << " do not link into the checkpoint: discarded";
                    reset_locked();
                    return Feed::Rejected;
                }
                m_complete = true;
                m_frontier_height = m_cp_height;
                m_frontier_hash = m_cp_hash;
                if (!m_db.put(state_key(), state_locked())) {
                    m_complete = false;
                    m_frontier_height = h;
                    m_frontier_hash = prev;
                    return Feed::NotNext;
                }
                m_cache.clear();
                LOG_INFO << "[EMB-DOGE] Hash schedule complete: heights 0.." << m_cp_height
                         << " link into the checkpoint " << m_cp_hash.GetHex().substr(0, 16);
                return Feed::Complete;
            }
            ++h;
            std::vector<uint8_t> v(64);
            std::memcpy(v.data(), hh.data(), 32);
            std::memcpy(v.data() + 32, prev.data(), 32);
            batch.put(height_key(h), v);
            prev = hh;
        }
        if (!commit_locked(batch, h, prev))
            return Feed::NotNext;
        return Feed::Extended;
    }

    /// Drop the schedule back to genesis (stored hashes above the frontier
    /// are rewritten by the next sync before anything reads them).
    void discard()
    {
        std::lock_guard<std::mutex> lock(m_mu);
        reset_locked();
    }

    /// Cut the frontier back to `height` (below the frontier, not complete):
    /// what a peer stored above it is dropped. Back to genesis when the
    /// record at `height` is missing.
    void truncate(uint32_t height)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_complete || height >= m_frontier_height)
            return;
        const uint256 x = stored_locked(height).first;
        if (x.IsNull()) {
            reset_locked();
            return;
        }
        m_frontier_height = height;
        m_frontier_hash = x;
        m_cache.clear();
        m_db.put(state_key(), state_locked());
    }

private:
    static constexpr uint8_t  STATE_VERSION = 2;               // 2: height records carry the parent hash
    static constexpr size_t   STATE_SIZE = 1 + 32 + 4 + 32 + 4 + 32 + 1;
    static constexpr uint32_t CHUNK_BITS = 16;                 // 65,536 heights (2 MB) per cache chunk
    static constexpr uint32_t CHUNK_MASK = (1u << CHUNK_BITS) - 1;
    static constexpr size_t   CACHE_CHUNKS = 2;
    static constexpr size_t   RECORD_SIZE = 64;                // hash | parent hash

    static std::string state_key() { return std::string(1, 'H'); }

    static std::string height_key(uint32_t h)
    {
        std::string k(5, '\0');
        k[0] = 'H';
        k[1] = static_cast<char>((h >> 24) & 0xFF);
        k[2] = static_cast<char>((h >> 16) & 0xFF);
        k[3] = static_cast<char>((h >> 8) & 0xFF);
        k[4] = static_cast<char>(h & 0xFF);
        return k;
    }

    static uint32_t key_height(const std::string& k)
    {
        return (uint32_t(uint8_t(k[1])) << 24) | (uint32_t(uint8_t(k[2])) << 16)
             | (uint32_t(uint8_t(k[3])) << 8) | uint32_t(uint8_t(k[4]));
    }

    static uint32_t read_u32(const uint8_t* p)
    {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }

    static void write_u32(uint8_t* p, uint32_t v)
    {
        for (int i = 0; i < 4; ++i)
            p[i] = static_cast<uint8_t>(v >> (8 * i));
    }

    std::vector<uint8_t> state_locked() const
    {
        std::vector<uint8_t> v(STATE_SIZE, 0);
        v[0] = STATE_VERSION;
        std::memcpy(v.data() + 1, m_cp_hash.data(), 32);
        write_u32(v.data() + 33, m_cp_height);
        std::memcpy(v.data() + 37, m_genesis.data(), 32);
        write_u32(v.data() + 69, m_frontier_height);
        std::memcpy(v.data() + 73, m_frontier_hash.data(), 32);
        v[105] = m_complete ? 1 : 0;
        return v;
    }

    /// Commit a batch of height records with the new frontier.
    bool commit_locked(core::LevelDBStore::BatchWriter& batch, uint32_t height, const uint256& hash)
    {
        const uint32_t old_height = m_frontier_height;
        const uint256 old_hash = m_frontier_hash;
        m_frontier_height = height;
        m_frontier_hash = hash;
        batch.put(state_key(), state_locked());
        if (!batch.commit()) {
            m_frontier_height = old_height;
            m_frontier_hash = old_hash;
            return false;
        }
        return true;
    }

    /// Every height 1 .. checkpoint - 1 stored, in order, each record's
    /// parent the hash below it (genesis for 1), the last one `cp_parent`.
    bool verify_prefix_locked(const uint256& cp_parent) const
    {
        uint32_t expect = 1;
        uint256 below = m_genesis;
        bool ok = true;
        const bool scanned = m_db.for_each_prefix(state_key(),
            [&](const std::string& k, const std::vector<uint8_t>& v) {
                if (k.size() != 5)
                    return true;  // the state record
                const uint32_t h = key_height(k);
                if (h >= m_cp_height)
                    return false;  // nothing at or above the checkpoint belongs here
                if (h != expect || v.size() != RECORD_SIZE
                    || std::memcmp(v.data() + 32, below.data(), 32) != 0) {
                    ok = false;
                    return false;
                }
                std::memcpy(below.data(), v.data(), 32);
                ++expect;
                return true;
            });
        return scanned && ok && expect == m_cp_height && below == cp_parent;
    }

    void reset_locked()
    {
        m_frontier_height = 0;
        m_frontier_hash = m_genesis;
        m_complete = false;
        m_cache.clear();
        m_db.put(state_key(), state_locked());
    }

    /// The record at `h`: (hash, parent); nulls when absent.
    std::pair<uint256, uint256> stored_locked(uint32_t h) const
    {
        if (h == 0)
            return {m_genesis, uint256()};
        std::vector<uint8_t> v;
        if (!m_db.get(height_key(h), v) || v.size() != RECORD_SIZE)
            return {};
        uint256 x, p;
        std::memcpy(x.data(), v.data(), 32);
        std::memcpy(p.data(), v.data() + 32, 32);
        return {x, p};
    }

    std::map<uint32_t, std::vector<uint256>>::iterator load_chunk_locked(uint32_t chunk) const
    {
        std::vector<uint256> hashes(size_t(1) << CHUNK_BITS);
        const std::string prefix = height_key(chunk << CHUNK_BITS).substr(0, 3);
        const bool ok = m_db.for_each_prefix(prefix, [&](const std::string& k, const std::vector<uint8_t>& v) {
            if (k.size() == 5 && v.size() == RECORD_SIZE)
                std::memcpy(hashes[key_height(k) & CHUNK_MASK].data(), v.data(), 32);
            return true;
        });
        if (!ok)
            return m_cache.end();
        while (m_cache.size() >= CACHE_CHUNKS)
            m_cache.erase(m_cache.begin());
        return m_cache.emplace(chunk, std::move(hashes)).first;
    }

    core::LevelDBStore& m_db;
    const uint32_t      m_cp_height;
    const uint256       m_cp_hash;
    const uint256       m_genesis;

    mutable std::mutex m_mu;
    uint32_t m_frontier_height{0};
    uint256  m_frontier_hash;
    bool     m_complete{false};
    mutable std::map<uint32_t, std::vector<uint256>> m_cache;  // chunk -> 65,536 hashes
};

/// The hash schedule's P2P sync (main_ltc's DOGE wiring drives it):
///   - getheaders to ONE peer at a time (a 3-4 GB AuxPoW header sync must
///     not be asked of every peer); the first peer is picked at random;
///   - every batch that continues the frontier is taken, whoever sends it (a
///     replaced peer's late answer included: under the header chain's own
///     getheaders traffic an answer can take longer than STALL); safety is
///     feed()'s - a batch extends only at the frontier, and no chain but the
///     checkpoint's completes. Any other batch is the header chain's;
///   - a stall is no frontier progress for STALL since the later of the last
///     progress and the moment this peer was asked; asking the same peer
///     again does not restart the clock. A stalled peer is replaced;
///   - the frontier is a stack of runs: consecutive extensions by one peer.
///     A batch that breaks or reaches the checkpoint with another hash cuts
///     back its sender's run when that run is the top one (nobody continued
///     it); a frontier no peer continues for long (FRUITLESS_AFTER peers that
///     answered but did not continue it, and TRUNCATE_AFTER without progress;
///     silence never counts) loses its top run (truncate): a lying peer costs
///     its own batches, not the prefix. Again and again, back to genesis.
/// Thread safety: every public method takes the internal mutex.
class HashScheduleSync {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::chrono::seconds STALL{30};
    static constexpr uint32_t FRUITLESS_AFTER = 20;
    static constexpr std::chrono::minutes TRUNCATE_AFTER{30};

    explicit HashScheduleSync(HashSchedule& schedule)
        : m_s(schedule)
        , m_rr(static_cast<size_t>(std::random_device{}()))
    {
    }

    /// A getheaders to send: `peer_idx` picks a peer round robin when
    /// `peer` is empty (a new peer), else `peer` is asked again.
    struct Ask {
        std::vector<uint256> locator;
        size_t               peer_idx{0};
        std::string          peer;
    };

    /// Who to ask now: nothing while the asked peer is within its time or
    /// the schedule is complete; a new peer (after a stall) otherwise.
    std::optional<Ask> due(Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_s.complete())
            return std::nullopt;
        if (m_progress_at == Clock::time_point{})
            m_progress_at = now;  // the clock starts with the sync
        note_progress_locked(now);
        if (!m_peer.empty()) {
            const auto since = std::max(m_progress_at, m_asked_at);
            if (now - since < STALL)
                return std::nullopt;
            ++m_stalls;
            if (m_turn_answered && m_s.frontier_height() == m_height_when_asked)
                ++m_fruitless;  // it answered, and not with the frontier's continuation
            LOG_INFO << "[EMB-DOGE] Hash schedule at h=" << m_s.frontier_height() << "/"
                     << m_s.checkpoint_height() << ": no progress from " << m_peer << " in "
                     << std::chrono::duration_cast<std::chrono::seconds>(now - since).count()
                     << "s; asking another peer";
            if (m_fruitless >= FRUITLESS_AFTER && now - m_progress_at >= TRUNCATE_AFTER) {
                const uint32_t to = m_runs.empty() ? 0 : m_runs.back().first;
                LOG_WARNING << "[EMB-DOGE] Hash schedule: " << m_fruitless
                            << " peers answered without continuing the frontier at h="
                            << m_s.frontier_height() << " for "
                            << std::chrono::duration_cast<std::chrono::minutes>(now - m_progress_at).count()
                            << " min: cut back to h=" << to << " (before the peer that extended it)";
                if (!m_runs.empty())
                    m_runs.pop_back();
                truncate_locked(to, now);
            }
            m_peer.clear();
            ++m_rr;
        }
        return Ask{m_s.locator(), m_rr, std::string()};
    }

    /// The peer the getheaders went to ("" = none was ready: asked again at
    /// the next due()).
    void asked(const std::string& peer, Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (peer.empty()) {
            m_peer.clear();
            return;
        }
        if (peer != m_peer)
            start_turn_locked(peer, now);
    }

    /// A headers batch from `peer`: fed when it continues the frontier,
    /// whoever sent it; otherwise NotNext (the caller hands it to the header
    /// chain). `ask_next`: ask that peer for the next batch now (after an
    /// extension), or a new peer (after a bad batch).
    HashSchedule::Feed on_headers(const std::string& peer,
                                  const std::vector<ltc::coin::BlockHeaderType>& headers,
                                  Clock::time_point now, std::optional<Ask>& ask_next)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        ask_next.reset();
        if (m_s.complete())
            return HashSchedule::Feed::Done;
        if (!peer.empty() && peer == m_peer)
            m_turn_answered = true;
        const uint32_t before_h = m_s.frontier_height();
        const auto r = m_s.feed(headers);
        switch (r) {
        case HashSchedule::Feed::Extended: {
            if (m_runs.empty() || m_runs.back().second != peer) {
                if (m_runs.size() >= MAX_RUNS)
                    m_runs.erase(m_runs.begin());  // the deepest base is forgotten: genesis then
                m_runs.emplace_back(before_h, peer);
            }
            if (peer != m_peer && !peer.empty())
                start_turn_locked(peer, now);
            note_progress_locked(now);
            ask_next = Ask{m_s.locator(), m_rr, m_peer};
            break;
        }
        case HashSchedule::Feed::Broken:
        case HashSchedule::Feed::Rejected: {
            // This peer's chain is not the checkpoint's: what it stored and
            // nobody continued goes, another peer is asked now.
            const bool cut = !m_runs.empty() && m_runs.back().second == peer;
            if (cut) {
                const uint32_t to = m_runs.back().first;
                m_runs.pop_back();
                truncate_locked(to, now);
            }
            if (peer == m_peer) {
                m_peer.clear();
                ++m_rr;
            }
            if (cut || m_peer.empty())
                ask_next = Ask{m_s.locator(), m_rr, std::string()};
            break;
        }
        default:
            break;
        }
        return r;
    }

    std::string peer() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_peer;
    }
    uint64_t stalls() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_stalls;
    }
    uint64_t truncations() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_truncations;
    }

private:
    static constexpr size_t MAX_RUNS = 4096;

    void start_turn_locked(const std::string& peer, Clock::time_point now)
    {
        m_peer = peer;
        m_asked_at = now;
        m_height_when_asked = m_s.frontier_height();
        m_turn_answered = false;
    }

    void truncate_locked(uint32_t height, Clock::time_point now)
    {
        m_s.truncate(height);
        ++m_truncations;
        m_fruitless = 0;
        const uint32_t h = m_s.frontier_height();
        while (!m_runs.empty() && m_runs.back().first >= h)
            m_runs.pop_back();  // runs that started above the cut (genesis: all)
        m_progress_height = h;
        m_progress_at = now;
        m_height_when_asked = std::min(m_height_when_asked, h);
    }

    void note_progress_locked(Clock::time_point now)
    {
        const uint32_t h = m_s.frontier_height();
        if (h > m_progress_height) {
            m_progress_height = h;
            m_progress_at = now;
            m_fruitless = 0;
        } else if (h < m_progress_height) {
            m_progress_height = h;  // cut back
        }
    }

    HashSchedule&     m_s;
    mutable std::mutex m_mu;
    std::string       m_peer;             // the peer asked ("" = none)
    size_t            m_rr{0};
    Clock::time_point m_asked_at{};
    Clock::time_point m_progress_at{};
    uint32_t          m_progress_height{0};
    uint32_t          m_height_when_asked{0};
    bool              m_turn_answered{false};  // the asked peer sent a batch this turn
    uint32_t          m_fruitless{0};     // peers in a row that answered without continuing
    uint64_t          m_stalls{0};
    uint64_t          m_truncations{0};
    std::vector<std::pair<uint32_t, std::string>> m_runs;  // (base height, peer), deepest first
};

} // namespace coin
} // namespace doge
