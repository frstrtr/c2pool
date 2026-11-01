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

#include <impl/doge/coin/schedule_anchors.hpp>
#include <impl/ltc/coin/block.hpp>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
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
        Truncated, // (HashScheduleSync) the batch did not parse to its end: a strike
                   // for its peer, never a cut; what linked onto the frontier is stored
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
        case Feed::Truncated: return "truncated";
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
        std::vector<uint256> out;
        for (const auto& e : locator_entries())
            out.push_back(e.second);
        return out;
    }

    /// The locator with each entry's height (genesis last, at 0).
    std::vector<std::pair<uint32_t, uint256>> locator_entries() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<std::pair<uint32_t, uint256>> out;
        uint32_t step = 1;
        int64_t h = m_frontier_height;
        while (h > 0) {
            const uint32_t hh = static_cast<uint32_t>(h);
            const uint256 x = hh == m_frontier_height ? m_frontier_hash : stored_locked(hh).first;
            if (!x.IsNull())
                out.emplace_back(hh, x);
            if (out.size() > 10)
                step *= 2;
            h -= step;
        }
        out.emplace_back(0u, m_genesis);
        return out;
    }

    /// The height of `h` in the current locator (nullopt: not in it).
    std::optional<uint32_t> locator_height(const uint256& h) const
    {
        for (const auto& e : locator_entries())
            if (e.second == h)
                return e.first;
        return std::nullopt;
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
    /// record at `height` is missing. false: the state could not be written
    /// (the cut holds in memory; the next batch's commit writes it).
    bool truncate(uint32_t height)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_complete || height >= m_frontier_height)
            return true;
        const uint256 x = stored_locked(height).first;
        if (x.IsNull()) {
            reset_locked();
            return true;
        }
        m_frontier_height = height;
        m_frontier_hash = x;
        m_cache.clear();
        if (!m_db.put(state_key(), state_locked())) {
            LOG_ERROR << "[EMB-DOGE] Hash schedule: the cut to h=" << height
                      << " could not be written; a restart before the next batch resumes above it";
            return false;
        }
        return true;
    }

    /// The sync's run bases (HashScheduleSync), persisted so a restart cuts
    /// back run by run as the process before it would have; deepest first,
    /// the most recent RUNS_KEPT.
    static constexpr size_t RUNS_KEPT = 64;
    bool save_runs(const std::vector<uint32_t>& bases)
    {
        const size_t n = std::min(bases.size(), RUNS_KEPT);
        std::vector<uint8_t> v(1 + 4 * n);
        v[0] = RUNS_VERSION;
        for (size_t i = 0; i < n; ++i)
            write_u32(v.data() + 1 + 4 * i, bases[bases.size() - n + i]);
        return m_db.put(runs_key(), v);
    }
    std::vector<uint32_t> load_runs() const
    {
        std::vector<uint8_t> v;
        std::vector<uint32_t> out;
        if (!m_db.get(runs_key(), v) || v.empty() || v[0] != RUNS_VERSION || (v.size() - 1) % 4 != 0)
            return out;
        for (size_t i = 1; i + 4 <= v.size(); i += 4)
            out.push_back(read_u32(v.data() + i));
        return out;
    }

    // ── Anchored ranges (RangeSync, DESIGN-ANCHORS) ─────────────────────
    // Range i = heights (STEP * i, STEP * (i + 1)]. A range is stored only
    // whole: its STEP headers link from anchor i to anchor i + 1. The range
    // bitmap is written in the same batch as the range's records, and the
    // frontier is the end of the contiguous delivered prefix.

    enum class RangeMode {
        None,      // no usable anchors (absent, another chain, above the
                   // checkpoint, or refused at run time): the sequential sync
        Anchored,  // the anchors end at the configured checkpoint
        Tail,      // they end below it: the ranges, then the sequential sync
    };

    enum class RangeFeed {
        Stored,    // the range is stored
        Complete,  // ... and it was the last: the schedule is proven
        Done,      // already stored (or the schedule is complete): ignored
        NotOurs,   // does not start at the range's anchor
        Short,     // links from the anchor but has fewer than STEP headers
        Long,      // more than STEP headers
        Broken,    // a header does not link to the one before it
        WrongEnd,  // STEP linked headers that end at another hash than the next anchor
        Failed,    // the write failed: nothing stored
        Rejected,  // the last range, but the stored prefix does not link: reset
    };

    /// Use `a` (after load()): they must start at genesis and end at or below
    /// the configured checkpoint (at it: with its hash). Loads the range
    /// bitmap kept for these anchors, else imports what a sequential sync
    /// stored (a range whose STEP records link from its anchor to the next).
    RangeMode use_anchors(const ScheduleAnchors& a)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_range_mode = RangeMode::None;
        m_anchors.reset();
        if (m_complete || a.empty())
            return RangeMode::None;
        const uint32_t acp = a.checkpoint_height();
        if (a.hashes.front() != m_genesis) {
            LOG_WARNING << "[EMB-DOGE] Hash schedule: the anchors start at another genesis: not used";
            return RangeMode::None;
        }
        if (acp > m_cp_height || (acp == m_cp_height && a.checkpoint_hash() != m_cp_hash)) {
            LOG_WARNING << "[EMB-DOGE] Hash schedule: the anchors end at " << acp << " "
                        << a.checkpoint_hash().GetHex().substr(0, 16) << ", the checkpoint is " << m_cp_height
                        << " " << m_cp_hash.GetHex().substr(0, 16) << ": not used";
            return RangeMode::None;
        }
        m_anchors = a;
        m_anchors_digest = a.digest();
        m_range_bits.assign((a.ranges() + 7) / 8, 0);
        bool refused = false;  // a flag older builds wrote: ignored, the anchors are tried again
        if (!load_ranges_locked(refused))
            import_ranges_locked();
        recount_locked();
        m_range_mode = acp == m_cp_height ? RangeMode::Anchored : RangeMode::Tail;
        // The frontier: the contiguous delivered prefix (a tail already
        // synced past the anchors' end keeps its place).
        const uint32_t prefix = ScheduleAnchors::STEP * m_first_undone;
        if (!(m_range_mode == RangeMode::Tail && m_first_undone == a.ranges() && m_frontier_height > prefix)) {
            m_frontier_height = prefix;
            m_frontier_hash = a.hashes[m_first_undone];
            m_cache.clear();
        }
        auto batch = m_db.create_batch();
        batch.put(ranges_key(), ranges_record_locked(m_range_bits, false));
        batch.put(state_key(), state_locked());
        if (!batch.commit())
            LOG_WARNING << "[EMB-DOGE] Hash schedule: the range bitmap could not be written";
        LOG_INFO << "[EMB-DOGE] Hash schedule: " << a.ranges() << " anchored ranges to h=" << acp << ", "
                 << m_ranges_done << " delivered, the prefix at h=" << m_frontier_height
                 << (m_range_mode == RangeMode::Tail ? " (then the sequential sync to the checkpoint)" : "");
        if (m_ranges_done == a.ranges() && m_range_mode == RangeMode::Anchored)
            finish_ranges_locked();
        return m_range_mode;
    }

    RangeMode range_mode() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_range_mode;
    }
    uint32_t ranges_total() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_anchors ? m_anchors->ranges() : 0;
    }
    uint32_t ranges_done() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_ranges_done;
    }
    uint32_t first_undone_range() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_first_undone;
    }
    bool range_done(uint32_t i) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return range_bit_locked(i);
    }

    /// Store range i from `headers` if they are exactly it. `end`: the hash
    /// the STEP linked headers end at (set for WrongEnd and Stored).
    RangeFeed store_range(uint32_t i, const std::vector<ltc::coin::BlockHeaderType>& headers,
                          uint256* end = nullptr)
    {
        constexpr uint32_t STEP = ScheduleAnchors::STEP;
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_complete)
            return RangeFeed::Done;
        if (!m_anchors || i >= m_anchors->ranges() || headers.empty()
            || headers.front().m_previous_block != m_anchors->hashes[i])
            return RangeFeed::NotOurs;
        if (range_bit_locked(i))
            return RangeFeed::Done;
        if (headers.size() > STEP)
            return RangeFeed::Long;
        std::vector<uint256> hs;
        hs.reserve(headers.size());
        uint256 prev = m_anchors->hashes[i];
        for (const auto& hdr : headers) {
            if (hdr.m_previous_block != prev)
                return RangeFeed::Broken;
            prev = Hash(pack(hdr).get_span());
            hs.push_back(prev);
        }
        if (headers.size() < STEP)
            return RangeFeed::Short;
        if (end)
            *end = prev;
        if (prev != m_anchors->hashes[i + 1])
            return RangeFeed::WrongEnd;
        auto batch = m_db.create_batch();
        uint256 parent = m_anchors->hashes[i];
        for (uint32_t k = 0; k < STEP; ++k) {
            const uint32_t h = STEP * i + k + 1;
            if (h < m_cp_height) {
                std::vector<uint8_t> v(RECORD_SIZE);
                std::memcpy(v.data(), hs[k].data(), 32);
                std::memcpy(v.data() + 32, parent.data(), 32);
                batch.put(height_key(h), v);
            }
            parent = hs[k];
        }
        auto bits = m_range_bits;
        bits[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
        batch.put(ranges_key(), ranges_record_locked(bits, false));
        // The frontier moves when the prefix grows.
        const uint32_t old_h = m_frontier_height;
        const uint256 old_hash = m_frontier_hash;
        uint32_t first = m_first_undone;
        while (first < m_anchors->ranges() && (bits[first / 8] >> (first % 8) & 1))
            ++first;
        if (STEP * first > m_frontier_height) {
            m_frontier_height = STEP * first;
            m_frontier_hash = m_anchors->hashes[first];
        }
        batch.put(state_key(), state_locked());
        if (!batch.commit()) {
            m_frontier_height = old_h;
            m_frontier_hash = old_hash;
            return RangeFeed::Failed;
        }
        m_range_bits.swap(bits);
        m_first_undone = first;
        ++m_ranges_done;
        if (m_ranges_done == m_anchors->ranges() && m_range_mode == RangeMode::Anchored)
            return finish_ranges_locked();
        return RangeFeed::Stored;
    }

    /// The anchors are refused for the rest of this process (a wrong anchor,
    /// an undeliverable range, every peer excluded). Not persisted: a refusal
    /// at run time is likelier forced by peers than a wrong shipped anchor
    /// (tools/doge-anchor-check.py checks those before they ship), so the
    /// next start tries the anchors again (VERIFY5 S1).
    void refuse_anchors()
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (!m_anchors)
            return;
        m_range_mode = RangeMode::None;
    }

    /// The record's hash at `h` (0 < h < checkpoint), complete or not; null
    /// when absent.
    uint256 stored_hash(uint32_t h) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return stored_locked(h).first;
    }

    /// The 'H' state of a schedule DB, read without a configured checkpoint
    /// (the anchor dump).
    struct StoredState {
        uint32_t cp_height{0};
        uint256  cp_hash;
        uint256  genesis;
        uint32_t frontier{0};
        bool     complete{false};
    };
    static std::optional<StoredState> read_state(core::LevelDBStore& db)
    {
        std::vector<uint8_t> v;
        if (!db.get(state_key(), v) || v.size() != STATE_SIZE || v[0] != STATE_VERSION)
            return std::nullopt;
        StoredState st;
        std::memcpy(st.cp_hash.data(), v.data() + 1, 32);
        st.cp_height = read_u32(v.data() + 33);
        std::memcpy(st.genesis.data(), v.data() + 37, 32);
        st.frontier = read_u32(v.data() + 69);
        st.complete = v[105] != 0;
        return st;
    }

private:
    static constexpr uint8_t  STATE_VERSION = 2;               // 2: height records carry the parent hash
    static constexpr size_t   STATE_SIZE = 1 + 32 + 4 + 32 + 4 + 32 + 1;
    static constexpr uint32_t CHUNK_BITS = 16;                 // 65,536 heights (2 MB) per cache chunk
    static constexpr uint32_t CHUNK_MASK = (1u << CHUNK_BITS) - 1;
    static constexpr size_t   CACHE_CHUNKS = 2;
    static constexpr size_t   RECORD_SIZE = 64;                // hash | parent hash

    static std::string state_key() { return std::string(1, 'H'); }
    // Not under 'H' (the height records' scan); the header chain's keys are
    // "h" + hash, "H" + height, "tip", "height".
    static std::string runs_key() { return "schedule_runs"; }
    static constexpr uint8_t RUNS_VERSION = 1;
    // The range bitmap: version | flags (1 = refused, written by older builds; ignored) | anchors digest
    // | checkpoint height | checkpoint hash | bits. Not under 'H' either.
    static std::string ranges_key() { return "schedule_ranges"; }
    static constexpr uint8_t RANGES_VERSION = 1;

    std::vector<uint8_t> ranges_record_locked(const std::vector<uint8_t>& bits, bool refused) const
    {
        std::vector<uint8_t> v(1 + 1 + 32 + 4 + 32);
        v[0] = RANGES_VERSION;
        v[1] = refused ? 1 : 0;
        std::memcpy(v.data() + 2, m_anchors_digest.data(), 32);
        write_u32(v.data() + 34, m_cp_height);
        std::memcpy(v.data() + 38, m_cp_hash.data(), 32);
        v.insert(v.end(), bits.begin(), bits.end());
        return v;
    }

    /// The bitmap kept for these anchors and this checkpoint; false when
    /// absent or for others (then the import runs).
    bool load_ranges_locked(bool& refused)
    {
        std::vector<uint8_t> v;
        if (!m_db.get(ranges_key(), v) || v.size() != 70 + m_range_bits.size() || v[0] != RANGES_VERSION)
            return false;
        uint256 d, cp;
        std::memcpy(d.data(), v.data() + 2, 32);
        std::memcpy(cp.data(), v.data() + 38, 32);
        if (d != m_anchors_digest || read_u32(v.data() + 34) != m_cp_height || cp != m_cp_hash)
            return false;
        refused = v[1] & 1;
        std::copy(v.begin() + 70, v.end(), m_range_bits.begin());
        return true;
    }

    /// One ordered scan of the height records: a range whose STEP records
    /// are all present, link from its anchor and end at the next anchor is
    /// delivered. The last range of an anchored schedule ends at the
    /// checkpoint, which has no record: it is always fetched.
    void import_ranges_locked()
    {
        constexpr uint32_t STEP = ScheduleAnchors::STEP;
        std::fill(m_range_bits.begin(), m_range_bits.end(), 0);
        const uint32_t n = m_anchors->ranges();
        uint32_t cur = UINT32_MAX, expect = 0, imported = 0;
        uint256 below;
        bool ok = false;
        m_db.for_each_prefix(state_key(), [&](const std::string& k, const std::vector<uint8_t>& v) {
            if (k.size() != 5)
                return true;
            const uint32_t h = key_height(k);
            if (h >= m_cp_height || h == 0)
                return h < m_cp_height;
            const uint32_t r = (h - 1) / STEP;
            if (r >= n)
                return false;
            if (r != cur) {
                cur = r;
                expect = STEP * r + 1;
                below = m_anchors->hashes[r];
                ok = true;
            }
            if (!ok)
                return true;
            if (h != expect || v.size() != RECORD_SIZE || std::memcmp(v.data() + 32, below.data(), 32) != 0) {
                ok = false;
                return true;
            }
            std::memcpy(below.data(), v.data(), 32);
            ++expect;
            if (h == STEP * (r + 1)) {
                if (below == m_anchors->hashes[r + 1]) {
                    m_range_bits[r / 8] |= static_cast<uint8_t>(1u << (r % 8));
                    ++imported;
                }
                ok = false;
            }
            return true;
        });
        LOG_INFO << "[EMB-DOGE] Hash schedule: imported " << imported << " of " << n
                 << " ranges from the stored heights";
    }

    bool range_bit_locked(uint32_t i) const
    {
        return i / 8 < m_range_bits.size() && (m_range_bits[i / 8] >> (i % 8) & 1);
    }

    void recount_locked()
    {
        const uint32_t n = m_anchors ? m_anchors->ranges() : 0;
        m_ranges_done = 0;
        m_first_undone = n;
        for (uint32_t i = 0; i < n; ++i) {
            if (range_bit_locked(i))
                ++m_ranges_done;
            else if (m_first_undone == n)
                m_first_undone = i;
        }
    }

    /// Every range of an anchored schedule is stored: prove the prefix
    /// (heights 1 .. checkpoint - 1 link from genesis; the last range linked
    /// the checkpoint to its parent when it was stored), then complete.
    RangeFeed finish_ranges_locked()
    {
        const uint256 cp_parent = stored_locked(m_cp_height - 1).first;
        if (cp_parent.IsNull() || !verify_prefix_locked(cp_parent)) {
            LOG_ERROR << "[EMB-DOGE] Hash schedule: every range is stored but heights 1.." << m_cp_height - 1
                      << " do not link: the ranges are fetched again";
            std::fill(m_range_bits.begin(), m_range_bits.end(), 0);
            m_db.put(ranges_key(), ranges_record_locked(m_range_bits, false));
            recount_locked();
            reset_locked();
            return RangeFeed::Rejected;
        }
        m_complete = true;
        m_frontier_height = m_cp_height;
        m_frontier_hash = m_cp_hash;
        if (!m_db.put(state_key(), state_locked())) {
            m_complete = false;
            m_frontier_height = ScheduleAnchors::STEP * m_first_undone;
            return RangeFeed::Failed;
        }
        m_cache.clear();
        LOG_INFO << "[EMB-DOGE] Hash schedule complete (anchored ranges): heights 0.." << m_cp_height
                 << " link into the checkpoint " << m_cp_hash.GetHex().substr(0, 16);
        return RangeFeed::Complete;
    }

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

    // Anchored ranges (use_anchors).
    std::optional<ScheduleAnchors> m_anchors;
    uint256              m_anchors_digest;
    std::vector<uint8_t> m_range_bits;
    uint32_t             m_ranges_done{0};
    uint32_t             m_first_undone{0};
    RangeMode            m_range_mode{RangeMode::None};
};

/// The hash schedule's P2P sync (main_ltc's DOGE wiring drives it):
///   - getheaders to one peer at a time (a 3-4 GB AuxPoW header sync must
///     not be asked of every peer), two after a stall (a hedge: a slow peer
///     cannot hold the sync); the first peer is picked at random;
///   - only an answer to a getheaders of ours is fed: from a peer with an
///     outstanding ask (asked within ASK_TTL, one answer per ask), so a late
///     answer from a replaced peer is taken, a peer never asked is not. A
///     batch is taken when it continues the frontier (feed()); any other
///     batch is the header chain's;
///   - a stall is no frontier progress for STALL since the later of the last
///     progress and the moment the turn began; asking the same peer again
///     does not restart the clock. A stalled turn goes to new peers;
///   - the frontier is a stack of runs: consecutive extensions by one peer.
///     A batch that breaks or reaches the checkpoint with another hash cuts
///     back its sender's run when that run is the top one (nobody continued
///     it); a frontier no peer continues for long (FRUITLESS_AFTER turns in
///     which a peer answered the schedule's locator without continuing it,
///     and TRUNCATE_AFTER without progress; silence and the header chain's
///     traffic never count) loses its top run (truncate): a lying peer costs
///     its own batches, not the prefix. Again and again, back to genesis.
///     The run bases are persisted (a restart cuts back the same way);
///   - every cut but a broken or rejected batch's needs the stall: 20
///     fruitless turns and 30 minutes without progress. A run longer than
///     MAX_UNPROVEN_CUT needs evidence on top: VOTES_TO_CUT asked peers whose
///     answers to the locator carry, at a height inside the run, a header
///     other than the stored one (another chain), gathered since the run
///     last moved. Votes alone cut nothing: they cost a sybil one 80-byte
///     header each, so a run that is still progressing is never cut (VERIFY5
///     M1), and slow or silent peers never cut a long run (live, 825f4fd8c:
///     970,000 honest heights were cut on 20 slow answers and 30 minutes);
///   - a floor (the anchored prefix, when this sync is the fallback of the
///     anchored ranges) is never cut below;
///   - a peer whose run was cut, or that sent a broken or rejected batch, is
///     never fed nor asked again by this process;
///   - a batch that did not parse to its end (truncated_at: the AuxPoW parser
///     stopped at an entry it could not read) is a strike, never a cut: what
///     links onto the frontier is stored, the ask is answered and the turn
///     goes to another peer, the peer stays askable. A bad parse is no
///     evidence of another chain (the 19 cuts of the live log were this).
/// Thread safety: every public method takes the internal mutex.
class HashScheduleSync {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::chrono::seconds STALL{30};
    static constexpr uint32_t FRUITLESS_AFTER = 20;
    static constexpr std::chrono::minutes TRUNCATE_AFTER{30};
    static constexpr std::chrono::minutes ASK_TTL{10};  // far longer than any queued answer
    static constexpr size_t HEDGE = 2;                  // new peers asked after a stall
    static constexpr uint32_t MAX_UNPROVEN_CUT = 20000; // longest run cut on silence alone
    static constexpr size_t VOTES_TO_CUT = 3;           // peers that show another chain inside the run

    explicit HashScheduleSync(HashSchedule& schedule)
        : m_s(schedule)
        , m_rr(static_cast<size_t>(std::random_device{}()))
    {
        // The runs the last process knew (their peers are gone).
        const uint32_t f = m_s.frontier_height();
        for (const uint32_t b : m_s.load_runs())
            if (b < f && (m_runs.empty() || b > m_runs.back().first))
                m_runs.emplace_back(b, std::string());
    }

    /// A getheaders to send: to `peer` (asked again), or to `peers` new
    /// peers picked round robin from `peer_idx` (pick()) when it is empty.
    struct Ask {
        std::vector<uint256> locator;
        size_t               peer_idx{0};
        std::string          peer;
        size_t               peers{1};
    };

    /// Who to ask now: nothing while the turn is within its time or the
    /// schedule is complete; new peers (after a stall) otherwise.
    std::optional<Ask> due(Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_s.complete())
            return std::nullopt;
        if (m_progress_at == Clock::time_point{})
            m_progress_at = now;  // the clock starts with the sync
        note_progress_locked(now);
        size_t peers = 1;
        if (!m_peer.empty()) {
            const auto since = std::max(m_progress_at, m_asked_at);
            if (now - since < STALL)
                return std::nullopt;
            ++m_stalls;
            if (m_turn_answered && m_s.frontier_height() == m_height_when_asked)
                ++m_fruitless;  // a peer answered the locator, and not with the continuation
            LOG_INFO << "[EMB-DOGE] Hash schedule at h=" << m_s.frontier_height() << "/"
                     << m_s.checkpoint_height() << ": no progress from " << m_peer << " in "
                     << std::chrono::duration_cast<std::chrono::seconds>(now - since).count()
                     << "s; asking other peers";
            const uint32_t run_len = m_s.frontier_height() - (m_runs.empty() ? 0 : m_runs.back().first);
            const bool stalled = m_fruitless >= FRUITLESS_AFTER && now - m_progress_at >= TRUNCATE_AFTER;
            const bool proven = run_len <= MAX_UNPROVEN_CUT || m_votes.size() >= VOTES_TO_CUT;
            if (stalled && !proven) {
                if (!m_unproven_logged) {
                    m_unproven_logged = true;
                    LOG_INFO << "[EMB-DOGE] Hash schedule: no progress at h=" << m_s.frontier_height()
                             << ", but the top run is " << run_len << " headers and " << m_votes.size()
                             << " peer(s) showed another chain: not cut";
                }
            } else if (stalled) {
                LOG_WARNING << "[EMB-DOGE] Hash schedule: " << m_fruitless
                            << " turns answered without continuing the frontier at h="
                            << m_s.frontier_height() << ", "
                            << std::chrono::duration_cast<std::chrono::minutes>(now - m_progress_at).count()
                            << " min without progress";
                cut_top_run_locked(now);
            }
            m_peer.clear();
            m_rr += HEDGE;
            peers = HEDGE;
        }
        return Ask{ask_locator_locked(), m_rr, std::string(), peers};
    }

    /// The sequential sync never cuts below `h` (the anchored prefix it
    /// continues, as the anchored ranges' fallback).
    void set_floor(uint32_t h)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_floor = h;
    }

    /// The peers to ask for `a` among `ready` (the connected peers): `a.peers`
    /// distinct ones round robin from `a.peer_idx`, never a cut peer.
    std::vector<std::string> pick(const std::vector<std::string>& ready, const Ask& a) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        std::vector<std::string> out;
        for (size_t i = 0; i < ready.size() && out.size() < a.peers; ++i) {
            const std::string& p = ready[(a.peer_idx + i) % ready.size()];
            if (!m_cut.count(p))
                out.push_back(p);
        }
        return out;
    }

    /// The getheaders went to `peer` ("" = none was ready: asked again at
    /// the next due()). `hedge`: a second peer asked in the same turn.
    void asked(const std::string& peer, Clock::time_point now, bool hedge = false)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (peer.empty()) {
            if (!hedge)
                m_peer.clear();
            return;
        }
        expire_asks_locked(now);
        auto& a = m_asks[peer];
        ++a.outstanding;
        a.at = now;
        if (!hedge && peer != m_peer)
            start_turn_locked(peer, now);
    }

    /// A headers batch from `peer`: fed when `peer` has an outstanding ask
    /// and it continues the frontier; otherwise NotNext (the caller hands it
    /// to the header chain). `ask_next`: ask that peer for the next batch
    /// now (after an extension), or new peers (after a bad batch).
    /// `truncated_at`: the message did not parse past that entry, `headers`
    /// are the ones before it (they link): Truncated, a strike, never a cut.
    HashSchedule::Feed on_headers(const std::string& peer,
                                  const std::vector<ltc::coin::BlockHeaderType>& headers,
                                  Clock::time_point now, std::optional<Ask>& ask_next,
                                  std::optional<size_t> truncated_at = std::nullopt)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        ask_next.reset();
        if (m_s.complete())
            return HashSchedule::Feed::Done;
        auto ask = m_asks.find(peer);
        if (peer.empty() || ask == m_asks.end() || now - ask->second.at > ASK_TTL || m_cut.count(peer))
            return HashSchedule::Feed::NotNext;  // not an answer to us
        if (truncated_at)
            return truncated_locked(peer, ask, headers, *truncated_at, now, ask_next);
        const uint32_t before_h = m_s.frontier_height();
        const auto r = m_s.feed(headers);
        switch (r) {
        case HashSchedule::Feed::Extended:
            answered_locked(ask);
            run_extended_locked(before_h, peer);
            if (peer != m_peer)
                start_turn_locked(peer, now);
            note_progress_locked(now);
            ask_next = Ask{ask_locator_locked(), m_rr, m_peer, 1};
            break;
        case HashSchedule::Feed::Complete:
            m_asks.clear();
            break;
        case HashSchedule::Feed::Broken:
        case HashSchedule::Feed::Rejected: {
            // This peer's chain is not the checkpoint's: what it stored and
            // nobody continued goes, it is not asked again, others are now.
            answered_locked(ask);
            const bool cut = !m_runs.empty() && m_runs.back().second == peer;
            if (cut)
                cut_top_run_locked(now);
            mark_cut_locked(peer);
            if (peer == m_peer) {
                m_peer.clear();
                m_rr += HEDGE;
            }
            if (cut || m_peer.empty())
                ask_next = Ask{ask_locator_locked(), m_rr, std::string(), 1};
            break;
        }
        case HashSchedule::Feed::NotNext:
            // An answer to the schedule's getheaders starts at a locator
            // entry: it is this turn's answer, and it did not continue the
            // frontier. The header chain's traffic (above the checkpoint)
            // is no answer; the ask stays outstanding.
            if (!headers.empty()) {
                if (const auto at = answer_start_locked(headers.front().m_previous_block)) {
                    if (ask->second.at >= m_asked_at && !m_peer.empty())
                        m_turn_answered = true;
                    answered_locked(ask);
                    // Evidence for a cut, never a cut by itself: one is
                    // made only after the stall (due()).
                    if (shows_another_chain_locked(*at, headers) && m_votes.insert(peer).second
                        && m_votes.size() == VOTES_TO_CUT)
                        LOG_WARNING << "[EMB-DOGE] Hash schedule: " << m_votes.size()
                                    << " peers answered with another chain above h="
                                    << (m_runs.empty() ? 0 : m_runs.back().first)
                                    << "; the run is cut if it does not move for "
                                    << std::chrono::duration_cast<std::chrono::minutes>(TRUNCATE_AFTER).count()
                                    << " min";
                }
            }
            break;
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
    size_t cut_peers() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_cut.size();
    }
    uint64_t bad_parses() const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_bad_parses;
    }

private:
    static constexpr size_t MAX_RUNS = 4096;
    static constexpr size_t MAX_ASKS = 256;
    static constexpr size_t MAX_CUT = 4096;

    struct Asked {
        uint32_t          outstanding{0};
        Clock::time_point at{};  // the last ask
    };
    using AskMap = std::map<std::string, Asked>;

    void answered_locked(AskMap::iterator it)
    {
        if (it->second.outstanding > 1)
            --it->second.outstanding;
        else
            m_asks.erase(it);
    }

    /// The frontier moved from `before_h` on `peer`'s batch: a new top run
    /// unless it is that peer's already.
    void run_extended_locked(uint32_t before_h, const std::string& peer)
    {
        if (!m_runs.empty() && m_runs.back().second == peer)
            return;
        if (m_runs.size() >= MAX_RUNS)
            m_runs.erase(m_runs.begin());  // the deepest base is forgotten: genesis then
        m_runs.emplace_back(before_h, peer);
        m_votes.clear();
        m_unproven_logged = false;
        save_runs_locked();
    }

    /// `peer`'s answer did not parse past entry `at`; `headers` are the ones
    /// before it. What continues the frontier is stored (a run of that peer,
    /// as any extension); the ask is answered and the turn goes to another
    /// peer, since the same peer sends the same bytes again. Nothing is cut
    /// and the peer is not marked: this side could not read its answer,
    /// which says nothing about the chain it is on.
    HashSchedule::Feed truncated_locked(const std::string& peer, AskMap::iterator ask,
                                        const std::vector<ltc::coin::BlockHeaderType>& headers, size_t at,
                                        Clock::time_point now, std::optional<Ask>& ask_next)
    {
        const uint32_t before_h = m_s.frontier_height();
        const auto r = headers.empty() ? HashSchedule::Feed::NotNext : m_s.feed(headers);
        answered_locked(ask);
        if (r == HashSchedule::Feed::Complete) {
            m_asks.clear();
            return r;
        }
        if (r == HashSchedule::Feed::Extended) {
            run_extended_locked(before_h, peer);
            note_progress_locked(now);
        }
        ++m_bad_parses;
        LOG_WARNING << "[EMB-DOGE] Hash schedule: the batch from " << peer << " does not parse past entry " << at
                    << " (the " << headers.size() << " before it: " << HashSchedule::feed_name(r)
                    << "): a strike, not another chain; asking another peer";
        if (peer == m_peer) {
            m_peer.clear();
            m_rr += HEDGE;
        }
        ask_next = Ask{ask_locator_locked(), m_rr, std::string(), 1};
        return HashSchedule::Feed::Truncated;
    }

    void expire_asks_locked(Clock::time_point now)
    {
        for (auto it = m_asks.begin(); it != m_asks.end();)
            it = now - it->second.at > ASK_TTL ? m_asks.erase(it) : std::next(it);
        while (m_asks.size() >= MAX_ASKS) {
            auto oldest = m_asks.begin();
            for (auto it = m_asks.begin(); it != m_asks.end(); ++it)
                if (it->second.at < oldest->second.at)
                    oldest = it;
            m_asks.erase(oldest);
        }
    }

    void mark_cut_locked(const std::string& peer)
    {
        if (peer.empty())
            return;
        if (m_cut.size() >= MAX_CUT)
            m_cut.clear();
        m_cut.insert(peer);
        m_asks.erase(peer);
    }

    /// The locator asked: the schedule's, with the top run's base inserted
    /// (by height): a peer without the run answers from its base, so its
    /// answer covers the run's first height and shows whether it is on the
    /// same chain; a peer with the run continues it.
    std::vector<uint256> ask_locator_locked() const
    {
        auto entries = m_s.locator_entries();
        if (!m_runs.empty() && m_runs.back().first > 0) {
            const uint32_t base = m_runs.back().first;
            const uint256 bh = m_s.stored_hash(base);
            if (!bh.IsNull()) {
                auto it = entries.begin();
                while (it != entries.end() && it->first > base)
                    ++it;
                if (it == entries.end() || it->first != base)
                    entries.insert(it, {base, bh});
            }
        }
        std::vector<uint256> out;
        out.reserve(entries.size());
        for (const auto& e : entries)
            out.push_back(e.second);
        return out;
    }

    /// The height of the locator entry an answer starts at (the base of the
    /// top run included).
    std::optional<uint32_t> answer_start_locked(const uint256& prev) const
    {
        if (!m_runs.empty() && m_runs.back().first > 0 && prev == m_s.stored_hash(m_runs.back().first))
            return m_runs.back().first;
        return m_s.locator_height(prev);
    }

    /// An answer from the locator entry at height `at` that carries, at a
    /// height inside the top run, another header than the stored one.
    bool shows_another_chain_locked(uint32_t at, const std::vector<ltc::coin::BlockHeaderType>& headers) const
    {
        if (m_runs.empty())
            return false;
        const uint32_t base = m_runs.back().first, f = m_s.frontier_height();
        for (size_t k = 0; k < headers.size(); ++k) {
            const uint32_t h = at + 1 + static_cast<uint32_t>(k);
            if (h <= base)
                continue;
            if (h > f)
                return false;
            return Hash(pack(headers[k]).get_span()) != m_s.stored_hash(h);
        }
        return false;
    }

    void start_turn_locked(const std::string& peer, Clock::time_point now)
    {
        m_peer = peer;
        m_asked_at = now;
        m_height_when_asked = m_s.frontier_height();
        m_turn_answered = false;
    }

    /// The top run goes: back to its base (genesis without one); its peer
    /// is not fed again.
    void cut_top_run_locked(Clock::time_point now)
    {
        const uint32_t f = m_s.frontier_height();
        while (!m_runs.empty() && m_runs.back().first >= f)
            m_runs.pop_back();  // runs a reset or an earlier cut already undid
        uint32_t to = 0;
        if (!m_runs.empty()) {
            to = m_runs.back().first;
            mark_cut_locked(m_runs.back().second);
            m_runs.pop_back();
        }
        m_votes.clear();
        m_unproven_logged = false;
        if (to < m_floor)
            to = m_floor;
        if (to >= f) {
            m_fruitless = 0;
            m_progress_at = now;
            return;  // nothing above the floor to cut
        }
        LOG_WARNING << "[EMB-DOGE] Hash schedule: the frontier at h=" << f << " is cut back to h=" << to
                    << (to == 0 ? " (genesis: no earlier run known)" : " (the top run's base)");
        m_s.truncate(to);
        ++m_truncations;
        m_fruitless = 0;
        const uint32_t h = m_s.frontier_height();
        while (!m_runs.empty() && m_runs.back().first >= h)
            m_runs.pop_back();
        save_runs_locked();
        m_progress_height = h;
        m_progress_at = now;
        m_height_when_asked = std::min(m_height_when_asked, h);
    }

    void save_runs_locked()
    {
        std::vector<uint32_t> bases;
        bases.reserve(m_runs.size());
        for (const auto& r : m_runs)
            bases.push_back(r.first);
        if (!m_s.save_runs(bases))
            LOG_WARNING << "[EMB-DOGE] Hash schedule: the run bases could not be written";
    }

    void note_progress_locked(Clock::time_point now)
    {
        const uint32_t h = m_s.frontier_height();
        if (h > m_progress_height) {
            m_progress_height = h;
            m_progress_at = now;
            m_fruitless = 0;
            m_votes.clear();  // evidence counts only from the stall it explains
        } else if (h < m_progress_height) {
            m_progress_height = h;  // cut back
        }
    }

    HashSchedule&     m_s;
    mutable std::mutex m_mu;
    std::string       m_peer;             // the turn's peer ("" = none)
    size_t            m_rr{0};
    Clock::time_point m_asked_at{};       // the turn began
    Clock::time_point m_progress_at{};
    uint32_t          m_progress_height{0};
    uint32_t          m_height_when_asked{0};
    bool              m_turn_answered{false};  // a peer asked this turn answered the locator
    uint32_t          m_fruitless{0};     // such turns in a row without progress
    uint64_t          m_stalls{0};
    uint64_t          m_truncations{0};
    uint64_t          m_bad_parses{0};    // answers that did not parse to their end (strikes)
    AskMap            m_asks;             // peers with an outstanding getheaders
    std::set<std::string> m_cut;          // never fed nor asked again
    std::set<std::string> m_votes;        // peers that showed another chain inside the top run
    bool              m_unproven_logged{false};
    uint32_t          m_floor{0};         // never cut below (the anchored prefix)
    std::vector<std::pair<uint32_t, std::string>> m_runs;  // (base height, peer), deepest first
};

} // namespace coin
} // namespace doge
