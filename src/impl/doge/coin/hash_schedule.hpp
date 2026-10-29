// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the best chain's block hash at every height below the
/// header chain's checkpoint.
///
/// The DOGE header chain is rooted at a fast-start checkpoint (mainnet
/// 6,160,000): it holds no header below it, so no body below it can be
/// asked for. A UTXO set built from genesis needs every one of them. The
/// schedule is built once from `headers` messages (getheaders from genesis),
/// keeping only each height's hash and dropping the header and its AuxPoW;
/// it is not added to HeaderChain (6.16 M resident index entries would cost
/// ~1.5 GB of RAM). It lives in a LevelDB (the header chain's) under
///   'H' + height (4 bytes BE) -> block hash (32 bytes)
///   'H'                       -> state (below)
/// with a small read cache.
///
/// Proof: the schedule is served only once its hash chain links, by the
/// parent hash of every header, from genesis into the configured checkpoint
/// hash at the checkpoint height. The checkpoint commits to the whole prefix
/// (a hash chain is the commitment), so scrypt and AuxPoW are not checked
/// below it. A chain that breaks or reaches the checkpoint height with
/// another hash is discarded (re-synced from another peer). The body stream
/// proves the links again: a body whose parent is not the UTXO set's best
/// block is refused at the connect point (ParentMismatch).
///
/// Thread safety: every public method takes the internal mutex.

#include <impl/ltc/coin/block.hpp>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
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
        NotNext,   // the batch does not continue the schedule (another request's answer): ignored
        Broken,    // a header does not link to the one before it: the schedule is discarded
        Rejected,  // the checkpoint height carries another hash: the schedule is discarded
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

    /// Read the persisted state. A state for another checkpoint or genesis
    /// starts over at genesis.
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
    /// A peer that does not have the frontier answers from the deepest of
    /// these it has; feed() then continues from that height.
    std::vector<uint256> locator()
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_locator.clear();
        std::vector<uint256> out;
        uint32_t step = 1;
        int64_t h = m_frontier_height;
        while (h > 0) {
            const uint32_t hh = static_cast<uint32_t>(h);
            const uint256 x = hh == m_frontier_height ? m_frontier_hash : stored_locked(hh);
            if (!x.IsNull()) {
                out.push_back(x);
                m_locator[x] = hh;
            }
            if (out.size() > 10)
                step *= 2;
            h -= step;
        }
        out.push_back(m_genesis);
        m_locator[m_genesis] = 0;
        return out;
    }

    /// Append a `headers` batch. It must continue the frontier (or a
    /// height of the last locator()); every header must link to the one
    /// before it. The header at the checkpoint height must hash to the
    /// checkpoint: then the schedule is complete. Anything else discards
    /// the schedule back to genesis.
    Feed feed(const std::vector<ltc::coin::BlockHeaderType>& headers)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_complete)
            return Feed::Done;
        if (headers.empty())
            return Feed::NotNext;
        uint32_t h = m_frontier_height;
        uint256 prev = m_frontier_hash;
        if (headers.front().m_previous_block != prev) {
            auto it = m_locator.find(headers.front().m_previous_block);
            if (it == m_locator.end())
                return Feed::NotNext;
            h = it->second;
            prev = it->first;
        }
        auto batch = m_db.create_batch();
        for (const auto& hdr : headers) {
            if (hdr.m_previous_block != prev) {
                LOG_WARNING << "[EMB-DOGE] Hash schedule: header at h=" << h + 1
                            << " does not link to h=" << h << ": discarded";
                reset_locked();
                return Feed::Broken;
            }
            ++h;
            const uint256 hh = Hash(pack(hdr).get_span());
            if (h == m_cp_height) {
                if (hh != m_cp_hash) {
                    LOG_WARNING << "[EMB-DOGE] Hash schedule: h=" << h << " is " << hh.GetHex().substr(0, 16)
                                << ", the checkpoint is " << m_cp_hash.GetHex().substr(0, 16) << ": discarded";
                    reset_locked();
                    return Feed::Rejected;
                }
                m_frontier_height = h;
                m_frontier_hash = hh;
                m_complete = true;
                batch.put(state_key(), state_locked());
                if (!batch.commit()) {
                    m_complete = false;
                    reset_locked();
                    return Feed::Broken;
                }
                m_locator.clear();
                LOG_INFO << "[EMB-DOGE] Hash schedule complete: heights 0.." << m_cp_height
                         << " link into the checkpoint " << m_cp_hash.GetHex().substr(0, 16);
                return Feed::Complete;
            }
            batch.put(height_key(h), std::vector<uint8_t>(hh.data(), hh.data() + 32));
            prev = hh;
        }
        const uint32_t old_height = m_frontier_height;
        const uint256 old_hash = m_frontier_hash;
        m_frontier_height = h;
        m_frontier_hash = prev;
        batch.put(state_key(), state_locked());
        if (!batch.commit()) {
            m_frontier_height = old_height;
            m_frontier_hash = old_hash;
            return Feed::NotNext;
        }
        // Heights at or below a rewind point may be cached from before.
        m_cache.clear();
        return Feed::Extended;
    }

    /// Drop the schedule back to genesis (stored hashes above the frontier
    /// are rewritten by the next sync before anything reads them).
    void discard()
    {
        std::lock_guard<std::mutex> lock(m_mu);
        reset_locked();
    }

private:
    static constexpr uint8_t  STATE_VERSION = 1;
    static constexpr size_t   STATE_SIZE = 1 + 32 + 4 + 32 + 4 + 32 + 1;
    static constexpr uint32_t CHUNK_BITS = 16;          // 65,536 heights (2 MB) per cache chunk
    static constexpr uint32_t CHUNK_MASK = (1u << CHUNK_BITS) - 1;
    static constexpr size_t   CACHE_CHUNKS = 2;

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

    void reset_locked()
    {
        m_frontier_height = 0;
        m_frontier_hash = m_genesis;
        m_complete = false;
        m_cache.clear();
        m_locator.clear();
        m_db.put(state_key(), state_locked());
    }

    uint256 stored_locked(uint32_t h) const
    {
        if (h == 0)
            return m_genesis;
        std::vector<uint8_t> v;
        if (!m_db.get(height_key(h), v) || v.size() != 32)
            return uint256();
        uint256 x;
        std::memcpy(x.data(), v.data(), 32);
        return x;
    }

    std::map<uint32_t, std::vector<uint256>>::iterator load_chunk_locked(uint32_t chunk) const
    {
        std::vector<uint256> hashes(size_t(1) << CHUNK_BITS);
        const std::string prefix = height_key(chunk << CHUNK_BITS).substr(0, 3);
        const bool ok = m_db.for_each_prefix(prefix, [&](const std::string& k, const std::vector<uint8_t>& v) {
            if (k.size() == 5 && v.size() == 32) {
                const uint32_t h = (uint32_t(uint8_t(k[1])) << 24) | (uint32_t(uint8_t(k[2])) << 16)
                                 | (uint32_t(uint8_t(k[3])) << 8) | uint32_t(uint8_t(k[4]));
                std::memcpy(hashes[h & CHUNK_MASK].data(), v.data(), 32);
            }
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
    std::map<uint256, uint32_t> m_locator;  // hashes of the last locator() and their heights
    mutable std::map<uint32_t, std::vector<uint256>> m_cache;  // chunk -> 65,536 hashes
};

} // namespace coin
} // namespace doge
