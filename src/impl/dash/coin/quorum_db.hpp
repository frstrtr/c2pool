#pragma once

/// QuorumDb: LevelDB-backed persistent store for QuorumManager state.
///
/// Sister of SMLDb — same pattern, same atomic-batch contract, same
/// path layout (`~/.c2pool/<coin>/quorum_db/`). Persists the active
/// LLMQ quorum set so a restart between two mnlistdiffs doesn't leave
/// QuorumManager empty (the next incremental diff would not refill it,
/// and ChainLock verify would return NO_POOL forever until something
/// triggered a cold-start).
///
/// Key schema:
///   'Q' + llmqType(1B) + quorumHash(32B)  →  serialized CFinalCommitment
///   'C' + idx(2B LE)                       →  pack(LatestCLSigEntry)
///   'B'                                    →  best_hash(32B) + best_height(4B LE)
///
/// The 'B' sentinel mirrors SMLDb's. main_dash compares the two on
/// startup; if they don't match, both stores are wiped and we cold-
/// start (a wipe-on-mismatch policy is simpler than reasoning about
/// partial-write recovery, and the cost is one ~400 KB diff).
///
/// Per-diff write cost: ~88 active quorums × ~350 B = ~30 KB rewrite,
/// + ~30 cl-sig entries × ~100 B = ~3 KB. LevelDB compaction handles
/// the churn. Same full-rewrite-each-diff strategy as SMLDb.

#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

class QuorumDb
{
public:
    explicit QuorumDb(const std::string& db_path,
                      const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[QUO-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const   { return m_best_hash; }
    uint32_t get_best_height() const { return m_best_height; }

    // Load persisted active set + cached cl_sigs into qm. Returns true
    // if state was warm-loaded; false on cold-start (no BEST sentinel
    // and no entries). Caller treats false as "needs cold-start
    // mnlistdiff(zero, tip)".
    bool load_into(QuorumManager& qm)
    {
        std::vector<QuorumManager::Entry> active;
        std::vector<QuorumManager::CLSig> cl_sigs;

        // ── Active set ('Q' keys) ───────────────────────────────────
        // Phase C-TEMPLATE step 4 schema: per-entry value is now
        // [4B LE mining_height] + pack(CFinalCommitment). Detect old
        // format (no mining_height prefix) by trying the new format
        // first; if commitment-parse fails, fall back to old format
        // (mining_height = 0). On next observed qfcommit, the
        // scanner repopulates correctly.
        auto qkeys = m_store.list_keys(std::string(1, 'Q'),
                                       /*limit=*/100000);
        active.reserve(qkeys.size());
        size_t bad = 0;
        for (const auto& key : qkeys) {
            if (key.size() != 34 || key[0] != 'Q') continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) { ++bad; continue; }
            uint32_t mining_height = 0;
            vendor::CFinalCommitment c;
            bool parsed = false;
            // Try new format: [4B mining_height] + commitment.
            if (data.size() >= 4) {
                try {
                    uint32_t mh = uint32_t(data[0])
                                | (uint32_t(data[1]) << 8)
                                | (uint32_t(data[2]) << 16)
                                | (uint32_t(data[3]) << 24);
                    std::vector<uint8_t> tail(data.begin() + 4, data.end());
                    ::PackStream s(tail);
                    vendor::CFinalCommitment cn;
                    s >> cn;
                    if (s.cursor_size() == 0) {
                        mining_height = mh;
                        c = std::move(cn);
                        parsed = true;
                    }
                } catch (...) {}
            }
            // Fall back to old format: pack(commitment) directly.
            if (!parsed) {
                try {
                    ::PackStream s(data);
                    s >> c;
                    parsed = true;
                    // mining_height stays 0 — qfcommit scanner will
                    // populate on next block observation.
                } catch (const std::exception& ex) {
                    ++bad;
                    LOG_WARNING << "[QUO-DB] commitment deserialize failed: "
                                << ex.what();
                    continue;
                }
            }
            QuorumManager::ActiveKey k{
                static_cast<uint8_t>(key[1]),
                {}};
            std::memcpy(k.quorumHash.data(),
                        key.data() + 2, 32);
            QuorumManager::Entry entry{k, std::move(c)};
            entry.mining_height = mining_height;
            active.push_back(std::move(entry));
        }

        // ── Cached cl_sigs ('C' keys, ordered by 2B LE index) ──────
        auto ckeys = m_store.list_keys(std::string(1, 'C'),
                                       /*limit=*/100000);
        // list_keys returns in lexicographic order; for a 2-byte LE
        // suffix that's NOT numeric order, so we sort by parsed index.
        std::vector<std::pair<uint16_t, std::string>> ordered;
        ordered.reserve(ckeys.size());
        for (auto& k : ckeys) {
            if (k.size() != 3) continue;
            uint16_t idx = uint16_t(uint8_t(k[1]))
                         | (uint16_t(uint8_t(k[2])) << 8);
            ordered.emplace_back(idx, std::move(k));
        }
        std::sort(ordered.begin(), ordered.end(),
            [](auto& a, auto& b) { return a.first < b.first; });
        cl_sigs.reserve(ordered.size());
        for (auto& [idx, key] : ordered) {
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) { ++bad; continue; }
            QuorumManager::CLSig entry{};
            if (!decode_cl_sig(data, entry)) { ++bad; continue; }
            cl_sigs.push_back(std::move(entry));
        }

        if (bad > 0) {
            LOG_WARNING << "[QUO-DB] " << bad
                        << " entries failed to load (skipped)";
        }

        bool warm = !active.empty() || !m_best_hash.IsNull();
        size_t n_active = active.size();
        size_t n_cl     = cl_sigs.size();
        qm.replace_state(std::move(active), std::move(cl_sigs));

        if (warm) {
            LOG_INFO << "[QUO-DB] loaded active=" << n_active
                     << " cl_sigs=" << n_cl
                     << " best_height=" << m_best_height;
        }
        return warm;
    }

    // Atomic full-rewrite: delete all 'Q' + 'C' keys, write new state,
    // update BEST. One LevelDB batch.
    bool write_state(const QuorumManager& qm,
                     const uint256& best_hash,
                     uint32_t best_height)
    {
        auto batch = m_store.create_batch();

        // Delete all existing 'Q' + 'C' keys.
        auto existing_q = m_store.list_keys(std::string(1, 'Q'),
                                            /*limit=*/100000);
        for (auto& k : existing_q) batch.remove(k);
        auto existing_c = m_store.list_keys(std::string(1, 'C'),
                                            /*limit=*/100000);
        for (auto& k : existing_c) batch.remove(k);

        // Insert active set. Phase C-TEMPLATE step 4 wire format:
        // [4B LE mining_height] + pack(CFinalCommitment). mining_height
        // = 0 means "not yet observed" (scanner-driven, populated on
        // first qfcommit tx observation).
        for (const auto& e : qm.active_entries()) {
            auto key = make_quorum_key(e.key.llmqType, e.key.quorumHash);
            auto stream = ::pack(e.commitment);
            auto sp = stream.get_span();
            std::vector<uint8_t> data;
            data.reserve(4 + sp.size());
            data.push_back(uint8_t( e.mining_height        & 0xFF));
            data.push_back(uint8_t((e.mining_height >>  8) & 0xFF));
            data.push_back(uint8_t((e.mining_height >> 16) & 0xFF));
            data.push_back(uint8_t((e.mining_height >> 24) & 0xFF));
            data.insert(data.end(),
                        reinterpret_cast<const uint8_t*>(sp.data()),
                        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
            batch.put(key, data);
        }

        // Insert cached cl_sigs (indexed by position, 2B LE suffix).
        const auto& cls = qm.latest_cl_sigs();
        for (uint16_t i = 0; i < cls.size(); ++i) {
            batch.put(make_clsig_key(i), encode_cl_sig(cls[i]));
        }

        // BEST sentinel.
        batch.put(make_state_key(), encode_best_state(best_hash, best_height));

        if (!batch.commit()) {
            LOG_WARNING << "[QUO-DB] write_state batch commit failed";
            return false;
        }
        m_best_hash = best_hash;
        m_best_height = best_height;
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        for (auto& k : m_store.list_keys(std::string(1, 'Q'), 100000))
            batch.remove(k);
        for (auto& k : m_store.list_keys(std::string(1, 'C'), 100000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash = uint256{};
        m_best_height = 0;
        LOG_INFO << "[QUO-DB] cleared (reorg, manual reset, or SMLDb mismatch)";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint32_t             m_best_height{0};

    static std::string make_quorum_key(uint8_t llmqType, const uint256& h)
    {
        std::string k;
        k.reserve(34);
        k.push_back('Q');
        k.push_back(static_cast<char>(llmqType));
        k.append(reinterpret_cast<const char*>(h.data()), 32);
        return k;
    }

    static std::string make_clsig_key(uint16_t idx)
    {
        std::string k;
        k.reserve(3);
        k.push_back('C');
        k.push_back(static_cast<char>( idx       & 0xFF));
        k.push_back(static_cast<char>((idx >> 8) & 0xFF));
        return k;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height)
    {
        std::vector<uint8_t> out(36);
        std::memcpy(out.data(), hash.data(), 32);
        out[32] = static_cast<uint8_t>( height        & 0xFF);
        out[33] = static_cast<uint8_t>((height >>  8) & 0xFF);
        out[34] = static_cast<uint8_t>((height >> 16) & 0xFF);
        out[35] = static_cast<uint8_t>((height >> 24) & 0xFF);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 36) {
            return;
        }
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = uint32_t(data[32])
                      | (uint32_t(data[33]) <<  8)
                      | (uint32_t(data[34]) << 16)
                      | (uint32_t(data[35]) << 24);
    }

    // CLSig wire layout (private, internal-only — not consensus):
    //   96 bytes BLS sig
    //   uint16 LE n_indices
    //   n_indices × uint16 LE
    static std::vector<uint8_t> encode_cl_sig(const QuorumManager::CLSig& e)
    {
        const auto& sig = e.first;
        const auto& idxs = e.second;
        std::vector<uint8_t> out;
        out.reserve(sig.size() + 2 + idxs.size() * 2);
        out.insert(out.end(), sig.begin(), sig.end());
        out.push_back(static_cast<uint8_t>( idxs.size()       & 0xFF));
        out.push_back(static_cast<uint8_t>((idxs.size() >> 8) & 0xFF));
        for (uint16_t v : idxs) {
            out.push_back(static_cast<uint8_t>( v       & 0xFF));
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        }
        return out;
    }

    static bool decode_cl_sig(const std::vector<uint8_t>& bytes,
                              QuorumManager::CLSig& out)
    {
        constexpr size_t SIG = vendor::CFinalCommitment::BLS_SIG_SIZE;
        if (bytes.size() < SIG + 2) return false;
        std::memcpy(out.first.data(), bytes.data(), SIG);
        uint16_t n = uint16_t(bytes[SIG])
                   | (uint16_t(bytes[SIG + 1]) << 8);
        if (bytes.size() != SIG + 2 + size_t(n) * 2) return false;
        out.second.clear();
        out.second.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            uint16_t v = uint16_t(bytes[SIG + 2 + i * 2])
                       | (uint16_t(bytes[SIG + 3 + i * 2]) << 8);
            out.second.push_back(v);
        }
        return true;
    }
};

} // namespace coin
} // namespace dash
