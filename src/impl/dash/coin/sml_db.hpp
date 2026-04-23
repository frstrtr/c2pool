#pragma once

/// SMLDb: LevelDB-backed persistent Simplified Masternode List store.
///
/// Phase C-SML step 5. Mirrors UTXOViewDB's pattern:
/// open at `~/.c2pool/<coin>/sml_db/`, atomic batch writes for crash-
/// safe diff application, sentinel "BEST" key for tip tracking.
///
/// Key schema:
///   'S' + proRegTxHash(32B)  →  serialized CSimplifiedMNListEntry
///   'B'                       →  best_hash(32B) + best_height(4B LE)
///
/// On startup: load_sml() walks all 'S' keys, deserializes each into a
/// CSimplifiedMNList, sorts. ~3700 entries × ~150 B ≈ 555 KB read +
/// deserialize on cold startup; well under a second.
///
/// On apply_diff: caller provides the post-apply CSimplifiedMNList +
/// new best block; write_sml() atomically REPLACES the persisted set.
/// We don't try to do per-entry incremental updates — the SML is small
/// enough that full rewrite is simpler than tracking which keys to
/// delete vs update vs insert. ~555 KB write per tip advance is
/// acceptable; LevelDB compaction handles the churn.
///
/// On reorg (drop-and-refetch): clear() wipes every 'S' key + the BEST
/// sentinel so the next mnlistdiff arrival starts from cold-state.

#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

class SMLDb
{
public:
    explicit SMLDb(const std::string& db_path,
                   const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[SML-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const   { return m_best_hash; }
    uint32_t get_best_height() const { return m_best_height; }

    // Load the persisted SML into `out`. Returns true if at least one
    // entry was found OR the BEST sentinel exists (warm restart with
    // empty SML is technically valid). On false, caller should treat
    // this as cold-start (no prior state).
    bool load_sml(vendor::CSimplifiedMNList& out)
    {
        out.mnList.clear();
        // Walk all keys with 'S' prefix.
        auto keys = m_store.list_keys(std::string(1, 'S'),
                                      /*limit=*/100000);
        out.mnList.reserve(keys.size());
        size_t bad = 0;
        for (const auto& key : keys) {
            if (key.size() != 33 || key[0] != 'S') continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) { ++bad; continue; }
            try {
                vendor::CSimplifiedMNListEntry e;
                ::PackStream s(data);
                s >> e;
                out.mnList.push_back(std::move(e));
            } catch (const std::exception& ex) {
                ++bad;
                LOG_WARNING << "[SML-DB] entry deserialize failed: "
                            << ex.what();
            }
        }
        out.sort();
        if (bad > 0) {
            LOG_WARNING << "[SML-DB] " << bad
                        << " entries failed to load (skipped)";
        }
        bool warm = !out.mnList.empty() || !m_best_hash.IsNull();
        if (warm) {
            LOG_INFO << "[SML-DB] loaded " << out.mnList.size()
                     << " entries best_height=" << m_best_height;
        }
        return warm;
    }

    // Atomic full-rewrite: delete all existing 'S' entries, write the
    // new set, update BEST sentinel. Single LevelDB batch.
    bool write_sml(const vendor::CSimplifiedMNList& sml,
                   const uint256& best_hash,
                   uint32_t best_height)
    {
        auto batch = m_store.create_batch();

        // Delete every existing 'S' key. list_keys() snapshots before
        // batch.remove() so this is safe.
        auto existing = m_store.list_keys(std::string(1, 'S'),
                                          /*limit=*/100000);
        for (const auto& k : existing) {
            batch.remove(k);
        }

        // Insert each entry from the new SML.
        for (const auto& e : sml.mnList) {
            auto key = make_entry_key(e.proRegTxHash);
            auto stream = ::pack(e);
            auto sp = stream.get_span();
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(sp.data()),
                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
            batch.put(key, data);
        }

        // BEST sentinel.
        batch.put(make_state_key(), encode_best_state(best_hash, best_height));

        if (!batch.commit()) {
            LOG_WARNING << "[SML-DB] write_sml batch commit failed";
            return false;
        }
        m_best_hash = best_hash;
        m_best_height = best_height;
        return true;
    }

    // Wipe everything: all 'S' entries + BEST sentinel. Used on reorg
    // (drop-and-refetch path). Caller follows up with cold-start
    // mnlistdiff request.
    bool clear()
    {
        auto batch = m_store.create_batch();
        auto existing = m_store.list_keys(std::string(1, 'S'),
                                          /*limit=*/100000);
        for (const auto& k : existing) batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash = uint256{};
        m_best_height = 0;
        LOG_INFO << "[SML-DB] cleared (reorg or manual reset)";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint32_t             m_best_height{0};

    static std::string make_entry_key(const uint256& proRegTxHash)
    {
        std::string k;
        k.reserve(33);
        k.push_back('S');
        k.append(reinterpret_cast<const char*>(proRegTxHash.data()), 32);
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
};

} // namespace coin
} // namespace dash
