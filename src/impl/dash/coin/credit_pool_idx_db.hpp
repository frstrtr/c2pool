// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Variant B — persistent CreditPool INDEX state (the sister lane's disk half).
///
/// A NEW namespace, SEPARATE from the existing CreditPoolDb (which stays
/// untouched at its single-'B'-key 45-byte encode_state, credit_pool_db.hpp:
/// 99-115, so flag-OFF disk state is bit-identical). Records, all values
/// little-endian, batch-written atomically ONLY after a clean apply (the MN
/// lane's note_persist doctrine: persisted == delivered + folded):
///
///   key 'R'              — the CRangesSet equivalent:
///                          [1B schema_ver=1][varint n_ranges]
///                          [n × (8B u64 start LE, 8B u64 end_exclusive LE)]
///                          ranges sorted, disjoint, non-adjacent — the
///                          canonical compact form of every mined unlock index
///                          since the v20 floor.
///   key 'w' + [4B height]— per-block window rows (key height BIG-endian so a
///                          prefix scan walks ascending heights):
///                          [8B int64 gross_unlocked LE][4B u32 n_type9 LE]
///                          for each of the last (window+1)=577 heights;
///                          rows below cursor−577 pruned in the same batch.
///   key 'C'              — cursor / attestation:
///                          [1B schema_ver=1][4B height LE][32B block_hash]
///                          [8B int64 computed_balance LE][1B proven_complete]
///                          [1B era (0=pre-v22, 1=v22, 2=v24)]
///                          computed_balance MUST equal the cbTx
///                          creditPoolBalance of block_hash at write time.
///   key 'S'              — seed provenance:
///                          [4B v20_floor_height LE][32B v20_block_hash]
///                          [8B seed_wallclock LE]
///                          so a later reader can verify the lineage really
///                          starts at the trustless floor.
///
/// LOAD ADJUDICATION (try_restore doctrine, mn_checkpoint_lane.hpp:1365-1394):
/// ANY decode failure, a missing 'C'/'S'/'R' while any sibling is present, or
/// a malformed range list ⇒ the WHOLE namespace is treated as absent: load()
/// reports no state and the caller wipes + re-seeds from the v20 floor. The
/// deeper checks that need chain context (hash lineage against the header
/// spine, missing 'w' row inside the window, balance == cbTx) live in the
/// follower (credit_pool_idx.hpp), which also fails to a wipe.

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

struct CpIdxCursor {
    uint32_t height{0};
    uint256  block_hash;
    int64_t  computed_balance{0};
    bool     proven_complete{false};
    uint8_t  era{0};
};

struct CpIdxSeedProvenance {
    uint32_t v20_floor_height{0};
    uint256  v20_block_hash;
    int64_t  seed_wallclock{0};
};

struct CpIdxWindowRowRec {
    int64_t  gross_unlocked{0};
    uint32_t n_type9{0};
};

class CreditPoolIdxDb
{
public:
    static constexpr uint8_t kSchemaVer = 1;

    explicit CreditPoolIdxDb(const std::string& db_path,
                             const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()   { return m_store.open(); }
    void close()  { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    /// Load the whole namespace. Returns true when a COMPLETE, well-formed
    /// state was present (out params filled); false when the namespace is
    /// absent OR any record fails to decode — in which case the caller must
    /// treat persisted state as nonexistent (wipe + reseed from the floor).
    /// A false return with `corrupt=true` means records existed but did not
    /// adjudicate; the caller should wipe() before re-seeding.
    bool load(std::vector<std::pair<uint64_t, uint64_t>>& ranges,
              std::map<uint32_t, CpIdxWindowRowRec>&      window_rows,
              CpIdxCursor&                                 cursor,
              CpIdxSeedProvenance&                         seed,
              bool&                                        corrupt)
    {
        corrupt = false;
        ranges.clear();
        window_rows.clear();

        std::vector<uint8_t> c_raw, s_raw, r_raw;
        const bool have_c = m_store.get(key_cursor(), c_raw);
        const bool have_s = m_store.get(key_seed(),   s_raw);
        const bool have_r = m_store.get(key_ranges(), r_raw);

        if (!have_c && !have_s && !have_r) return false;   // genuinely absent
        if (!(have_c && have_s && have_r)) {                // torn namespace
            LOG_WARNING << "[CP-IDX-DB] torn namespace (C=" << have_c
                        << " S=" << have_s << " R=" << have_r
                        << ") — adjudicating ABSENT (wipe + reseed)";
            corrupt = true;
            return false;
        }
        if (!decode_cursor(c_raw, cursor) || !decode_seed(s_raw, seed) ||
            !decode_ranges(r_raw, ranges)) {
            corrupt = true;
            return false;
        }

        bool rows_ok = true;
        const bool scan_ok = m_store.for_each_prefix(
            std::string(1, 'w'),
            [&](const std::string& key, const std::vector<uint8_t>& value) {
                if (key.size() != 5 || value.size() != 12) { rows_ok = false; return false; }
                const uint32_t h = (uint32_t(uint8_t(key[1])) << 24)
                                 | (uint32_t(uint8_t(key[2])) << 16)
                                 | (uint32_t(uint8_t(key[3])) <<  8)
                                 |  uint32_t(uint8_t(key[4]));
                CpIdxWindowRowRec row;
                uint64_t u = 0;
                for (int i = 0; i < 8; ++i) u |= uint64_t(value[i]) << (8 * i);
                row.gross_unlocked = static_cast<int64_t>(u);
                row.n_type9 = uint32_t(value[8]) | (uint32_t(value[9]) << 8)
                            | (uint32_t(value[10]) << 16) | (uint32_t(value[11]) << 24);
                window_rows[h] = row;
                return true;
            });
        if (!scan_ok || !rows_ok) {
            LOG_WARNING << "[CP-IDX-DB] window-row scan failed (scan_ok="
                        << scan_ok << ") — adjudicating ABSENT";
            corrupt = true;
            return false;
        }
        return true;
    }

    /// One clean apply, atomically: the full ranges snapshot, this height's
    /// window row, the cursor, and the pruning of rows that fell out of the
    /// window. Written ONLY after the fold + cross-check succeeded.
    bool write_apply(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                     uint32_t height, const CpIdxWindowRowRec& row,
                     const CpIdxCursor& cursor, uint32_t prune_below)
    {
        auto batch = m_store.create_batch();
        batch.put(key_ranges(), encode_ranges(ranges));
        batch.put(key_window(height), encode_row(row));
        batch.put(key_cursor(), encode_cursor(cursor));
        // Prune the single row that just slid out (rows leave one at a time on
        // a contiguous fold; a bounded loop covers restarts mid-prune).
        for (uint32_t h = prune_below >= 8 ? prune_below - 8 : 0; h < prune_below; ++h)
            batch.remove(key_window(h));
        if (!batch.commit()) {
            LOG_WARNING << "[CP-IDX-DB] write_apply batch commit failed h=" << height;
            return false;
        }
        return true;
    }

    bool write_seed(const CpIdxSeedProvenance& seed)
    {
        auto batch = m_store.create_batch();
        batch.put(key_seed(), encode_seed(seed));
        return batch.commit();
    }

    /// Rewrite just the cursor (proven_complete flips at seed-meets-tip and
    /// on fail-closed latching).
    bool write_cursor(const CpIdxCursor& cursor)
    {
        auto batch = m_store.create_batch();
        batch.put(key_cursor(), encode_cursor(cursor));
        return batch.commit();
    }

    /// Total loss of provenance: remove EVERY key of the namespace. The next
    /// state on disk after a wipe is a fresh floor seed or nothing.
    bool wipe()
    {
        std::vector<std::string> keys;
        // Bounded namespace: 'R','C','S' + 'w' rows (window-sized).
        m_store.for_each_prefix(std::string(1, 'w'),
            [&](const std::string& key, const std::vector<uint8_t>&) {
                keys.push_back(key);
                return true;
            });
        auto batch = m_store.create_batch();
        for (const auto& k : keys) batch.remove(k);
        batch.remove(key_ranges());
        batch.remove(key_cursor());
        batch.remove(key_seed());
        const bool ok = batch.commit();
        LOG_INFO << "[CP-IDX-DB] wiped (" << keys.size() << " window rows + R/C/S) ok=" << ok;
        return ok;
    }

    // ── wire codecs (exposed for the schema KAT) ────────────────────────────

    static std::vector<uint8_t>
    encode_ranges(const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
    {
        std::vector<uint8_t> out;
        out.push_back(kSchemaVer);
        put_varint(out, ranges.size());
        for (const auto& [b, e] : ranges) { put_u64(out, b); put_u64(out, e); }
        return out;
    }

    static bool decode_ranges(const std::vector<uint8_t>& in,
                              std::vector<std::pair<uint64_t, uint64_t>>& out)
    {
        out.clear();
        size_t pos = 0;
        uint8_t ver;
        if (!get_u8(in, pos, ver) || ver != kSchemaVer) return false;
        uint64_t n;
        if (!get_varint(in, pos, n)) return false;
        uint64_t prev_end = 0;
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t b, e;
            if (!get_u64(in, pos, b) || !get_u64(in, pos, e)) return false;
            // sorted, disjoint, NON-adjacent, non-empty — the canonical form.
            if (e <= b) return false;
            if (i > 0 && b <= prev_end) return false;
            prev_end = e;
            out.emplace_back(b, e);
        }
        return pos == in.size();
    }

    static std::vector<uint8_t> encode_cursor(const CpIdxCursor& c)
    {
        std::vector<uint8_t> out;
        out.push_back(kSchemaVer);
        put_u32(out, c.height);
        out.insert(out.end(), c.block_hash.data(), c.block_hash.data() + 32);
        put_u64(out, static_cast<uint64_t>(c.computed_balance));
        out.push_back(c.proven_complete ? 1 : 0);
        out.push_back(c.era);
        return out;
    }

    static bool decode_cursor(const std::vector<uint8_t>& in, CpIdxCursor& c)
    {
        if (in.size() != 1 + 4 + 32 + 8 + 1 + 1) return false;
        size_t pos = 0;
        uint8_t ver;
        if (!get_u8(in, pos, ver) || ver != kSchemaVer) return false;
        get_u32(in, pos, c.height);
        std::memcpy(c.block_hash.data(), in.data() + pos, 32); pos += 32;
        uint64_t u; get_u64(in, pos, u);
        c.computed_balance = static_cast<int64_t>(u);
        c.proven_complete  = in[pos++] != 0;
        c.era              = in[pos++];
        if (c.era > 2) return false;
        return true;
    }

    static std::vector<uint8_t> encode_seed(const CpIdxSeedProvenance& s)
    {
        std::vector<uint8_t> out;
        put_u32(out, s.v20_floor_height);
        out.insert(out.end(), s.v20_block_hash.data(), s.v20_block_hash.data() + 32);
        put_u64(out, static_cast<uint64_t>(s.seed_wallclock));
        return out;
    }

    static bool decode_seed(const std::vector<uint8_t>& in, CpIdxSeedProvenance& s)
    {
        if (in.size() != 4 + 32 + 8) return false;
        size_t pos = 0;
        get_u32(in, pos, s.v20_floor_height);
        std::memcpy(s.v20_block_hash.data(), in.data() + pos, 32); pos += 32;
        uint64_t u; get_u64(in, pos, u);
        s.seed_wallclock = static_cast<int64_t>(u);
        return true;
    }

    static std::vector<uint8_t> encode_row(const CpIdxWindowRowRec& r)
    {
        std::vector<uint8_t> out;
        put_u64(out, static_cast<uint64_t>(r.gross_unlocked));
        put_u32(out, r.n_type9);
        return out;
    }

    static std::string key_window(uint32_t height)
    {
        std::string k(5, '\0');
        k[0] = 'w';
        k[1] = static_cast<char>((height >> 24) & 0xFF);   // BIG-endian key:
        k[2] = static_cast<char>((height >> 16) & 0xFF);   // prefix scans walk
        k[3] = static_cast<char>((height >>  8) & 0xFF);   // ascending heights
        k[4] = static_cast<char>( height        & 0xFF);
        return k;
    }
    static std::string key_ranges() { return std::string(1, 'R'); }
    static std::string key_cursor() { return std::string(1, 'C'); }
    static std::string key_seed()   { return std::string(1, 'S'); }

private:
    ::core::LevelDBStore m_store;

    static void put_u8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }
    static void put_u32(std::vector<uint8_t>& v, uint32_t x)
    {
        for (int i = 0; i < 4; ++i) v.push_back(uint8_t((x >> (8 * i)) & 0xFF));
    }
    static void put_u64(std::vector<uint8_t>& v, uint64_t x)
    {
        for (int i = 0; i < 8; ++i) v.push_back(uint8_t((x >> (8 * i)) & 0xFF));
    }
    static void put_varint(std::vector<uint8_t>& v, uint64_t x)
    {
        // Bitcoin CompactSize (matches the 'varint n_ranges' schema note).
        if (x < 253) { v.push_back(uint8_t(x)); }
        else if (x <= 0xFFFF) { v.push_back(253); v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8)); }
        else if (x <= 0xFFFFFFFFull) { v.push_back(254); for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i))); }
        else { v.push_back(255); for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i))); }
    }
    static bool get_u8(const std::vector<uint8_t>& v, size_t& pos, uint8_t& x)
    {
        if (pos + 1 > v.size()) return false;
        x = v[pos++]; return true;
    }
    static bool get_u32(const std::vector<uint8_t>& v, size_t& pos, uint32_t& x)
    {
        if (pos + 4 > v.size()) return false;
        x = 0;
        for (int i = 0; i < 4; ++i) x |= uint32_t(v[pos + i]) << (8 * i);
        pos += 4; return true;
    }
    static bool get_u64(const std::vector<uint8_t>& v, size_t& pos, uint64_t& x)
    {
        if (pos + 8 > v.size()) return false;
        x = 0;
        for (int i = 0; i < 8; ++i) x |= uint64_t(v[pos + i]) << (8 * i);
        pos += 8; return true;
    }
    static bool get_varint(const std::vector<uint8_t>& v, size_t& pos, uint64_t& x)
    {
        uint8_t tag;
        if (!get_u8(v, pos, tag)) return false;
        if (tag < 253) { x = tag; return true; }
        int n = tag == 253 ? 2 : tag == 254 ? 4 : 8;
        if (pos + n > v.size()) return false;
        x = 0;
        for (int i = 0; i < n; ++i) x |= uint64_t(v[pos + i]) << (8 * i);
        pos += n; return true;
    }
};

} // namespace coin
} // namespace dash
