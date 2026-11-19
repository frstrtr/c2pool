// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <optional>
#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

namespace c2pool {
namespace storage {

/// Persistent record for a found block (Layer +2 in THE terminology).
/// Never pruned — these represent actual blockchain economic events.
struct FoundBlockRecord {
    std::string chain;              // "LTC"/"tLTC"/"DOGE" etc
    uint64_t    height{0};          // parent chain block height
    std::string block_hash;         // parent chain block hash hex
    uint64_t    timestamp{0};       // when found (unix seconds)
    uint8_t     status{0};          // 0=pending, 1=confirmed, 2=orphaned, 3=stale
    uint8_t     check_count{0};     // verification attempts so far
    uint64_t    last_checked{0};    // timestamp of last verification
    uint32_t    confirmations{0};   // last known confirmation count
    std::string finder_address;     // miner who found the block (if known)
    uint64_t    reward_satoshis{0}; // coinbase reward amount (if known)
    uint256     the_state_root;     // THE commitment embedded in coinbase scriptSig
    // --- v2 dashboard-enrichment fields (issue #159) ---
    // Persisted from the in-memory FoundBlock so a restored row keeps its
    // difficulties, pool hashrate, winning-share hash and authorship instead of
    // decaying to a bare skeleton after a restart. Doubles are stored as their
    // IEEE-754 bit pattern (uint64) to match the existing little-endian memcpy
    // read path — no dependency on operator<< double serialization.
    double      network_difficulty{0.0}; // network difficulty at time of find
    double      share_difficulty{0.0};   // winning share difficulty
    double      pool_hashrate{0.0};      // pool hashrate at time of find
    std::string share_hash;              // hash of the share that found the block
    uint8_t     authorship{0};           // BlockAuthorship: 0=unknown, 1=peer, 2=this node
    // --- v3 explorer fields (issue #946) ---
    // Empty coinbase_txid / nullopt tx_count mean "not known yet" and render as
    // JSON null. tx_count stays unset on peer-found rows until the full block
    // arrives over P2P (v34+ shares carry no tx list), so 0 is never a stand-in.
    std::string             coinbase_txid;
    std::optional<uint32_t> tx_count;
    // --- v4 merged-parent fields (issue #946) ---
    // DOGE rows only: the LTC block id the aux solve was mined on and the LTC
    // height it was mined at. Empty / nullopt = unknown (JSON null), never 0.
    std::string             parent_hash;
    std::optional<uint64_t> parent_height;
    // --- v4 extension (no version bump, see serialize) ---
    // Merged (aux) rows: network_difficulty is the AUX chain's own, read off
    // the aux block's bits. A row written before this flag existed holds the
    // PARENT's difficulty there (#1738) and reads false: its difficulty is
    // not known. Meaningless on a parent-chain row.
    bool                    aux_difficulty_known{false};
    // The row came from an import of another node's history
    // (MiningInterface::import_found_blocks, --import-found-blocks), not from
    // this node's own observation. Same extension byte, no version bump: a
    // build that predates the bit reads the row and ignores it (it writes the
    // row back without the bit, which reads as "recorded" here).
    bool                    imported{false};
    // Another node's measured effort of the round that ends in this block
    // (--import-found-blocks; MiningInterface::FoundBlock::imported_effort):
    // the source row's effort, its history_coverage and the block it timed
    // the round from. 0 / "" = none. A TAIL after the extension byte, present
    // only when bit kExtImportedEffort says so -- again no version bump:
    // every earlier build stops reading at (or before) the extension byte, so
    // it keeps the row and ignores the tail; it writes the row back without
    // the tail and the bit, which reads as "no imported effort" here.
    double                  imported_effort{0.0};
    double                  imported_coverage{0.0};
    std::string             imported_prev_hash;

    // Bits of the extension byte that follows the v4 tail.
    static constexpr uint8_t kExtAuxDifficultyKnown = 0x01;
    static constexpr uint8_t kExtImported           = 0x02;
    static constexpr uint8_t kExtImportedEffort     = 0x04;   // the tail follows

    /// An imported effort a reader may use: positive and finite, a coverage
    /// in (0, 1], the block it was timed from.
    bool has_imported_effort() const
    {
        return imported_effort > 0.0 && std::isfinite(imported_effort)
            && imported_coverage > 0.0 && imported_coverage <= 1.0
            && !imported_prev_hash.empty();
    }

    // Serialize to bytes for LevelDB storage
    std::vector<uint8_t> serialize() const
    {
        PackStream ps;
        // Version byte. Each version appends a tail after the previous body; a
        // newer reader that meets an older record leaves the missing fields at
        // their defaults (read-compat). v2 = #159 enrichment, v3 = #946 explorer,
        // v4 = #946 merged parent.
        //
        // The byte after the v4 tail is an EXTENSION, deliberately without a
        // version bump: every reader refuses a version it does not know and
        // returns an empty record, so a v5 row would vanish from /recent_blocks
        // on a node rolled back to an earlier build. A v4 reader stops after
        // the v4 tail and never looks at what follows, so the row stays
        // readable there; that build writes the row back without the byte,
        // which reads as "not known" here.
        uint8_t version = 4;
        ps << version;
        // Chain as length-prefixed string
        uint8_t chain_len = static_cast<uint8_t>(std::min(chain.size(), size_t(255)));
        ps << chain_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(chain.data()), chain_len));
        ps << height;
        // block_hash as length-prefixed string
        uint8_t hash_len = static_cast<uint8_t>(std::min(block_hash.size(), size_t(255)));
        ps << hash_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(block_hash.data()), hash_len));
        ps << timestamp;
        ps << status;
        ps << check_count;
        ps << last_checked;
        ps << confirmations;
        // finder_address
        uint8_t addr_len = static_cast<uint8_t>(std::min(finder_address.size(), size_t(255)));
        ps << addr_len;
        if (addr_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(finder_address.data()), addr_len));
        ps << reward_satoshis;
        // --- v2 tail ---
        auto put_double = [&ps](double d) {
            uint64_t bits;
            std::memcpy(&bits, &d, sizeof(bits));
            ps << bits;
        };
        put_double(network_difficulty);
        put_double(share_difficulty);
        put_double(pool_hashrate);
        uint8_t sh_len = static_cast<uint8_t>(std::min(share_hash.size(), size_t(255)));
        ps << sh_len;
        if (sh_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(share_hash.data()), sh_len));
        ps << authorship;
        // --- v3 tail ---
        uint8_t cb_len = static_cast<uint8_t>(std::min(coinbase_txid.size(), size_t(255)));
        ps << cb_len;
        if (cb_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(coinbase_txid.data()), cb_len));
        uint8_t has_tx_count = tx_count.has_value() ? 1 : 0;
        ps << has_tx_count;
        ps << static_cast<uint32_t>(tx_count.value_or(0));
        // --- v4 tail ---
        uint8_t ph_len = static_cast<uint8_t>(std::min(parent_hash.size(), size_t(255)));
        ps << ph_len;
        if (ph_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(parent_hash.data()), ph_len));
        uint8_t has_parent_height = parent_height.has_value() ? 1 : 0;
        ps << has_parent_height;
        ps << static_cast<uint64_t>(parent_height.value_or(0));
        // --- v4 extension byte ---
        const bool effort_tail = has_imported_effort();
        uint8_t ext = (aux_difficulty_known ? kExtAuxDifficultyKnown : 0)
                    | (imported ? kExtImported : 0)
                    | (effort_tail ? kExtImportedEffort : 0);
        ps << ext;
        // --- imported-effort tail (only behind its bit: a row without an
        // imported effort is byte for byte what the earlier writer wrote) ---
        if (effort_tail) {
            put_double(imported_effort);
            put_double(imported_coverage);
            uint8_t ip_len = static_cast<uint8_t>(std::min(imported_prev_hash.size(), size_t(255)));
            ps << ip_len;
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(imported_prev_hash.data()), ip_len));
        }

        auto span = ps.get_span();
        return {reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size()};
    }

    // Deserialize from bytes
    static FoundBlockRecord deserialize(const std::vector<uint8_t>& data)
    {
        FoundBlockRecord rec;
        if (data.size() < 4) return rec;

        // A short read consumes the rest of the buffer and sets overrun, so the
        // leftover bytes of a cut field can never be read as the next field.
        size_t pos = 0;
        bool overrun = false;
        auto read_u8 = [&]() -> uint8_t {
            if (pos < data.size()) return data[pos++];
            overrun = true;
            return 0;
        };
        auto read_u32 = [&]() -> uint32_t {
            if (pos + 4 > data.size()) { pos = data.size(); overrun = true; return 0; }
            uint32_t v;
            std::memcpy(&v, &data[pos], 4);
            pos += 4;
            return v;
        };
        auto read_u64 = [&]() -> uint64_t {
            if (pos + 8 > data.size()) { pos = data.size(); overrun = true; return 0; }
            uint64_t v;
            std::memcpy(&v, &data[pos], 8);
            pos += 8;
            return v;
        };
        auto read_str = [&](uint8_t len) -> std::string {
            if (pos + len > data.size()) { pos = data.size(); overrun = true; return ""; }
            std::string s(reinterpret_cast<const char*>(&data[pos]), len);
            pos += len;
            return s;
        };

        uint8_t version = read_u8();
        if (version < 1 || version > 4) return rec; // unknown version

        uint8_t chain_len = read_u8();
        rec.chain = read_str(chain_len);
        rec.height = read_u64();
        uint8_t hash_len = read_u8();
        rec.block_hash = read_str(hash_len);
        rec.timestamp = read_u64();
        rec.status = read_u8();
        rec.check_count = read_u8();
        rec.last_checked = read_u64();
        rec.confirmations = read_u32();
        uint8_t addr_len = read_u8();
        rec.finder_address = read_str(addr_len);
        rec.reward_satoshis = read_u64();

        // Every writer since v1 writes the whole v1 body, so a cut inside it is
        // a damaged row: return an empty record (no block_hash), which load_all
        // and find_by_hash skip.
        if (overrun) return FoundBlockRecord{};

        // --- v2 enrichment tail (absent on v1 records) ---
        // Every read is bounds-checked (read_* return 0/"" past end), so a
        // truncated or partially-written v2 record degrades to defaults for the
        // missing fields rather than throwing — load stays crash-safe.
        if (version >= 2) {
            auto get_double = [&]() -> double {
                uint64_t bits = read_u64();
                double d;
                std::memcpy(&d, &bits, sizeof(d));
                return d;
            };
            rec.network_difficulty = get_double();
            rec.share_difficulty = get_double();
            rec.pool_hashrate = get_double();
            uint8_t sh_len = read_u8();
            rec.share_hash = read_str(sh_len);
            rec.authorship = read_u8();
        }

        // --- v3 explorer tail (absent on v1/v2 records) ---
        if (version >= 3) {
            uint8_t cb_len = read_u8();
            rec.coinbase_txid = read_str(cb_len);
            uint8_t has_tx_count = read_u8();
            // A truncated tail must not turn into a known tx_count of 0.
            bool whole = pos + 4 <= data.size();
            uint32_t n = read_u32();
            if (has_tx_count && whole) rec.tx_count = n;
        }

        // --- v4 merged-parent tail (absent on v1-v3 records) ---
        if (version >= 4) {
            uint8_t ph_len = read_u8();
            rec.parent_hash = read_str(ph_len);
            uint8_t has_parent_height = read_u8();
            // Same rule as tx_count: a cut tail stays unknown, never 0.
            bool whole = pos + 8 <= data.size();
            uint64_t ph = read_u64();
            if (has_parent_height && whole) rec.parent_height = ph;
            // --- v4 extension byte (absent on rows written before it) ---
            if (whole && pos < data.size()) {
                const uint8_t ext = read_u8();
                rec.aux_difficulty_known = (ext & kExtAuxDifficultyKnown) != 0;
                rec.imported = (ext & kExtImported) != 0;
                // --- the imported-effort tail, behind its bit. A cut or
                // malformed tail is no imported effort, never leftover bytes.
                if (ext & kExtImportedEffort) {
                    auto get_double = [&]() -> double {
                        uint64_t bits = read_u64();
                        double d;
                        std::memcpy(&d, &bits, sizeof(d));
                        return d;
                    };
                    const double effort = get_double();
                    const double coverage = get_double();
                    const uint8_t ip_len = read_u8();
                    std::string prev = read_str(ip_len);
                    FoundBlockRecord probe;
                    probe.imported_effort = effort;
                    probe.imported_coverage = coverage;
                    probe.imported_prev_hash = std::move(prev);
                    if (!overrun && probe.has_imported_effort()) {
                        rec.imported_effort = probe.imported_effort;
                        rec.imported_coverage = probe.imported_coverage;
                        rec.imported_prev_hash = std::move(probe.imported_prev_hash);
                    }
                }
            }
        }

        return rec;
    }
};

/// LevelDB-backed persistent store for found blocks.
/// Uses key prefix "fblk:" to share the same LevelDB instance as shares.
/// Never pruned — found blocks are permanent Layer +2 records.
class FoundBlockStore {
public:
    explicit FoundBlockStore(core::LevelDBStore& store) : m_store(store) {}

    /// Store a found block record.
    ///
    /// The key carries the height, and a block's height can be learned after
    /// the row was first stored: a stale-job block recorded at height 0 is
    /// given its real height later (MiningInterface learns it from the
    /// sharechain or the header chain). Height only ever moves out of 0, so
    /// storing a row at a real height drops the height-0 record of the same
    /// block -- otherwise the old key, which lists first, would be loaded
    /// again on the next start. Written first, removed second: a crash in
    /// between leaves both, which the load path resolves to the real height.
    ///
    /// A height that is CORRECTED (MiningInterface's correction of a pre-fix
    /// LTC peer row stored at the share absheight, 27707625 for block 3211872)
    /// names the key it moves from: `replaced_height`, from
    /// FoundBlock::replaced_height. The record at that key is dropped too, so
    /// the old height is not loaded again. O(1): no key scan on the record
    /// path (in embedded mode it runs before the block relay).
    bool store(const FoundBlockRecord& rec, uint64_t replaced_height = 0)
    {
        auto key = make_key(rec.chain, rec.height, rec.block_hash);
        auto data = rec.serialize();
        if (!m_store.put(key, data))
            return false;
        if (rec.height != 0) {
            drop_other_key(rec, 0);
            if (replaced_height != 0 && replaced_height != rec.height)
                drop_other_key(rec, replaced_height);
        }
        return true;
    }

    /// Update status of an existing record
    bool update_status(const std::string& chain, uint64_t height,
                       const std::string& block_hash,
                       uint8_t new_status, uint8_t check_count,
                       uint32_t confirmations)
    {
        auto key = make_key(chain, height, block_hash);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;

        auto rec = FoundBlockRecord::deserialize(data);
        if (rec.block_hash.empty())
            return false; // damaged row; don't overwrite it with an empty one
        rec.status = new_status;
        rec.check_count = check_count;
        rec.confirmations = confirmations;
        rec.last_checked = static_cast<uint64_t>(std::time(nullptr));

        return m_store.put(key, rec.serialize());
    }

    /// Load all found blocks (newest first by height)
    std::vector<FoundBlockRecord> load_all()
    {
        std::vector<FoundBlockRecord> result;

        // Scan all keys with "fblk:" prefix
        auto keys = m_store.list_keys("fblk:", 10000);
        for (const auto& key : keys)
        {
            std::vector<uint8_t> data;
            if (m_store.get(key, data))
            {
                auto rec = FoundBlockRecord::deserialize(data);
                if (!rec.block_hash.empty())
                    result.push_back(std::move(rec));
            }
        }

        // Sort newest first
        std::sort(result.begin(), result.end(),
            [](const FoundBlockRecord& a, const FoundBlockRecord& b) {
                return a.timestamp > b.timestamp;
            });

        return result;
    }

    /// Count stored found blocks
    size_t count()
    {
        return m_store.list_keys("fblk:", 10000).size();
    }

    /// Look a record up by its FULL block hash (#946 GET /found_block/<hash>).
    /// The key only carries hash.substr(0,16), so the key suffix is the index
    /// and the full hash in the value is the check: two blocks sharing a
    /// 16-char prefix never answer for each other. No result cap.
    std::optional<FoundBlockRecord> find_by_hash(const std::string& block_hash)
    {
        if (block_hash.size() < 16) return std::nullopt;
        for (const auto& key : m_store.list_keys("fblk:", SIZE_MAX)) {
            if (!key_ends_with_hash(key, block_hash)) continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) continue;
            auto rec = FoundBlockRecord::deserialize(data);
            if (rec.block_hash == block_hash) return rec;
        }
        return std::nullopt;
    }

    /// Fill the #946 body fields once the full block is known. Returns false
    /// when the record does not exist. Every other field is left as stored.
    bool update_body(const std::string& chain, uint64_t height,
                     const std::string& block_hash,
                     const std::string& coinbase_txid, uint32_t tx_count)
    {
        auto key = make_key(chain, height, block_hash);
        std::vector<uint8_t> data;
        if (!m_store.get(key, data))
            return false;
        auto rec = FoundBlockRecord::deserialize(data);
        if (rec.block_hash != block_hash)
            return false;
        rec.coinbase_txid = coinbase_txid;
        rec.tx_count = tx_count;
        return m_store.put(key, rec.serialize());
    }

private:
    // Remove the record of `rec`'s block stored at `height`, if the value
    // there is that block (the key only carries a 16-hex hash prefix).
    void drop_other_key(const FoundBlockRecord& rec, uint64_t height)
    {
        const auto other = make_key(rec.chain, height, rec.block_hash);
        std::vector<uint8_t> old;
        if (m_store.get(other, old)
            && FoundBlockRecord::deserialize(old).block_hash == rec.block_hash)
            m_store.remove(other);
    }

    core::LevelDBStore& m_store;

    static std::string make_key(const std::string& chain, uint64_t height,
                                const std::string& block_hash)
    {
        // Key format: fblk:<chain>:<zero-padded-height>:<hash>
        // Zero-padding ensures lexicographic = chronological ordering
        std::ostringstream oss;
        oss << "fblk:" << chain << ":"
            << std::setfill('0') << std::setw(12) << height << ":"
            << block_hash.substr(0, 16); // truncate hash in key (full hash in value)
        return oss.str();
    }

    static bool key_ends_with_hash(const std::string& key, const std::string& block_hash)
    {
        const std::string tail = ":" + block_hash.substr(0, 16);
        return key.size() >= tail.size() &&
               key.compare(key.size() - tail.size(), tail.size(), tail) == 0;
    }
};

/// Persistent record for a discovered merged block (DOGE etc).
/// Uses key prefix "mblk:" — never pruned.
struct MergedBlockRecord {
    uint32_t    chain_id{0};
    std::string symbol;
    int         height{0};
    std::string block_hash;
    std::string parent_hash;
    int64_t     timestamp{0};
    bool        accepted{true};
    uint64_t    coinbase_value{0};
    bool        is_local{false};
    uint32_t    parent_height{0};   // LTC height the parent was mined at; 0 = unknown
    std::string miner;
    // --- v2 explorer fields (issue #946) ---
    // Empty string / nullopt = unknown, rendered as JSON null (never "" or 0).
    std::string             share_hash;     // null when the solve missed the share target
    std::string             coinbase_txid;
    std::optional<uint32_t> tx_count;       // unset until the full DOGE block arrives
    // --- v2 extension (no version bump, as FoundBlockRecord's) ---
    // The aux chain's own network difficulty at find, from the aux block's
    // bits. 0 = not known (a record written before it existed).
    double                  difficulty{0.0};
    // The GROSS parent-chain pool rate at find (DiscoveredMergedBlock::
    // pool_hashrate). 0 = not known. Follows the difficulty, written only
    // when known: a record without it is byte for byte the earlier one, and
    // an earlier build stops after the difficulty, keeping the record.
    double                  pool_hashrate{0.0};

    std::vector<uint8_t> serialize() const
    {
        PackStream ps;
        // v2 appends the #946 tail after the v1 body; v1 records still load.
        // The difficulty follows the v2 tail WITHOUT a version bump: a v2
        // reader stops after its tail, so the record stays readable on a node
        // rolled back to an earlier build (a v3 one would not load there).
        uint8_t version = 2;
        ps << version;
        ps << chain_id;
        uint8_t sym_len = static_cast<uint8_t>(std::min(symbol.size(), size_t(31)));
        ps << sym_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(symbol.data()), sym_len));
        ps << static_cast<uint32_t>(height);
        uint8_t bh_len = static_cast<uint8_t>(std::min(block_hash.size(), size_t(255)));
        ps << bh_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(block_hash.data()), bh_len));
        uint8_t ph_len = static_cast<uint8_t>(std::min(parent_hash.size(), size_t(255)));
        ps << ph_len;
        ps.write(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(parent_hash.data()), ph_len));
        ps << static_cast<uint64_t>(timestamp);
        uint8_t flags = (accepted ? 1 : 0) | (is_local ? 2 : 0);
        ps << flags;
        ps << coinbase_value;
        ps << parent_height;
        uint8_t mn_len = static_cast<uint8_t>(std::min(miner.size(), size_t(255)));
        ps << mn_len;
        if (mn_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(miner.data()), mn_len));
        // --- v2 tail ---
        uint8_t sh_len = static_cast<uint8_t>(std::min(share_hash.size(), size_t(255)));
        ps << sh_len;
        if (sh_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(share_hash.data()), sh_len));
        uint8_t cb_len = static_cast<uint8_t>(std::min(coinbase_txid.size(), size_t(255)));
        ps << cb_len;
        if (cb_len > 0)
            ps.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(coinbase_txid.data()), cb_len));
        uint8_t has_tx_count = tx_count.has_value() ? 1 : 0;
        ps << has_tx_count;
        ps << static_cast<uint32_t>(tx_count.value_or(0));
        // --- v2 extension: IEEE-754 bits, as FoundBlockRecord's doubles ---
        uint64_t difficulty_bits;
        std::memcpy(&difficulty_bits, &difficulty, sizeof(difficulty_bits));
        ps << difficulty_bits;
        // --- the rate at find, only when known ---
        if (pool_hashrate > 0.0 && std::isfinite(pool_hashrate)) {
            uint64_t rate_bits;
            std::memcpy(&rate_bits, &pool_hashrate, sizeof(rate_bits));
            ps << rate_bits;
        }

        auto span = ps.get_span();
        return {reinterpret_cast<const uint8_t*>(span.data()),
                reinterpret_cast<const uint8_t*>(span.data()) + span.size()};
    }

    static MergedBlockRecord deserialize(const std::vector<uint8_t>& data)
    {
        MergedBlockRecord rec;
        if (data.size() < 4) return rec;
        // Same short-read rule as FoundBlockRecord::deserialize.
        size_t pos = 0;
        bool overrun = false;
        auto read_u8 = [&]() -> uint8_t {
            if (pos < data.size()) return data[pos++];
            overrun = true; return 0;
        };
        auto read_u32 = [&]() -> uint32_t {
            if (pos + 4 > data.size()) { pos = data.size(); overrun = true; return 0; }
            uint32_t v; std::memcpy(&v, &data[pos], 4); pos += 4; return v;
        };
        auto read_u64 = [&]() -> uint64_t {
            if (pos + 8 > data.size()) { pos = data.size(); overrun = true; return 0; }
            uint64_t v; std::memcpy(&v, &data[pos], 8); pos += 8; return v;
        };
        auto read_str = [&](uint8_t len) -> std::string {
            if (pos + len > data.size()) { pos = data.size(); overrun = true; return ""; }
            std::string s(reinterpret_cast<const char*>(&data[pos]), len);
            pos += len; return s;
        };

        uint8_t version = read_u8();
        if (version < 1 || version > 2) return rec; // unknown version
        rec.chain_id = read_u32();
        rec.symbol = read_str(read_u8());
        rec.height = static_cast<int>(read_u32());
        rec.block_hash = read_str(read_u8());
        rec.parent_hash = read_str(read_u8());
        rec.timestamp = static_cast<int64_t>(read_u64());
        uint8_t flags = read_u8();
        rec.accepted = (flags & 1) != 0;
        rec.is_local = (flags & 2) != 0;
        rec.coinbase_value = read_u64();
        rec.parent_height = read_u32();
        rec.miner = read_str(read_u8());
        // A cut inside the v1 body is a damaged row; load_all skips it.
        if (overrun) return MergedBlockRecord{};
        // --- v2 explorer tail (absent on v1 records) ---
        if (version >= 2) {
            rec.share_hash = read_str(read_u8());
            rec.coinbase_txid = read_str(read_u8());
            uint8_t has_tx_count = read_u8();
            // A truncated tail must not turn into a known tx_count of 0.
            bool whole = pos + 4 <= data.size();
            uint32_t n = read_u32();
            if (has_tx_count && whole) rec.tx_count = n;
            // --- v2 extension (absent on records written before it) ---
            if (whole && pos + 8 <= data.size()) {
                uint64_t bits = read_u64();
                double d;
                std::memcpy(&d, &bits, sizeof(d));
                if (d > 0.0 && std::isfinite(d)) rec.difficulty = d;
                // --- the rate at find (absent when not known) ---
                if (pos + 8 <= data.size()) {
                    uint64_t rbits = read_u64();
                    double r;
                    std::memcpy(&r, &rbits, sizeof(r));
                    if (r > 0.0 && std::isfinite(r)) rec.pool_hashrate = r;
                }
            }
        }
        return rec;
    }
};

/// LevelDB-backed persistent store for discovered merged blocks.
/// Uses key prefix "mblk:" — shares the same LevelDB as found blocks.
class MergedBlockStore {
public:
    explicit MergedBlockStore(core::LevelDBStore& store) : m_store(store) {}

    /// Store a merged block record. A rate at find already stored for the
    /// block is never replaced by an unknown one: the same block learned
    /// again long after its find (the startup scan of the share chain)
    /// carries none, and the record it overwrites holds the reading taken
    /// when the block was found.
    bool store(const MergedBlockRecord& rec)
    {
        auto key = make_key(rec.chain_id, rec.height, rec.block_hash);
        if (!(rec.pool_hashrate > 0.0)) {
            std::vector<uint8_t> old;
            if (m_store.get(key, old)) {
                const auto held = MergedBlockRecord::deserialize(old);
                if (held.block_hash == rec.block_hash && held.pool_hashrate > 0.0) {
                    MergedBlockRecord keep = rec;
                    keep.pool_hashrate = held.pool_hashrate;
                    return m_store.put(key, keep.serialize());
                }
            }
        }
        return m_store.put(key, rec.serialize());
    }

    bool update_coinbase(const std::string& block_hash, uint32_t chain_id, uint64_t coinbase_value)
    {
        auto key = find_key(block_hash, chain_id);
        if (!key) return false;
        std::vector<uint8_t> data;
        if (!m_store.get(*key, data)) return false;
        auto rec = MergedBlockRecord::deserialize(data);
        if (rec.block_hash.empty())
            return false; // damaged row; don't overwrite it with an empty one
        rec.coinbase_value = coinbase_value;
        return m_store.put(*key, rec.serialize());
    }

    /// Fill the #946 body fields once the full merged block is known.
    bool update_body(const std::string& block_hash, uint32_t chain_id,
                     const std::string& coinbase_txid, uint32_t tx_count)
    {
        auto key = find_key(block_hash, chain_id);
        if (!key) return false;
        std::vector<uint8_t> data;
        if (!m_store.get(*key, data)) return false;
        auto rec = MergedBlockRecord::deserialize(data);
        if (rec.block_hash.empty())
            return false; // damaged row; don't overwrite it with an empty one
        rec.coinbase_txid = coinbase_txid;
        rec.tx_count = tx_count;
        return m_store.put(*key, rec.serialize());
    }

    /// Look a record up by its FULL block hash across every merged chain
    /// (#946 GET /found_block/<hash>). Same key-suffix index + full-hash check
    /// as FoundBlockStore::find_by_hash.
    std::optional<MergedBlockRecord> find_by_hash(const std::string& block_hash)
    {
        if (block_hash.size() < 16) return std::nullopt;
        for (const auto& key : m_store.list_keys("mblk:", SIZE_MAX)) {
            if (!key_ends_with_hash(key, block_hash)) continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) continue;
            auto rec = MergedBlockRecord::deserialize(data);
            if (rec.block_hash == block_hash) return rec;
        }
        return std::nullopt;
    }

    std::vector<MergedBlockRecord> load_all()
    {
        std::vector<MergedBlockRecord> result;
        auto keys = m_store.list_keys("mblk:", 10000);
        for (const auto& key : keys) {
            std::vector<uint8_t> data;
            if (m_store.get(key, data)) {
                auto rec = MergedBlockRecord::deserialize(data);
                if (!rec.block_hash.empty())
                    result.push_back(std::move(rec));
            }
        }
        std::sort(result.begin(), result.end(),
            [](const MergedBlockRecord& a, const MergedBlockRecord& b) {
                return a.timestamp > b.timestamp;
            });
        return result;
    }

    size_t count() { return m_store.list_keys("mblk:", 10000).size(); }

private:
    core::LevelDBStore& m_store;

    static std::string make_key(uint32_t chain_id, int height, const std::string& block_hash)
    {
        std::ostringstream oss;
        oss << "mblk:" << chain_id << ":"
            << std::setfill('0') << std::setw(12) << height << ":"
            << block_hash.substr(0, 16);
        return oss.str();
    }

    static bool key_ends_with_hash(const std::string& key, const std::string& block_hash)
    {
        const std::string tail = ":" + block_hash.substr(0, 16);
        return key.size() >= tail.size() &&
               key.compare(key.size() - tail.size(), tail.size(), tail) == 0;
    }

    /// Key of the record for (block_hash, chain_id), or nullopt. Scans only
    /// this chain's keys, newest height first, with no result cap. It used to
    /// scan list_keys("mblk:", 1000) oldest first across all chains, so once
    /// 1000 records existed the newest block never got its coinbase_value.
    std::optional<std::string> find_key(const std::string& block_hash, uint32_t chain_id)
    {
        auto keys = m_store.list_keys("mblk:" + std::to_string(chain_id) + ":", SIZE_MAX);
        for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
            if (!key_ends_with_hash(*it, block_hash)) continue;
            std::vector<uint8_t> data;
            if (!m_store.get(*it, data)) continue;
            auto rec = MergedBlockRecord::deserialize(data);
            if (rec.block_hash == block_hash && rec.chain_id == chain_id)
                return *it;
        }
        return std::nullopt;
    }
};

} // namespace storage
} // namespace c2pool