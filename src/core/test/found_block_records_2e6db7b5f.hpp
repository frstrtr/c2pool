// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_records_2e6db7b5f.hpp -- the fblk / mblk RECORD serializers
// exactly as origin/master 2e6db7b5f has them (src/c2pool/storage/
// found_block_store.hpp lines 18-262 and 426-567, byte for byte; identical
// to v0.2.12.10's), in namespace c2pool::storage_2e6db7b5f. TEST-ONLY: the
// format KATs read and write with the earlier build's own code, so "an
// earlier build keeps the row" is checked against that build, not against
// a description of it. Never include it outside src/core/test.

#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <optional>
#include <algorithm>
#include <span>
#include <core/uint256.hpp>
#include <core/pack.hpp>

namespace c2pool {
namespace storage_2e6db7b5f {

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

    // Bits of the extension byte that follows the v4 tail.
    static constexpr uint8_t kExtAuxDifficultyKnown = 0x01;
    static constexpr uint8_t kExtImported           = 0x02;

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
        uint8_t ext = (aux_difficulty_known ? kExtAuxDifficultyKnown : 0)
                    | (imported ? kExtImported : 0);
        ps << ext;

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
            }
        }

        return rec;
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
            }
        }
        return rec;
    }
};

} // namespace storage_2e6db7b5f
} // namespace c2pool
