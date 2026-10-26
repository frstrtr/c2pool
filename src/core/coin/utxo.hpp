#pragma once

/// Core UTXO (Unspent Transaction Output) data structures.
///
/// Provides Coin, Outpoint, ChainLimits, MoneyRange, and serialization
/// for the embedded UTXO set. Shared between LTC and DOGE embedded nodes.
///
/// Reference: Litecoin Core coins.h (Coin class, per-output UTXO model)
/// Reference: Dogecoin Core coins.h (CCoins class, adapted to per-output)

#include <core/uint256.hpp>
#include <core/opscript.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <cstring>
#include <set>
#include <vector>
#include <functional>

namespace core {
namespace coin {

// ─── ChainLimits ─────────────────────────────────────────────────────────────

/// Chain-agnostic validation parameters.
/// Allows the same UTXO code to serve LTC, DOGE, and future chains.
///
/// Reference: LTC amount.h MAX_MONEY, consensus.h COINBASE_MATURITY/PEGOUT_MATURITY
/// Reference: DOGE amount.h MAX_MONEY
struct ChainLimits {
    int64_t  max_money;            // maximum valid value (satoshis)
    uint32_t coinbase_maturity;    // blocks before coinbase can be spent
    uint32_t pegout_maturity;      // blocks before pegout can be spent (0 = N/A)
};

/// LTC: 84M * 1e8 sat, 100-block coinbase maturity, 6-block pegout maturity
/// Reference: litecoin/src/consensus/consensus.h COINBASE_MATURITY, PEGOUT_MATURITY
static constexpr ChainLimits LTC_LIMITS  = {8'400'000'000'000'000LL, 100, 6};

/// DOGE: ~10B * 1e8 sat (infinite inflation, but max single value bounded),
///       240-block coinbase maturity (post-DigiShield), no pegout (no MWEB)
/// Reference: dogecoin/src/chainparams.cpp digishieldConsensus.nCoinbaseMaturity
static constexpr ChainLimits DOGE_LIMITS = {1'000'000'000'000'000'000LL, 240, 0};

/// DGB: 21B DGB max supply * 1e8 sat = 2.1e18 sat, 100-block coinbase maturity
///      at the current chain tip, no pegout (no MWEB).
/// Reference: digibyte/src/consensus/consensus.h defines COINBASE_MATURITY = 8
///   (legacy, early chain) AND COINBASE_MATURITY_2 = 100, selected by height
///   (DigiByte-Core PR #157). c2pool-dgb only ever validates at the current
///   tip, which is deep past the transition, so 100 is the operative value.
///   100 is also the conservative choice for the embedded fee lane: if a coin's
///   real maturity were lower, using 100 only OVER-rejects a young-coinbase
///   spend (that tx is excluded from selection, never falsely admitted) — the
///   same "never overstated" ceiling LTC/BTC/DASH accept. max_money 2.1e18 is
///   above LTC's 8.4e15 so a legitimately large DGB output is not falsely
///   rejected by a too-small bound (which LTC_LIMITS, the prior Mempool()
///   default for DGB, would have done above 84M DGB in one output).
static constexpr ChainLimits DGB_LIMITS = {2'100'000'000'000'000'000LL, 100, 0};

/// XMR (Monero): 60-block coinbase maturity (a mined output unlocks at
///   height + 60), no pegout. Sibling of the LTC/DOGE/DGB rows for the XMR
///   settlement lane (Family B).
/// coinbase_maturity = 60: monero-project cryptonote_config.h
///   CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 60 (~2 h at the 120 s v2 target).
/// pegout_maturity = 0: Monero has no MWEB/pegout.
/// max_money: DENOMINATION AND RANGE CAVEAT. Monero amounts are piconero
///   (1 XMR = 1e12 atomic units — NOT the 1e8-sat convention of the BTC
///   family), and Monero has no fixed supply cap (MONEY_SUPPLY is the
///   ((uint64_t)-1) sentinel; tail emission is 0.6 XMR/block forever). c2pool's
///   money_range() ceiling is int64_t, so we take INT64_MAX: it guards only
///   against negative / overflowed output amounts and never falsely rejects a
///   real coinbase output (per-output amounts sit far below 2^63 piconero).
///   Supply-cap and per-output validity are enforced by Monero consensus'
///   validate_miner_transaction; c2pool re-derives (P_i, view_tag_i) and
///   byte-compares outputs — it does not re-run XMR supply accounting.
static constexpr ChainLimits XMR_LIMITS = {9'223'372'036'854'775'807LL, 60, 0};

/// Minimum blocks of undo data to keep for reorg safety + pruning.
/// Matches the MIN_BLOCKS_TO_KEEP constant in each daemon's validation.h.
/// Reference: litecoin/src/validation.h  MIN_BLOCKS_TO_KEEP = 288
/// Reference: dogecoin/src/validation.h  MIN_BLOCKS_TO_KEEP = 1440
static constexpr uint32_t LTC_MIN_BLOCKS_TO_KEEP  = 288;
static constexpr uint32_t DOGE_MIN_BLOCKS_TO_KEEP = 1440;
/// DGB: MIN_BLOCKS_TO_KEEP = 288 (matches digibyte/src/validation.h, same as
/// Bitcoin Core). DGB's ~15 s block time makes 288 blocks ~72 min of undo
/// data — ample for the shallow reorgs DGB sees.
static constexpr uint32_t DGB_MIN_BLOCKS_TO_KEEP  = 288;
/// XMR: keep one coinbase-unlock window's worth of undo data. Monero has no
/// Bitcoin-style MIN_BLOCKS_TO_KEEP; its practical reorg depth is shallow and
/// the 60-block maturity window bounds what a settlement reorg can touch, so
/// 60 is the conservative keep depth. [est] engineering choice, not a cited
/// Monero constant.
static constexpr uint32_t XMR_MIN_BLOCKS_TO_KEEP  = 60;

/// Minimum UTXO depth before mining can start: coinbase_maturity + reorg_buffer.
/// LTC: 100 (COINBASE_MATURITY) + 6 (PEGOUT_MATURITY reorg depth) = 106
/// DOGE: 240 (nCoinbaseMaturity post-DigiShield) + 10 (reorg safety) = 250
/// Reference: litecoin/src/consensus/consensus.h, dogecoin/src/chainparams.cpp
static constexpr uint32_t LTC_MINING_GATE_DEPTH  = LTC_LIMITS.coinbase_maturity + LTC_LIMITS.pegout_maturity; // 106
static constexpr uint32_t DOGE_MINING_GATE_DEPTH = DOGE_LIMITS.coinbase_maturity + 10; // 250
/// DGB: 100 (COINBASE_MATURITY_2) + 10-block reorg safety buffer = 110.
static constexpr uint32_t DGB_MINING_GATE_DEPTH  = DGB_LIMITS.coinbase_maturity + 10; // 110
/// XMR: 60 (CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW) + 10-block reorg buffer = 70.
static constexpr uint32_t XMR_MINING_GATE_DEPTH  = XMR_LIMITS.coinbase_maturity + 10; // 70

/// Tip age threshold for considering chain synced (seconds).
/// Both LTC and DOGE use 24 hours (86400s) as DEFAULT_MAX_TIP_AGE.
/// Reference: litecoin/src/validation.h  DEFAULT_MAX_TIP_AGE = 24 * 60 * 60
/// Reference: dogecoin/src/validation.h  DEFAULT_MAX_TIP_AGE = 24 * 60 * 60
static constexpr uint32_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60; // 86400s

/// Check if a value is within the valid money range for a chain.
/// Reference: LTC/DOGE amount.h MoneyRange()
inline bool money_range(int64_t v, const ChainLimits& lim) {
    return v >= 0 && v <= lim.max_money;
}

// ─── Outpoint ────────────────────────────────────────────────────────────────

/// Identifies a specific output in a transaction.
/// Matches Bitcoin/Litecoin COutPoint: (txid, output_index).
struct Outpoint {
    uint256  txid;
    uint32_t index{0};

    Outpoint() = default;
    Outpoint(const uint256& h, uint32_t n) : txid(h), index(n) {}

    bool operator==(const Outpoint& o) const { return txid == o.txid && index == o.index; }
    bool operator!=(const Outpoint& o) const { return !(*this == o); }
    bool operator<(const Outpoint& o) const {
        if (txid != o.txid) return txid < o.txid;
        return index < o.index;
    }

    bool is_null() const { return txid.IsNull() && index == 0; }
};

/// Hash function for Outpoint, for use in unordered_map.
struct OutpointHasher {
    std::size_t operator()(const Outpoint& op) const noexcept {
        std::size_t h = 0;
        const auto* p = op.txid.data();
        for (int i = 0; i < 8; ++i)
            h ^= std::size_t(p[i]) << (i * 8);
        h ^= std::hash<uint32_t>{}(op.index) * 0x9e3779b97f4a7c15ULL;
        return h;
    }
};

// ─── Script helpers ──────────────────────────────────────────────────────────

/// Check if a scriptPubKey is provably unspendable.
/// Reference: LTC script.h IsUnspendable()
///   - OP_RETURN (0x6a) prefix
///   - Oversized script (> MAX_SCRIPT_SIZE = 10,000 bytes)
inline bool is_unspendable(const OPScript& script) {
    if (script.m_data.empty()) return false;
    if (script.m_data[0] == 0x6a) return true;                   // OP_RETURN
    if (script.m_data.size() > 10000) return true;                // MAX_SCRIPT_SIZE
    return false;
}

// ─── Coin ────────────────────────────────────────────────────────────────────

/// A single unspent transaction output.
///
/// Stores the full TxOut (value + scriptPubKey) plus metadata.
/// Full scriptPubKey is retained for:
///   - Transaction creation (pool payouts, priority tx insertion)
///   - Dust detection by script/address type
///   - Future script validation
///
/// Reference: Litecoin Core coins.h Coin class
struct Coin {
    int64_t  value{0};             // output value in satoshis
    OPScript scriptPubKey;         // output script (P2PKH, P2WPKH, P2SH, etc.)
    uint32_t height{0};            // block height where containing tx was included
    bool     coinbase{false};      // whether containing tx was a coinbase
    bool     pegout{false};        // MWEB pegout output (LTC only, 6-block maturity)

    Coin() = default;
    Coin(int64_t val, OPScript script, uint32_t h, bool cb, bool pg = false)
        : value(val), scriptPubKey(std::move(script)), height(h), coinbase(cb), pegout(pg) {}

    bool is_spent() const { return value == 0 && scriptPubKey.m_data.empty(); }

    void clear() {
        value = 0;
        scriptPubKey.m_data.clear();
        height = 0;
        coinbase = false;
        pegout = false;
    }

    /// Check if this coin is mature enough to spend at the given height.
    /// Reference: LTC consensus/tx_verify.cpp CheckTxInputs() lines 184-192
    bool is_mature(uint32_t spend_height, const ChainLimits& lim) const {
        if (coinbase && spend_height - height < lim.coinbase_maturity)
            return false;
        if (pegout && lim.pegout_maturity > 0 && spend_height - height < lim.pegout_maturity)
            return false;
        return true;
    }
};

// ─── Serialization ───────────────────────────────────────────────────────────

/// Varint encoding helper — appends to buffer.
inline void write_varint(std::vector<uint8_t>& buf, uint64_t v) {
    while (v >= 0x80) {
        buf.push_back(static_cast<uint8_t>(v & 0x7F) | 0x80);
        v >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(v));
}

/// Varint decoding helper — advances pos. Returns 0 on failure.
inline uint64_t read_varint(const uint8_t* data, size_t len, size_t& pos) {
    uint64_t v = 0;
    unsigned shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        v |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) return v;
        shift += 7;
        if (shift > 63) return 0;
    }
    return v;
}

/// Serialize an Outpoint to bytes: txid(32) + index(4 LE).
inline std::string outpoint_to_key(const Outpoint& op) {
    std::string key;
    key.reserve(36);
    key.append(reinterpret_cast<const char*>(op.txid.data()), 32);
    uint32_t idx = op.index;
    key.push_back(static_cast<char>(idx & 0xFF));
    key.push_back(static_cast<char>((idx >> 8) & 0xFF));
    key.push_back(static_cast<char>((idx >> 16) & 0xFF));
    key.push_back(static_cast<char>((idx >> 24) & 0xFF));
    return key;
}

/// Deserialize an Outpoint from a 36-byte key.
inline Outpoint key_to_outpoint(const std::string& key) {
    Outpoint op;
    if (key.size() < 36) return op;
    std::memcpy(op.txid.data(), key.data(), 32);
    const auto* p = reinterpret_cast<const uint8_t*>(key.data() + 32);
    op.index = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    return op;
}

/// Serialize a Coin to bytes.
/// Format: varint(code) + varint(value) + varint(script_len) + script_bytes
/// code = height * 2 + coinbase + (pegout ? (1<<31) : 0)
/// Bit 31 of code encodes pegout (matching LTC Core coins.h:71).
inline std::vector<uint8_t> serialize_coin(const Coin& coin) {
    std::vector<uint8_t> buf;
    buf.reserve(16 + coin.scriptPubKey.m_data.size());

    uint64_t code = static_cast<uint64_t>(coin.height) * 2 + (coin.coinbase ? 1 : 0);
    if (coin.pegout) code |= (uint64_t(1) << 31);
    write_varint(buf, code);
    write_varint(buf, static_cast<uint64_t>(coin.value));
    write_varint(buf, coin.scriptPubKey.m_data.size());
    buf.insert(buf.end(), coin.scriptPubKey.m_data.begin(), coin.scriptPubKey.m_data.end());
    return buf;
}

/// Deserialize a Coin from bytes. Returns false if data is malformed.
inline bool deserialize_coin(const uint8_t* data, size_t len, Coin& coin) {
    size_t pos = 0;
    uint64_t code = read_varint(data, len, pos);
    coin.pegout   = (code >> 31) & 1;
    code &= ~(uint64_t(1) << 31);
    coin.coinbase = (code & 1) != 0;
    coin.height   = static_cast<uint32_t>(code >> 1);
    coin.value    = static_cast<int64_t>(read_varint(data, len, pos));
    uint64_t slen = read_varint(data, len, pos);
    if (pos + slen > len) return false;
    coin.scriptPubKey.m_data.assign(data + pos, data + pos + slen);
    return true;
}

inline bool deserialize_coin(const std::vector<uint8_t>& data, Coin& coin) {
    return deserialize_coin(data.data(), data.size(), coin);
}

/// Serialize an Outpoint to bytes (for BlockUndo added_outpoints).
inline void serialize_outpoint(std::vector<uint8_t>& buf, const Outpoint& op) {
    buf.insert(buf.end(), op.txid.data(), op.txid.data() + 32);
    write_varint(buf, op.index);
}

/// Deserialize an Outpoint from a byte stream.
inline bool deserialize_outpoint(const uint8_t* data, size_t len, size_t& pos, Outpoint& op) {
    if (pos + 32 > len) return false;
    std::memcpy(op.txid.data(), data + pos, 32);
    pos += 32;
    op.index = static_cast<uint32_t>(read_varint(data, len, pos));
    return true;
}

/// Bounds-checked varint read: false on truncation or on more than 64 bits.
/// (read_varint above returns a partial value on truncation; record readers
/// that must fail closed use this one.)
inline bool read_varint_checked(const uint8_t* data, size_t len, size_t& pos, uint64_t& v) {
    v = 0;
    for (unsigned shift = 0; shift <= 63; shift += 7) {
        if (pos >= len) return false;
        const uint8_t b = data[pos++];
        v |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
    }
    return false;
}

// ─── BlockUndo ───────────────────────────────────────────────────────────────

/// Undo data for a single transaction: the coins that were spent by its inputs,
/// in vin order (Core validation.cpp UpdateCoins), each with its outpoint
/// (tx.vin[j].prevout). Core takes the outpoints from the block body at
/// disconnect time; c2pool stores them so a block can be disconnected from its
/// record alone.
/// Reference: Litecoin Core CTxUndo
struct TxUndo {
    std::vector<Coin>     spent_coins;      // Coin::is_spent() = not in the view at connect
    std::vector<Outpoint> spent_outpoints;  // same length as spent_coins; empty in a legacy record
    bool has_outpoints() const { return spent_outpoints.size() == spent_coins.size(); }
};

/// Undo data for an entire block.
/// Contains both spent coins with their outpoints (for restoring inputs) and
/// added outpoints (for removing outputs), enabling disconnect without full
/// block data.
/// Reference: Litecoin Core CBlockUndo (extended with outpoints, added_outpoints)
struct BlockUndo {
    std::vector<TxUndo> tx_undos;           // one per non-coinbase tx, block order
    std::vector<Outpoint> added_outpoints;  // all outputs created by this block
    uint256 block_hash;                     // the block this record undoes (null = unbound)
    uint8_t format{2};                      // 1 = legacy record (no outpoints), 2 = current

    /// Spent coins that cannot be put back: coins of a TxUndo without outpoints
    /// (a legacy record). A coin that was not in the view at connect
    /// (is_spent) has nothing to restore and does not count.
    size_t unrestorable_coins() const {
        size_t n = 0;
        for (const auto& tu : tx_undos) {
            if (tu.has_outpoints()) continue;
            for (const auto& c : tu.spent_coins)
                if (!c.is_spent()) ++n;
        }
        return n;
    }
    /// Every spent coin can be put back.
    bool restorable() const { return unrestorable_coins() == 0; }
};

/// Serialize BlockUndo to bytes (legacy format 1: no outpoints, no block hash).
/// Kept byte-identical for the DASH replay fold's own store; UTXOViewDB writes
/// format 2 (serialize_block_undo_v2).
inline std::vector<uint8_t> serialize_block_undo(const BlockUndo& undo) {
    std::vector<uint8_t> buf;
    buf.reserve(2048);

    // tx_undos
    write_varint(buf, undo.tx_undos.size());
    for (const auto& tu : undo.tx_undos) {
        write_varint(buf, tu.spent_coins.size());
        for (const auto& c : tu.spent_coins) {
            auto cb = serialize_coin(c);
            buf.insert(buf.end(), cb.begin(), cb.end());
        }
    }

    // added_outpoints (for disconnect without full block)
    write_varint(buf, undo.added_outpoints.size());
    for (const auto& op : undo.added_outpoints)
        serialize_outpoint(buf, op);

    return buf;
}

/// Deserialize BlockUndo from bytes (legacy format 1). The record carries no
/// outpoints and no block hash: format = 1, spent_outpoints empty.
inline bool deserialize_block_undo(const uint8_t* data, size_t len, BlockUndo& undo) {
    size_t pos = 0;
    undo.format = 1;
    undo.block_hash.SetNull();

    uint64_t n_txs = read_varint(data, len, pos);
    undo.tx_undos.resize(static_cast<size_t>(n_txs));

    for (auto& tu : undo.tx_undos) {
        tu.spent_outpoints.clear();
        uint64_t n_coins = read_varint(data, len, pos);
        tu.spent_coins.resize(static_cast<size_t>(n_coins));
        for (auto& c : tu.spent_coins) {
            if (!deserialize_coin(data + pos, len - pos, c))
                return false;
            auto re = serialize_coin(c);
            pos += re.size();
        }
    }

    // added_outpoints (may not be present in old undo records)
    if (pos < len) {
        uint64_t n_ops = read_varint(data, len, pos);
        undo.added_outpoints.resize(static_cast<size_t>(n_ops));
        for (auto& op : undo.added_outpoints) {
            if (!deserialize_outpoint(data, len, pos, op))
                return false;
        }
    }

    return true;
}

inline bool deserialize_block_undo(const std::vector<uint8_t>& data, BlockUndo& undo) {
    return deserialize_block_undo(data.data(), data.size(), undo);
}

/// BlockUndo format 2 (UTXOViewDB 'R' records). Varints are write_varint's
/// LEB128, not Bitcoin CompactSize:
///   u8      version = 0x02
///   32      block_hash (all zero = unbound)
///   varint  n_tx                      one per non-coinbase tx, block order
///   n_tx x  varint n_in               vin order
///           n_in x  32 txid | varint index | coin (serialize_coin; an input
///                   that was not in the view at connect is 00 00 00)
///   varint  n_added
///   n_added x 32 txid | varint index
/// Returns an empty vector for a record without outpoints (never writes a
/// format-2 record that cannot restore its coins).
inline constexpr uint8_t BLOCK_UNDO_V2 = 0x02;

inline std::vector<uint8_t> serialize_block_undo_v2(const BlockUndo& undo) {
    std::vector<uint8_t> buf;
    buf.reserve(2048);
    buf.push_back(BLOCK_UNDO_V2);
    buf.insert(buf.end(), undo.block_hash.data(), undo.block_hash.data() + 32);
    write_varint(buf, undo.tx_undos.size());
    for (const auto& tu : undo.tx_undos) {
        if (!tu.has_outpoints())
            return {};
        write_varint(buf, tu.spent_coins.size());
        for (size_t j = 0; j < tu.spent_coins.size(); ++j) {
            serialize_outpoint(buf, tu.spent_outpoints[j]);
            auto cb = serialize_coin(tu.spent_coins[j]);
            buf.insert(buf.end(), cb.begin(), cb.end());
        }
    }
    write_varint(buf, undo.added_outpoints.size());
    for (const auto& op : undo.added_outpoints)
        serialize_outpoint(buf, op);
    return buf;
}

/// Deserialize a format-2 record. Fails closed: wrong version, any truncation,
/// a count larger than the bytes left could hold, or trailing bytes.
inline bool deserialize_block_undo_v2(const uint8_t* data, size_t len, BlockUndo& undo) {
    undo = BlockUndo{};
    if (len < 33 || data[0] != BLOCK_UNDO_V2)
        return false;
    std::memcpy(undo.block_hash.data(), data + 1, 32);
    size_t pos = 33;

    auto read_outpoint = [&](Outpoint& op) {
        if (len - pos < 32) return false;
        std::memcpy(op.txid.data(), data + pos, 32);
        pos += 32;
        uint64_t idx;
        if (!read_varint_checked(data, len, pos, idx) || idx > 0xffffffffULL) return false;
        op.index = static_cast<uint32_t>(idx);
        return true;
    };
    auto read_coin = [&](Coin& c) {
        uint64_t code, value, slen;
        if (!read_varint_checked(data, len, pos, code)
            || !read_varint_checked(data, len, pos, value)
            || !read_varint_checked(data, len, pos, slen)
            || slen > len - pos)
            return false;
        c.pegout   = (code >> 31) & 1;
        code &= ~(uint64_t(1) << 31);
        c.coinbase = (code & 1) != 0;
        c.height   = static_cast<uint32_t>(code >> 1);
        c.value    = static_cast<int64_t>(value);
        c.scriptPubKey.m_data.assign(data + pos, data + pos + slen);
        pos += static_cast<size_t>(slen);
        return true;
    };

    uint64_t n_tx;
    if (!read_varint_checked(data, len, pos, n_tx) || n_tx > len - pos)
        return false;
    undo.tx_undos.resize(static_cast<size_t>(n_tx));
    for (auto& tu : undo.tx_undos) {
        uint64_t n_in;
        // An input takes at least 36 bytes (txid, index, empty coin).
        if (!read_varint_checked(data, len, pos, n_in) || n_in > (len - pos) / 36)
            return false;
        tu.spent_coins.resize(static_cast<size_t>(n_in));
        tu.spent_outpoints.resize(static_cast<size_t>(n_in));
        for (size_t j = 0; j < n_in; ++j) {
            if (!read_outpoint(tu.spent_outpoints[j]) || !read_coin(tu.spent_coins[j]))
                return false;
        }
    }
    uint64_t n_added;
    if (!read_varint_checked(data, len, pos, n_added) || n_added > (len - pos) / 33)
        return false;
    undo.added_outpoints.resize(static_cast<size_t>(n_added));
    for (auto& op : undo.added_outpoints) {
        if (!read_outpoint(op))
            return false;
    }
    if (pos != len)
        return false;
    undo.format = 2;
    return true;
}

inline bool deserialize_block_undo_v2(const std::vector<uint8_t>& data, BlockUndo& undo) {
    return deserialize_block_undo_v2(data.data(), data.size(), undo);
}

} // namespace coin
} // namespace core
