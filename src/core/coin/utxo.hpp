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
static constexpr ChainLimits LTC_LIMITS  = {8'400'000'000'000'000LL, 100, 6};

/// DOGE: ~10B * 1e8 sat (infinite inflation, but max single value bounded),
///       240-block coinbase maturity, no pegout (no MWEB)
static constexpr ChainLimits DOGE_LIMITS = {1'000'000'000'000'000'000LL, 240, 0};

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

// ─── BlockUndo ───────────────────────────────────────────────────────────────

/// Undo data for a single transaction: the coins that were spent by its inputs.
/// Reference: Litecoin Core CTxUndo
struct TxUndo {
    std::vector<Coin> spent_coins;
};

/// Undo data for an entire block.
/// Contains both spent coins (for restoring inputs) and added outpoints
/// (for removing outputs), enabling disconnect without full block data.
/// Reference: Litecoin Core CBlockUndo (extended with added_outpoints)
struct BlockUndo {
    std::vector<TxUndo> tx_undos;           // one per non-coinbase tx
    std::vector<Outpoint> added_outpoints;  // all outputs created by this block
};

/// Serialize BlockUndo to bytes.
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

/// Deserialize BlockUndo from bytes.
inline bool deserialize_block_undo(const uint8_t* data, size_t len, BlockUndo& undo) {
    size_t pos = 0;

    uint64_t n_txs = read_varint(data, len, pos);
    undo.tx_undos.resize(static_cast<size_t>(n_txs));

    for (auto& tu : undo.tx_undos) {
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

} // namespace coin
} // namespace core
