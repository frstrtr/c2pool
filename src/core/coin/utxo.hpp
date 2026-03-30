#pragma once

/// Core UTXO (Unspent Transaction Output) data structures.
///
/// Provides Coin, Outpoint, and serialization for the embedded UTXO set.
/// Shared between LTC and DOGE embedded nodes.
///
/// Reference: Litecoin Core coins.h (Coin class, per-output UTXO model)

#include <core/uint256.hpp>
#include <core/opscript.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <vector>
#include <functional>

namespace core {
namespace coin {

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
/// Uses SipHash-style mixing of txid bytes + index.
struct OutpointHasher {
    std::size_t operator()(const Outpoint& op) const noexcept {
        // Mix the first 8 bytes of txid with the index
        std::size_t h = 0;
        const auto* p = op.txid.data();
        for (int i = 0; i < 8; ++i)
            h ^= std::size_t(p[i]) << (i * 8);
        h ^= std::hash<uint32_t>{}(op.index) * 0x9e3779b97f4a7c15ULL;
        return h;
    }
};

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

    Coin() = default;
    Coin(int64_t val, OPScript script, uint32_t h, bool cb)
        : value(val), scriptPubKey(std::move(script)), height(h), coinbase(cb) {}

    bool is_spent() const { return value == 0 && scriptPubKey.m_data.empty(); }

    void clear() {
        value = 0;
        scriptPubKey.m_data.clear();
        height = 0;
        coinbase = false;
    }
};

// ─── Serialization ───────────────────────────────────────────────────────────

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
/// Format: varint(height * 2 + coinbase) + varint(value) + varint(script_len) + script_bytes
/// Matches Litecoin Core's compact encoding pattern.
inline std::vector<uint8_t> serialize_coin(const Coin& coin) {
    std::vector<uint8_t> buf;
    buf.reserve(16 + coin.scriptPubKey.m_data.size());

    // Encode height + coinbase as a single varint
    uint64_t code = static_cast<uint64_t>(coin.height) * 2 + (coin.coinbase ? 1 : 0);

    // Varint encode: code
    while (code >= 0x80) {
        buf.push_back(static_cast<uint8_t>(code & 0x7F) | 0x80);
        code >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(code));

    // Varint encode: value (as uint64)
    uint64_t val = static_cast<uint64_t>(coin.value);
    while (val >= 0x80) {
        buf.push_back(static_cast<uint8_t>(val & 0x7F) | 0x80);
        val >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(val));

    // Varint encode: script length
    uint64_t slen = coin.scriptPubKey.m_data.size();
    while (slen >= 0x80) {
        buf.push_back(static_cast<uint8_t>(slen & 0x7F) | 0x80);
        slen >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(slen));

    // Script bytes
    buf.insert(buf.end(), coin.scriptPubKey.m_data.begin(), coin.scriptPubKey.m_data.end());
    return buf;
}

/// Deserialize a Coin from bytes. Returns false if data is malformed.
inline bool deserialize_coin(const uint8_t* data, size_t len, Coin& coin) {
    size_t pos = 0;

    // Read varint: code = height*2 + coinbase
    uint64_t code = 0;
    unsigned shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        code |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) return false;
    }
    coin.coinbase = (code & 1) != 0;
    coin.height = static_cast<uint32_t>(code >> 1);

    // Read varint: value
    uint64_t val = 0;
    shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        val |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) return false;
    }
    coin.value = static_cast<int64_t>(val);

    // Read varint: script length
    uint64_t slen = 0;
    shift = 0;
    while (pos < len) {
        uint8_t b = data[pos++];
        slen |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) return false;
    }
    if (pos + slen > len) return false;

    // Read script bytes
    coin.scriptPubKey.m_data.assign(data + pos, data + pos + slen);
    return true;
}

inline bool deserialize_coin(const std::vector<uint8_t>& data, Coin& coin) {
    return deserialize_coin(data.data(), data.size(), coin);
}

// ─── BlockUndo ───────────────────────────────────────────────────────────────

/// Undo data for a single transaction: the coins that were spent by its inputs.
/// Used to reverse a block connection (reorg support).
/// Reference: Litecoin Core CTxUndo
struct TxUndo {
    std::vector<Coin> spent_coins;  // coins consumed by this tx's inputs (in order)
};

/// Undo data for an entire block: one TxUndo per non-coinbase transaction.
/// Reference: Litecoin Core CBlockUndo
struct BlockUndo {
    std::vector<TxUndo> tx_undos;  // one per non-coinbase tx, in block order
};

/// Serialize BlockUndo to bytes.
inline std::vector<uint8_t> serialize_block_undo(const BlockUndo& undo) {
    std::vector<uint8_t> buf;
    buf.reserve(1024);

    // Number of tx undos (varint)
    uint64_t n = undo.tx_undos.size();
    while (n >= 0x80) { buf.push_back(uint8_t(n & 0x7F) | 0x80); n >>= 7; }
    buf.push_back(uint8_t(n));

    for (const auto& tu : undo.tx_undos) {
        // Number of spent coins (varint)
        uint64_t nc = tu.spent_coins.size();
        while (nc >= 0x80) { buf.push_back(uint8_t(nc & 0x7F) | 0x80); nc >>= 7; }
        buf.push_back(uint8_t(nc));

        for (const auto& c : tu.spent_coins) {
            auto cb = serialize_coin(c);
            buf.insert(buf.end(), cb.begin(), cb.end());
        }
    }
    return buf;
}

/// Deserialize BlockUndo from bytes.
inline bool deserialize_block_undo(const uint8_t* data, size_t len, BlockUndo& undo) {
    size_t pos = 0;
    auto read_varint = [&]() -> uint64_t {
        uint64_t v = 0;
        unsigned s = 0;
        while (pos < len) {
            uint8_t b = data[pos++];
            v |= uint64_t(b & 0x7F) << s;
            if (!(b & 0x80)) return v;
            s += 7;
            if (s > 63) return 0;
        }
        return v;
    };

    uint64_t n_txs = read_varint();
    undo.tx_undos.resize(static_cast<size_t>(n_txs));

    for (auto& tu : undo.tx_undos) {
        uint64_t n_coins = read_varint();
        tu.spent_coins.resize(static_cast<size_t>(n_coins));

        for (auto& c : tu.spent_coins) {
            // Each coin starts at current pos — need to find its end
            size_t start = pos;
            // Deserialize coin from remaining buffer
            if (!deserialize_coin(data + pos, len - pos, c))
                return false;
            // Advance pos past this coin's data
            // Re-serialize to get the exact byte count (simple approach)
            auto re = serialize_coin(c);
            pos += re.size();
        }
    }
    return true;
}

inline bool deserialize_block_undo(const std::vector<uint8_t>& data, BlockUndo& undo) {
    return deserialize_block_undo(data.data(), data.size(), undo);
}

} // namespace coin
} // namespace core
