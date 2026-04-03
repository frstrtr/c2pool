#pragma once

/// BIP 152 Compact Block Support
///
/// Data structures and wire-format serialization for compact block relay.
/// Reduces block relay bandwidth by ~90-95%.
///
/// Wire format (HeaderAndShortIDs):
///   block_header (80 bytes) | nonce (uint64) |
///   shortids_length (compact) | shortids[] (6 bytes each) |
///   prefilledtxn_length (compact) | prefilledtxn[] { diff_index (compact), tx }
///
/// Prefilled transaction indexes use differential encoding:
///   first index is absolute; subsequent = (delta from previous + 1).

#include "block.hpp"
#include "transaction.hpp"
#include "mempool.hpp"  // compute_txid()

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <btclibs/crypto/siphash.h>

#include <cstdint>
#include <vector>
#include <map>

namespace ltc {
namespace coin {

// ─── Short Transaction ID (6 bytes) ─────────────────────────────────────────

struct ShortTxID {
    uint8_t data[6]{};

    ShortTxID() = default;
    explicit ShortTxID(uint64_t v) {
        for (int i = 0; i < 6; ++i) data[i] = static_cast<uint8_t>((v >> (i*8)) & 0xff);
    }
    uint64_t to_uint64() const {
        uint64_t v = 0;
        for (int i = 0; i < 6; ++i) v |= static_cast<uint64_t>(data[i]) << (i*8);
        return v;
    }
    bool operator==(const ShortTxID& o) const { return std::memcmp(data, o.data, 6) == 0; }
    bool operator<(const ShortTxID& o) const { return std::memcmp(data, o.data, 6) < 0; }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s.write(std::as_bytes(std::span{data, 6}));
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        s.read(std::as_writable_bytes(std::span{data, 6}));
    }
};

// ─── Prefilled Transaction ───────────────────────────────────────────────────

struct PrefilledTransaction {
    uint32_t index{0};  // absolute index in block (differential on wire)
    MutableTransaction tx;
};

// ─── Compact Block (HeaderAndShortIDs) ──────────────────────────────────────

struct CompactBlock {
    BlockHeaderType header;
    uint64_t nonce{0};
    std::vector<ShortTxID> short_ids;
    std::vector<PrefilledTransaction> prefilled_txns;

    /// Compute SipHash keys from header hash and nonce.
    void GetSipHashKeys(uint64_t& k0, uint64_t& k1) const {
        auto packed = pack(header);
        uint256 hdr_hash = Hash(packed.get_span());
        k0 = hdr_hash.GetUint64(0) ^ nonce;
        k1 = hdr_hash.GetUint64(1) ^ nonce;
    }

    /// Compute SipHash short ID for a txid using this block's key.
    ShortTxID GetShortID(const uint256& txid) const {
        uint64_t k0, k1;
        GetSipHashKeys(k0, k1);
        uint64_t h = SipHashUint256(k0, k1, txid);
        return ShortTxID(h & 0xFFFFFFFFFFFFULL);
    }

    /// Compute SipHash short ID with pre-computed keys (for batch lookups).
    static ShortTxID GetShortID(uint64_t k0, uint64_t k1, const uint256& txid) {
        uint64_t h = SipHashUint256(k0, k1, txid);
        return ShortTxID(h & 0xFFFFFFFFFFFFULL);
    }

    /// Serialize as BIP 152 HeaderAndShortIDs wire format.
    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, header);
        ::Serialize(s, nonce);

        // Short IDs: compact_size + raw 6-byte entries
        WriteCompactSize(s, short_ids.size());
        for (const auto& sid : short_ids)
            sid.Serialize(s);

        // Prefilled txns: compact_size + differential-index-encoded entries
        WriteCompactSize(s, prefilled_txns.size());
        uint32_t prev_index = 0;
        for (size_t i = 0; i < prefilled_txns.size(); ++i) {
            const auto& pt = prefilled_txns[i];
            // BIP 152: first index is absolute, subsequent are (index - prev - 1)
            uint32_t diff = (i == 0) ? pt.index : (pt.index - prev_index - 1);
            WriteCompactSize(s, diff);
            ::Serialize(s, TX_WITH_WITNESS(pt.tx));
            prev_index = pt.index;
        }
    }

    /// Deserialize from BIP 152 HeaderAndShortIDs wire format.
    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, header);
        ::Unserialize(s, nonce);

        // Short IDs
        uint64_t n_short_ids = ReadCompactSize(s);
        short_ids.resize(n_short_ids);
        for (auto& sid : short_ids)
            sid.Unserialize(s);

        // Prefilled txns (differential index decoding)
        uint64_t n_prefilled = ReadCompactSize(s);
        prefilled_txns.resize(n_prefilled);
        uint32_t prev_index = 0;
        for (size_t i = 0; i < n_prefilled; ++i) {
            uint32_t diff = static_cast<uint32_t>(ReadCompactSize(s));
            prefilled_txns[i].index = (i == 0) ? diff : (prev_index + diff + 1);
            UnserializeTransaction(prefilled_txns[i].tx, s, TX_WITH_WITNESS);
            prev_index = prefilled_txns[i].index;
        }
    }
};

// ─── Block Transactions Request (getblocktxn) ──────────────────────────────

struct BlockTransactionsRequest {
    uint256 blockhash;
    std::vector<uint32_t> indexes;  // absolute indexes (differential on wire)

    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, blockhash);
        WriteCompactSize(s, indexes.size());
        uint32_t prev = 0;
        for (size_t i = 0; i < indexes.size(); ++i) {
            uint32_t diff = (i == 0) ? indexes[i] : (indexes[i] - prev - 1);
            WriteCompactSize(s, diff);
            prev = indexes[i];
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, blockhash);
        uint64_t n = ReadCompactSize(s);
        indexes.resize(n);
        uint32_t prev = 0;
        for (size_t i = 0; i < n; ++i) {
            uint32_t diff = static_cast<uint32_t>(ReadCompactSize(s));
            indexes[i] = (i == 0) ? diff : (prev + diff + 1);
            prev = indexes[i];
        }
    }
};

// ─── Block Transactions Response (blocktxn) ─────────────────────────────────

struct BlockTransactionsResponse {
    uint256 blockhash;
    std::vector<MutableTransaction> txs;

    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, blockhash);
        WriteCompactSize(s, txs.size());
        for (const auto& tx : txs)
            ::Serialize(s, TX_WITH_WITNESS(tx));
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, blockhash);
        uint64_t n = ReadCompactSize(s);
        txs.resize(n);
        for (auto& tx : txs)
            UnserializeTransaction(tx, s, TX_WITH_WITNESS);
    }
};

// ─── Builder ─────────────────────────────────────────────────────────────────

/// Build a compact block from a full block header + transactions.
inline CompactBlock BuildCompactBlock(const BlockHeaderType& header,
                                       const std::vector<MutableTransaction>& txs,
                                       uint64_t nonce = 0)
{
    CompactBlock cb;
    cb.header = header;
    cb.nonce = nonce;

    // Coinbase always prefilled (index 0)
    if (!txs.empty()) {
        PrefilledTransaction pt;
        pt.index = 0;
        pt.tx = txs[0];
        cb.prefilled_txns.push_back(std::move(pt));
    }

    // Remaining txs as short IDs (pre-compute SipHash keys once)
    // BIP 152 v2: use wtxid (witness serialization hash) for short IDs.
    if (txs.size() > 1) {
        uint64_t k0, k1;
        cb.GetSipHashKeys(k0, k1);
        for (size_t i = 1; i < txs.size(); ++i) {
            auto packed = pack(TX_WITH_WITNESS(txs[i]));
            uint256 wtxid = Hash(packed.get_span());
            cb.short_ids.push_back(CompactBlock::GetShortID(k0, k1, wtxid));
        }
    }

    return cb;
}

// ─── Reconstruction ─────────────────────────────────────────────────────────

/// Result of attempting to reconstruct a full block from a compact block.
struct CompactBlockReconstructionResult {
    bool complete{false};
    BlockType block;
    std::vector<uint32_t> missing_indexes;  // absolute tx indexes still needed
};

/// Attempt to reconstruct a full block from a compact block + known transactions.
/// @param cb        The received compact block.
/// @param known_txs Map of wtxid → transaction (BIP 152 v2 uses wtxid for short ID matching).
/// @return          Result with reconstructed block (if complete) or missing indexes.
inline CompactBlockReconstructionResult ReconstructBlock(
    const CompactBlock& cb,
    const std::map<uint256, MutableTransaction>& known_txs)
{
    CompactBlockReconstructionResult result;

    // Total transaction count = short_ids + prefilled
    size_t total_txs = cb.short_ids.size() + cb.prefilled_txns.size();

    // Build transaction array
    std::vector<MutableTransaction> txs(total_txs);
    std::vector<bool> filled(total_txs, false);

    // Place prefilled transactions
    for (const auto& pt : cb.prefilled_txns) {
        if (pt.index >= total_txs) {
            // Invalid index — reconstruction fails
            result.complete = false;
            return result;
        }
        txs[pt.index] = pt.tx;
        filled[pt.index] = true;
    }

    // Build short ID → known tx lookup
    uint64_t k0, k1;
    cb.GetSipHashKeys(k0, k1);

    std::map<uint64_t, const MutableTransaction*> short_id_map;
    for (const auto& [txid, tx] : known_txs) {
        ShortTxID sid = CompactBlock::GetShortID(k0, k1, txid);
        uint64_t key = sid.to_uint64();
        // Collision detection: if two txs map to the same short ID, skip both
        if (short_id_map.count(key))
            short_id_map[key] = nullptr;  // mark collision
        else
            short_id_map[key] = &tx;
    }

    // Match short IDs to known transactions
    size_t sid_idx = 0;
    for (size_t i = 0; i < total_txs; ++i) {
        if (filled[i]) continue;

        if (sid_idx >= cb.short_ids.size()) {
            // More unfilled slots than short IDs — malformed
            result.complete = false;
            return result;
        }

        uint64_t key = cb.short_ids[sid_idx].to_uint64();
        auto it = short_id_map.find(key);
        if (it != short_id_map.end() && it->second != nullptr) {
            txs[i] = *(it->second);
            filled[i] = true;
        } else {
            result.missing_indexes.push_back(static_cast<uint32_t>(i));
        }
        ++sid_idx;
    }

    if (result.missing_indexes.empty()) {
        result.complete = true;
        static_cast<BlockHeaderType&>(result.block) = cb.header;
        result.block.m_txs = std::move(txs);
    }

    return result;
}

} // namespace coin
} // namespace ltc
