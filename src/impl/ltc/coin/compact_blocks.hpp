#pragma once

/// BIP 152 Compact Block Support
///
/// Data structures for compact block relay.
/// Reduces block relay bandwidth by ~90-95%.

#include "block.hpp"
#include "transaction.hpp"

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
    bool operator==(const ShortTxID& o) const { return std::memcmp(data, o.data, 6) == 0; }
    bool operator<(const ShortTxID& o) const { return std::memcmp(data, o.data, 6) < 0; }
};

// ─── Prefilled Transaction ───────────────────────────────────────────────────

struct PrefilledTransaction {
    uint32_t index{0};
    MutableTransaction tx;
};

// ─── Compact Block ───────────────────────────────────────────────────────────

struct CompactBlock {
    BlockHeaderType header;
    uint64_t nonce{0};
    std::vector<ShortTxID> short_ids;
    std::vector<PrefilledTransaction> prefilled_txns;

    /// Compute SipHash short ID for a txid using this block's key.
    ShortTxID GetShortID(const uint256& txid) const {
        auto packed = pack(header);
        uint256 hdr_hash = Hash(packed.get_span());
        uint64_t k0 = hdr_hash.GetUint64(0) ^ nonce;
        uint64_t k1 = hdr_hash.GetUint64(1) ^ nonce;
        uint64_t h = SipHashUint256(k0, k1, txid);
        return ShortTxID(h & 0xFFFFFFFFFFFFULL);
    }
};

// ─── Block Transactions Request ──────────────────────────────────────────────

struct BlockTransactionsRequest {
    uint256 blockhash;
    std::vector<uint32_t> indexes;
};

// ─── Block Transactions Response ─────────────────────────────────────────────

struct BlockTransactionsResponse {
    uint256 blockhash;
    std::vector<MutableTransaction> txs;
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

    // Coinbase always prefilled
    if (!txs.empty()) {
        PrefilledTransaction pt;
        pt.index = 0;
        pt.tx = txs[0];
        cb.prefilled_txns.push_back(std::move(pt));
    }

    // Remaining txs as short IDs
    for (size_t i = 1; i < txs.size(); ++i) {
        uint256 txid = compute_txid(txs[i]);
        cb.short_ids.push_back(cb.GetShortID(txid));
    }

    return cb;
}

} // namespace coin
} // namespace ltc
