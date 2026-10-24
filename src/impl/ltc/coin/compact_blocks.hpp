// SPDX-License-Identifier: AGPL-3.0-or-later
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
///
/// Litecoin v3 (MWEB) appends the extension block after the prefilled txs:
///   ... | presence (u8, 0 or 1) | [if 1] mw::Block (Header + TxBody)
/// and prefills the HogEx as the LAST transaction (litecoind
/// blockencodings.cpp CBlockHeaderAndShortTxIDs). A v1/v2 stream ends after
/// the prefilled txs.

#include "block.hpp"
#include "transaction.hpp"
#include "mempool.hpp"  // compute_txid()

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/siphash.h>

#include <algorithm>
#include <cstdint>
#include <ios>
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
    /// litecoind refuses a cmpctblock whose BlockTxCount() exceeds 16 bits
    /// (blockencodings.h "indexes overflowed 16 bits").
    static constexpr uint64_t MAX_TX_COUNT = 65535;

    BlockHeaderType header;
    uint64_t nonce{0};
    std::vector<ShortTxID> short_ids;
    std::vector<PrefilledTransaction> prefilled_txns;
    /// 3 when the stream carried the MWEB field (Litecoin v3), else 2.
    uint8_t cmpct_version{2};
    /// The serialized mw::Block (Header + TxBody) without the presence byte;
    /// empty when the field is absent (v2) or null (presence 0).
    std::vector<unsigned char> mweb_raw;

    size_t BlockTxCount() const { return short_ids.size() + prefilled_txns.size(); }

    /// BIP 152 SipHash keys: k0/k1 are the first two little-endian 64-bit
    /// words of a SINGLE SHA256 over the serialized header followed by the
    /// nonce (litecoind CBlockHeaderAndShortTxIDs::FillShortTxIDSelector).
    void GetSipHashKeys(uint64_t& k0, uint64_t& k1) const {
        PackStream ps;
        ps << header;
        ps << nonce;
        auto sp = ps.get_span();
        uint256 h;
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(sp.data()), sp.size())
            .Finalize(h.data());
        k0 = h.GetUint64(0);
        k1 = h.GetUint64(1);
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

        // v3 (Litecoin MWEB): the OptionalPtr presence byte + mw::Block.
        if (cmpct_version >= 3) {
            uint8_t presence = mweb_raw.empty() ? 0 : 1;
            ::Serialize(s, presence);
            if (presence) {
                s.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(mweb_raw.data()), mweb_raw.size()));
            }
        }
    }

    /// Deserialize from BIP 152 HeaderAndShortIDs wire format.
    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, header);
        ::Unserialize(s, nonce);

        // Short IDs. Bound the counts before allocating: litecoind refuses
        // more than 65535 txs per compact block.
        uint64_t n_short_ids = ReadCompactSize(s);
        if (n_short_ids > MAX_TX_COUNT)
            throw std::ios_base::failure("cmpctblock: short id count overflows 16 bits");
        short_ids.resize(n_short_ids);
        for (auto& sid : short_ids)
            sid.Unserialize(s);

        // Prefilled txns (differential index decoding)
        uint64_t n_prefilled = ReadCompactSize(s);
        if (n_prefilled > MAX_TX_COUNT - n_short_ids)
            throw std::ios_base::failure("cmpctblock: indexes overflowed 16 bits");
        prefilled_txns.resize(n_prefilled);
        uint64_t prev_index = 0;
        for (size_t i = 0; i < n_prefilled; ++i) {
            uint64_t diff = ReadCompactSize(s);
            uint64_t index = (i == 0) ? diff : (prev_index + diff + 1);
            if (index > MAX_TX_COUNT)
                throw std::ios_base::failure("cmpctblock: prefilled index overflowed 16 bits");
            prefilled_txns[i].index = static_cast<uint32_t>(index);
            UnserializeTransaction(prefilled_txns[i].tx, s, TX_WITH_WITNESS);
            prev_index = index;
        }

        // v3 (Litecoin MWEB) tail. The field is LAST in the message, so any
        // byte left after the prefilled txs is the presence byte; a v1/v2
        // stream has none.
        cmpct_version = 2;
        mweb_raw.clear();
        if constexpr (requires { s.cursor_size(); }) {
            if (s.cursor_size() > 0) {
                cmpct_version = 3;
                uint8_t presence = 0;
                ::Unserialize(s, presence);
                if (presence == 1) {
                    const size_t remaining = s.cursor_size();
                    if (remaining == 0)
                        throw std::ios_base::failure("cmpctblock: MWEB presence 1 without an mw::Block");
                    mweb_raw.resize(remaining);
                    s.read(std::span<std::byte>(
                        reinterpret_cast<std::byte*>(mweb_raw.data()), remaining));
                } else if (presence != 0) {
                    throw std::ios_base::failure("cmpctblock: bad MWEB presence byte");
                }
            }
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

/// Build a v3 (Litecoin MWEB) compact block the way litecoind does
/// (blockencodings.cpp CBlockHeaderAndShortTxIDs): the coinbase prefilled at
/// 0, the HogEx (when the block has one) prefilled as the LAST transaction,
/// short ids by wtxid for every other transaction, and the block's mw::Block
/// as the MWEB field. litecoind prefills the HogEx when the block carries an
/// mweb block; a block whose last tx is a HogEx always does.
inline CompactBlock BuildCompactBlockV3(const BlockType& block, uint64_t nonce = 0)
{
    CompactBlock cb;
    cb.header = static_cast<const BlockHeaderType&>(block);
    cb.nonce = nonce;
    cb.cmpct_version = 3;
    if (block.m_txs.empty())
        return cb;

    cb.prefilled_txns.push_back(PrefilledTransaction{0, block.m_txs[0]});

    uint64_t k0, k1;
    cb.GetSipHashKeys(k0, k1);
    for (size_t i = 1; i < block.m_txs.size(); ++i) {
        const auto& tx = block.m_txs[i];
        if (tx.m_hogEx)
            continue;
        auto packed = pack(TX_WITH_WITNESS(tx));
        cb.short_ids.push_back(CompactBlock::GetShortID(k0, k1, Hash(packed.get_span())));
    }
    if (block.m_txs.size() >= 2 && block.m_txs.back().m_hogEx) {
        cb.prefilled_txns.push_back(PrefilledTransaction{
            static_cast<uint32_t>(block.m_txs.size() - 1), block.m_txs.back()});
        cb.mweb_raw = block.m_mweb_raw;
    }
    return cb;
}

// ─── MWEB (Litecoin v3) ──────────────────────────────────────────────────────

/// The HogEx of a v3 compact block: the LAST prefilled transaction, at the
/// last block index, flagged as a HogEx — and no other prefilled tx may be a
/// HogEx. nullptr otherwise (the caller falls back to a full block).
inline const MutableTransaction* hogex_from_cmpct(const CompactBlock& cb)
{
    const size_t total = cb.BlockTxCount();
    const MutableTransaction* found = nullptr;
    for (size_t i = 0; i < cb.prefilled_txns.size(); ++i) {
        const auto& pt = cb.prefilled_txns[i];
        if (!pt.tx.m_hogEx)
            continue;
        if (i + 1 != cb.prefilled_txns.size() || static_cast<size_t>(pt.index) + 1 != total)
            return nullptr;  // a HogEx anywhere but the last slot
        found = &pt.tx;
    }
    return found;
}

/// What to do with a received compact block for MWEB state.
enum class CmpctFallback { None, FullBlock };

struct CmpctMwebVerdict {
    CmpctFallback fallback{CmpctFallback::None};
    const char*   reason{""};
};

/// Decide whether a compact block can yield MWEB state through reconstruction
/// or the block must be fetched in full (MSG_MWEB_BLOCK). The HogEx and the
/// MWEB field come together; once MWEB is active a block without them cannot
/// be complete. Pure: the decision the coin-side handler acts on.
inline CmpctMwebVerdict cmpct_mweb_verdict(const CompactBlock& cb, bool mweb_active)
{
    const MutableTransaction* hogex = hogex_from_cmpct(cb);
    bool any_hogex = false;
    for (const auto& pt : cb.prefilled_txns)
        any_hogex = any_hogex || pt.tx.m_hogEx;

    if (any_hogex && !hogex)
        return {CmpctFallback::FullBlock, "hogex-not-last"};
    if (hogex && cb.mweb_raw.empty())
        return {CmpctFallback::FullBlock, "mweb-absent"};
    if (!hogex && !cb.mweb_raw.empty())
        return {CmpctFallback::FullBlock, "no-hogex-prefill"};
    if (mweb_active && !hogex) {
        if (cb.cmpct_version < 3)
            return {CmpctFallback::FullBlock, "not-v3"};
        return {CmpctFallback::FullBlock, "mweb-absent"};
    }
    return {};
}

/// One sendcmpct announcement.
struct CmpctAnnounce {
    bool     high_bandwidth{false};
    uint64_t version{2};
};

/// The sendcmpct messages to send after verack, in order. litecoind locks a
/// peer's compact-block version on the FIRST sendcmpct it accepts and takes
/// the announce (high-bandwidth) bit only from a message of the locked
/// version (net_processing.cpp SENDCMPCT). So v3 goes first: an MWEB peer
/// locks v3 (with the requested bandwidth mode) and ignores the v2 that
/// follows; a non-MWEB peer ignores v3 and locks v2, exactly as before.
/// version < 3 announces v2 low-bandwidth only.
inline std::vector<CmpctAnnounce> cmpct_announcements(uint64_t version, bool high_bandwidth)
{
    if (version >= 3)
        return {CmpctAnnounce{high_bandwidth, 3}, CmpctAnnounce{false, 2}};
    return {CmpctAnnounce{false, 2}};
}

/// How a full block reached the node.
enum class BlockSource : uint8_t {
    Block,               // a "block" message (getdata answer or unsolicited)
    CmpctReconstructed,  // cmpctblock reconstructed from the mempool
    CmpctBlocktxn,       // cmpctblock completed via getblocktxn/blocktxn
};

/// The coin-side decision for a received compact block.
enum class CmpctAction {
    Reconstruct,  // reconstruct (mempool, then getblocktxn)
    FetchFull,    // ask this peer for the full block (MSG_MWEB_BLOCK) instead
    Drop,         // ignore (duplicate, or the header does not connect)
};

/// What the P2P node did with a compact block it reconstructed.
enum class CmpctOutcome {
    Reconstructed,       // complete from the mempool, merkle ok, delivered
    AwaitingBlocktxn,    // getblocktxn sent
    BlocktxnCompleted,   // completed via blocktxn, merkle ok, delivered
    MerkleMismatch,      // discarded, full block requested
    Invalid,             // malformed, full block requested
};

// ─── Relay mode ──────────────────────────────────────────────────────────────

/// How to relay a block we found to one peer.
enum class RelayMode { Full, Compact };

/// A peer may send several sendcmpct messages (litecoind sends v3, v2, v1 in
/// that order). Keep the highest version it announced, not the last one.
inline uint64_t fold_cmpct_version(uint64_t current, uint64_t announced) {
    return std::max(current, announced);
}

/// NODE_MWEB service bit (litecoind).
constexpr uint64_t NODE_MWEB_SERVICE = 1ULL << 24;

/// The compact-block version our relay decision uses for a peer. An MWEB peer
/// (litecoind) announces v3, v2, v1: use the highest. Every other chain that
/// shares this P2P node (DOGE, NMC) keeps the last announced version, exactly
/// as before, so their relay does not change.
inline uint64_t relay_cmpct_version(uint64_t peer_services,
                                    uint64_t last_announced,
                                    uint64_t highest_announced) {
    return (peer_services & NODE_MWEB_SERVICE) ? highest_announced : last_announced;
}

/// True when the block's last transaction is the MWEB HogEx.
inline bool block_has_hogex(const BlockType& block) {
    return !block.m_txs.empty() && block.m_txs.back().m_hogEx;
}

/// Relay mode for a block to a peer whose highest sendcmpct version is
/// peer_cmpct_version. Our CompactBlock is the v2 (BIP 152 witness) encoding,
/// which has no room for the MWEB extension block: after MWEB activation
/// litecoind drops a v1/v2 cmpctblock and never sees the block. A HogEx block
/// therefore always goes out as a full block, which carries "01" + mweb. A
/// compact block is sent only to a v2 peer and only for a block without a
/// HogEx (v3 is not announced or encoded here). Outside Litecoin, BIP 152
/// versions are 1 and 2 only, so "== 2" is the old ">= 2" gate there.
inline RelayMode relay_mode_for(uint64_t peer_cmpct_version, const BlockType& block) {
    if (block_has_hogex(block))
        return RelayMode::Full;
    return peer_cmpct_version == 2 ? RelayMode::Compact : RelayMode::Full;
}

// ─── Reconstruction ─────────────────────────────────────────────────────────

/// Result of attempting to reconstruct a full block from a compact block.
struct CompactBlockReconstructionResult {
    bool complete{false};
    bool merkle_mismatch{false};  // reconstructed txs failed the header Merkle check -> DISCARD, never deliver
    bool invalid{false};          // malformed compact block / blocktxn -> DISCARD, fetch the full block
    BlockType block;
    std::vector<uint32_t> missing_indexes;  // absolute tx indexes still needed
    /// Incomplete: the slot-aligned txs placed so far (prefilled + mempool
    /// matches), kept so a blocktxn answer fills exactly the missing slots.
    std::vector<MutableTransaction> partial_txs;
};

/// Compute the SHA256d Merkle root over a block's transaction vector (txid-based).
/// Mirrors template_builder::compute_merkle_root; kept self-contained here so this
/// lightweight wire header need not pull the heavy template_builder include chain.
inline uint256 ComputeTxMerkleRoot(const std::vector<MutableTransaction>& txs) {
    if (txs.empty()) return uint256::ZERO;
    std::vector<uint256> hashes;
    hashes.reserve(txs.size());
    for (const auto& tx : txs)
        hashes.push_back(compute_txid(tx));
    while (hashes.size() > 1) {
        if (hashes.size() & 1u)
            hashes.push_back(hashes.back());  // duplicate last for odd count
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2) {
            auto sl = std::span<const uint8_t>(hashes[i].data(),     32);
            auto sr = std::span<const uint8_t>(hashes[i + 1].data(), 32);
            next.push_back(Hash(sl, sr));
        }
        hashes = std::move(next);
    }
    return hashes[0];
}

/// The MWEB field a reconstructed block carries: the compact block's mw::Block,
/// but only when its HogEx is prefilled as the last transaction. litecoind
/// sends the two together; a tail without the prefilled HogEx is not trusted
/// to belong to the block (the caller falls back to a full block).
inline std::vector<unsigned char> mweb_for_reconstruction(const CompactBlock& cb)
{
    if (cb.mweb_raw.empty() || !hogex_from_cmpct(cb))
        return {};
    return cb.mweb_raw;
}

/// Attempt to reconstruct a full block from a compact block + known transactions.
/// @param cb        The received compact block.
/// @param known_txs Map of wtxid → transaction (BIP 152 v2 uses wtxid for short ID matching).
/// @return          Result with reconstructed block (if complete) or missing indexes.
/// A complete block passed the header Merkle check and carries the v3 MWEB
/// field (see mweb_for_reconstruction) as m_mweb_raw.
inline CompactBlockReconstructionResult ReconstructBlock(
    const CompactBlock& cb,
    const std::map<uint256, MutableTransaction>& known_txs)
{
    CompactBlockReconstructionResult result;

    // Total transaction count = short_ids + prefilled
    size_t total_txs = cb.short_ids.size() + cb.prefilled_txns.size();
    if (total_txs == 0 || total_txs > CompactBlock::MAX_TX_COUNT) {
        result.invalid = true;
        return result;
    }

    // Build transaction array
    std::vector<MutableTransaction> txs(total_txs);
    std::vector<bool> filled(total_txs, false);

    // Place prefilled transactions
    for (const auto& pt : cb.prefilled_txns) {
        if (pt.index >= total_txs || filled[pt.index]) {
            // Invalid index — reconstruction fails
            result.complete = false;
            result.invalid = true;
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
            result.invalid = true;
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
        // BIP 152: a filled short-ID slot is NOT proof of correctness. Short IDs are
        // 48-bit SipHash, so a collision can silently substitute the wrong tx. The
        // header Merkle root is the ONLY backstop (Core tolerates mempool-based
        // reconstruction only because of it) -- verify BEFORE delivery, and on
        // mismatch DISCARD so the caller falls back to a full getdata/getblocktxn.
        if (ComputeTxMerkleRoot(txs) != cb.header.m_merkle_root) {
            result.complete = false;
            result.merkle_mismatch = true;
            return result;
        }
        result.complete = true;
        static_cast<BlockHeaderType&>(result.block) = cb.header;
        result.block.m_txs = std::move(txs);
        result.block.m_mweb_raw = mweb_for_reconstruction(cb);
    } else {
        result.partial_txs = std::move(txs);
    }

    return result;
}

/// Complete a compact block from a blocktxn answer: `partial` is the
/// incomplete ReconstructBlock result for `cb`, `missing_txs` the txs the
/// peer returned for partial.missing_indexes (same order). Same contract as
/// ReconstructBlock: the header Merkle root is verified before delivery and
/// the complete block carries the v3 MWEB field.
inline CompactBlockReconstructionResult FillBlockFromBlocktxn(
    const CompactBlock& cb,
    const CompactBlockReconstructionResult& partial,
    const std::vector<MutableTransaction>& missing_txs)
{
    CompactBlockReconstructionResult result;
    const size_t total_txs = cb.BlockTxCount();
    if (missing_txs.size() != partial.missing_indexes.size()
        || partial.partial_txs.size() != total_txs) {
        result.invalid = true;
        return result;
    }
    std::vector<MutableTransaction> txs = partial.partial_txs;
    for (size_t i = 0; i < partial.missing_indexes.size(); ++i) {
        const uint32_t idx = partial.missing_indexes[i];
        if (idx >= total_txs) {
            result.invalid = true;
            return result;
        }
        txs[idx] = missing_txs[i];
    }
    if (ComputeTxMerkleRoot(txs) != cb.header.m_merkle_root) {
        result.merkle_mismatch = true;
        return result;
    }
    result.complete = true;
    static_cast<BlockHeaderType&>(result.block) = cb.header;
    result.block.m_txs = std::move(txs);
    result.block.m_mweb_raw = mweb_for_reconstruction(cb);
    return result;
}

} // namespace coin
} // namespace ltc