// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// xmr_block_template.hpp -- whole-block Monero template builder (Family B).
//
// PROVENANCE: clean-room from Monero-core v0.18.5.1 (monero-project/monero,
// BSD-3-Clause: the block and transaction wire format, get_block_hashing_blob,
// calculate_transaction_hash, get_block_reward and the tx-pool template fill
// rule) and the public RPC/ZMQ/stratum/CryptoNote protocol; not derived from
// p2pool. The interface is the one the c2pool callers use (xmr_block_assembly.hpp,
// the o2 settlement source, the template KATs); the behaviour is what those
// callers and the KATs pin.
//
// What a template is
//   One Monero block for one parent (prev_id, height): a header, a v2 coinbase
//   (miner) transaction whose outputs and keys come from an IXmrSettlementSource,
//   and a list of mempool transaction ids. For each 32-bit extra nonce the
//   builder produces
//     * the hashing blob   header || tree_root || varint(n_tx + 1)   (RandomX input)
//     * the block blob     header || miner_tx || varint(n_tx) || n_tx * 32-byte id
//   Both share the header byte for byte; the 4-byte header nonce is zero.
//
// Miner transaction layout (CryptoNote v2, RCTTypeNull)
//   varint(2) varint(height + 60) 01 ff varint(height) varint(n) n * output
//   varint(extra_len) extra 00
//   output = varint(amount) 03 one_time_key[32] view_tag[1]        (tagged key)
//   extra  = 01 R[32]
//            02 varint(len) [worker nonce LE32 | bind | zero pad | tail]
//            03 varint(len) varint(merkle_tree_data) root[32]       (last field)
//
// Weight invariance
//   The block reward depends on the block weight, which includes the miner
//   transaction, whose output amounts depend on the reward. update() sizes the
//   miner transaction with the settlement source's SIZING amounts, selects the
//   transactions and computes the final reward against that weight, then asks
//   for the FINAL amounts and pads the extra nonce by exactly the bytes the
//   amount varints shrank, so the final transaction has the weight the reward
//   was computed for. If that cannot be made to hold (pad out of range, or a
//   length varint changes size) update() re-sizes once with the final amounts;
//   if it still cannot hold, update() leaves the previous template in place.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <shared_mutex>
#include <vector>

#include "xmr_coin_primitives.hpp"   // hash, difficulty_type, HASH_SIZE

namespace c2pool::xmr {

inline constexpr std::size_t NONCE_SIZE            = 4;     // block header nonce
inline constexpr std::size_t EXTRA_NONCE_SIZE      = 4;     // worker nonce (LE32) in the 0x02 field
inline constexpr std::size_t EXTRA_NONCE_MAX_SIZE  = EXTRA_NONCE_SIZE + 10;  // worker nonce + weight pad
inline constexpr std::size_t EXTRA_NONCE_BIND_MAX  = 32;    // per-job binding after the worker nonce
inline constexpr std::size_t TX_EXTRA_NONCE_MAX    = 255;   // Monero TX_EXTRA_NONCE_MAX_COUNT
inline constexpr std::size_t HASHING_BLOB_MIN_SIZE = 76;    // v16 header with a 5-byte timestamp
inline constexpr std::size_t HASHING_BLOB_MAX_SIZE = 128;
inline constexpr std::size_t MAX_BLOCK_TEMPLATE_BLOB = 128 * 1024;   // whole block blob cap
inline constexpr std::uint64_t BASE_BLOCK_REWARD   = 600000000000ULL; // tail emission, 0.6 XMR per 2-min block
inline constexpr std::uint8_t HARDFORK_SUPPORTED_VERSION = 16;        // pre-CARROT
inline constexpr std::uint64_t MEMPOOL_MIN_AGE_SECONDS = 5;           // default path only

// CryptoNote coinbase wire constants (Monero cryptonote_basic / tx_extra.h).
inline constexpr std::uint64_t TX_VERSION                = 2;      // RingCT-era transaction
inline constexpr std::uint8_t  TXIN_GEN                  = 0xFF;   // coinbase input tag
inline constexpr std::uint64_t MINER_REWARD_UNLOCK_TIME  = 60;     // CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
inline constexpr std::uint8_t  TXOUT_TO_TAGGED_KEY       = 0x03;   // output with view tag (since HF15)
inline constexpr std::uint8_t  TX_EXTRA_TAG_PUBKEY       = 0x01;
inline constexpr std::uint8_t  TX_EXTRA_NONCE            = 0x02;
inline constexpr std::uint8_t  TX_EXTRA_MERGE_MINING_TAG = 0x03;

// Parent context, as monerod's get_miner_data reports it.
struct XmrMinerData {
    std::uint8_t    major_version = 0;
    std::uint64_t   height = 0;                 // height of the block being built
    hash            prev_id;
    hash            seed_hash;                  // RandomX key for this height
    difficulty_type difficulty;                 // network difficulty
    difficulty_type lane_target;                // share target handed to jobs
    std::uint64_t   median_weight = 0;          // effective median block weight
    std::uint64_t   already_generated_coins = 0;
    std::uint64_t   median_timestamp = 0;
};

// One mempool (or pre-selected) transaction.
struct XmrTxMempoolData {
    hash          id;
    std::uint64_t weight = 0;
    std::uint64_t fee = 0;
    std::uint64_t time_received = 0;            // unix seconds; 0 = unknown / long ago
};

// One coinbase payee: a standard address's public spend and view keys.
struct XmrPayee {
    hash spend_public_key;
    hash view_public_key;
};

// What the coinbase pays and with which keys. All methods are const and may be
// called again at job / submit time for any template built over this source.
class IXmrSettlementSource {
public:
    virtual ~IXmrSettlementSource() = default;

    virtual const std::vector<XmrPayee>& payees() const = 0;
    virtual const hash& tx_secret_key() const = 0;
    virtual const hash& tx_public_key() const = 0;           // R, the 0x01 field
    // One-time output key and view tag of payee i under fork hf_major; false refuses.
    virtual bool derive_output_key(std::size_t i, std::uint8_t hf_major,
                                   hash& out_eph_pubkey, std::uint8_t& out_view_tag) const = 0;
    // Exact-sum amounts for `reward`, one per payee; false refuses.
    // update() calls it first as a SIZING pass, then with each real reward.
    virtual bool split_reward(std::uint64_t reward, std::vector<std::uint64_t>& rewards) const = 0;
    // The 32-byte root carried in the 0x03 field for this extra nonce.
    virtual hash commitment_leaf(std::uint32_t extra_nonce) const = 0;
    // The varint written before that root in the 0x03 field.
    virtual std::uint64_t merkle_tree_data() const = 0;

    // Bytes appended to the 0x02 payload after the padded worker nonce.
    virtual std::vector<std::uint8_t> extra_nonce_tail() const { return {}; }
    // Size of the per-job binding written right after the worker nonce (<= EXTRA_NONCE_BIND_MAX).
    virtual std::size_t extra_nonce_bind_size() const { return 0; }
    virtual bool extra_nonce_bind(std::uint32_t /*extra_nonce*/, std::uint8_t* /*out*/) const { return false; }
};

class XmrBlockTemplate {
public:
    explicit XmrBlockTemplate(const IXmrSettlementSource* seam);
    ~XmrBlockTemplate();
    XmrBlockTemplate(const XmrBlockTemplate&) = delete;
    XmrBlockTemplate& operator=(const XmrBlockTemplate&) = delete;

    // Build a new template. On success the template id advances and the
    // previous templates stay resolvable by id. On any refusal the previous
    // template (possibly none) stays in place and last_updated() is unchanged.
    // take_mempool_as_given: mine `mempool` in the given order (no age gate,
    // no re-selection); only the block-blob size cap still applies.
    void update(const XmrMinerData& data, const std::vector<XmrTxMempoolData>& mempool,
                bool take_mempool_as_given = false);

    std::uint64_t   get_reward() const;
    std::uint64_t   get_height() const;
    difficulty_type get_lane_target() const;
    std::uint64_t   last_updated() const;      // unix seconds of the last successful update; 0 = never

    // Hashing blob of the CURRENT template for one extra nonce. `blob` must hold
    // HASHING_BLOB_MAX_SIZE bytes. Returns its length (0 if there is no template).
    std::uint32_t get_hashing_blob(std::uint32_t extra_nonce, std::uint8_t* blob,
                                   std::uint64_t& height, difficulty_type& lane_target,
                                   hash& seed_hash, std::size_t& nonce_offset,
                                   std::uint32_t& template_id) const;

    // `count` consecutive extra nonces from `extra_nonce_start`, concatenated.
    // Returns the length of one blob.
    std::uint32_t get_hashing_blobs(std::uint32_t extra_nonce_start, std::uint32_t count,
                                    std::vector<std::uint8_t>& blobs,
                                    std::uint64_t& height, difficulty_type& lane_target,
                                    hash& seed_hash, std::size_t& nonce_offset,
                                    std::uint32_t& template_id) const;

    // Full block blob of template `template_id` (current or a kept previous one).
    // Offsets: header nonce, first byte of the 0x02 payload, first byte of the
    // 0x03 root. Empty when the id is unknown.
    std::vector<std::uint8_t> get_block_template_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                                                      std::size_t& nonce_offset, std::size_t& extra_nonce_offset,
                                                      std::size_t& merkle_root_offset, hash& merkle_root) const;

    struct Snapshot;   // one built template (defined in the .cpp)

private:
    static constexpr std::size_t kKeepPrevious = 7;

    std::shared_ptr<const Snapshot> current() const;
    std::shared_ptr<const Snapshot> find(std::uint32_t template_id) const;

    const IXmrSettlementSource* m_seam;
    mutable std::shared_mutex m_lock;
    std::shared_ptr<const Snapshot> m_current;
    std::deque<std::shared_ptr<const Snapshot>> m_previous;   // newest first
    std::uint32_t m_next_id = 1;
    std::uint64_t m_last_updated = 0;
};

} // namespace c2pool::xmr
