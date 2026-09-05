/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// =============================================================================
// PROVENANCE (c2pool AGPL-3.0 combines this GPLv3 code via AGPLv3 section 13).
//
//   Upstream : SChernykh/p2pool  src/block_template.h + src/block_template.cpp
//   Commit   : 128643114f9bea55bfdb95462eaeffa2e3f666bd  (master, 2026-09-05)
//   Adapted  : Monero whole-block-template PLUMBING only, for the v37 Family-B
//              XMR settlement lane (frstrtr/c2pool). Kept verbatim in behaviour:
//                * penalty-aware reward math  (get_base_reward / get_block_reward)
//                * greedy penalty-zone tx selection + reference O(N*W) knapsack
//                * miner_tx (coinbase) assembly: txin_gen, txout_to_tagged_key,
//                  tx_extra 0x01 pubkey / 0x02 nonce / 0x03 merge-mining tag
//                * v2 tx-hash triple + Keccak-midstate coinbase opening
//                * tree_hash main branch + 76-byte hashing-blob assembly
//                * per-worker extra-nonce jobs (re-serialise coinbase -> tx hash
//                  -> tree root -> blob), single job and batched
//   REMOVED  : p2pool's POOL MODEL. No SideChain, MinerShare, PoolBlock, PPLNS,
//              uncles, sidechain id, consensus id, or p2pool merge-mining aux
//              slot machinery. v37 supplies its own RDWR / work-receipts model
//              through IXmrSettlementSource below (the sharechain seam). The one
//              structural remnant of merge mining is the 0x03 tag itself: v37's
//              commitment rides there as a single MM-tree leaf (scoping S2.3,
//              "MM-tree leaf recommended"), forward-compatible with real Tari
//              aux mining that a later leg may re-enable.
//
//   FENCE    : all coinbase-output DERIVATION is pre-CARROT and pinned to the
//              Monero hard-fork major_version (see XMR_HF_MAJOR / the guard in
//              IXmrSettlementSource::derive_output_key). FCMP++/CARROT may
//              rewrite output-key derivation; if so, only the seam impl (X6)
//              changes, not this template builder.
// =============================================================================

#pragma once

#include "xmr_coin_primitives.hpp"

#include <cstdint>
#include <atomic>
#include <vector>
#include <array>
#include <random>

namespace c2pool::xmr {

// ---------------------------------------------------------------------------
// Monero consensus constants (lifted from p2pool src/common.h + src/pool_block.h,
// same upstream commit). These are Monero facts, not p2pool policy.
// ---------------------------------------------------------------------------
inline constexpr uint8_t  HARDFORK_SUPPORTED_VERSION = 16;    // pin per fork; RandomX v2 -> bump here
inline constexpr uint8_t  MINER_REWARD_UNLOCK_TIME   = 60;    // CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW => D_conf floor 60
inline constexpr uint8_t  NONCE_SIZE                 = 4;     // header miner nonce
inline constexpr uint8_t  EXTRA_NONCE_SIZE           = 4;     // per-worker extra nonce (min)
inline constexpr uint8_t  EXTRA_NONCE_MAX_SIZE       = EXTRA_NONCE_SIZE + 10; // padded to keep miner-tx weight invariant
inline constexpr uint8_t  TX_VERSION                 = 2;
inline constexpr uint8_t  TXIN_GEN                   = 0xFF;  // gen (coinbase) input tag
inline constexpr uint8_t  TXOUT_TO_TAGGED_KEY        = 3;     // output target since view-tags (HF15)
inline constexpr uint8_t  TX_EXTRA_TAG_PUBKEY        = 1;     // 0x01  R = r*G
inline constexpr uint8_t  TX_EXTRA_NONCE             = 2;     // 0x02  extra nonce (<= 255 B)
inline constexpr uint8_t  TX_EXTRA_MERGE_MINING_TAG  = 3;     // 0x03  {varint depth/nonce, 32-B root}

inline constexpr uint64_t MAX_BLOCK_SIZE        = 128 * 1024 - 5; // p2p carrier cap analogue
inline constexpr uint64_t BASE_BLOCK_REWARD     = 600000000000ULL; // 0.6 XMR tail (piconero)
inline constexpr uint64_t MAX_OUTPUT_VALUE      = (1ULL << 56) - 1;
inline constexpr uint64_t HASHING_BLOB_MIN_SIZE = 76;
inline constexpr uint64_t HASHING_BLOB_MAX_SIZE = 128;
inline constexpr uint64_t HIGH_FEE_VALUE        = 6000000000ULL;  // 0.006 XMR: take immediately, skip the 5-s mempool age gate

// TEST_KNAPSACK_ALGORITHM=1 compiles the reference O(N*W) DP next to the greedy
// heuristic so a golden test can assert the heuristic is within a micronero of
// optimal. Off in production (too slow / too much RAM on real full blocks).
#ifndef TEST_KNAPSACK_ALGORITHM
#define TEST_KNAPSACK_ALGORITHM 0
#endif

// ---------------------------------------------------------------------------
// Inputs from the monerod adapter leg (X2): get_miner_data + ZMQ backlog.
// ---------------------------------------------------------------------------
struct XmrMinerData {                 // <- monerod get_miner_data / ZMQ json-full-miner_data
    uint8_t         major_version = 0;
    uint64_t        height = 0;
    hash            prev_id;
    uint64_t        already_generated_coins = 0;
    uint64_t        median_weight = 0;        // 100-block median; penalty pivot
    uint64_t        median_timestamp = 0;
    difficulty_type difficulty;               // mainchain difficulty (info only for the builder)
    hash            seed_hash;                 // RandomX seed for this height's epoch
    difficulty_type lane_target;               // v37 T_origin for the XMR lane (share target), carried in side data
};

struct XmrTxMempoolData {             // <- monerod get_miner_data tx backlog / ZMQ txpool_add
    hash     id;                       // tx hash (a tree leaf)
    uint64_t weight = 0;               // Monero tx weight (bytes + bp+ penalty)
    uint64_t fee = 0;                  // piconero
    uint64_t time_received = 0;        // for the 5-s age gate
    // fee-per-byte order (highest first) — same predicate p2pool sorts by.
    bool operator<(const XmrTxMempoolData& o) const {
        return static_cast<__uint128_t>(fee) * o.weight > static_cast<__uint128_t>(o.fee) * weight;
    }
};

// ---------------------------------------------------------------------------
// One K_fair-ordered payee for this height. RESOLVED target only: the settlement
// leg has already turned a PayoutDescriptor (XMR_STD/XMR_SUB) into (B, A) and
// checked torsion; the builder never sees address strings (scoping S2.3).
// ---------------------------------------------------------------------------
struct XmrPayee {
    hash spend_public_key;   // B
    hash view_public_key;    // A  (or D_i/A_main for a subaddress)
};

// ===========================================================================
// v37 SETTLEMENT SEAM  (replaces p2pool SideChain).
//
// Everything below the sharechain seam is owned by the W5-XMR (X6) +
// descriptor-kinds (X3) legs, NOT this one. The template builder calls into it
// and stays pool-model-free. Every method is a pure function of committed lane
// state so that "every node computes the same coinbase" holds (scoping S2.4).
// ===========================================================================
class IXmrSettlementSource {
public:
    virtual ~IXmrSettlementSource() = default;

    // K_fair-ordered payees to settle at this height (owed >= h_min, capped by C
    // and the penalty/byte budget). Order is deterministic (age, then key).
    [[nodiscard]] virtual const std::vector<XmrPayee>& payees() const = 0;

    // Deterministic tx key. r = H(domain || lane_commitment || prev_id || height
    // || ...) re-derived and byte-checked by every node (p2pool S2.2 pattern).
    // tx_public_key() = R = r*G goes into tx_extra tag 0x01.
    [[nodiscard]] virtual const hash& tx_secret_key() const = 0;   // r
    [[nodiscard]] virtual const hash& tx_public_key() const = 0;   // R

    // Derive one-time output key P_i and its 1-byte view tag for payee i under r.
    // Monero get_eph_public_key: D = 8*r*A ; P_i = H_s(D||i)*G + B ;
    // view_tag = first byte of H("view_tag"||D||i).
    // hf_major pins the derivation to a Monero fork (pre-CARROT fence).
    [[nodiscard]] virtual bool derive_output_key(size_t i, uint8_t hf_major,
                                                 hash& out_eph_pubkey,
                                                 uint8_t& out_view_tag) const = 0;

    // Split `reward` across payees so Sum == reward EXACTLY (exact-sum rule since
    // HF13). K_fair proportional split + running truncation + mandated residual
    // sink for the unabsorbed remainder (scoping S2.3 CONS-1: no burn escape).
    // Fills `rewards` (piconero per payee, payees().size() entries).
    [[nodiscard]] virtual bool split_reward(uint64_t reward,
                                             std::vector<uint64_t>& rewards) const = 0;

    // The 32-byte v37 commitment leaf that rides in tx_extra 0x03 for a given
    // extra_nonce. Binds owed_digest / info_digest (share-format S3). For the
    // foundation this is a single MM-tree leaf, so merkle_root == leaf.
    [[nodiscard]] virtual hash commitment_leaf(uint32_t extra_nonce) const = 0;

    // Varint payload of the 0x03 merge-mining tag preceding the 32-B root.
    // Foundation: a 1-leaf tree (encodes n_chains=1). A later leg widens this
    // to re-admit Tari-style aux mining without touching the builder.
    [[nodiscard]] virtual uint64_t merkle_tree_data() const = 0;
};

// ===========================================================================
// XmrBlockTemplate  --  the whole-block template builder (X-lane, item 10).
//
// The pool assembles the ENTIRE Monero block itself; monerod's single-output
// get_block_template coinbase is not usable as-is (scoping S2.2). One update()
// per new prev_id builds the template; workers then pull per-extra-nonce jobs.
// ===========================================================================
class XmrBlockTemplate {
public:
    explicit XmrBlockTemplate(IXmrSettlementSource* settle);
    ~XmrBlockTemplate();

    XmrBlockTemplate(const XmrBlockTemplate& b);
    XmrBlockTemplate& operator=(const XmrBlockTemplate& b);

    // Rebuild the template from fresh miner data + mempool backlog.
    void update(const XmrMinerData& data, const std::vector<XmrTxMempoolData>& mempool);

    [[nodiscard]] uint64_t last_updated() const { return m_lastUpdated.load(); }
    [[nodiscard]] uint64_t get_height()   const { return m_height.load(); }
    [[nodiscard]] difficulty_type get_lane_target() const { return m_laneTarget; } // v37 T_origin
    [[nodiscard]] uint64_t get_reward()   const { return m_finalReward.load(); }

    // ---- per-worker extra-nonce jobs -------------------------------------
    // One 76-80 B RandomX hashing blob for this extra_nonce. Distinct extra_nonce
    // => distinct coinbase => distinct tx hash => distinct tree root => distinct
    // blob, so N workers grind disjoint search spaces off one template.
    //   blob        := serialize(header) || tree_root(32) || varint(n_tx+1)
    //   nonce_offset := byte offset of the 4-byte header nonce a worker mutates
    [[nodiscard]] uint32_t get_hashing_blob(uint32_t extra_nonce,
                                            uint8_t (&blob)[HASHING_BLOB_MAX_SIZE],
                                            uint64_t& height,
                                            difficulty_type& lane_target,
                                            hash& seed_hash,
                                            size_t& nonce_offset,
                                            uint32_t& template_id) const;

    // `count` consecutive blobs from `extra_nonce_start`, laid out back-to-back;
    // returns the per-blob size. Parallel-filled (see get_hashing_blobs body).
    [[nodiscard]] uint32_t get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count,
                                             std::vector<uint8_t>& blobs,
                                             uint64_t& height,
                                             difficulty_type& lane_target,
                                             hash& seed_hash,
                                             size_t& nonce_offset,
                                             uint32_t& template_id) const;

    // Re-materialise the full block-template blob for a winning (template_id,
    // extra_nonce) so it can be handed to monerod submit_block. Reports the
    // offsets a submitter patches (header nonce, extra nonce, MM root).
    [[nodiscard]] std::vector<uint8_t> get_block_template_blob(uint32_t template_id,
                                                               uint32_t extra_nonce,
                                                               size_t& nonce_offset,
                                                               size_t& extra_nonce_offset,
                                                               size_t& merkle_root_offset,
                                                               hash& merkle_root) const;

private:
    // Shallow ctor for the old-template double-buffer entries only (no recursion).
    XmrBlockTemplate(IXmrSettlementSource* settle, bool shallow);

    IXmrSettlementSource* m_settle;

    // Coinbase (miner_tx) assembly. dry_run leaves output keys zeroed and only
    // sizes the amount varints (so the two passes agree on miner-tx weight
    // before r-derivation runs). Returns <0 on failure, -3 = extra-nonce grew
    // past EXTRA_NONCE_MAX_SIZE (caller re-solves the reward, see update()).
    [[nodiscard]] int  create_miner_tx(const XmrMinerData& data,
                                       uint64_t max_reward_amounts_weight,
                                       bool dry_run);

    // Mempool -> m_mempoolTxs, with the 5-s age gate / high-fee bypass and the
    // 128 KB carrier-size safeguard.
    void select_mempool_transactions(const std::vector<XmrTxMempoolData>& mempool);

    // v2 tx hash of the coinbase for a given extra_nonce, with extra_nonce and
    // the MM commitment root patched in-place (Keccak-midstate fast path).
    [[nodiscard]] hash calc_miner_tx_hash(uint32_t extra_nonce) const;

    // tree_hash "main branch" (the coinbase-side authentication path) over the
    // non-coinbase tx hashes; used to fold the miner-tx hash up to the root.
    void calc_merkle_tree_main_branch();

    // Assemble one hashing blob for `extra_nonce` (no lock).
    [[nodiscard]] uint32_t get_hashing_blob_nolock(uint32_t extra_nonce, uint8_t* blob) const;

    void shuffle_tx_order();

#if TEST_KNAPSACK_ALGORITHM
    // Reference optimal fill (golden-test only), max_weight = median + median/8
    // - miner_tx_weight (the penalty-zone budget). Not used in production.
    void fill_optimal_knapsack(const XmrMinerData& data, uint64_t base_reward,
                               uint64_t miner_tx_weight, uint64_t& best_reward,
                               uint64_t& final_fees, uint64_t& final_weight);
    std::vector<uint32_t> m_knapsack;
#endif

    // ---- template state --------------------------------------------------
    uint32_t              m_templateId = 0;
    std::atomic<uint64_t> m_lastUpdated{0};

    std::vector<uint8_t>  m_blockTemplateBlob;  // header || miner_tx || varint(n_tx) || tx hashes
    std::vector<uint8_t>  m_merkleTreeMainBranch;

    size_t   m_blockHeaderSize = 0;
    size_t   m_minerTxOffsetInTemplate = 0;
    size_t   m_minerTxSize = 0;
    size_t   m_nonceOffset = 0;               // header nonce offset (worker-mutable)
    size_t   m_extraNonceOffsetInTemplate = 0;

    size_t          m_numTransactionHashes = 0;
    hash            m_prevId;
    std::atomic<uint64_t> m_height{0};
    difficulty_type m_laneTarget;             // v37 T_origin (was p2pool m_difficulty)
    hash            m_seedHash;
    uint64_t        m_timestamp = 0;
    uint8_t         m_majorVersion = 0;

    std::atomic<uint64_t> m_finalReward{0};
    uint32_t        m_extraNonceSize = 0;
    uint64_t        m_merkleTreeData = 0;
    size_t          m_merkleTreeDataSize = 0;

    // Keccak midstate of the miner-tx prefix absorbed up to the tx_extra
    // boundary: turns per-extra-nonce re-hashing from O(N) into O(1).
    std::array<uint64_t, 25> m_minerTxKeccakState{};
    size_t m_minerTxKeccakStateInputLength = 0;

    // Small double-buffer so in-flight jobs keep resolving after an update()
    // (generic template caching, NOT p2pool's sidechain). One id -> one blob.
#ifdef XMR_TEMPLATE_UNIT_TESTS
    static constexpr size_t OLD_TEMPLATES = 1;
#else
    static constexpr size_t OLD_TEMPLATES = 4;
#endif
    XmrBlockTemplate* m_oldTemplates[OLD_TEMPLATES] = {};

    // ---- transient (cleared after update(); skipped by copy ctor/assign) --
    std::vector<uint8_t> m_minerTx;
    std::vector<uint8_t> m_minerTxExtra;
    std::vector<uint8_t> m_blockHeader;
    std::vector<uint8_t> m_transactionHashes;   // leaf 0 slot + non-coinbase hashes
    std::vector<uint64_t> m_rewards;            // piconero per payee
    std::vector<XmrTxMempoolData> m_mempoolTxs;
    std::vector<int>     m_mempoolTxsOrder;
    std::vector<int>     m_mempoolTxsOrder2;

    std::mt19937_64 m_rng;
};

} // namespace c2pool::xmr
