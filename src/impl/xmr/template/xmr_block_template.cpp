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
//   Upstream : SChernykh/p2pool  src/block_template.cpp
//   Commit   : 128643114f9bea55bfdb95462eaeffa2e3f666bd  (master, 2026-09-05)
//   Adapted  : Monero whole-block-template plumbing for the v37 Family-B XMR
//              settlement lane. See xmr_block_template.hpp for the full list of
//              what was kept verbatim and what (the p2pool pool model) was cut.
//   Behaviour of the reward math, the greedy penalty-zone selection, the
//   reference knapsack, the miner_tx byte layout, the v2 tx-hash triple, the
//   Keccak-midstate opening, and the tree_hash main branch is unchanged from
//   upstream; only p2pool's SideChain calls were rerouted to IXmrSettlementSource
//   and the sidechain-id / aux-slot machinery was removed.
// =============================================================================

#include "xmr_block_template.hpp"

#include <algorithm>
#include <numeric>
#include <cstring>
#include <unordered_set>

namespace c2pool::xmr {

// std::unordered_set<hash> needs a hasher; the first 8 bytes are already a
// uniform Keccak digest, so use them directly.
struct HashHasher {
    size_t operator()(const hash& h) const {
        size_t v;
        std::memcpy(&v, h.h, sizeof(v));
        return v;
    }
};

// ---------------------------------------------------------------------------
// Reward / penalty math  (upstream get_base_reward / get_block_reward, verbatim).
// The quadratic block-size penalty above the 100-block median is the whole
// reason the template builder cares about weight at all.
// ---------------------------------------------------------------------------
static inline uint64_t get_base_reward(uint64_t already_generated_coins)
{
    const uint64_t result = ~already_generated_coins >> 19;
    return (result < BASE_BLOCK_REWARD) ? BASE_BLOCK_REWARD : result;
}

static inline uint64_t get_block_reward(uint64_t base_reward, uint64_t median_weight,
                                        uint64_t fees, uint64_t weight)
{
    if (weight <= median_weight) {
        return base_reward + fees;
    }
    if (weight > median_weight * 2) {
        return 0;                       // over 2x median: zero reward, block invalid
    }
    // reward = base_reward * (2*median - weight) * weight / median^2  (128-bit)
    // NOTE (upstream): overflows if median_weight >= 2^32; acceptable for now.
    uint64_t product[2];
    product[0] = umul128(base_reward, (median_weight * 2 - weight) * weight, &product[1]);
    uint64_t rem;
    uint64_t reward = udiv128(product[1], product[0], median_weight * median_weight, &rem);
    return reward + fees;
}

// ---------------------------------------------------------------------------
// Lifecycle. m_oldTemplates is a generic double-buffer (NOT a sidechain): jobs
// handed out under an old template id keep resolving after a new update().
// The transient temp vectors are intentionally not copied. Thread-safety around
// update() vs the job getters is the caller's (real tree: one rwlock/instance).
// ---------------------------------------------------------------------------
XmrBlockTemplate::XmrBlockTemplate(IXmrSettlementSource* settle)
    : m_settle(settle)
{
    m_rng.seed(seconds_since_epoch());
    for (size_t i = 0; i < OLD_TEMPLATES; ++i) {
        m_oldTemplates[i] = new XmrBlockTemplate(settle, /*shallow*/ true);
    }
}

// private shallow ctor used only for the old-template buffers (no recursion)
XmrBlockTemplate::XmrBlockTemplate(IXmrSettlementSource* settle, bool)
    : m_settle(settle) {}

XmrBlockTemplate::~XmrBlockTemplate()
{
    for (size_t i = 0; i < OLD_TEMPLATES; ++i) {
        delete m_oldTemplates[i];
        m_oldTemplates[i] = nullptr;
    }
}

XmrBlockTemplate::XmrBlockTemplate(const XmrBlockTemplate& b) { *this = b; }

XmrBlockTemplate& XmrBlockTemplate::operator=(const XmrBlockTemplate& b)
{
    if (this == &b) return *this;

    m_settle                     = b.m_settle;
    m_templateId                 = b.m_templateId;
    m_lastUpdated                = b.m_lastUpdated.load();
    m_blockTemplateBlob          = b.m_blockTemplateBlob;
    m_merkleTreeMainBranch       = b.m_merkleTreeMainBranch;
    m_blockHeaderSize            = b.m_blockHeaderSize;
    m_minerTxOffsetInTemplate    = b.m_minerTxOffsetInTemplate;
    m_minerTxSize                = b.m_minerTxSize;
    m_nonceOffset                = b.m_nonceOffset;
    m_extraNonceOffsetInTemplate = b.m_extraNonceOffsetInTemplate;
    m_numTransactionHashes       = b.m_numTransactionHashes;
    m_prevId                     = b.m_prevId;
    m_height                     = b.m_height.load();
    m_laneTarget                 = b.m_laneTarget;
    m_seedHash                   = b.m_seedHash;
    m_timestamp                  = b.m_timestamp;
    m_majorVersion               = b.m_majorVersion;
    m_finalReward                = b.m_finalReward.load();
    m_extraNonceSize             = b.m_extraNonceSize;
    m_merkleTreeData             = b.m_merkleTreeData;
    m_merkleTreeDataSize         = b.m_merkleTreeDataSize;
    m_minerTxKeccakState         = b.m_minerTxKeccakState;
    m_minerTxKeccakStateInputLength = b.m_minerTxKeccakStateInputLength;
    m_rng                        = b.m_rng;
    // m_oldTemplates and all transient temp vectors are deliberately not copied.
    return *this;
}

void XmrBlockTemplate::shuffle_tx_order()
{
    if (m_mempoolTxsOrder.size() > 1) {
        for (size_t i = m_mempoolTxsOrder.size() - 1; i >= 1; --i) {
            std::swap(m_mempoolTxsOrder[i], m_mempoolTxsOrder[m_rng() % (i + 1)]);
        }
    }
}

// ---------------------------------------------------------------------------
// select_mempool_transactions  (upstream, with p2pool sidechain serialisation
// replaced by a conservative fixed template-overhead estimate).
// ---------------------------------------------------------------------------
void XmrBlockTemplate::select_mempool_transactions(const std::vector<XmrTxMempoolData>& mempool)
{
    m_mempoolTxs.clear();

    const uint64_t cur_time = seconds_since_epoch();
    for (const XmrTxMempoolData& tx : mempool) {
        // take only txs seen >= 5 s ago, or high-fee txs immediately
        if ((cur_time > tx.time_received + 5) || (tx.fee >= HIGH_FEE_VALUE)) {
            m_mempoolTxs.emplace_back(tx);
        }
    }

    // Carrier-size safeguard: the whole block must fit MAX_BLOCK_SIZE. Budget the
    // header + miner_tx + the per-payee outputs, then spend the rest on 32-B tx
    // hashes. (Upstream sizes this from the serialised pool block; here the
    // settlement leg's payee count drives the coinbase estimate.)
    const size_t num_payees = m_settle ? m_settle->payees().size() : 0;

    size_t k = 128; // header + miner_tx prefix + tx_extra (pubkey/nonce/MM tag), rounded up
    writeVarint(num_payees,        [&k](uint8_t) { ++k; });
    writeVarint(m_mempoolTxs.size(), [&k](uint8_t) { ++k; });
    // per output: <=5 B reward varint + 1 B tag + 32 B key + 1 B view tag
    k += num_payees * (5 + 1 + HASH_SIZE + 1);

    const uint32_t max_transactions =
        static_cast<uint32_t>((MAX_BLOCK_SIZE > k) ? ((MAX_BLOCK_SIZE - k) / HASH_SIZE) : 0);

    if (max_transactions == 0) {
        m_mempoolTxs.clear();
    }
    else if (m_mempoolTxs.size() > max_transactions) {
        // keep the highest fee/byte ones (operator< is fee/byte, highest first)
        std::nth_element(m_mempoolTxs.begin(), m_mempoolTxs.begin() + max_transactions, m_mempoolTxs.end());
        m_mempoolTxs.resize(max_transactions);
    }
}

// ---------------------------------------------------------------------------
// create_miner_tx  (upstream miner_tx assembly; p2pool Wallet::get_eph_public_key
// -> IXmrSettlementSource::derive_output_key, p2pool txkey* -> the seam's r/R).
//
//   version=2 | unlock=height+60 | 1 input txin_gen{height} |
//   N outputs [ amount varint | 0x03 txout_to_tagged_key | key(32) | view_tag ] |
//   tx_extra [ 0x01 R(32) | 0x02 len nonce | 0x03 len mm_data root(32) ] |
//   rct_type=0
// ---------------------------------------------------------------------------
int XmrBlockTemplate::create_miner_tx(const XmrMinerData& data,
                                      uint64_t max_reward_amounts_weight, bool dry_run)
{
    m_minerTx.clear();

    const std::vector<XmrPayee>& payees = m_settle->payees();
    const size_t num_outputs = payees.size();
    m_minerTx.reserve(num_outputs * 39 + 55);

    m_minerTx.push_back(TX_VERSION);
    writeVarint(data.height + MINER_REWARD_UNLOCK_TIME, m_minerTx); // unlock_time = h + 60
    m_minerTx.push_back(1);                                         // one input
    m_minerTx.push_back(TXIN_GEN);                                  // txin_gen tag (0xFF)
    writeVarint(data.height, m_minerTx);                           // txin_gen.height == block height
    writeVarint(num_outputs, m_minerTx);

    uint64_t reward_amounts_weight = 0;
    for (size_t i = 0; i < num_outputs; ++i) {
        writeVarint(m_rewards[i], [this, &reward_amounts_weight](uint8_t b) {
            m_minerTx.push_back(b);
            ++reward_amounts_weight;
        });
        m_minerTx.push_back(TXOUT_TO_TAGGED_KEY);

        uint8_t view_tag = 0;
        if (dry_run) {
            // sizing pass: real key not needed, only the amount-varint weight
            m_minerTx.insert(m_minerTx.end(), HASH_SIZE, 0);
        }
        else {
            hash eph_public_key;
            if (!m_settle->derive_output_key(i, m_majorVersion, eph_public_key, view_tag)) {
                return -1; // derivation failed at index i (upstream logs + continues; we fail closed)
            }
            m_minerTx.insert(m_minerTx.end(), eph_public_key.h, eph_public_key.h + HASH_SIZE);
        }
        m_minerTx.emplace_back(view_tag);
    }

    if (dry_run) {
        if (reward_amounts_weight != max_reward_amounts_weight) return -1;
    }
    else if (reward_amounts_weight > max_reward_amounts_weight) {
        return -2;
    }

    // ---- tx_extra ----
    m_minerTxExtra.clear();

    // 0x01 : R = r*G  (the deterministic tx public key)
    m_minerTxExtra.push_back(TX_EXTRA_TAG_PUBKEY);
    {
        const hash& R = m_settle->tx_public_key();
        m_minerTxExtra.insert(m_minerTxExtra.end(), R.h, R.h + HASH_SIZE);
    }

    // 0x02 : extra nonce, padded so the miner-tx weight is invariant to how many
    // bytes the reward amount varints actually took (upstream trick).
    m_minerTxExtra.push_back(TX_EXTRA_NONCE);
    const uint64_t corrected_extra_nonce_size =
        EXTRA_NONCE_SIZE + max_reward_amounts_weight - reward_amounts_weight;
    if (corrected_extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
        return -3;  // caller re-solves the reward with a smaller budget (see update())
    }
    writeVarint(corrected_extra_nonce_size, m_minerTxExtra);

    uint64_t extraNonceOffsetInMinerTx = m_minerTxExtra.size();
    m_minerTxExtra.insert(m_minerTxExtra.end(), corrected_extra_nonce_size, 0);
    m_extraNonceSize = static_cast<uint32_t>(corrected_extra_nonce_size);

    // 0x03 : merge-mining tag. v37 commitment (owed_digest/info_digest) rides
    // here as the single MM-tree leaf (root == leaf for a 1-leaf tree).
    m_minerTxExtra.push_back(TX_EXTRA_MERGE_MINING_TAG);
    m_minerTxExtra.push_back(static_cast<uint8_t>(m_merkleTreeDataSize + HASH_SIZE));
    writeVarint(m_merkleTreeData, m_minerTxExtra);
    m_minerTxExtra.insert(m_minerTxExtra.end(), HASH_SIZE, 0); // root patched per extra_nonce later

    writeVarint(m_minerTxExtra.size(), m_minerTx);
    extraNonceOffsetInMinerTx += m_minerTx.size();
    m_extraNonceOffsetInTemplate = extraNonceOffsetInMinerTx;
    m_minerTx.insert(m_minerTx.end(), m_minerTxExtra.begin(), m_minerTxExtra.end());
    m_minerTxExtra.clear();

    // rct_type = 0 (RCTTypeNull); not part of the tx-prefix hash
    m_minerTx.push_back(0);
    return 1;
}

// ---------------------------------------------------------------------------
// calc_miner_tx_hash  (upstream). v2 tx hash = Keccak(H(prefix) || H(rct_base)
// || H(prunable)); for an RCTTypeNull coinbase H(prunable)=0 and H(rct_base) is
// a known constant. The prefix hash is computed with extra_nonce and the MM root
// patched in-place, using the cached Keccak midstate for O(1) per extra_nonce.
// ---------------------------------------------------------------------------
hash XmrBlockTemplate::calc_miner_tx_hash(uint32_t extra_nonce) const
{
    uint8_t hashes[HASH_SIZE * 3];

    const uint8_t* data = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;

    const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
    const uint8_t extra_nonce_buf[EXTRA_NONCE_SIZE] = {
        static_cast<uint8_t>(extra_nonce >> 0),
        static_cast<uint8_t>(extra_nonce >> 8),
        static_cast<uint8_t>(extra_nonce >> 16),
        static_cast<uint8_t>(extra_nonce >> 24),
    };

    // v37: single MM-tree leaf, so the tag's 32-B root IS the commitment leaf.
    const hash merge_mining_root = m_settle->commitment_leaf(extra_nonce);

    const size_t merkle_root_offset =
        extra_nonce_offset + m_extraNonceSize + 2 + m_merkleTreeDataSize;

    // Prefix = whole miner_tx minus the trailing rct_type byte.
    const size_t tx_size = m_minerTxSize - 1;

    hash full_hash;
    uint8_t tx_buf[288];

    const size_t N = m_minerTxKeccakStateInputLength;
    const bool fast = N && (N <= extra_nonce_offset) && (N < tx_size) && (tx_size - N <= sizeof(tx_buf));

    if (!fast) {
        // slow path O(N): stream the prefix, substituting the mutated regions
        keccak_custom([data, extra_nonce_offset, &extra_nonce_buf, merkle_root_offset, &merge_mining_root](int offset) -> uint8_t {
            uint32_t k = static_cast<uint32_t>(offset - static_cast<int>(extra_nonce_offset));
            if (k < EXTRA_NONCE_SIZE) return extra_nonce_buf[k];
            k = static_cast<uint32_t>(offset - static_cast<int>(merkle_root_offset));
            if (k < HASH_SIZE) return merge_mining_root.h[k];
            return data[offset];
        }, static_cast<int>(tx_size), full_hash.h, HASH_SIZE);
        std::memcpy(hashes, full_hash.h, HASH_SIZE);
    }
    else {
        // fast path O(1): resume from the cached midstate, only the tail bytes
        // (which contain extra_nonce + MM root) are absorbed fresh
        const int inlen = static_cast<int>(tx_size - N);
        std::memcpy(tx_buf, data + N, inlen);
        std::memcpy(tx_buf + extra_nonce_offset - N, extra_nonce_buf, EXTRA_NONCE_SIZE);
        std::memcpy(tx_buf + merkle_root_offset - N, merge_mining_root.h, HASH_SIZE);

        std::array<uint64_t, 25> st = m_minerTxKeccakState;
        keccak_finish(tx_buf, inlen, st);
        std::memcpy(hashes, st.data(), HASH_SIZE);
    }

    // Base RCT of an RCTTypeNull coinbase is a single 0 byte; its Keccak is fixed.
    static constexpr uint8_t known_second_hash[HASH_SIZE] = {
        188,54,120,158,122,30,40,20,54,70,66,41,130,143,129,125,
        102,18,247,180,119,214,101,145,255,150,169,224,100,188,201,138
    };
    std::memcpy(hashes + HASH_SIZE, known_second_hash, HASH_SIZE);

    // Prunable RCT is empty in a coinbase -> null hash.
    std::memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

    hash result;
    keccak(hashes, sizeof(hashes), result.h);
    return result;
}

// ---------------------------------------------------------------------------
// calc_merkle_tree_main_branch  (upstream, verbatim). Precomputes the fixed
// authentication path from leaf 0 (the coinbase) to the tree root, so that each
// per-extra-nonce blob only folds the new miner-tx hash up this branch.
// ---------------------------------------------------------------------------
void XmrBlockTemplate::calc_merkle_tree_main_branch()
{
    m_merkleTreeMainBranch.clear();

    const uint64_t count = m_numTransactionHashes + 1;
    if (count == 1) return;

    const uint8_t* h = m_transactionHashes.data();

    if (count == 2) {
        m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
        return;
    }

    size_t i, j, cnt;
    for (i = 0, cnt = 1; cnt <= count; ++i, cnt <<= 1) {}
    cnt >>= 1;

    std::vector<uint8_t> ints(cnt * HASH_SIZE);
    std::memcpy(ints.data(), h, (cnt * 2 - count) * HASH_SIZE);

    hash tmp;
    for (i = cnt * 2 - count, j = cnt * 2 - count; j < cnt; i += 2, ++j) {
        if (i == 0) {
            m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
        }
        keccak(h + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
        std::memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
    }

    while (cnt > 2) {
        cnt >>= 1;
        for (i = 0, j = 0; j < cnt; i += 2, ++j) {
            if (i == 0) {
                m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
            }
            keccak(ints.data() + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
            std::memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
        }
    }

    m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
}

// ---------------------------------------------------------------------------
// get_hashing_blob_nolock  (upstream). The 76-80 B RandomX input:
//   header(bin) || tree_root(32) || varint(n_tx + 1)
// ---------------------------------------------------------------------------
uint32_t XmrBlockTemplate::get_hashing_blob_nolock(uint32_t extra_nonce, uint8_t* blob) const
{
    uint8_t* p = blob;

    std::memcpy(p, m_blockTemplateBlob.data(), m_blockHeaderSize);
    p += m_blockHeaderSize;

    // fold the freshly-hashed coinbase up the precomputed main branch to the root
    hash root_hash = calc_miner_tx_hash(extra_nonce);
    for (size_t i = 0; i < m_merkleTreeMainBranch.size(); i += HASH_SIZE) {
        uint8_t pair[HASH_SIZE * 2];
        std::memcpy(pair, root_hash.h, HASH_SIZE);
        std::memcpy(pair + HASH_SIZE, m_merkleTreeMainBranch.data() + i, HASH_SIZE);
        keccak(pair, HASH_SIZE * 2, root_hash.h);
    }

    std::memcpy(p, root_hash.h, HASH_SIZE);
    p += HASH_SIZE;

    writeVarint(m_numTransactionHashes + 1, [&p](uint8_t b) { *(p++) = b; });
    return static_cast<uint32_t>(p - blob);
}

// ---------------------------------------------------------------------------
// update  (upstream orchestration; SideChain calls -> IXmrSettlementSource).
// ---------------------------------------------------------------------------
void XmrBlockTemplate::update(const XmrMinerData& data, const std::vector<XmrTxMempoolData>& mempool)
{
    if (data.major_version > HARDFORK_SUPPORTED_VERSION) {
        return; // unknown fork: refuse to build, pin HARDFORK_SUPPORTED_VERSION per fork
    }

    // snapshot the outgoing template so in-flight job ids keep resolving
    if (m_templateId > 0) {
        *m_oldTemplates[m_templateId % OLD_TEMPLATES] = *this;
    }
    ++m_templateId;
    m_lastUpdated = seconds_since_epoch();

    auto use_old_template = [this]() {
        const uint32_t id = m_templateId - 1;
        *this = *m_oldTemplates[id % OLD_TEMPLATES];
    };

    m_height       = data.height;
    m_laneTarget   = data.lane_target;
    m_seedHash     = data.seed_hash;
    m_majorVersion = data.major_version;

    // ---- block header ----
    m_blockHeader.clear();
    m_blockHeader.push_back(data.major_version);
    m_blockHeader.push_back(HARDFORK_SUPPORTED_VERSION);

    m_timestamp = seconds_since_epoch();
    if (m_timestamp <= data.median_timestamp) {
        m_timestamp = data.median_timestamp + 1;
    }
    writeVarint(m_timestamp, m_blockHeader);

    m_blockHeader.insert(m_blockHeader.end(), data.prev_id.h, data.prev_id.h + HASH_SIZE);
    m_prevId = data.prev_id;

    m_nonceOffset = m_blockHeader.size();
    m_blockHeader.insert(m_blockHeader.end(), NONCE_SIZE, 0);
    m_blockHeaderSize = m_blockHeader.size();

    // ---- payees + MM-tree shape from the settlement seam ----
    const std::vector<XmrPayee>& payees = m_settle->payees();
    m_merkleTreeData = m_settle->merkle_tree_data();
    m_merkleTreeDataSize = 0;
    writeVarint(m_merkleTreeData, [this](uint8_t) { ++m_merkleTreeDataSize; });

    select_mempool_transactions(mempool);

    const uint64_t base_reward = get_base_reward(data.already_generated_coins);

    uint64_t total_tx_fees = 0, total_tx_weight = 0;
    for (const XmrTxMempoolData& tx : m_mempoolTxs) {
        total_tx_fees += tx.fee;
        total_tx_weight += tx.weight;
    }

    // amount-varint weight of a full-reward split fixes the dry-run coinbase size
    if (!m_settle->split_reward(base_reward + total_tx_fees, m_rewards)) {
        use_old_template();
        return;
    }
    auto get_reward_amounts_weight = [this]() {
        return std::accumulate(m_rewards.begin(), m_rewards.end(), 0ULL,
            [](uint64_t a, uint64_t b) { writeVarint(b, [&a](uint8_t) { ++a; }); return a; });
    };
    uint64_t max_reward_amounts_weight = get_reward_amounts_weight();

    if (create_miner_tx(data, max_reward_amounts_weight, true) < 0) { use_old_template(); return; }
    uint64_t miner_tx_weight = m_minerTx.size();

    uint64_t final_reward, final_fees, final_weight;

    m_mempoolTxsOrder.resize(m_mempoolTxs.size());
    for (size_t i = 0; i < m_mempoolTxs.size(); ++i) m_mempoolTxsOrder[i] = static_cast<int>(i);

    if (total_tx_weight + miner_tx_weight <= data.median_weight) {
        // below the penalty zone: take everything
        final_fees = 0;
        final_weight = miner_tx_weight;
        shuffle_tx_order();

        m_numTransactionHashes = m_mempoolTxsOrder.size();
        m_transactionHashes.assign(HASH_SIZE, 0);
        std::unordered_set<hash, HashHasher> seen;
        for (int idx : m_mempoolTxsOrder) {
            const XmrTxMempoolData& tx = m_mempoolTxs[idx];
            if (!seen.insert(tx.id).second) continue;
            m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
            final_fees += tx.fee;
            final_weight += tx.weight;
        }
        final_reward = base_reward + final_fees;
    }
    else {
        // penalty zone: greedy fee-per-byte pick with 100-deep replacement,
        // maximising get_block_reward (upstream heuristic).
        std::sort(m_mempoolTxsOrder.begin(), m_mempoolTxsOrder.end(),
                  [this](int a, int b) { return m_mempoolTxs[a] < m_mempoolTxs[b]; });

        final_reward = base_reward;
        final_fees = 0;
        final_weight = miner_tx_weight;
        m_mempoolTxsOrder2.clear();

        for (int i = 0; i < static_cast<int>(m_mempoolTxsOrder.size()); ++i) {
            const XmrTxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
            int k = -1;
            const uint64_t reward = get_block_reward(base_reward, data.median_weight, final_fees + tx.fee, final_weight + tx.weight);
            if (reward > final_reward) { final_reward = reward; k = i; }

            if (final_weight + tx.weight > data.median_weight) {
                const int n = static_cast<int>(m_mempoolTxsOrder2.size());
                for (int j = n - 1, j1 = std::max<int>(0, n - 100); j >= j1; --j) {
                    const XmrTxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[j]];
                    const uint64_t reward2 = get_block_reward(base_reward, data.median_weight,
                        final_fees + tx.fee - prev_tx.fee, final_weight + tx.weight - prev_tx.weight);
                    if (reward2 > final_reward) { final_reward = reward2; k = j; }
                }
            }

            if (k == i) {
                m_mempoolTxsOrder2.push_back(m_mempoolTxsOrder[i]);
                final_fees += tx.fee; final_weight += tx.weight;
            }
            else if (k >= 0) {
                const XmrTxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[k]];
                m_mempoolTxsOrder2[k] = m_mempoolTxsOrder[i];
                final_fees += tx.fee - prev_tx.fee;
                final_weight += tx.weight - prev_tx.weight;
            }
        }
        m_mempoolTxsOrder = m_mempoolTxsOrder2;

        final_fees = 0;
        final_weight = miner_tx_weight;
        shuffle_tx_order();

        m_numTransactionHashes = m_mempoolTxsOrder.size();
        m_transactionHashes.assign(HASH_SIZE, 0);
        std::unordered_set<hash, HashHasher> seen;
        for (int idx : m_mempoolTxsOrder) {
            const XmrTxMempoolData& tx = m_mempoolTxs[idx];
            if (!seen.insert(tx.id).second) continue;
            m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
            final_fees += tx.fee;
            final_weight += tx.weight;
        }
        final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);
    }

    if (!m_settle->split_reward(final_reward, m_rewards)) { use_old_template(); return; }

    int r = create_miner_tx(data, max_reward_amounts_weight, false);
    if (r < 0) {
        if (r == -3) {
            // extra nonce grew past its cap: re-solve reward on a smaller weight
            const uint64_t w = (final_weight > m_rewards.size()) ? (final_weight - m_rewards.size()) : 0;
            const uint64_t r2 = get_block_reward(base_reward, data.median_weight, final_fees, w);
            if (!m_settle->split_reward(r2, m_rewards)) { use_old_template(); return; }
            max_reward_amounts_weight = get_reward_amounts_weight();
            if (create_miner_tx(data, max_reward_amounts_weight, true) < 0) { use_old_template(); return; }
            final_weight += m_minerTx.size() - miner_tx_weight;
            miner_tx_weight = m_minerTx.size();
            final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);
            if (!m_settle->split_reward(final_reward, m_rewards)) { use_old_template(); return; }
            if (create_miner_tx(data, max_reward_amounts_weight, false) < 0) { use_old_template(); return; }
        }
        else { use_old_template(); return; }
    }
    if (m_minerTx.size() != miner_tx_weight) { use_old_template(); return; }

    m_finalReward = final_reward;

    // ---- assemble the block-template blob: header || miner_tx || varint(n_tx) || tx hashes ----
    m_blockTemplateBlob = m_blockHeader;
    m_extraNonceOffsetInTemplate += m_blockHeader.size();
    m_minerTxOffsetInTemplate = m_blockHeader.size();
    m_minerTxSize = m_minerTx.size();
    m_blockTemplateBlob.insert(m_blockTemplateBlob.end(), m_minerTx.begin(), m_minerTx.end());
    writeVarint(m_numTransactionHashes, m_blockTemplateBlob);
    // leaf 0 (miner-tx hash) slot is skipped; only the non-coinbase hashes go in
    m_blockTemplateBlob.insert(m_blockTemplateBlob.end(),
                               m_transactionHashes.begin() + HASH_SIZE, m_transactionHashes.end());

    // ---- cache the Keccak midstate of the miner-tx prefix up to tx_extra ----
    m_minerTxKeccakState = {};
    const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
    if (extra_nonce_offset >= KeccakParams::HASH_DATA_AREA) {
        m_minerTxKeccakStateInputLength =
            (extra_nonce_offset / KeccakParams::HASH_DATA_AREA) * KeccakParams::HASH_DATA_AREA;
        keccak_step(m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate,
                    static_cast<int>(m_minerTxKeccakStateInputLength), m_minerTxKeccakState);
    }
    else {
        m_minerTxKeccakStateInputLength = 0;
    }

    // leaf 0 = coinbase hash at extra_nonce 0; then the fixed main branch
    const hash minerTx_hash = calc_miner_tx_hash(0);
    std::memcpy(m_transactionHashes.data(), minerTx_hash.h, HASH_SIZE);
    calc_merkle_tree_main_branch();

    // free transient state
    m_minerTx.clear();
    m_blockHeader.clear();
    m_minerTxExtra.clear();
    m_transactionHashes.clear();
    m_rewards.clear();
    m_mempoolTxs.clear();
    m_mempoolTxsOrder.clear();
    m_mempoolTxsOrder2.clear();
    (void)payees;
}

// ---------------------------------------------------------------------------
// per-worker job APIs
// ---------------------------------------------------------------------------
uint32_t XmrBlockTemplate::get_hashing_blob(uint32_t extra_nonce,
                                            uint8_t (&blob)[HASHING_BLOB_MAX_SIZE],
                                            uint64_t& height, difficulty_type& lane_target,
                                            hash& seed_hash, size_t& nonce_offset,
                                            uint32_t& template_id) const
{
    height      = m_height.load();
    lane_target = m_laneTarget;
    seed_hash   = m_seedHash;
    nonce_offset = m_nonceOffset;
    template_id = m_templateId;
    return get_hashing_blob_nolock(extra_nonce, blob);
}

uint32_t XmrBlockTemplate::get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count,
                                             std::vector<uint8_t>& blobs,
                                             uint64_t& height, difficulty_type& lane_target,
                                             hash& seed_hash, size_t& nonce_offset,
                                             uint32_t& template_id) const
{
    blobs.clear();
    height      = m_height.load();
    lane_target = m_laneTarget;
    seed_hash   = m_seedHash;
    nonce_offset = m_nonceOffset;
    template_id = m_templateId;

    blobs.resize(HASHING_BLOB_MAX_SIZE);
    const uint32_t blob_size = get_hashing_blob_nolock(extra_nonce_start, blobs.data());
    if (blob_size < HASHING_BLOB_MIN_SIZE || blob_size > HASHING_BLOB_MAX_SIZE) {
        return blob_size; // caller treats out-of-range as an internal error
    }
    blobs.resize(static_cast<size_t>(blob_size) * count);

    if (count > 1) {
        uint8_t* blobs_data = blobs.data();
        std::atomic<uint32_t> counter{1};
        parallel_run([this, blob_size, extra_nonce_start, count, &counter, blobs_data]() {
            for (;;) {
                const uint32_t i = counter.fetch_add(1);
                if (i >= count) return;
                (void)get_hashing_blob_nolock(extra_nonce_start + i,
                                              blobs_data + static_cast<size_t>(i) * blob_size);
            }
        }, true);
    }
    return blob_size;
}

std::vector<uint8_t> XmrBlockTemplate::get_block_template_blob(uint32_t template_id, uint32_t extra_nonce,
                                                               size_t& nonce_offset,
                                                               size_t& extra_nonce_offset,
                                                               size_t& merkle_root_offset,
                                                               hash& merkle_root) const
{
    // resolve template_id against this template or the double-buffer
    const XmrBlockTemplate* t = this;
    if (template_id != m_templateId) {
        for (size_t i = 0; i < OLD_TEMPLATES; ++i) {
            if (m_oldTemplates[i] && m_oldTemplates[i]->m_templateId == template_id) {
                t = m_oldTemplates[i];
                break;
            }
        }
    }

    std::vector<uint8_t> blob = t->m_blockTemplateBlob;
    nonce_offset       = t->m_nonceOffset;
    extra_nonce_offset = t->m_extraNonceOffsetInTemplate;
    merkle_root_offset = t->m_extraNonceOffsetInTemplate + t->m_extraNonceSize + 2 + t->m_merkleTreeDataSize;

    // patch this worker's extra nonce
    const uint8_t en[EXTRA_NONCE_SIZE] = {
        static_cast<uint8_t>(extra_nonce >> 0), static_cast<uint8_t>(extra_nonce >> 8),
        static_cast<uint8_t>(extra_nonce >> 16), static_cast<uint8_t>(extra_nonce >> 24),
    };
    std::memcpy(blob.data() + extra_nonce_offset, en, EXTRA_NONCE_SIZE);

    // patch the MM commitment root for this extra nonce
    merkle_root = t->m_settle->commitment_leaf(extra_nonce);
    std::memcpy(blob.data() + merkle_root_offset, merkle_root.h, HASH_SIZE);
    return blob;
}

#if TEST_KNAPSACK_ALGORITHM
// Reference optimal knapsack (golden-test only). max_weight is the penalty-zone
// budget: median + median/8 - miner_tx_weight. O(N*W) DP over fee/byte.
void XmrBlockTemplate::fill_optimal_knapsack(const XmrMinerData& data, uint64_t base_reward,
                                             uint64_t miner_tx_weight, uint64_t& best_reward,
                                             uint64_t& final_fees, uint64_t& final_weight)
{
    constexpr uint64_t FEE_COEFF = 1000;
    const uint64_t n = m_mempoolTxs.size();
    const uint64_t max_weight = data.median_weight + (data.median_weight / 8) - miner_tx_weight;

    m_knapsack.assign((n + 1) * max_weight, 0);

    for (size_t i = 1; i <= n; ++i) {
        const XmrTxMempoolData& tx = m_mempoolTxs[i - 1];
        const uint32_t tx_fee = static_cast<uint32_t>(tx.fee / FEE_COEFF);
        const uint64_t tx_weight = tx.weight;

        uint32_t* row = m_knapsack.data() + i * max_weight;
        const uint32_t* prev_row = row - max_weight;
        row[0] = 0;
        std::memcpy(row + 1, prev_row + 1, (tx_weight - 1) * sizeof(uint32_t));

        for (uint64_t w = tx_weight; w < max_weight; ++w) {
            const uint32_t used = prev_row[w - tx_weight] + tx_fee;
            const uint32_t notused = prev_row[w];
            row[w] = (used > notused) ? used : notused;
        }
    }

    best_reward = base_reward;
    uint64_t best_weight = 0;
    for (uint64_t w = 0; w < max_weight; ++w) {
        const uint64_t fee = static_cast<uint64_t>(m_knapsack[n * max_weight + w]) * FEE_COEFF;
        if (fee) {
            const uint64_t cur = get_block_reward(base_reward, data.median_weight, fee, w + miner_tx_weight);
            if (cur > best_reward) { best_reward = cur; best_weight = w; }
        }
    }

    m_numTransactionHashes = 0;
    final_fees = 0;
    final_weight = miner_tx_weight;
    m_mempoolTxsOrder.clear();
    m_transactionHashes.assign(HASH_SIZE, 0);
    for (int i = static_cast<int>(n); (i > 0) && (best_weight > 0); --i) {
        if (m_knapsack[i * max_weight + best_weight] > m_knapsack[(i - 1) * max_weight + best_weight]) {
            m_mempoolTxsOrder.push_back(i - 1);
            const XmrTxMempoolData& tx = m_mempoolTxs[i - 1];
            m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
            ++m_numTransactionHashes;
            best_weight -= tx.weight;
            final_fees += tx.fee;
            final_weight += tx.weight;
        }
    }
    m_knapsack.clear();
}
#endif

} // namespace c2pool::xmr
