// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// xmr_block_template.cpp -- whole-block Monero template builder (Family B).
//
// PROVENANCE: clean-room from Monero-core v0.18.5.1 (monero-project/monero,
// BSD-3-Clause) and the public RPC/ZMQ/stratum/CryptoNote protocol; not
// derived from p2pool. The Monero rules applied here, by their Monero-core names:
//   * cryptonote::get_block_reward (cryptonote_basic_impl.cpp): base reward
//     (MONEY_SUPPLY - already_generated_coins) >> 19 for 2-minute blocks,
//     floored at the tail emission; no penalty up to the median weight; above
//     it reward = base * (2M - W) * W / M / M; refused above 2M.
//   * tx_memory_pool::fill_block_template (tx_pool.cpp): take transactions in
//     fee-per-weight order and accept one only if the coinbase (reward + fees)
//     does not decrease.
//   * Blockchain::create_block_template: timestamp = now, raised to the median
//     timestamp when the clock is behind it.
//   * get_block_hashing_blob / calculate_transaction_hash / tree_hash: through
//     the lane's own serializer and the vendored Monero crypto (xmr_blob.hpp).
// Serialization of the coinbase prefix head (version, unlock time, txin_gen,
// tagged-key outputs) is xmr::coin::write_coinbase_prefix_head, so the
// template's miner transaction and the lane's settlement coinbase share one
// serializer.

#include "xmr_block_template.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>

#include "xmr_blob.hpp"           // xmr::coin::BlobWriter, write_coinbase_prefix_head, hashes, tree_root
#include "xmr_crypto_types.hpp"   // xmr::coin::PublicKey, ViewTag, Hash256

namespace c2pool::xmr {

namespace {

namespace coin = ::xmr::coin;

constexpr std::uint64_t kMoneySupply = std::numeric_limits<std::uint64_t>::max();
constexpr unsigned kEmissionShift = 19;   // EMISSION_SPEED_FACTOR_PER_MINUTE(20) - (2 - 1)

std::uint64_t base_reward(std::uint64_t already_generated_coins) {
    const std::uint64_t r = (kMoneySupply - already_generated_coins) >> kEmissionShift;
    return r < BASE_BLOCK_REWARD ? BASE_BLOCK_REWARD : r;
}

// Monero get_block_reward over the supplied (effective) median.
bool block_reward(std::uint64_t base, std::uint64_t median, std::uint64_t weight, std::uint64_t& reward) {
    if (weight <= median) {
        reward = base;
        return true;
    }
    if (median == 0 || weight > 2 * median) return false;
    std::uint64_t multiplicand = 2 * median - weight;   // same 64-bit arithmetic as Monero
    multiplicand *= weight;
    const unsigned __int128 product = static_cast<unsigned __int128>(base) * multiplicand;
    const unsigned __int128 divisor = static_cast<unsigned __int128>(median) * median;
    reward = static_cast<std::uint64_t>(product / divisor);   // == two truncating divisions by median
    return true;
}

std::size_t varint_size(std::uint64_t v) {
    std::size_t n = 1;
    while (v >= 0x80) { v >>= 7; ++n; }
    return n;
}

std::size_t amounts_weight(const std::vector<std::uint64_t>& amounts) {
    std::size_t w = 0;
    for (std::uint64_t a : amounts) w += varint_size(a);
    return w;
}

coin::Hash256 to_h256(const hash& h) {
    coin::Hash256 o;
    std::memcpy(o.data(), h.h, HASH_SIZE);
    return o;
}

// fee per weight, descending: a.fee / a.weight > b.fee / b.weight without division.
bool better_fee_rate(const XmrTxMempoolData& a, const XmrTxMempoolData& b) {
    const unsigned __int128 l = static_cast<unsigned __int128>(a.fee) * (b.weight ? b.weight : 1);
    const unsigned __int128 r = static_cast<unsigned __int128>(b.fee) * (a.weight ? a.weight : 1);
    if (l != r) return l > r;
    if (a.time_received != b.time_received) return a.time_received < b.time_received;
    return std::memcmp(a.id.h, b.id.h, HASH_SIZE) < 0;
}

} // namespace

// ---------------------------------------------------------------------------
// One built template.
// ---------------------------------------------------------------------------
struct XmrBlockTemplate::Snapshot {
    std::uint32_t id = 0;
    std::uint64_t height = 0;
    hash prev_id;
    hash seed_hash;
    difficulty_type lane_target;
    std::uint64_t reward = 0;

    std::vector<unsigned char> header;        // varint major | varint minor | varint ts | prev_id | nonce 0
    std::size_t nonce_offset = 0;

    std::vector<unsigned char> outputs_head;  // coinbase prefix up to (not incl.) the extra length
    hash tx_pubkey;
    std::size_t nonce_field_size = EXTRA_NONCE_SIZE;   // worker nonce + weight pad
    std::size_t bind_size = 0;
    std::vector<std::uint8_t> tail;
    std::uint64_t mm_data = 0;

    std::vector<hash> tx_ids;                 // block order
    const IXmrSettlementSource* seam = nullptr;
};

namespace {

// The miner transaction for one extra nonce, with its field offsets.
struct MinerTx {
    std::vector<unsigned char> bytes;   // prefix || rct_type(0)
    std::size_t extra_nonce_offset = 0; // first byte of the 0x02 payload
    std::size_t mm_root_offset = 0;     // first byte of the 0x03 root
    hash mm_root;
};

std::vector<std::uint8_t> nonce_payload(std::uint32_t extra_nonce, std::size_t nonce_field_size,
                                        std::size_t bind_size, const std::vector<std::uint8_t>& tail,
                                        const IXmrSettlementSource* seam) {
    std::vector<std::uint8_t> p;
    p.reserve(nonce_field_size + bind_size + tail.size());
    for (int i = 0; i < 4; ++i) p.push_back(static_cast<std::uint8_t>(extra_nonce >> (8 * i)));
    if (bind_size) {
        std::vector<std::uint8_t> bind(bind_size, 0);
        if (!seam || !seam->extra_nonce_bind(extra_nonce, bind.data()))
            std::fill(bind.begin(), bind.end(), 0);   // no binding available: zeros (the share will not verify)
        p.insert(p.end(), bind.begin(), bind.end());
    }
    p.insert(p.end(), nonce_field_size - EXTRA_NONCE_SIZE, 0);
    p.insert(p.end(), tail.begin(), tail.end());
    return p;
}

MinerTx build_miner_tx(const std::vector<unsigned char>& outputs_head, const hash& tx_pubkey,
                       const std::vector<std::uint8_t>& payload, std::uint64_t mm_data, const hash& mm_root) {
    coin::BlobWriter extra;
    extra.put_byte(coin::TX_EXTRA_TAG_PUBKEY);
    extra.put_bytes(tx_pubkey.h, HASH_SIZE);
    extra.put_byte(coin::TX_EXTRA_TAG_NONCE);
    extra.put_varint(payload.size());
    const std::size_t payload_at = extra.size();
    extra.put_bytes(payload.data(), payload.size());
    extra.put_byte(coin::TX_EXTRA_TAG_MERGE_MINING);
    extra.put_varint(varint_size(mm_data) + HASH_SIZE);
    extra.put_varint(mm_data);
    const std::size_t root_at = extra.size();
    extra.put_bytes(mm_root.h, HASH_SIZE);

    MinerTx tx;
    coin::BlobWriter w;
    w.put_bytes(outputs_head.data(), outputs_head.size());
    w.put_varint(extra.size());
    const std::size_t extra_at = w.size();
    w.put_bytes(extra.bytes().data(), extra.size());
    w.put_byte(0);   // rct_signatures.type = RCTTypeNull
    tx.bytes = w.bytes();
    tx.extra_nonce_offset = extra_at + payload_at;
    tx.mm_root_offset = extra_at + root_at;
    tx.mm_root = mm_root;
    return tx;
}

MinerTx miner_tx_for(const XmrBlockTemplate::Snapshot& s, std::uint32_t extra_nonce) {
    const std::vector<std::uint8_t> payload =
        nonce_payload(extra_nonce, s.nonce_field_size, s.bind_size, s.tail, s.seam);
    const hash root = s.seam ? s.seam->commitment_leaf(extra_nonce) : hash{};
    return build_miner_tx(s.outputs_head, s.tx_pubkey, payload, s.mm_data, root);
}

// header || tree_root([miner_tx hash] ++ tx ids) || varint(n_tx + 1)
std::vector<unsigned char> hashing_blob_for(const XmrBlockTemplate::Snapshot& s, const MinerTx& tx) {
    const std::vector<unsigned char> prefix(tx.bytes.begin(), tx.bytes.end() - 1);
    std::vector<coin::Hash256> leaves;
    leaves.reserve(1 + s.tx_ids.size());
    leaves.push_back(coin::coinbase_tx_hash(coin::tx_prefix_hash(prefix)));
    for (const hash& id : s.tx_ids) leaves.push_back(to_h256(id));
    return coin::assemble_hashing_blob(s.header, coin::tree_root(leaves), leaves.size());
}

// Sizing / selection state for one attempt.
struct Attempt {
    std::vector<std::uint64_t> amounts;   // final amounts
    std::vector<std::size_t> selected;    // indices into the candidate list
    std::uint64_t reward = 0;
    std::size_t nonce_field_size = EXTRA_NONCE_SIZE;
    std::size_t tx_weight = 0;            // miner tx weight the reward was computed for
};

} // namespace

// ---------------------------------------------------------------------------

XmrBlockTemplate::XmrBlockTemplate(const IXmrSettlementSource* seam) : m_seam(seam) {}
XmrBlockTemplate::~XmrBlockTemplate() = default;

std::shared_ptr<const XmrBlockTemplate::Snapshot> XmrBlockTemplate::current() const {
    std::shared_lock<std::shared_mutex> lk(m_lock);
    return m_current;
}

std::shared_ptr<const XmrBlockTemplate::Snapshot> XmrBlockTemplate::find(std::uint32_t template_id) const {
    std::shared_lock<std::shared_mutex> lk(m_lock);
    if (m_current && m_current->id == template_id) return m_current;
    for (const auto& s : m_previous)
        if (s->id == template_id) return s;
    return nullptr;
}

std::uint64_t XmrBlockTemplate::get_reward() const { auto s = current(); return s ? s->reward : 0; }
std::uint64_t XmrBlockTemplate::get_height() const { auto s = current(); return s ? s->height : 0; }
difficulty_type XmrBlockTemplate::get_lane_target() const { auto s = current(); return s ? s->lane_target : difficulty_type{}; }
std::uint64_t XmrBlockTemplate::last_updated() const {
    std::shared_lock<std::shared_mutex> lk(m_lock);
    return m_last_updated;
}

void XmrBlockTemplate::update(const XmrMinerData& data, const std::vector<XmrTxMempoolData>& mempool,
                              bool take_mempool_as_given) {
    if (!m_seam || data.height == 0) return;
    if (data.major_version > HARDFORK_SUPPORTED_VERSION) return;   // pre-CARROT only

    const std::vector<XmrPayee>& payees = m_seam->payees();
    const std::size_t n_out = payees.size();
    if (n_out == 0) return;
    const std::uint64_t mm_data = m_seam->merkle_tree_data();
    const std::uint64_t base = base_reward(data.already_generated_coins);
    const std::uint64_t now = seconds_since_epoch();

    // ---- candidates: unique ids; the default path also applies the age gate and sorts by fee rate
    std::vector<XmrTxMempoolData> cand;
    cand.reserve(mempool.size());
    {
        std::set<std::array<std::uint8_t, HASH_SIZE>> seen;
        for (const XmrTxMempoolData& t : mempool) {
            std::array<std::uint8_t, HASH_SIZE> k;
            std::memcpy(k.data(), t.id.h, HASH_SIZE);
            if (!seen.insert(k).second) continue;   // a block may not carry a transaction twice
            if (!take_mempool_as_given && t.time_received != 0 &&
                t.time_received + MEMPOOL_MIN_AGE_SECONDS > now)
                continue;                           // too new: give it time to propagate
            cand.push_back(t);
        }
    }
    if (!take_mempool_as_given) std::stable_sort(cand.begin(), cand.end(), better_fee_rate);
    std::uint64_t fees_all = 0;
    for (const XmrTxMempoolData& t : cand) fees_all += t.fee;

    // ---- header (fixed for this template)
    const std::uint8_t minor = HARDFORK_SUPPORTED_VERSION;
    const std::uint64_t timestamp = std::max<std::uint64_t>(now, data.median_timestamp);
    const std::vector<unsigned char> header =
        coin::write_block_header_prefix(data.major_version, minor, timestamp, to_h256(data.prev_id), 0);
    const std::size_t nonce_offset = header.size() - NONCE_SIZE;

    const std::size_t bind_size = m_seam->extra_nonce_bind_size();
    if (bind_size > EXTRA_NONCE_BIND_MAX) return;

    const std::vector<coin::PublicKey> zero_keys(n_out);
    const std::vector<coin::ViewTag> zero_tags(n_out);

    // Miner transaction size for a set of amounts (keys do not change the size).
    auto tx_size = [&](const std::vector<std::uint64_t>& amounts, std::size_t nonce_field,
                       const std::vector<std::uint8_t>& tail) -> std::size_t {
        const std::vector<unsigned char> head = coin::write_coinbase_prefix_head(
            data.height, amounts.data(), zero_keys.data(), zero_tags.data(), n_out);
        const std::vector<std::uint8_t> payload(nonce_field + bind_size + tail.size(), 0);
        return build_miner_tx(head, hash{}, payload, mm_data, hash{}).bytes.size();
    };

    // Select transactions given the miner transaction weight; returns false when
    // even the coinbase-only block has no valid reward.
    auto select = [&](std::size_t cb_weight, std::vector<std::size_t>& sel, std::uint64_t& reward) -> bool {
        sel.clear();
        std::uint64_t weight = cb_weight, fees = 0, best = 0;
        if (!block_reward(base, data.median_weight, weight, best)) return false;
        std::size_t blob = header.size() + cb_weight + varint_size(0);
        for (std::size_t i = 0; i < cand.size(); ++i) {
            const XmrTxMempoolData& t = cand[i];
            const std::size_t blob2 = blob - varint_size(sel.size()) + varint_size(sel.size() + 1) + HASH_SIZE;
            if (blob2 > MAX_BLOCK_TEMPLATE_BLOB) {
                if (take_mempool_as_given) break;   // keep the given order: drop the tail
                continue;
            }
            const std::uint64_t w2 = weight + t.weight;
            if (take_mempool_as_given) {
                sel.push_back(i); weight = w2; fees += t.fee; blob = blob2;
                continue;
            }
            std::uint64_t r2 = 0;
            if (!block_reward(base, data.median_weight, w2, r2)) continue;
            const std::uint64_t coinbase = r2 + fees + t.fee;
            if (coinbase < best) continue;           // the coinbase must not decrease
            sel.push_back(i); weight = w2; fees += t.fee; best = coinbase; blob = blob2;
        }
        std::uint64_t r = 0;
        if (!block_reward(base, data.median_weight, weight, r)) return false;
        reward = r + fees;
        return true;
    };

    // One sizing + selection + final-amount attempt. `sizing` are the amounts
    // the miner transaction is sized with.
    auto attempt = [&](const std::vector<std::uint64_t>& sizing, Attempt& out) -> bool {
        if (sizing.size() != n_out) return false;
        const std::vector<std::uint8_t> tail = m_seam->extra_nonce_tail();
        const std::size_t w_dry = tx_size(sizing, EXTRA_NONCE_SIZE, tail);
        std::uint64_t reward = 0;
        if (!select(w_dry, out.selected, reward)) return false;
        std::vector<std::uint64_t> final_amounts;
        if (!m_seam->split_reward(reward, final_amounts) || final_amounts.size() != n_out) return false;
        const std::size_t aw_dry = amounts_weight(sizing), aw_final = amounts_weight(final_amounts);
        if (aw_final > aw_dry) return false;                          // amounts grew: re-size
        const std::size_t nonce_field = EXTRA_NONCE_SIZE + (aw_dry - aw_final);
        if (nonce_field > EXTRA_NONCE_MAX_SIZE) return false;          // pad out of range: re-size
        const std::vector<std::uint8_t> tail2 = m_seam->extra_nonce_tail();   // read after the final split
        if (nonce_field + bind_size + tail2.size() > TX_EXTRA_NONCE_MAX) return false;
        if (tx_size(final_amounts, nonce_field, tail2) != w_dry) return false;   // a length varint moved
        out.amounts = std::move(final_amounts);
        out.reward = reward;
        out.nonce_field_size = nonce_field;
        out.tx_weight = w_dry;
        return true;
    };

    // Sizing pass: the reward with every candidate's fee and no penalty.
    std::vector<std::uint64_t> sizing;
    if (!m_seam->split_reward(base + fees_all, sizing)) return;
    Attempt a;
    if (!attempt(sizing, a)) {
        // Re-size once with the amounts of the reward the first attempt reached.
        std::uint64_t reward = 0;
        std::vector<std::size_t> sel;
        if (sizing.size() != n_out) return;
        if (!select(tx_size(sizing, EXTRA_NONCE_SIZE, m_seam->extra_nonce_tail()), sel, reward)) return;
        std::vector<std::uint64_t> resized;
        if (!m_seam->split_reward(reward, resized)) return;
        a = Attempt{};
        if (!attempt(resized, a)) return;
    }

    // ---- final keys
    auto s = std::make_shared<Snapshot>();
    std::vector<coin::PublicKey> keys(n_out);
    std::vector<coin::ViewTag> tags(n_out);
    for (std::size_t i = 0; i < n_out; ++i) {
        hash p;
        std::uint8_t vt = 0;
        if (!m_seam->derive_output_key(i, data.major_version, p, vt)) return;
        std::memcpy(&keys[i], p.h, HASH_SIZE);
        tags[i].tag = vt;
    }
    s->outputs_head = coin::write_coinbase_prefix_head(data.height, a.amounts.data(), keys.data(), tags.data(), n_out);
    s->tx_pubkey = m_seam->tx_public_key();
    s->tail = m_seam->extra_nonce_tail();
    s->nonce_field_size = a.nonce_field_size;
    s->bind_size = bind_size;
    s->mm_data = mm_data;
    s->seam = m_seam;
    s->height = data.height;
    s->prev_id = data.prev_id;
    s->seed_hash = data.seed_hash;
    s->lane_target = data.lane_target;
    s->reward = a.reward;
    s->header = header;
    s->nonce_offset = nonce_offset;
    s->tx_ids.reserve(a.selected.size());
    for (std::size_t i : a.selected) s->tx_ids.push_back(cand[i].id);

    // Self-check at extra nonce 0: the final miner transaction has the weight the
    // reward was computed for, and the hashing blob is in range.
    const MinerTx tx0 = miner_tx_for(*s, 0);
    if (tx0.bytes.size() != a.tx_weight) return;
    const std::size_t hb = hashing_blob_for(*s, tx0).size();
    if (hb < HASHING_BLOB_MIN_SIZE || hb > HASHING_BLOB_MAX_SIZE) return;

    std::unique_lock<std::shared_mutex> lk(m_lock);
    s->id = m_next_id++;
    if (m_current) {
        m_previous.push_front(m_current);
        if (m_previous.size() > kKeepPrevious) m_previous.pop_back();
    }
    m_current = std::move(s);
    m_last_updated = now ? now : 1;
}

std::uint32_t XmrBlockTemplate::get_hashing_blob(std::uint32_t extra_nonce, std::uint8_t* blob,
                                                 std::uint64_t& height, difficulty_type& lane_target,
                                                 hash& seed_hash, std::size_t& nonce_offset,
                                                 std::uint32_t& template_id) const {
    const auto s = current();
    if (!s) {
        template_id = 0;
        return 0;
    }
    const std::vector<unsigned char> hb = hashing_blob_for(*s, miner_tx_for(*s, extra_nonce));
    if (hb.size() > HASHING_BLOB_MAX_SIZE) {
        template_id = 0;
        return 0;
    }
    std::memcpy(blob, hb.data(), hb.size());
    height = s->height;
    lane_target = s->lane_target;
    seed_hash = s->seed_hash;
    nonce_offset = s->nonce_offset;
    template_id = s->id;
    return static_cast<std::uint32_t>(hb.size());
}

std::uint32_t XmrBlockTemplate::get_hashing_blobs(std::uint32_t extra_nonce_start, std::uint32_t count,
                                                  std::vector<std::uint8_t>& blobs,
                                                  std::uint64_t& height, difficulty_type& lane_target,
                                                  hash& seed_hash, std::size_t& nonce_offset,
                                                  std::uint32_t& template_id) const {
    blobs.clear();
    const auto s = current();
    if (!s || count == 0) {
        template_id = 0;
        return 0;
    }
    std::uint32_t size = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::vector<unsigned char> hb = hashing_blob_for(*s, miner_tx_for(*s, extra_nonce_start + i));
        if (i == 0) {
            size = static_cast<std::uint32_t>(hb.size());
            blobs.reserve(static_cast<std::size_t>(size) * count);
        }
        if (hb.size() != size || size > HASHING_BLOB_MAX_SIZE) {   // every blob of one template has one size
            blobs.clear();
            template_id = 0;
            return 0;
        }
        blobs.insert(blobs.end(), hb.begin(), hb.end());
    }
    height = s->height;
    lane_target = s->lane_target;
    seed_hash = s->seed_hash;
    nonce_offset = s->nonce_offset;
    template_id = s->id;
    return size;
}

std::vector<std::uint8_t> XmrBlockTemplate::get_block_template_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                                                                    std::size_t& nonce_offset,
                                                                    std::size_t& extra_nonce_offset,
                                                                    std::size_t& merkle_root_offset,
                                                                    hash& merkle_root) const {
    nonce_offset = extra_nonce_offset = merkle_root_offset = 0;
    const auto s = find(template_id);
    if (!s) return {};
    const MinerTx tx = miner_tx_for(*s, extra_nonce);

    coin::BlobWriter w;
    w.put_bytes(s->header.data(), s->header.size());
    w.put_bytes(tx.bytes.data(), tx.bytes.size());
    w.put_varint(s->tx_ids.size());
    for (const hash& id : s->tx_ids) w.put_bytes(id.h, HASH_SIZE);

    nonce_offset = s->nonce_offset;
    extra_nonce_offset = s->header.size() + tx.extra_nonce_offset;
    merkle_root_offset = s->header.size() + tx.mm_root_offset;
    merkle_root = tx.mm_root;
    const std::vector<unsigned char>& b = w.bytes();
    return std::vector<std::uint8_t>(b.begin(), b.end());
}

} // namespace c2pool::xmr
