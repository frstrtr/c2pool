#pragma once

// P2: Share verification — check_hash_link, check_merkle_link, share init/check
// Ported from legacy sharechains/data.cpp + sharechains/share.cpp

#include "config_pool.hpp"
#include "share.hpp"
#include "share_types.hpp"

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/scrypt.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace ltc
{

// ============================================================================
// check_hash_link()
//
// Restores SHA256 mid-state from hash_link, continues hashing with
// (data + extra), then double-SHA256 finalises to the gentx_hash.
//
// Legacy: sharechains/data.cpp  check_hash_link()
// ============================================================================
template <typename HashLinkT>
inline uint256 check_hash_link(const HashLinkT& hash_link,
                               const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& const_ending = {})
{
    const uint64_t extra_length = hash_link.m_length % 64; // 512/8 = 64

    // hash_link.extra_data handling:
    // Pre-V36: extra_data is always empty (FixedStr<0>)
    // V36:     extra_data is VarStr (may contain data)
    std::vector<unsigned char> extra;
    if constexpr (requires { hash_link.m_extra_data.m_data; })
    {
        // V36HashLinkType: extra_data is BaseScript (VarStr)
        extra.assign(hash_link.m_extra_data.m_data.begin(),
                     hash_link.m_extra_data.m_data.end());
        if (extra.size() < extra_length)
        {
            // Pad from const_ending tail
            auto needed = extra_length - extra.size();
            if (const_ending.size() >= needed)
                extra.insert(extra.begin(), const_ending.end() - needed, const_ending.end());
        }
    }
    else
    {
        // Pre-V36: extra_data always empty, use const_ending tail
        extra.assign(const_ending.begin(), const_ending.end());
        if (extra.size() > extra_length)
            extra.erase(extra.begin(), extra.begin() + (extra.size() - extra_length));
    }
    if (extra.size() != extra_length)
        throw std::runtime_error("check_hash_link: extra size mismatch");

    // Restore SHA256 mid-state from hash_link.m_state (32 bytes, big-endian)
    const auto& state_bytes = hash_link.m_state.m_data;
    uint32_t init_state[8] = {
        ReadBE32(state_bytes.data() +  0),
        ReadBE32(state_bytes.data() +  4),
        ReadBE32(state_bytes.data() +  8),
        ReadBE32(state_bytes.data() + 12),
        ReadBE32(state_bytes.data() + 16),
        ReadBE32(state_bytes.data() + 20),
        ReadBE32(state_bytes.data() + 24),
        ReadBE32(state_bytes.data() + 28),
    };

    // Continue hashing from mid-state: Write(data) fills the partial
    // block (extra is already in buf via the constructor), then processes
    // remaining full blocks.  Single SHA256 pass.
    unsigned char out1[CSHA256::OUTPUT_SIZE];
    CSHA256(init_state, extra, hash_link.m_length)
        .Write(data.data(), data.size())
        .Finalize(out1);

    // Second SHA256 pass → double-SHA256
    unsigned char out2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(out1, CSHA256::OUTPUT_SIZE).Finalize(out2);

    // Write raw double-SHA256 output directly into uint256
    // (matches Bitcoin Core's Hash() which does the same)
    uint256 result;
    std::memcpy(result.data(), out2, 32);
    return result;
}

// ============================================================================
// check_merkle_link()
//
// Walk a Merkle branch to compute the root from a given tip_hash.
//
// Legacy: libcoind/data.cpp  check_merkle_link()
// ============================================================================
inline uint256 check_merkle_link(const uint256& tip_hash, const MerkleLink& link)
{
    if (link.m_branch.size() > 0 &&
        link.m_index >= (1u << link.m_branch.size()))
        throw std::invalid_argument("check_merkle_link: index too large");

    uint256 cur = tip_hash;
    for (size_t i = 0; i < link.m_branch.size(); ++i)
    {
        // Combine: if bit i of index is set, branch[i] is on the left
        PackStream ps;
        if ((link.m_index >> i) & 1)
        {
            ps << link.m_branch[i];
            ps << cur;
        }
        else
        {
            ps << cur;
            ps << link.m_branch[i];
        }

        // double-SHA256 of the 64-byte concatenation
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);
    }
    return cur;
}

// ============================================================================
// compute_gentx_before_refhash()
//
// Computes the constant ending bytes that appear after the coinbase outputs
// and before the ref_hash in the serialised coinbase transaction.
//
// Legacy: networks/network.cpp  "init gentx_before_refhash"
// Formula: VarStr(DONATION_SCRIPT) + int64(0) + VarStr(0x6a28 + int256(0) + int64(0))[:3]
// ============================================================================
inline std::vector<unsigned char> compute_gentx_before_refhash(int64_t share_version)
{
    std::vector<unsigned char> result;

    // 1. VarStr(DONATION_SCRIPT)
    auto donation_script = PoolConfig::get_donation_script(share_version);
    {
        PackStream s;
        BaseScript bs;
        bs.m_data = donation_script;
        s << bs;
        auto* p = reinterpret_cast<const unsigned char*>(s.data());
        result.insert(result.end(), p, p + s.size());
    }

    // 2. int64(0)
    {
        uint64_t zero64 = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero64);
        result.insert(result.end(), p, p + 8);
    }

    // 3. VarStr(0x6a 0x28 + int256(0) + int64(0)) — but only the first 3 bytes
    {
        PackStream inner;
        // raw bytes: OP_RETURN (0x6a) + PUSH_40 (0x28)
        unsigned char prefix[2] = {0x6a, 0x28};
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(prefix), 2));
        // 32 zero bytes (uint256(0))
        uint256 zero256;
        inner << zero256;
        // 8 zero bytes (uint64(0))
        uint64_t zero64 = 0;
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero64), 8));

        // Pack as VarStr
        PackStream outer;
        BaseScript bs;
        bs.m_data.resize(inner.size());
        std::memcpy(bs.m_data.data(), inner.data(), inner.size());
        outer << bs;

        // Take only the first 3 bytes
        auto* p = reinterpret_cast<const unsigned char*>(outer.data());
        result.insert(result.end(), p, p + std::min<size_t>(3, outer.size()));
    }

    return result;
}

// ============================================================================
// share_init_verify()
//
// Performs the init()-phase verification of a share:
//   1. Basic field validation (coinbase size, merkle branch lengths)
//   2. Compute hash_link_data from ref serialisation
//   3. check_hash_link → gentx_hash
//   4. check_merkle_link → merkle_root
//   5. Build full block header
//   6. Compute hash (double-SHA256 of header)
//   7. Verify pow_hash <= target
//
// Returns the share hash (double-SHA256 of the reconstructed header).
// Throws on any validation failure.
//
// NOTE: The full GenerateShareTransaction reconstruction from check() is
// deferred to a later PR (P2.5).  This function covers the PoW + hash-link
// verification path from legacy Share::init().
// ============================================================================
template <typename ShareT>
uint256 share_init_verify(const ShareT& share)
{
    // --- Basic validation ---
    if (share.m_coinbase.size() < 2 || share.m_coinbase.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    if (share.m_merkle_link.m_branch.size() > 16)
        throw std::invalid_argument("merkle branch too long");

    constexpr int64_t ver = ShareT::version;

    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                if (share.m_segwit_data->m_txid_merkle_link.m_branch.size() > 16)
                    throw std::invalid_argument("segwit txid merkle branch too long");
            }
        }
    }

    // --- Compute ref_hash ---
    // RefType serialisation: IDENTIFIER + share_info fields + segwit_data
    // Then hash256 it, then check_merkle_link with ref_merkle_link
    //
    // For now we serialise the minimal fields the same way the legacy code
    // does (share_data + share_info + optional segwit_data) via a PackStream.
    PackStream ref_stream;

    // IDENTIFIER bytes (8 bytes from IDENTIFIER_HEX)
    {
        auto hex = PoolConfig::IDENTIFIER_HEX;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    // share_info serialisation — we re-serialise the share's share_info fields
    // through the same Formatter path that was used to decode them.
    // For ref_hash we need: share_data + share_info fields + segwit_data
    // We serialise the relevant fields into the ref_stream.
    {
        // prev_hash
        ref_stream << share.m_prev_hash;
        // coinbase
        ref_stream << share.m_coinbase;
        // nonce (uint32_t LE)
        ref_stream << share.m_nonce;

        // address or pubkey_hash — V34/V35 use m_address (VarStr),
        // V36+ uses m_pubkey_hash (uint160), pre-V34 uses m_pubkey_hash.
        if constexpr (requires { share.m_address; })
            ref_stream << share.m_address;
        else
            ref_stream << share.m_pubkey_hash;

        // subsidy (uint64_t LE), donation (uint16_t LE)
        ref_stream << share.m_subsidy;
        ref_stream << share.m_donation;
        // stale_info as EnumType<IntType<8>> — single byte
        {
            uint8_t si = static_cast<uint8_t>(share.m_stale_info);
            ref_stream << si;
        }
        // desired_version as VarInt
        {
            uint64_t dv = share.m_desired_version;
            ::Serialize(ref_stream, VarInt(dv));
        }

        // segwit_data (optional)
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
                ref_stream << share.m_segwit_data.value();
        }

        // tx info (pre-v34)
        if constexpr (ver < 34)
        {
            if constexpr (requires { share.m_tx_info; })
                ref_stream << share.m_tx_info;
        }

        // far_share_hash, max_bits (uint32_t), bits (uint32_t),
        // timestamp (uint32_t), absheight (uint32_t), abswork (uint128)
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;
        ref_stream << share.m_abswork;
    }

    // hash256 of the ref_type serialisation
    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);

    // check_merkle_link with ref_merkle_link
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // --- Build hash_link_data ---
    // hash_link_data = ref_hash bytes + pack(last_txout_nonce, LE64) + pack(0, LE32)
    std::vector<unsigned char> hash_link_data;
    hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        // last_txout_nonce as little-endian uint64
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
    }
    {
        // trailing zero uint32
        uint32_t zero = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), p, p + 4);
    }

    auto gentx_before_refhash = compute_gentx_before_refhash(ver);

    // --- check_hash_link → gentx_hash ---
    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    // --- Merkle root ---
    // For segwit-activated shares, use segwit_data.txid_merkle_link; otherwise merkle_link
    uint256 merkle_root;
    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
                merkle_root = check_merkle_link(gentx_hash, share.m_segwit_data->m_txid_merkle_link);
            else
                merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
        else
        {
            merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
    }
    else
    {
        merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
    }

    // --- Reconstruct full block header and compute hash ---
    // BlockHeaderType: version(int32) + previous_block + merkle_root + timestamp + bits + nonce
    // Note: the full block header uses fixed 4-byte version (not VarInt like SmallBlockHeaderType)
    PackStream header_stream;
    {
        uint32_t hdr_version = static_cast<uint32_t>(share.m_min_header.m_version);
        header_stream << hdr_version;
    }
    header_stream << share.m_min_header.m_previous_block;
    header_stream << merkle_root;
    header_stream << share.m_min_header.m_timestamp;
    header_stream << share.m_min_header.m_bits;
    header_stream << share.m_min_header.m_nonce;

    // hash = double-SHA256 of the header (the share's identity)
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = Hash(hdr_span);

    // --- PoW check (scrypt) ---
    // For Litecoin the POW_FUNC is scrypt(1024,1,1,256).
    // Blocks are identified by SHA256d, but PoW validity uses scrypt hash.
    uint256 target = chain::bits_to_target(share.m_bits);
    if (target.IsNull())
        throw std::invalid_argument("share target is zero");

    // Compute the scrypt hash of the 80-byte block header
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_stream.data()),
                        pow_hash_bytes);
    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    if (pow_hash > target)
        throw std::invalid_argument("share PoW hash does not meet target");

    return share_hash;
}

// ============================================================================
// Helper: convert pubkey_hash + type to full scriptPubKey
// ============================================================================
inline std::vector<unsigned char> pubkey_hash_to_script(const uint160& hash, uint8_t type = 0)
{
    std::vector<unsigned char> script;
    auto h = hash.GetChars();
    switch (type)
    {
    case 1: // P2WPKH: OP_0 <20>
        script.reserve(22);
        script.push_back(0x00);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        break;
    case 2: // P2SH: OP_HASH160 <20> OP_EQUAL
        script.reserve(23);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x87);
        break;
    default: // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        script.reserve(25);
        script.push_back(0x76);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x88);
        script.push_back(0xac);
        break;
    }
    return script;
}

// ============================================================================
// Helper: extract full scriptPubKey from a share variant
// ============================================================================
inline std::vector<unsigned char> get_share_script(const auto* obj)
{
    if constexpr (requires { obj->m_pubkey_type; })
        return pubkey_hash_to_script(obj->m_pubkey_hash, obj->m_pubkey_type);
    else if constexpr (requires { obj->m_address; })
        return obj->m_address.m_data;
    else
        return pubkey_hash_to_script(obj->m_pubkey_hash, 0);
}

// ============================================================================
// generate_share_transaction()
//
// Reconstructs the expected coinbase transaction from a share's fields and
// the PPLNS weights computed from the share chain.  Returns the expected
// gentx txid (double-SHA256 of the non-witness serialised transaction).
//
// This is the C++ port of p2pool v36's generate_transaction() / check().
//
// The coinbase structure is:
//   tx_ins:  [ { prev_output: 0...0:ffffffff, script: coinbase } ]
//   tx_outs: [ segwit_commitment?,
//              ...pplns_payout_outputs...,
//              donation_output,
//              op_return_commitment ]
//   lock_time: 0
//
// Reference: frstrtr/p2pool-merged-v36  p2pool/data.py  generate_transaction()
// ============================================================================
template <typename ShareT, typename TrackerT>
uint256 generate_share_transaction(const ShareT& share, TrackerT& tracker)
{
    constexpr int64_t ver = ShareT::version;
    const uint64_t subsidy = share.m_subsidy;
    const uint16_t donation = share.m_donation;

    // --- 1. Compute PPLNS weights with full scriptPubKey keys ---
    // Walk from share's prev_hash (parent) backward through the chain.
    // This matches the Python: weights are computed relative to the share's parent.

    auto prev_hash = share.m_prev_hash;
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        auto chain_len = std::min(
            tracker.chain.get_height(prev_hash),
            static_cast<int32_t>(PoolConfig::REAL_CHAIN_LENGTH));

        auto block_target = chain::bits_to_target(share.m_max_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * PoolConfig::SHARE_PERIOD * 65535;

        // Walk the chain share-by-share to get weights keyed by full script
        auto walk_count = static_cast<size_t>(chain_len);
        auto walk_view = tracker.chain.get_chain(prev_hash, walk_count);

        for (auto& [hash, data] : walk_view)
        {
            uint288 share_att;
            uint32_t share_don = 0;
            std::vector<unsigned char> script;

            data.share.invoke([&](auto* obj) {
                auto target = chain::bits_to_target(obj->m_bits);
                share_att = chain::target_to_average_attempts(target);
                share_don = obj->m_donation;
                script = get_share_script(obj);
            });

            uint288 share_total = share_att * 65535;
            uint288 share_don_w = share_att * share_don;

            if (total_weight + share_total > max_weight)
            {
                // Proportional inclusion of the last share
                auto remaining = max_weight - total_weight;
                auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);

                uint288 partial_addr;
                if (!share_total.IsNull())
                    partial_addr = remaining / 65535 * share_addr_weight / (share_total / 65535);

                if (weights.contains(script))
                    weights[script] += partial_addr;
                else
                    weights[script] = partial_addr;

                uint288 partial_donation;
                if (!share_total.IsNull())
                    partial_donation = remaining / 65535 * share_don_w / (share_total / 65535);

                total_donation_weight += partial_donation;
                total_weight = max_weight;
                break;
            }

            auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);
            if (weights.contains(script))
                weights[script] += share_addr_weight;
            else
                weights[script] = share_addr_weight;

            total_weight += share_total;
            total_donation_weight += share_don_w;
        }
    }

    // --- 2. Convert weights to exact integer payout amounts ---
    // Python formula:
    //   Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
    //            amounts[finder] += subsidy // 200
    //   V36:     amounts[script] = subsidy * weight / total_weight
    //   donation = subsidy - sum(amounts)

    std::map<std::vector<unsigned char>, uint64_t> amounts;

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount;
            if constexpr (ver >= 36)
            {
                // V36: amounts[script] = subsidy * weight / total_weight
                uint288 num = uint288(subsidy) * weight;
                amount = (num / total_weight).GetLow64();
            }
            else
            {
                // Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
                uint288 num = uint288(subsidy) * (weight * 199);
                uint288 den = total_weight * 200;
                amount = (num / den).GetLow64();
            }
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    // Pre-V36: add 0.5% finder fee to share creator
    if constexpr (ver < 36)
    {
        auto finder_script = get_share_script(&share);
        amounts[finder_script] += subsidy / 200;
    }

    // Donation output = subsidy minus sum of all payout amounts
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    // --- 3. Build sorted output list ---
    // Sort payout outputs by (amount desc, script asc) — Python sort is stable
    // and sorts by -amount first, then script order
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs(
        amounts.begin(), amounts.end());
    std::sort(payout_outputs.begin(), payout_outputs.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second; // desc by amount
            return a.first < b.first; // asc by script for tie-breaking
        });

    // Cap to MAX_COINBASE_OUTPUTS (Python default is 4000 for LTC)
    constexpr size_t MAX_OUTPUTS = 4000;
    if (payout_outputs.size() > MAX_OUTPUTS)
        payout_outputs.resize(MAX_OUTPUTS);

    // --- 4. Serialise the coinbase transaction ---
    // Non-witness serialization (for txid computation):
    //   version(4) + vin_count(varint) + vin + vout_count(varint) + vouts + locktime(4)
    PackStream tx;

    // tx version = 1
    uint32_t tx_version = 1;
    tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&tx_version), 4));

    // vin count = 1
    {
        unsigned char one = 1;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1));
    }

    // vin[0]: prev_output = 0...0:ffffffff, script = coinbase, sequence = 0
    {
        // prev_hash (32 zero bytes)
        uint256 zero_hash;
        tx << zero_hash;
        // prev_index (0xffffffff)
        uint32_t prev_idx = 0xffffffff;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&prev_idx), 4));
        // script (VarStr)
        tx << share.m_coinbase;
        // sequence
        uint32_t seq = 0;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4));
    }

    // Count total outputs
    size_t n_outs = payout_outputs.size() + 1 /* donation */ + 1 /* OP_RETURN commitment */;
    // Segwit commitment output (if applicable)
    bool has_segwit = false;
    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                has_segwit = true;
                n_outs += 1;
            }
        }
    }

    // vout count (varint — for < 253 outputs, it's a single byte)
    if (n_outs < 253)
    {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    }
    else
    {
        uint8_t marker = 0xfd;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    // Helper to write a single tx_out: value(8LE) + script(VarStr)
    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs;
        bs.m_data = script;
        tx << bs;
    };

    // Segwit commitment output (value=0, script=OP_RETURN + witness_commitment)
    if (has_segwit)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                // witness commitment: 0x6a24aa21a9ed + witness_merkle_root
                std::vector<unsigned char> wscript;
                wscript.push_back(0x6a); // OP_RETURN
                wscript.push_back(0x24); // PUSH 36
                wscript.push_back(0xaa);
                wscript.push_back(0x21);
                wscript.push_back(0xa9);
                wscript.push_back(0xed);
                // witness_merkle_root is hash256(witness_root || reserved_value)
                // For the commitment we need the wtxid_merkle_root from segwit_data
                auto& sd = share.m_segwit_data.value();
                auto root_bytes = sd.m_wtxid_merkle_root.GetChars();
                wscript.insert(wscript.end(), root_bytes.begin(), root_bytes.end());
                write_txout(0, wscript);
            }
        }
    }

    // PPLNS payout outputs
    for (auto& [script, amount] : payout_outputs)
        write_txout(amount, script);

    // Donation output
    auto donation_script = PoolConfig::get_donation_script(ver);
    write_txout(donation_amount, donation_script);

    // OP_RETURN commitment: value=0, script = 0x6a28 + ref_hash(32) + last_txout_nonce(8)
    {
        // We need the ref_hash — recompute it from the share the same way share_init_verify does
        PackStream ref_stream;

        // IDENTIFIER bytes
        {
            auto hex = PoolConfig::IDENTIFIER_HEX;
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                unsigned char byte = static_cast<unsigned char>(
                    std::stoul(hex.substr(i, 2), nullptr, 16));
                ref_stream.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&byte), 1));
            }
        }

        // share_info fields (same as share_init_verify)
        {
            ref_stream << share.m_prev_hash;
            ref_stream << share.m_coinbase;
            ref_stream << share.m_nonce;

            if constexpr (requires { share.m_address; })
                ref_stream << share.m_address;
            else if constexpr (requires { share.m_pubkey_type; })
            {
                ref_stream << share.m_pubkey_hash;
                ref_stream << share.m_pubkey_type;
            }
            else
                ref_stream << share.m_pubkey_hash;

            if constexpr (ver >= 36)
                ::Serialize(ref_stream, VarInt(share.m_subsidy));
            else
                ref_stream << share.m_subsidy;

            ref_stream << share.m_donation;
            {
                uint8_t si = static_cast<uint8_t>(share.m_stale_info);
                ref_stream << si;
            }
            ::Serialize(ref_stream, VarInt(share.m_desired_version));

            if constexpr (requires { share.m_segwit_data; })
            {
                if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
                {
                    if (share.m_segwit_data.has_value())
                        ref_stream << share.m_segwit_data.value();
                }
            }

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_merged_addresses; })
                    ref_stream << share.m_merged_addresses;
            }

            if constexpr (ver < 34)
            {
                if constexpr (requires { share.m_tx_info; })
                    ref_stream << share.m_tx_info;
            }

            ref_stream << share.m_far_share_hash;
            ref_stream << share.m_max_bits;
            ref_stream << share.m_bits;
            ref_stream << share.m_timestamp;
            ref_stream << share.m_absheight;

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_abswork; })
                    ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
            }
            else
            {
                ref_stream << share.m_abswork;
            }

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_merged_coinbase_info; })
                    ref_stream << share.m_merged_coinbase_info;
                if constexpr (requires { share.m_merged_payout_hash; })
                    ref_stream << share.m_merged_payout_hash;
            }
        }

        auto ref_span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
        uint256 hash_ref = Hash(ref_span);
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

        // Build OP_RETURN script: 0x6a 0x28 + ref_hash(32) + last_txout_nonce(8)
        std::vector<unsigned char> op_return_script;
        op_return_script.push_back(0x6a); // OP_RETURN
        op_return_script.push_back(0x28); // PUSH 40 bytes
        op_return_script.insert(op_return_script.end(), ref_hash.data(), ref_hash.data() + 32);
        {
            uint64_t nonce = share.m_last_txout_nonce;
            auto* p = reinterpret_cast<const unsigned char*>(&nonce);
            op_return_script.insert(op_return_script.end(), p, p + 8);
        }
        write_txout(0, op_return_script);
    }

    // lock_time = 0
    {
        uint32_t locktime = 0;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&locktime), 4));
    }

    // --- 5. Compute txid (double-SHA256 of non-witness serialization) ---
    auto tx_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(tx.data()), tx.size());
    return Hash(tx_span);
}

// ============================================================================
// share_check()
//
// The check()-phase verification after init:
//   1. Timestamp not too far in the future
//   2. Version counting (stub — version upgrade enforcement)
//   3. Transaction hash resolution (for pre-v34 shares)
//   4. GenerateShareTransaction reconstruction & comparison
//
// Returns true if the share passes all checks.
// Throws on validation failure.
// ============================================================================
template <typename ShareT, typename TrackerT>
bool share_check(const ShareT& share,
                 const uint256& share_hash,
                 const uint256& gentx_hash,
                 TrackerT& tracker)
{
    // 1. Timestamp check — must not be more than 600s in the future
    auto now = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    if (share.m_timestamp > now + 600)
        throw std::invalid_argument("share timestamp is too far in the future");

    // 2. Version counting — AutoRatchet upgrade enforcement
    // If 95% of recent shares desire a higher version, this share's version
    // is considered obsolete and must be rejected.
    {
        auto lookbehind = static_cast<int32_t>(PoolConfig::CHAIN_LENGTH);
        auto height = tracker.chain.get_height(share_hash);
        if (height >= lookbehind)
        {
            if (tracker.should_punish_version(share_hash, share.version, lookbehind))
                throw std::invalid_argument("share version too old — newer version has 95%+ activation");
        }
    }

    // 3. GenerateShareTransaction reconstruction & comparison
    // Rebuild the expected coinbase from PPLNS weights and share fields,
    // then verify its txid matches the gentx_hash from share_init_verify().
    if (!share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash))
    {
        uint256 expected_gentx = generate_share_transaction(share, tracker);
        if (expected_gentx != gentx_hash)
            throw std::invalid_argument("GenerateShareTransaction mismatch — coinbase does not match PPLNS payouts");
    }

    return true;
}

// ============================================================================
// verify_share()
//
// Combined entry point: runs both init-phase and check-phase verification.
// Returns the computed share hash.
// ============================================================================
template <typename ShareT, typename TrackerT>
uint256 verify_share(const ShareT& share, TrackerT& tracker)
{
    // share_init_verify computes gentx_hash along the way — we need it
    // for the GenerateShareTransaction comparison in share_check.
    // Re-extract gentx_hash by running the hash-link path.
    uint256 hash = share_init_verify(share);

    // Re-derive gentx_hash for the check phase
    constexpr int64_t ver = ShareT::version;
    auto gentx_before_refhash = compute_gentx_before_refhash(ver);

    // Rebuild ref_hash + hash_link_data the same way init does
    PackStream ref_stream;
    {
        auto hex = PoolConfig::IDENTIFIER_HEX;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }
    {
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_nonce;

        if constexpr (requires { share.m_address; })
            ref_stream << share.m_address;
        else if constexpr (requires { share.m_pubkey_type; })
        {
            ref_stream << share.m_pubkey_hash;
            ref_stream << share.m_pubkey_type;
        }
        else
            ref_stream << share.m_pubkey_hash;

        if constexpr (ver >= 36)
            ::Serialize(ref_stream, VarInt(share.m_subsidy));
        else
            ref_stream << share.m_subsidy;

        ref_stream << share.m_donation;
        {
            uint8_t si = static_cast<uint8_t>(share.m_stale_info);
            ref_stream << si;
        }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));

        if constexpr (requires { share.m_segwit_data; })
        {
            if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
            {
                if (share.m_segwit_data.has_value())
                    ref_stream << share.m_segwit_data.value();
            }
        }

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_addresses; })
                ref_stream << share.m_merged_addresses;
        }

        if constexpr (ver < 34)
        {
            if constexpr (requires { share.m_tx_info; })
                ref_stream << share.m_tx_info;
        }

        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_abswork; })
                ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
        }
        else
        {
            ref_stream << share.m_abswork;
        }

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_coinbase_info; })
                ref_stream << share.m_merged_coinbase_info;
            if constexpr (requires { share.m_merged_payout_hash; })
                ref_stream << share.m_merged_payout_hash;
        }
    }

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);

    std::vector<unsigned char> hash_link_data;
    {
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);
        hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
        uint32_t zero = 0;
        auto* z = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), z, z + 4);
    }

    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    share_check(share, hash, gentx_hash, tracker);
    return hash;
}

} // namespace ltc
