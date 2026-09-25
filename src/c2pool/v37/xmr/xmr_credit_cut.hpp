// SPDX-License-Identifier: AGPL-3.0-or-later
//
// recon(A+B credit): the ON-CHAIN CREDIT CUT.
//
// The payout side of XMR settlement reads the winner's coinbase from the block
// (coinbase authority, v37/xmr-recon-coinbase). The CREDIT side (E_b = who did
// how much work) is fold_eb(reward, view@P) -- a pure function of the receipt
// lane at ONE prefix P (w4_settlement.hpp S8). The block already commits
//   * the OWED side   : lane_commitment == owed_digest (0x03 MM leaf, r-seed)
//   * the reward      : Σ vout (exact-sum) == budget
//   * the payout map  : every vout under deterministic r
//   * bid / h_b       : the block id / txin_gen height
// The ONLY thing a receiver cannot get from the block today is WHICH lane
// prefix the winner folded at: (cut_next_pos, cut_spine_digest) -- 40 bytes.
// This PoC carries exactly those 40 bytes (+4 magic) in the coinbase 0x02
// extra-nonce payload, AFTER the per-worker nonce + weight padding:
//
//     0x02  varint(len)  [ nonce(4) | pad(0..10) | "V37C" | u64le P | b32 spine ]
//
// so deterministic r (lane_commitment/prev_id/height) and the 0x03 root are
// UNTOUCHED, the miner_tx weight stays invariant (a constant +44), and every
// byte is under the block's PoW. CONSENSUS SEAM (operator-hand at landing):
// this changes the coinbase bytes -> a coinbase-shape golden.
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32

namespace c2pool::v37n::xmr::credit {

inline constexpr unsigned char kMagic[4] = {'V', '3', '7', 'C'};
inline constexpr std::size_t   kTailBytes = 4 + 8 + 32;   // 44

struct CreditCut {
    std::uint64_t  next_pos = 0;        // P: the lane prefix E_b is folded at
    ::v37::bytes32 spine_digest{};      // LaneSnapshot::digest at P (the view's address + verifier)
    bool operator==(const CreditCut&) const = default;
};

inline std::vector<std::uint8_t> encode_tail(const CreditCut& c) {
    std::vector<std::uint8_t> t;
    t.reserve(kTailBytes);
    t.insert(t.end(), kMagic, kMagic + 4);
    for (int i = 0; i < 8; ++i) t.push_back(static_cast<std::uint8_t>(c.next_pos >> (8 * i)));
    t.insert(t.end(), c.spine_digest.begin(), c.spine_digest.end());
    return t;
}

// The whole 0x02 payload out of a tx_extra byte string (0x01 pubkey | 0x02
// nonce | 0x03 mm ...). nullopt if there is no 0x02 field.
inline std::optional<std::vector<std::uint8_t>> extra_nonce_field(const std::vector<unsigned char>& tx_extra) {
    std::size_t i = 0;
    while (i < tx_extra.size()) {
        const unsigned char tag = tx_extra[i++];
        if (tag == 0x00) continue;                       // padding
        if (tag == 0x01) { i += 32; continue; }          // pubkey
        // varint length for 0x02 / 0x03 / 0x04 ...
        std::uint64_t len = 0; int shift = 0;
        while (i < tx_extra.size()) {
            const unsigned char b = tx_extra[i++];
            len |= static_cast<std::uint64_t>(b & 0x7f) << shift; shift += 7;
            if (!(b & 0x80)) break;
        }
        if (i + len > tx_extra.size()) return std::nullopt;
        if (tag == 0x02) return std::vector<std::uint8_t>(tx_extra.begin() + i, tx_extra.begin() + i + len);
        i += len;
    }
    return std::nullopt;
}

// The credit cut at the END of a 0x02 payload (magic-checked). nullopt if absent.
inline std::optional<CreditCut> parse_tail(const std::vector<std::uint8_t>& nonce_payload) {
    if (nonce_payload.size() < kTailBytes) return std::nullopt;
    const std::uint8_t* t = nonce_payload.data() + nonce_payload.size() - kTailBytes;
    if (std::memcmp(t, kMagic, 4) != 0) return std::nullopt;
    CreditCut c;
    for (int i = 0; i < 8; ++i) c.next_pos |= static_cast<std::uint64_t>(t[4 + i]) << (8 * i);
    std::memcpy(c.spine_digest.data(), t + 12, 32);
    return c;
}

inline std::optional<CreditCut> parse_from_tx_extra(const std::vector<unsigned char>& tx_extra) {
    const auto f = extra_nonce_field(tx_extra);
    if (!f) return std::nullopt;
    return parse_tail(*f);
}

// ---------------------------------------------------------------------------
// POOL-LINEAGE (operator ruling 2026-09-25): the V37C tail's versioned pool-tag
// field. Every lane block a pool builds commits its pool_tag
// (xmr_pool_tag.hpp: sha256d('V37PT' || lane_tag || pool_genesis_id)) as
//
//     "V37P" | u8 version (= 1) | b32 pool_tag                        (37 B)
//
// placed IMMEDIATELY BEFORE the credit-cut tail (or last when the node has no
// cut yet), so the 0x02 payload of a lineage-tagged pool reads
//
//     [ nonce 4 | rbind? | pad | "V37D" u64le? | "V37P" v pool_tag | "V37C" P spine? ]
//
// parse_tail() above is unchanged (V37C stays LAST). The field is END-anchored
// like the rest of the tail, constant size, never patched per extra_nonce.
// STRICT parse: a "V37P" magic with any version other than 1 is MALFORMED (a
// reader never guesses the layout of a future version); no magic at the field
// position = an untagged (pre-lineage) tail.
// ---------------------------------------------------------------------------
inline constexpr unsigned char kPoolTagMagic[4]   = {'V', '3', '7', 'P'};
inline constexpr std::uint8_t  kPoolTagVersion    = 1;
inline constexpr std::size_t   kPoolTagFieldBytes = 4 + 1 + 32;   // 37

inline std::vector<std::uint8_t> encode_pool_tag_field(const ::v37::bytes32& pool_tag) {
    std::vector<std::uint8_t> t;
    t.reserve(kPoolTagFieldBytes);
    t.insert(t.end(), kPoolTagMagic, kPoolTagMagic + 4);
    t.push_back(kPoolTagVersion);
    t.insert(t.end(), pool_tag.begin(), pool_tag.end());
    return t;
}

enum class PoolTagParse : std::uint8_t {
    Absent    = 0,   // no V37P field: an untagged (pre-lineage) payload
    Present   = 1,   // a version-1 field; pool_tag filled
    Malformed = 2,   // the V37P magic with an unknown version (strict reject)
};

// End offset of the part of a 0x02 payload BEFORE the credit-cut tail (the
// payload size when there is no V37C tail).
inline std::size_t end_before_credit_tail(const std::vector<std::uint8_t>& p) {
    std::size_t end = p.size();
    if (end >= kTailBytes && std::memcmp(p.data() + end - kTailBytes, kMagic, 4) == 0) end -= kTailBytes;
    return end;
}

inline PoolTagParse parse_pool_tag_payload(const std::vector<std::uint8_t>& p, ::v37::bytes32* pool_tag = nullptr) {
    const std::size_t end = end_before_credit_tail(p);
    if (end < kPoolTagFieldBytes) return PoolTagParse::Absent;
    const std::uint8_t* f = p.data() + end - kPoolTagFieldBytes;
    if (std::memcmp(f, kPoolTagMagic, 4) != 0) return PoolTagParse::Absent;
    if (f[4] != kPoolTagVersion) return PoolTagParse::Malformed;
    if (pool_tag) std::memcpy(pool_tag->data(), f + 5, 32);
    return PoolTagParse::Present;
}

inline PoolTagParse parse_pool_tag(const std::vector<unsigned char>& tx_extra, ::v37::bytes32* pool_tag = nullptr) {
    const auto f = extra_nonce_field(tx_extra);
    if (!f) return PoolTagParse::Absent;
    return parse_pool_tag_payload(*f, pool_tag);
}

// ---------------------------------------------------------------------------
// POOL-LINEAGE: chain-block classification by the V37C tail's pool tag
// (xmr_pool_tag.hpp derives the tag).
// ---------------------------------------------------------------------------
enum class BlockLineage : std::uint8_t {
    Own       = 0,   // carries OUR pool_tag: a lane block of this pool
    Foreign   = 1,   // carries ANOTHER pool's tag: an ordinary block here
    Untagged  = 2,   // no V37P field (pre-lineage tail / not a v37 block): ordinary
    Malformed = 3,   // a V37P magic of an unknown version: strict reject -> ordinary
};

inline const char* to_string(BlockLineage c) {
    switch (c) {
        case BlockLineage::Own:       return "own";
        case BlockLineage::Foreign:   return "foreign";
        case BlockLineage::Untagged:  return "untagged";
        case BlockLineage::Malformed: return "malformed";
    }
    return "?";
}

inline BlockLineage classify_lineage(const std::vector<unsigned char>& tx_extra, const ::v37::bytes32& our_pool_tag,
                             ::v37::bytes32* seen = nullptr) {
    ::v37::bytes32 t{};
    switch (parse_pool_tag(tx_extra, &t)) {
        case PoolTagParse::Absent:    return BlockLineage::Untagged;
        case PoolTagParse::Malformed: return BlockLineage::Malformed;
        case PoolTagParse::Present:   break;
    }
    if (seen) *seen = t;
    return t == our_pool_tag ? BlockLineage::Own : BlockLineage::Foreign;
}

} // namespace c2pool::v37n::xmr::credit
