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
//     0x02  varint(len)  [ nonce(4) | V37P v2 (45) | rbind? | pad(0..10) | ... | "V37C" | u64le P | b32 spine ]
//
// (RULES RATCHET R1: the pool-identity field V37P v2 rides FIRST after the
// nonce, see below; the credit cut stays the END-anchored tail.) So deterministic r (lane_commitment/prev_id/height) and the 0x03 root are
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
// POOL IDENTITY (RULES RATCHET R1, operator rulings 2026-10-03): the V37P v2
// field at the FIXED OFFSET, first in the 0x02 payload after the 4-byte extra
// nonce, BEFORE the per-job rbind:
//
//     V37P v2 (45 B) = "V37P" | u8 0x02 | b32 pool_id | u32 epoch_cur | u32 epoch_max
//     0x02 payload   = [ nonce 4 | V37P 45 | rbind 32? | pad 0..10 | "V37R" 12 | "V37F" 69? |
//                        "V37N" 12? | "V37D" 12? | "V37C" 44 ]
//     offsets        : V37P at [4..49); rbind at [49..81) when present; V37C END-anchored
//     widest payload : 4 + 45 + 32 + 10 + 12 + 69 + 12 + 12 + 44 = 240 B (<= 255, Monero's
//                      TX_EXTRA_NONCE_MAX_COUNT; the length is a two-byte varint)
//
// A node of ANY epoch finds (pool_id, epoch_cur) at 0x02[4..49) in every later
// block whatever later epochs put behind it. epoch_cur = the epoch the coinbase
// was built under (must equal epoch_of(height)); epoch_max = the highest epoch
// the builder's binary implements (a capability, the follower's WARN / HOLD
// input; never a vote). The field is per TEMPLATE (never patched per job); the
// nonce and rbind are per job. STRICT parse: a "V37P" magic with any version
// other than 2 is MALFORMED (a reader never guesses the layout of another
// version); no magic at [4..8) = an Untagged payload (not a lane block).
// ---------------------------------------------------------------------------
inline constexpr unsigned char kPoolFieldMagic[4] = {'V', '3', '7', 'P'};
inline constexpr std::uint8_t  kPoolFieldVersion  = 2;
inline constexpr std::size_t   kPoolFieldOffset   = 4;                 // right after the 4-byte extra nonce
inline constexpr std::size_t   kPoolFieldBytes    = 4 + 1 + 32 + 4 + 4; // 45
inline constexpr std::size_t   kRbindOffset       = kPoolFieldOffset + kPoolFieldBytes;   // 49: rbind at [49..81)

struct PoolField {
    ::v37::bytes32 pool_id{};
    std::uint32_t  epoch_cur = 1;
    std::uint32_t  epoch_max = 1;
    bool operator==(const PoolField&) const = default;
};

inline std::vector<std::uint8_t> encode_pool_field(const PoolField& f) {
    std::vector<std::uint8_t> t;
    t.reserve(kPoolFieldBytes);
    t.insert(t.end(), kPoolFieldMagic, kPoolFieldMagic + 4);
    t.push_back(kPoolFieldVersion);
    t.insert(t.end(), f.pool_id.begin(), f.pool_id.end());
    for (int i = 0; i < 4; ++i) t.push_back(static_cast<std::uint8_t>(f.epoch_cur >> (8 * i)));
    for (int i = 0; i < 4; ++i) t.push_back(static_cast<std::uint8_t>(f.epoch_max >> (8 * i)));
    return t;
}

enum class PoolFieldParse : std::uint8_t {
    Absent    = 0,   // no V37P magic at [4..8): an untagged payload (not a lane block)
    Present   = 1,   // a version-2 field; `out` filled
    Malformed = 2,   // the V37P magic with another version (strict reject)
};

// End offset of the part of a 0x02 payload BEFORE the credit-cut tail (the
// payload size when there is no V37C tail).
inline std::size_t end_before_credit_tail(const std::vector<std::uint8_t>& p) {
    std::size_t end = p.size();
    if (end >= kTailBytes && std::memcmp(p.data() + end - kTailBytes, kMagic, 4) == 0) end -= kTailBytes;
    return end;
}

inline PoolFieldParse parse_pool_field_payload(const std::vector<std::uint8_t>& p, PoolField* out = nullptr) {
    if (p.size() < kPoolFieldOffset + 4) return PoolFieldParse::Absent;
    const std::uint8_t* f = p.data() + kPoolFieldOffset;
    if (std::memcmp(f, kPoolFieldMagic, 4) != 0) return PoolFieldParse::Absent;
    if (p.size() < kPoolFieldOffset + kPoolFieldBytes || f[4] != kPoolFieldVersion) return PoolFieldParse::Malformed;
    if (out) {
        std::memcpy(out->pool_id.data(), f + 5, 32);
        out->epoch_cur = 0; out->epoch_max = 0;
        for (int i = 0; i < 4; ++i) out->epoch_cur |= static_cast<std::uint32_t>(f[37 + i]) << (8 * i);
        for (int i = 0; i < 4; ++i) out->epoch_max |= static_cast<std::uint32_t>(f[41 + i]) << (8 * i);
    }
    return PoolFieldParse::Present;
}

inline PoolFieldParse parse_pool_field(const std::vector<unsigned char>& tx_extra, PoolField* out = nullptr) {
    const auto f = extra_nonce_field(tx_extra);
    if (!f) return PoolFieldParse::Absent;
    return parse_pool_field_payload(*f, out);
}

// ---------------------------------------------------------------------------
// Chain-block classification by the V37P v2 field (spec sec. 1.4). The EPOCH
// decision (validate / misbuilt / HOLD) is taken by the booking code, which
// knows the ledger's epoch_of(h); this classifier answers the POOL question and
// hands back (pool_id, epoch_cur, epoch_max).
// ---------------------------------------------------------------------------
enum class BlockLineage : std::uint8_t {
    Own       = 0,   // carries OUR pool_id: a lane block of this pool
    Foreign   = 1,   // carries ANOTHER pool's id: an ordinary block here
    Untagged  = 2,   // no V37P field (not a v37 lane block): ordinary
    Malformed = 3,   // a V37P magic of another version: strict reject -> ordinary
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

inline BlockLineage classify_lineage(const std::vector<unsigned char>& tx_extra, const ::v37::bytes32& our_pool_id,
                                     PoolField* seen = nullptr) {
    PoolField f;
    switch (parse_pool_field(tx_extra, &f)) {
        case PoolFieldParse::Absent:    return BlockLineage::Untagged;
        case PoolFieldParse::Malformed: return BlockLineage::Malformed;
        case PoolFieldParse::Present:   break;
    }
    if (seen) *seen = f;
    return f.pool_id == our_pool_id ? BlockLineage::Own : BlockLineage::Foreign;
}

} // namespace c2pool::v37n::xmr::credit
