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

} // namespace c2pool::v37n::xmr::credit
