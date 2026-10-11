// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_lane_rules.hpp
// Path B lane rules (the K list), the rules block, rules_digest, the genesis
// digest G per network, and the K20 monero_rules_digest.
//
//   rules block  = u8 codec (K22 = 2) | LE16 rules_len | TLV
//   TLV entry    = u8 id | u8 len | value; id = the K number, ids strictly
//                  ascending; integers little-endian; digests and key
//                  references raw
//   rules_digest = sha256d("c2pool-v37-xmr-lane-rules-v1" || rules block)
//                  (the 28 domain bytes without a terminator; 294 preimage
//                  bytes at epoch 0)
//   G(net)       = rules_digest of the epoch-0 list of the network
//
//   id   field                K       value(s)                              bytes
//   0x01 carrier_interval_s   K01     10                                    u64
//   0x02 d_min                K02     18180                                 u64
//   0x03 retarget             K03     N_rt 2160, formula 1, m_rt 9          u64 u8 u64
//   0x04 open_bins            K04     96                                    u64
//   0x05 liveness_delta       K05     1                                     u64
//   0x06 seal_depth           K06     0                                     u64
//   0x07 fresh_max            K07     2                                     u64
//   0x08 r_max                K08     16                                    u64
//   0x09 coverage             K09     2                                     u8
//   0x0a n_rule_version       K10     1                                     u8
//   0x0b w_max_rule_version   K11     1                                     u8
//   0x0f owner_fee_version    K15     1                                     u8
//   0x10 donation             K16     give_author_bp 10, author_ref(net)    u16 ref[66]
//   0x11 payment_groups       K17     1                                     u8
//   0x12 receipt_size_rule    K18     1                                     u8
//   0x14 monero_rules_digest  K20     K20 below                             b32
//   0x15 side_data_and_format K21     side_data 3, payee 0x10, coinbase 1   u8 u8 u8
//   0x17 roundabout_chains    K23     1                                     u8
//   0x18 ovh_out              K24     89, 61, 34, 84                        4 x u16
//   0x19 coinbase_reserve     K25     divisor 2, N_min 1                    u8 u8
//   0x1d split_rule_version   K29     1                                     u8
//   0x1e ratchet              K30     rule 1, L, GRACE, TIMEOUT             u8 3 x u64
//   22 entries, 263 B at epoch 0. K22 is the codec byte; epoch_cur travels in
//   the HELLO trailer (pathb_hello.hpp); the pool identity is not an entry.
//
//   monero_rules_digest (K20) = sha256d("c2pool-v37-xmr-monero-rules-v1" || TLV)
//     id = 1.. in the order of kMoneroRules; u64 value (len 8), (hf16, hf17)
//     pair (len 16) or u8 formula version (len 1); 26 entries, 287 B.
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "impl/xmr/native/consensus/xmr_hf_table.hpp"   // hf_ring_size
#include "impl/xmr/native/consensus/xmr_reward.hpp"     // MONEY_SUPPLY, EMISSION_SPEED_FACTOR_PER_MINUTE, FINAL_SUBSIDY_PER_MINUTE
#include "impl/xmr/native/consensus/xmr_timestamp.hpp"  // BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW
#include "impl/xmr/native/consensus/xmr_weight.hpp"     // CRYPTONOTE_REWARD_BLOCKS_WINDOW, ..._LONG_TERM_...

#include "pathb_caps.hpp"                 // kMinTxWeight, zone, surge_factor, tree_extra_leaves, block_trailer_bytes
#include "pathb_emission.hpp"             // kInputWeight, fee_reference_weight, kFeeQuantizationStep, ovh, OUT bases
#include "pathb_params.hpp"
#include "pathb_ratchet_state.hpp"        // kRuledRatchetParams
#include "pathb_receipt_admission.hpp"    // kLivenessDelta
#include "pathb_retarget.hpp"             // retarget_min_span
#include "pathb_window.hpp"               // kCoverage
#include "pathb_wire_v3.hpp"              // kSideDataV3Version, kPayeeKindXmrStd, kKeyRefBytes

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Networks (the relay HELLO network byte)
// ---------------------------------------------------------------------------
enum class LaneNet : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2, Regtest = 3 };

inline constexpr std::array<LaneNet, 4> kLaneNets{LaneNet::Mainnet, LaneNet::Testnet, LaneNet::Stagenet,
                                                  LaneNet::Regtest};

inline constexpr std::string_view lane_net_name(LaneNet n) noexcept {
    switch (n) {
        case LaneNet::Testnet: return "testnet";
        case LaneNet::Stagenet: return "stagenet";
        case LaneNet::Regtest: return "regtest";
        case LaneNet::Mainnet: break;
    }
    return "mainnet";
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------
namespace lr_detail {

inline constexpr unsigned kByteBits = 8;

inline void put_le(std::vector<std::uint8_t>& out, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) out.push_back(static_cast<std::uint8_t>(v >> (kByteBits * i)));
}

inline std::uint64_t get_le(const std::uint8_t* p, std::size_t width) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i) v |= std::uint64_t{p[i]} << (kByteBits * i);
    return v;
}

inline constexpr std::uint8_t hex_nibble(char c) noexcept {
    return static_cast<std::uint8_t>(c >= '0' && c <= '9'   ? c - '0'
                                     : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                            : c - 'A' + 10);
}

inline std::string hex(const std::uint8_t* p, std::size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(kDigits[p[i] >> 4]);
        s.push_back(kDigits[p[i] & 0x0f]);
    }
    return s;
}

}  // namespace lr_detail

// ---------------------------------------------------------------------------
// K16 author reference (XmrKeyRef: spend B, view A), the per-network donation
// keys of src/c2pool/v37/xmr/xmr_fee_model.hpp; on the TLV as put_key_ref
// writes it: kind 0x10 | len 64 | spend | view (66 B).
// ---------------------------------------------------------------------------
inline constexpr char kAuthorSpendHexMainnet[] = "14d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7";
inline constexpr char kAuthorViewHexMainnet[] = "b3157741ab68969aeb7fe9ebd4fa3ec5ce4dcdc7b43249fdb40311cb03779e03";
inline constexpr char kAuthorSpendHexTestnet[] = "a7731abbe9bb2cf3264395231a8645172ffd7f08c6097e3402197f3f1c6ffcbb";
inline constexpr char kAuthorViewHexTestnet[] = "ef3c9a659a67c3bf081a352e7cfbfb94cc5e11921a3e8953223fca1ed14e2200";
inline constexpr char kAuthorSpendHexStagenet[] = "7f095705904be1df109bdf44b0027c339fde3ece7d85069f8bdfb19fd8c16c41";
inline constexpr char kAuthorViewHexStagenet[] = "0abca326ba53a6f5387785822296c1d15df03e6c51cd44d7dbe270667b5fe34c";
inline constexpr char kAuthorSpendHexRegtest[] = "3091e80a51918c67eb67b6fefaf77e374dd898240953bbb75d47b82b8615c638";
inline constexpr char kAuthorViewHexRegtest[] = "c5d453f0d54332e4f48f12abab2551132f00037f0c51892ebe3b41928ab5bec1";

inline constexpr XmrKeyRef make_key_ref(const char* spend_hex, const char* view_hex) noexcept {
    XmrKeyRef r{};
    for (std::size_t i = 0; i < kHashBytes; ++i) {
        r.spend[i] = static_cast<std::uint8_t>((lr_detail::hex_nibble(spend_hex[2 * i]) << 4)
                                               | lr_detail::hex_nibble(spend_hex[2 * i + 1]));
        r.view[i] = static_cast<std::uint8_t>((lr_detail::hex_nibble(view_hex[2 * i]) << 4)
                                              | lr_detail::hex_nibble(view_hex[2 * i + 1]));
    }
    return r;
}

inline constexpr XmrKeyRef author_ref(LaneNet n) noexcept {
    switch (n) {
        case LaneNet::Testnet: return make_key_ref(kAuthorSpendHexTestnet, kAuthorViewHexTestnet);
        case LaneNet::Stagenet: return make_key_ref(kAuthorSpendHexStagenet, kAuthorViewHexStagenet);
        case LaneNet::Regtest: return make_key_ref(kAuthorSpendHexRegtest, kAuthorViewHexRegtest);
        case LaneNet::Mainnet: break;
    }
    return make_key_ref(kAuthorSpendHexMainnet, kAuthorViewHexMainnet);
}

// identity = key_ref_identity(XmrKeyRef) (pathb_wire_v3.hpp).
inline Hash32 author_identity(LaneNet n) { return key_ref_identity(author_ref(n)); }

// K16 default give_author_bp.
inline constexpr std::uint16_t kDonationBp = 10;

// ---------------------------------------------------------------------------
// K20 monero_rules_digest
// ---------------------------------------------------------------------------
inline constexpr std::string_view kMoneroRulesDomain = "c2pool-v37-xmr-monero-rules-v1";

enum class MoneroRuleClass : std::uint8_t { Scalar, Pair, Version };

struct MoneroRule {
    std::uint8_t id = 0;
    std::string_view name;
    MoneroRuleClass cls = MoneroRuleClass::Scalar;
    std::uint64_t hf16 = 0;  // the value (Scalar), the hf 16 value (Pair) or the formula version (Version)
    std::uint64_t hf17 = 0;  // the hf 17 value (Pair)
};

inline constexpr std::uint8_t kHf17 = HF_VERSION_FCMP_PLUS_PLUS;

// Formula versions: 1 = the rule as Monero's hf 16 / hf 17 code has it.
inline constexpr std::uint64_t kFeeFactorRuleVersion = 1;        // lo -= lo / 20 at hf <= 16
inline constexpr std::uint64_t kBlockWeightLimitRuleVersion = 1;  // limit = kBlockWeightLimitPerMedian x median
inline constexpr std::uint64_t kOutFormulaVersion = 1;            // OUT(hf) = base(hf) + V(amount)
static_assert(kBlockWeightLimitPerMedian == 2);

inline constexpr std::array<MoneroRule, 26> kMoneroRules{{
    {1, "DIFFICULTY_TARGET_V2", MoneroRuleClass::Scalar, DIFFICULTY_TARGET_V2, 0},
    {2, "DIFFICULTY_WINDOW", MoneroRuleClass::Scalar, DIFFICULTY_WINDOW, 0},
    {3, "DIFFICULTY_LAG", MoneroRuleClass::Scalar, DIFFICULTY_LAG, 0},
    {4, "CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW", MoneroRuleClass::Scalar, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, 0},
    {5, "MONEY_SUPPLY", MoneroRuleClass::Scalar, ::c2pool::xmr::native::MONEY_SUPPLY, 0},
    {6, "EMISSION_SPEED_FACTOR_PER_MINUTE", MoneroRuleClass::Scalar,
     static_cast<std::uint64_t>(::c2pool::xmr::native::EMISSION_SPEED_FACTOR_PER_MINUTE), 0},
    {7, "FINAL_SUBSIDY_PER_MINUTE", MoneroRuleClass::Scalar, ::c2pool::xmr::native::FINAL_SUBSIDY_PER_MINUTE, 0},
    {8, "kInputWeight", MoneroRuleClass::Scalar, kInputWeight, 0},
    {9, "DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT", MoneroRuleClass::Pair, fee_reference_weight(kHf16),
     fee_reference_weight(kHf17)},
    {10, "CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5", MoneroRuleClass::Pair, zone(kHf16), zone(kHf17)},
    {11, "fee_quantum", MoneroRuleClass::Scalar, kFeeQuantizationStep, 0},
    {12, "fee_factor_0_95", MoneroRuleClass::Version, kFeeFactorRuleVersion, 0},
    {13, "ring_size", MoneroRuleClass::Scalar, ::c2pool::xmr::native::hf_ring_size(kHf16), 0},
    {14, "FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS", MoneroRuleClass::Scalar, FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS, 0},
    {15, "w_min", MoneroRuleClass::Scalar, kMinTxWeight, 0},
    {16, "X_hf", MoneroRuleClass::Pair, tree_extra_leaves(kHf16), tree_extra_leaves(kHf17)},
    {17, "SURGE", MoneroRuleClass::Pair, surge_factor(kHf16), surge_factor(kHf17)},
    {18, "CRYPTONOTE_REWARD_BLOCKS_WINDOW", MoneroRuleClass::Scalar,
     ::c2pool::xmr::native::CRYPTONOTE_REWARD_BLOCKS_WINDOW, 0},
    {19, "CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE", MoneroRuleClass::Scalar,
     ::c2pool::xmr::native::CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE, 0},
    {20, "BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW", MoneroRuleClass::Scalar,
     ::c2pool::xmr::native::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, 0},
    {21, "SEEDHASH_EPOCH_BLOCKS", MoneroRuleClass::Scalar, SEEDHASH_EPOCH_BLOCKS, 0},
    {22, "SEEDHASH_EPOCH_LAG", MoneroRuleClass::Scalar, SEEDHASH_EPOCH_LAG, 0},
    {23, "block_weight_limit", MoneroRuleClass::Version, kBlockWeightLimitRuleVersion, 0},
    {24, "TRAILER", MoneroRuleClass::Pair, block_trailer_bytes(kHf16), block_trailer_bytes(kHf17)},
    {25, "OUT_formula", MoneroRuleClass::Version, kOutFormulaVersion, 0},
    {26, "OVH", MoneroRuleClass::Pair, ovh(kHf16), ovh(kHf17)},
}};

inline constexpr std::size_t monero_rule_value_bytes(MoneroRuleClass c) noexcept {
    return c == MoneroRuleClass::Pair ? 2 * kU64Bytes : c == MoneroRuleClass::Version ? kU8Bytes : kU64Bytes;
}

inline std::vector<std::uint8_t> monero_rules_tlv(std::span<const MoneroRule> rules) {
    std::vector<std::uint8_t> out;
    for (const MoneroRule& r : rules) {
        out.push_back(r.id);
        out.push_back(static_cast<std::uint8_t>(monero_rule_value_bytes(r.cls)));
        if (r.cls == MoneroRuleClass::Version) {
            lr_detail::put_le(out, r.hf16, kU8Bytes);
        } else {
            lr_detail::put_le(out, r.hf16, kU64Bytes);
            if (r.cls == MoneroRuleClass::Pair) lr_detail::put_le(out, r.hf17, kU64Bytes);
        }
    }
    return out;
}

inline Hash32 monero_rules_digest(std::span<const MoneroRule> rules) {
    std::vector<std::uint8_t> pre(kMoneroRulesDomain.begin(), kMoneroRulesDomain.end());
    const std::vector<std::uint8_t> t = monero_rules_tlv(rules);
    pre.insert(pre.end(), t.begin(), t.end());
    return ::v37::sha256d(pre);
}

inline Hash32 monero_rules_digest() { return monero_rules_digest(kMoneroRules); }

// ---------------------------------------------------------------------------
// The Path B lane rules
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kPathbRulesCodec = 2;  // K22
inline constexpr std::string_view kLaneRulesDomain = "c2pool-v37-xmr-lane-rules-v1";
inline constexpr std::string_view kLaneRulesMismatchText = "LANE_RULES_MISMATCH";

// Rule and format versions of the epoch-0 list.
inline constexpr std::uint8_t kRetargetFormulaVersion = 1;   // K03b
inline constexpr std::uint8_t kNRuleVersion = 1;             // K10
inline constexpr std::uint8_t kWMaxRuleVersion = 1;          // K11
inline constexpr std::uint8_t kOwnerFeeVersion = 1;          // K15
inline constexpr std::uint8_t kPaymentGroups = 1;            // K17
inline constexpr std::uint8_t kReceiptSizeRuleVersion = 1;   // K18
inline constexpr std::uint8_t kCoinbaseFormatVersion = 1;    // K21
inline constexpr std::uint8_t kRoundaboutChains = 1;         // K23
inline constexpr std::uint8_t kReserveDivisor = 2;           // K25a
inline constexpr std::uint8_t kReserveNMin = 1;              // K25b
inline constexpr std::uint8_t kSplitRuleVersion = 1;         // K29
inline constexpr std::uint8_t kRatchetRuleVersion = 1;       // K30a

struct PathbLaneRules {
    std::uint64_t carrier_interval_s = 0;      // 0x01 K01
    std::uint64_t d_min = 0;                   // 0x02 K02
    std::uint64_t retarget_span = 0;           // 0x03 K03a
    std::uint8_t retarget_formula = 0;         //      K03b
    std::uint64_t retarget_min_span = 0;       //      K03c
    std::uint64_t open_bins = 0;               // 0x04 K04
    std::uint64_t liveness_delta = 0;          // 0x05 K05
    std::uint64_t seal_depth = 0;              // 0x06 K06
    std::uint64_t fresh_max = 0;               // 0x07 K07
    std::uint64_t r_max = 0;                   // 0x08 K08
    std::uint8_t coverage = 0;                 // 0x09 K09
    std::uint8_t n_rule_version = 0;           // 0x0a K10
    std::uint8_t w_max_rule_version = 0;       // 0x0b K11
    std::uint8_t owner_fee_version = 0;        // 0x0f K15
    std::uint16_t give_author_bp = 0;          // 0x10 K16
    XmrKeyRef author{};                        //      K16
    std::uint8_t payment_groups = 0;           // 0x11 K17
    std::uint8_t receipt_size_rule = 0;        // 0x12 K18
    Hash32 monero_rules_digest{};              // 0x14 K20
    std::uint8_t side_data_version = 0;        // 0x15 K21a
    std::uint8_t payee_kind = 0;               //      K21c
    std::uint8_t coinbase_format_version = 0;  //      K21
    std::uint8_t roundabout_chains = 0;        // 0x17 K23
    std::uint16_t ovh_hf16 = 0;                // 0x18 K24a
    std::uint16_t ovh_hf17 = 0;
    std::uint16_t out_base_hf16 = 0;           //      K24b
    std::uint16_t out_base_hf17 = 0;
    std::uint8_t reserve_divisor = 0;          // 0x19 K25a
    std::uint8_t reserve_n_min = 0;            //      K25b
    std::uint8_t split_rule_version = 0;       // 0x1d K29
    std::uint8_t ratchet_version = 0;          // 0x1e K30a
    std::uint64_t vote_window = 0;             //      K30b L
    std::uint64_t grace = 0;                   //      K30c
    std::uint64_t timeout = 0;                 //      K30d

    friend bool operator==(const PathbLaneRules&, const PathbLaneRules&) = default;
};

// The field set (the X-macro of record): id, name, value bytes.
#define C2POOL_PATHB_LANE_RULES_FIELDS(X)    \
    X(0x01, carrier_interval_s, 8)           \
    X(0x02, d_min, 8)                        \
    X(0x03, retarget, 17)                    \
    X(0x04, open_bins, 8)                    \
    X(0x05, liveness_delta, 8)               \
    X(0x06, seal_depth, 8)                   \
    X(0x07, fresh_max, 8)                    \
    X(0x08, r_max, 8)                        \
    X(0x09, coverage, 1)                     \
    X(0x0a, n_rule_version, 1)               \
    X(0x0b, w_max_rule_version, 1)           \
    X(0x0f, owner_fee_version, 1)            \
    X(0x10, donation, 68)                    \
    X(0x11, payment_groups, 1)               \
    X(0x12, receipt_size_rule, 1)            \
    X(0x14, monero_rules_digest, 32)         \
    X(0x15, side_data_and_format, 3)         \
    X(0x17, roundabout_chains, 1)            \
    X(0x18, ovh_out, 8)                      \
    X(0x19, coinbase_reserve, 2)             \
    X(0x1d, split_rule_version, 1)           \
    X(0x1e, ratchet, 25)

struct LaneRuleField {
    std::uint8_t id;
    std::string_view name;
    std::size_t len;
};

inline constexpr LaneRuleField kPathbLaneRuleFields[] = {
#define C2POOL_PATHB_LR_FIELD(fid, fname, flen) {fid, #fname, flen},
    C2POOL_PATHB_LANE_RULES_FIELDS(C2POOL_PATHB_LR_FIELD)
#undef C2POOL_PATHB_LR_FIELD
};

inline constexpr std::size_t kPathbLaneRuleFieldCount = std::size(kPathbLaneRuleFields);
static_assert(kPathbLaneRuleFieldCount == 22);

inline constexpr std::size_t kHeaderBytes = 2;  // u8 id | u8 len

inline constexpr std::size_t pathb_lane_rules_tlv_bytes() noexcept {
    std::size_t n = 0;
    for (const LaneRuleField& f : kPathbLaneRuleFields) n += kHeaderBytes + f.len;
    return n;
}
static_assert(pathb_lane_rules_tlv_bytes() == 263);

inline constexpr const LaneRuleField* lane_rule_field(std::uint8_t id) noexcept {
    for (const LaneRuleField& f : kPathbLaneRuleFields)
        if (f.id == id) return &f;
    return nullptr;
}

// The epoch-0 list of a network. K30 of every network is kRuledRatchetParams
// (a rig may run regtest with other K30 values; G is then computed at start).
inline PathbLaneRules epoch0_lane_rules(LaneNet n) {
    const LaneParams& p = kRuledLaneParams;
    PathbLaneRules r;
    r.carrier_interval_s = p.carrier_interval_s;
    r.d_min = p.d_min;
    r.retarget_span = p.retarget_span;
    r.retarget_formula = kRetargetFormulaVersion;
    r.retarget_min_span = retarget_min_span(p);
    r.open_bins = p.open_bins;
    r.liveness_delta = kLivenessDelta;
    r.seal_depth = seal_depth(p);
    r.fresh_max = p.fresh_max;
    r.r_max = p.r_max;
    r.coverage = static_cast<std::uint8_t>(kCoverage);
    r.n_rule_version = kNRuleVersion;
    r.w_max_rule_version = kWMaxRuleVersion;
    r.owner_fee_version = kOwnerFeeVersion;
    r.give_author_bp = kDonationBp;
    r.author = author_ref(n);
    r.payment_groups = kPaymentGroups;
    r.receipt_size_rule = kReceiptSizeRuleVersion;
    r.monero_rules_digest = monero_rules_digest();
    r.side_data_version = kSideDataV3Version;
    r.payee_kind = kPayeeKindXmrStd;
    r.coinbase_format_version = kCoinbaseFormatVersion;
    r.roundabout_chains = kRoundaboutChains;
    r.ovh_hf16 = static_cast<std::uint16_t>(kOvhHf16);
    r.ovh_hf17 = static_cast<std::uint16_t>(kOvhHf17);
    r.out_base_hf16 = static_cast<std::uint16_t>(kOutBaseHf16);
    r.out_base_hf17 = static_cast<std::uint16_t>(kOutBaseHf17);
    r.reserve_divisor = kReserveDivisor;
    r.reserve_n_min = kReserveNMin;
    r.split_rule_version = kSplitRuleVersion;
    r.ratchet_version = kRatchetRuleVersion;
    r.vote_window = kRuledRatchetParams.window;
    r.grace = kRuledRatchetParams.grace;
    r.timeout = kRuledRatchetParams.timeout;
    return r;
}

// The value bytes of field `id`.
inline std::vector<std::uint8_t> lane_rule_value(const PathbLaneRules& r, std::uint8_t id) {
    using lr_detail::put_le;
    std::vector<std::uint8_t> v;
    switch (id) {
        case 0x01: put_le(v, r.carrier_interval_s, kU64Bytes); break;
        case 0x02: put_le(v, r.d_min, kU64Bytes); break;
        case 0x03:
            put_le(v, r.retarget_span, kU64Bytes);
            put_le(v, r.retarget_formula, kU8Bytes);
            put_le(v, r.retarget_min_span, kU64Bytes);
            break;
        case 0x04: put_le(v, r.open_bins, kU64Bytes); break;
        case 0x05: put_le(v, r.liveness_delta, kU64Bytes); break;
        case 0x06: put_le(v, r.seal_depth, kU64Bytes); break;
        case 0x07: put_le(v, r.fresh_max, kU64Bytes); break;
        case 0x08: put_le(v, r.r_max, kU64Bytes); break;
        case 0x09: put_le(v, r.coverage, kU8Bytes); break;
        case 0x0a: put_le(v, r.n_rule_version, kU8Bytes); break;
        case 0x0b: put_le(v, r.w_max_rule_version, kU8Bytes); break;
        case 0x0f: put_le(v, r.owner_fee_version, kU8Bytes); break;
        case 0x10:
            put_le(v, r.give_author_bp, kU16Bytes);
            detail::put_key_ref(v, r.author);
            break;
        case 0x11: put_le(v, r.payment_groups, kU8Bytes); break;
        case 0x12: put_le(v, r.receipt_size_rule, kU8Bytes); break;
        case 0x14: v.insert(v.end(), r.monero_rules_digest.begin(), r.monero_rules_digest.end()); break;
        case 0x15:
            put_le(v, r.side_data_version, kU8Bytes);
            put_le(v, r.payee_kind, kU8Bytes);
            put_le(v, r.coinbase_format_version, kU8Bytes);
            break;
        case 0x17: put_le(v, r.roundabout_chains, kU8Bytes); break;
        case 0x18:
            put_le(v, r.ovh_hf16, kU16Bytes);
            put_le(v, r.ovh_hf17, kU16Bytes);
            put_le(v, r.out_base_hf16, kU16Bytes);
            put_le(v, r.out_base_hf17, kU16Bytes);
            break;
        case 0x19:
            put_le(v, r.reserve_divisor, kU8Bytes);
            put_le(v, r.reserve_n_min, kU8Bytes);
            break;
        case 0x1d: put_le(v, r.split_rule_version, kU8Bytes); break;
        case 0x1e:
            put_le(v, r.ratchet_version, kU8Bytes);
            put_le(v, r.vote_window, kU64Bytes);
            put_le(v, r.grace, kU64Bytes);
            put_le(v, r.timeout, kU64Bytes);
            break;
        default: break;
    }
    return v;
}

inline std::vector<std::uint8_t> encode_lane_rules_tlv(const PathbLaneRules& r) {
    std::vector<std::uint8_t> out;
    out.reserve(pathb_lane_rules_tlv_bytes());
    for (const LaneRuleField& f : kPathbLaneRuleFields) {
        const std::vector<std::uint8_t> v = lane_rule_value(r, f.id);
        out.push_back(f.id);
        out.push_back(static_cast<std::uint8_t>(v.size()));
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

// u8 codec | LE16 rules_len | TLV
inline std::vector<std::uint8_t> rules_block(const PathbLaneRules& r) {
    const std::vector<std::uint8_t> t = encode_lane_rules_tlv(r);
    std::vector<std::uint8_t> out;
    out.reserve(kU8Bytes + kU16Bytes + t.size());
    out.push_back(kPathbRulesCodec);
    lr_detail::put_le(out, t.size(), kU16Bytes);
    out.insert(out.end(), t.begin(), t.end());
    return out;
}

inline std::vector<std::uint8_t> rules_digest_preimage(const PathbLaneRules& r) {
    std::vector<std::uint8_t> pre(kLaneRulesDomain.begin(), kLaneRulesDomain.end());
    const std::vector<std::uint8_t> b = rules_block(r);
    pre.insert(pre.end(), b.begin(), b.end());
    return pre;
}

inline Hash32 rules_digest(const PathbLaneRules& r) { return ::v37::sha256d(rules_digest_preimage(r)); }

// ---------------------------------------------------------------------------
// Decoding a rules block (refusal names the field)
// ---------------------------------------------------------------------------
enum class LaneRulesError : std::uint8_t {
    None,
    Truncated,     // shorter than the codec byte + rules_len, or than rules_len
    Codec,         // codec byte other than K22 = 2 (names K22)
    Length,        // rules_len does not match the bytes that follow
    UnknownId,     // an id not in the field set
    Order,         // ids not strictly ascending
    Width,         // a known id with another length
    Missing,       // a field of the set absent
    Value,         // K16's author reference not (XMR_STD, 64)
};

struct LaneRulesDecode {
    LaneRulesError error = LaneRulesError::None;
    std::uint8_t id = 0;  // the field the refusal names (Codec: 22, the K number of the codec)
    std::uint8_t codec = 0;
    PathbLaneRules rules{};
    std::vector<std::pair<std::uint8_t, std::vector<std::uint8_t>>> entries;  // id, value, in wire order
};

inline constexpr std::uint8_t kCodecKNumber = 22;

inline LaneRulesDecode decode_rules_block(std::span<const std::uint8_t> b) {
    LaneRulesDecode d;
    if (b.size() < kU8Bytes + kU16Bytes) {
        d.error = LaneRulesError::Truncated;
        return d;
    }
    d.codec = b[0];
    if (d.codec != kPathbRulesCodec) {
        d.error = LaneRulesError::Codec;
        d.id = kCodecKNumber;
        return d;
    }
    const std::size_t len = static_cast<std::size_t>(lr_detail::get_le(b.data() + 1, kU16Bytes));
    if (b.size() - (kU8Bytes + kU16Bytes) != len) {
        d.error = len > b.size() - (kU8Bytes + kU16Bytes) ? LaneRulesError::Truncated : LaneRulesError::Length;
        return d;
    }
    const std::uint8_t* p = b.data() + kU8Bytes + kU16Bytes;
    std::size_t off = 0;
    int last = -1;
    std::vector<std::uint8_t> seen;
    while (off < len) {
        if (len - off < kHeaderBytes) {
            d.error = LaneRulesError::Truncated;
            return d;
        }
        const std::uint8_t id = p[off];
        const std::size_t n = p[off + 1];
        off += kHeaderBytes;
        if (len - off < n) {
            d.error = LaneRulesError::Truncated;
            d.id = id;
            return d;
        }
        if (static_cast<int>(id) <= last) {
            d.error = LaneRulesError::Order;
            d.id = id;
            return d;
        }
        last = id;
        const LaneRuleField* f = lane_rule_field(id);
        if (f == nullptr) {
            d.error = LaneRulesError::UnknownId;
            d.id = id;
            return d;
        }
        if (f->len != n) {
            d.error = LaneRulesError::Width;
            d.id = id;
            return d;
        }
        d.entries.emplace_back(id, std::vector<std::uint8_t>(p + off, p + off + n));
        seen.push_back(id);
        off += n;
    }
    for (const LaneRuleField& f : kPathbLaneRuleFields) {
        bool have = false;
        for (std::uint8_t s : seen) have = have || s == f.id;
        if (!have) {
            d.error = LaneRulesError::Missing;
            d.id = f.id;
            return d;
        }
    }
    using lr_detail::get_le;
    PathbLaneRules& r = d.rules;
    for (const auto& [id, v] : d.entries) {
        const std::uint8_t* q = v.data();
        switch (id) {
            case 0x01: r.carrier_interval_s = get_le(q, 8); break;
            case 0x02: r.d_min = get_le(q, 8); break;
            case 0x03:
                r.retarget_span = get_le(q, 8);
                r.retarget_formula = static_cast<std::uint8_t>(q[8]);
                r.retarget_min_span = get_le(q + 9, 8);
                break;
            case 0x04: r.open_bins = get_le(q, 8); break;
            case 0x05: r.liveness_delta = get_le(q, 8); break;
            case 0x06: r.seal_depth = get_le(q, 8); break;
            case 0x07: r.fresh_max = get_le(q, 8); break;
            case 0x08: r.r_max = get_le(q, 8); break;
            case 0x09: r.coverage = q[0]; break;
            case 0x0a: r.n_rule_version = q[0]; break;
            case 0x0b: r.w_max_rule_version = q[0]; break;
            case 0x0f: r.owner_fee_version = q[0]; break;
            case 0x10:
                r.give_author_bp = static_cast<std::uint16_t>(get_le(q, 2));
                if (q[2] != kPayeeKindXmrStd || q[3] != kKeyRefPayloadBytes) {
                    d.error = LaneRulesError::Value;
                    d.id = id;
                    return d;
                }
                for (std::size_t i = 0; i < kHashBytes; ++i) {  // after the kind and len bytes
                    r.author.spend[i] = q[2 + 2 + i];
                    r.author.view[i] = q[2 + 2 + kHashBytes + i];
                }
                break;
            case 0x11: r.payment_groups = q[0]; break;
            case 0x12: r.receipt_size_rule = q[0]; break;
            case 0x14:
                for (std::size_t i = 0; i < kHashBytes; ++i) r.monero_rules_digest[i] = q[i];
                break;
            case 0x15:
                r.side_data_version = q[0];
                r.payee_kind = q[1];
                r.coinbase_format_version = q[2];
                break;
            case 0x17: r.roundabout_chains = q[0]; break;
            case 0x18:
                r.ovh_hf16 = static_cast<std::uint16_t>(get_le(q, 2));
                r.ovh_hf17 = static_cast<std::uint16_t>(get_le(q + 2, 2));
                r.out_base_hf16 = static_cast<std::uint16_t>(get_le(q + 4, 2));
                r.out_base_hf17 = static_cast<std::uint16_t>(get_le(q + 6, 2));
                break;
            case 0x19:
                r.reserve_divisor = q[0];
                r.reserve_n_min = q[1];
                break;
            case 0x1d: r.split_rule_version = q[0]; break;
            case 0x1e:
                r.ratchet_version = q[0];
                r.vote_window = get_le(q + 1, 8);
                r.grace = get_le(q + 9, 8);
                r.timeout = get_le(q + 17, 8);
                break;
            default: break;
        }
    }
    return d;
}

// ---------------------------------------------------------------------------
// Comparing two rules blocks at the same epoch_cur
// ---------------------------------------------------------------------------
enum class LaneRulesVerdict : std::uint8_t {
    Equal,     // compatible
    Mismatch,  // LANE_RULES_MISMATCH naming the first differing field
    Refused,   // their block does not decode (codec K22, unknown / missing id, order, width, length)
};

struct LaneRulesCompare {
    LaneRulesVerdict verdict = LaneRulesVerdict::Equal;
    std::uint8_t id = 0;
    std::string text;
};

inline std::string lane_rule_field_name(std::uint8_t id) {
    if (id == kCodecKNumber) return "K22";
    const LaneRuleField* f = lane_rule_field(id);
    return f ? std::string(f->name) : "id" + std::to_string(id);
}

inline LaneRulesCompare lane_rules_mismatch(std::span<const std::uint8_t> ours, std::span<const std::uint8_t> theirs) {
    LaneRulesCompare c;
    const LaneRulesDecode t = decode_rules_block(theirs);
    if (t.error != LaneRulesError::None) {
        c.verdict = LaneRulesVerdict::Refused;
        c.id = t.id;
        c.text = std::string(kLaneRulesMismatchText) + " refused field=" + lane_rule_field_name(t.id);
        return c;
    }
    const LaneRulesDecode o = decode_rules_block(ours);
    for (std::size_t i = 0; i < o.entries.size() && i < t.entries.size(); ++i) {
        if (o.entries[i] == t.entries[i]) continue;
        c.verdict = LaneRulesVerdict::Mismatch;
        c.id = o.entries[i].first;
        c.text = std::string(kLaneRulesMismatchText) + " field=" + lane_rule_field_name(c.id) + " ours="
                 + lr_detail::hex(o.entries[i].second.data(), o.entries[i].second.size()) + " theirs="
                 + lr_detail::hex(t.entries[i].second.data(), t.entries[i].second.size());
        return c;
    }
    return c;
}

// HELLO: the rules blocks are compared only at the same epoch_cur; a peer at
// another epoch_cur is accepted without a comparison.
inline LaneRulesCompare hello_rules_compare(std::uint16_t our_epoch, std::span<const std::uint8_t> ours,
                                            std::uint16_t their_epoch, std::span<const std::uint8_t> theirs) {
    if (our_epoch != their_epoch) return {};
    return lane_rules_mismatch(ours, theirs);
}

// ---------------------------------------------------------------------------
// G per network (compiled; v37_xmr_lane_rules_kat pins each against an
// independent recompute)
// ---------------------------------------------------------------------------
inline constexpr Hash32 hash_from_hex(const char* h) noexcept {
    Hash32 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>((lr_detail::hex_nibble(h[2 * i]) << 4) | lr_detail::hex_nibble(h[2 * i + 1]));
    return out;
}

inline constexpr Hash32 kGenesisRulesDigestMainnet =
        hash_from_hex("31ac3ccf21f4aa825bb1ef657fe418b9f58861c1698bbfe357649176fac54e55");
inline constexpr Hash32 kGenesisRulesDigestTestnet =
        hash_from_hex("bf2df9c500f3cee6344b862917ab0234ec5e65e0fbccf10ad568bfc6080ae213");
inline constexpr Hash32 kGenesisRulesDigestStagenet =
        hash_from_hex("45744e8c486eac5068f5e8179c8e96b7ecdb264ab43610447318b46ff3ffda49");
inline constexpr Hash32 kGenesisRulesDigestRegtest =
        hash_from_hex("f91737946910674cbe8dac71618f5c02ab5c6c7d4a431163c9b4d2222ce67e0e");

inline constexpr Hash32 genesis_rules_digest(LaneNet n) noexcept {
    switch (n) {
        case LaneNet::Testnet: return kGenesisRulesDigestTestnet;
        case LaneNet::Stagenet: return kGenesisRulesDigestStagenet;
        case LaneNet::Regtest: return kGenesisRulesDigestRegtest;
        case LaneNet::Mainnet: break;
    }
    return kGenesisRulesDigestMainnet;
}

// The epoch-0 digest a node starts with: the compiled G; on regtest a rig
// list that differs from the default in K30 only gives rules_digest(rig list).
// nullopt: the list is not the network's epoch-0 list (the node refuses to start).
inline std::optional<Hash32> genesis_digest_for(LaneNet n, const PathbLaneRules& own) {
    const PathbLaneRules def = epoch0_lane_rules(n);
    if (own == def) {
        const Hash32 g = genesis_rules_digest(n);
        if (rules_digest(own) != g) return std::nullopt;
        return g;
    }
    if (n != LaneNet::Regtest) return std::nullopt;
    PathbLaneRules k30_default = own;
    k30_default.vote_window = def.vote_window;
    k30_default.grace = def.grace;
    k30_default.timeout = def.timeout;
    if (k30_default != def) return std::nullopt;
    return rules_digest(own);
}

inline RatchetParams ratchet_params_of(const PathbLaneRules& r) noexcept {
    return RatchetParams{r.vote_window, r.grace, r.timeout};
}

// ---------------------------------------------------------------------------
// Stratum login disclosure of the K15 / K16 shares (basis points as percent,
// four decimals).
// ---------------------------------------------------------------------------
inline std::string bp_percent_text(std::uint16_t bp) {
    const std::uint64_t whole = bp / 100;
    const std::uint64_t frac = (bp % 100) * 100;  // four decimals
    std::string f = std::to_string(frac);
    while (f.size() < 4) f.insert(f.begin(), '0');
    return std::to_string(whole) + "." + f;
}

inline std::string login_fee_disclosure(std::uint16_t give_author_bp, std::uint16_t owner_fee_bp) {
    return "\"give_author_pct\":" + bp_percent_text(give_author_bp) + ",\"node_owner_fee_pct\":"
           + bp_percent_text(owner_fee_bp);
}

}  // namespace c2pool::xmr::pathb
