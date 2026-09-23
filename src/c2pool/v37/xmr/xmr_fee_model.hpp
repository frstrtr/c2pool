// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_fee_model.hpp -- the v36 fee model, ported to the
// v37 XMR lane (consumer tree).
//
// Ported from the p2pool lineage (forrestv p2pool from the first commit,
// 2011-06-11, and the V36 fork frstrtr/p2pool-merged-v36). It is NOT the
// Monero p2pool model: SChernykh's p2pool has no fee and no donation at all.
//
// GATED: everything here is live only under LaneParams::fee (FeeModelGate,
// sharechain/v37/v37_lane.hpp), default OFF => master-identical coinbase and
// credit. The gate is folded into the relay's lane_params_digest, so a mixed
// fleet refuses at HELLO instead of diverging (ruling S4).
//
//   1. DONATION OUTPUT = MANDATORY, ONE OUTPUT = 1 + RESIDUAL (ruling S1).
//      p2pool data.py: amounts[DONATION] += subsidy - sum(amounts), and V36
//      requires the donation output to be >= 1 atomic unit. Here the lane
//      coinbase carries ONE donation output, LAST: a FixedOutput to the
//      donation ref whose declared amount kDonationDustPico (1 piconero) is a
//      MINIMUM, and the residual sink IS the donation address, so X6
//      (allocate_exact_sum, residual_folds_into_fixed) folds the whole
//      exact-sum residual into that output -- there is never a separate sink.
//        * serve side: inspect_donation_marker() refuses a template whose
//          canonical coinbase does not end in that one output;
//        * receive side: apply_donation_rule() refuses to book a lane
//          coinbase whose last output is not a >= 1 piconero donation output
//          (REFUSE-IF-ABSENT).
//   2. THE 1-PICONERO DUST COMES FROM THE LARGEST PAYEE (ruling S2, V36
//      data.py "take 1 from the largest"). Only when the owed pass exhausts
//      the budget (residual 0) does X6 deduct the minimum, from the LARGEST
//      owed output (ties: earliest in K_fair order); the piconero stays owed.
//   3. GIVE-AUTHOR = A u16 INSIDE THE PoW-COMMITTED RECEIPT (ruling S3). The
//      Family-B receipt's side_data_v2 carries give_author; its info_digest
//      commits it and, with --relay-bind rbind, the coinbase 0x02 region
//      [extra_nonce 4 | rbind 32] binds (payee, give_author) to the share's
//      RandomX PoW (SEAM-1). The relay ingest and the repair replay read the
//      u16 from THERE -- never from a feed line. Every receipt is pushed at
//      weight kFeeReceiptWeight (65535) split v36-style: (payee, 65535 - d),
//      then (donation, d) iff d > 0. Every node folds every receipt with the
//      receipt's OWN u16, so nodes with different give-author % build the
//      same coinbase. (Family-A: WorkEvent::donation, w2_receipt.hpp.)
//   4. NODE-OWNER FEE = PROBABILISTIC PAYEE SUBSTITUTION AT JOB ISSUE (v36
//      work.py: random.uniform(0,100) < node_owner_fee -> pubkey_hash =
//      my_pubkey_hash, decided when the WORK is handed out). The roll picks
//      the payee that the job's rbind commits to, so the substituted payee is
//      PoW-bound in the share the miner then finds; peers admit it as
//      ordinary work. Never a post-FOUND payee swap.
//   5. NO FINDER BONUS (V36 dropped forrestv's 0.5% finder output).
//
// Everything here is a pure function of its arguments (the owner-fee roll
// takes its random word as an argument) so it is KAT-able.
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_descriptor.hpp>
#include <sharechain/v37/v37_descriptor_xmr.hpp>
#include <sharechain/v37/v37_hash.hpp>
#include <sharechain/v37/v37_lane.hpp>             // LaneParams::fee (FeeModelGate)

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"   // xmr::coin::keccak256 (cn_fast_hash)
#include "impl/xmr/settle/xmr_coinbase.hpp"        // FixedOutput, CoinbaseOutput

namespace c2pool::v37n::xmr::fee {

namespace x6 = ::v37::xmr::settle;

// ---------------------------------------------------------------------------
// Constants (consensus once activated; compiled in, never a CLI knob)
// ---------------------------------------------------------------------------
// The protocol donation / author address (Monero mainnet standard address,
// public keys only).
inline constexpr char kDonationAddress[] =
    "42QtUEQ6E4v2wtkG2h72osTqZgLo7vtjg4SngeG47AnaaQLUUQrGvPXSuvCmHcRVuPa5xxUU5Mfo6jSEqYYUk34Z1PM1oPF";
// Its decoded public spend (B) and view (A) keys. Pinned against the decoder
// by v37_xmr_fee_model_kat (decode(kDonationAddress) must equal these bytes).
inline constexpr char kDonationSpendHex[] = "14d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7";
inline constexpr char kDonationViewHex[]  = "b3157741ab68969aeb7fe9ebd4fa3ec5ce4dcdc7b43249fdb40311cb03779e03";
// The V36 marker minimum: the donation output is never below 1 atomic unit.
inline constexpr std::uint64_t kDonationDustPico = 1;
// The give-author scale (v36 share_data.donation is a u16 over 65535).
inline constexpr std::uint32_t kGiveAuthorScale = 65535;
// Under the gate every PoW-committed receipt is pushed at this lane weight,
// split by its u16 (v36: miner att*(65535-d), donation att*d). Uniform across
// receipts, so relative credit is unchanged versus the gate-OFF weight 1.
inline constexpr std::uint64_t kFeeReceiptWeight = kGiveAuthorScale;
// The gate's version the code below implements (FeeModelGate::version).
inline constexpr std::uint32_t kFeeModelVersion = 1;

inline bool fee_model_on(const ::v37::LaneParams& p) {
    return p.fee.enabled && p.fee.version == kFeeModelVersion;
}

// Monero address network bytes (cryptonote_config.h).
inline constexpr std::uint64_t kPrefixMainnetStd = 18, kPrefixMainnetInt = 19, kPrefixMainnetSub = 42;
inline constexpr std::uint64_t kPrefixTestnetStd = 53, kPrefixTestnetInt = 54, kPrefixTestnetSub = 63;
inline constexpr std::uint64_t kPrefixStagenetStd = 24, kPrefixStagenetInt = 25, kPrefixStagenetSub = 36;

// ---------------------------------------------------------------------------
// CryptoNote base58 (block-wise: 8 bytes <-> 11 chars, tail per kEncSizes)
// ---------------------------------------------------------------------------
namespace detail {
inline constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
inline constexpr int  kEncSizes[9] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
inline int digit_of(char c) {
    for (int i = 0; i < 58; ++i) if (kAlphabet[i] == c) return i;
    return -1;
}
inline bool decode_block(const char* s, std::size_t n, std::vector<std::uint8_t>& out) {
    int res = -1;
    for (int i = 0; i < 9; ++i) if (kEncSizes[i] == static_cast<int>(n)) { res = i; break; }
    if (res <= 0) return false;
    unsigned __int128 num = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const int d = digit_of(s[i]);
        if (d < 0) return false;
        num = num * 58 + static_cast<unsigned>(d);
        if (num >> 64) return false;                       // u64 overflow (monero: overflow)
    }
    if (res < 8 && (num >> (8 * res)) != 0) return false;  // does not fit the block size
    for (int i = res - 1; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(num >> (8 * i)));
    return true;
}
} // namespace detail

inline bool cn_base58_decode(const std::string& s, std::vector<std::uint8_t>& out) {
    out.clear();
    const std::size_t full = s.size() / 11, rem = s.size() % 11;
    for (std::size_t i = 0; i < full; ++i)
        if (!detail::decode_block(s.data() + 11 * i, 11, out)) return false;
    if (rem && !detail::decode_block(s.data() + 11 * full, rem, out)) return false;
    return true;
}

struct DecodedAddress {
    bool          ok = false;
    std::string   why;
    std::uint64_t prefix = 0;
    bool          subaddress = false;
    std::array<std::uint8_t, 32> spend{};   // B (or D_i for a subaddress)
    std::array<std::uint8_t, 32> view{};    // A (or C_i for a subaddress)
    // The XMR_STD payout ref. Only meaningful when ok && !subaddress: a
    // subaddress encodes (D_i, C_i) while XMR_SUB is (D_i, A_main), and the
    // main view key is not in the address -- so a subaddress is refused as a
    // payee at this seam (the caller checks `subaddress`).
    ::v37::ScriptRef ref() const { return ::v37::xmr::make_xmr_std(spend, view); }
};

// Decode a standard address or a subaddress (integrated addresses are
// refused: a payment id has no place in a coinbase payee). Verifies the
// keccak checksum and the varint network byte.
inline DecodedAddress decode_xmr_address(const std::string& addr) {
    DecodedAddress d;
    std::vector<std::uint8_t> raw;
    if (!cn_base58_decode(addr, raw)) { d.why = "not CryptoNote base58"; return d; }
    // varint prefix
    std::uint64_t pfx = 0; std::size_t i = 0; int shift = 0;
    for (;; ++i) {
        if (i >= raw.size() || shift > 63) { d.why = "truncated varint prefix"; return d; }
        pfx |= static_cast<std::uint64_t>(raw[i] & 0x7f) << shift;
        shift += 7;
        if (!(raw[i] & 0x80)) { ++i; break; }
    }
    if (raw.size() != i + 64 + 4) { d.why = "wrong length " + std::to_string(raw.size()) + " (integrated address or garbage)"; return d; }
    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(raw.data(), raw.size() - 4);
    if (std::memcmp(h.data(), raw.data() + raw.size() - 4, 4) != 0) { d.why = "checksum mismatch"; return d; }
    switch (pfx) {
        case kPrefixMainnetStd: case kPrefixTestnetStd: case kPrefixStagenetStd: d.subaddress = false; break;
        case kPrefixMainnetSub: case kPrefixTestnetSub: case kPrefixStagenetSub: d.subaddress = true; break;
        default: d.why = "unsupported network byte " + std::to_string(pfx); return d;
    }
    d.prefix = pfx;
    std::memcpy(d.spend.data(), raw.data() + i, 32);
    std::memcpy(d.view.data(), raw.data() + i + 32, 32);
    d.ok = true;
    return d;
}

// ---------------------------------------------------------------------------
// The donation payee
// ---------------------------------------------------------------------------
inline bool hex32_of(const char* hx, std::array<std::uint8_t, 32>& out) {
    if (std::strlen(hx) != 64) return false;
    for (int i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1; };
        const int hi = nib(hx[2 * i]), lo = nib(hx[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}
inline ::v37::ScriptRef donation_ref() {
    std::array<std::uint8_t, 32> B{}, A{};
    hex32_of(kDonationSpendHex, B);
    hex32_of(kDonationViewHex, A);
    return ::v37::xmr::make_xmr_std(B, A);
}
inline ::v37::bytes32 donation_identity() { return ::v37::xmr::xmr_identity_key(donation_ref()); }

// The mandatory donation output (declared LAST among the fixed outputs, and
// paying the residual sink, so X6 folds the residual into it: the canonical
// tail is [ ... owed ][ donation: max(1, residual) ], one output -- S1).
inline x6::FixedOutput donation_marker() {
    x6::FixedOutput f;
    f.pay = donation_ref();
    f.amount = kDonationDustPico;
    f.identity = donation_identity();
    return f;
}

// ---------------------------------------------------------------------------
// Give-author (receipt-carried u16)
// ---------------------------------------------------------------------------
// v36 encodes perfect_round(65535*pct/100) (stochastic rounding); the u16 is
// minted into the receipt and is node-local policy, so a deterministic
// round-half-up is used here (bias <= 0.5/65535, never consensus).
inline std::uint16_t give_author_u16(double pct) {
    if (!(pct > 0.0)) return 0;
    if (pct >= 100.0) return static_cast<std::uint16_t>(kGiveAuthorScale);
    const double x = static_cast<double>(kGiveAuthorScale) * pct / 100.0 + 0.5;
    const auto v = static_cast<std::uint32_t>(x);
    return static_cast<std::uint16_t>(v > kGiveAuthorScale ? kGiveAuthorScale : v);
}

// v36 weights: miner att*(65535-d), donation att*d. The lane takes integer
// w_raw per push, so ONE receipt of weight w becomes two pushes whose sum is
// exactly w: donation = floor(w*d/65535), miner = w - donation (the miner
// keeps the floor remainder). d == 0 -> donation == 0 -> a single push.
struct SplitWeight { std::uint64_t miner = 0; std::uint64_t donation = 0; };
inline SplitWeight split_receipt_weight(std::uint64_t w, std::uint16_t d) {
    SplitWeight s;
    const unsigned __int128 p = static_cast<unsigned __int128>(w) * d;
    s.donation = static_cast<std::uint64_t>(p / kGiveAuthorScale);
    s.miner = w - s.donation;
    return s;
}

// ---------------------------------------------------------------------------
// The lane pushes of ONE PoW-committed receipt (every node, same order).
//   gate OFF: (payee, off_weight)                 -- byte-identical to master
//   gate ON : (payee, 65535 - d) [+ (donation, d) iff d > 0], d = the receipt's
//             OWN give_author u16 (side_data_v2), never the folding node's.
// ---------------------------------------------------------------------------
inline std::vector<std::pair<::v37::ScriptRef, std::uint64_t>>
receipt_lane_pushes(const ::v37::ScriptRef& payee, std::uint16_t give_author, bool fee_on,
                    std::uint64_t off_weight = 1) {
    std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> v;
    if (!fee_on) { v.emplace_back(payee, off_weight); return v; }
    const SplitWeight s = split_receipt_weight(kFeeReceiptWeight, give_author);
    if (s.miner) v.emplace_back(payee, s.miner);
    if (s.donation) v.emplace_back(donation_ref(), s.donation);
    return v;
}

// ---------------------------------------------------------------------------
// Node-owner fee (roll at JOB ISSUE: the payee the job's rbind commits to)
// ---------------------------------------------------------------------------
// fee in basis points of a percent-of-100 (1% = 100 bp, 100% = 10000 bp).
inline std::uint32_t pct_to_bp(double pct) {
    if (!(pct > 0.0)) return 0;
    if (pct >= 100.0) return 10000;
    return static_cast<std::uint32_t>(pct * 100.0 + 0.5);
}
// v36 work.py: random.uniform(0,100) < node_owner_fee. `roll` is a uniform
// random 64-bit word supplied by the caller.
inline bool owner_fee_hit(std::uint64_t roll, std::uint32_t fee_bp) {
    return fee_bp != 0 && (roll % 10000u) < fee_bp;
}
// The payee a job commits to: the owner on a hit (when one is configured),
// else the miner. *substituted reports which (bookkeeping only).
inline ::v37::ScriptRef choose_payee(const ::v37::ScriptRef& miner,
                                     const std::optional<::v37::ScriptRef>& owner,
                                     std::uint32_t owner_fee_bp, std::uint64_t roll,
                                     bool* substituted = nullptr) {
    const bool hit = owner && owner_fee_hit(roll, owner_fee_bp);
    if (substituted) *substituted = hit;
    return hit ? *owner : miner;
}

// ---------------------------------------------------------------------------
// The donation rule over a coinbase's output list, identity-mapped (S1).
//
// Canonical tail (X6 order [owed] ++ [fixed], the residual FOLDED into the
// last fixed output because it pays the sink):  ... owed | D:max(1, residual)
//
// Deterministic location, identical on every node: the LAST output pays the
// donation identity D with amount >= kDonationDustPico -> it is the donation
// output; otherwise the donation output is ABSENT -> REFUSE. Outputs to D
// BEFORE it are ordinary OWED outputs (give-author credit) and are booked as
// ledger deductions; the donation output itself is coverage only (D1).
// ---------------------------------------------------------------------------
struct MarkerLocation {
    bool        ok = false;
    std::string why;
    std::size_t marker = 0;
};
inline MarkerLocation locate_donation_marker(const std::vector<::v37::bytes32>& ids,
                                             const std::vector<std::uint64_t>& amounts,
                                             const ::v37::bytes32& D) {
    MarkerLocation m;
    const std::size_t n = ids.size();
    if (n == 0 || amounts.size() != n) { m.why = "donation output absent: no outputs"; return m; }
    if (!(ids[n - 1] == D)) { m.why = "donation output absent: the last output does not pay the donation address"; return m; }
    if (amounts[n - 1] < kDonationDustPico) {
        m.why = "donation output absent: the last donation output pays " + std::to_string(amounts[n - 1]) +
                " < " + std::to_string(kDonationDustPico) + " piconero";
        return m;
    }
    m.ok = true; m.marker = n - 1;
    return m;
}

// Serve-side property over the builder's canonical output list (roles known):
// exactly ONE donation output, last, Fixed, >= 1 piconero, and NO separate
// residual sink (the residual must have folded into it).
inline MarkerLocation inspect_donation_marker(const std::vector<x6::CoinbaseOutput>& outs,
                                              const ::v37::bytes32& D) {
    MarkerLocation m;
    const std::size_t n = outs.size();
    for (const auto& o : outs)
        if (o.role == x6::CoinbaseOutput::Role::Sink) {
            m.why = "a separate residual-sink output is present: the residual must fold into the donation output (S1)";
            return m;
        }
    if (n == 0 || outs[n - 1].role != x6::CoinbaseOutput::Role::Fixed || !(outs[n - 1].identity == D) ||
        outs[n - 1].amount < kDonationDustPico || !(outs[n - 1].pay == donation_ref())) {
        m.why = "donation output absent: the canonical coinbase does not end in the >= " +
                std::to_string(kDonationDustPico) + "-piconero donation output (1 + residual)";
        return m;
    }
    m.ok = true; m.marker = n - 1;
    return m;
}

// Receive-side booking rule. `ids`/`amounts` are the per-vout identities and
// amounts the coinbase-authority decoder mapped; `payout` / `sink_total` are
// its maps, where every output to D (the sink identity) was tallied as
// coverage. Re-books D's pre-marker outputs as owed (ledger deductions).
// Returns false (and *why) when the marker is absent: the caller refuses.
inline bool apply_donation_rule(const std::vector<::v37::bytes32>& ids,
                                const std::vector<std::uint64_t>& amounts,
                                const ::v37::bytes32& D,
                                std::map<::v37::bytes32, long long>& payout,
                                long long& sink_total, std::string* why) {
    const MarkerLocation m = locate_donation_marker(ids, amounts, D);
    if (!m.ok) { if (why) *why = m.why; return false; }
    for (std::size_t i = 0; i < m.marker; ++i) {
        if (!(ids[i] == D)) continue;
        sink_total -= static_cast<long long>(amounts[i]);
        payout[D] += static_cast<long long>(amounts[i]);
    }
    return true;
}

} // namespace c2pool::v37n::xmr::fee
