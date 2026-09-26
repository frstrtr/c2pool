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
//   1. DONATION OUTPUT = MANDATORY, EXACTLY ONE OUTPUT (rulings S1 + 09-23).
//      p2pool data.py: amounts[DONATION] += subsidy - sum(amounts), and V36
//      requires the donation output to be >= 1 atomic unit; share credit to
//      the donation script and the residual land in that ONE output. Here the
//      lane coinbase carries ONE output to the donation address, LAST: a
//      FixedOutput to the donation ref whose declared amount kDonationDustPico
//      (1 piconero) is a MINIMUM; the residual sink IS the donation address,
//      so X6 (allocate_exact_sum, residual_folds_into_fixed) folds the whole
//      exact-sum residual into it, and the donation's own K_fair payout
//      (give-author credit, paid at its age position) is MERGED into it too:
//          amount    = owed_paid + 1 + residual
//          owed_part = min(owed_in, amount - 1)     (x6 CoinbaseOutput)
//      owed_in (the owed the coinbase's input set held for the donation;
//      under the default W4Propose source that is its proposed K_fair take,
//      so owed_part is exactly its K_fair payout, less any S2 dust it paid)
//      is committed in the 0x02 payload as the 12-byte tail "V37D" || u64le,
//      just before the credit-cut tail, so every receiver splits the output
//      the same way without the ledger (the input set includes node-local
//      pending state that owed_digest does not commit).
//        * serve side: inspect_donation_marker() refuses a template whose
//          canonical coinbase does not end in that one output, or pays the
//          donation anywhere else;
//        * receive side: apply_donation_rule() refuses to book a lane
//          coinbase whose last output is not a >= 1 piconero donation output,
//          that pays the donation in an earlier output, or that lacks the
//          owed_in tail (REFUSE-IF-ABSENT); it books owed_part as the
//          donation's payout (a ledger deduction, like any K_fair payout)
//          and the rest (1 + residual) as coverage.
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
#include "xmr_credit_cut.hpp"                      // extra_nonce_field, the credit-cut tail it precedes

namespace c2pool::v37n::xmr::fee {

namespace x6 = ::v37::xmr::settle;

// ---------------------------------------------------------------------------
// Constants (consensus once activated; compiled in, never a CLI knob)
// ---------------------------------------------------------------------------
// The protocol donation / author address (Monero mainnet standard address,
// public keys only). MAINNET only: the other networks' identities are in
// donation_info() below, selected by the node's --network (DON-NET).
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
// Per-network donation identity (DON-NET)
// ---------------------------------------------------------------------------
// The donation identity is chosen by the node's Monero network (--network),
// never by a knob. MAINNET is kDonationAddress above, byte-for-byte; the
// other networks carry project-controlled wallets generated offline (public
// addresses only here; keys are held off-tree). Regtest (monerod --regtest,
// FAKECHAIN) encodes addresses with the MAINNET network byte, so its address
// has prefix 18 but distinct keys. The values of DonationNet are the relay
// HELLO network byte (0 mainnet, 1 testnet, 2 stagenet, 3 regtest).
#define C2POOL_V37_XMR_DONATION_PER_NETWORK 1
enum class DonationNet : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2, Regtest = 3 };

struct DonationIdentity {
    const char*   address;     // standard address (public keys only)
    const char*   spend_hex;   // its decoded public spend key B
    const char*   view_hex;    // its decoded public view key A
    std::uint64_t prefix;      // its network byte
};
inline constexpr char kDonationAddressTestnet[] =
    "9yWhJcSRcNFhfrZJAkgh5N4swx92cHLP79hYbP8YJwJKYSCcdKXpgrvYxFHZ5kvfUERtXjvwNTJN4EuW7FypyDZ3114t5rG";
inline constexpr char kDonationSpendHexTestnet[] = "a7731abbe9bb2cf3264395231a8645172ffd7f08c6097e3402197f3f1c6ffcbb";
inline constexpr char kDonationViewHexTestnet[]  = "ef3c9a659a67c3bf081a352e7cfbfb94cc5e11921a3e8953223fca1ed14e2200";
inline constexpr char kDonationAddressStagenet[] =
    "56eN1fax2baeK1WQtCassh9dpgnWbnzTPTgoPQ7wbWPmBszKeTHwa5ji1wuqZnxERNc284ESw3xoDd76uzEtwjge9gesBUp";
inline constexpr char kDonationSpendHexStagenet[] = "7f095705904be1df109bdf44b0027c339fde3ece7d85069f8bdfb19fd8c16c41";
inline constexpr char kDonationViewHexStagenet[]  = "0abca326ba53a6f5387785822296c1d15df03e6c51cd44d7dbe270667b5fe34c";
inline constexpr char kDonationAddressRegtest[] =
    "43TryRMP6jdJP9h1CSgskqAFX6dA4h76rXfs7x5wvfGZAVmVBBUxRHjfJ9tfgnBtsJ4D75rdz9gVe8pU4SxA2rJhNrx87oD";
inline constexpr char kDonationSpendHexRegtest[] = "3091e80a51918c67eb67b6fefaf77e374dd898240953bbb75d47b82b8615c638";
inline constexpr char kDonationViewHexRegtest[]  = "c5d453f0d54332e4f48f12abab2551132f00037f0c51892ebe3b41928ab5bec1";

inline constexpr DonationIdentity donation_info(DonationNet n) {
    switch (n) {
        case DonationNet::Testnet:  return {kDonationAddressTestnet, kDonationSpendHexTestnet, kDonationViewHexTestnet, kPrefixTestnetStd};
        case DonationNet::Stagenet: return {kDonationAddressStagenet, kDonationSpendHexStagenet, kDonationViewHexStagenet, kPrefixStagenetStd};
        case DonationNet::Regtest:  return {kDonationAddressRegtest, kDonationSpendHexRegtest, kDonationViewHexRegtest, kPrefixMainnetStd};
        case DonationNet::Mainnet:  break;
    }
    return {kDonationAddress, kDonationSpendHex, kDonationViewHex, kPrefixMainnetStd};
}
inline constexpr const char* donation_address(DonationNet n) { return donation_info(n).address; }
inline constexpr const char* to_string(DonationNet n) {
    switch (n) {
        case DonationNet::Testnet:  return "testnet";
        case DonationNet::Stagenet: return "stagenet";
        case DonationNet::Regtest:  return "regtest";
        case DonationNet::Mainnet:  break;
    }
    return "mainnet";
}

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
// The donation payee of network `n`. The no-argument forms are MAINNET (the
// historical single identity); every daemon call site passes its --network.
inline ::v37::ScriptRef donation_ref(DonationNet n) {
    const DonationIdentity di = donation_info(n);
    std::array<std::uint8_t, 32> B{}, A{};
    hex32_of(di.spend_hex, B);
    hex32_of(di.view_hex, A);
    return ::v37::xmr::make_xmr_std(B, A);
}
inline ::v37::ScriptRef donation_ref() { return donation_ref(DonationNet::Mainnet); }
inline ::v37::bytes32 donation_identity(DonationNet n) { return ::v37::xmr::xmr_identity_key(donation_ref(n)); }
inline ::v37::bytes32 donation_identity() { return donation_identity(DonationNet::Mainnet); }

// The mandatory donation output (declared LAST among the fixed outputs, and
// paying the residual sink, so X6 folds the residual AND the donation's own
// K_fair payout into it: the canonical tail is
// [ ... owed ][ donation: owed_paid + 1 + residual ], one output).
inline x6::FixedOutput donation_marker(DonationNet n) {
    x6::FixedOutput f;
    f.pay = donation_ref(n);
    f.amount = kDonationDustPico;
    f.identity = donation_identity(n);
    return f;
}
inline x6::FixedOutput donation_marker() { return donation_marker(DonationNet::Mainnet); }

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
                    std::uint64_t off_weight = 1, DonationNet net = DonationNet::Mainnet) {
    std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> v;
    if (!fee_on) { v.emplace_back(payee, off_weight); return v; }
    const SplitWeight s = split_receipt_weight(kFeeReceiptWeight, give_author);
    if (s.miner) v.emplace_back(payee, s.miner);
    if (s.donation) v.emplace_back(donation_ref(net), s.donation);
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
// The donation owed_in commitment: the 0x02 tail "V37D" || u64le owed_in.
// Written by the settlement source whenever the residual folds into the
// donation output (fee model ON only; gate OFF has no fold, so no tail and
// master's bytes). Layout of the 0x02 payload under the gate:
//     [ nonce 4 | rbind? | pad | "V37D" u64le | "V37P" v pool_tag? | "V37C" P spine ]
// (the credit-cut tail stays LAST, so credit::parse_tail is unchanged; the
// POOL-LINEAGE field sits between V37D and V37C, xmr_credit_cut.hpp).
// Constant size, so the miner_tx weight invariance holds.
// ---------------------------------------------------------------------------
inline constexpr unsigned char kDonationOwedMagic[4] = {'V', '3', '7', 'D'};
inline constexpr std::size_t   kDonationOwedTailBytes = 4 + 8;   // 12

inline std::vector<std::uint8_t> encode_donation_owed_tail(std::uint64_t owed_in) {
    std::vector<std::uint8_t> t(kDonationOwedMagic, kDonationOwedMagic + 4);
    for (int i = 0; i < 8; ++i) t.push_back(static_cast<std::uint8_t>(owed_in >> (8 * i)));
    return t;
}
// Read owed_in out of a whole 0x02 payload: the 12 bytes just before the
// credit-cut tail when one is present, else the last 12 bytes. nullopt when
// the magic is not there.
inline std::optional<std::uint64_t> parse_donation_owed_payload(const std::vector<std::uint8_t>& p) {
    // POOL-LINEAGE: a lineage-tagged payload carries the V37P field between
    // V37D and V37C; skip it (a malformed field leaves `end` where it is, so the
    // V37D magic check below fails closed). LANE-EPOCH: likewise a well-formed
    // V37E field right before V37P (absent under the gate OFF: same offset).
    std::size_t end = credit::end_before_lineage_fields(p);
    if (end < kDonationOwedTailBytes) return std::nullopt;
    const std::uint8_t* t = p.data() + end - kDonationOwedTailBytes;
    if (std::memcmp(t, kDonationOwedMagic, 4) != 0) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(t[4 + i]) << (8 * i);
    return v;
}
inline std::optional<std::uint64_t> parse_donation_owed(const std::vector<unsigned char>& tx_extra) {
    const auto nf = credit::extra_nonce_field(tx_extra);
    if (!nf) return std::nullopt;
    return parse_donation_owed_payload(*nf);
}

// The receive-side split of the ONE donation output (the X6 MERGE rule with
// minimum kDonationDustPico): the part booked as the donation's payout.
inline std::uint64_t donation_owed_part(std::uint64_t amount, std::uint64_t owed_in) {
    const std::uint64_t over_min = amount > kDonationDustPico ? amount - kDonationDustPico : 0;
    return owed_in < over_min ? owed_in : over_min;
}

// ---------------------------------------------------------------------------
// The donation rule over a coinbase's output list, identity-mapped.
//
// Canonical tail (X6 order [owed] ++ [fixed], the residual AND the donation's
// K_fair payout merged into the last fixed output because it pays the sink):
//     ... owed (none to D) | D: owed_paid + 1 + residual
//
// Deterministic location, identical on every node: the LAST output pays the
// donation identity D with amount >= kDonationDustPico and NO earlier output
// pays D -> it is the donation output; otherwise REFUSE.
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
    for (std::size_t i = 0; i + 1 < n; ++i)
        if (ids[i] == D) {
            m.why = "more than one donation output: output " + std::to_string(i) +
                    " also pays the donation address (its owed payout must merge into the last one)";
            return m;
        }
    m.ok = true; m.marker = n - 1;
    return m;
}

// Serve-side property over the builder's canonical output list (roles known):
// exactly ONE output to D, last, Fixed, >= 1 piconero, its owed_part leaving
// the minimum, and NO separate residual sink (the residual must have folded).
inline MarkerLocation inspect_donation_marker(const std::vector<x6::CoinbaseOutput>& outs,
                                              const ::v37::bytes32& D, const ::v37::ScriptRef& Dref) {
    MarkerLocation m;
    const std::size_t n = outs.size();
    for (const auto& o : outs)
        if (o.role == x6::CoinbaseOutput::Role::Sink) {
            m.why = "a separate residual-sink output is present: the residual must fold into the donation output (S1)";
            return m;
        }
    if (n == 0 || outs[n - 1].role != x6::CoinbaseOutput::Role::Fixed || !(outs[n - 1].identity == D) ||
        outs[n - 1].amount < kDonationDustPico || !(outs[n - 1].pay == Dref)) {
        m.why = "donation output absent: the canonical coinbase does not end in the >= " +
                std::to_string(kDonationDustPico) + "-piconero donation output (owed + 1 + residual)";
        return m;
    }
    for (std::size_t i = 0; i + 1 < n; ++i)
        if (outs[i].identity == D || outs[i].pay == Dref) {
            m.why = "more than one donation output: output " + std::to_string(i) +
                    " also pays the donation address (its owed payout must merge into the last one)";
            return m;
        }
    if (outs[n - 1].owed_part > outs[n - 1].amount - kDonationDustPico) {
        m.why = "the donation output's owed part " + std::to_string(outs[n - 1].owed_part) +
                " leaves less than the " + std::to_string(kDonationDustPico) + "-piconero minimum";
        return m;
    }
    m.ok = true; m.marker = n - 1;
    return m;
}
// Mainnet form (D = the mainnet donation identity) and the per-network form.
inline MarkerLocation inspect_donation_marker(const std::vector<x6::CoinbaseOutput>& outs,
                                              const ::v37::bytes32& D) {
    return inspect_donation_marker(outs, D, donation_ref());
}
inline MarkerLocation inspect_donation_marker(const std::vector<x6::CoinbaseOutput>& outs, DonationNet n) {
    return inspect_donation_marker(outs, donation_identity(n), donation_ref(n));
}

// Receive-side booking rule. `ids`/`amounts` are the per-vout identities and
// amounts the coinbase-authority decoder mapped; `payout` / `sink_total` are
// its maps, where every output to D (the sink identity) was tallied as
// coverage. `owed_in` is the coinbase's committed "V37D" tail. Books
// donation_owed_part(amount, owed_in) of the ONE donation output as D's
// payout (a ledger deduction) and leaves the rest (1 + residual) as coverage.
// Returns false (and *why) when the output or the tail is absent: the caller
// refuses.
inline bool apply_donation_rule(const std::vector<::v37::bytes32>& ids,
                                const std::vector<std::uint64_t>& amounts,
                                const ::v37::bytes32& D,
                                const std::optional<std::uint64_t>& owed_in,
                                std::map<::v37::bytes32, long long>& payout,
                                long long& sink_total, std::string* why) {
    const MarkerLocation m = locate_donation_marker(ids, amounts, D);
    if (!m.ok) { if (why) *why = m.why; return false; }
    if (!owed_in) {
        if (why) *why = "the donation owed_in commitment (0x02 tail V37D) is absent";
        return false;
    }
    const std::uint64_t part = donation_owed_part(amounts[m.marker], *owed_in);
    if (part > 0) {
        sink_total -= static_cast<long long>(part);
        payout[D] += static_cast<long long>(part);
    }
    return true;
}

} // namespace c2pool::v37n::xmr::fee
