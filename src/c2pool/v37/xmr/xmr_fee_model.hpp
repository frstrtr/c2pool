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
//   1. DONATION OUTPUT = MANDATORY. Every lane coinbase carries the donation
//      output to the protocol donation address. In p2pool it is structural
//      (the donation script sits in the hashed gentx tail, so a gentx without
//      it fails the share PoW); V36 adds the ">= 1 satoshi" marker rule
//      (data.py: final_donation < 1 -> take 1 from the largest payee). Here:
//        * a FixedOutput of EXACTLY kDonationDustPico (1 piconero) to the
//          donation ref, on every node, from a compiled-in constant -- no
//          node can omit it (there is no knob);
//        * serve side: inspect_donation_marker() refuses a template whose
//          canonical coinbase does not end in the marker (+ optional sink);
//        * receive side: apply_donation_rule() refuses to book a lane
//          coinbase that does not carry the marker (REFUSE-IF-ABSENT).
//   2. DONATION = THE RESIDUAL SINK. The exact-sum remainder (p2pool data.py:
//      amounts[DONATION] += subsidy - sum(amounts)) goes to the donation
//      address: residual_sink := donation ref. With the unchanged X6
//      allocator this is a SECOND output to the same address, emitted only
//      when residual > 0 (folding it INTO the marker output is the X6
//      allocator edit handed to the operator, see the seam notes below).
//   3. GIVE-AUTHOR = a u16 CARRIED IN THE RECEIPT. v36: share_data.donation =
//      perfect_round(65535*pct/100); weights miner att*(65535-d), donation
//      att*d. Every node folds every receipt with the receipt's OWN u16, so
//      two nodes with different give-author % still build the same coinbase.
//      Here: the minted receipt carries d; ingest splits ONE receipt of weight
//      w into two lane pushes, (miner, w - floor(w*d/65535)) and (donation,
//      floor(w*d/65535)). The lane / fold_eb code is untouched; d = 0 is a
//      single push, byte-identical to the pre-fee receipt stream.
//   4. NODE-OWNER FEE = PROBABILISTIC IDENTITY SUBSTITUTION AT MINT (v36
//      work.py: random.uniform(0,100) < node_owner_fee -> pubkey_hash =
//      my_pubkey_hash). The roll happens when the RECEIPT is minted; the
//      substituted payee rides in the receipt and peers admit it as ordinary
//      work. Never a post-FOUND payee swap.
//   5. NO FINDER BONUS (V36 dropped forrestv's 0.5% finder output).
//
// Everything here is a pure function of its arguments (the owner-fee roll
// takes its random word as an argument) so it is KAT-able.
//
// CONSENSUS SEAMS HANDED TO THE OPERATOR (not edited here; master 4345baf68):
//   S1 single donation output (the exact p2pool shape): xmr_coinbase.cpp:160-170
//      emits the residual as a SEPARATE Sink iff > 0; fold it into the last
//      fixed output when that output pays residual_sink (marker := 1+residual),
//      drop the sink slot from CapTooSmall (:109-114). Then the tail is ONE
//      donation output >= 1 and locate_donation_marker() simplifies to "last
//      output pays D, amount >= 1" (removes the 1-piconero S/N ambiguity).
//      Moves the X6 coinbase goldens that set fixed == sink.
//   S2 the V36 ">= 1 from the LARGEST payee": here the marker is deducted
//      before the owed pass, so the 1 piconero comes out of the LAST K_fair
//      paid entry and is CARRIED as owed (lossless). Ruling owed.
//   S3 the give-author u16 in the PoW-committed receipt: Family-A
//      w2_receipt.hpp:206-234 (field + preimage after nonce), w3_wire_freeze
//      .hpp:195-215 (v0x03, 114-byte fixed prefix, F-5 dual-accept),
//      w3_relay.hpp:393-403/504-515 (put/get_u16 after nonce); Family-B
//      xmr_receipt.hpp:211-216 (ReceiptSideData) + xmr_receipt_verify.cpp:
//      139-148 (side_data_digest appends le16). Until then the u16 rides the
//      regtest R1 feed line only (not PoW-bound).
//   S4 coordinated activation: +1 marker output, sink := donation, and the
//      donation pushes change coinbase bytes and the lane record stream on
//      every node together; this branch applies them unconditionally (no
//      activation height) -- the v37.0x subversion gate is the operator's.
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

// The mandatory marker output (declared LAST among the fixed outputs so the
// canonical tail is [ ... owed ][ marker ][ sink? ]).
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
// Node-owner fee (roll at receipt mint)
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

// ---------------------------------------------------------------------------
// The minted receipt (XMR regtest carrier stand-in wire, one line):
//   "R1 <kind:u8> <payload:128hex> <w:u64> <d:u16>\n"
// The payee IS the receipt's identity (owner-fee substitution already
// applied), d IS the give-author u16. Every node that reads the line folds it
// the same way. Legacy "idx w" lines stay valid (d = 0).
// ---------------------------------------------------------------------------
struct MintedReceipt {
    ::v37::ScriptRef payee;
    std::uint64_t    w = 0;
    std::uint16_t    d = 0;
    bool             owner_substituted = false;   // mint-side bookkeeping only (not on the wire)
};

inline MintedReceipt mint_receipt(const ::v37::ScriptRef& miner,
                                  const std::optional<::v37::ScriptRef>& owner,
                                  std::uint32_t owner_fee_bp, std::uint16_t give_author,
                                  std::uint64_t w, std::uint64_t roll) {
    MintedReceipt r;
    r.w = w;
    r.d = give_author;
    if (owner && owner_fee_hit(roll, owner_fee_bp)) { r.payee = *owner; r.owner_substituted = true; }
    else r.payee = miner;
    return r;
}

inline std::string encode_receipt_line(const MintedReceipt& r) {
    static const char* hx = "0123456789abcdef";
    std::string s = "R1 " + std::to_string(static_cast<unsigned>(r.payee.kind)) + " ";
    for (std::uint8_t b : r.payee.payload) { s += hx[b >> 4]; s += hx[b & 15]; }
    s += " " + std::to_string(r.w) + " " + std::to_string(r.d) + "\n";
    return s;
}

inline std::optional<MintedReceipt> parse_receipt_line(const std::string& ln) {
    if (ln.size() < 3 || ln.compare(0, 3, "R1 ") != 0) return std::nullopt;
    unsigned kind = 0; char pay[129] = {0}; unsigned long long w = 0; unsigned d = 0;
    if (std::sscanf(ln.c_str(), "R1 %u %128s %llu %u", &kind, pay, &w, &d) != 4) return std::nullopt;
    if (std::strlen(pay) != 128 || w == 0 || d > kGiveAuthorScale || kind > 255) return std::nullopt;
    MintedReceipt r;
    r.payee.kind = static_cast<::v37::ScriptKind>(kind);
    if (!::v37::xmr::is_xmr_kind(r.payee.kind)) return std::nullopt;
    std::array<std::uint8_t, 32> a{}, b{};
    const std::string ps(pay);
    if (!hex32_of(ps.substr(0, 64).c_str(), a) || !hex32_of(ps.substr(64, 64).c_str(), b)) return std::nullopt;
    r.payee = r.payee.kind == ::v37::xmr::XMR_SUB ? ::v37::xmr::make_xmr_sub(a, b) : ::v37::xmr::make_xmr_std(a, b);
    r.w = w;
    r.d = static_cast<std::uint16_t>(d);
    return r;
}

// The lane pushes ONE receipt becomes (every node, same order): the miner
// push first, then the donation push iff its share is non-zero.
inline std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> receipt_pushes(const MintedReceipt& r) {
    std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> v;
    const SplitWeight s = split_receipt_weight(r.w, r.d);
    if (s.miner) v.emplace_back(r.payee, s.miner);
    if (s.donation) v.emplace_back(donation_ref(), s.donation);
    return v;
}

// ---------------------------------------------------------------------------
// The marker rule over a coinbase's output list, identity-mapped.
//
// Canonical tail (X6 order [owed] ++ [fixed] ++ [sink?], marker LAST fixed,
// sink := donation):   ... owed | D:1 (marker) | D:residual (sink, iff > 0)
//
// Deterministic location, identical on every node:
//   S: ids[n-1]==D && ids[n-2]==D && amt[n-2]==DUST -> marker n-2, sink n-1
//   N: ids[n-1]==D && amt[n-1]==DUST                -> marker n-1, no sink
//   otherwise: the marker is ABSENT -> REFUSE.
// (S wins the one 1-piconero ambiguity [D-owed:1][marker:1] vs [marker:1]
// [sink:1]; both nodes pick S, so the booking stays identical.)
// Outputs to D BEFORE the marker are ordinary OWED outputs (give-author
// credit) and are booked as ledger deductions; the marker and the sink are
// coverage only (D1).
// ---------------------------------------------------------------------------
struct MarkerLocation {
    bool        ok = false;
    std::string why;
    std::size_t marker = 0;
    bool        has_sink = false;
};
inline MarkerLocation locate_donation_marker(const std::vector<::v37::bytes32>& ids,
                                             const std::vector<std::uint64_t>& amounts,
                                             const ::v37::bytes32& D) {
    MarkerLocation m;
    const std::size_t n = ids.size();
    if (n == 0 || amounts.size() != n) { m.why = "donation marker absent: no outputs"; return m; }
    if (!(ids[n - 1] == D)) { m.why = "donation marker absent: the last output does not pay the donation address"; return m; }
    if (n >= 2 && ids[n - 2] == D && amounts[n - 2] == kDonationDustPico) { m.ok = true; m.marker = n - 2; m.has_sink = true; return m; }
    if (amounts[n - 1] == kDonationDustPico) { m.ok = true; m.marker = n - 1; m.has_sink = false; return m; }
    m.why = "donation marker absent: no " + std::to_string(kDonationDustPico) +
            "-piconero donation output at the canonical tail (last donation output = " + std::to_string(amounts[n - 1]) + ")";
    return m;
}

// Serve-side property over the builder's canonical output list (roles known).
inline MarkerLocation inspect_donation_marker(const std::vector<x6::CoinbaseOutput>& outs,
                                              const ::v37::bytes32& D) {
    MarkerLocation m;
    const std::size_t n = outs.size();
    std::size_t k = n;
    if (n && outs[n - 1].role == x6::CoinbaseOutput::Role::Sink) {
        if (!(outs[n - 1].identity == D)) { m.why = "the residual sink is not the donation address"; return m; }
        k = n - 1; m.has_sink = true;
    }
    if (k == 0 || outs[k - 1].role != x6::CoinbaseOutput::Role::Fixed || !(outs[k - 1].identity == D) ||
        outs[k - 1].amount != kDonationDustPico || !(outs[k - 1].pay == donation_ref())) {
        m.why = "donation marker absent: the canonical coinbase does not end in the " +
                std::to_string(kDonationDustPico) + "-piconero donation output (+ optional donation sink)";
        return m;
    }
    m.ok = true; m.marker = k - 1;
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
