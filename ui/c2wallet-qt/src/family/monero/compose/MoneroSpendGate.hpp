// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/compose/MoneroSpendGate.hpp
//
// The Qt-FREE money-decision core shared by the Family-B (Monero) Build/Sign
// pages (PageBuildTxMonero / PageSignMonero) and their KAT. It mirrors, for
// Monero, the anti-misdirection gate the Family-A slice-2a pages carry (design
// §5.3 / §5.5 money-path discipline):
//
//   * BOTH-UNITS, INTEGER-ONLY amounts (T-1): every piconero value renders as
//     an exact 12-dp XMR string AND its raw piconero; parsing is integer-only.
//     NO IEEE double ever touches a money amount (rounding would lose funds).
//   * DESTINATION NET CHECK (T-2 / T-12, the Monero #961 analog): a decoded
//     address is accepted only when its network matches the composer's; a
//     testnet/stagenet address in a mainnet build is refused, not silently sent.
//   * BALANCE GATE (T-5 precondition): Sum(source amounts) == Sum(dest amounts)
//     + fee, checked on integers before anything is assembled or signed.
//   * OWN vs EXTERNAL (T-3): a destination is OWN/CHANGE iff it pays the
//     wallet's primary (spend_pub,view_pub) or a subaddress in the wallet's
//     precomputed table; everything else leaves the wallet. Shown BEFORE the
//     secret is committed to signing.
//   * GAP-6 secret scrub (T-8): a page-side explicit wipe of every spend
//     secret (SpendInput.one_time_sec) on every path, belt-and-braces with the
//     lib-side SpendInput destructor.
//
// Qt-free on purpose so the money logic builds and KAT-runs without the Qt app
// (design §2.3 — link the leaf, not the shell), exactly as the Family-B crypto
// core does.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"                 // Bytes32
#include "family/monero/MoneroKey.hpp"                     // MoneroKeys
#include "family/monero/addr/MoneroAddress.hpp"            // Network, AddressType, address_decode
#include "family/monero/scan/MoneroScanner.hpp"            // SubaddressTable
#include "family/monero/prover/MoneroRingctBuilder.hpp"    // TxDestination, SpendInput
#include "family/monero/artifact/MoneroArtifact.hpp"       // UnsignedTxSource

namespace c2wallet::monero::compose {

// XMR carries 12 decimals: 1 XMR == 1e12 piconero.
inline constexpr std::uint64_t PICO_PER_XMR = 1000000000000ULL;

// Exact 12-dp XMR string for `pico`, integer-only (never a double). e.g.
// 1234500000000 -> "1.234500000000".
std::string format_xmr(std::uint64_t pico);

// "1.234500000000 XMR (1234500000000 pico)" — the T-1 both-units render.
std::string both_units(std::uint64_t pico);

// Parse a decimal XMR amount (<=12 fractional digits) into piconero. Integer
// arithmetic only; rejects a non-numeric char, >12 dp, or an overflow.
bool parse_xmr(const std::string& s, std::uint64_t& pico, std::string& err);

// A decoded, net-checked destination address.
struct DecodedDest {
    prover::TxDestination      dest{};          // spend_pub/view_pub set; amount left 0 (caller fills)
    AddressType                type{AddressType::Standard};
    bool                       has_payment_id{false};
    std::array<std::uint8_t,8> payment_id{};    // integrated only (read+warn, never generated)
};

// Decode `addr` and REFUSE a network mismatch (T-2/T-12). On success fills
// `out` (dest.is_subaddress set for a subaddress) and returns true.
bool decode_dest(const std::string& addr, Network expected_net,
                 DecodedDest& out, std::string& err);

// Balance gate (integer-only): sum_in := Σ sources.amount, sum_out := Σ
// dests.amount, and the tx is balanced iff sum_in == sum_out + fee.
bool balance_ok(const std::vector<artifact::UnsignedTxSource>& sources,
                const std::vector<prover::TxDestination>& dests,
                std::uint64_t fee,
                std::uint64_t& sum_in, std::uint64_t& sum_out);

// OWN/EXTERNAL verdict for one destination (T-3). OWN binds BOTH keys: for the
// primary account (0,0) it is (spend_pub,view_pub) == the wallet's; for a
// subaddress (i,j) the spend-pub must be in the precomputed table AND satisfy
// K_v^(i,j) == k_v * K_s^(i,j). Binding spend-pub ALONE is a fund-loss hole: a
// compromised online host could swap the change dest's view key for a garbage
// point, the card would show "OWN — change returns to you", the operator would
// sign, and the change would be BURNED (the owner's scanner computes
// D = k_v*R != r*A, so nobody can spend it). Self-verify cannot catch that (the
// tx is cryptographically valid) — this two-key gate is the only defence.
enum class Ownership { Own, External };
Ownership classify_dest(const prover::TxDestination& d, const MoneroKeys& keys,
                        const SubaddressTable& subs);

// Payability gate: this signer supports only STANDARD-address destinations.
//   * A SUBADDRESS destination needs a per-output additional tx key (tx_extra
//     0x04); the RingCT assembler does not emit one, so a subaddress output
//     would be UNSPENDABLE (burned). Refused until that is implemented.
//   * An INTEGRATED / payment-id destination needs its 8-byte pid encrypted
//     under the tx secret key r; the assembler generates r internally and never
//     re-encrypts, so the pid would be wrong/absent and an exchange deposit
//     would not be credited. Refused until pid-encryption-with-r exists.
// Returns false + a named `reason` for such a destination — enforced at Build
// (per decoded address) and at Sign (per parsed dest / non-empty tx_extra).
bool dest_supported(bool is_subaddress, bool has_payment_id, std::string& reason);

// GAP-6 (T-8): explicitly scrub every spend secret x_i. Called on every path
// AFTER the secrets have been consumed (sign / self-verify), belt-and-braces
// with prover::SpendInput's own destructor.
void wipe_spend_inputs(std::vector<prover::SpendInput>& v);

} // namespace c2wallet::monero::compose
