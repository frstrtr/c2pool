// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// UTXO intake for the DASH builders: the insight-API UTXO list (what
// build_collateral_unsigned.py reads from /addr/<a>/utxo) parsed into Utxo
// records, and the one screening pass every plan runs over its UTXOs — malformed
// entries and foreign scriptPubKeys refused, dust and immature outputs set
// aside so the summary can list them.
//
// The intake is public data only. Amounts are taken from the integer
// `satoshis` field; the floating `amount` field is ignored. Insight carries no
// coinbase flag, so every parsed UTXO has coinbase == nullopt and is held to
// the coinbase rule, max(min_confirmations, 100) (a coinbase output dropped into
// a template before it matures is dropped silently by the node, so this gate is
// the only guard).
//
// std-only header; the .cpp sits on the btclibs closure (hdkeys MiniJson / hex).

#include "CollateralTx.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

// Parse an insight UTXO array: [{txid, vout, satoshis, confirmations,
// scriptPubKey, ...}, ...]. Returns the UTXOs in file order (txid lowercased),
// or an empty vector with `err` set on the first malformed entry. A missing
// confirmations field reads as 0 (unconfirmed); a missing scriptPubKey reads as
// empty, which a strict screen then refuses.
std::vector<Utxo> parse_insight_utxos(const std::string& json, std::string& err);

// Confirmations a UTXO needs before a plan may spend it: 1 for an output KNOWN
// not to be coinbase; otherwise (coinbase, or unknown) max(min_confirmations,
// kCoinbaseMaturity).
int64_t confirmations_needed(const Utxo& u, int64_t min_confirmations);

struct UtxoScreen {
    std::vector<Utxo> spendable; // request order
    std::vector<Utxo> immature;  // confirmations < confirmations_needed
    std::vector<Utxo> dust;      // satoshis < dust_floor (checked before maturity)
};

// Screen `raw` for a plan funded by `funding_h160`. Throws DashAbort on a
// malformed entry (bad txid, negative value) or a scriptPubKey that is present
// and does not pay the funding P2PKH, and on an outpoint listed twice (in every
// mode: a tx spending it twice is invalid). With `strict` (inject mode,
// sweep_all and SweepTx) a missing scriptPubKey is refused as well.
UtxoScreen screen_utxos(const std::vector<Utxo>& raw,
                        const std::array<uint8_t, 20>& funding_h160,
                        int64_t min_confirmations,
                        int64_t dust_floor,
                        bool strict);

// The sweep builders' default input order: (display txid, vout), case-blind,
// as build_collateral_unsigned.py sorts. Stable.
void sort_by_outpoint(std::vector<Utxo>& utxos);

// Fixed 8-decimal DASH amount ("1.00000000") for summaries.
std::string format_dash(int64_t duffs);

// Summary lines for what a screen left out: every immature UTXO with "matures
// in N blocks", every dust UTXO, and the perpetual-tail note (nothing here
// builds a follow-up tx for them). Empty when nothing was left out.
std::string describe_skipped(const UtxoScreen& screen, int64_t min_confirmations,
                             int64_t dust_floor);

} // namespace c2w::dash
