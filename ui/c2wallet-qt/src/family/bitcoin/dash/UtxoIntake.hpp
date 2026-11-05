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
// scriptPubKey, height, ...}, ...]. Returns the UTXOs in file order (txid
// lowercased), or an empty vector with `err` set on the first malformed entry. A
// missing confirmations field reads as 0 (unconfirmed); a missing scriptPubKey
// reads as empty, which a strict screen then refuses; a missing height reads as
// 0 (unknown).
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

// ── Slice 2: the intake formats an operator actually produces ───────────────
//
//   ExportV1         ui/c2wallet-qt/tools/export_utxos.py on the online host:
//                    {"schema":"c2wallet-utxo-export/1", "coin":"dash",
//                     "network":"mainnet"|"testnet", "address", "tip_height",
//                     "tip_hash", "utxos":[{txid, vout, satoshis, height,
//                     confirmations, coinbase, scriptPubKey}]}
//   GetAddressUtxos  dashd `getaddressutxos` (addressindex): the bare array
//                    [{address, txid, outputIndex, script, satoshis, height}]
//                    plus the tip height typed by the operator, or the
//                    chainInfo object {"utxos":[...], "hash", "height"}.
//   Insight          parse_insight_utxos above.
//
// Every row of every format must pay ONE P2PKH script; the funding address is
// derived from that script (an `address` field, where present, must agree).
// Refusals throw DashAbort and return nothing.
enum class UtxoSource : uint8_t { ExportV1, GetAddressUtxos, Insight };
const char* utxo_source_name(UtxoSource s);

inline constexpr const char* kUtxoExportSchema = "c2wallet-utxo-export/1";

struct UtxoImport {
    UtxoSource source = UtxoSource::Insight;
    std::string address;          // the funding address every row pays
    bool testnet = false;
    int64_t tip_height = 0;       // the tip the confirmations are counted at; 0 = unknown
    std::string tip_hash;         // ExportV1 / chainInfo form only
    bool coinbase_flags = false;  // every row carries a KNOWN coinbase flag
    std::vector<Utxo> utxos;      // file order; txid lowercased; height 0 = unknown
    int64_t total = 0;            // sum of satoshis (<= MAX_MONEY)
};

// dashd getaddressutxos. For the bare array `tip_height` is required (> 0) and
// confirmations = tip - height + 1 (a row above the tip is refused). For the
// chainInfo object, `tip_height` must be 0 or equal to its "height". coinbase
// is unknown for every row (held to the coinbase rule).
UtxoImport parse_getaddressutxos(const std::string& json, int64_t tip_height, bool testnet);

// The c2wallet export v1. Refuses another schema, a coin other than dash, a
// network other than the page's, tip_height <= 0, a row whose confirmations is
// not tip - height + 1 (two tips mixed), and a row without scriptPubKey. A row
// without a coinbase flag is treated as coinbase.
UtxoImport parse_utxo_export_v1(const std::string& json, bool testnet);

// Format auto-detect: an object carrying "schema" is ExportV1, an object
// carrying "utxos" + "height" is the getaddressutxos chainInfo form, an array
// whose first row has "outputIndex" is getaddressutxos, one whose first row has
// "vout" is insight. For insight the tip is `tip_height` when given, else
// derived from rows carrying both height and confirmations (all must agree).
UtxoImport parse_utxo_json(const std::string& json, int64_t tip_height, bool testnet);

// ── Maturity at a target landing height (design §4.4) ──────────────────────
//
// A coinbase output created at height h may be spent in the block at height H
// iff H >= h + 100 (dashd CheckTxInputs; the node's next_height < h + 100 =>
// immature). The confirmations an input "has" when block H is built are H - h,
// so the screen rewrites each input's confirmations to that value and runs the
// one gate, screen_utxos. min_confirmations (default 101) keeps one block of
// slack over the consensus 100.
//
// confirmations_at: height known => H - h (never below 0); height unknown but a
// tip known and the row confirmed => confirmations + (H - tip - 1); otherwise
// the confirmations as exported (an unconfirmed row is never projected).
int64_t confirmations_at(const Utxo& u, int64_t tip_height, int64_t target_height);

// Blocks until `u` clears the gate at `target_height` (0 when it already does).
int64_t matures_in(const Utxo& u, int64_t tip_height, int64_t target_height,
                   int64_t min_confirmations);

// The block height an input was created at: its height, else tip - conf + 1
// when both are known, else 0.
int64_t effective_height(const Utxo& u, int64_t tip_height);

// The earliest block height in which EVERY one of `inputs` is spendable under
// consensus: max over inputs of (height + 100) for coinbase-or-unknown inputs,
// (height + 1) for known non-coinbase ones. 0 when an input's height cannot be
// derived (the caller reports it as unknown).
int64_t safe_from_height(const std::vector<Utxo>& inputs, int64_t tip_height);

struct TargetScreen {
    UtxoScreen screen;              // confirmations rewritten to the target height
    std::vector<Utxo> projected;    // every input, confirmations at the target (request order)
    int64_t tip_height = 0;
    int64_t target_height = 0;
    int64_t min_confirmations = 0;
    int64_t dust_floor = 0;
    int64_t safe_from_height = 0;   // over screen.spendable; 0 = unknown
    int64_t youngest_height = 0;    // max effective height over screen.spendable; 0 = unknown
};

// Re-screen `utxos` (counted at `tip_height`) for landing at `target_height`.
// Throws DashAbort if target_height <= tip_height (a tx cannot land at or below
// the screened tip) or target_height <= 0, plus every screen_utxos refusal.
TargetScreen rescreen_at_height(const std::vector<Utxo>& utxos,
                                const std::array<uint8_t, 20>& funding_h160,
                                int64_t tip_height,
                                int64_t target_height,
                                int64_t min_confirmations,
                                int64_t dust_floor,
                                bool strict);

} // namespace c2w::dash
