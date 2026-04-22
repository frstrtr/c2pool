#pragma once

/// Dash UTXO adapter layer — Phase U step 1.
///
/// Plumbs `dash::coin::BlockType` and `dash::coin::MutableTransaction` into
/// the chain-agnostic `core::coin::UTXOViewCache` / `UTXOViewDB` machinery
/// (already used by LTC and DOGE). This file is the **type-compatibility
/// shim only** — no live UTXOViewCache instance is constructed yet; that
/// wiring lands in later Phase U steps (connect_block on new-tip arrival,
/// LevelDB persistence, block-bootstrapper cold-start).
///
/// Why adapter-only first: lets us ship the Dash-side types + constants +
/// txid helper in a standalone commit so the larger Phase U integration
/// stages (which touch main_dash.cpp + broadcaster event plumbing) land
/// against a stable base.
///
/// References:
///   - `dashcore/src/consensus/consensus.h` (COINBASE_MATURITY = 100)
///   - `dashcore/src/consensus/amount.h`    (MAX_MONEY = 21M * COIN)
///   - `dashcore/src/validation.h`          (MIN_BLOCKS_TO_KEEP = 288)

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>

namespace dash {
namespace coin {

// ── ChainLimits ────────────────────────────────────────────────────────────
//
// Dash consensus constants, mirroring dashcore/src/consensus. Values
// chosen to match the generic UTXO machinery's ChainLimits struct
// (max_money / coinbase_maturity / pegout_maturity).
//
// - max_money         : 21_000_000 * COIN (dashcore's validation bound;
//                       Dash's circulating supply is ~21 M DASH but
//                       dashcore inherits Bitcoin's 21 M MoneyRange check).
// - coinbase_maturity : 100 blocks (standard Bitcoin-family value;
//                       dashcore/src/consensus/consensus.h COINBASE_MATURITY).
// - pegout_maturity   : 0 (Dash has no MWEB, so no pegout concept).
inline constexpr ::core::coin::ChainLimits DASH_LIMITS = {
    /* max_money         */ 2'100'000'000'000'000LL,
    /* coinbase_maturity */ 100,
    /* pegout_maturity   */ 0,
};

// Undo-data retention: at least 288 blocks, same as dashcore's
// MIN_BLOCKS_TO_KEEP (validation.h). Keeps reorg-repair data around
// long enough to handle deep reorganisations.
inline constexpr uint32_t DASH_MIN_BLOCKS_TO_KEEP = 288;

// Minimum chain depth before embedded mining can fully trust the UTXO
// set: coinbase_maturity + a small reorg buffer. 100 + 6 = 106, in
// line with LTC's approach (LTC uses coinbase_maturity + pegout_maturity
// = 106; Dash has no pegout so we add an equivalent 6-block reorg
// buffer explicitly).
inline constexpr uint32_t DASH_MINING_GATE_DEPTH =
    DASH_LIMITS.coinbase_maturity + 6;

// ── Dash txid helper ───────────────────────────────────────────────────────
//
// Double-SHA256 of the transaction's canonical serialization. DIP3 /
// DIP4 special transactions (type != 0) carry an `extra_payload` field
// that `MutableTransaction::Serialize` already appends; the resulting
// byte stream is what dashcore hashes into the txid, so we mirror
// exactly. Plain (type=0) transactions serialize identically to
// pre-DIP3 Bitcoin-family txs.
//
// UTXOViewCache::connect_block<BlockType> takes a TxidFn parameter —
// this function matches that signature.
inline ::uint256 dash_txid(const MutableTransaction& tx)
{
    auto packed = ::pack(tx);
    return ::Hash(packed.get_span());
}

// ── Alias so call sites read naturally ─────────────────────────────────────
using UtxoViewCache = ::core::coin::UTXOViewCache;
using UtxoViewDB    = ::core::coin::UTXOViewDB;
using Outpoint      = ::core::coin::Outpoint;
using Coin          = ::core::coin::Coin;
using BlockUndo     = ::core::coin::BlockUndo;

// ── Compile-time shape check ──────────────────────────────────────────────
//
// Confirms BlockType + MutableTransaction + the adapter constants are
// mutually consistent with the generic UTXOViewCache template interface.
// No runtime cost; just a type-lookup assertion that fails-to-compile if
// any of the expected fields are missing or renamed.
static_assert(sizeof(DASH_LIMITS) > 0,
              "DASH_LIMITS must be a valid ChainLimits instance");
static_assert(MutableTransaction::m_hogEx == false,
              "Dash transactions never mark as MWEB HogEx (m_hogEx=false is "
              "required by the shared UTXOViewCache::connect_block template)");

} // namespace coin
} // namespace dash
