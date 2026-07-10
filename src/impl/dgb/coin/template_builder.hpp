// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// DGB block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp.
// Must emit p2pool-merged-v36-compatible templates (V36 master compat).
//
// >>> SCRYPT GBT FILTER POINT (M1 section 3) <<<
// DGB multi-algo: getblocktemplate is requested with rules=["scrypt"] so the
// embedded daemon only returns Scrypt-eligible templates. The builder assembles
// and submits Scrypt blocks only in V36. (config_coin.hpp CoinParams::GBT_ALGO.)
//
// Share/PoW format is identical to LTC Scrypt; share assembly reuses the shared
// Scrypt-family path (do NOT fork LTC share logic -- per-coin isolation).
// TODO(M3): TemplateBuilder + EmbeddedCoinNode emitting p2pool-merged-v36-parity
// Scrypt templates (mirror of btc's HeaderChain+Mempool-backed EmbeddedCoinNode).
//
// Namespace note: seam-facing DGB types live in dgb::coin / dgb::interfaces,
// matching config_coin.hpp (namespace dgb) and the btc::coin / ltc::coin
// pattern the family-1 seam binds against.

#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "rpc_data.hpp"
#include "dgb_block_algo.hpp"  // DGB_BLOCK_VERSION_SCRYPT (Scrypt lane pin)

namespace dgb
{

namespace coin
{

// --- CoinNodeInterface ------------------------------------------------------
// Abstract interface for obtaining work and submitting blocks; lets the
// concrete CoinNode swap between RPC (legacy), embedded, or hybrid sources
// without changing downstream code. TRIMMED mirror of btc's CoinNodeInterface
// (src/impl/btc/coin/template_builder.hpp:93): submit_block(BlockType&) is
// deferred to M3 with the coin/block.hpp port -- BlockType does not exist for
// dgb yet, and the family-1 seam submits via NodeRPC::submit_block_hex, so
// nothing binds the trimmed slot today.
class CoinNodeInterface {
public:
    virtual ~CoinNodeInterface() = default;

    /// Return a block template as WorkData.
    /// Throws std::runtime_error if no template can be produced.
    virtual rpc::WorkData getwork() = 0;

    /// Return chain info (analogous to getblockchaininfo RPC).
    virtual nlohmann::json getblockchaininfo() = 0;

    /// True when the embedded chain is up to date with the network
    /// AND has enough UTXO depth for coinbase maturity validation.
    virtual bool is_synced() const { return false; }

    // TODO(M3): virtual void submit_block(BlockType& block) = 0; -- restored
    // verbatim from btc once coin/block.hpp is ported.
};


// ── Work-template assembly SSOT (Stage 4c) ──────────────────────────────────
// build_work_template() shapes the already-resolved field values into the
// GBT-compatible JSON template that DGBWorkSource::get_current_work_template()
// returns. Lifting the assembly here makes the stratum work source and the
// embedded path emit ONE template object -- they cannot diverge once both call
// this SSOT (the same intent as routing get_current_gbt_prevhash through
// tip_hash() in Stage 4b).
//
// NON-CONSENSUS: this function only SHAPES values; it never derives or alters
// the consensus-bearing coinbasevalue. That value is computed by the caller
// through the #207 resolve_coinbase_value -> subsidy_func SSOT and passed in
// verbatim. The builder fabricates nothing: transactions[] is a caller-supplied
// pass-through (empty by default until a mempool tx source is wired -- truthful
// absence, never a fabricated tx; the fee total is folded into coinbasevalue
// UPSTREAM via resolve_coinbase_value, not here), previousblockhash
// is emitted ONLY when the caller supplies a real tip hash (truthful absence,
// never a fabricated id), and `bits` is likewise a caller-supplied conditional
// pass-through: emitted ONLY when the caller hands in the authoritative
// external-daemon GBT bits. The embedded Scrypt-only path supplies none -- DGB
// Core's live next-target is MultiShield V4 (a global 5-algo window == V37), so
// a Scrypt-only walk would emit a known-wrong difficulty (the same fabrication
// the empty transactions[] deliberately avoids); it leaves bits unset and the
// field is held back for that caller, never fabricated. The G1 replay harness
// and any future daemon-GBT caller set in.bits from the oracle value.
struct WorkTemplateInputs {
    // Absolute height of the NEXT block (#209 next_block_height()).
    uint32_t next_height = 0;
    // Reward for the next block, already resolved via the #207 SSOT. Passed in
    // verbatim; the builder never recomputes or scales it.
    uint64_t coinbasevalue = 0;
    // DGB Core ContextualCheckBlockHeader lower bound source (median-time-past).
    // INT64_MIN means an empty chain (unconstrained) -> mintime emits 0.
    int64_t  median_time_past = std::numeric_limits<int64_t>::min();
    // GBT suggested header nTime. Injected by the caller (work source: wall
    // clock) so the assembly is deterministically testable.
    int64_t  curtime = 0;
    // Tip block id as GBT big-endian display hex, already formatted by the
    // caller (work source: u256_be_display_hex). nullopt -> previousblockhash
    // omitted from the template.
    std::optional<std::string> previousblockhash;
    // GBT transactions[] array, already shaped by the caller (per-tx
    // {data,txid,hash,fee} objects, the same shape btc's template_builder
    // emits). The builder passes it through VERBATIM and shapes nothing -- the
    // identical truthful-absence discipline as previousblockhash: it defaults
    // to an empty array, so a caller that has wired no transaction source (the
    // current embedded + stratum paths) emits an empty transactions[] and
    // fabricates nothing. The fee total those txs carry is folded into
    // coinbasevalue UPSTREAM via resolve_coinbase_value(total_fees) (#207 SSOT);
    // the builder never derives the reward, so this field is display-only shape.
    nlohmann::json transactions = nlohmann::json::array();
    // GBT nBits (compact difficulty) as the daemon emits it -- the authoritative
    // external-daemon GBT value, supplied by the caller. nullopt -> bits omitted
    // from the template (truthful absence: the embedded Scrypt-only path can only
    // reconstruct MultiShield V4 with a full 5-algo window (== V37), so it never
    // fabricates a Scrypt-only value and leaves this unset). The identical
    // conditional-emit discipline as previousblockhash.
    std::optional<std::string> bits;
};

inline nlohmann::json build_work_template(const WorkTemplateInputs& in)
{
    // version: BIP9 base | DGB Scrypt algo nibble (dgb_block_algo.hpp SSOT). A
    // DGB template MUST pin the Scrypt lane -- the mining algo lives in 4
    // nVersion bits and Scrypt is the all-zero codepoint (DGB_BLOCK_VERSION_SCRYPT
    // == 0x0000); any other nibble is a non-Scrypt algo this V36 binary never
    // emits a template for.
    static constexpr uint32_t BIP9_BASE_VERSION = 0x20000000u;
    const uint32_t version =
        BIP9_BASE_VERSION |
        static_cast<uint32_t>(DGB_BLOCK_VERSION_SCRYPT);

    // mintime: median_time_past()+1 (DGB Core's nTime > MTP lower bound). An
    // empty chain reports INT64_MIN (unconstrained) -> emit 0.
    const int64_t mintime =
        (in.median_time_past == std::numeric_limits<int64_t>::min())
            ? 0 : (in.median_time_past + 1);

    nlohmann::json tmpl = nlohmann::json::object();
    tmpl["height"]        = in.next_height;
    tmpl["coinbasevalue"] = in.coinbasevalue;
    tmpl["version"]       = version;
    tmpl["curtime"]       = in.curtime;
    tmpl["mintime"]       = mintime;
    tmpl["transactions"]  = in.transactions;  // caller-supplied; empty by default

    // previousblockhash: truthful conditional emit (see struct notes).
    if (in.previousblockhash)
        tmpl["previousblockhash"] = *in.previousblockhash;

    // bits: truthful conditional emit -- present only when the caller supplies
    // the authoritative external-daemon GBT value (see struct notes).
    if (in.bits)
        tmpl["bits"] = *in.bits;

    return tmpl;
}


} // namespace coin

} // namespace dgb