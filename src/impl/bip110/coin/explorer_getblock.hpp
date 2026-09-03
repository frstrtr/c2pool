// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// bip110::coin explorer getblock decision — SSOT for the read-only /api/explorer
// getblock body wired into main_bip110.cpp (set_explorer_getblock_fn).
//
// The bip110 node already downloads every full block over coin-p2p for its M3
// own-UTXO view and RETAINS the last EXPLORER_DEPTH (288) bodies in the
// UTXOViewDB it already owns (main_bip110.cpp full_block subscriber ->
// put_raw_block/prune_raw_blocks). This header carries the SERVE half:
//
//   explorer_getblock_body() = full-then-partial (DASH #1460/#99 shape):
//     * below the retention window (tip>depth && height<tip-depth) -> header
//       partial (body pruned / never stored),
//     * body not in the DB                                          -> header partial,
//     * body deserialize / decode failure                          -> header partial,
//     * retained body                                              -> FULL body
//       via block_to_explorer_json.
//
//   explorer_header_partial() = honest header truth (hash/height/version/prev/
//     merkleroot/time/bits/nonce/confirmations/nextblockhash/difficulty) + a
//     named "unavailable" map for the body-only fields. NEVER fabricates tx:[]
//     or sizes, and carries NO "error" key so the explorer still renders the row
//     (an "error" key makes explorer.py drop the getblock JSON).
//
// PURE, display-only — no node, no network, no consensus/reward/share/coinbase/
// gentx/wire path. Reads: header chain (via the IndexEntry + tip + next hash the
// caller resolves) and the retained raw block (via UTXOViewDB). Hoisted out of
// the main_bip110 closure verbatim so the bip110_explorer_getblock_kat can bind
// the EXACT shipped decision (not a re-derivation).
// ---------------------------------------------------------------------------

#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/block_json.hpp>   // ExplorerChainParams, block_to_explorer_json, detail::bits_to_hex_str
#include <impl/bip110/coin/header_chain.hpp> // IndexEntry, target_from_bits

#include <core/coin/utxo_view_db.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace bip110
{
namespace coin
{

// Honest header-only answer for a block whose body is not (or no longer) served.
// Mirrors the DASH header-partial (main_dash.cpp:4496-4563 / #1460).
inline nlohmann::json explorer_header_partial(
    const IndexEntry& e,
    uint32_t tip_height,
    const std::optional<uint256>& next_block_hash,
    const uint256& pow_limit)
{
    nlohmann::json r;
    r["hash"]              = e.block_hash.GetHex();
    r["height"]            = e.height;
    r["version"]           = static_cast<int64_t>(e.header.m_version);
    r["previousblockhash"] = e.header.m_previous_block.GetHex();
    r["merkleroot"]        = e.header.m_merkle_root.GetHex();
    r["time"]              = e.header.m_timestamp;
    r["bits"]              = detail::bits_to_hex_str(e.header.m_bits);
    r["nonce"]             = e.header.m_nonce;
    r["confirmations"]     = static_cast<int64_t>(tip_height) - static_cast<int64_t>(e.height) + 1;
    if (next_block_hash)
        r["nextblockhash"] = next_block_hash->GetHex();
    auto target = target_from_bits(e.header.m_bits);
    if (!target.IsNull())
        r["difficulty"] = pow_limit.getdouble() / target.getdouble();
    const char* why = "requires the block body; this SPV node retains headers only "
                      "(bodies kept for the last 288 blocks once received)";
    nlohmann::json unavailable = nlohmann::json::object();
    for (const char* f : {"tx", "nTx", "size", "strippedsize", "weight"})
        unavailable[f] = why;
    r["unavailable"] = unavailable;
    r["partial"] = true;
    return r;
}

// Full-then-partial getblock body. The caller resolves `entry`, `tip_height` and
// `next_block_hash` from the HeaderChain and passes the already-owned UTXOViewDB;
// this function makes the retention-window decision and decodes the retained body.
inline nlohmann::json explorer_getblock_body(
    const IndexEntry& entry,
    const uint256& blk_hash,
    uint32_t tip_height,
    const std::optional<uint256>& next_block_hash,
    const uint256& pow_limit,
    core::coin::UTXOViewDB& udb,
    uint32_t explorer_depth,
    const ExplorerChainParams& params)
{
    auto partial = [&]() {
        return explorer_header_partial(entry, tip_height, next_block_hash, pow_limit);
    };

    uint32_t height = entry.height;
    // Below the retention window -> body pruned (or never stored). Honest header.
    if (tip_height > explorer_depth && height < tip_height - explorer_depth)
        return partial();
    auto raw = udb.get_raw_block(height);
    if (!raw)
        return partial();
    BlockType block;
    try {
        PackStream ps(*raw);
        ps >> block;
    } catch (...) {
        return partial();
    }
    try {
        return block_to_explorer_json(block, height, blk_hash, params);
    } catch (const std::exception&) {
        return partial();
    } catch (...) {
        return partial();
    }
}

} // namespace coin
} // namespace bip110
