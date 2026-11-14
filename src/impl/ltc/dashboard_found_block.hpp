// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// dashboard_found_block.hpp -- the LTC /recent_blocks row, built from the SAME
// facts on the node that found the block and on every node that learned it
// from the share chain.
//
// THE DEFECT (LTC 3211872 / share 84024db9..., 2026-11-12). One find, two rows:
//
//   finder (block-submitted callback, header only):
//     height 3211872 (header chain) ✓, miner "" (the node's own --address),
//     share 9497f877... (the sharechain BEST share at submit time: the
//     winner's PARENT), found_by "unknown" (the site never labelled itself).
//   peers (tracker m_on_block_found, the gossiped share):
//     height 27707625 (the share's ABSHEIGHT), miner
//     "085cdff070d752d9e137e82396e387ec1641fd75" (m_pubkey_hash.GetHex(): a
//     byte-reversed hash160, not an address), share 84024db9... ✓.
//
// The share carries every fact exactly. On a p2pool chain the share hash IS
// the block header hash; its payout script names the miner; its coinbase
// scriptSig starts with the block's BIP34 height (litecoind rejects a block
// without it, bad-cb-height); m_subsidy is the coinbase value it committed to.
// row_from_share reads them off the share; row_from_submit takes the same
// fields from the stratum submit that minted the share
// (core::FoundBlockSubmitContext), so the two rows agree by construction.
//
// Display only: nothing here reaches a submit, a target or a payout.

#include <core/address_utils.hpp>
#include <core/found_block_submit.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <impl/ltc/share_check.hpp>   // ltc::get_share_script

#include <cstdint>
#include <string>

namespace ltc::dashboard {

/// The found-block chain label of this lane. record_found_block dedups on
/// (block hash, chain), so both record sites must use exactly this string.
inline std::string chain_label(bool testnet) { return testnet ? "tLTC" : "LTC"; }

/// One dashboard row: the record_found_block fields that are block facts.
/// Network difficulty and pool hashrate are node readings taken at record time.
struct FoundBlockRow
{
    uint64_t    height{0};            ///< coin block height; 0 = unknown
    uint256     block_hash;
    uint64_t    timestamp{0};         ///< the block header's nTime
    std::string chain;
    std::string miner;                ///< the winning share's payout address
    std::string share_hash;           ///< "" = no share named
    double      share_difficulty{0.0};
    uint64_t    subsidy{0};           ///< coinbase value (subsidy + fees); 0 = unknown
};

/// The row of a verified share that met the block target. `share_hash` is the
/// tracker's key for the share and, on a p2pool chain, the block's hash.
template <class ShareT>
inline FoundBlockRow row_from_share(const uint256& share_hash, const ShareT& s, bool testnet)
{
    FoundBlockRow row;
    row.block_hash = share_hash;
    row.share_hash = share_hash.GetHex();
    row.timestamp  = static_cast<uint64_t>(s.m_min_header.m_timestamp);
    row.chain      = chain_label(testnet);
    // The coin block height, never the sharechain absheight.
    row.height     = core::bip34_height_from_script_sig(s.m_coinbase.m_data);
    // Rendered as an address, exactly as the stratum submit renders the
    // script it pays (core::make_found_block_submit_context).
    row.miner      = core::script_to_address(ltc::get_share_script(&s),
                                             /*is_litecoin=*/true, testnet);
    if (s.m_bits != 0)
        row.share_difficulty =
            chain::target_to_difficulty(chain::bits_to_target(s.m_bits));
    row.subsidy    = s.m_subsidy;
    return row;
}

/// The finder's row. `chain_height` is the header chain's (prev + 1; 0 when
/// unknown, the share's BIP34 height then stands). `ctx` is the stratum
/// submit's context; null for a submit without one (JSON-RPC submitblock), the
/// row then names no share and no miner -- the caller decides the fallback.
inline FoundBlockRow row_from_submit(const uint256& block_hash, uint32_t header_timestamp,
                                     uint64_t chain_height,
                                     const core::FoundBlockSubmitContext* ctx,
                                     bool testnet)
{
    FoundBlockRow row;
    row.block_hash = block_hash;
    row.timestamp  = header_timestamp;
    row.chain      = chain_label(testnet);
    row.height     = chain_height;
    if (ctx) {
        if (row.height == 0)
            row.height = ctx->height;
        row.miner            = ctx->miner;
        row.share_hash       = ctx->share_hash;
        row.share_difficulty = ctx->share_difficulty;
        row.subsidy          = ctx->subsidy;
    }
    return row;
}

} // namespace ltc::dashboard
