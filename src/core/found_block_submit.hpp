// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// found_block_submit.hpp -- what the stratum submit knows about a parent-chain
// block this node just found, handed to the coin lane's found-block recorder.
//
// THE DEFECT (LTC 3211872 / DOGE 6454700, 2026-11-12). One find, two stories:
// the FINDER recorded its LTC row from the block-submitted callback, which
// sees only the 80-byte header. It filled what it could not see from live
// node state -- miner = the node's own --address (empty on that node, so ""),
// share = the sharechain BEST share at that instant (the PARENT of the winning
// share: the new share is not the best yet), found_by left unlabelled -- while
// every PEER read the same facts off the gossiped share. On a p2pool chain the
// winning share's hash IS the block header hash, its payout script names the
// miner, and its coinbase scriptSig carries the block's BIP34 height, so the
// stratum submit that minted the share knows every one of these exactly. It
// hands them over here, for the duration of the submit only.
//
// Plain data and pure helpers. Nothing here reaches a submit, a target or a
// payout: display only.

#include <core/address_utils.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace core {

struct FoundBlockSubmitContext
{
    /// The winning share's payout script, rendered as an address for the coin.
    /// That is the finder every peer reads off the gossiped share (after any
    /// node-fee draw: the share pays whom its script names).
    std::string miner;
    /// The share the submit minted. On a p2pool chain this is the block hash
    /// itself. "" when no share was minted (it stays JSON null).
    std::string share_hash;
    /// BIP34 height from the share's coinbase scriptSig; 0 = unknown.
    uint64_t    height{0};
    /// The coinbase value the share committed to (subsidy + fees); 0 = unknown.
    uint64_t    subsidy{0};
    /// The share target's difficulty; 0 = unknown.
    double      share_difficulty{0.0};
};

/// The block height a coinbase scriptSig pushes first (BIP34: a minimal
/// CScriptNum, or OP_1..OP_16 for heights 1..16). 0 when the script does not
/// start with a height push -- never a guessed value.
inline uint64_t bip34_height_from_script_sig(const unsigned char* data, size_t len)
{
    if (data == nullptr || len == 0)
        return 0;
    const unsigned char op = data[0];
    if (op >= 0x51 && op <= 0x60)
        return static_cast<uint64_t>(op - 0x50);
    if (op < 1 || op > 8 || len < static_cast<size_t>(op) + 1)
        return 0;
    // CScriptNum is sign-magnitude: the top bit of the last byte is the sign.
    if (data[op] & 0x80)
        return 0;
    uint64_t h = 0;
    for (size_t i = 0; i < op; ++i)
        h |= static_cast<uint64_t>(data[1 + i]) << (8 * i);
    return h;
}

inline uint64_t bip34_height_from_script_sig(const std::vector<unsigned char>& script_sig)
{
    return bip34_height_from_script_sig(script_sig.data(), script_sig.size());
}

/// Compose the context from the share the submit minted. `payout_script` is
/// the script the share pays (empty: unknown, `fallback_miner` is used);
/// `created_share` null = no share minted; `share_bits` 0 = unknown.
inline FoundBlockSubmitContext make_found_block_submit_context(
    const std::vector<unsigned char>& payout_script,
    bool is_litecoin, bool testnet,
    const std::string& fallback_miner,
    const uint256& created_share,
    const std::vector<unsigned char>& coinbase_script_sig,
    uint64_t subsidy,
    uint32_t share_bits)
{
    FoundBlockSubmitContext ctx;
    if (!payout_script.empty())
        ctx.miner = core::script_to_address(payout_script, is_litecoin, testnet);
    if (ctx.miner.empty())
        ctx.miner = fallback_miner;
    if (!created_share.IsNull())
        ctx.share_hash = created_share.GetHex();
    ctx.height  = bip34_height_from_script_sig(coinbase_script_sig);
    ctx.subsidy = subsidy;
    if (share_bits != 0)
        ctx.share_difficulty = chain::target_to_difficulty(chain::bits_to_target(share_bits));
    return ctx;
}

} // namespace core
