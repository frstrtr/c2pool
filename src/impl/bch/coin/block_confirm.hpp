// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BCH found-block confirm/orphan resolver -- TELEMETRY ONLY (#995 BCH arm).
//
// Answers "did the block we CLAIMED at height h actually WIN height h on our
// own best chain?" from a caller-supplied winner_at(height) oracle (the
// embedded HeaderChain's best branch) plus the current tip height. It feeds the
// operator dashboard's found-block verifier (MiningInterface::set_block_verify_fn):
// a won block starts life "pending" and this resolver flips it to confirmed or
// orphaned. Without it a BCH won block stays "pending" forever and an orphan
// (the class that lost DASH block 2508008) is found by humans, not the board.
//
// STRICTLY DOWNSTREAM of block submission: it runs only after a block has been
// dispatched to the broadcaster, and NEVER gates broadcast, mint, target or
// payout. A wrong verdict here can only mislabel a dashboard row.
//
// BCH is a SHA256d standalone parent: the block id == SHA256d(80-byte header),
// so the pow_hash the miner found IS the block hash keyed here -- no segwit,
// no separate wtxid/block-hash split.
//
// This mirrors the DASH found-block lane's CONTRACT (dash::coin::block_confirm)
// but is an INDEPENDENT BCH-tree implementation -- per-coin isolation, no
// cross-coin code sharing.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>

#include <core/uint256.hpp>

namespace bch::coin::block_confirm {

// Confirmations required before a found block flips pending -> confirmed. 6 is
// the conventional "permanently accepted" depth; below it the block is in our
// best chain but not yet buried, so it stays pending and we keep polling.
inline constexpr uint32_t kDefaultConfirmDepth = 6;

// Resolve a found block's status against our own best chain.
//   winner_at(h) -> hash of the block our best chain holds at height h, or
//                   std::nullopt if we have not yet reached/indexed height h.
//   tip_height   -> current best-chain tip height.
//   hash         -> the found block's id (SHA256d header hash).
//   found_height -> the height the block was mined at (authoritative, from our
//                   own found-block record -- survives an orphan whose header
//                   peers never relayed to us).
//
// Returns, matching MiningInterface::block_verify_fn_t's contract
// (web_server.cpp verify_found_block: >0 confirmed / <0 orphaned / 0 pending):
//   > 0 : confirmed  (value = confirmations; only once >= kDefaultConfirmDepth)
//   < 0 : orphaned   (a DIFFERENT block won found_height on our best chain)
//     0 : pending    (height not yet reached, tip behind, or in-chain-but-shallow)
template <class WinnerAt>
inline int resolve_status(WinnerAt&& winner_at, uint32_t tip_height,
                          const uint256& hash, uint32_t found_height)
{
    std::optional<uint256> winner = winner_at(found_height);
    if (!winner)
        return 0;                        // height not yet indexed -> pending
    if (*winner != hash)
        return -1;                       // someone else won that height -> orphaned
    if (tip_height < found_height)
        return 0;                        // in chain but tip behind (reorg) -> pending
    uint32_t confs = tip_height - found_height + 1;
    if (confs >= kDefaultConfirmDepth)
        return static_cast<int>(confs);  // buried deep enough -> confirmed
    return 0;                            // in chain but shallow -> pending
}

} // namespace bch::coin::block_confirm
