// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::make_reconstruct_closure -- the run-loop's faithful
// WonBlockReconstructor (#82): the closure main_dgb.cpp binds into
// make_on_block_found, replacing the interim `return nullopt` stub. It is the
// open half of DGB's #82 broadcaster dual-path -- until this is non-stub a
// pool-won DGB block is announced + audited but never reconstructed, so neither
// the P2P-relay arm (#260) nor the submitblock RPC fallback ever fires on a
// real won share.
//
// It composes the already-landed, individually-KAT'd slices into one faithful
// port of p2pool data.py Share.as_block(tracker, known_txs):
//   gentx     = unpack_gentx_coinbase(generate_share_transaction(share).bytes)
//   other_txs = [known_txs[h] for h in get_other_tx_hashes(tracker)]
//   block     = reconstruct_won_block(header, link, gentx, ..., refs, ...)
//
// SEAM-FIRST (mirrors every #82 sub-slice): the share lookup, the gentx
// regeneration, and the three tracker/mempool walks are INJECTED as callables,
// so the whole closure -- including its fail-closed posture -- is unit-testable
// against a synthetic share set with NO live ShareTracker / mempool. In the
// run-loop they bind to:
//   share_fields_fn  = chain.get_share(h) -> {m_min_header, m_merkle_link,
//                      m_tx_info.m_transaction_hash_refs}
//   gentx_bytes_fn   = generate_share_transaction(share, tracker, params,
//                      false, v36_active=false, &gc) -> gc.bytes   (#173 SSOT)
//   nth_parent_fn    = chain.get_nth_parent_via_skip(h, n)
//   new_tx_hashes_fn = chain.get_share(h)->m_tx_info.m_new_transaction_hashes
//   known_txs_fn     = mempool/known-tx find_tx(hash) -> *MutableTransaction
//
// FAIL-CLOSED (integrator 2026-06-19/20, REWARD-PATH CRITICAL): this callback
// fires from the compute thread on a won share. It NEVER throws out of the
// callback and NEVER emits a partial/wrong block: ANY missing share, missing
// known-tx, out-of-range ref-walk, or gentx-regen failure is caught, logged
// LOUDLY, and yields std::nullopt -- the share is announced + audited, the RPC
// submitblock fallback still attempts independently, and no malformed block
// reaches the network. A wrong reconstruction would hash to the wrong merkle
// root and be daemon-rejected anyway, so failing closed here is strictly safer
// than emitting it.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE --
// pure composition of already-validated share_info + already-relayed txs + the
// proven BlockType serializer. DGB-Scrypt is a STANDALONE parent in the V36
// default build (no merged-coinbase leg).
// ---------------------------------------------------------------------------

#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include "reconstruct_won_block.hpp"   // reconstruct_won_block, ReconstructedWonBlock, SmallBlockHeaderType, MutableTransaction
#include "gentx_unpack.hpp"            // unpack_gentx_coinbase, UnpackedGentx
#include "won_block_dispatch.hpp"      // WonBlockReconstructor
#include "won_share_inputs.hpp"        // WonShareInputs, won_share_inputs (#279)

namespace dgb
{
namespace coin
{

// The per-share inputs the closure pulls from the sharechain to drive
// reconstruct_won_block: everything that is NOT the gentx or the ancestry walk.
//   small_header : share.m_min_header  (version|prev|time|bits|nonce)
//   merkle_link  : share.m_merkle_link (gentx -> merkle root branch)
//   refs         : share.m_tx_info.m_transaction_hash_refs, in order
struct ShareReconstructFields
{
    SmallBlockHeaderType small_header;
    ::dgb::MerkleLink merkle_link;
    std::vector<TxHashRefs> refs;
};

// Build the run-loop WonBlockReconstructor. See header note for the run-loop
// bindings of each injected seam. The returned callable is fail-closed: it
// returns std::nullopt (never throws, never a partial block) on ANY error.
inline WonBlockReconstructor
make_reconstruct_closure(
    std::function<ShareReconstructFields(const uint256&)> share_fields_fn,
    std::function<std::vector<unsigned char>(const uint256&)> gentx_bytes_fn,
    std::function<uint256(const uint256&, uint64_t)> nth_parent_fn,
    std::function<const std::vector<uint256>&(const uint256&)> new_tx_hashes_fn,
    std::function<const MutableTransaction*(const uint256&)> known_txs_fn)
{
    return [share_fields_fn = std::move(share_fields_fn),
            gentx_bytes_fn = std::move(gentx_bytes_fn),
            nth_parent_fn = std::move(nth_parent_fn),
            new_tx_hashes_fn = std::move(new_tx_hashes_fn),
            known_txs_fn = std::move(known_txs_fn)](const uint256& share_hash)
        -> std::optional<std::pair<std::vector<unsigned char>, std::string>>
    {
        try
        {
            // 1. share-level fields (header / merkle_link / tx refs).
            const ShareReconstructFields f = share_fields_fn(share_hash);

            // 2. regenerate the share's SSOT gentx bytes, then unpack to the
            //    MutableTransaction (+ canonical txid) reconstruct injects at
            //    block tx index 0. unpack throws on a malformed serialization.
            const UnpackedGentx ug = unpack_gentx_coinbase(gentx_bytes_fn(share_hash));

            // 3. compose: resolve refs -> assemble other_txs -> frame the block.
            ReconstructedWonBlock r = reconstruct_won_block(
                f.small_header, f.merkle_link, ug.tx, ug.txid, share_hash, f.refs,
                nth_parent_fn, new_tx_hashes_fn, known_txs_fn);

            return std::make_pair(std::move(r.bytes), std::move(r.hex));
        }
        catch (const std::exception& e)
        {
            // Fail closed: announce + audit, never broadcast a partial/wrong
            // block. The RPC submitblock fallback still attempts independently.
            std::cout << "[DGB-POOL-BLOCK] won share " << share_hash.GetHex().substr(0, 16)
                      << " -- reconstruct FAILED CLOSED (" << e.what()
                      << "); NOT broadcast on P2P arm (RPC fallback still attempts)"
                      << std::endl;
            return std::nullopt;
        }
    };
}


// ---------------------------------------------------------------------------
// make_reconstruct_closure_from_template -- the version-AGNOSTIC #82 closure,
// and the one the run-loop should install. reconstruct_won_block_from_template
// (reconstruct_won_block.hpp) is the CORRECT won-block tx source per the
// work.py @42ccca53 audit: the broadcast block's non-coinbase set is the GBT
// TEMPLATE the miner was handed at job hand-out (current_work transactions[]),
// NOT the share's transaction_hash_refs. That dissolves the "v34+ carries no
// m_tx_info -> reconstruct fails" concern entirely -- the share never carried
// the block tx set for ANY version. This builder composes the three version-
// agnostic inputs into the run-loop WonBlockReconstructor:
//   won_share_fields_fn   = won_share_inputs(chain.get_share(h)) (#279) ->
//                           { small_header = share.m_min_header,
//                             merkle_link  = share.m_merkle_link }
//   gentx_bytes_fn        = generate_share_transaction(share,...).bytes (#173)
//                           -> unpack_gentx_coinbase -> { tx, txid }
//   template_other_txs_fn = the captured-GBT template's non-coinbase txs in
//                           template order (#271). Empty today (mempool tx-
//                           selection pending) => a valid coinbase-only block,
//                           correct-and-empty, NOT fail-closed. It fills with
//                           NO change to this seam as tx-selection lands.
//
// Same FAIL-CLOSED posture as make_reconstruct_closure: fires on the compute
// thread for a won share, NEVER throws and NEVER emits a partial/wrong block --
// any error is caught, logged LOUDLY, and yields std::nullopt (announce +
// audit; the RPC submitblock fallback still attempts independently).
//
// Prefer THIS over make_reconstruct_closure for the run-loop install: the
// ref-walk variant is a share-CHAIN peer-propagation mechanism, never the
// block-broadcast source. Per-coin isolation: src/impl/dgb/ only.
// p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------
inline WonBlockReconstructor
make_reconstruct_closure_from_template(
    std::function<WonShareInputs(const uint256&)> won_share_fields_fn,
    std::function<std::vector<unsigned char>(const uint256&)> gentx_bytes_fn,
    std::function<std::vector<MutableTransaction>(const uint256&)> template_other_txs_fn)
{
    return [won_share_fields_fn = std::move(won_share_fields_fn),
            gentx_bytes_fn = std::move(gentx_bytes_fn),
            template_other_txs_fn = std::move(template_other_txs_fn)](
               const uint256& share_hash)
        -> std::optional<std::pair<std::vector<unsigned char>, std::string>>
    {
        try
        {
            // 1. share-side inputs the won share carries verbatim (#279).
            const WonShareInputs si = won_share_fields_fn(share_hash);

            // 2. regenerate + unpack the share's SSOT gentx (block tx index 0).
            const UnpackedGentx ug = unpack_gentx_coinbase(gentx_bytes_fn(share_hash));

            // 3. the captured-GBT template's non-coinbase set (template order).
            const std::vector<MutableTransaction> other_txs =
                template_other_txs_fn(share_hash);

            // 4. frame [gentx] ++ template_other_txs via the assemble_won_block
            //    SSOT (version-agnostic; empty other_txs => coinbase-only).
            ReconstructedWonBlock r = reconstruct_won_block_from_template(
                si.small_header, si.merkle_link, ug.tx, ug.txid, other_txs);

            return std::make_pair(std::move(r.bytes), std::move(r.hex));
        }
        catch (const std::exception& e)
        {
            // Fail closed: announce + audit, never broadcast a partial/wrong
            // block. The RPC submitblock fallback still attempts independently.
            std::cout << "[DGB-POOL-BLOCK] won share " << share_hash.GetHex().substr(0, 16)
                      << " -- reconstruct (from-template) FAILED CLOSED (" << e.what()
                      << "); NOT broadcast on P2P arm (RPC fallback still attempts)"
                      << std::endl;
            return std::nullopt;
        }
    };
}

} // namespace coin
} // namespace dgb