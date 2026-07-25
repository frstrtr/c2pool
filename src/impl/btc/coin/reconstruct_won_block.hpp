// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::coin::reconstruct_won_block / make_reconstruct_closure -- the won-block
// reconstructor's (#744 dispatch arc, slice 5/7) BODY + run-loop closure: the
// single composition the dispatch handler (won_block_dispatch.hpp,
// make_on_block_found) injects as its WonBlockReconstructor. It ties the landed
// sub-slices into one C++ implementation of the p2pool data.py
// Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)          # the coinbase tx
//     other_txs = [known_txs[h] for h in transaction_hashes]
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// Composition (each step is its own KAT'd SSOT slice):
//   1. select_won_block_merkle_link  (this file)
//        share_version + merkle_link + optional txid_merkle_link --segwit gate-->
//        the merkle link the framer must walk gentx_hash up to reproduce the
//        share-committed header root (share_check.hpp:674-692). SEGWIT LINK
//        SELECTION LIVES HERE (the caller), not in the framer -- block_assembly.hpp
//        takes an already-resolved MerkleLink so the sealed link math is reused
//        with NO new merkle path introduced downstream.
//   2. unpack_gentx_coinbase         (gentx_unpack.hpp, slice 1 / #822)
//        the share's SSOT non-witness gentx bytes --> {MutableTransaction, txid}
//        injected at block tx index 0.
//   3. assemble_won_block            (block_assembly.hpp, as_block FRAMING / #838)
//        small_header + gentx + resolved merkle_link + other_txs --> {bytes, hex}
//        (merkle_root recomputed from gentx_hash up the link; txs = [gentx] ++
//         other_txs; body/header consistency guard fails closed; BlockType codec
//         is the live submitblock path).
//
// ---- BTC won-block tx source: the CAPTURED GBT TEMPLATE, not tx_hash_refs ----
// The broadcast block's non-coinbase tx set is the GBT template snapshot the
// miner was handed at job hand-out time (template_capture.hpp, slice 3), NOT the
// share's transaction_hash_refs. The ref-walk (DGB other_tx_resolver) is a
// share-CHAIN peer-propagation mechanism; it is never the block-broadcast
// source. That is why this path is version-AGNOSTIC: pre-v34 vs v34+/v36 makes
// no difference, because the share never carried the block tx set in the first
// place. The template txs are INJECTED as a callable (template_other_txs_fn), so
// this whole reconstruction is unit-testable against a synthetic template set
// with NO live TemplateCapture / mempool. On a capture MISS slice 3 replays an
// EMPTY transactions[] -> other_txs = {} -> a valid coinbase-only block (the
// full subsidy), which the body/header guard accepts iff the won share committed
// to an empty merkle link (see block_assembly.hpp's template_capture note).
//
// FAIL-CLOSED (integrator 2026-06-19/20, REWARD-PATH CRITICAL): make_on_block_found
// fires this callback from the compute thread on a won share. It NEVER throws out
// of the callback and NEVER emits a partial/wrong block: ANY missing share,
// gentx-unpack failure, or body/header merkle mismatch is caught, logged LOUDLY,
// and yields std::nullopt -- the share is announced + audited, the submitblock
// RPC fallback still attempts independently (block_broadcast.hpp), and no
// malformed block reaches the network. A wrong reconstruction would hash to the
// wrong merkle root and be daemon-rejected anyway, so failing closed here is
// strictly safer than emitting it.
//
// SEAM-FIRST (mirrors every #744 sub-slice): the share-field lookup, the gentx
// regeneration, and the template-tx snapshot are INJECTED as callables, so the
// whole closure -- including its fail-closed posture -- is unit-testable against
// a synthetic share set with NO live ShareTracker / TemplateCapture. In the
// run-loop (main_btc, slice 7) they bind to:
//   share_fields_fn        = chain.get_share(h) -> { m_min_header, VERSION,
//                            m_merkle_link, m_segwit_data->m_txid_merkle_link }
//   gentx_bytes_fn         = generate_share_transaction(share, ...).bytes (SSOT)
//                            -> unpack_gentx_coinbase -> { tx, txid }
//   template_other_txs_fn  = TemplateCapture replay for the won share's job
//                            (slice 3), in template order
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE --
// pure composition of already-validated share_info + the captured template + the
// proven BlockType serializer; no share format, PoW, coinbase commitment, or
// PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <exception>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include "block_assembly.hpp"      // assemble_won_block, SmallBlockHeaderType, MutableTransaction
#include "gentx_unpack.hpp"        // unpack_gentx_coinbase, UnpackedGentx
#include "won_block_dispatch.hpp"  // WonBlockReconstructor
#include "../share_types.hpp"      // btc::MerkleLink, btc::is_segwit_activated

namespace btc
{
namespace coin
{

// The reconstructed parent block, ready for broadcast_block_for_connect's dual
// path:
//   bytes : the pre-serialized blob the embedded P2P relay sends
//   hex   : the same block for the external submitblock (RPC) fallback
struct ReconstructedWonBlock
{
    std::vector<unsigned char> bytes;
    std::string hex;
};

// The per-share inputs the closure resolves before framing -- everything that is
// NOT the gentx or the template tx set.
//   small_header      : share.m_min_header  (version|prev|time|bits|nonce)
//   share_version     : the share format VERSION (segwit-activation gate input)
//   merkle_link       : share.m_merkle_link  (legacy gentx->root branch)
//   txid_merkle_link  : share.m_segwit_data->m_txid_merkle_link if the share
//                       carried segwit_data, else std::nullopt
struct WonShareReconstructFields
{
    SmallBlockHeaderType small_header;
    uint64_t share_version{0};
    ::btc::MerkleLink merkle_link;
    std::optional<::btc::MerkleLink> txid_merkle_link;
};

// Segwit merkle-link SELECTION SSOT -- mirrors share_check.hpp:674-692 verbatim
// at runtime. A segwit-activated share that carried segwit_data committed its
// header merkle_root over segwit_data.txid_merkle_link; a legacy share (or a
// segwit-active share with no segwit_data sentinel) committed over merkle_link.
// The framer must walk gentx_hash up the SAME link the share committed to, or
// the reconstructed header hashes to a different root than the share's PoW-valid
// header and the daemon rejects the block. Returns a reference into one of the
// two arguments (no copy).
inline const ::btc::MerkleLink&
select_won_block_merkle_link(uint64_t share_version,
                             const ::btc::MerkleLink& merkle_link,
                             const std::optional<::btc::MerkleLink>& txid_merkle_link)
{
    if (::btc::is_segwit_activated(share_version) && txid_merkle_link.has_value())
        return txid_merkle_link.value();
    return merkle_link;
}

// Reconstruct the full serialized parent block for a won share.
//   small_header       : share.m_min_header (version|prev|time|bits|nonce)
//   share_version      : the share format VERSION (segwit-activation gate)
//   merkle_link        : share.m_merkle_link (legacy path)
//   txid_merkle_link   : share.m_segwit_data->m_txid_merkle_link, or nullopt
//   gentx              : the share's ALREADY witness-committed coinbase (tx 0)
//   gentx_hash         : its txid (double-SHA256 of the non-witness bytes)
//   template_other_txs : the captured template's non-coinbase txs, template order
// Returns {bytes, hex} with hex == HexStr(bytes). Throws (via assemble_won_block)
// if the assembled body's merkle root does not match the share-committed header
// root -- fail-closed against a bad-txnmrklroot block.
inline ReconstructedWonBlock
reconstruct_won_block(const SmallBlockHeaderType& small_header,
                      uint64_t share_version,
                      const ::btc::MerkleLink& merkle_link,
                      const std::optional<::btc::MerkleLink>& txid_merkle_link,
                      const MutableTransaction& gentx,
                      const uint256& gentx_hash,
                      const std::vector<MutableTransaction>& template_other_txs)
{
    // 1. segwit-resolve the link the share committed its header root to.
    const ::btc::MerkleLink& link =
        select_won_block_merkle_link(share_version, merkle_link, txid_merkle_link);

    // 2. frame [gentx] ++ template_other_txs via the assemble_won_block SSOT
    //    (recompute header root up `link`; body/header guard; BlockType codec).
    auto framed = assemble_won_block(small_header, gentx, gentx_hash, link,
                                     template_other_txs);
    return ReconstructedWonBlock{std::move(framed.first), std::move(framed.second)};
}

// Build the run-loop WonBlockReconstructor the dispatch handler
// (make_on_block_found) installs. See the header note for the run-loop bindings
// of each injected seam. The returned callable is FAIL-CLOSED: it returns
// std::nullopt (never throws, never a partial block) on ANY error -- an unknown
// share, a malformed gentx serialization, or a body/header merkle mismatch.
inline WonBlockReconstructor
make_reconstruct_closure(
    std::function<WonShareReconstructFields(const uint256&)> share_fields_fn,
    std::function<std::vector<unsigned char>(const uint256&)> gentx_bytes_fn,
    std::function<std::vector<MutableTransaction>(const uint256&)> template_other_txs_fn)
{
    return [share_fields_fn = std::move(share_fields_fn),
            gentx_bytes_fn = std::move(gentx_bytes_fn),
            template_other_txs_fn = std::move(template_other_txs_fn)](
               const uint256& share_hash)
        -> std::optional<std::pair<std::vector<unsigned char>, std::string>>
    {
        try
        {
            // 1. share-level fields (header / version / merkle links).
            const WonShareReconstructFields f = share_fields_fn(share_hash);

            // 2. regenerate + unpack the share's SSOT gentx (block tx index 0);
            //    unpack throws on a malformed (trailing-byte) serialization.
            const UnpackedGentx ug = unpack_gentx_coinbase(gentx_bytes_fn(share_hash));

            // 3. the captured-GBT template's non-coinbase set (template order;
            //    empty on a capture miss => a valid coinbase-only block).
            const std::vector<MutableTransaction> other_txs =
                template_other_txs_fn(share_hash);

            // 4. select segwit link + frame the block (guard fails closed).
            ReconstructedWonBlock r = reconstruct_won_block(
                f.small_header, f.share_version, f.merkle_link, f.txid_merkle_link,
                ug.tx, ug.txid, other_txs);

            return std::make_pair(std::move(r.bytes), std::move(r.hex));
        }
        catch (const std::exception& e)
        {
            // Fail closed: announce + audit, never broadcast a partial/wrong
            // block. The submitblock RPC fallback still attempts independently.
            LOG_WARNING << "[EMB-BTC] won share " << share_hash.GetHex().substr(0, 16)
                        << " -- reconstruct FAILED CLOSED (" << e.what()
                        << "); NOT broadcast on P2P arm (submitblock RPC fallback still attempts).";
            return std::nullopt;
        }
    };
}

} // namespace coin
} // namespace btc
