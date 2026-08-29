// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// DASH embedded live-feed bridge (E2a, #738).
//
// E1 (p2p_client.hpp) landed a coin-network P2P client that dials a dashd peer
// and FIRES the RAW dash::interfaces::Node events off the wire:
//   new_block(hash)  new_tx(Transaction)  full_block(BlockType)
//   new_headers(vector<BlockHeaderType>)  new_chainlock({hash,height})
// but with NO subscribers those events are no-ops and NodeCoinState never
// populates. The four ingest legs (mempool_ingest / tip_ingest /
// block_connect_ingest / mn_list_ingest) subscribe DERIVED events the raw wire
// does not fire directly:
//   * tip_ingest        <- Node::new_tip        (TipAdvance: height/hash/bits/mtp/addr)
//   * block_connect_ingest <- Node::block_connected (BlockConnected: block + height)
//   * mn_list_ingest    <- Node::mn_list_update  (MnListUpdate: full DMN set)
//   * mempool_ingest    <- Node::new_tx          (direct — already matches)
//
// This bridge is the E2a translation layer that turns the raw wire events into
// the derived ingest events, using a HeaderChain as the tip/height authority:
//
//   new_headers ──> HeaderChain::add_headers ──(tip advances)──> Node::new_tip
//   full_block  ──(X11 hash -> HeaderChain height)──────────────> Node::block_connected
//   new_block(hash inv) ──> request the full block from the peer (getdata)
//
// The tip-advance params (bits-for-next via DarkGravityWave, median-time-past,
// coin address versions) are exactly build_embedded_workdata()'s inputs — they
// come off the HeaderChain, NOT a dashd poll, keeping the embedded arm
// daemonless.
//
// FENCED: src/impl/dash/coin only, dash interface only. Header-only, pulls the
// full dash codec (block/transaction/header_chain), so include ONLY from a TU
// that already links the dash codec (main_dash + this bridge's KAT), never a
// guard-weight TU — identical contract to the ingest legs.
// ===========================================================================
#include <memory>
#include <vector>

#include <core/events.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>

#include "node_interface.hpp"   // dash::interfaces::Node + TipAdvance/BlockConnected
#include "block.hpp"            // BlockType / BlockHeaderType
#include "header_chain.hpp"     // HeaderChain, x11_hash, IndexEntry
#include "block_producer.hpp"   // dash::coin::block_body_binds_to_header (E2 finding A)

#include <impl/dash/crypto/hash_x11.hpp>

namespace dash {
namespace coin {

// Build the TipAdvance the embedded template consumes from a HeaderChain's
// current tip: prev_height/hash = the tip to build ON, bits_for_next =
// DarkGravityWave next-work over the tip window, mtp_at_tip = median-time-past
// (BIP113), plus the coin address versions for coinbase-payee encoding. Returns
// nullopt when the chain has no usable tip / cannot retarget yet (caller keeps
// the dashd fallback).
inline std::optional<::dash::interfaces::TipAdvance>
tip_advance_from_chain(const HeaderChain& chain,
                       uint8_t address_version,
                       uint8_t address_p2sh_version)
{
    auto tip = chain.tip();
    if (!tip) return std::nullopt;
    uint32_t bits_for_next = chain.next_work_required();
    if (bits_for_next == 0) return std::nullopt;   // not enough headers to retarget
    ::dash::interfaces::TipAdvance t;
    t.prev_height          = tip->height;
    t.prev_hash            = tip->hash;
    t.bits_for_next        = bits_for_next;
    t.mtp_at_tip           = chain.median_time_past();
    t.address_version      = address_version;
    t.address_p2sh_version = address_p2sh_version;
    // curtime/version left 0 => build_embedded_workdata()'s SAFE-ADDITIVE defaults.
    return t;
}

// Subscribe the HeaderChain to Node::new_headers: every batch of headers off
// the wire is fed to add_headers (X11 PoW + DarkGravityWave validated). Returns
// the subscription handle so the caller controls teardown. The tip-advance
// republish is driven by HeaderChain::set_on_tip_changed (wired by the caller,
// so it can also fold the #739 idle-notify) — NOT here, so a batch that does
// not move the tip costs nothing downstream.
inline std::shared_ptr<EventDisposable>
wire_header_ingest(::dash::interfaces::Node& node, HeaderChain& chain)
{
    return node.new_headers.subscribe(
        [&chain](const std::vector<BlockHeaderType>& headers)
        {
            if (headers.empty()) return;
            chain.add_headers(headers);
        });
}

// Subscribe Node::full_block -> derive height off the HeaderChain -> fire
// Node::block_connected({block, height}). block_connected then drives BOTH the
// maintainer's incremental MnStateMachine::apply_block (leg 3) AND the E2b UTXO
// lane connect_block, from a single fired event. A block whose header is not yet
// in the chain (raced ahead of headers sync) is skipped — apply_block/UTXO need
// the chain-position height, and a subsequent headers batch + re-request closes
// the gap. Returns the subscription handle.
inline std::shared_ptr<EventDisposable>
wire_full_block_ingest(::dash::interfaces::Node& node, HeaderChain& chain)
{
    return node.full_block.subscribe(
        [&node, &chain](const BlockType& block)
        {
            auto packed_hdr = ::pack(
                static_cast<const BlockHeaderType&>(block));
            const uint256 hash =
                ::dash::crypto::hash_x11(packed_hdr.get_span());
            auto entry = chain.get_header(hash);
            if (!entry) {
                LOG_DEBUG_COIND << "[EMB-DASH] full_block " << hash.GetHex().substr(0, 16)
                                << " not in header chain yet — deferring connect";
                return;
            }
            // E2 finding A (reward-critical): the header is PoW/DGW-validated, but
            // the BODY arrives cryptographically UNBOUND. Bind it before firing
            // block_connected — the merkle root over the tx set must match the
            // header's committed root — so a forged body (e.g. a fake type-5
            // coinbase with the right nHeight but a wrong creditPoolBalance) can
            // never reach the credit-pool bootstrap / apply_block / UTXO legs.
            // Fail closed: skip the connect (the real body re-request closes it).
            if (!dash::coin::block_body_binds_to_header(block)) {
                LOG_WARNING << "[EMB-DASH] full_block " << hash.GetHex().substr(0, 16)
                            << " body merkle root != header commitment (forged/mutated"
                               " body) — REFUSING connect (fail closed to dashd fallback)";
                return;
            }
            node.block_connected.happened(
                ::dash::interfaces::BlockConnected{block, entry->height});
        });
}

} // namespace coin
} // namespace dash
