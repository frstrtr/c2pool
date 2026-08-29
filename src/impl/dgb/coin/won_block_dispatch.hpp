// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::make_on_block_found -- the won-block DISPATCH handler the run-loop
// installs as dgb::ShareTracker::m_on_block_found.
//
// This is the wiring half between the dispatcher (#166, broadcast_won_block)
// and the live run-loop: on a won block the tracker fires m_on_block_found with
// the winning share hash. This handler turns that share hash into a fully
// serialized parent block (via an injected WonBlockReconstructor -- the
// share->block "as_block" step) and then dispatches it down BOTH broadcast
// paths via broadcast_won_block (P2P primary + external digibyted submitblock
// fallback, always-fire dual-path rule).
//
// The reconstruct step is injected as a std::function rather than called inline
// so this handler is build-verifiable and run-tested NOW, before the faithful
// share->block reassembly (gentx_before_refhash + ref/merkle link + tx lookup,
// mirroring p2pool data.py Share.as_block) is ported. The run-loop binds the
// real reconstructor + the live P2P relay sink + the CoinNode seam when the
// embedded NodeP2P lands; until then a stub reconstructor + the external-RPC
// fallback already carry a won block onto the network.
//
// Contract:
//   * reconstruct(share_hash) -> nullopt  => UNKNOWN/unassemblable share: log a
//     warning and broadcast NOTHING (never fabricate or relay a partial block).
//   * reconstruct(share_hash) -> {bytes,hex} => fire broadcast_won_block, whose
//     own dual-path guards decide which sink(s) carry it.
//
// DGB-Scrypt is a STANDALONE parent in the V36 default build -- no merged-
// coinbase leg (DOGE aux is -DAUX_DOGE=ON stretch, a separate parent path).
// p2pool-merged-v36 surface: NONE -- block dispatch only; no PoW hash, share
// format, coinbase commitment, or PPLNS math is touched. Per-coin isolation:
// src/impl/dgb/coin/ only.
// ---------------------------------------------------------------------------

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/coin/node_iface.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include "block_broadcast.hpp"

namespace dgb
{
namespace coin
{

// Reconstructs the full serialized parent block for a won share.
//   share_hash -> {block_bytes, block_hex}, or nullopt if the share is unknown
//   or cannot be assembled (e.g. a referenced tx is missing).
// block_bytes is the pre-serialized blob the embedded P2P relay sends; block_hex
// is the same block for the external submitblock fallback. Mirrors p2pool
// data.py Share.as_block; the faithful body lands in a follow-up slice.
using WonBlockReconstructor =
    std::function<std::optional<std::pair<std::vector<unsigned char>, std::string>>(const uint256&)>;

// Optional post-broadcast telemetry hook (#995 DGB found-block arm). Fired AFTER
// a won block is reconstructed + dispatched down both broadcast arms, carrying
// the winning share hash, the serialized parent block, and its hex. main_dgb
// binds it to MiningInterface::record_found_block + schedule_block_verification
// so a pool-won DGB block lands on /recent_blocks and enters the confirm/orphan
// poller. Empty by default (dashboard off / --http absent): a won block still
// broadcasts, it is simply not recorded. TELEMETRY ONLY -- it runs strictly
// after both broadcast arms and never gates, delays, or alters a broadcast.
using FoundBlockReporter =
    std::function<void(const uint256& share_hash,
                       const std::vector<unsigned char>& block_bytes,
                       const std::string& block_hex)>;

// Build the m_on_block_found handler. The run-loop assigns the returned closure
// to tracker.m_on_block_found; `p2p_relay` may be empty (no embedded sink yet)
// and `seam` may be null / RPC-less -- broadcast_won_block guards each leg.
inline std::function<void(const uint256&)>
make_on_block_found(WonBlockReconstructor reconstruct,
                    P2pRelaySink p2p_relay,
                    core::coin::ICoinNode* seam,
                    FoundBlockReporter on_found = {})
{
    return [reconstruct = std::move(reconstruct),
            p2p_relay = std::move(p2p_relay),
            seam, on_found = std::move(on_found)](const uint256& share_hash)
    {
        if (!reconstruct) {
            LOG_ERROR << "[EMB-DGB] won-block " << share_hash.GetHex().substr(0, 16)
                      << " -- no reconstructor wired; cannot broadcast.";
            return;
        }

        auto blk = reconstruct(share_hash);
        if (!blk) {
            LOG_WARNING << "[EMB-DGB] won-block " << share_hash.GetHex().substr(0, 16)
                        << " could not be reconstructed -- NOT broadcast.";
            return;
        }

        LOG_INFO << "[EMB-DGB] GOT BLOCK! share=" << share_hash.GetHex().substr(0, 16)
                 << " reconstructed " << blk->first.size()
                 << " bytes -- dispatching dual-path.";
        broadcast_won_block(p2p_relay, seam, blk->first, blk->second);

        // #995 DGB found-block arm: surface the reconstructed win to the
        // dashboard + confirm/orphan verdict lane (record_found_block +
        // schedule_block_verification), strictly AFTER both broadcast arms.
        // Telemetry only -- an empty hook (no dashboard) changes nothing here.
        if (on_found) on_found(share_hash, blk->first, blk->second);
    };
}

} // namespace coin
} // namespace dgb