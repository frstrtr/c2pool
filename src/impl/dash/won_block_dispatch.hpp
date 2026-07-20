// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::make_on_block_found -- the won-block DISPATCH handler the run-loop
// installs as dash::ShareTracker::m_on_block_found (share_tracker.hpp:368).
//
// Phase S8. This is the wiring half between the tracker seam and the keystone.
// On a won X11 block the tracker fires m_on_block_found with the winning share
// hash. This handler turns that share hash into a fully serialized parent block
// (via an injected WonBlockReconstructor -- the share->block "as_block" step)
// and hands the bytes to DashBroadcasterFull::on_block_found, which already
// drives BOTH arms with its own guards:
//     ARM A: embedded-P2P fan-out to every live slot (daemonless path).
//     ARM B: dashd submitblock RPC fallback (authoritative; opt-in, never
//            removed).
// A won block therefore reaches the network with NO local dashd whenever the
// embedded peer-pool is live, while the RPC fallback still carries it when it
// is wired -- the operator-gated dual-path rule.
//
// The reconstruct step is injected as a std::function (not called inline) so
// this handler is build-verifiable and unit-testable NOW, before the faithful
// share->block reassembly (gentx + ref/merkle link + tx lookup, mirroring
// p2pool data.py Share.as_block) is ported in a follow-up slice. main_dash
// binds the real reconstructor + the live DashBroadcasterFull when the embedded
// NodeP2P + NodeRPC arms are stood up; until then a stub reconstructor + the
// external-RPC fallback already carry a won block onto the network. Mirrors
// dgb::coin::make_on_block_found.
//
// Contract:
//   * reconstruct(share_hash) -> nullopt  => UNKNOWN/unassemblable share: log a
//     warning and broadcast NOTHING (never fabricate or relay a partial block).
//   * reconstruct(share_hash) -> {bytes,hex} => call broadcaster.on_block_found
//     with the bytes; its dual-arm guards decide which sink(s) carry it.
//
// SCOPE / NON-CONSENSUS: single dash tree, header-only. The block bytes are an
// OPAQUE, caller-supplied blob (the won block as packed by submit_validator) --
// carried verbatim, NOT re-serialized, no PoW/coinbase/PPLNS value touched.
// Per-coin isolation: src/impl/dash/ only.
// ---------------------------------------------------------------------------

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include "broadcaster_full.hpp"

namespace dash
{

// Reconstructs the full serialized parent block for a won share.
//   share_hash -> {block_bytes, block_hex}, or nullopt if the share is unknown
//   or cannot be assembled (e.g. a referenced tx is missing).
// block_bytes is the pre-serialized blob both arms consume (the keystone hexes
// it for the submitblock fallback). Mirrors p2pool data.py Share.as_block; the
// faithful body lands in a follow-up slice.
using WonBlockReconstructor =
    std::function<std::optional<std::pair<std::vector<unsigned char>, std::string>>(
        const uint256&)>;

// Build the m_on_block_found handler. The run-loop assigns the returned closure
// to tracker.m_on_block_found. `broadcaster` MUST outlive the returned closure
// (main_dash owns it for the run-loop lifetime); its arms may be individually
// unarmed (no live peers / no RPC) -- on_block_found guards each leg and reports
// via reached_network().
inline std::function<void(const uint256&)>
make_on_block_found(WonBlockReconstructor reconstruct,
                    DashBroadcasterFull& broadcaster)
{
    return [reconstruct = std::move(reconstruct), &broadcaster](
               const uint256& share_hash)
    {
        const std::string tag = share_hash.GetHex().substr(0, 16);

        if (!reconstruct) {
            LOG_ERROR << "[EMB-DASH] won-block " << tag
                      << " -- no reconstructor wired; cannot broadcast.";
            return;
        }

        auto blk = reconstruct(share_hash);
        if (!blk) {
            LOG_WARNING << "[EMB-DASH] won-block " << tag
                        << " could not be reconstructed -- NOT broadcast.";
            return;
        }

        LOG_INFO << "[EMB-DASH] GOT BLOCK! share=" << tag << " reconstructed "
                 << blk->first.size() << " bytes -- dispatching dual-arm.";

        auto out = broadcaster.on_block_found(blk->first);
        if (!out.reached_network())
            LOG_WARNING << "[EMB-DASH] won-block " << tag
                        << " reached NO arm (no live peers, no RPC ack).";
    };
}

} // namespace dash
