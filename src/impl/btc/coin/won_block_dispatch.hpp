// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::coin::make_on_block_found -- the won-block DISPATCH handler the run-loop
// installs as btc::ShareTracker::m_on_block_found (gate #744).
//
// BTC exposes ShareTracker::m_on_block_found and fires it (share_tracker.hpp
// L385 scan path, L540 live-verify path) the moment a verified sharechain share
// crosses the BTC network target -- i.e. a block was WON by ANY peer's share,
// not just a local stratum submit. But main_btc.cpp never ASSIGNED that member,
// so a peer-relayed won share was detected and then SILENTLY DROPPED: the full
// subsidy lost. (The stratum submit path already dual-broadcasts via
// coin_node.submit_block_for_connect; this closes the OTHER seam -- the
// sharechain-detected won block.)
//
// This handler turns the winning share hash into a fully serialized parent
// block (via an injected WonBlockReconstructor -- the share->block "as_block"
// step) and dispatches it down the CONNECT-AUTHORITATIVE dual-path via
// broadcast_block_for_connect (P2P relay best-effort + submitblock RPC ALWAYS,
// because a cmpctblock announce alone does not ConnectBlock the tip -- the same
// policy the stratum won-block path already uses, block_broadcast.hpp).
//
// The reconstruct step is injected as a std::function rather than called inline
// so this handler is build-verifiable and run-tested NOW, before the faithful
// share->block reassembly (gentx + ref/merkle link + other-tx lookup, mirroring
// p2pool data.py Share.as_block, DGB #174/#176) is ported for BTC. The run-loop
// binds the real reconstructor + the live P2P relay sink + the submitblock RPC
// when they land; until then an injected reconstructor already carries a won
// block onto the network. Per-coin isolation: src/impl/btc/coin/ only.
//
// Contract:
//   * reconstruct(share_hash) -> nullopt  => UNKNOWN/unassemblable share: log a
//     warning and broadcast NOTHING (never fabricate or relay a partial block).
//   * reconstruct(share_hash) -> {bytes,hex} => fire broadcast_block_for_connect,
//     whose own dual-path guards decide which sink(s) carry it; a both-legs-fail
//     return is logged as a LOST SUBSIDY (never a silent success).
// ---------------------------------------------------------------------------

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include "block_broadcast.hpp"   // btc::coin::broadcast_block_for_connect

namespace btc
{
namespace coin
{

// Reconstructs the full serialized parent block for a won share.
//   share_hash -> {block_bytes, block_hex}, or nullopt if the share is unknown
//   or cannot be assembled (e.g. a referenced tx is missing). block_bytes is the
//   pre-serialized blob the P2P relay sends; block_hex is the same block for the
//   submitblock RPC. Mirrors p2pool data.py Share.as_block; the faithful body
//   lands in a follow-up slice.
using WonBlockReconstructor =
    std::function<std::optional<std::pair<std::vector<unsigned char>, std::string>>(const uint256&)>;

// Embedded P2P relay sink: sends the pre-serialized block bytes. Returns true
// iff the relay accepted/sent. May be empty (no embedded sink wired yet).
using P2pRelaySink = std::function<bool(const std::vector<unsigned char>&)>;

// submitblock RPC sink: connect-authoritative full-block submission. Returns
// true iff the daemon accepted. May be empty (RPC-less).
using SubmitRpcSink = std::function<bool(const std::string&)>;

// Build the m_on_block_found handler. The run-loop assigns the returned closure
// to tracker.m_on_block_found; `relay_p2p` may be empty (no embedded sink yet)
// and `submit_rpc` may be empty -- broadcast_block_for_connect guards each leg.
inline std::function<void(const uint256&)>
make_on_block_found(WonBlockReconstructor reconstruct,
                    P2pRelaySink relay_p2p,
                    SubmitRpcSink submit_rpc)
{
    return [reconstruct = std::move(reconstruct),
            relay_p2p   = std::move(relay_p2p),
            submit_rpc  = std::move(submit_rpc)](const uint256& share_hash)
    {
        if (!reconstruct) {
            LOG_ERROR << "[EMB-BTC] won-block " << share_hash.GetHex().substr(0, 16)
                      << " -- no reconstructor wired; cannot broadcast.";
            return;
        }

        auto blk = reconstruct(share_hash);
        if (!blk) {
            LOG_WARNING << "[EMB-BTC] won-block " << share_hash.GetHex().substr(0, 16)
                        << " could not be reconstructed -- NOT broadcast.";
            return;
        }

        LOG_INFO << "[EMB-BTC] GOT BLOCK! share=" << share_hash.GetHex().substr(0, 16)
                 << " reconstructed " << blk->first.size()
                 << " bytes -- dispatching connect-authoritative dual-path.";

        const std::vector<unsigned char>& bytes = blk->first;
        const std::string&                hex   = blk->second;
        bool reached = broadcast_block_for_connect(
            [&]() -> bool { return relay_p2p ? relay_p2p(bytes) : false; },
            [&]() -> bool { return submit_rpc ? submit_rpc(hex)  : false; });

        if (!reached) {
            LOG_ERROR << "[EMB-BTC] won-block " << share_hash.GetHex().substr(0, 16)
                      << " reached NEITHER sink -- SUBSIDY LOST.";
        }
    };
}

} // namespace coin
} // namespace btc
