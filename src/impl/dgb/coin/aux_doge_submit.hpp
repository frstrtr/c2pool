#pragma once
// ---------------------------------------------------------------------------
// dgb::coin -- DOGE-aux won-block SUBMIT half (phase DC, -DAUX_DOGE=ON only).
//
// SEAM RULING (integrator UID:3130, 2026-06-28): option (b). A DGB-parent share
// that also clears the DOGE-aux target wins a DOGE block; that DOGE block is
// SUBMITTED FROM DGBS OWN dispatch -- the same ownership boundary as the parent
// won-block handler (won_block_dispatch.hpp / m_on_block_found, #82). The shared
// src/impl/doge/coin/ aux module is consumed READ-SIDE ONLY: DGB builds the
// AuxPoW proof via the parent-neutral producer c2pool::merged::build_auxpow_proof
// and NEVER writes into doges submit path. (b) requires nothing from ltc-doge:
// DGB never reaches into doges submit code, which respects -- not violates --
// their ownership of that module.
//
// ASYMMETRY vs the parent dispatcher (block_broadcast.hpp). The parent path is
// DUAL: embedded DGB-P2P relay (primary) + digibyted submitblock (fallback).
// The DOGE-aux path is RPC-ONLY: DGB runs no DOGE P2P node, so the sole DGB-owned
// route to the DOGE network is submitblock -> dogecoind, issued through a SECOND,
// DGB-owned ICoinNode seam (the DOGE RPC seam), DISTINCT from the digibyted seam.
//
// AuxPoW INVARIANT (load-bearing, reviewer checks first): ONE parent per DOGE
// block. This is a SEPARATE deployment from the canonical LTC+DOGE merged path --
// a given DOGE block is won by EITHER the LTC parent OR the DGB parent, never
// both. Nothing here touches the LTC+DOGE submit path; the DGB-owned DOGE seam is
// its own dogecoind connection.
//
// BUILD-VERIFIABLE NOW. The DOGE block assembly (header w/ 0x100 AuxPoW bit ||
// CAuxPow proof || DOGE block body from the getauxblock template) is injected as
// a std::function -- exactly as won_block_dispatch.hpp injects WonBlockRecon-
// structor -- so this half compiles + unit-tests before the live DOGE template
// seam lands. The run-loop binds the real assembler + the DGB-owned DOGE seam
// when the embedded path is wired (DD).
//
// Default Scrypt-only build: this whole TU is excluded (AUX_DOGE undefined).
// Per-coin isolation: src/impl/dgb/coin/ only. p2pool-merged-v36 surface: NONE
// beyond the existing AUX_DOGE stretch seam -- no parent share format, PoW hash,
// coinbase commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------
#ifdef AUX_DOGE

#include <functional>
#include <optional>
#include <string>
#include <utility>

#include <core/coin/node_iface.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

namespace dgb
{
namespace coin
{

// Outcome of a won DOGE-aux block submit. RPC-ONLY: unlike the parent dual-path
// broadcast there is no embedded-P2P leg (DGB does not speak DOGE P2P), so the
// only sink is dogecoind submitblock via the DGB-owned DOGE seam.
struct AuxDogeSubmit
{
    bool had_seam = false;   // a DGB-owned DOGE RPC seam was present + had_rpc()
    bool rpc_ok   = false;   // dogecoind submitblock returned ok OR duplicate
    bool any() const { return rpc_ok; }
};

// Assemble the full DOGE submit-block hex for a won DOGE-aux target hit:
//   (share_hash, auxpow_hex) -> DOGE block hex, or nullopt if unassemblable.
// auxpow_hex is the CAuxPow proof the PARENT side already built via the shared
// read-side producer (c2pool::merged::build_auxpow_proof) -- passed in, never
// rebuilt here, so the doge module stays read-side-only. Injected as a
// std::function (mirrors WonBlockReconstructor) so the submit half is build-
// verifiable + KAT-able before the live getauxblock template seam lands.
using AuxDogeBlockAssembler =
    std::function<std::optional<std::string>(const uint256& /*share_hash*/,
                                             const std::string& /*auxpow_hex*/)>;

// RPC-only dispatcher: submit the won DOGE block to dogecoind via the DGB-owned
// DOGE seam (a SECOND ICoinNode, distinct from the digibyted/parent seam).
// `doge_seam` may be null or RPC-less -- guarded so it never throws or
// dereferences a null sink. ignore_failure=true so a duplicate/already-have on
// resubmit never masks a prior accept.
inline AuxDogeSubmit submit_won_aux_doge_block(core::coin::ICoinNode* doge_seam,
                                               const std::string& doge_block_hex)
{
    AuxDogeSubmit r;
    if (doge_seam && doge_seam->has_rpc()) {
        r.had_seam = true;
        r.rpc_ok = doge_seam->submit_block_hex(doge_block_hex, /*ignore_failure=*/true);
        LOG_INFO << "[EMB-DGB/AUX-DOGE] won DOGE-aux block submitblock "
                 << (r.rpc_ok ? "ok/duplicate" : "no-ack")
                 << " (" << doge_block_hex.size() / 2 << " bytes, RPC-only).";
    } else {
        LOG_ERROR << "[EMB-DGB/AUX-DOGE] won DOGE-aux block: no DGB-owned dogecoind "
                     "RPC seam wired -- DOGE block NOT submitted!";
    }
    return r;
}

// The AUX_DOGE leg of the won-block handler. On a DOGE-aux target hit the share-
// tracker fires this with the winning share hash + the parent-built AuxPoW proof.
// It assembles the DOGE submit block and dispatches it RPC-only to dogecoind.
// The run-loop installs the returned closure ALONGSIDE the parent
// m_on_block_found: both legs fire independently off the SAME scrypt pow_hash
// (dual-target, neither gates the other -- cf. aux_doge_dc_proof_test §4).
inline std::function<void(const uint256&, const std::string&)>
make_aux_doge_on_block_found(AuxDogeBlockAssembler assemble,
                             core::coin::ICoinNode* doge_seam)
{
    return [assemble = std::move(assemble), doge_seam]
           (const uint256& share_hash, const std::string& auxpow_hex)
    {
        if (!assemble) {
            LOG_ERROR << "[EMB-DGB/AUX-DOGE] won DOGE-aux "
                      << share_hash.GetHex().substr(0, 16)
                      << " -- no DOGE block assembler wired; cannot submit.";
            return;
        }
        auto doge_block = assemble(share_hash, auxpow_hex);
        if (!doge_block) {
            LOG_WARNING << "[EMB-DGB/AUX-DOGE] won DOGE-aux "
                        << share_hash.GetHex().substr(0, 16)
                        << " could not be assembled -- NOT submitted.";
            return;
        }
        LOG_INFO << "[EMB-DGB/AUX-DOGE] GOT DOGE-AUX BLOCK! share="
                 << share_hash.GetHex().substr(0, 16)
                 << " auxpow=" << auxpow_hex.size() / 2
                 << " bytes -- submitting to dogecoind (RPC-only).";
        submit_won_aux_doge_block(doge_seam, *doge_block);
    };
}

} // namespace coin
} // namespace dgb

#endif // AUX_DOGE
