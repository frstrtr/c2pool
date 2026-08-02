// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::build_aux_backends / btc::merged_addr_entries — NMC PE host-wire slice 4.
//
// Slice 3 turned each --merged SPEC into a typed AuxChainConfig (merged_configs).
// This slice consumes them at two seams:
//
//   (1) build_aux_backends — construct one IAuxChainBackend per config. The
//       backend built here is the AuxChainRPC external-daemon path, which is the
//       fallback route that MUST always exist (never removed). The embedded-NMC
//       SPV backend (nmc::coin::AuxChainEmbedded) lands in PA/PB and is
//       registered as primary alongside this RPC fallback, mirroring the
//       DOGE/NMC blocks in main_ltc (~L5350+). Construction is inert — no
//       connect() here, so an unreachable aux daemon never blocks BTC startup.
//
//   (2) merged_addr_entries — map each config to the per-chain MergedAddressEntry
//       committed in the local share at the create_local_share seam
//       (main_btc ~1293). The aux coinbase pays the pool's script on the aux
//       chain; Namecoin shares Bitcoin's script templates (identical opcodes,
//       only address-encoding version bytes differ), so absent an explicit aux
//       payout address we commit the same raw script bytes the parent share
//       pays (default_script) under the aux chain_id. PPLNS per-share aux scripts
//       frozen into the template replace this default when the merged template
//       builder lands (PC); until then the --merged path is wire-only and not
//       yet consensus-consistent with the frozen ref.
//
// Absent --merged both return empty and the BTC host path stays v35
// byte-for-byte. Pure/stateless (build_aux_backends only needs an io_context),
// so both KAT without a daemon.
// ---------------------------------------------------------------------------
#include <impl/btc/share_types.hpp>          // btc::MergedAddressEntry, BaseScript
#include <c2pool/merged/merged_mining.hpp>   // AuxChainConfig, IAuxChainBackend, AuxChainRPC

#include <boost/asio/io_context.hpp>

#include <memory>
#include <vector>

namespace btc {

// One RPC-backed IAuxChainBackend per parsed aux config. Construction only —
// the manager dials lazily, so an offline aux daemon does not stall the parent.
inline std::vector<std::unique_ptr<c2pool::merged::IAuxChainBackend>>
build_aux_backends(boost::asio::io_context& ioc,
                   const std::vector<c2pool::merged::AuxChainConfig>& configs)
{
    std::vector<std::unique_ptr<c2pool::merged::IAuxChainBackend>> backends;
    backends.reserve(configs.size());
    for (const auto& cfg : configs)
        backends.push_back(
            std::make_unique<c2pool::merged::AuxChainRPC>(ioc, cfg));
    return backends;
}

// One MergedAddressEntry per aux config: {chain_id, aux payout script}. The
// default_script (the parent share's payout script) is committed as the aux
// payout until per-share PPLNS aux scripts are frozen into the template (PC).
inline std::vector<MergedAddressEntry>
merged_addr_entries(const std::vector<c2pool::merged::AuxChainConfig>& configs,
                    const std::vector<unsigned char>& default_script)
{
    std::vector<MergedAddressEntry> entries;
    entries.reserve(configs.size());
    for (const auto& cfg : configs) {
        MergedAddressEntry e;
        e.m_chain_id = cfg.chain_id;
        e.m_script.m_data = default_script;
        entries.push_back(std::move(e));
    }
    return entries;
}

} // namespace btc
