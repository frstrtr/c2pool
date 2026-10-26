// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// dash::stratum won-block record facts — taken from the JOB, never from the
// work source's CURRENT template.
//
// A won block belongs to the job the miner hashed, and that job can be minutes
// older than whatever cached_work() holds when the solve arrives. The won-block
// arm used to read the block's height from cached_work(), so a solve on a
// STALE job was recorded at the CURRENT template's height — and, when the cache
// was empty or the serve gate was declining, at height 0.
//
// Measured on the private DASH v36 primary, 2026-10-25 18:52:21Z: the default
// --bestcl-policy freshness gate declined new templates for 376 s, the rigs
// kept hashing the last job (prev = 2561315) and solved it while the network
// was already at 2561318. The node logged "height~=0", the ledger line said
// "h=0 ... mn_payout_outputs=0 subsidy=0", /recent_blocks stored the row at
// height 0 (sorted to the bottom, past the ten rows the table shows), the
// confirm/orphan lane asked "which block won height 0?" and kept the row
// pending forever, and the hashrate chart drew it as a green "Block Found!"
// with Height "?" and "1st block" luck. The reserve, which learned the same
// block from the sharechain, recorded it correctly as 2561316 / orphaned —
// it reads the height from the block's own coinbase (BIP34), see
// dash::dashboard::row_from_share.
//
// This header is that same derivation for the finder's stratum arm. Pure: no
// locks, no I/O, no globals — a direct KAT surface
// (test_dash_stratum_work_source.cpp).

#include <impl/dash/coin/rpc_data.hpp>      // DashWorkData
#include <impl/dash/coin/transaction.hpp>   // MutableTransaction (DASH tx codec)

#include <core/coinbase_builder.hpp>        // c2pool::ParsedScriptSig (BIP34 height)
#include <core/pack.hpp>

#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace dash::stratum {

/// The BIP34 height pushed at the head of a DASH coinbase's scriptSig, or 0
/// when the coinbase does not deserialize or carries no height push. dashd's
/// ContextualCheckBlock enforces this prefix (bad-cb-height), so it is the
/// height the block was actually built at — whatever the template cache says
/// now. Same parser the sharechain-peer path uses (ParsedScriptSig).
inline uint32_t coinbase_bip34_height(const std::vector<unsigned char>& coinbase_bytes)
{
    if (coinbase_bytes.empty()) return 0;
    dash::coin::MutableTransaction cb;
    try {
        PackStream ps(coinbase_bytes);
        ps >> cb;
    } catch (const std::exception&) {
        return 0;
    }
    if (cb.vin.empty()) return 0;
    const auto& sig = cb.vin[0].scriptSig.m_data;
    if (sig.empty()) return 0;
    c2pool::ParsedScriptSig parsed;
    (void)c2pool::ParsedScriptSig::parse(sig.data(), sig.size(), parsed);
    return parsed.block_height > 0 ? static_cast<uint32_t>(parsed.block_height) : 0;
}

/// True when `current` is the template the job was cut from: same parent,
/// hence same height and the same height-deterministic masternode payee set.
/// False for an empty cache (null) and for a template that has moved on.
inline bool template_is_jobs(const dash::coin::DashWorkData* current,
                             const std::string& job_gbt_prevhash)
{
    return current != nullptr && !job_gbt_prevhash.empty()
        && current->m_previous_block.GetHex() == job_gbt_prevhash;
}

/// The coin height a won block was mined at. The block's own BIP34 height
/// first; the current template's height only when that template IS the job's
/// (same parent); otherwise 0, which every consumer reads as "unknown".
inline uint32_t won_block_height(const std::vector<unsigned char>& coinbase_bytes,
                                 const std::string& job_gbt_prevhash,
                                 const dash::coin::DashWorkData* current)
{
    if (const uint32_t h = coinbase_bip34_height(coinbase_bytes); h != 0)
        return h;
    if (template_is_jobs(current, job_gbt_prevhash))
        return current->m_height;
    return 0;
}

}  // namespace dash::stratum
