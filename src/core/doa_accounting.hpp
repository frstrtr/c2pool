// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <string>

namespace core::doa {

// DOA-under-load accounting predicate (v36 cutover deploy path) — SSOT.
//
// A submitted share is Dead-On-Arrival when the live GBT previousblockhash has
// advanced past the prevhash that was frozen into the job at get_work() time:
// the miner was still grinding the parent tip we have already moved off. This
// is ACCOUNTING ONLY. The caller MUST NOT mutate job.stale_info on a DOA — that
// field is part of ref_hash, frozen at template time; changing it at submit
// breaks ref_hash consistency and yields a GENTX-FAIL. The share is still
// created and broadcast, matching p2pool behaviour; only doa_shares_ moves.
//
// Guard clauses mirror the live call site (stratum_server.cpp handle_submit):
// an empty operand means the template is unfetched or the job never populated
// its prevhash — freshness is UNKNOWN, so we never count it as DOA. DOA is
// asserted only on a positive, fully-populated prevhash MISMATCH.
inline bool is_doa_share(const std::string& current_gbt_prevhash,
                         const std::string& job_gbt_prevhash) noexcept
{
    return !current_gbt_prevhash.empty()
        && !job_gbt_prevhash.empty()
        && current_gbt_prevhash != job_gbt_prevhash;
}

} // namespace core::doa
