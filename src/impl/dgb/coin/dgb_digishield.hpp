// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB DigiShield Scrypt-only ancestor walk  (M3 §7b — SCRYPT-ONLY VALIDATION).
//
// DigiByte retargets per-block per-algo with DigiShield/MultiShield, NOT
// Bitcoin's 2016-block window. For the V36 Scrypt-only lane the difficulty
// window must walk SCRYPT-ALGO ancestors ONLY. On a mixed-algo chain the
// header sequence interleaves Scrypt headers (full PoW validate) with
// non-Scrypt headers accepted by continuity (work-neutral). Folding a
// continuity header into the retarget window corrupts the Scrypt target AND
// re-introduces the work-neutrality break documented as the THIRD INVARIANT
// in coin/header_chain.hpp. This header isolates that walk so the trap lives
// in one consensus-pinned, separately-guarded place — exactly the failure the
// header_chain.hpp DIGISHIELD INSERTION POINT note warns is "easy to get wrong
// on a mixed-algo chain".
//
// This is the ancestor-selection step only; the per-algo DigiShield target
// math (LWMA/MultiShield) layers on top in the following slice and consumes
// the indices this returns.
//
// Header-only: depends ONLY on coin/dgb_block_algo.hpp + std, so it links into
// the standalone CI guard (GTest-only, no dgb OBJECT lib) like algo_select.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include <impl/dgb/coin/dgb_block_algo.hpp>

namespace dgb::coin {

// THIRD-INVARIANT work-accounting predicate. Only a Scrypt header credits
// cumulative work / best-chain weight; a continuity (known non-Scrypt) header
// extends the header chain but is work-neutral. This is the single predicate
// HeaderChain::validate() consults before adding a header's work, so the
// invariant cannot drift between the validate() path and the retarget walk.
inline bool header_credits_work(int32_t n_version) noexcept
{
    return is_scrypt_header(n_version);
}

// Collect the Scrypt-algo ancestors that form a DigiShield retarget window.
//
//   version_at(k) -> nVersion of the header k positions back from the search
//                    start (k = 0 is the nearest candidate ancestor).
//   depth         -> how many positions are walkable (chain length behind).
//   window        -> number of Scrypt ancestors the retarget needs.
//
// Returns the k-indices of the first `window` SCRYPT headers, nearest-first,
// skipping every non-Scrypt (continuity) header. Returns fewer than `window`
// only when the available chain is exhausted (early-chain / genesis region).
// Unknown-algo headers never enter a validated chain (REJECT at ingest), so
// the walk treats anything not Scrypt as a skip.
inline std::vector<std::size_t> scrypt_window_ancestors(
    const std::function<int32_t(std::size_t)>& version_at,
    std::size_t depth,
    std::size_t window)
{
    std::vector<std::size_t> out;
    if (window == 0) return out;
    out.reserve(window);
    for (std::size_t k = 0; k < depth && out.size() < window; ++k)
    {
        if (is_scrypt_header(version_at(k)))
            out.push_back(k);
        // else: continuity header -> skipped, contributes no window sample
    }
    return out;
}

} // namespace dgb::coin