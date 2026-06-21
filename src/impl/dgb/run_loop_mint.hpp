#pragma once

// run_loop_mint.hpp — DGB Phase B pool/share: the live create_local_share()
// caller that the AutoRatchet {mint, vote} selector feeds.
//
// auto_ratchet_wire.hpp resolves the {share_version_to_mint,
// desired_version_to_vote} pair (oracle baseline 35, target 36). Until now that
// pair was computed only in tests; the share-mint path still defaulted
// create_local_share()'s trailing version arguments to a hardcoded 36/36, which
// would make a freshly-started node skip ahead of the network and mint V36
// shares the older DGB sharechain cannot accept.
//
// This seam closes that gap: it is the ONE place the run-loop asks the ratchet
// for the version pair and stamps it onto the share it is about to create. It
// adds NO new policy — get_share_version() already owns the work-weighted gate
// (#249/#289). The create step is injected (CreateFn) rather than called
// directly so this glue stays free of the ~30-argument create_local_share()
// surface: the run-loop binds every other field, this helper only chooses, and
// forwards, the version pair. Fenced, header-only, non-consensus glue over the
// already-tap-reviewed selector.

#include <cstdint>
#include <utility>

#include "auto_ratchet_wire.hpp"   // dgb_select_mint_versions, AutoRatchet
#include <core/uint256.hpp>   // uint256 (also via auto_ratchet_wire)

namespace dgb
{

// Ask the ratchet for {mint, vote}, then hand them to the caller-supplied
// create step (which binds them to create_local_share's trailing
// share_version / desired_version arguments). Returns the create step's result
// verbatim — typically the new share hash. The chosen versions are NEVER a
// hardcoded constant: a VOTING node mints DGB_BASE_VERSION (35) while voting
// DGB_TARGET_VERSION (36), and follows the state machine thereafter.
//
// CreateFn signature: R(int64_t share_version, uint64_t desired_version).
template <class CreateFn>
inline auto mint_local_share_with_ratchet(
    AutoRatchet& ratchet,
    ShareTracker& tracker,
    const uint256& best_share_hash,
    CreateFn&& create_with_versions)
    -> decltype(create_with_versions(int64_t{0}, uint64_t{0}))
{
    auto [mint, vote] = dgb_select_mint_versions(ratchet, tracker, best_share_hash);
    return std::forward<CreateFn>(create_with_versions)(
        mint, static_cast<uint64_t>(vote));
}

} // namespace dgb
