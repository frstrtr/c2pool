#pragma once
//
// version_gate.hpp — Cross-coin c2pool share-version activation gate (SINGLE SOURCE OF TRUTH).
//
// c2pool's sharechain format is versioned. The V36 format revision is a
// CONSENSUS boundary that is IDENTICAL across every coin c2pool mines
// (btc/ltc/bch/dgb): when a share's VERSION >= 36 the wire layout switches to
// the V36 encoding (VarInt subsidy, AbsworkV36Format, merged_addresses,
// merged_coinbase_info + merged_payout_hash, V36HashLinkType extra_data,
// message_data) and the V36 PPLNS / donation semantics engage. The activation
// number 36 carries no per-coin network state — every coin's params set
// current_share_version = 36 — so it belongs here in core/ rather than being
// re-spelled as a bare `>= 36` literal at each call site.
//
// SCOPE — what this gate does and does NOT own:
//   OWNS:   the V36 share-format / consensus-revision boundary (uniform 36).
//   NOT:    segwit activation. That version is coin-SPECIFIC
//           (BTC 33, dgb 35, ltc/bch 17) and stays in each coin's PoolConfig
//           as SEGWIT_ACTIVATION_VERSION, surfaced via the per-coin
//           is_segwit_activated() helper. Do not fold segwit into this gate.
//
// Conformance shape (BTC-first, per v36-standardize goal):
//   Every coin replaces its scattered `version >= 36` / `>= 36` literals with
//   core::version_gate::is_v36_active(version). Both compile-time
//   (`if constexpr (is_v36_active(Tmpl::version))`) and runtime
//   (`if (is_v36_active(p.share_version))`) call sites are covered because the
//   predicate is constexpr. BTC is the reference adoption; ltc/dgb/bch conform
//   by mechanical site-rewrite — no value changes, byte-for-byte identical gate.
//
// Provenance: p2pool check() gates the V36 share rev on self.VERSION >= 36
//   (jtoomim/forrestv). The number is shared across the c2pool multi-coin tree.
//

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

namespace core::version_gate
{

// V36 share-format / consensus-revision activation version. Uniform cross-coin.
inline constexpr uint64_t V36_ACTIVATION_VERSION = 36;

// True iff a share of the given VERSION uses the V36 sharechain encoding and
// V36 consensus semantics. constexpr so it serves both `if constexpr` template
// gates and runtime checks.
constexpr bool is_v36_active(uint64_t version)
{
    return version >= V36_ACTIVATION_VERSION;
}


// Canonical v36-native share-version-transition rule (cross-coin SSOT).
// Applies the boundary admit/reject decision to an ALREADY-EXTRACTED
// (parent_version, share_version) pair using a PRECOMPUTED PPLNS-WEIGHTED
// desired-version tally for the [CHAIN_LENGTH*9/10, CHAIN_LENGTH] window behind
// the parent, plus a flag for whether CHAIN_LENGTH history exists behind the
// parent. Throws std::invalid_argument on a disallowed switch; returns on an
// admissible one.
//
// Rule (p2pool data.py check()): same-version always valid; +1 upgrade needs
// >= 60% PPLNS-WEIGHTED desired-version support for the new version in the
// window AND CHAIN_LENGTH history; -1 (AutoRatchet deactivation) valid; any
// other jump throws when history exists. With insufficient history only a +1
// upgrade is rejected ("switch without enough history") and other shapes pass,
// matching the BTC inline gate exactly.
//
// `floor` is the per-coin v36 activation version (e.g. BTC 35->36, DASH 16->36).
// It is bucket-3 transition-compat carried as a PARAMETER (never hardcoded) so a
// coin whose seam also runs an obsolescence branch (DASH) can thread its own
// floor when it migrates onto this SSOT; the canonical boundary rule itself does
// not reference it. Defaulted to V36_ACTIVATION_VERSION.
template <typename WeightT>
inline void verify_version_transition(
    int64_t parent_version,
    int64_t share_version,
    const std::map<uint64_t, WeightT>& window_weights,
    bool have_history,
    uint64_t floor = V36_ACTIVATION_VERSION)
{
    (void)floor;
    // same version — always valid (it was correct when minted), regardless of history.
    if (share_version == parent_version)
        return;

    if (have_history)
    {
        if (share_version == parent_version + 1)
        {
            // Upgrade by one: needs >= 60% weighted support for the new version.
            WeightT new_ver_weight{};
            WeightT total_weight{};
            for (const auto& [ver, w] : window_weights)
            {
                total_weight = total_weight + w;
                if (static_cast<int64_t>(ver) == share_version)
                    new_ver_weight = new_ver_weight + w;
            }
            // canonical: counts.get(VERSION,0) < sum(counts)*60//100
            if (new_ver_weight * uint32_t(100) < total_weight * uint32_t(60))
                throw std::invalid_argument("switch without enough hash power upgraded");
        }
        else if (parent_version == share_version + 1)
        {
            // downgrade by one (AutoRatchet deactivation: V35 may follow V36)
        }
        else
        {
            throw std::invalid_argument("invalid version jump from "
                + std::to_string(parent_version) + " to " + std::to_string(share_version));
        }
    }
    else if (share_version == parent_version + 1)
    {
        // Not enough history for an upgrade boundary.
        throw std::invalid_argument("switch without enough history");
    }
    // else (downgrade / multi-jump with insufficient history): admitted, matching BTC.
}

} // namespace core::version_gate
