#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DC) — dual-target SELECTION scaffold.
//
// Pure, header-only, fenced. NOT wired into any production path (no run-loop,
// no node seam, no share-tracker touch) — it pins the load-bearing DC decision
// contract that the eventual DC wiring (node.hpp:57 AUX_DOGE bind + submit) must
// satisfy, BEFORE that seam is touched (seam is parked on #82 + ltc-doge
// concurrence). Zero consensus surface; the DGB-parent consensus path is
// unchanged whether or not these helpers are ever consumed.
//
// Two independent decisions:
//
//   MINT-TIME  (mirrors #486 embed-at-mint): the DGB parent coinbase embeds the
//     fabe6d6d merged-mining commitment (built by #475) IFF aux MM is enabled
//     AND a DOGE work job is present. Otherwise no embed -> byte-identical
//     no-op coinbase (the #486 nullopt invariant).
//
//   SUBMIT-TIME: the DGB-parent target and the DOGE-aux target are INDEPENDENT
//     thresholds against the SAME scrypt pow_hash (pow <= target == hit;
//     mirrors aux_doge_dc_proof_test DualTargetIndependentThresholds). The
//     DOGE-aux path is only a candidate when a DOGE job was minted in.
//
// LOAD-BEARING LINKAGE (DC<->DB): a DOGE-aux win can only be assembled when the
// fabe6d6d commitment was minted — so fire_doge_aux ==> embed_commitment. This
// guard is what couples submit-time selection back to the #475/#486 mint.
// ---------------------------------------------------------------------------

#include <core/uint256.hpp>

namespace dgb
{
namespace coin
{

// fabe6d6d merged-mining commitment tag — the magic prefix #475 prepends to the
// 44-byte MM commitment (fa be 6d 6d || root32BE || size4LE || nonce4LE). Pinned
// here as the non-circular mint anchor; the DC wiring builds the real record.
inline constexpr unsigned char MM_COMMITMENT_TAG[4] = {0xfa, 0xbe, 0x6d, 0x6d};

// MINT-TIME embed decision (#486). embed_commitment is true IFF aux MM is
// enabled and a DOGE work job is present; false -> nullopt / no-op coinbase.
struct AuxMintDecision
{
    bool embed_commitment;
};

inline AuxMintDecision aux_mint_decision(bool aux_enabled, bool has_doge_job)
{
    return AuxMintDecision{aux_enabled && has_doge_job};
}

// SUBMIT-TIME dual-target fire decision. Independent per-path thresholds against
// one scrypt pow_hash. DOGE-aux only fires when a DOGE job was minted in.
struct DualTargetFire
{
    bool fire_dgb_parent;
    bool fire_doge_aux;
};

inline DualTargetFire select_submit(const uint256& pow_hash,
                                    const uint256& dgb_target,
                                    bool           has_doge_job,
                                    const uint256& doge_target)
{
    const bool dgb_hit  = !(pow_hash > dgb_target);
    const bool doge_hit = has_doge_job && !(pow_hash > doge_target);
    return DualTargetFire{dgb_hit, doge_hit};
}

// LOAD-BEARING DC<->DB linkage: a DOGE-aux win is only assemblable when the
// fabe6d6d commitment was minted. fire_doge_aux ==> embed_commitment.
inline bool selection_is_consistent(const AuxMintDecision& mint,
                                    const DualTargetFire&  fire)
{
    return !fire.fire_doge_aux || mint.embed_commitment;
}

} // namespace coin
} // namespace dgb
