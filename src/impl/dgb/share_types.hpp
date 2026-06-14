#pragma once

/// DigiByte Scrypt share type constants (Phase B scaffolding).
///
/// DGB-Scrypt uses the same 80-byte header layout and share format as LTC.
/// This stub declares the DGB-specific surface; the full type definitions
/// are ported from src/impl/ltc/share_types.hpp during Phase B.
///
/// SCOPE: Scrypt-only (V36). Other DGB algos (SHA256d/Skein/Qubit/Odocrypt)
/// are accept-by-continuity / ignored — NOT validated here. Full 5-algo = V37.
///
/// TODO(Phase B): port StaleInfo / MerkleLinkParams / ShareType from ltc,
/// drop LTC SegWit-activation gating (DGB activates differently; confirm vs
/// p2pool-merged-v36 networks/digibyte.py before wiring).

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/pack.hpp>

namespace dgb
{

enum StaleInfo
{
    none = 0,
    orphan = 253,
    doa = 254
};

// TODO(Phase B): MerkleLinkParams, ShareType, GenerateShareTransaction —
// port from ltc/share_types.hpp, Scrypt-only.

} // namespace dgb
