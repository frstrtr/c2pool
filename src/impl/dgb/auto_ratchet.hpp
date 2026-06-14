#pragma once

/// PILLAR 1 (version auto-ratchet) — Phase B scaffolding STUB, GATED.
///
/// GATE: F10 fence on share_check version-acceptance (transitional v35/v36
/// window). The version-acceptance surface (accept BOTH v35 and v36 during the
/// ratchet window) is the F10-fenced path. This pillar stays a STUB until the
/// F10 capture PR clears — see [[dgb-modern-layer-activation]] memory.
///
/// Target shape: mirror src/impl/ltc/auto_ratchet.hpp (AutoRatchet, target
/// version = 36), reading live voted version from the sharechain. DGB-Scrypt
/// uses the same ratchet math as LTC — Scrypt-only, no algo divergence here.
///
/// COMPAT: must match frstrtr/p2pool-merged-v36 version-voting + ratchet rules
/// exactly. Any divergence => [decision-needed] to integrator (V37 by def).

namespace dgb
{

// TODO(Phase B, F10-gated): port ltc::AutoRatchet -> dgb::AutoRatchet.
// Do NOT author the share_check version-acceptance path until F10 capture
// PR lands. Pillar-1 core cannot fully land before then.
class AutoRatchet; // forward-declared only; definition deferred behind F10.

} // namespace dgb
