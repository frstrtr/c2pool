#pragma once

/// PILLAR 1 (version auto-ratchet) — Phase B scaffolding STUB, GATED.
///
/// GATE: F10 fence on share_check version-acceptance (transitional v35/v36
/// window). The version-acceptance surface (accept BOTH v35 and v36 during the
/// ratchet window) is the F10-fenced path. This pillar stays a STUB until the
/// F10 capture PR clears — see [[dgb-modern-layer-activation]] memory.
///
/// SOAK FREEZE: the ratchet thresholds below are carried verbatim from
/// src/impl/ltc/auto_ratchet.hpp, but the transition state machine
/// (get_share_version / load / save) stays a fenced TODO until the LTC soak
/// freezes the reference (see share.hpp conformance note). DGB-Scrypt uses the
/// SAME ratchet math as LTC — Scrypt-only, no algo divergence — so when the
/// fence lifts the port is a namespace change, not a re-derivation.
///
/// COMPAT: must match frstrtr/p2pool-merged-v36 version-voting + ratchet rules
/// exactly. Any divergence => [decision-needed] to integrator (V37 by def).

#include <cstdint>

namespace dgb
{

enum class RatchetState : uint8_t
{
    VOTING    = 0,  // producing old-format shares, voting for upgrade
    ACTIVATED = 1,  // producing new-format shares, monitoring support
    CONFIRMED = 2   // permanent: new format confirmed, survives restart
};

inline const char* ratchet_state_str(RatchetState s)
{
    switch (s) {
    case RatchetState::VOTING:    return "VOTING";
    case RatchetState::ACTIVATED: return "ACTIVATED";
    case RatchetState::CONFIRMED: return "CONFIRMED";
    }
    return "UNKNOWN";
}

// AutoRatchet: autonomous V35 -> V36 share-version transition state machine.
// Mirrors ltc::AutoRatchet (p2pool-v36 data.py AutoRatchet, lines 2109-2344).
//
// Thresholds are FROZEN here (95 / 50 / 2x) to match the Python reference and
// ltc::AutoRatchet byte-for-byte. The transition logic is intentionally NOT
// authored yet — see the F10 + soak-freeze fences above.
class AutoRatchet
{
public:
    // Ratchet thresholds — must match p2pool-merged-v36 + ltc::AutoRatchet exactly.
    static constexpr int ACTIVATION_THRESHOLD    = 95;  // % votes to activate (VOTING -> ACTIVATED)
    static constexpr int DEACTIVATION_THRESHOLD  = 50;  // % below which to revert (ACTIVATED -> VOTING)
    static constexpr int CONFIRMATION_MULTIPLIER = 2;   // confirm after 2x CHAIN_LENGTH sustained
    static constexpr int SWITCH_THRESHOLD        = 60;  // % tail-guard floor for format switch (jtoomim rule)

    // TODO(Phase B, F10-gated + post-soak-freeze): port the ltc::AutoRatchet
    // state machine into dgb:: once the F10 version-acceptance capture PR lands
    // AND the LTC soak freezes the reference:
    //   - ctor(state_file_path, target_version = 36) + JSON load()/save()
    //   - get_share_version(ShareTracker&, best_share_hash):
    //       VOTING/ACTIVATED/CONFIRMED transitions, tail guard, retroactive credit
    //   - state() / target_version() accessors + RatchetState members
    // Do NOT author the share_check version-acceptance path before F10 clears.
};

} // namespace dgb
