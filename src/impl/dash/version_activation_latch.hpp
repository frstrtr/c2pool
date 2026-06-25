#pragma once

// Dash v36 activation LATCH — the persisted VOTING -> ACTIVATED -> CONFIRMED
// state machine that Component A of the v36-migration-mechanism-standard
// requires and that DASH previously lacked.
//
// version_negotiation.hpp computes the v36-active verdict LIVE from chain
// ancestry every call (v36_active(weights) -- the 95% weighted gate). That is
// correct for a continuously-running supervised node, but an UNSUPERVISED node
// that restarts recomputes the verdict from whatever window it currently holds
// and can therefore FLAP: a transient dip below 95% (reorg, partial sync) would
// read as "not active" even though the chain had already crossed and confirmed.
//
// The latch fixes that by recording the crossing as durable state:
//
//   VOTING     v36 has not yet held the 95% weighted gate.
//   ACTIVATED  v36_active first observed true; activation height recorded. The
//              chain has crossed but the crossing is not yet irreversible — if
//              signaling falls back below 95% before it is sustained, the latch
//              reverts to VOTING (the activation was not real / was reorged out).
//   CONFIRMED  v36_active held continuously for 2 * CHAIN_LENGTH ancestors after
//              activation. IRREVERSIBLE: once confirmed the latch never reverts,
//              even if a later window dips below 95%. This is the value that is
//              persisted so a restart reloads "confirmed" instead of recomputing.
//
// 3-bucket classification (operator 2026-06-17): this is a v36-NATIVE SHARED
// STRUCTURE (Bucket 2) — the activation-latch shape is identical across coins
// and standardizes toward the v37 unified multichain datastructure. It carries
// NO per-coin isolation primitive (no PREFIX/IDENTIFIER) and is NOT pre-v36
// transition compat. Pure + scaffolding-only: it owns no chain handle and has no
// live share_check caller yet (the caller feeds it the already-computed
// v36_active boolean), so it is socket-free testable and zero consensus risk.

#include "config_pool.hpp"   // dash::PoolConfig::CHAIN_LENGTH

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace dash::version_activation_latch
{

enum class LatchState : uint8_t {
    Voting    = 0,  // 95% weighted gate not yet held
    Activated = 1,  // gate first held; crossing not yet irreversible
    Confirmed = 2,  // gate held for 2*CHAIN_LENGTH after activation -- latched
};

inline const char* to_string(LatchState s)
{
    switch (s) {
        case LatchState::Voting:    return "VOTING";
        case LatchState::Activated: return "ACTIVATED";
        case LatchState::Confirmed: return "CONFIRMED";
    }
    return "VOTING";
}

inline LatchState state_from_string(const std::string& s)
{
    if (s == "CONFIRMED") return LatchState::Confirmed;
    if (s == "ACTIVATED") return LatchState::Activated;
    return LatchState::Voting;
}

// The persisted latch. `confirm_span` defaults to 2 * CHAIN_LENGTH per the
// migration standard; it is a field (not a hard constant) so it round-trips
// through JSON and so a test can drive a short span without a 4320-deep chain.
struct ActivationLatch
{
    LatchState state          = LatchState::Voting;
    uint64_t   version        = 36;     // the version this latch tracks activation of
    uint64_t   activated_height = 0;    // height at which v36_active first held (valid iff != Voting)
    uint64_t   confirm_span   = 2ull * PoolConfig::CHAIN_LENGTH;  // 2*CHAIN_LENGTH ancestors

    bool is_confirmed() const { return state == LatchState::Confirmed; }

    // Feed one observation: `active` = version_negotiation::v36_active over the
    // window ending at `height`. Advances the latch deterministically. CONFIRMED
    // is a sink (never reverts); a pre-confirmation dip reverts ACTIVATED->VOTING.
    void observe(bool active, uint64_t height)
    {
        if (state == LatchState::Confirmed) return;  // irreversible sink

        if (active) {
            if (state == LatchState::Voting) {
                state            = LatchState::Activated;
                activated_height = height;
            } else if (state == LatchState::Activated) {
                // confirm once the crossing has been sustained for the full span
                if (height >= activated_height &&
                    height - activated_height >= confirm_span) {
                    state = LatchState::Confirmed;
                }
            }
        } else {
            // signaling fell back below 95% before the crossing was irreversible
            if (state == LatchState::Activated) {
                state            = LatchState::Voting;
                activated_height = 0;
            }
        }
    }

    nlohmann::json to_json() const
    {
        return nlohmann::json{
            {"state", to_string(state)},
            {"version", version},
            {"activated_height", activated_height},
            {"confirm_span", confirm_span},
        };
    }

    static ActivationLatch from_json(const nlohmann::json& j)
    {
        ActivationLatch l;
        l.state            = state_from_string(j.at("state").get<std::string>());
        l.version          = j.at("version").get<uint64_t>();
        l.activated_height = j.at("activated_height").get<uint64_t>();
        l.confirm_span     = j.at("confirm_span").get<uint64_t>();
        return l;
    }
};

} // namespace dash::version_activation_latch
