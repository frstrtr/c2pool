// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — arming policy (design §7), the Qt-free core only.
//
// The normal production posture is a STANDING arm from the node's unit flag
// (--embedded-tx-inject), which survives restarts. Auto-arm is the fallback:
// the scheduler flips the node's runtime "embedded.tx_inject" key through the
// two-phase POST /api/config/apply flow, and ONLY when the operator recorded
// consent (auto_arm + consented_at + consent_text in the queue file). It is
// never a default:
//   * a queue claiming auto_arm (or auto_disarm_when_idle, or an item with
//     allow_auto_arm:true) without consented_at is invalid at load;
//   * the per-item allow_auto_arm narrows (false) or widens (true) the queue
//     policy; null inherits it;
//   * a money_gate refusal (the node's tripwire fired) suspends auto-arm for
//     the queue until a human re-records consent;
//   * at most one arm attempt per 10 minutes;
//   * the money nonce lives in memory only for the confirm POST, then is wiped.
// The consent and arm/disarm dialogs are slice S5; this is the logic they use.

#include "InjectQueue.hpp"
#include "NodeApi.hpp"

#include "../../secure/SecureString.hpp"

#include <cstdint>
#include <string>

namespace c2w::companion::sched::arm {

inline constexpr const char* kArmKey = "embedded.tx_inject";
inline constexpr int64_t kArmRetrySeconds = 600;

// Queue-level validity: auto flags and per-item widening need consented_at.
bool validate(const Queue& q, std::string& why);

// Does the recorded policy allow arming the node for this item?
bool consent_applies(const ArmPolicyRecord& p, const Item& it);

// Record (or re-record) consent. Refuses an empty consent text when any auto
// flag is on. Clears a previous suspension (a human looked at it again).
bool record_consent(ArmPolicyRecord& p, bool auto_arm, bool auto_disarm_when_idle,
                    const std::string& consent_text, int64_t now, std::string& why);

enum class ArmResultKind : uint8_t {
    Applied,    // phase 2 answered applied with applied_keys == [embedded.tx_inject]
    NotArmed,   // 503: the node's control plane has no token registered
    NoToken,    // 403: token refused
    MoneyGate,  // 409 money_gate: the node's tripwire fired; suspend auto-arm
    Rejected,   // 400 no_runtime_setter / validation
    Protocol,   // an unexpected answer (e.g. money_keys other than [embedded.tx_inject])
    Transport,  // node unreachable
};

const char* arm_result_name(ArmResultKind k);

struct ArmResult {
    ArmResultKind kind = ArmResultKind::Transport;
    std::string why;
    int posts = 0;            // POSTs sent to /api/config/apply (1 or 2)
};

// The two-phase apply of {"embedded.tx_inject": enable ? "true" : "false"}:
//   1. POST {control_token, changes}            -> expect need_confirm, money_keys == [key], money_nonce
//   2. POST {control_token, changes, money_nonce} -> expect applied, applied_keys == [key]
// The two bodies differ only by the trailing money_nonce member. Both bodies
// and the nonce are wiped before return.
ArmResult two_phase_apply(NodeApi& api, const c2w::secure::SecureString& token, bool enable);

// The three-line exposure summary (§7.3) the consent dialog and the daemon's
// status print restate.
const char* exposure_text();

} // namespace c2w::companion::sched::arm
