// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ArmPolicy.hpp"

#include "Clock.hpp"
#include "Json.hpp"
#include "TokenFile.hpp"

namespace c2w::companion::sched::arm {

bool validate(const Queue& q, std::string& why)
{
    const ArmPolicyRecord& p = q.arm_policy;
    const bool consent = p.consented_at.has_value() && !p.consented_at->empty();
    if (p.auto_arm && !consent) {
        why = "arm_policy.auto_arm is true but no consented_at is recorded (auto-arm needs explicit consent)";
        return false;
    }
    if (p.auto_disarm_when_idle && !consent) {
        why = "arm_policy.auto_disarm_when_idle is true but no consented_at is recorded";
        return false;
    }
    if (consent) {
        int64_t t = 0;
        std::string perr;
        if (!parse_utc(*p.consented_at, t, perr)) {
            why = "arm_policy.consented_at: " + perr;
            return false;
        }
    }
    for (const Item& it : q.items) {
        if (it.submit.allow_auto_arm.value_or(false) && !consent) {
            why = "item " + it.id + " sets allow_auto_arm:true but the queue has no recorded consent";
            return false;
        }
    }
    return true;
}

bool consent_applies(const ArmPolicyRecord& p, const Item& it)
{
    if (!p.consented_at || p.consented_at->empty()) return false;
    if (it.submit.allow_auto_arm) return *it.submit.allow_auto_arm;
    return p.auto_arm;
}

bool record_consent(ArmPolicyRecord& p, bool auto_arm, bool auto_disarm_when_idle,
                    const std::string& consent_text, int64_t now, std::string& why)
{
    if ((auto_arm || auto_disarm_when_idle) && consent_text.empty()) {
        why = "consent text is required to enable auto-arm or auto-disarm";
        return false;
    }
    p.auto_arm = auto_arm;
    p.auto_disarm_when_idle = auto_disarm_when_idle;
    if (auto_arm || auto_disarm_when_idle) {
        p.consented_at = format_utc(now);
        p.consent_text = consent_text;
    } else {
        p.consented_at.reset();
        p.consent_text.reset();
    }
    p.suspended_reason.reset();
    p.last_arm_attempt_at.reset();
    return true;
}

const char* arm_result_name(ArmResultKind k)
{
    switch (k) {
    case ArmResultKind::Applied: return "applied";
    case ArmResultKind::NotArmed: return "not_armed";
    case ArmResultKind::NoToken: return "no_token";
    case ArmResultKind::MoneyGate: return "money_gate";
    case ArmResultKind::Rejected: return "rejected";
    case ArmResultKind::Protocol: return "protocol";
    case ArmResultKind::Transport: return "transport";
    }
    return "?";
}

namespace {

bool keys_are_exactly_arm_key(const json::J& j, const char* field)
{
    if (!j.contains(field) || !j[field].is_array() || j[field].size() != 1) return false;
    const auto& k = j[field][0];
    return k.is_string() && k.get<std::string>() == kArmKey;
}

// Map a non-success apply reply to a result kind.
ArmResult map_failure(const HttpReply& r, const json::J& j, bool parsed, int posts)
{
    ArmResult out;
    out.posts = posts;
    const std::string status = parsed && j.is_object() && j.contains("status") && j["status"].is_string()
                                   ? j["status"].get<std::string>()
                                   : std::string();
    const std::string err = parsed && j.is_object() && j.contains("error") && j["error"].is_string()
                                ? j["error"].get<std::string>()
                                : std::string();
    if (!r.transport_ok) {
        out.kind = ArmResultKind::Transport;
        out.why = "node unreachable (" + r.error + ")";
    } else if (r.status == 503 || status == "not_armed") {
        out.kind = ArmResultKind::NotArmed;
        out.why = "control plane not armed on the node (--control-plane-token-file missing)";
    } else if (r.status == 403 || status == "no_token") {
        out.kind = ArmResultKind::NoToken;
        out.why = "node refused the control token";
    } else if (r.status == 409 || status == "money_gate") {
        out.kind = ArmResultKind::MoneyGate;
        out.why = "money_gate: the node's tripwire fired (" + (err.empty() ? status : err) + ")";
    } else if (r.status == 400) {
        out.kind = ArmResultKind::Rejected;
        out.why = "node rejected the change (" + (status.empty() ? err : status) + ")";
    } else {
        out.kind = ArmResultKind::Protocol;
        out.why = "unexpected apply reply HTTP " + std::to_string(r.status) + (status.empty() ? "" : " " + status);
    }
    return out;
}

} // namespace

ArmResult two_phase_apply(NodeApi& api, const c2w::secure::SecureString& token, bool enable)
{
    const std::string changes =
        std::string("\"changes\":{\"") + kArmKey + "\":\"" + (enable ? "true" : "false") + "\"}";

    std::string body1 = build_token_body(token, changes);
    HttpReply r1 = api.post_json(route::kConfigApply, body1);
    wipe_string(body1);

    json::J j1;
    std::string perr;
    const bool p1 = r1.transport_ok && json::parse_bounded(r1.body, j1, perr) && j1.is_object();
    wipe_string(r1.body); // carries the nonce on need_confirm
    const std::string st1 = p1 && j1.contains("status") && j1["status"].is_string() ? j1["status"].get<std::string>()
                                                                                      : std::string();
    if (!(r1.transport_ok && r1.status == 200 && p1)) return map_failure(r1, j1, p1, 1);

    if (st1 == "applied") {
        // The node took it without a confirmation phase (the key is not on its
        // money list). Accept only the exact key.
        ArmResult out;
        out.posts = 1;
        out.kind = keys_are_exactly_arm_key(j1, "applied_keys") ? ArmResultKind::Applied : ArmResultKind::Protocol;
        out.why = out.kind == ArmResultKind::Applied ? "applied without a confirmation phase"
                                                     : "phase 1 applied unexpected keys";
        return out;
    }
    if (st1 != "need_confirm") return map_failure(r1, j1, p1, 1);
    if (!keys_are_exactly_arm_key(j1, "money_keys")) {
        ArmResult out;
        out.posts = 1;
        out.kind = ArmResultKind::Protocol;
        out.why = "arm aborted: the node asked to confirm money keys other than [" + std::string(kArmKey) + "]";
        return out;
    }
    if (!j1.contains("money_nonce") || !j1["money_nonce"].is_string() ||
        j1["money_nonce"].get_ref<const std::string&>().empty()) {
        ArmResult out;
        out.posts = 1;
        out.kind = ArmResultKind::Protocol;
        out.why = "arm aborted: need_confirm without a money_nonce";
        return out;
    }

    // Phase 2: the same diff + the nonce, appended last so the two bodies differ
    // only by this member.
    std::string& nonce_ref = j1["money_nonce"].get_ref<std::string&>();
    std::string rest;
    // Reserve once (worst-case escaping) so the buffer holding the nonce never
    // reallocates and leaves a stale copy behind.
    rest.reserve(changes.size() + 20 + nonce_ref.size() * 6);
    rest += changes;
    rest += ",\"money_nonce\":\"";
    append_json_escaped(rest, reinterpret_cast<const uint8_t*>(nonce_ref.data()), nonce_ref.size());
    rest += "\"";
    wipe_string(nonce_ref);
    std::string body2 = build_token_body(token, rest);
    wipe_string(rest);
    HttpReply r2 = api.post_json(route::kConfigApply, body2);
    wipe_string(body2);

    json::J j2;
    const bool p2 = r2.transport_ok && json::parse_bounded(r2.body, j2, perr) && j2.is_object();
    const std::string st2 = p2 && j2.contains("status") && j2["status"].is_string() ? j2["status"].get<std::string>()
                                                                                      : std::string();
    if (!(r2.transport_ok && r2.status == 200 && p2 && st2 == "applied")) return map_failure(r2, j2, p2, 2);
    ArmResult out;
    out.posts = 2;
    if (!keys_are_exactly_arm_key(j2, "applied_keys")) {
        out.kind = ArmResultKind::Protocol;
        out.why = "phase 2 applied unexpected keys";
        return out;
    }
    out.kind = ArmResultKind::Applied;
    out.why = std::string(enable ? "armed" : "disarmed") + " through the two-phase apply";
    return out;
}

const char* exposure_text()
{
    return "Arming lets a process on the node host holding the 0600 control token submit raw txs over loopback "
           "(local budget 200 injects / 8 MiB per 60 s, pool 1024 entries / 400000 B).\n"
           "It also opens the peer tx_inject sink: sharechain peers may push injects, each through a separate "
           "peer budget, the sandbox, the pool caps and the full admission gate including the script check.\n"
           "It does not expose the reward path, any key, config writes without token + two-phase nonce, or "
           "off-box HTTP; a runtime arm does not survive a node restart (the unit flag does).";
}

} // namespace c2w::companion::sched::arm
