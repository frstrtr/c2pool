// SPDX-License-Identifier: AGPL-3.0-or-later
//
// THE DRAIN RULE's arithmetic, dependency-free (the X6 allocator, the XMR
// settlement source and the node config's knob check all read it).
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace v37 {
namespace xmr {
namespace settle {

// ---------------------------------------------------------------------------
// THE DRAIN RULE (operator rulings R1/R2, 2026-10-02; docs/xmr-lane/
// settlement-drain.md). Old balances are paid only out of a bounded slice of
// the block, Delta; the window's E_b is split at P = R - debt_paid and paid in
// full when everyone fits, so a canonical block creates no new balance.
//
//     Delta = min(F, floor(R * min(dh, H_cap) / (Q * kDrainRefCadence)))
//
// F = SUM max(0, EffectiveOwed) over the whole ledger, dh = Monero heights
// since this pool's previous lane block (a ledger fact), Q and H_cap the lane
// rules drain_q / drain_h_cap. kDrainRefCadence is the P2Pool-main lane-block
// cadence the operator's "1/16 of a block" is normalised at (rule version 1:
// R / 256 per Monero height); changing it is a new rule version. u128
// product, floor division. Q == 0 => 0 (no drain: master).
inline constexpr std::uint64_t kDrainRefCadence = 16;
inline constexpr std::uint32_t kDrainRuleVersion = 1;   // the newest drain rule this build implements
inline std::uint64_t drain_delta(std::uint64_t F, std::uint64_t R, std::uint64_t dh,
                                 std::uint32_t q, std::uint32_t h_cap) {
    if (q == 0 || h_cap == 0 || F == 0) return 0;
    const std::uint64_t eff = (dh == 0 || dh > h_cap) ? h_cap : dh;   // dh == 0: no predecessor => the cap
    const unsigned __int128 num = static_cast<unsigned __int128>(R) * eff;
    const unsigned __int128 den = static_cast<unsigned __int128>(q) * kDrainRefCadence;
    const unsigned __int128 d = num / den;
    return d < F ? static_cast<std::uint64_t>(d) : F;
}
// Rule-version-1 validity of (version, Q, H_cap): 0/0/0 is master; version 1
// needs Q >= 1 and 1 <= H_cap < Q * kDrainRefCadence, so Delta < R and the
// owed pass can never take every slot (nobody admitted is unreachable).
// Returns "" when valid, else the reason.
inline const char* drain_rule_refusal(std::uint32_t version, std::uint32_t q, std::uint32_t h_cap) {
    if (version == 0) return (q == 0 && h_cap == 0) ? "" : "drain_q / drain_h_cap set while drain_rule_version is 0";
    if (version > kDrainRuleVersion) return "a newer drain rule version than this build implements: upgrade";
    if (q == 0) return "drain_rule_version 1 needs drain_q >= 1";
    if (h_cap == 0) return "drain_rule_version 1 needs drain_h_cap >= 1";
    if (static_cast<std::uint64_t>(h_cap) >= static_cast<std::uint64_t>(q) * kDrainRefCadence)
        return "drain_h_cap must stay below drain_q * 16 (Delta < R: the window always keeps part of the block)";
    return "";
}

// The builder's reward fixpoint. The owed takes are chosen at Delta(R), so a
// template must be cut at its own FINAL reward (every receiver recomputes at
// the coinbase total: takes chosen at another reward are an over- or
// under-take). The payee set can move the reward through the coinbase weight,
// so the provider rebuilds at the reward the template settled on until the two
// agree. `rebuild(hint, why)` cuts the settlement source at `hint`, assembles,
// and returns the template's reward (nullopt + why = a refusal). At most
// kDrainFixpointPasses rebuilds; beyond that the template fails closed and is
// not served. Rule off: no rebuild (master). On success hint == reward.
inline constexpr int kDrainFixpointPasses = 4;
template <class Rebuild>
inline bool drain_reward_fixpoint(bool drain_on, std::uint64_t& hint, std::uint64_t& reward, Rebuild&& rebuild,
                                  std::string& why, int* passes_out = nullptr) {
    int pass = 0;
    for (; drain_on && reward != hint; ++pass) {
        if (pass >= kDrainFixpointPasses) {
            why = "drain rule: no reward fixpoint within " + std::to_string(kDrainFixpointPasses) + " passes (snapshot at " +
                  std::to_string(hint) + ", template reward " + std::to_string(reward) + ")";
            if (passes_out) *passes_out = pass;
            return false;
        }
        hint = reward;
        const std::optional<std::uint64_t> r = rebuild(hint, why);
        if (!r) { if (passes_out) *passes_out = pass + 1; return false; }
        reward = *r;
    }
    if (passes_out) *passes_out = pass;
    return true;
}

} // namespace settle
} // namespace xmr
} // namespace v37
