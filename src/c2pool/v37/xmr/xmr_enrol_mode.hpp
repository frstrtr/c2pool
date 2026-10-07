#pragma once
// DROPS-AUTO-ENROL: the XMR pool's enrolment mode and its HELLO tag. A leaf
// header (no relay / impl includes) shared by xmr_relay_wire.hpp (the HELLO
// refusal names the mode) and xmr_drops_wiring.hpp (the lane enrolment rule).
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32, ::v37::sha256d

namespace c2pool::v37n::xmr::relay {

// ★ DROPS-AUTO-ENROL (operator ruling 09-27): the pool's enrolment MODE.
//   Auto = no --drops-enrol list: every payee enrols at its first share on the
//          lane prefix (the #1805 lane rule, no set filter) -- the default;
//   List = an explicit --drops-enrol list: only those payees (unchanged);
//   None = --drops-enrol none: nobody (DROPS armed, credits zero).
// The HELLO enrol-set digest encodes the mode: List = enrol_set_digest(list)
// (byte-identical to the list-only builds), Auto / None = a domain tag. So two
// nodes in different modes are refused at HELLO by name.
enum class EnrolMode : std::uint8_t { Auto = 0, List = 1, None = 2 };
inline const char* to_string(EnrolMode m) { return m == EnrolMode::Auto ? "auto" : m == EnrolMode::List ? "list" : "none"; }
inline ::v37::bytes32 enrol_mode_tag(EnrolMode m) {   // Auto / None only (List carries the set digest)
    const char* dom = m == EnrolMode::Auto ? "V37ENROLAUTO1" : "V37ENROLNONE1";
    std::vector<std::uint8_t> b(dom, dom + std::strlen(dom));
    return ::v37::sha256d(b);
}

// DROPS RULE FLAG DAY (handoff A3 + A5, ruling 2026-09-30). The DROPS due
// (A5, "V37U") and the raindrop enrolment registry (A3, "V37G") change what a
// lane block books and what its coinbase pays, so a node with another rule set
// can never fold the same lane. With either rule on, the HELLO enrol digest
// carries the rule tag (like kFeeLanePushRule in the fee-model gate): a mixed
// fleet is refused at HELLO by name (DROPS_RULE_MISMATCH) instead of by lane
// root refusals. Rule 0 (both off, the gate-OFF node) leaves the digest
// byte-identical.
inline constexpr std::uint32_t kDropsRuleDue = 1;            // A5: the DROPS due in the ledger
inline constexpr std::uint32_t kDropsRuleRaindropEnrol = 2;  // A3: enrolment by raindrop, registry in the ledger
// A4b (ruling 2026-10-01, "Window price"): DROPS work is window weight, paid in
// every lane block of its window ("V37W"), never priced once. A node with it
// and a node without it split the same lane block differently: a separate bit,
// so a fleet mixing the A5 rule (tag 3) and the window rule (tag 7) is refused
// at HELLO by name.
inline constexpr std::uint32_t kDropsRuleWindow = 4;
inline std::uint32_t drops_rule_tag(bool due, bool raindrop_enrol, bool window = false) {
    return (due ? kDropsRuleDue : 0u) | (raindrop_enrol ? kDropsRuleRaindropEnrol : 0u) |
           (window ? kDropsRuleWindow : 0u);
}
inline std::string drops_rule_label(std::uint32_t r) {
    if (r == 0) return "none (pre-A5 rules)";
    std::string s;
    if (r & kDropsRuleDue) s += "due";
    if (r & kDropsRuleRaindropEnrol) s += s.empty() ? "raindrop-enrol" : "+raindrop-enrol";
    if (r & kDropsRuleWindow) s += s.empty() ? "window" : "+window";
    if (r & ~(kDropsRuleDue | kDropsRuleRaindropEnrol | kDropsRuleWindow)) s += (s.empty() ? "" : "+") + std::string("unknown");
    return s;
}
// The rule-tagged enrol digest: sha256d("V37ENROLRULE2" || base || u32 rule)
// with its last four bytes set to 'D' 'R' '2' rule, so a receiver reads the
// peer's rule back and names it. rule 0 = `base`, unchanged.
inline ::v37::bytes32 enrol_rule_digest(const ::v37::bytes32& base, std::uint32_t rule) {
    if (rule == 0) return base;
    const char* dom = "V37ENROLRULE2";
    std::vector<std::uint8_t> b(dom, dom + std::strlen(dom));
    b.insert(b.end(), base.begin(), base.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((rule >> (8 * i)) & 0xff));
    ::v37::bytes32 d = ::v37::sha256d(b);
    d[28] = 'D'; d[29] = 'R'; d[30] = '2'; d[31] = static_cast<std::uint8_t>(rule & 0xff);
    return d;
}
// The rule a HELLO enrol digest carries (0 = untagged: gate-OFF or a pre-A5 build).
inline std::uint32_t enrol_rule_of(const ::v37::bytes32& d) {
    return (d[28] == 'D' && d[29] == 'R' && d[30] == '2') ? d[31] : 0u;
}

}  // namespace c2pool::v37n::xmr::relay
