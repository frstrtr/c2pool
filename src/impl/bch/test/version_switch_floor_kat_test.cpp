// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch version-switch accept gate: floored-threshold KAT.
//
// Pins bch::version_switch_underweight (src/impl/bch/version_switch_gate.hpp),
// the LIVE predicate bch::check_share uses for an upgrade boundary share,
// against the p2pool-merged-v36 oracle (data.py check()):
//
//     counts.get(self.VERSION, 0) < sum(counts)*60//100   -> reject
//
// The oracle floors the threshold before comparing. The pre-fix inline form
// `new_ver_weight*100 < total_weight*60` compared against the exact 0.6*T, so
// whenever 0.6*T is not a whole number and new_ver_weight == floor(0.6*T) it
// rejected a boundary share the oracle admits. The boundary vectors below all
// have a fractional 0.6*T; the expected verdicts are hand-computed constants,
// not re-derived from the formula under test.
//
// RED on the pre-fix form (the C-boundary admits fail), GREEN with the floor.
//
// MUST appear in BOTH this dir's CMakeLists.txt AND both build.yml COIN_BCH
// --target lists, or it silently never builds.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include <core/uint256.hpp>
#include <impl/bch/version_switch_gate.hpp>

namespace {

int failures = 0;
void check(bool cond, const char* label)
{
    std::cout << (cond ? "  PASS  " : "  FAIL  ") << label << "\n";
    if (!cond) ++failures;
}

bool admitted(const uint288& a, const uint288& t)
{
    return !bch::version_switch_underweight(a, t);
}

// The pre-fix inline form, kept ONLY as a negative control: it must disagree
// with the oracle on every C-boundary vector, otherwise the vectors no longer
// discriminate floor-vs-exact and this KAT would pass on the old code.
bool prefix_admitted(const uint288& a, const uint288& t)
{
    return !((a * static_cast<uint32_t>(100)) < (t * static_cast<uint32_t>(60)));
}

struct Boundary { uint64_t total; uint64_t floor_60pct; const char* admit_label; const char* reject_label; };

} // namespace

int main()
{
    std::cout << "[bch version-switch floor KAT]\n";

    // -- C-boundary: 0.6*T fractional; a == floor(0.6*T) ADMITTED, one below REJECTED.
    const Boundary vectors[] = {
        {    7,   4, "T=7    (0.6T=4.2):   a=4   -> ADMIT", "T=7    (0.6T=4.2):   a=3   -> REJECT"},
        {  101,  60, "T=101  (0.6T=60.6):  a=60  -> ADMIT", "T=101  (0.6T=60.6):  a=59  -> REJECT"},
        { 1003, 601, "T=1003 (0.6T=601.8): a=601 -> ADMIT", "T=1003 (0.6T=601.8): a=600 -> REJECT"},
    };
    for (const auto& v : vectors) {
        const uint288 t(v.total), at(v.floor_60pct), below(v.floor_60pct - 1);
        check( admitted(at, t),    v.admit_label);
        check(!admitted(below, t), v.reject_label);
        check(!prefix_admitted(at, t), "  negative control: pre-fix exact form rejects a == floor(0.6T)");
    }

    // -- C-boundary-wide: real work weights are ~2^256-scale uint288 sums.
    // T = 2^256 + 1 -> T*60//100 = 0x99..9a (64 hex digits), remainder 20.
    {
        const uint288 t = (uint288(1) << 256) + uint288(1);
        const uint288 at("999999999999999999999999999999999999999999999999999999999999999a");
        const uint288 below = at - uint288(1);
        check( admitted(at, t),        "T=2^256+1: a == floor(0.6T) -> ADMIT (no uint288 overflow)");
        check(!admitted(below, t),     "T=2^256+1: a == floor(0.6T)-1 -> REJECT");
        check(!prefix_admitted(at, t), "  negative control: pre-fix exact form rejects a == floor(0.6T)");
    }

    // -- C-integral: 0.6*T whole -> floor and exact agree (no behaviour change).
    {
        check( admitted(uint288(60),  uint288(100)), "T=100: a=60 -> ADMIT");
        check(!admitted(uint288(59),  uint288(100)), "T=100: a=59 -> REJECT");
        check( admitted(uint288(21),  uint288(35)),  "T=35:  a=21 -> ADMIT (3 of 5 equal-work miners)");
        check(!admitted(uint288(14),  uint288(35)),  "T=35:  a=14 -> REJECT");
        check( admitted(uint288(100), uint288(100)), "T=100: a=100 -> ADMIT");
        check(!admitted(uint288(0),   uint288(1000)),"all-old window -> REJECT");
    }

    // -- C-empty: T == 0 evaluates 0 < 0 == false -> ADMITTED, same as the
    // oracle. Parity pin only; hardening is the v37 tracker #906.
    check(admitted(uint288(0), uint288(0)), "empty window (T=0) -> ADMIT (oracle parity, #906 = v37)");

    std::cout << (failures ? "[FAIL] " : "[OK] ")
              << "bch version-switch floor KAT, " << failures << " failure(s)\n";
    return failures ? 1 : 0;
}
