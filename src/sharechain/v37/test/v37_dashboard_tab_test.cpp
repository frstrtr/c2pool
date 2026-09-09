// V37 dashboard frozen tab-descriptor — pinning KAT (task #926).
//
// Freezes the renderer<->steward contract: field set, field order, canonical
// serialization, and the derived pin digests. If any of these changes the
// golden hex below changes and this test fails — which is the whole point: the
// shape is not allowed to drift silently under the renderer.

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include "../v37_dashboard_tab.hpp"

namespace {

std::string hex(const v37::bytes32& d) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (unsigned char b : d) {
        s.push_back(k[b >> 4]);
        s.push_back(k[b & 0xf]);
    }
    return s;
}

int failures = 0;
void check(bool ok, const char* what) {
    if (!ok) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

}  // namespace

int main() {
    // --- Golden single record --------------------------------------------
    // A live DASH lane bound to its data route.
    const v37::DashboardTab dash{"dash", "DASH", true, "/api/v37/lane/dash"};
    check(hex(v37::pin_digest(dash)) ==
              "03a739ad5ccd1d1be5e0e0359e127147ffb5ba938cbd8c4bf19c42cac8531bf6",
          "single-record pin digest");

    // --- Field semantics are load-bearing in the digest ------------------
    // symbol is display-only but still part of the frozen shape: changing it
    // changes the pin (the contract covers the full record, not just identity).
    v37::DashboardTab dash_relabel = dash;
    dash_relabel.symbol = "XDASH";
    check(v37::pin_digest(dash_relabel) != v37::pin_digest(dash),
          "symbol participates in the frozen shape");

    // active flips the liveness byte -> different pin.
    v37::DashboardTab dash_idle = dash;
    dash_idle.active = false;
    check(v37::pin_digest(dash_idle) != v37::pin_digest(dash),
          "active participates in the frozen shape");

    // coin is the identity/join key.
    check((dash < v37::DashboardTab{"digibyte", "", false, ""}),
          "ordering is by coin (identity key)");

    // Honesty rule: an unknown lane carries an EMPTY coin (renderer shows
    // "unknown"), and an unasserted ticker is empty (never fabricated).
    const v37::DashboardTab unknown{"", "", false, ""};
    check(unknown.coin.empty() && unknown.symbol.empty(),
          "unknown lane leaves coin/symbol empty (no fabrication)");

    // Consistency invariant: an unbound source (empty location) cannot be live.
    check(v37::DashboardTab{"btc", "BTC", true, "/x"}.is_consistent(),
          "live + bound source is consistent");
    check(!v37::DashboardTab{"btc", "BTC", true, ""}.is_consistent(),
          "live + empty location is inconsistent");
    check(v37::DashboardTab{"btc", "BTC", false, ""}.is_consistent(),
          "idle + empty location is consistent");

    // --- Golden tab set (ordered) ----------------------------------------
    // The renderer's tab order is part of the pin: a reorder is a different set.
    const std::vector<v37::DashboardTab> set{
        {"bitcoin", "BTC", true, "/api/v37/lane/bitcoin"},
        {"dash", "DASH", true, "/api/v37/lane/dash"},
        {"digibyte", "DGB", false, ""},  // configured-but-idle lane
    };
    check(hex(v37::pin_digest(set)) ==
              "c630d2516d805e2c6420290caa377b7c82e2fe31696167a8afd2236cf8ff5b1d",
          "tab-set pin digest");

    std::vector<v37::DashboardTab> reordered{set[1], set[0], set[2]};
    check(v37::pin_digest(reordered) != v37::pin_digest(set),
          "tab-set pin is order-sensitive");

    if (failures == 0) {
        std::printf("v37_dashboard_tab: all checks passed\n");
        return 0;
    }
    std::printf("v37_dashboard_tab: %d check(s) FAILED\n", failures);
    return 1;
}
