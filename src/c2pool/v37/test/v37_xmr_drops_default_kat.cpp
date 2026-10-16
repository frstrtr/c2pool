// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See <https://www.gnu.org/licenses/>.
//
// v37_xmr_drops_default_kat -- raindrops are off in the default XMR build
// (src/c2pool/CMakeLists.txt option V37_XMR_DROPS_DEFAULT OFF; no XMR target
// defines V37_ACTIVATE_CONSENSUS_V1). Pins:
//   DD1  V37_XMR_DROPS_DEFAULT is not defined; kActivateConsensusV1 and
//        kDropsWiringArmed are false; the default XmrNodeConfig lane carries no
//        DROPS gate, the fee model is off, and make_drops_wiring(default lane)
//        is not armed.
#include <cstdio>
#include <cstdlib>
#include <string>

#include <c2pool/v37/v37_node_lane_activation.hpp>
#include <c2pool/v37/v37_drops_wiring.hpp>
#include <c2pool/v37/xmr/xmr_node_config.hpp>

namespace n37 = ::c2pool::v37n;

static int g_fail = 0, g_pass = 0;
static void check(bool ok, const std::string& what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    (ok ? g_pass : g_fail)++;
}

int main() {
    std::printf("v37_xmr_drops_default_kat (V37_ACTIVATE_CONSENSUS_V1=%d, kDropsWiringArmed=%d)\n",
                (int)V37_ACTIVATE_CONSENSUS_V1, (int)n37::kDropsWiringArmed);

    std::printf("-- DD1 the default XMR build leaves raindrops off\n");
    const ::c2pool::v37n::xmr::XmrNodeConfig cfg;
#ifdef V37_XMR_DROPS_DEFAULT
    check(false, "DD1 V37_XMR_DROPS_DEFAULT is not defined for this XMR target (CMake option OFF)");
#else
    check(true, "DD1 V37_XMR_DROPS_DEFAULT is not defined for this XMR target (CMake option OFF)");
#endif
    check(!n37::kActivateConsensusV1 && !n37::kDropsWiringArmed,
          "DD1 kActivateConsensusV1 and kDropsWiringArmed are false");
    check(!cfg.lane_params.subthreshold.enabled, "DD1 XmrNodeConfig{}.lane_params carries no DROPS gate");
    check(!cfg.lane_params.fee.enabled, "DD1 the fee model is off");
    check(!n37::make_drops_wiring(cfg.lane_params).has_value(), "DD1 make_drops_wiring(default lane) is not armed");

    std::printf("== v37_xmr_drops_default_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
