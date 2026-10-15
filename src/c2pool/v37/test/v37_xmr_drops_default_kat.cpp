// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See <https://www.gnu.org/licenses/>.
//
// v37_xmr_drops_default_kat -- XMR-DROPS-DEFAULT (operator ruling 09-27:
// "raindrops should be default"). The XMR node and its KATs are built with the
// V37.1 activation (src/c2pool/CMakeLists.txt c2pool_xmr_drops_default); every
// other coin keeps the flip at 0. Pins:
//   DD1  the XMR build is armed: kActivateConsensusV1, kDropsWiringArmed, the
//        default XmrNodeConfig lane = the DROPS gate of for_version(1) with the
//        Count estimator (mode 2, floor shift 6), the fee model off, and
//        make_drops_wiring(default lane) armed.
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

    std::printf("-- DD1 the XMR build arms raindrops by default\n");
    const ::c2pool::v37n::xmr::XmrNodeConfig cfg;
    const ::v37::LaneParams on = ::v37::LaneParams::for_version(1);
#ifdef V37_XMR_DROPS_DEFAULT
    check(true, "DD1 V37_XMR_DROPS_DEFAULT is defined for this XMR target (CMake c2pool_xmr_drops_default)");
#else
    check(false, "DD1 V37_XMR_DROPS_DEFAULT is defined for this XMR target (CMake c2pool_xmr_drops_default)");
#endif
    check(n37::kActivateConsensusV1 && n37::kDropsWiringArmed && n37::kActivationArity == 1,
          "DD1 kActivateConsensusV1 && kDropsWiringArmed at arity 1 (DROPS only, ridge OFF)");
    check(cfg.lane_params.subthreshold.enabled && cfg.lane_params.subthreshold.K == on.subthreshold.K &&
          cfg.lane_params.subthreshold.version == on.subthreshold.version,
          "DD1 XmrNodeConfig{}.lane_params carries the DROPS gate of for_version(1) (K=" +
          std::to_string(cfg.lane_params.subthreshold.K) + ")");
    check(cfg.lane_params.subthreshold.mode == 2 && cfg.lane_params.subthreshold.count_floor_shift == 6,
          "DD1 the default XMR lane credits raindrops by Count (mode 2, floor shift 6)");
    check(!cfg.lane_params.fee.enabled, "DD1 the fee model stays opt-in (--fee-model v1)");
    check(n37::make_drops_wiring(cfg.lane_params).has_value(), "DD1 make_drops_wiring(default lane) is armed");

    std::printf("== v37_xmr_drops_default_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
