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
//        default XmrNodeConfig lane = for_version(1) + the Count estimator
//        (DROPS ON, ridge OFF), and
//        the DROPS bundle is constructed from it (make() non-null).
//   DD2  HELLO: pool rules v3; a raindrops-OFF node (pool rules v2, bare
//        LaneParams{}) is refused BOTH directions as TAG_MISMATCH field=version
//        naming DROPS; a same-rules peer with DROPS off is refused on
//        lane_params_digest; two default nodes stay compatible.
//   DD3  d5: split_give_author splits a composed delta the way the receipts
//        split (payee 65535-d, donation d), conserving, both signs, folded base
//        included, donation row never re-split, zero rows dropped.
//   DD4  the shell applies DD3 under the fee model and records the u16 (source).
//   DD5  DROPS-AUTO-ENROL: auto (default) enrols every payee at its first lane
//        share; list / none unchanged / nobody; HELLO names a mode mismatch.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include <c2pool/v37/v37_node_lane_activation.hpp>
#include <c2pool/v37/v37_drops_wiring.hpp>
#include <c2pool/v37/xmr/xmr_node_config.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>

namespace n37 = ::c2pool::v37n;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace rl = ::c2pool::v37n::xmr::relay;
using ::v37::bytes32;

static int g_fail = 0, g_pass = 0;
static void check(bool ok, const std::string& what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    (ok ? g_pass : g_fail)++;
}
static bytes32 key(int i) { bytes32 k{}; k[0] = 0xD0; k[31] = static_cast<std::uint8_t>(i); return k; }
static std::string slurp(const char* p) { std::ifstream f(p); std::stringstream s; s << f.rdbuf(); return s.str(); }

static rl::Hello hello_of(const ::v37::LaneParams& p, std::uint32_t rules, std::uint64_t nonce) {
    rl::Hello h;
    h.network = 3; h.chain_id = 7; h.share_diff = 8; h.node_nonce = nonce; h.bind = rl::BindMode::None;
    h.lane_params_digest = rl::lane_params_digest(p, h.share_diff, h.bind, h.network);
    h.pool = rl::pool_id_of(h.chain_id, p, rules);
    h.pool->genesis = key(0x6E);
    return h;
}

int main() {
    std::printf("v37_xmr_drops_default_kat (V37_ACTIVATE_CONSENSUS_V1=%d, kDropsWiringArmed=%d, pool rules v%u)\n",
                (int)V37_ACTIVATE_CONSENSUS_V1, (int)n37::kDropsWiringArmed, (unsigned)rl::kXmrPoolRulesVersion);

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
    // The XMR default is for_version(1) with the Count estimator in place of
    // K-min (mode 2, the drops floor shift 6): nothing else differs.
    ::v37::LaneParams on_count = on;
    on_count.subthreshold.mode = ::c2pool::v37n::xmr::kXmrCreditModeCount;
    on_count.subthreshold.count_floor_shift = ::c2pool::v37n::xmr::kXmrDropsFloorShift;
    check(cfg.lane_params.subthreshold.mode == 2 && cfg.lane_params.subthreshold.count_floor_shift == 6,
          "DD1 the default XMR lane credits raindrops by Count (mode 2, floor shift 6)");
    check(rl::lane_params_digest(cfg.lane_params, 8, rl::BindMode::None, 3) == rl::lane_params_digest(on_count, 8, rl::BindMode::None, 3),
          "DD1 the default lane is field-for-field for_version(1) + Count on the HELLO digest (no ridge, no fee)");
    check(rl::lane_params_digest(cfg.lane_params, 8, rl::BindMode::None, 3) != rl::lane_params_digest(on, 8, rl::BindMode::None, 3),
          "DD1 a K-min (mode 1) XMR node is refused on lane_params_digest");
    check(!cfg.lane_params.fee.enabled, "DD1 the fee model stays opt-in (--fee-model v1)");
    auto w = dx::XmrDropsWiring::make(cfg.lane_params, 8, rl::kReceiptWeight);
    check(w != nullptr && w->floor_diff() == dx::drops_floor_diff(8), "DD1 XmrDropsWiring::make(default lane) builds the bundle");
    check(n37::make_drops_wiring(cfg.lane_params).has_value(), "DD1 make_drops_wiring(default lane) is armed");
    check(dx::XmrDropsWiring::make(::v37::LaneParams{}, 8, rl::kReceiptWeight) == nullptr,
          "DD1 a lane without the gate still builds nothing (fail-closed)");

    std::printf("-- DD2 HELLO refuses a raindrops-OFF node by name\n");
    check(rl::kXmrPoolRulesVersion == rl::kXmrPoolRulesVersionDropsOn && rl::kXmrPoolRulesVersion == 3,
          "DD2 this XMR build HELLOs pool rules v3");
    check(rl::node_pool_id(7, cfg.lane_params) == rl::pool_id_of(7, cfg.lane_params, 3), "DD2 node_pool_id folds v3");
    const rl::Hello ours = hello_of(cfg.lane_params, rl::kXmrPoolRulesVersion, 1);
    const rl::Hello ours2 = hello_of(cfg.lane_params, rl::kXmrPoolRulesVersion, 2);
    const rl::Hello old = hello_of(::v37::LaneParams{}, rl::kXmrPoolRulesVersionDropsOff, 3);   // the pre-default XMR HELLO
    const std::string r1 = rl::hello_mismatch(ours, old), r2 = rl::hello_mismatch(old, ours);
    std::printf("    ours vs raindrops-OFF: \"%s\"\n    reverse: \"%s\"\n", r1.c_str(), r2.c_str());
    check(rl::is_tag_mismatch(r1) && r1.find("field=version") != std::string::npos &&
          r1.find("raindrops (DROPS) OFF") != std::string::npos,
          "DD2 a raindrops-OFF peer is refused: TAG_MISMATCH field=version, reason names DROPS OFF");
    check(rl::is_tag_mismatch(r2) && r2.find("field=version") != std::string::npos &&
          r2.find("raindrops (DROPS) ON") != std::string::npos,
          "DD2 the reverse direction (a DROPS-off node seeing us) is refused by name too");
    const rl::Hello off_same_rules = hello_of(::v37::LaneParams{}, rl::kXmrPoolRulesVersion, 4);
    const std::string r3 = rl::hello_mismatch(ours, off_same_rules);
    check(!r3.empty() && r3.find("lane_params_digest differs") != std::string::npos && r3.find("DROPS") != std::string::npos,
          "DD2 same rules, DROPS gate off: refused on lane_params_digest (\"" + r3 + "\")");
    check(rl::hello_mismatch(ours, ours2).empty(), "DD2 two default XMR nodes stay HELLO-compatible");
    check(rl::pool_rules_reason(2, 1).find("pre-#1803") != std::string::npos, "DD2 the pre-#1803 reason is kept");

    std::printf("-- DD3 d5: the composed delta splits like the receipts (payee 65535-d, donation d)\n");
    const bytes32 P = key(1), Q = key(2), R = key(3), DON = key(0x77);
    dx::LanePrefix lp;
    lp.shares = {{P, 10, 66}, {P, 11, 66}, {P, 12, 66}, {Q, 10, 0}, {R, 11, 655}};
    lp.base_give[R] = {655, 1};   // one folded receipt of R at d=655
    std::map<bytes32, long long> d{{P, 1'000'000}, {Q, 5'000}, {R, -400'000}, {key(9), 12'345}};
    long long before = 0; for (const auto& [k, v] : d) before += v;
    dx::split_give_author(d, lp, DON);
    long long after = 0; for (const auto& [k, v] : d) after += v;
    const long long dp = 1'000'000LL * 66 * 3 / (3 * 65535), dr = -(400'000LL * 655 * 2 / (2 * 65535));
    check(d[P] == 1'000'000 - dp && dp == 1007, "DD3 payee P (d=66): v - trunc(v*66/65535) = " + std::to_string(d[P]));
    check(d[Q] == 5'000, "DD3 payee Q (d=0): unchanged");
    check(d[R] == -400'000 - dr && dr == -3997, "DD3 negative delta splits with truncation toward zero (R " + std::to_string(d[R]) + ")");
    check(d[key(9)] == 12'345, "DD3 a payee with no receipt on the prefix: unchanged");
    check(d[DON] == dp + dr, "DD3 the donation row = the sum of the split slices (" + std::to_string(d[DON]) + ")");
    check(before == after, "DD3 conserving: row sum unchanged (" + std::to_string(before) + ")");
    std::map<bytes32, long long> z{{P, 1}, {DON, 50}};
    dx::split_give_author(z, lp, DON);
    check(z.size() == 2 && z[P] == 1 && z[DON] == 50, "DD3 the donation row is never re-split; a slice of 0 adds no row");
    std::map<bytes32, long long> zz{{P, 0}};
    dx::split_give_author(zz, lp, DON);
    check(zz.empty(), "DD3 zero rows are dropped (canonical carriage)");

    std::printf("-- DD5 DROPS-AUTO-ENROL: auto (default) / list / none, and HELLO names a mode mismatch\n");
    {
        using rl::EnrolMode;
        dx::LanePrefix ep;
        ep.shares = {{P, 12, 0}, {Q, 10, 0}, {P, 11, 0}, {R, 14, 0}};
        ep.base_first[key(5)] = 3;   // a folded payee (first share at bin 3)
        const auto a = dx::lane_enrollment(ep, {}, EnrolMode::Auto);
        const auto* ap = a.find(P); const auto* aq = a.find(Q); const auto* ar = a.find(R); const auto* a5 = a.find(key(5));
        check(ap && aq && ar && a5 && ap->effective_from == 12 && aq->effective_from == 11 && ar->effective_from == 15 &&
              a5->effective_from == 4,
              "DD5 auto: EVERY payee of the prefix (folded base included) enrols at its first share, effective bin+1");
        const auto l = dx::lane_enrollment(ep, {P}, EnrolMode::List);
        check(l.find(P) && !l.find(Q) && !l.find(R) && l.book_digest() == dx::lane_enrollment(ep, {P}).book_digest(),
              "DD5 list: only the listed payee, byte-identical to the pre-auto rule");
        check(dx::lane_enrollment(ep, {P, Q}, EnrolMode::None).book_digest() == ::c2pool::v37n::empty_enrollment_digest() &&
              dx::lane_enrollment(ep, {}).book_digest() == ::c2pool::v37n::empty_enrollment_digest(),
              "DD5 none: nobody (and the pre-auto empty list is still the empty book)");
        check(dx::enrol_mode_digest(EnrolMode::List, {P, Q}) == dx::enrol_set_digest({P, Q}) &&
              dx::hello_digest_with_enrol(key(40), EnrolMode::List, {P, Q}) == dx::hello_digest_with_enrol(key(40), {P, Q}),
              "DD5 list mode HELLO digests are byte-identical to the list-only builds");
        auto hm = [&](EnrolMode m, std::set<bytes32> s, std::uint64_t nonce) {
            rl::Hello h = hello_of(cfg.lane_params, rl::kXmrPoolRulesVersion, nonce);
            h.lane_params_digest = dx::hello_digest_with_enrol(h.lane_params_digest, m, s);
            h.enrol_set = dx::enrol_mode_digest(m, s);
            return h;
        };
        const auto au1 = hm(EnrolMode::Auto, {}, 11), au2 = hm(EnrolMode::Auto, {}, 12);
        const auto li = hm(EnrolMode::List, {P, Q}, 13), no = hm(EnrolMode::None, {}, 14);
        const std::string m1 = rl::hello_mismatch(au1, li), m2 = rl::hello_mismatch(au1, no), m3 = rl::hello_mismatch(li, no);
        std::printf("    auto vs list: \"%s\"\n", m1.c_str());
        check(rl::hello_mismatch(au1, au2).empty(), "DD5 two auto nodes stay HELLO-compatible");
        check(m1.rfind(rl::kEnrolSetMismatch, 0) == 0 && m1.find("ours=auto") != std::string::npos && m1.find("theirs=list") != std::string::npos,
              "DD5 auto vs list: refused ENROL_SET_MISMATCH naming both modes");
        check(m2.rfind(rl::kEnrolSetMismatch, 0) == 0 && m2.find("ours=auto") != std::string::npos && m2.find("theirs=none") != std::string::npos,
              "DD5 auto vs none: refused by name");
        check(m3.rfind(rl::kEnrolSetMismatch, 0) == 0 && m3.find("ours=list") != std::string::npos && m3.find("theirs=none") != std::string::npos,
              "DD5 list vs none: refused by name");
    }

    std::printf("-- DD4 the shell wires it (source)\n");
#ifdef V37_XMR_SHELL_SRC
    const std::string src = slurp(V37_XMR_SHELL_SRC);
    check(src.find("if (c2pool::v37n::xmr::fee::fee_model_on(cfg.lane_params))   // ★ d5") != std::string::npos &&
          src.find("drops::split_give_author(out.carry.delta, *lp,") != std::string::npos,
          "DD4 drops_compose_lane splits the composed delta under the fee model");
    check(src.find("a.r.side.give_author);   // ★ d5") != std::string::npos &&
          src.find("(void)relay_node->cached(id, nullptr, &give);") != std::string::npos,
          "DD4 own and repaired lane prefixes carry the receipt's give-author u16");
    check(src.find("g_drops_enrol.empty() ? relay::EnrolMode::Auto : relay::EnrolMode::List") != std::string::npos &&
          src.find("drops->set_enrol_mode(emode);") != std::string::npos &&
          src.find("enrol_mode_digest(drops->enrol_mode(), drops->enrol_set())") != std::string::npos,
          "DD4 the shell defaults to AUTO (no --drops-enrol), sets the mode and carries the mode digest in HELLO");
#else
    check(false, "DD4 V37_XMR_SHELL_SRC defined");
#endif
    std::printf("== v37_xmr_drops_default_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
