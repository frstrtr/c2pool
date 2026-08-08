// SPDX-License-Identifier: AGPL-3.0-or-later
// D1 regression gate — the 2026-08-07/08 hotel freeze (0 of 26 rigs, twice).
//
// Root cause (three identical gdb stacks 5 s apart on the live node):
//   StratumSession::handle_submit -> DASHWorkSource::get_current_gbt_prevhash
//   -> cached_work() -> NodeCoinState::embedded_template_emit_ok()
//   -> CSimplifiedMNList::CalcMerkleRoot() -> CSHA256
// ~17 submits/s x ~2000 masternodes = ~68k SHA256d/s on the single io thread;
// the stratum recvQ grew 7 -> 62 MB and the served tip froze.
//
// THE PIN: a submit-path tip READ (get_current_gbt_prevhash) must be a pure
// template_mutex_-guarded peek of the cached snapshot — it must NEVER evaluate
// the serve gate (embedded_template_emit_ok), reset the cache, or re-source.
// NodeCoinState counts gate EVALUATIONS at the top of emit_ok (before any
// early return), so the pin holds regardless of whether the gate passes.
//
// Constructed RED on the pre-fix master: there, every get_current_gbt_prevhash
// routed through cached_work()'s fresh-cache branch, which re-evaluates
// emit_ok on an embedded cache hit — 100 reads == 100 gate evaluations.
//
// Builds into the test_dash_stratum_work_source executable (same harness /
// legacy inline path — no refresh executor wired — as
// test_dash_stratum_work_source.cpp).

#include <impl/dash/stratum/work_source.hpp>

#include <impl/dash/coin/mn_state_db.hpp>   // MNState (resolvable payee, #996 gate)

#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

// Mirrors the C1-gate fixtures in test_dash_stratum_work_source.cpp (those
// helpers live in that TU's anonymous namespace, so they are re-stated here):
// a populated coin-state whose embedded template serves on the testnet arm.
const char* const kEmbPrevHashHex =
    "0000000000000000abcdef0123456789abcdef0123456789abcdef0123456789";
constexpr uint32_t kEmbPrevHeight = 500000u;   // embedded template -> +1
constexpr uint32_t kCurtime       = 1751000000u;
constexpr int32_t  kVersion       = 0x20000000;

std::vector<unsigned char> p2pkh_script()
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0x11);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// #996 fail-closed guard: seed ONE live MN so the embedded arm is genuinely
// viable (a payee is resolvable at the tip) and the arm under test is the
// embedded one, not a masked refusal.
void seed_resolvable_mn(dash::coin::NodeCoinState& cs)
{
    dash::coin::MNState mn;
    mn.isValid           = true;              // eligible (nPoSeBanHeight == 0)
    mn.nRegisteredHeight = 1;                 // a positive payment-queue slot
    mn.collateralOutpoint.hash.SetHex(std::string(64, '9'));
    mn.collateralOutpoint.index = 0;
    mn.scriptPayout.m_data = p2pkh_script();
    mn.payoutSplitProvenance = dash::coin::MNState::SPLIT_KNOWN;
    uint256 protx;
    protx.SetHex(std::string(64, 'a'));
    cs.mnstates().load({{protx, mn}}, /*as_of_height=*/kEmbPrevHeight);
}

void seed_populated(dash::coin::NodeCoinState& cs)
{
    uint256 emb_prev;
    emb_prev.SetHex(kEmbPrevHashHex);
    cs.set_tip(kEmbPrevHeight, emb_prev, /*bits_for_next=*/0x1e0ffff0u,
               /*mtp_at_tip=*/1'700'000'000u, /*addr_ver=*/76, /*p2sh_ver=*/16,
               /*curtime=*/kCurtime, /*version=*/static_cast<uint32_t>(kVersion));
    seed_resolvable_mn(cs);
}

}  // namespace

TEST(DashSubmitGateScaling, SubmitPathTipReadNeverEvaluatesServeGate)
{
    dash::coin::NodeCoinState cs;
    seed_populated(cs);
    ASSERT_TRUE(cs.populated());

    // Empty fallback: the embedded arm must carry the whole serve, and a
    // silent flip to the dashd arm (where the re-check is exempt by design,
    // :993) cannot fake a green.
    auto fallback = []() -> dash::coin::DashWorkData { return {}; };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t, bool) { return true; };

    // is_testnet=true => embedded arm enabled; no refresh executor wired =>
    // the legacy inline cached_work() path, same as the rest of this harness.
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/true);

    // Prime the cache ONCE through the notify-path getter (this getter is
    // allowed — required, even — to run the build/serve gates).
    ASSERT_FALSE(ws.get_current_work_template().empty());

    // Arm sanity: the cached template really is the EMBEDDED one. If this
    // pinned the fallback arm instead, the re-check would be exempt and the
    // whole test vacuously green.
    uint256 emb_prev;
    emb_prev.SetHex(kEmbPrevHashHex);
    ASSERT_EQ(ws.get_current_gbt_prevhash(), emb_prev.GetHex());

    // THE PIN: 100 submit-path tip reads, zero serve-gate evaluations.
    const auto baseline = cs.emit_ok_call_count();
    for (int i = 0; i < 100; ++i)
        (void) ws.get_current_gbt_prevhash();
    EXPECT_EQ(cs.emit_ok_call_count() - baseline, 0u)
        << "submit-path tip reads must not evaluate the serve gate";
}
