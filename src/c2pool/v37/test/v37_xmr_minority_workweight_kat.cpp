// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_minority_workweight_kat   (D2, operator ruling D-1 = C)
//
// N production FinalizeConnect nodes in LOCKSTEP over one mock chain (the D2Rig
// of xmr_o2_finalize_connect.hpp), each lane-suspend decision fed through the
// production LaneSuspendState exactly as main's apply_suspension feeds it.
//
//   WW1  the D-1 blocker: 3 honest nodes + a byzantine PAIR (two attacker-chosen
//        builder keys) mining 3 consecutive fake-digest lane blocks while holding
//        3/8 of the window's work. EVERY honest node: no detection, no alarm edge,
//        the lane never suspended (stratum stays up), >= 1 alarm counted, honest
//        owed_digest sequences equal, the pair's credits in no honest ledger,
//        ledger_mutations_on_refuse = 0.
//   WW2  the work-weighted trigger: the minority A whose own isolated block the
//        majority refused. Unmatched foreign lane blocks = 40% of A's window ->
//        A does NOT re-seed (stays on its own ledger, alarms); 60% -> A re-seeds
//        and its owed_digest equals the majority's; the majority never detects.
//   WW3  DIVERGED is ALARM-ONLY: forker blocks holding 6/8 of the window whose
//        roots nothing reproduces -> DIVERGED, but the lane is never suspended,
//        booking continues, nothing mutated; matched blocks clear it.
//
// Written against APIs present before the ruling too (defaults + the existing
// stats), so the SAME source runs on the D2-A port (red: every honest node
// halts in WW1, A re-seeds at 40% in WW2, DIVERGED suspends the lane in WW3)
// and on the fix (green). No node, no network, no monerod.
// ===========================================================================
#include <cstdio>
#include <filesystem>
#include <string>
#include <unistd.h>

#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_lane_suspend_state.hpp"

namespace c2pool::v37n::xmr::o2 {

static int g_n = 0, g_fail = 0;
static void check(const std::string& name, bool ok, const std::string& detail = {}) {
    ++g_n; if (!ok) ++g_fail;
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.empty() ? "" : "  -- ", detail.c_str());
}
// Fields / knobs that exist only once the ruling is implemented: read as 0 /
// left at the default on the D2-A port, so this file compiles on both.
template <class S> static std::uint64_t alarms_of(const S& s) {
    if constexpr (requires { s.minority_alarms; }) return s.minority_alarms; else return 0;
}
template <class S> static long long share_of(const S& s) {
    if constexpr (requires { s.minority_share_permille; }) return static_cast<long long>(s.minority_share_permille); else return -1;
}
template <class O> static void set_window(O& o, std::size_t w) {
    if constexpr (requires { o.minority_window; }) o.minority_window = w;
}
static bool is_diverged(const FinalizeConnect& fc) { return fc.converge_state() == FinalizeConnect::ConvergeState::Diverged; }

static int run(const std::filesystem::path& tmp) {
    using Node = D2Rig::Node;
    using LS = c2pool::v37n::xmr::LaneSuspendState;
    auto cfg_of = [&](const std::string& name) {
        XmrNodeConfig c; c.network = MoneroNetwork::Stagenet; c.lane_chain = 7; c.d_conf = 3;
        c.settle_db_path = (tmp / name).string();
        std::filesystem::create_directories(c.settle_db_path);
        return c;
    };
    auto opts_of = [&](const XmrNodeConfig& c, bool majority) {
        FinalizeConnectOptions o; o.out = nullptr;
        o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
        if (majority) o.retry_bound = 1;
        return o;
    };
    auto hx = [](const ::v37::bytes32& d) { return hex_of(d).substr(0, 12); };
    auto obs_text = [](const FinalizeConnect& fc) {
        std::string t;
        for (const auto& o : fc.minority_observations())
            t += " " + std::to_string(o.h) + (o.own ? "o" : o.verdict == minority::Verdict::Matched ? "m" : o.verdict == minority::Verdict::Unmatched ? "U" : "?");
        return t;
    };

    // ── WW1 the byzantine pair (M1) ─────────────────────────────────────────
    {
        D2Rig R;
        auto cA = cfg_of("ww1-A"), cB = cfg_of("ww1-B"), cC = cfg_of("ww1-C");
        Node& A = R.add("A", false, 'A', cA, opts_of(cA, false));
        Node& B = R.add("B", false, 'B', cB, opts_of(cB, false));
        Node& C = R.add("C", false, 'C', cC, opts_of(cC, false));
        if (!R.boot(A) || !R.boot(B) || !R.boot(C)) { check("WW1 boot", false, A.boot_error + B.boot_error + C.boot_error); return 1; }
        Node* honest[3] = {&A, &B, &C};
        LS ls[3] = {LS(3), LS(3), LS(3)};
        std::uint64_t susp[3] = {0, 0, 0};
        bool left_converged[3] = {false, false, false};
        for (std::uint64_t h = 1; h <= 24; ++h) {
            if (h >= 5) {
                if (h >= 13 && h <= 15) {   // the pair: 3 consecutive fake-digest lane blocks, two builder keys
                    R.mine(h, (h % 2) ? 'D' : 'E', &A, /*garbage=*/true);
                    R.spec[h].en = ((h % 2) ? 0x05500000u : 0x06600000u) + static_cast<std::uint32_t>(h);
                } else {
                    Node* b = honest[h % 3];
                    R.mine(h, b->who, b);
                }
            }
            R.apply(h);
            for (int i = 0; i < 3; ++i) {
                const auto e = ls[i].update(0, false, false, false, honest[i]->fc->converging(), is_diverged(*honest[i]->fc));
                if (e.suspend_edge) ++susp[i];
                if (honest[i]->fc->converge_state() != FinalizeConnect::ConvergeState::Converged) left_converged[i] = true;
            }
        }
        std::string det;
        bool all_ok = true, pair_credited = false;
        for (int i = 0; i < 3; ++i) {
            const Node& n = *honest[i];
            const auto& s = n.fc->stats();
            const bool ok = s.minority_runs_detected == 0 && !left_converged[i] && n.hook_on == 0 && susp[i] == 0 && !ls[i].suspended() &&
                            alarms_of(s) >= 1 && s.refused_not_credited == 3 && s.ledger_mutations_on_refuse == 0 && s.converged == 0;
            all_ok = all_ok && ok;
            for (std::uint64_t h = 13; h <= 15; ++h)
                pair_credited = pair_credited || n.node->ledger().is_settled(R.spec[h].bid) || n.node->ledger().is_pending(R.spec[h].bid);
            det += std::string(" ") + n.name + ": detected=" + std::to_string(s.minority_runs_detected) + " state=" +
                   FinalizeConnect::converge_state_name(n.fc->converge_state()) + " left_converged=" + std::to_string(left_converged[i]) +
                   " alarm_edges=" + std::to_string(n.hook_on) + " lane_suspend_edges=" + std::to_string(susp[i]) + " alarms=" +
                   std::to_string(alarms_of(s)) + " share=" + std::to_string(share_of(s)) + " refused=" + std::to_string(s.refused_not_credited) + ";";
        }
        const bool eq = A.node->ledger().owed_digest() == B.node->ledger().owed_digest() &&
                        B.node->ledger().owed_digest() == C.node->ledger().owed_digest() && A.dseq == B.dseq && B.dseq == C.dseq;
        int halted = 0;
        for (int i = 0; i < 3; ++i) halted += (susp[i] > 0 || ls[i].suspended()) ? 1 : 0;
        check("WW1 (M1) a byzantine PAIR (2 builder keys) mines 3 consecutive fake-digest lane blocks holding 3/8 of the window's work: 0/3 honest nodes detect, raise an alarm edge or suspend the lane (stratum stays up); every honest node counts >= 1 alarm; the pair's blocks refused (3 each), never credited; ledger_mutations_on_refuse = 0",
              all_ok && !pair_credited && halted == 0, "halted=" + std::to_string(halted) + "/3" + det);
        check("WW1b the honest owed_digest SEQUENCES are equal on all 3 nodes (the pair moved nobody)",
              eq, "A=" + hx(A.node->ledger().owed_digest()) + " B=" + hx(B.node->ledger().owed_digest()) + " C=" +
                  hx(C.node->ledger().owed_digest()) + " states=" + std::to_string(A.dseq.size()) + "/" + std::to_string(B.dseq.size()) + "/" +
                  std::to_string(C.dseq.size()));
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── WW2 the work-weighted trigger: 40% -> no re-seed, 60% -> re-seed (M2) ─
    // The FC31 layout: 5..7 majority; 8 = X, A's own isolated find the majority
    // refuses (a decided credit-cut mismatch); 9, 10, 12 majority (matched on
    // A); 11 = W, A's own block on the shared state; 13 = Y, A's own block on
    // its minority lineage; 14.. majority blocks A cannot reproduce. Window 10:
    // at h=17 A's window is X W Y (own) + 9 10 12 (matched) + 14..17 (unmatched)
    // = 40%; at h=19 it is 10 W 12 Y + 14..19 = 60%.
    {
        D2Rig R;
        auto cA = cfg_of("ww2-A"), cB = cfg_of("ww2-B");
        FinalizeConnectOptions oA = opts_of(cA, false), oB = opts_of(cB, true);
        set_window(oA, 10); set_window(oB, 10);
        Node& A = R.add("A", false, 'A', cA, oA);
        Node& B = R.add("B", true, 'B', cB, oB);
        if (!R.boot(A) || !R.boot(B)) { check("WW2 boot", false, A.boot_error + B.boot_error); return 1; }
        const std::string X = hex_of(D2Rig::id(8));
        auto step = [&](std::uint64_t h) {
            if (h >= 5) {
                if (h == 8) { R.mine(8, 'A', &A, false, /*stall=*/true); A.fc->mark_isolated_own(X, 8, "test: parked, no relay peer"); }
                else if (h == 11 || h == 13) R.mine(h, 'A', &A);
                else R.mine(h, (h % 2) ? 'B' : 'C', &B);
            }
            R.apply(h);
        };
        for (std::uint64_t h = 1; h <= 17; ++h) step(h);
        const auto s40 = A.fc->stats();
        const bool diff40 = !(A.node->ledger().owed_digest() == B.node->ledger().owed_digest());
        const bool x40 = A.node->ledger().is_settled(X);
        const std::string obs40 = obs_text(*A.fc);
        check("WW2a (M2) unmatched foreign lane blocks = 40% of A's window (4 of 10): A does NOT re-seed -- no detection, no adoption, A stays on its OWN ledger (X still credited, digest != the majority's) and alarms",
              s40.minority_runs_detected == 0 && s40.converged == 0 && A.node->relineages() == 0 && diff40 && x40 && alarms_of(s40) >= 1 &&
              (share_of(s40) == 400 || share_of(s40) == -1),
              "detected=" + std::to_string(s40.minority_runs_detected) + " converged=" + std::to_string(s40.converged) + " share=" +
              std::to_string(share_of(s40)) + " alarms=" + std::to_string(alarms_of(s40)) + " obs:" + obs40);
        step(18);
        const auto s50 = A.fc->stats();
        step(19);
        const auto s60 = A.fc->stats();
        const bool eq60 = A.node->ledger().owed_digest() == B.node->ledger().owed_digest();
        bool eq_after = eq60;
        for (std::uint64_t h = 20; h <= 23; ++h) { step(h); eq_after = eq_after && A.node->ledger().owed_digest() == B.node->ledger().owed_digest(); }
        check("WW2b 50% (h=18, 5 of 10) still no re-seed; 60% (h=19, 6 of 10): A re-seeds -- detected once, adopted once, owed_digest == the majority's from that step on, FINALIZED sets equal, X no longer credited on A",
              s50.minority_runs_detected == 0 && s50.converged == 0 && s60.minority_runs_detected == 1 && s60.converged == 1 && eq60 &&
              eq_after && D2Rig::same_settled(R, A, B) && !A.node->ledger().is_settled(X),
              "at50 detected=" + std::to_string(s50.minority_runs_detected) + " share=" + std::to_string(share_of(s50)) +
              " | at60 detected=" + std::to_string(s60.minority_runs_detected) + " converged=" + std::to_string(s60.converged) +
              " share=" + std::to_string(share_of(s60)) + " eq60=" + std::to_string(eq60) + " A=" + hx(A.node->ledger().owed_digest()) +
              " B=" + hx(B.node->ledger().owed_digest()) + " obs:" + obs_text(*A.fc));
        const auto& sb = B.fc->stats();
        check("WW2c the majority never moves: B never detects, never converges; ledger_mutations_on_refuse = 0 on both",
              sb.minority_runs_detected == 0 && sb.converged == 0 && B.hook_on == 0 && sb.ledger_mutations_on_refuse == 0 &&
              A.fc->stats().ledger_mutations_on_refuse == 0,
              "B detected=" + std::to_string(sb.minority_runs_detected) + " share=" + std::to_string(share_of(sb)));
        for (auto& n : R.nodes) R.shutdown(n);
    }

    // ── WW3 DIVERGED is alarm-only ──────────────────────────────────────────
    {
        D2Rig R;
        auto cA = cfg_of("ww3-A");
        Node& A = R.add("A", false, 'A', cA, opts_of(cA, false));
        if (!R.boot(A)) { check("WW3 boot", false, A.boot_error); return 1; }
        LS ls(3);
        std::uint64_t susp = 0, ev_at_div = 0;
        bool saw_div = false;
        for (std::uint64_t h = 1; h <= 19; ++h) {
            if (h >= 5) {
                const bool forker = h >= 10 && h <= 15;
                R.mine(h, (h % 2) ? 'B' : 'C', &A, forker);
                if (forker) R.spec[h].en = ((h % 2) ? 0x05500000u : 0x06600000u) + static_cast<std::uint32_t>(h);
            }
            R.apply(h);
            const auto e = ls.update(0, false, false, false, A.fc->converging(), is_diverged(*A.fc));
            if (e.suspend_edge) ++susp;
            if (is_diverged(*A.fc) && !saw_div) { saw_div = true; ev_at_div = A.node->finalize_driver().event_seq(); }
        }
        const auto& s = A.fc->stats();
        check("WW3 forker blocks holding 6/8 of the window, reproducible by no candidate -> DIVERGED, ALARM-ONLY: the lane is never suspended (0 suspend edges), booking continues past it, nothing mutated; matched blocks bring the share to <= 50% and clear it",
              saw_div && susp == 0 && !ls.suspended() && A.node->finalize_driver().event_seq() > ev_at_div && A.node->relineages() == 0 &&
              s.converged == 0 && s.ledger_mutations_on_refuse == 0 && A.fc->converge_state() == FinalizeConnect::ConvergeState::Converged &&
              s.diverged_cleared == 1 && alarms_of(s) >= 2,
              "saw_diverged=" + std::to_string(saw_div) + " suspend_edges=" + std::to_string(susp) + " events " + std::to_string(ev_at_div) +
              "->" + std::to_string(A.node->finalize_driver().event_seq()) + " cleared=" + std::to_string(s.diverged_cleared) +
              " state=" + FinalizeConnect::converge_state_name(A.fc->converge_state()) + " alarms=" + std::to_string(alarms_of(s)));
        for (auto& n : R.nodes) R.shutdown(n);
    }
    return 0;
}

} // namespace c2pool::v37n::xmr::o2

int main() {
    const std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-ww-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_minority_workweight_kat (D2, ruling D-1 = C) ==\n");
    const int rc = c2pool::v37n::xmr::o2::run(tmp);
    std::filesystem::remove_all(tmp);
    using c2pool::v37n::xmr::o2::g_fail;
    using c2pool::v37n::xmr::o2::g_n;
    std::printf("== %s (%d/%d passed) ==\n", (g_fail || rc) ? "FAIL" : "OK", g_n - g_fail, g_n);
    return (g_fail || rc) ? 1 : 0;
}
