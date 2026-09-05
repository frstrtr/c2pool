// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_download_retry_kat — the parent-share download CONTINUATION KAT.
//
// THE DEFECT THIS CLOSES (bip110 federation cold-attach ~1.4 shares/min vs
// python2 p2pool thousands/min): p2pool's downloader (node.py:108-141) is a
// self-driving loop over desired_var — a round-trip that TIMES OUT (node.py:127
// `continue`) or returns an EMPTY batch (node.py:138 `sleep(1); continue`) does
// NOT end the walk; it immediately re-requests the SAME still-missing desired
// hash from a freshly chosen random peer. c2pool's NodeImpl::download_shares
// instead chained the NEXT request ONLY on a NON-empty reply — an empty / timed-
// out round-trip just bumped a failure counter and RETURNED, stranding the whole
// chain-walk until the next periodic think/clean tick. On the quiet bip110
// federation that tick is minutes apart, so one dead round-trip cost ~30 min of
// sync (the node2 log `parents=145 stops=0` @10:11:54 → `parents=3 stops=2`
// @10:42:22 — a 30-minute gap between parent-share download batches).
//
// The fix wires p2pool's `sleep(1); continue` as an explicit 1s retry over a
// deduped pending set, with a permanent-failure ceiling (MAX_EMPTY_RETRIES)
// standing in for desired_var naturally dropping a hash the network no longer
// has. The two continuation DECISIONS live in the SSOT download_retry.hpp so
// this KAT can prove they match p2pool WITHOUT standing up a NodeImpl /
// ReplyMatcher / peer set. (The wiring — download_shares calling these, the 5s
// think/clean tick, and clean_tracker republishing desired — is compile+link
// covered by bip110_pool_node_compile, which ODR-uses the node.)
//
// ASSERTIONS:
//   [1] EMPTY-REPLY RETRY (the smoking gun): an empty reply BELOW the ceiling
//       schedules another attempt (should_retry_after_empty == true), and the
//       drain RE-ISSUES download_shares for that exact hash — i.e. batch/empty-
//       receipt drives the NEXT request, the behaviour p2pool has and pre-fix
//       c2pool lacked. RED intent: the pre-fix empty branch returned without
//       any re-issue, so the walk died here.
//   [2] PERMANENT-FAILURE CEILING: at/above MAX_EMPTY_RETRIES we STOP retrying
//       (should_retry_after_empty == false) and the drain SKIPS a maxed hash —
//       p2pool's desired_var drop, made explicit and bounded (no infinite spin).
//   [3] ARRIVED-MEANWHILE: a pending hash that landed in the chain via another
//       peer/path is NOT re-requested (dedup against the local chain).
//   [4] NO-PEERS: a non-empty pending set with zero peers does NOT drop the walk
//       — it signals a re-arm (p2pool `if not self.peers: sleep(1); continue`),
//       requesting nothing now but resuming the instant a peer exists.
//   [5] ORDER + MULTIPLICITY: the drain re-issues every eligible pending hash,
//       in input order, so a fan-out of missing parents all get re-driven.
//
// Per-coin isolation: bip110/ only. Drives the PRODUCTION SSOT functions.

#include "../download_retry.hpp"

#include <core/uint256.hpp>

#include <cstdio>
#include <functional>
#include <set>
#include <vector>

using bip110::pool::should_retry_after_empty;
using bip110::pool::plan_download_retries;
using bip110::pool::RetryDrainResult;

static int g_fail = 0;
static void expect_true(const char* name, bool cond) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++g_fail;
}

// Distinct, stable hashes for the test.
static uint256 H(uint8_t b) {
    uint256 h;              // default-constructed = all-zero
    h.data()[0] = b;        // distinguishing byte
    return h;
}

int main() {
    std::printf("bip110_download_retry_kat: parent-share download continuation "
                "(p2pool node.py:108-141 parity)\n");

    constexpr int MAXR = 3;   // NodeImpl::MAX_EMPTY_RETRIES

    const uint256 a = H(0xA1);
    const uint256 b = H(0xB2);
    const uint256 c = H(0xC3);

    // ── [1] EMPTY-REPLY RETRY — the smoking gun ──────────────────────────────
    // First empty reply for `a`: fail_count becomes 1 (< 3) → retry scheduled,
    // and draining the pending {a} with a peer present RE-ISSUES a request for a.
    expect_true("[1a] empty reply #1 (fail=1<3) schedules a retry",
                should_retry_after_empty(1, MAXR) == true);
    {
        std::vector<uint256> pending = { a };
        std::set<uint256> in_chain;                 // a NOT yet in chain
        std::function<bool(const uint256&)> ic =
            [&](const uint256& h){ return in_chain.count(h) != 0; };
        std::function<int(const uint256&)> fc =
            [&](const uint256&){ return 1; };        // one prior empty
        RetryDrainResult r = plan_download_retries(pending, /*have_peers=*/true,
                                                   ic, fc, MAXR);
        expect_true("[1b] drain re-issues the SAME still-missing hash (walk continues)",
                    r.to_request.size() == 1 && r.to_request[0] == a && !r.rearm_no_peers);
    }

    // ── [2] PERMANENT-FAILURE CEILING ────────────────────────────────────────
    // At the ceiling we STOP (no infinite spin); the drain skips a maxed hash.
    expect_true("[2a] empty reply at ceiling (fail=3>=3) does NOT reschedule",
                should_retry_after_empty(MAXR, MAXR) == false);
    {
        std::vector<uint256> pending = { a };
        std::function<bool(const uint256&)> ic = [](const uint256&){ return false; };
        std::function<int(const uint256&)> fc = [&](const uint256&){ return MAXR; };
        RetryDrainResult r = plan_download_retries(pending, true, ic, fc, MAXR);
        expect_true("[2b] drain SKIPS a hash at the failure ceiling (bounded)",
                    r.to_request.empty() && !r.rearm_no_peers);
    }

    // ── [3] ARRIVED-MEANWHILE ────────────────────────────────────────────────
    // `a` landed in the chain via another peer between the empty reply and the
    // retry tick → not re-requested; `b` (still missing) is.
    {
        std::vector<uint256> pending = { a, b };
        std::set<uint256> in_chain = { a };
        std::function<bool(const uint256&)> ic =
            [&](const uint256& h){ return in_chain.count(h) != 0; };
        std::function<int(const uint256&)> fc = [](const uint256&){ return 1; };
        RetryDrainResult r = plan_download_retries(pending, true, ic, fc, MAXR);
        expect_true("[3] arrived-meanwhile hash skipped, still-missing one re-issued",
                    r.to_request.size() == 1 && r.to_request[0] == b);
    }

    // ── [4] NO-PEERS: re-arm, never drop the walk ────────────────────────────
    {
        std::vector<uint256> pending = { a, b };
        std::function<bool(const uint256&)> ic = [](const uint256&){ return false; };
        std::function<int(const uint256&)> fc = [](const uint256&){ return 0; };
        RetryDrainResult r = plan_download_retries(pending, /*have_peers=*/false,
                                                   ic, fc, MAXR);
        expect_true("[4] no peers → re-arm (walk preserved), request nothing now",
                    r.rearm_no_peers == true && r.to_request.empty());
    }

    // ── [5] ORDER + MULTIPLICITY ─────────────────────────────────────────────
    // Fan-out of missing parents: all eligible, re-issued in input order.
    {
        std::vector<uint256> pending = { a, b, c };
        std::function<bool(const uint256&)> ic = [](const uint256&){ return false; };
        std::function<int(const uint256&)> fc = [](const uint256&){ return 2; }; // <3
        RetryDrainResult r = plan_download_retries(pending, true, ic, fc, MAXR);
        expect_true("[5] every eligible pending parent re-issued in input order",
                    r.to_request.size() == 3 &&
                    r.to_request[0] == a && r.to_request[1] == b && r.to_request[2] == c &&
                    !r.rearm_no_peers);
    }

    // ── Empty pending is a clean no-op (no spurious re-arm) ───────────────────
    {
        std::vector<uint256> pending;
        std::function<bool(const uint256&)> ic = [](const uint256&){ return false; };
        std::function<int(const uint256&)> fc = [](const uint256&){ return 0; };
        RetryDrainResult r = plan_download_retries(pending, true, ic, fc, MAXR);
        expect_true("[6] empty pending → no requests, no re-arm",
                    r.to_request.empty() && !r.rearm_no_peers);
    }

    if (g_fail == 0) {
        std::printf("bip110_download_retry_kat: ALL PASS — empty/timeout reply "
                    "re-drives the parent-share walk (p2pool sleep(1);continue "
                    "parity), bounded by the failure ceiling.\n");
        return 0;
    }
    std::printf("bip110_download_retry_kat: %d FAILED\n", g_fail);
    return 1;
}
