// ===========================================================================
// v37_xmr_recon_kat.cpp — RECON Phase-1 (operator-ruled 2026-09-20): the
// payout-side convergence mechanism, exercised through the PRODUCTION modules
//   xmr_recon_ring.hpp   (XmrReconRing — the atomic-in-finalize snapshot ring)
//   xmr_recon.hpp        (XmrRecon::evaluate — reconstruct-at-the-winner's-cut)
//
// QUESTION (the cursor-15 defect, restated): can a peer converge owed_digest
// THROUGH settling blocks with ZERO new wire bytes — reconstructing the
// winner's K_fair payout from its OWN (S-1c-converged) owed ledger AT THE
// WINNER'S LEDGER CUT, picked by the v0x02 field owed_digest_at_win — and FAIL
// CLOSED (never fork) when it cannot?
//
// This is the p2pool discipline (a share carries tx HASHES / a coinbase root;
// each node rebuilds the tx set from its mempool and refuses what it cannot
// rebuild) applied to the payout leg:
//     payout map  == the tx set     (derived, reconstructable)
//     owed ledger == the mempool     (shared, S-1c-convergent state)
//     commitment  == the on-chain coinbase (O(1); here the winner's actual map
//                    is used as a test-local oracle to check the reconstruction
//                    reproduced it — production reaches it via `bid`)
//
// Three peer POLICIES over the SAME 40-round stream, with the same two-clock
// skew as the sibling S-1c KAT (B books each descriptor ONE ROUND LATER):
//   CONTROL    ruling (a): recompute from B's ledger AT RECEIPT -> reproduces
//              the cursor-15 fork class (state one finalize apart)
//   ORACLE     B books the winner's actual K_fair map verbatim -> converges
//              (the test-local reference digest; NEVER on the wire)
//   RECON      the production XmrReconRing + XmrRecon::evaluate: pick the
//              snapshot the winner's owed_digest_at_win names, reconcile pending
//              to the reservation window, re-run the SAME K_fair, book it — or
//              PARK (behind) / REFUSE (cannot reproduce), never a different map.
//
// Uses ONLY public seams: on_block_found / on_block_finalized / on_block_orphaned
// / propose_coinbase / owed_digest; the real V37Engine fold_at_tip /
// fold_at_peer_cut; and the production RECON modules. Nothing under
// src/sharechain/v37 is touched; nothing here is a consensus rule.
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>
#include <c2pool/v37/xmr/xmr_recon_ring.hpp>
#include <c2pool/v37/xmr/xmr_recon.hpp>

using namespace c2pool::v37n;
using ::c2pool::v37n::settle::OwedLedger;
namespace xo = c2pool::v37n::xmr::o2;
using Amounts = OwedLedger::Amounts;

static int g_pass = 0, g_fail = 0;
static void chk(bool ok, const std::string& name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", name.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s%s%s\n", name.c_str(),
                                    detail.empty() ? "" : " — ", detail.c_str()); }
}
static std::string hx(const ::v37::bytes32& d) { return xo::s1_hex32(d); }

// ── fixtures ────────────────────────────────────────────────────────────────
static constexpr ::v37::ChainId CHAIN    = 7;
static constexpr std::uint64_t  REWARD   = 600000000000ull;
static constexpr std::uint64_t  D_CONF   = 3;
static constexpr unsigned       CAP_OWED = 0;
static constexpr std::size_t    ROUNDS   = 40;

static ::v37::PayoutDescriptor id_of(std::uint8_t tag) {
    ::v37::PayoutDescriptor d; ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH; r.payload.assign(20, tag); d.pay = r; return d;
}
static std::map<::v37::bytes32, ::v37::ScriptRef> g_refs;
static ::v37::ScriptRef pay_of(const ::v37::bytes32& k) {
    auto it = g_refs.find(k);
    if (it != g_refs.end()) return it->second;
    ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; raw.payload.clear(); return raw;
}
static std::uint64_t h_min_of(::v37::ScriptKind k) {
    return k == ::v37::ScriptKind::P2PKH ? 1ull : (std::numeric_limits<std::uint64_t>::max)();
}
static void learn(std::uint8_t tag) { const auto d = id_of(tag); g_refs[d.identity_key()] = d.pay; }

// THE K_FAIR RUN — the one and only K_fair caller shape (propose_coinbase),
// byte-identical to the served-template path and the reconstruction path.
static Amounts kfair_owed_map(const OwedLedger& l, std::uint64_t reward, std::uint64_t sink_floor) {
    const std::uint64_t owed_budget = reward > sink_floor ? reward - sink_floor : 0;
    const OwedLedger::Proposal p = l.propose_coinbase(owed_budget, CAP_OWED, pay_of, h_min_of);
    Amounts m;
    for (const auto& o : p.outs) m[o.key] += static_cast<long long>(o.amount);
    return m;
}
static long long amt_sum(const Amounts& a) { long long s = 0; for (auto& [k, v] : a) { (void)k; s += v; } return s; }
static long long min_finalW(const OwedLedger& l) { long long m = 0; for (auto& [k, v] : l.finalW()) { (void)k; if (v < m) m = v; } return m; }

static constexpr std::uint64_t SINK_FLOOR = 1000ull;   // fleet-identical cap by assumption

struct Push { std::uint8_t tag; std::uint64_t w; };
static Push round_work(std::size_t r) {
    static const Push kCycle[] = { {0xA1, 1000}, {0xB2, 3000}, {0xA1, 2000}, {0xC3, 4000},
                                   {0xB2, 1500}, {0xD4, 2500}, {0xC3, 1200} };
    return kCycle[r % (sizeof(kCycle) / sizeof(kCycle[0]))];
}

struct Node {
    V37Engine  engine;
    OwedLedger ledger{CHAIN};
    bool start() {
        engine.start();
        return engine.submit_tracked(::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{})).get().applied();
    }
    bool push(std::uint8_t tag, std::uint64_t w) {
        return engine.submit_tracked(::v37::LaneRecord::push(CHAIN, id_of(tag), w, 0)).get().applied();
    }
    ~Node() { engine.stop(); }
};

enum class Policy { CONTROL, ORACLE, RECON };
static const char* pname(Policy p) {
    return p == Policy::CONTROL ? "CONTROL(recompute-at-receipt)"
         : p == Policy::ORACLE  ? "ORACLE(book winner's map verbatim)"
                                : "RECON(production reconstruct-at-cut + fail-closed)";
}

// a descriptor as B receives it: v0x02 fields only (XmrPeerWin), plus the
// winner's ACTUAL map, kept ONLY as the ORACLE reference / the test-local
// commitment the RECON reconstruction is checked against (never on the wire).
struct Desc {
    xo::XmrPeerWin w;          // bid / h_b / cut_* / reward / payout_emitted / owed_digest_at_win
    Amounts        winner_map; // the winner's actual K_fair map (oracle / commitment)
    Amounts        credit;     // B's own E_b fold at the winner's cut (S-1c)
    bool           settling = false;
    std::size_t    tries = 0;
};

struct Faults {
    std::size_t   drop_round = 0;          // B never receives this round's descriptor
    bool          fetch_after_park = false;// ... but can FETCH it on the bounded park (repair loop)
    std::uint64_t b_sink_floor = 0;        // B runs a different K_fair cap (0 = fleet-identical)
};

struct RunReport {
    ::v37::bytes32 a{}, b{};
    std::size_t settling = 0, agreed_after = 0, first_fork = 0, skewed = 0, rounds = 0;
    long long min_finalw = 0;
    // RECON verdict tallies (from the production engine's stats + the harness)
    std::size_t applied = 0, parked = 0, refused = 0, fetched = 0, mismatch = 0;
    bool every_folded = true;
};

// Drive the whole stream under one policy. The RECON policy uses the PRODUCTION
// XmrReconRing + XmrRecon::evaluate; CONTROL/ORACLE are the reference baselines.
static RunReport run_stream(Policy pol, Faults f = {}) {
    RunReport rep; Node A, B;
    if (!A.start() || !B.start()) { rep.every_folded = false; return rep; }
    xo::XmrS1FoldStats fs_a; xo::XmrS1PeerStats ps_b;

    // ---- B's production RECON wiring ----
    const std::uint64_t b_floor = f.b_sink_floor ? f.b_sink_floor : SINK_FLOOR;
    xo::XmrReconRing ring(2 * D_CONF + 4);
    std::uint64_t b_cursor = 0;
    // pending B holds: bid -> (height, payout it settled) — the reservation set
    std::map<std::string, std::pair<std::uint64_t, Amounts>> b_pending;

    xo::XmrRecon::Deps rd;
    rd.ring        = &ring;
    rd.live_ledger = [&B]() -> const OwedLedger& { return B.ledger; };
    rd.cursor_now  = [&b_cursor]() { return b_cursor; };
    rd.recon_owed_map = [b_floor](const OwedLedger& scratch, std::uint64_t reward,
                                  Amounts& out, std::unique_ptr<xo::XmrOwedSettlementSource>& src,
                                  std::string& why) -> bool {
        (void)why; (void)src;               // reconstruction-only: coinbase verify is SECTION B
        out = kfair_owed_map(scratch, reward, b_floor);
        return true;                         // src stays null; XmrRecon skips the coinbase leg
    };
    rd.fetch_coinbase = nullptr;             // reconstruction-authoritative on the live path
    xo::XmrRecon recon(std::move(rd));

    std::deque<Desc> inflight;               // one-round lag
    std::deque<Desc> parked;
    std::optional<Desc> dropped;             // the descriptor B never got (fault)
    std::vector<std::pair<std::string, std::uint64_t>> due_a, due_b;
    std::map<std::string, std::uint64_t> h_of;
    std::uint64_t cursor_a = 0;

    // book a drained descriptor per policy; returns 0=booked, 1=park, 2=refuse
    auto book = [&](Desc& d) -> int {
        if (!d.settling) {                   // non-settling: payout {} on every policy (S-1c)
            B.ledger.on_block_found(d.w.bid, d.credit, {});
            b_pending[d.w.bid] = {d.w.h_b, {}}; return 0;
        }
        if (pol == Policy::ORACLE) {
            B.ledger.on_block_found(d.w.bid, d.credit, d.winner_map);
            b_pending[d.w.bid] = {d.w.h_b, d.winner_map}; return 0;
        }
        if (pol == Policy::CONTROL) {
            const Amounts own_now = kfair_owed_map(B.ledger, d.w.reward, b_floor);
            if (!(own_now == d.winner_map)) ++rep.skewed;
            B.ledger.on_block_found(d.w.bid, d.credit, own_now);
            b_pending[d.w.bid] = {d.w.h_b, own_now}; return 0;
        }
        // ---- RECON: the production engine ----
        std::vector<xo::ReconReservation> pend;
        for (const auto& [bid, hp] : b_pending)
            pend.push_back(xo::ReconReservation{bid, hp.first, hp.second});
        const xo::XmrPeerPayoutOutcome ro = recon.evaluate(d.w, pend);
        if (!ro.ok) {
            if (std::string_view(ro.code) == "no-state" && d.tries < 4) return 1;  // PARK (bounded)
            ++rep.refused; return 2;                                                // fail-closed
        }
        // The test-local commitment check stands in for the production coinbase
        // verify (xmr_recon_verify.hpp / canonical_coinbase_matches, reached via
        // `bid`): the reconstructed map MUST reproduce the winner's actual map. A
        // mismatch when a reservation descriptor is still MISSING is recoverable
        // (PARK, then fetch completes the set on retry); after the bounded budget
        // it is a hard REFUSE (a persistent cap mismatch). Either way a map that
        // does not match the winner's coinbase is NEVER booked.
        if (!(ro.payout == d.winner_map)) {
            if (d.tries < 4) return 1;                       // PARK (missing reservation, fetchable)
            ++rep.mismatch; ++rep.refused; return 2;         // fail-closed (persistent divergence)
        }
        B.ledger.on_block_found(d.w.bid, d.credit, ro.payout);
        b_pending[d.w.bid] = {d.w.h_b, ro.payout};
        return 0;
    };

    for (std::size_t round = 0; round < ROUNDS; ++round) {
        const std::uint64_t h_b = 500 + round; rep.rounds = round + 1;
        const Push p = round_work(round);
        rep.every_folded &= A.push(p.tag, p.w);
        rep.every_folded &= B.push(p.tag, p.w);

        // ---- WINNER A: template instant = ledger state after last finalize ----
        const ::v37::bytes32 owed_at_win_a = A.ledger.owed_digest();
        const Amounts payout_a = kfair_owed_map(A.ledger, REWARD, SINK_FLOOR);
        const xo::XmrEbCut cut = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs_a);
        rep.every_folded &= cut.folded;
        const std::string bid = "block-" + std::to_string(h_b);
        A.ledger.on_block_found(bid, cut.credit, payout_a);
        h_of[bid] = h_b; due_a.emplace_back(bid, h_b + D_CONF);
        const bool settling = !payout_a.empty();
        if (settling) ++rep.settling;

        // ---- the descriptor B receives (v0x02 fields only) ----
        Desc d; d.settling = settling; d.winner_map = payout_a;
        d.w.bid = bid; d.w.h_b = h_b; d.w.cut_next_pos = cut.next_pos;
        d.w.cut_spine_digest = cut.lane_digest; d.w.reward = REWARD;
        d.w.payout_emitted = settling; d.w.owed_digest_at_win = owed_at_win_a;

        // ---- B folds E_b at the winner's cut NOW (S-1c), books LATER ----
        const xo::XmrPeerFoldOutcome fo = xo::fold_at_peer_cut(B.engine, CHAIN, d.w, ps_b);
        rep.every_folded &= fo.ok; d.credit = fo.cut.credit;
        if (f.drop_round && round == f.drop_round) dropped = d;
        else inflight.push_back(d);

        // ---- B drains what arrived LAST round (+ retries parked) ----
        std::deque<Desc> todo;
        while (!parked.empty()) { todo.push_back(parked.front()); parked.pop_front(); }
        if (inflight.size() > 1) { todo.push_back(inflight.front()); inflight.pop_front(); }
        for (Desc& x : todo) {
            const int r = book(x);
            if (r == 0) { due_b.emplace_back(x.w.bid, x.w.h_b + D_CONF); ++rep.applied; }
            else if (r == 1) {
                ++x.tries; ++rep.parked; parked.push_back(x);
                if (f.fetch_after_park && dropped && x.tries == 2) {
                    Desc got = *dropped; dropped.reset(); ++rep.fetched;
                    if (book(got) == 0) due_b.emplace_back(got.w.bid, got.w.h_b + D_CONF);
                }
            }
        }

        // ---- FINALIZE: chain-anchored; both cross the same bins ----
        auto settle_due = [&](OwedLedger& l, std::vector<std::pair<std::string, std::uint64_t>>& due,
                              std::uint64_t& cur) {
            std::vector<std::pair<std::string, std::uint64_t>> keep; bool any = false; std::uint64_t maxh = 0;
            for (auto& [b, bin] : due) {
                if (bin <= h_b) { l.on_block_finalized(b, bin); any = true; if (h_of[b] > maxh) maxh = h_of[b]; }
                else keep.emplace_back(b, bin);
            }
            due.swap(keep);
            if (any) cur = maxh;
            return any;
        };
        settle_due(A.ledger, due_a, cursor_a);
        const bool b_touched = settle_due(B.ledger, due_b, b_cursor);
        // S1 seam analogue: snapshot ATOMICALLY after the finalize step, keyed by cursor
        if (b_touched) ring.observe(b_cursor, B.ledger);

        const bool agree = (A.ledger.owed_digest() == B.ledger.owed_digest());
        if (agree) ++rep.agreed_after; else if (rep.first_fork == 0) rep.first_fork = rep.settling;
        if (min_finalW(A.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(A.ledger);
        if (min_finalW(B.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(B.ledger);
    }
    rep.a = A.ledger.owed_digest(); rep.b = B.ledger.owed_digest();
    // absorb the engine's own verdict counters into the report
    rep.refused = recon.stats().refused_recon + recon.stats().refused_cb + rep.refused;
    (void)pname;
    return rep;
}

int main() {
    std::printf("== v37 RECON Phase-1 KAT: reconstruct-at-the-winner's-cut, 0 new wire bytes ==\n");
    learn(0xA1); learn(0xB2); learn(0xC3); learn(0xD4);
    const ::v37::bytes32 ANCHOR = OwedLedger(CHAIN).owed_digest();

    // ── 1. CONTROL: ruling (a) recompute-at-receipt reproduces the fork class ──
    std::printf("-- 1. CONTROL (recompute at receipt) --\n");
    RunReport ctl = run_stream(Policy::CONTROL);
    chk(ctl.every_folded, "1a every round pushed + folded (both nodes)");
    chk(ctl.settling >= 20, "1b >= 20 settling blocks", "settling=" + std::to_string(ctl.settling));
    chk(ctl.first_fork != 0, "1c CONTROL FORKS: recompute from B's ledger at receipt (one finalize apart) books a different map",
        "first fork at settling #" + std::to_string(ctl.first_fork) + ", skewed=" + std::to_string(ctl.skewed));
    chk(ctl.skewed > 0, "1d the skew is REAL on " + std::to_string(ctl.skewed) + " settling blocks");

    // ── 2. ORACLE: booking the winner's map verbatim converges (reference) ─────
    std::printf("-- 2. ORACLE (winner's map verbatim) --\n");
    RunReport orc = run_stream(Policy::ORACLE);
    chk(orc.first_fork == 0 && orc.a == orc.b, "2a ORACLE converges (reference digest)",
        "agreed_after=" + std::to_string(orc.agreed_after));

    // ── 3. RECON: converge THROUGH settling with NO map on the wire ────────────
    std::printf("-- 3. RECON (production XmrReconRing + XmrRecon::evaluate) --\n");
    RunReport rc = run_stream(Policy::RECON);
    chk(rc.every_folded, "3a every round pushed + folded (both nodes)");
    chk(rc.settling >= 20, "3b >= 20 settling blocks", "settling=" + std::to_string(rc.settling));
    chk(rc.first_fork == 0, "3c NOT ONE FORK through every settling block — NO map on the wire",
        rc.first_fork ? "first fork at settling #" + std::to_string(rc.first_fork) : "");
    chk(rc.agreed_after == rc.rounds, "3d SUSTAINED: byte-equal after ALL " + std::to_string(rc.rounds) + " rounds",
        "agreed_after=" + std::to_string(rc.agreed_after));
    chk(rc.a == rc.b && !(rc.a == ANCHOR), "3e ends BYTE-EQUAL and OFF the empty anchor",
        "A=" + hx(rc.a).substr(0, 16) + " B=" + hx(rc.b).substr(0, 16));
    chk(rc.a == orc.a, "3f RECON's final digest == ORACLE's (same settlement, no map carried)",
        "recon=" + hx(rc.a).substr(0, 16) + " oracle=" + hx(orc.a).substr(0, 16));
    chk(rc.mismatch == 0 && rc.refused == 0,
        "3g every settling win was RECONSTRUCTED and reproduced the winner's map (0 mismatch, 0 refusal)",
        "applied=" + std::to_string(rc.applied) + " parked=" + std::to_string(rc.parked) +
        " mismatch=" + std::to_string(rc.mismatch) + " refused=" + std::to_string(rc.refused));
    chk(rc.min_finalw >= 0, "3h no double-pay: finalW >= 0 on both nodes throughout",
        "min=" + std::to_string(rc.min_finalw));

    // ── 4. FAIL-CLOSED: cannot reconstruct -> PARK then REFUSE, never a fork ────
    std::printf("-- 4a. fault: B never receives one descriptor in the reservation window --\n");
    { Faults f; f.drop_round = 10;
      RunReport r = run_stream(Policy::RECON, f);
      chk(r.parked > 0 && r.refused > 0, "4a a win B cannot reconstruct is PARKED then REFUSED (fail-closed), never a different map",
          "parked=" + std::to_string(r.parked) + " refused=" + std::to_string(r.refused) + " mismatch=" + std::to_string(r.mismatch));
      chk(r.first_fork != 0, "4a' the divergence is VISIBLE in the per-cursor digest (a loud fork), not hidden behind a silently-booked plausible map",
          "first fork at settling #" + std::to_string(r.first_fork));
    }
    std::printf("-- 4b. same fault + the repair loop (fetch the missing descriptor) --\n");
    { Faults f; f.drop_round = 10; f.fetch_after_park = true;
      RunReport r = run_stream(Policy::RECON, f);
      chk(r.fetched == 1, "4b the missing descriptor was fetched on the bounded park", "fetched=" + std::to_string(r.fetched));
      chk(r.a == r.b, "4b' after the fetch the two ledgers RE-CONVERGE byte-equal (repair, not fork)",
          "A=" + hx(r.a).substr(0, 16) + " B=" + hx(r.b).substr(0, 16));
    }
    std::printf("-- 4c. fault: B runs a different K_fair cap (sink floor) — non-fleet-identical config --\n");
    { Faults f; f.b_sink_floor = 5000;
      RunReport r = run_stream(Policy::RECON, f);
      chk(r.mismatch > 0 || r.refused > 0, "4c a reconstruction that does not reproduce the winner's map is REFUSED (never booked)",
          "mismatch=" + std::to_string(r.mismatch) + " refused=" + std::to_string(r.refused) + " applied=" + std::to_string(r.applied));
      chk(r.first_fork != 0, "4c' and the divergence is VISIBLE in the per-cursor digest (loud), not a silent different fold");
      RunReport c2 = run_stream(Policy::CONTROL, f);
      chk(c2.skewed > 0, "4c'' (contrast) CONTROL under the same cap mismatch SILENTLY books a different map",
          "skewed=" + std::to_string(c2.skewed));
    }

    std::printf("== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
