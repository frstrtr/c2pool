// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_s1c_recovery_kat.cpp — the two S-1c CARRIER-PATH RACES, and the two
// recovery paths that close them (c2pool#1625, R-A and R-B).
//
// Both races are PRE-EXISTING: they sit in the shared S-1c carrier path, they
// predate the v0x03 K_fair WIRE-CARRY, and they are what kept cross-node
// convergence from being SUSTAINED on the 2-node XMR regtest even after the
// carried map itself was proven row-for-row correct.
//
// ── R-A: the prefix the peer's executor COALESCED THROUGH ───────────────────
// A winner names its fold as (P, spine_digest), where P is the lane RECORD
// PREFIX its E_b was folded at. The receiver answers that name out of
// V37Engine's OI-W4-3 ring. But the executor publishes ONE settlement view per
// COALESCED BURST (v37_engine.hpp kCoalesceBurst = 64), so the ring holds a view
// only at burst-terminal prefixes — and the winner's P is a boundary of the
// WINNER'S bursts, not of ours. Live, the peer's lane version jumped by more
// than one on 92 of 102 status samples and the seam logged
//
//     "S-1c REFUSED h=24: the winner prefix P=295 is not a version THIS node
//      published (older than the settlement ring, or the executor coalesced
//      through it)"
//
// after the whole 20-tick cut-miss retry — a retry that can never succeed,
// because no amount of waiting conjures a publication that was coalesced away.
//
// THE FIX IS NOT TO PUBLISH MORE OFTEN. A snapshot's CONTENT is a pure function
// of the committed record prefix (v37_lane_executor.hpp), so the view at P is
// well-defined whether or not this node published it. The receiver therefore
// PROJECTS it: xmr_cut_projector.hpp keeps a shadow ::v37::LaneExecutor fed from
// the same single producer seam and replays the record log to exactly P. The
// engine's publication semantics are untouched.
//
// ★ AND IT CANNOT MIS-CREDIT. A projection is accepted ONLY when its own lane
// digest at P equals the digest the winner committed to. A faithful replica
// therefore turns a refusal into the CORRECT credit; an unfaithful one can only
// leave the refusal standing. Section 1 pins both halves of that.
//
// ── R-B: the block-winner carrier DROPPED for a momentary parent miss ───────
// A block-winner carrier is keyed to the block's PARENT. The receiver admits it
// against its own mainchain index, so a parent it has not polled yet makes W2
// answer CarrierStatus::REJECT_POW (the enum lumps "unresolvable bin" in with a
// real PoW failure) and the receive seam returned early — throwing the cut
// descriptor away with the frame. Live: node A emitted 45 block-winner carriers
// and node B offered 44; the one that went missing (h=86, win:9291a269,
// parent@85) was never re-offered and B never registered h=86 at all — a
// PERMANENT fork from a condition that resolves one poll later.
//
// THE FIX is a bounded park-and-re-offer register keyed by (h_b, bid) that
// re-asks the I-2 tri-state gate each tick, plus a bounded re-announce of our
// OWN winner frames so a descriptor lost on the wire is recoverable too. The
// carrier wire itself is untouched.
//
// WHAT THIS SUITE PINS, and what makes it go RED if either fix regresses:
//   1  the shadow replica is BIT-EQUAL to the engine at EVERY record prefix,
//      including the ones a coalesced burst never published;
//   2  the pre-R-A behaviour reproduced directly — a coalesced-through prefix
//      REFUSES with cut_miss — and the post-R-A behaviour on the same input:
//      folded, with a credit map byte-equal to the winner's;
//   3  the three fail-closed refusals the projector must keep: a wrong digest
//      at a real prefix, a prefix ahead of every record seen, and a lane the
//      projector can no longer claim to replay (Rewind/RemoveLane);
//   4  ★ SUSTAINED: 25 consecutive settling blocks whose owed_digest is
//      byte-equal on both nodes while EVERY ONE of them is served by the
//      projection (the peer's ring holds none of the winner's prefixes), with
//      zero cut-miss refusals and no double-pay;
//   5  R-B on the REAL relay path: a block-winner frame whose parent is
//      unresolvable is rejected with carrier_status=2 and its cut descriptor is
//      surfaced-and-lost by the old shape, PARKED by the new one, and re-offered
//      the moment the parent resolves — with the negative control (no park =>
//      the block is never learned of) reproduced beside it;
//   6  every bound: the attempt budget, the TTL, the parked-set cap, the
//      re-announce repeat count, and the dedup answer a re-announce gets from a
//      peer that already took the block.
//
// Stdlib + Threads (the engine's executor thread). No coin backend, no crypto
// backend, no sockets, no clocks that must pass. SAME HOLLOW-GREEN GUARD as the
// sibling suites: registered with add_test AND listed on BOTH build.yml --target
// lists so CI compiles and RUNS it instead of leaving a NOT_BUILT CTest
// sentinel (the DGB #137 / #769 / c2pool#1539 unregistered-KAT class).
// ===========================================================================
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/carrier_emit.hpp>          // mint_work_event
#include <c2pool/v37/carrier_ingest.hpp>        // CarrierIngest, MemShareTracker
#include <c2pool/v37/v37_engine.hpp>            // V37Engine, SettlementView
#include <c2pool/v37/w2_admission.hpp>          // IMainchainIndex, CarrierStatus
#include <c2pool/v37/w3_relay.hpp>              // CarrierRelay, CarrierWire, Carrier
#include <c2pool/v37/w4_settlement.hpp>         // OwedLedger
#include <c2pool/v37/xmr/xmr_carrier_defer.hpp> // ★ R-B
#include <c2pool/v37/xmr/xmr_cut_projector.hpp> // ★ R-A
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>       // fold_at_tip / fold_at_peer_cut

using namespace c2pool::v37n;
namespace xo = c2pool::v37n::xmr::o2;
using c2pool::v37n::settle::OwedLedger;

static int g_pass = 0, g_fail = 0;
static void chk(bool ok, const std::string& name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", name.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s%s%s\n", name.c_str(),
                                    detail.empty() ? "" : " \xe2\x80\x94 ", detail.c_str()); }
}
static std::string hex32(const ::v37::bytes32& d) { return xo::s1_hex32(d); }

static constexpr ::v37::ChainId CHAIN  = 7;
static constexpr std::uint64_t  REWARD = 600000000000ull;   // 0.6 XMR in piconero
static constexpr std::uint64_t  SINK_FLOOR = 1000ull;
static constexpr std::uint64_t  D_CONF = 3;
static constexpr unsigned       CAP_OWED = 0;               // 0 == UNBOUNDED

// ── identities ──────────────────────────────────────────────────────────────
static ::v37::PayoutDescriptor id_of(std::uint8_t tag) {
    ::v37::PayoutDescriptor d;
    ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH;
    r.payload.assign(20, tag);
    d.pay = r;
    return d;
}
static std::map<::v37::bytes32, ::v37::ScriptRef> g_refs;
static void learn(std::uint8_t tag) {
    const ::v37::PayoutDescriptor d = id_of(tag);
    g_refs[d.identity_key()] = d.pay;
}
static ::v37::ScriptRef pay_of(const ::v37::bytes32& k) {
    auto it = g_refs.find(k);
    if (it != g_refs.end()) return it->second;
    ::v37::ScriptRef raw;
    raw.kind = ::v37::ScriptKind::RAW;
    return raw;
}
static std::uint64_t h_min_of(::v37::ScriptKind k) {
    return k == ::v37::ScriptKind::P2PKH ? 1ull : ~std::uint64_t{0};
}
static OwedLedger::Amounts kfair_owed_map(const OwedLedger& l, std::uint64_t reward) {
    const std::uint64_t budget = reward > SINK_FLOOR ? reward - SINK_FLOOR : 0;
    const OwedLedger::Proposal p = l.propose_coinbase(budget, CAP_OWED, pay_of, h_min_of);
    OwedLedger::Amounts m;
    for (const auto& o : p.outs) m[o.key] += static_cast<long long>(o.amount);
    return m;
}
static long long amounts_sum(const OwedLedger::Amounts& a) {
    long long s = 0;
    for (const auto& [k, v] : a) { (void)k; s += v; }
    return s;
}
static long long min_finalW(const OwedLedger& l) {
    long long m = 0;
    for (const auto& [k, v] : l.finalW()) { (void)k; if (v < m) m = v; }
    return m;
}
static long long min_effective_owed(const OwedLedger& l) {
    long long m = 0;
    for (const auto& [k, v] : l.effective_owed_all()) { (void)k; if (v < m) m = v; }
    return m;
}

// ── the record stream both nodes see, in one fixed order ────────────────────
struct Rec { std::uint8_t tag; std::uint64_t w; };
static Rec rec_at(std::size_t i) {
    static const Rec kCycle[] = {
        {0xA1, 1000}, {0xB2, 3000}, {0xA1, 2000}, {0xC3, 4000}, {0xB2, 1500},
        {0xD4, 2500}, {0xC3, 1200}, {0xA1,  700}, {0xD4, 3300},
    };
    return kCycle[i % (sizeof(kCycle) / sizeof(kCycle[0]))];
}

// ── one node ────────────────────────────────────────────────────────────────
// `ring_depth` is the OI-W4-3 retention depth. Depth 1 keeps exactly the LAST
// published view, which is how the sustained run below guarantees that a
// winner's prefix is never answerable from the ring and MUST be projected.
struct Node {
    explicit Node(std::size_t ring_depth = V37Engine::kDefaultRingDepth)
        : engine(ring_depth) {}
    V37Engine  engine;
    OwedLedger ledger{CHAIN};
    bool start() {
        engine.start();
        return engine.submit_tracked(
                        ::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{}))
            .get().applied();
    }
    // One record, PUBLISHED (submit_tracked resolves after the burst publishes).
    bool push(const Rec& r) {
        return engine.submit_tracked(
                        ::v37::LaneRecord::push(CHAIN, id_of(r.tag), r.w, 0))
            .get().applied();
    }
    ~Node() { engine.stop(); }
};

// ═══════════════════════════════════════════════════════════════════════════
// 1. R-A — the coalesced-through prefix, reproduced and recovered
// ═══════════════════════════════════════════════════════════════════════════
static void section_1() {
    std::printf("  -- 1. R-A: a prefix the executor COALESCED THROUGH --\n");
    const std::size_t N = 9;

    // (a) The REFERENCE node publishes at every prefix (one record per burst),
    //     so it hands us the true digest at each of 1..N.
    Node ref;
    bool seeded = ref.start();
    std::vector<::v37::bytes32> digest_at(N + 1);
    bool published_every = true;
    for (std::size_t i = 1; i <= N; ++i) {
        seeded &= ref.push(rec_at(i - 1));
        auto s = ref.engine.snapshot(CHAIN);
        published_every &= (s && s->next_pos == i);
        digest_at[i] = s ? s->digest : ::v37::bytes32{};
    }
    chk(seeded && published_every,
        "1a the reference node applied and PUBLISHED a view at every one of the " +
            std::to_string(N) + " prefixes");

    // (b) The COALESCED node. Every record is queued BEFORE the executor thread
    //     exists, so run() takes the whole queue as ONE burst and drain_burst
    //     publishes exactly once — the deterministic form of the live race.
    V37Engine coal;
    coal.submit(::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{}));
    for (std::size_t i = 0; i < N; ++i)
        coal.submit(::v37::LaneRecord::push(CHAIN, id_of(rec_at(i).tag), rec_at(i).w, 0));
    coal.start();
    // The whole queue was populated BEFORE the executor thread existed, so run()
    // takes it as ONE burst: this is the deterministic form of the live race.
    while (coal.ops_committed() < N + 1) std::this_thread::yield();
    auto tip = coal.snapshot(CHAIN);
    chk(tip && tip->next_pos == N,
        "1b the coalesced node applied every record (its lane prefix is " +
            std::to_string(N) + ")");

    std::size_t ring_hits = 0;
    for (std::size_t i = 1; i <= N; ++i) {
        bool mis = false;
        if (coal.settlement_view_by_cut(CHAIN, i, digest_at[i], &mis)) ++ring_hits;
    }
    chk(ring_hits == 1,
        "1c \xe2\x98\x85 THE RACE: the coalesced node's ring can answer only " +
            std::to_string(ring_hits) + " of " + std::to_string(N) +
            " prefixes \xe2\x80\x94 every other winner cut is a permanent cut_miss",
        "ring_hits=" + std::to_string(ring_hits));

    // (c) The projector, fed the identical record stream, reproduces the engine
    //     BIT-FOR-BIT at every prefix — including the ones never published.
    xo::XmrCutProjector proj(CHAIN);
    proj.seed(::v37::LaneParams{}, /*incarnation=*/1);
    for (std::size_t i = 0; i < N; ++i)
        proj.note_push(id_of(rec_at(i).tag), rec_at(i).w, 0);
    std::size_t projected = 0;
    for (std::size_t i = 1; i <= N; ++i) {
        bool mis = false;
        auto v = proj.project(i, digest_at[i], &mis);
        if (v && v->next_pos == i && v->digest == digest_at[i]) ++projected;
    }
    chk(projected == N,
        "1d \xe2\x98\x85 the shadow replica is BIT-EQUAL to the engine at EVERY record "
        "prefix, published or coalesced through",
        "projected=" + std::to_string(projected) + "/" + std::to_string(N));

    // (d) The fold itself: same winner cut, with and without the projector.
    const std::uint64_t P = 5;              // strictly inside the coalesced burst
    xo::XmrPeerWin w;
    w.bid = std::string(64, 'a');
    w.h_b = 100;
    w.cut_next_pos = P;
    w.cut_spine_digest = digest_at[P];
    w.reward = REWARD;

    xo::XmrS1PeerStats before;
    const xo::XmrPeerFoldOutcome no_proj =
        xo::fold_at_peer_cut(coal, CHAIN, w, before, true, nullptr);
    chk(!no_proj.ok && no_proj.cut_miss && !no_proj.cut_digest_mismatch &&
            before.cut_miss == 1,
        "1e NEGATIVE CONTROL (pre-R-A): the coalesced-through prefix REFUSES with "
        "cut_miss \xe2\x80\x94 this is the fork the live rig hit");

    xo::XmrS1PeerStats after;
    const xo::XmrPeerFoldOutcome with_proj =
        xo::fold_at_peer_cut(coal, CHAIN, w, after, true, &proj);
    chk(with_proj.ok && with_proj.cut.projected && after.cut_projected == 1 &&
            after.cut_miss == 0,
        "1f \xe2\x98\x85 R-A: the SAME cut now FOLDS, served by the projection at the "
        "winner's exact prefix");

    // ... and the credit is the winner's, not a number we invented: fold the
    // same prefix out of the reference node's own ring and compare.
    xo::XmrS1PeerStats ref_st;
    const xo::XmrPeerFoldOutcome ref_fold =
        xo::fold_at_peer_cut(ref.engine, CHAIN, w, ref_st, true, nullptr);
    chk(ref_fold.ok && ref_fold.cut.credit == with_proj.cut.credit &&
            !ref_fold.cut.credit.empty(),
        "1g \xe2\x98\x85 the projected fold's E_b is BYTE-EQUAL to the fold a node that "
        "PUBLISHED that prefix produces (" +
            std::to_string(with_proj.cut.credit.size()) + " keys/" +
            std::to_string(amounts_sum(with_proj.cut.credit)) + " pico)");

    // (e) The three fail-closed refusals the projector must keep.
    {
        xo::XmrPeerWin bad = w;
        bad.cut_spine_digest = digest_at[P == 1 ? 2 : P - 1];   // a NEIGHBOUR's digest
        xo::XmrS1PeerStats st;
        const xo::XmrPeerFoldOutcome f =
            xo::fold_at_peer_cut(coal, CHAIN, bad, st, true, &proj);
        chk(!f.ok && f.cut_digest_mismatch && st.cut_project_mismatch == 1 &&
                st.cut_mismatch == 1,
            "1h FAIL-CLOSED: a projection that reaches P under a DIFFERENT digest is "
            "refused as a divergence, never folded");
    }
    {
        xo::XmrPeerWin ahead = w;
        ahead.cut_next_pos = N + 50;                 // records we have never seen
        ahead.cut_spine_digest = digest_at[N];
        xo::XmrS1PeerStats st;
        const xo::XmrPeerFoldOutcome f =
            xo::fold_at_peer_cut(coal, CHAIN, ahead, st, true, &proj);
        chk(!f.ok && f.cut_miss && st.cut_project_miss == 1 && st.cut_miss == 1,
            "1i FAIL-CLOSED: a prefix AHEAD of every record admitted here is a miss the "
            "retry can still recover, never a fold at a neighbouring prefix (O2.3)");
    }
    {
        xo::XmrCutProjector p2(CHAIN);
        p2.seed(::v37::LaneParams{}, 1);
        for (std::size_t i = 0; i < N; ++i)
            p2.note_push(id_of(rec_at(i).tag), rec_at(i).w, 0);
        p2.note(::v37::LaneRecord::rewind(CHAIN, 2));
        bool mis = false;
        chk(!p2.ready() && !p2.project(P, digest_at[P], &mis) && !mis &&
                p2.stats().disabled,
            "1j FAIL-CLOSED: a Rewind on the observed lane DISABLES the projector "
            "(a push-log replica cannot stay faithful across one)");
    }
    {
        // A projector that never saw the AddLane answers nothing.
        xo::XmrCutProjector p3(CHAIN);
        bool mis = false;
        chk(!p3.ready() && !p3.project(1, digest_at[1], &mis),
            "1k FAIL-CLOSED: an unseeded projector serves nothing");
    }
    {
        // The retry path costs nothing: the same (P, digest) is cached.
        const auto s0 = proj.stats();
        bool mis = false;
        (void)proj.project(P, digest_at[P], &mis);
        chk(proj.stats().cache_hits > s0.cache_hits,
            "1l the 20-tick cut-miss retry re-asks the SAME cut and is served from the "
            "cache, not by replaying the log again");
    }
    coal.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. R-A SUSTAINED — 25 settling blocks, every one of them projected
//
// The peer's ring is one deep and the peer runs ONE record ahead of the winner,
// so the winner's prefix is NEVER the peer's last publication: without R-A every
// single block would be refused. FINALIZE is chain-anchored (bin H_b + D_conf),
// so both ledgers cross the same bins; the K_fair map rides the WIRE-CARRY, i.e.
// the peer folds exactly what the winner spent.
// ═══════════════════════════════════════════════════════════════════════════
struct SustainReport {
    std::size_t rounds = 0, settling = 0, agreed = 0, projected = 0;
    std::size_t first_fork = 0;
    bool  every_folded = true;
    long long min_finalw = 0, min_eff = 0;
    ::v37::bytes32 a{}, b{};
    xo::XmrS1PeerStats ps;
};

static SustainReport run_sustained(std::size_t rounds, bool with_projector) {
    SustainReport rep;
    rep.rounds = rounds;
    Node A;                      // the winner: publishes at every prefix
    Node B(/*ring_depth=*/1);    // the peer: keeps ONLY its last publication
    if (!A.start() || !B.start()) { rep.every_folded = false; return rep; }

    xo::XmrCutProjector proj(CHAIN);
    proj.seed(::v37::LaneParams{}, 1);

    xo::XmrS1FoldStats fs_a;
    std::vector<std::pair<std::string, std::uint64_t>> due_a, due_b;

    // B starts one record ahead of A, in the SAME order, and stays there.
    proj.note_push(id_of(rec_at(0).tag), rec_at(0).w, 0);
    rep.every_folded &= B.push(rec_at(0));

    for (std::size_t r = 0; r < rounds; ++r) {
        const std::uint64_t h_b = 500 + r;
        rep.every_folded &= A.push(rec_at(r));                  // A: prefix r+1
        proj.note_push(id_of(rec_at(r + 1).tag), rec_at(r + 1).w, 0);
        rep.every_folded &= B.push(rec_at(r + 1));              // B: prefix r+2

        const OwedLedger::Amounts payout_a = kfair_owed_map(A.ledger, REWARD);
        const xo::XmrEbCut cut = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs_a);
        rep.every_folded &= cut.folded;
        const std::string bid = "block-" + std::to_string(h_b);
        A.ledger.on_block_found(bid, cut.credit, payout_a);
        due_a.emplace_back(bid, h_b + D_CONF);
        const bool settling = !payout_a.empty();
        if (settling) ++rep.settling;

        xo::XmrPeerWin w;
        w.bid = bid;
        w.h_b = h_b;
        w.cut_next_pos = cut.next_pos;
        w.cut_spine_digest = cut.lane_digest;
        w.reward = REWARD;
        w.payout_emitted = settling;
        w.payout_carried = settling;
        w.payout = payout_a;                  // the v0x03 WIRE-CARRY, unchanged

        const xo::XmrPeerFoldOutcome f = xo::fold_at_peer_cut(
            B.engine, CHAIN, w, rep.ps, true, with_projector ? &proj : nullptr);
        if (!f.ok) { rep.every_folded = false; continue; }
        if (f.cut.projected) ++rep.projected;
        B.ledger.on_block_found(bid, f.cut.credit, settling ? payout_a
                                                            : OwedLedger::Amounts{});
        due_b.emplace_back(bid, h_b + D_CONF);

        auto settle_due = [&](OwedLedger& l,
                              std::vector<std::pair<std::string, std::uint64_t>>& due) {
            std::vector<std::pair<std::string, std::uint64_t>> keep;
            for (auto& [b, bin] : due) {
                if (bin <= h_b) l.on_block_finalized(b, bin);
                else keep.emplace_back(b, bin);
            }
            due.swap(keep);
        };
        settle_due(A.ledger, due_a);
        settle_due(B.ledger, due_b);

        if (A.ledger.owed_digest() == B.ledger.owed_digest()) ++rep.agreed;
        else if (rep.first_fork == 0) rep.first_fork = r + 1;
        if (min_finalW(A.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(A.ledger);
        if (min_finalW(B.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(B.ledger);
        if (min_effective_owed(A.ledger) < rep.min_eff) rep.min_eff = min_effective_owed(A.ledger);
        if (min_effective_owed(B.ledger) < rep.min_eff) rep.min_eff = min_effective_owed(B.ledger);
    }
    rep.a = A.ledger.owed_digest();
    rep.b = B.ledger.owed_digest();
    return rep;
}

static void section_2() {
    std::printf("  -- 2. R-A SUSTAINED: the peer's ring can answer NONE of the cuts --\n");
    const std::size_t R = 25;

    const SustainReport off = run_sustained(R, /*with_projector=*/false);
    chk(off.ps.cut_miss == R && off.agreed < R,
        "2a NEGATIVE CONTROL (pre-R-A): with the projector unbound EVERY one of the " +
            std::to_string(R) + " winner cuts is a cut_miss and the two ledgers never "
            "sustain agreement",
        "cut_miss=" + std::to_string(off.ps.cut_miss) +
            " agreed=" + std::to_string(off.agreed));

    const SustainReport on = run_sustained(R, /*with_projector=*/true);
    chk(on.every_folded,
        "2b every round pushed, folded at the winner's cut and registered");
    chk(on.projected == R && on.ps.cut_projected == R,
        "2c \xe2\x98\x85 all " + std::to_string(R) +
            " folds were served by the PROJECTION (the ring held none of them)",
        "projected=" + std::to_string(on.projected));
    chk(on.ps.cut_miss == 0 && on.ps.cut_mismatch == 0 &&
            on.ps.cut_project_mismatch == 0,
        "2d \xe2\x98\x85 ZERO cut-miss refusals and zero digest mismatches across the run");
    chk(on.settling >= 15,
        "2e at least fifteen of the blocks actually SETTLED owed balances",
        "settling=" + std::to_string(on.settling));
    chk(on.first_fork == 0 && on.agreed == R,
        "2f \xe2\x98\x85 SUSTAINED: owed_digest(A) == owed_digest(B) after EVERY one of the " +
            std::to_string(R) + " blocks, not merely at the end",
        on.first_fork ? "first fork at round " + std::to_string(on.first_fork)
                      : "agreed=" + std::to_string(on.agreed));
    chk(on.a == on.b && !(on.a == OwedLedger(CHAIN).owed_digest()),
        "2g \xe2\x98\x85 the two nodes end BYTE-EQUAL and OFF the empty anchor",
        "A=" + hex32(on.a) + " B=" + hex32(on.b));
    chk(on.min_finalw >= 0,
        "2h no over-payment: finalW never went negative on either node",
        "min_finalW=" + std::to_string(on.min_finalw));
    chk(on.min_eff >= 0,
        "2i no double-pay: EffectiveOwed never went negative on either node",
        "min_eff=" + std::to_string(on.min_eff));
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. R-B — the unresolvable parent, on the REAL relay path
// ═══════════════════════════════════════════════════════════════════════════

// A transport that swallows frames (the relay's flood is not what is under test).
struct NullTransport final : ICarrierTransport {
    std::size_t broadcast(const std::vector<std::uint8_t>&) override { return 0; }
    std::size_t n_peers() const override { return 0; }
};

// The I-2 tri-state index, with a switch: `open == false` is the momentary
// "parent not polled yet" that made W2 answer REJECT_POW and the old receive
// seam throw the block-winner descriptor away.
struct GatedIndex final : IMainchainIndex {
    bool open = false;
    u64  height = 40;
    std::optional<u64> height_of(const bytes32&) const override {
        if (!open) return std::nullopt;
        return height;
    }
};

static void section_3() {
    std::printf("  -- 3. R-B: a block-winner carrier whose parent is not polled yet --\n");

    V37Engine engine;
    engine.start();
    chk(engine.submit_tracked(::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{}))
            .get().applied(),
        "3a receiver lane seeded");

    GatedIndex index;
    MemShareTracker tracker;
    CarrierIngest ingest(engine, CHAIN, index, tracker, /*incarnation=*/1);
    NullTransport transport;
    CarrierRelay relay(ingest.fn(), transport);

    // Mint a REAL block-winner frame: a self-bound carrier ground to the
    // consensus target for the parent's bin, carrying a v0x02 cut descriptor.
    const ::v37::PayoutDescriptor desc = id_of(0xA1);
    bytes32 prev{};
    prev.fill(0x5e);
    const std::uint64_t h_b = 86;
    auto ev = mint_work_event(static_cast<std::uint32_t>(CHAIN), desc, prev,
                              W2_GENESIS_PREV_OWN, consensus_lz(index.height),
                              "win:9291a269", 0);
    chk(ev.has_value(), "3b a block-winner carrier minted at the consensus target");
    Carrier c;
    c.carrier = *ev;
    CutDescriptor cd;
    cd.bid.fill(0x92);
    cd.h_b = h_b;
    cd.cut_next_pos = 1;
    cd.cut_spine_digest.fill(0x11);
    cd.reward = REWARD;
    cd.payout_emitted = false;
    c.cut = cd;
    const std::vector<std::uint8_t> frame = CarrierWire::encode(c);
    chk(!frame.empty(), "3c the block-winner frame encodes at the frozen wire");

    // ── the race, reproduced: the parent is not in the index yet ─────────────
    const CarrierRelay::Outcome o1 = relay.handle_inbound(frame);
    chk(o1.wire == WireStatus::OK && !o1.admitted &&
            o1.admission.carrier_status == CarrierStatus::REJECT_POW && o1.cut &&
            o1.cut->h_b == h_b,
        "3d \xe2\x98\x85 THE RACE: the frame decodes and CARRIES its cut, but W2 refuses it "
        "with carrier_status=2 because the parent is not in this node's index yet");

    // NEGATIVE CONTROL: the old seam returned here. Nothing re-offers the block,
    // so the receiver never learns h_b exists — a permanent fork from a condition
    // that clears one poll later.
    index.open = true;
    const CarrierRelay::Outcome never = relay.handle_inbound(std::vector<std::uint8_t>{});
    chk(never.wire != WireStatus::OK,
        "3e NEGATIVE CONTROL: with the frame dropped there is nothing left to re-drive "
        "\xe2\x80\x94 the descriptor is gone and the block is never learned of");
    index.open = false;

    // ── R-B: park it, and re-offer through the tri-state gate ───────────────
    xo::XmrDeferredCarriers defer;
    const std::string bid(64, '9');
    chk(defer.park(h_b, bid, ev->prev_block_hash, frame) && defer.size() == 1 &&
            defer.holds(h_b, bid),
        "3f R-B: the rejected block-winner frame is PARKED, keyed by (h_b, bid)");
    chk(defer.park(h_b, bid, ev->prev_block_hash, frame) && defer.size() == 1 &&
            defer.stats().duplicates == 1,
        "3g a second copy of the same block (a flood echo, or our bounded re-announce) "
        "does not multiply the register");

    std::size_t offered = 0;
    auto redrive = [&](const std::vector<std::uint8_t>& f) {
        const CarrierRelay::Outcome o = relay.handle_inbound(f);
        if (o.admitted && o.cut) ++offered;      // what the receive seam would offer
        return o.admitted;
    };
    auto resolves = [&](const bytes32& p) { return index.height_of(p).has_value(); };

    std::vector<std::string> lines;
    chk(defer.pump(resolves, redrive, &lines) == 0 && defer.size() == 1 &&
            defer.stats().re_offered == 0 && offered == 0,
        "3h while the parent stays unresolvable the frame WAITS: it is not re-driven, "
        "not burned and not dropped");

    index.open = true;                            // the poll lands
    const std::size_t recovered = defer.pump(resolves, redrive, &lines);
    chk(recovered == 1 && offered == 1 && defer.size() == 0 &&
            defer.stats().readmitted == 1,
        "3i \xe2\x98\x85 R-B: the moment the parent resolves the parked frame is re-offered, "
        "ADMITTED, and its cut descriptor reaches the settlement seam");
    chk(!lines.empty(), "3j the recovery is narrated, not silent");

    // W2 credited the block exactly once: the rejected first pass never entered
    // the dedup window, and a third drive is a plain ECHO.
    const CarrierRelay::Outcome echo = relay.handle_inbound(frame);
    chk(!echo.admitted && echo.admission.carrier_status == CarrierStatus::REJECT_DEDUP,
        "3k a later copy of the SAME winner frame is a DEDUP echo \xe2\x80\x94 no second lane "
        "credit, which is what makes the bounded re-announce safe");

    // ── the bounds ──────────────────────────────────────────────────────────
    {
        xo::XmrDeferredCarriers::Options bo;
        bo.max_parked = 2;
        bo.max_attempts = 3;
        xo::XmrDeferredCarriers small(bo);
        chk(small.park(1, std::string(64, '1'), prev, frame) &&
                small.park(2, std::string(64, '2'), prev, frame) &&
                !small.park(3, std::string(64, '3'), prev, frame) &&
                small.stats().dropped_full == 1,
            "3l BOUNDED: the parked set has a hard cap and a refusal past it is COUNTED "
            "(the only remaining silent-ish drop, now visible)");
        auto never_resolves = [](const bytes32&) { return false; };
        auto never_drives = [](const std::vector<std::uint8_t>&) { return false; };
        for (int i = 0; i < 6; ++i) small.pump(never_resolves, never_drives);
        chk(small.size() == 0 && small.stats().dropped_spent == 2,
            "3m BOUNDED: a parent that never resolves spends its attempt budget and the "
            "entry is dropped LOUDLY, not held forever");
    }
    {
        xo::XmrDeferredCarriers d2;
        d2.park(7, std::string(64, '7'), prev, frame);
        d2.retire(7, std::string(64, '7'));
        chk(d2.size() == 0,
            "3n a block learned of by some other route retires its parked copy");
    }
    engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. R-B — the bounded re-announce
// ═══════════════════════════════════════════════════════════════════════════
static void section_4() {
    std::printf("  -- 4. R-B: the bounded re-announce of our own winner frames --\n");
    xo::XmrWinnerReflood::Options ro;
    ro.repeats = 2;
    ro.interval = std::chrono::milliseconds(0);   // due immediately: no sleeping KAT
    ro.max_held = 2;
    xo::XmrWinnerReflood rf(ro);

    std::vector<std::uint8_t> frame(64, 0xab);
    std::size_t sent = 0;
    auto bcast = [&](const std::vector<std::uint8_t>& f) { sent += f.size() ? 1 : 0; return 1u; };

    rf.hold(frame);
    chk(rf.stats().held == 1, "4a a block-winner frame is held for re-announce");
    chk(rf.pump(bcast) == 1 && sent == 1, "4b the first re-announce goes out");
    chk(rf.pump(bcast) == 1 && sent == 2, "4c the second re-announce goes out");
    chk(rf.pump(bcast) == 0 && sent == 2 && rf.stats().retired == 1,
        "4d \xe2\x98\x85 BOUNDED: exactly `repeats` extra floods, then the frame retires \xe2\x80\x94 "
        "a re-announce loop is not a broadcast storm");

    rf.hold(frame); rf.hold(frame);
    rf.hold(frame);
    chk(rf.stats().dropped == 1,
        "4e BOUNDED: the hold set has a cap and a refusal past it is counted");

    xo::XmrWinnerReflood::Options off;
    off.repeats = 0;
    xo::XmrWinnerReflood none(off);
    none.hold(frame);
    chk(none.stats().held == 0 && none.pump(bcast) == 0,
        "4f repeats=0 disables the re-announce entirely (the pre-R-B behaviour)");
}

int main() {
    std::printf("== v37 XMR S-1c CARRIER-PATH RACE RECOVERY (R-A projection, R-B defer) ==\n");
    learn(0xA1); learn(0xB2); learn(0xC3); learn(0xD4);
    std::printf("  empty owed anchor = %s\n",
                hex32(OwedLedger(CHAIN).owed_digest()).c_str());

    section_1();
    section_2();
    section_3();
    section_4();

    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
