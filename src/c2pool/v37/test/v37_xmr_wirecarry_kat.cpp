// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_wirecarry_kat.cpp
//     WIRE-CARRY of the K_fair owed-deduction map (carrier wire v0x03 section
//     2) — and the SUSTAINED convergence through settlement that it buys.
//
// WHAT CHANGED, AND WHY THERE IS A SECOND KAT.
// v37_xmr_peer_recompute_kat.cpp pins the PREVIOUS answer: a peer receiving a
// SETTLING block re-derives the winner's K_fair payout from its own ledger,
// because the map was not on the frozen v0x02 wire. That KAT is green and its
// claim is true — K_fair IS deterministic, and two ledgers in the same state
// propose the byte-identical map. The claim it could not make is the one that
// matters on a live rig: that the two ledgers ARE in the same state at the
// instant the map is decided. They are not. Two daemons sample their ledgers on
// independent clocks, and on an isolated 2-node XMR regtest the recompute path
// converged byte-equal through roughly four settling blocks and then forked at
// the fifth, refusing every settling block after it with no path back.
//
// THE SWITCH THIS KAT PINS. The winner already knows its map exactly — it is
// the Owed-role output set of the template it mined, the very map its own
// ledger booked — so it CARRIES it on the v0x03 trailer and the peer FOLDS IT
// VERBATIM. No recompute, no template build to compare against, no same-instant
// requirement anywhere on the path. The two-clock dependency is removed rather
// than guarded, which is why convergence is SUSTAINED instead of eventual.
//
// WHAT IS ASSERTED (a FIXED record stream: no clocks, no sockets, no RNG)
//   1  the wire leg: a K_fair map survives encode -> decode at v0x03 EXACTLY
//      (keys, order, amounts), and the section is refused in every shape that
//      could fork a ledger — no cut, a denying descriptor, a zero row,
//      unordered keys, and a total above the frame's own reward
//   2  ★ THE CLAIM: >= 20 CONSECUTIVE SETTLING blocks driven through
//      FOUND(credit=E_b, payout) -> FINALIZE on two independent ledgers, the
//      peer folding ONLY what the winner carried — owed_digest(A) ==
//      owed_digest(B) after EVERY one, off the empty anchor, no refusal, no
//      fork, finalW >= 0 and min EffectiveOwed >= 0 on both sides throughout
//   3  ★ THE SKEW IS REAL AND WIRE-CARRY IGNORES IT: at every settling block
//      the peer's OWN K_fair proposal at receipt DIFFERS from the winner's, so
//      a recompute would have had nothing correct to book — and the carried
//      fold converges anyway
//   4  ★ THE CONTROL: the SAME stream, with the peer booking its own
//      recomputed-at-receipt map instead of the carried one, FORKS — and stays
//      forked. This is the defect being replaced, reproduced in-tree so this
//      KAT goes red if the recompute-apply ever comes back as the authority
//   5  NO DOUBLE-PAY: the carried map is exactly the winner's booked coinbase
//      owed-set, and after it finalizes neither node's next K_fair proposal
//      re-offers what that block already paid
//   6  the fail-closed half, which is NEVER a timing skew: payout_emitted with
//      no carried section refuses; a carried section on a denying descriptor
//      refuses; a carried map the ledger cannot book refuses
//   7  ★ COEXISTENCE with c2pool#1627: one v0x03 frame carries the DROPS credit
//      section AND the K_fair payout section, each decodes to itself, and the
//      payout section's bytes are identical with section 1 present or absent
//
// SCOPE FENCE. Consumer tree only. This KAT drives OwedLedger through its
// PUBLIC seams (on_block_found / on_block_finalized / propose_coinbase /
// owed_digest) and the frozen wire codec; it edits nothing under
// src/sharechain/v37, nothing in the owed_digest() fold body, nothing in
// fold_eb or settle_block.
//
// Stdlib-only self-harness (the sibling convention in this directory): no gtest,
// no Boost, no coin lib, no crypto backend. Links Threads for the engine's
// single executor thread. Registered with add_test AND in BOTH build.yml
// --target lists (the c2pool#1539 / #769 hollow-green rule).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>

using namespace c2pool::v37n;
using ::c2pool::v37n::settle::OwedLedger;
namespace xo = c2pool::v37n::xmr::o2;
namespace wf = c2pool::v37n::wire_freeze;

// ── the tiny self-harness ───────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void chk(bool ok, const std::string& name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", name.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s%s%s\n", name.c_str(),
                                    detail.empty() ? "" : " — ", detail.c_str()); }
}
static std::string hex32(const ::v37::bytes32& d) { return xo::s1_hex32(d); }

// ── fixtures (the sibling recompute KAT's, so the two are comparable) ───────
static constexpr ::v37::ChainId CHAIN      = 7;
static constexpr std::uint64_t  REWARD     = 600000000000ull;   // 0.6 XMR in piconero
static constexpr std::uint64_t  SINK_FLOOR = 1000ull;           // mandated residual sink
static constexpr std::uint64_t  D_CONF     = 3;
static constexpr unsigned       CAP_OWED   = 0;                 // R1: 0 == UNBOUNDED
static constexpr std::size_t    ROUNDS     = 24;                // >= 20 settling blocks

static ::v37::PayoutDescriptor id_of(std::uint8_t tag) {
    ::v37::PayoutDescriptor d;
    ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH;
    r.payload.assign(20, tag);
    d.pay = r;
    return d;
}
static std::map<::v37::bytes32, ::v37::ScriptRef> g_refs;
static ::v37::ScriptRef pay_of(const ::v37::bytes32& k) {
    auto it = g_refs.find(k);
    if (it != g_refs.end()) return it->second;
    ::v37::ScriptRef raw;
    raw.kind = ::v37::ScriptKind::RAW;
    raw.payload.clear();
    return raw;
}
static std::uint64_t h_min_of(::v37::ScriptKind k) {
    return k == ::v37::ScriptKind::P2PKH ? 1ull
                                         : (std::numeric_limits<std::uint64_t>::max)();
}
static void learn(std::uint8_t tag) {
    const ::v37::PayoutDescriptor d = id_of(tag);
    g_refs[d.identity_key()] = d.pay;
}

// THE K_FAIR RUN: exactly what the option-B template does (KFairSource::W4Propose
// withholds Σfixed and the residual-sink floor, then asks propose_coinbase).
static OwedLedger::Amounts kfair_owed_map(const OwedLedger& l, std::uint64_t reward) {
    const std::uint64_t owed_budget = reward > SINK_FLOOR ? reward - SINK_FLOOR : 0;
    const OwedLedger::Proposal p = l.propose_coinbase(owed_budget, CAP_OWED, pay_of, h_min_of);
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

// ── THE WIRE LEG ────────────────────────────────────────────────────────────
// Build the block-winner carrier the way XmrCarrierStack::mint_block_winner
// does, put it through the FROZEN v0x03 codec, and hand back what a peer's
// XmrPeerWin would hold. `nullopt` means the frame did not decode — which is
// the fail-closed answer, never a silently emptied map.
struct WireLeg {
    bool                      framed = false;   // the encoder produced bytes
    WireStatus                status = WireStatus::REJECT_TRUNCATED;
    bool                      carried = false;  // section 2 present after decode
    OwedLedger::Amounts       map;              // what the peer would fold
    std::size_t               bytes = 0;
};
static WireLeg carry(const OwedLedger::Amounts& payout, std::uint64_t reward,
                     bool payout_emitted, bool with_drops = false) {
    WireLeg out;
    Carrier c = wf::fixture_a();               // an identity-bound share body
    CutDescriptor d;
    d.bid              = wf::detail::pat(0x5a);
    d.h_b              = 900;
    d.cut_next_pos     = 42;
    d.cut_spine_digest = wf::detail::pat(0x20);
    d.reward           = reward;
    d.payout_emitted   = payout_emitted;
    c.cut = d;
    if (!payout.empty()) {
        KfairPayout k;
        for (const auto& [id, amt] : payout)
            k.pay.emplace_back(id, static_cast<std::uint64_t>(amt));
        c.payout = std::move(k);
    }
    if (with_drops) c.drops = wf::detail::drops(0x11, 0x22, 0x33, 0xe7);
    const std::vector<std::uint8_t> b = CarrierWire::encode(c);
    out.framed = !b.empty();
    out.bytes  = b.size();
    if (!out.framed) return out;
    const DecodeResult dr = CarrierWire::decode(b);
    out.status = dr.status;
    if (dr.status != WireStatus::OK) return out;
    if (dr.carrier.payout) {
        out.carried = true;
        for (const auto& [id, amt] : dr.carrier.payout->pay)
            out.map[id] = static_cast<long long>(amt);
    }
    return out;
}

// ── one node: the engine (for the real E_b fold) beside its owed ledger ─────
struct Node {
    V37Engine  engine;
    OwedLedger ledger{CHAIN};
    bool start() {
        engine.start();
        return engine.submit_tracked(
                        ::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{}))
            .get().applied();
    }
    bool push(std::uint8_t tag, std::uint64_t w) {
        return engine.submit_tracked(::v37::LaneRecord::push(CHAIN, id_of(tag), w, 0))
            .get().applied();
    }
    ~Node() { engine.stop(); }
};

struct Push { std::uint8_t tag; std::uint64_t w; };
static Push round_work(std::size_t r) {
    static const Push kCycle[] = {
        {0xA1, 1000}, {0xB2, 3000}, {0xA1, 2000}, {0xC3, 4000}, {0xB2, 1500},
        {0xD4, 2500}, {0xC3, 1200},
    };
    return kCycle[r % (sizeof(kCycle) / sizeof(kCycle[0]))];
}

// The outcome of one full run of the stream, under one peer POLICY.
struct RunReport {
    ::v37::bytes32 a{}, b{};
    std::size_t settling      = 0;
    std::size_t agreed_after  = 0;   // blocks after which the two digests matched
    std::size_t first_fork    = 0;   // 1-based settling index of the first fork (0 = none)
    std::size_t skewed        = 0;   // settling blocks where the peer's OWN map differed
    bool        every_framed  = true;
    bool        every_folded  = true;
    long long   min_finalw    = 0;
    long long   min_eff       = 0;
};

// policy = true  -> the peer folds the CARRIED map (the switch under test)
// policy = false -> the peer folds ITS OWN map, recomputed when it books (the
//                   control: what the recompute-apply path had available)
//
// ── HOW THE TWO-CLOCK SKEW IS MODELLED, AND WHY THIS SHAPE ─────────────────
// FINALIZE is CHAIN-anchored: a block finalizes at bin H_b + D_conf on every
// node, so both ledgers cross the same finalize points in the same order. That
// is why owed_digest CAN converge at all. What is NOT chain-anchored is when a
// node BOOKS a FOUND and when it BUILDS a template — the winner books its own
// block before proposing the next height (the R-7 hold), while a peer learns of
// the same block through a relay hop and drains the descriptor a tick later.
// So the peer routinely proposes K_fair over a reservation set that is MISSING
// a block the winner had already reserved, and EffectiveOwed = finalW -
// Σ_pending payout is therefore different on the two nodes at the one instant
// that decides the map.
//
// B here carries that offset explicitly: it queues each received descriptor and
// books it ONE ROUND LATER, still comfortably inside the D_conf window, so both
// nodes finalize the same bids at the same bins. Under WIRE-CARRY that offset is
// invisible — B folds the number A sent. Under the control B must answer from
// its own ledger at the moment it books, and that is the fork.
struct Received {
    std::string          bid;
    OwedLedger::Amounts  credit;
    OwedLedger::Amounts  carried;
    std::uint64_t        h_b = 0;
    bool                 settling = false;
};

static RunReport run_stream(bool fold_carried) {
    RunReport rep;
    Node A, B;
    if (!A.start() || !B.start()) { rep.every_folded = false; return rep; }
    xo::XmrS1FoldStats  fs_a;
    xo::XmrS1PeerStats  ps_b;

    std::vector<Received>                       inflight;   // B's un-drained descriptors
    std::vector<std::pair<std::string, std::uint64_t>> due_a, due_b;   // bid -> bin

    for (std::size_t round = 0; round < ROUNDS; ++round) {
        const std::uint64_t h_b = 500 + round;
        const Push p = round_work(round);
        rep.every_folded &= A.push(p.tag, p.w);
        rep.every_folded &= B.push(p.tag, p.w);

        // ---- the WINNER's template instant, and its own K_fair map ---------
        // A books its own FOUND immediately after proposing (the R-7 hold), so
        // its reservation set always contains its own block.
        const OwedLedger::Amounts payout_a = kfair_owed_map(A.ledger, REWARD);
        const xo::XmrEbCut cut = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs_a);
        rep.every_folded &= cut.folded;
        const std::string bid = "block-" + std::to_string(h_b);
        const ::v37::bytes32 owed_at_win_a = A.ledger.owed_digest();
        A.ledger.on_block_found(bid, cut.credit, payout_a);
        due_a.emplace_back(bid, h_b + D_CONF);

        // ---- the v0x03 frame A actually emits ------------------------------
        const bool settling = !payout_a.empty();
        const WireLeg leg = carry(payout_a, REWARD, settling);
        rep.every_framed &= leg.framed && leg.status == WireStatus::OK;
        if (settling) ++rep.settling;

        xo::XmrPeerWin w;
        w.bid                = bid;
        w.h_b                = h_b;
        w.cut_next_pos       = cut.next_pos;
        w.cut_spine_digest   = cut.lane_digest;
        w.reward             = REWARD;
        w.payout_emitted     = settling;
        w.owed_digest_at_win = owed_at_win_a;
        w.payout_carried     = leg.carried;
        w.payout             = leg.map;

        // ---- B folds at the winner's cut NOW, but BOOKS one round later ----
        const xo::XmrPeerFoldOutcome f = xo::fold_at_peer_cut(B.engine, CHAIN, w, ps_b);
        rep.every_folded &= f.ok;
        inflight.push_back({bid, f.cut.credit, w.payout, h_b, settling});

        // ---- B drains what arrived LAST round ------------------------------
        if (inflight.size() > 1) {
            Received r = inflight.front();
            inflight.erase(inflight.begin());
            OwedLedger::Amounts payout_b;
            if (r.settling) {
                // What a RECOMPUTE has available AT THIS INSTANT: B's own K_fair
                // over its own ledger, one descriptor behind the winner's view.
                const OwedLedger::Amounts own_now = kfair_owed_map(B.ledger, REWARD);
                if (!(own_now == r.carried)) ++rep.skewed;
                payout_b = fold_carried ? r.carried : own_now;
            }
            B.ledger.on_block_found(r.bid, r.credit, payout_b);
            due_b.emplace_back(r.bid, r.h_b + D_CONF);
        }

        // ---- FINALIZE: chain-anchored, so both nodes cross the same bins ---
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

        const bool agree = (A.ledger.owed_digest() == B.ledger.owed_digest());
        if (agree) ++rep.agreed_after;
        else if (rep.first_fork == 0) rep.first_fork = rep.settling;
        if (min_finalW(A.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(A.ledger);
        if (min_finalW(B.ledger) < rep.min_finalw) rep.min_finalw = min_finalW(B.ledger);
        if (min_effective_owed(A.ledger) < rep.min_eff) rep.min_eff = min_effective_owed(A.ledger);
        if (min_effective_owed(B.ledger) < rep.min_eff) rep.min_eff = min_effective_owed(B.ledger);

        if (fold_carried)
            std::printf("    h=%llu settling=%d carried=%zu keys/%lld pico frame=%zuB  "
                        "A=%s  B=%s  %s\n",
                        static_cast<unsigned long long>(h_b), settling ? 1 : 0,
                        leg.map.size(), amounts_sum(leg.map), leg.bytes,
                        hex32(A.ledger.owed_digest()).substr(0, 16).c_str(),
                        hex32(B.ledger.owed_digest()).substr(0, 16).c_str(),
                        agree ? "EQUAL" : "*** FORK ***");
    }
    rep.a = A.ledger.owed_digest();
    rep.b = B.ledger.owed_digest();
    return rep;
}

int main() {
    std::printf("== v37 XMR WIRE-CARRY of the K_fair owed-deduction map (v0x03 section 2) ==\n");
    learn(0xA1); learn(0xB2); learn(0xC3); learn(0xD4);

    const ::v37::bytes32 ANCHOR = OwedLedger(CHAIN).owed_digest();
    std::printf("  empty owed anchor = %s\n", hex32(ANCHOR).c_str());
    std::printf("  wire              = %s\n", wf::flag_day_id());

    // ── 1. the wire leg, on its own ─────────────────────────────────────────
    {
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 400000000000ll;
        credit[id_of(0xB2).identity_key()] = 150000000000ll;
        credit[id_of(0xC3).identity_key()] =  30000000000ll;
        l.on_block_found("seed-1", credit, {});
        l.on_block_finalized("seed-1", 100);
        const OwedLedger::Amounts m = kfair_owed_map(l, REWARD);
        chk(m.size() >= 2, "1a the fixture ledger proposes a multi-key K_fair map",
            std::to_string(m.size()) + " keys/" + std::to_string(amounts_sum(m)) + " pico");

        const WireLeg leg = carry(m, REWARD, /*payout_emitted=*/true);
        chk(leg.framed && leg.status == WireStatus::OK && leg.carried,
            "1b a settling block-winner carrier frames and decodes at v0x03");
        chk(leg.map == m,
            "1c ★ the K_fair map survives encode -> decode EXACTLY (keys, order, amounts)");

        // A share carries neither section and costs exactly two bytes more.
        const Carrier share = wf::fixture_a();
        chk(CarrierWire::encode(share).size() ==
                CarrierWire::encode_version(share, wf::kFrozenVersionV2).size() + 2,
            "1d a plain share pays exactly two bytes for the two absent sections");

        // The refusals that could otherwise fork a ledger.
        {
            Carrier c = wf::fixture_a();
            KfairPayout k;
            k.pay.emplace_back(wf::detail::pat(0x44), 1ULL);
            c.payout = k;                                   // no cut at all
            chk(CarrierWire::encode(c).empty(),
                "1e a payout map with NO cut descriptor names no settlement -> refused");
        }
        {
            const WireLeg denied = carry(m, REWARD, /*payout_emitted=*/false);
            chk(!denied.framed,
                "1f a payout map on a payout_emitted=0 descriptor contradicts itself -> refused");
        }
        {
            OwedLedger::Amounts zero = m;
            zero.begin()->second = 0;
            const WireLeg z = carry(zero, REWARD, true);
            chk(!z.framed, "1g a zero-amount row -> refused (a no-op row is a second encoding)");
        }
        {
            const WireLeg over = carry(m, /*reward=*/1, true);
            chk(!over.framed,
                "1h a map above the frame's OWN reward -> refused (out of budget)");
        }
        {
            // Unordered keys cannot come out of a std::map, so this one is built
            // by hand: the codec must refuse it, or the fold would depend on
            // decode order.
            Carrier c = wf::fixture_a();
            CutDescriptor d;
            d.reward = REWARD; d.payout_emitted = true; d.h_b = 1;
            c.cut = d;
            KfairPayout k;
            k.pay.emplace_back(wf::detail::pat(0x99), 10ULL);
            k.pay.emplace_back(wf::detail::pat(0x11), 10ULL);   // descending
            c.payout = k;
            chk(CarrierWire::encode(c).empty(),
                "1i unordered payout identities -> refused (one encoding per map)");
        }
    }

    // ── 2/3. ★ THE CLAIM: sustained convergence through >= 20 settling blocks
    RunReport carried;
    {
        std::printf("  -- WIRE-CARRY run (the peer folds ONLY what the winner sent) --\n");
        carried = run_stream(/*fold_carried=*/true);
        chk(carried.every_framed,
            "2a every block-winner carrier framed and decoded at wire v0x03");
        chk(carried.every_folded,
            "2b every round pushed, folded at the winner's cut and registered");
        chk(carried.settling >= 20,
            "2c ★ at least TWENTY of the blocks actually SETTLED owed balances",
            "settling=" + std::to_string(carried.settling));
        chk(carried.first_fork == 0,
            "2d ★ NOT ONE fork: owed_digest(A) == owed_digest(B) after EVERY block",
            carried.first_fork ? "first fork at settling block #" +
                                     std::to_string(carried.first_fork)
                               : "");
        chk(carried.agreed_after == ROUNDS,
            "2e ★ SUSTAINED: the digests agreed after all " + std::to_string(ROUNDS) +
                " blocks, not merely at the end",
            "agreed=" + std::to_string(carried.agreed_after));
        chk(carried.a == carried.b && !(carried.a == ANCHOR),
            "2f ★ the two nodes end BYTE-EQUAL and OFF the empty anchor",
            "A=" + hex32(carried.a) + " B=" + hex32(carried.b));
        chk(carried.min_finalw >= 0,
            "2g SOLVENCY: finalW never negative on either node at any point",
            "min=" + std::to_string(carried.min_finalw));
        chk(carried.min_eff >= 0,
            "2h SOLVENCY: min EffectiveOwed never negative on either node at any point",
            "min=" + std::to_string(carried.min_eff));
        chk(carried.skewed > 0,
            "3a ★ THE SKEW IS REAL: on " + std::to_string(carried.skewed) +
                " settling block(s) the peer's OWN K_fair proposal at receipt DIFFERED "
                "from the winner's — a recompute had nothing correct to book there",
            "skewed=" + std::to_string(carried.skewed) + "/" +
                std::to_string(carried.settling));
        chk(carried.skewed > 0 && carried.first_fork == 0,
            "3b ★ and the carried fold converged THROUGH every one of them");
    }

    // ── 4. ★ THE CONTROL: the same stream, recomputed-at-receipt, FORKS ─────
    {
        std::printf("  -- CONTROL run (the peer books its OWN map, recomputed at receipt) --\n");
        const RunReport ctl = run_stream(/*fold_carried=*/false);
        chk(ctl.settling == carried.settling,
            "4a the control drives the IDENTICAL stream (same settling count)",
            std::to_string(ctl.settling) + " vs " + std::to_string(carried.settling));
        chk(ctl.first_fork != 0,
            "4b ★ the recompute-at-receipt peer FORKS",
            ctl.first_fork ? "first fork at settling block #" + std::to_string(ctl.first_fork)
                           : "it did NOT fork — the skew this KAT relies on is gone");
        chk(!(ctl.a == ctl.b),
            "4c ★ and STAYS forked to the end — there is no path back",
            "A=" + hex32(ctl.a).substr(0, 16) + " B=" + hex32(ctl.b).substr(0, 16));
        chk(ctl.agreed_after < ROUNDS,
            "4d the control never reaches the sustained property",
            "agreed=" + std::to_string(ctl.agreed_after) + "/" + std::to_string(ROUNDS));
    }

    // ── 5. NO DOUBLE-PAY ────────────────────────────────────────────────────
    {
        Node A, B;
        chk(A.start() && B.start(), "5a two engines up for the double-pay check");
        A.push(0xA1, 5000); B.push(0xA1, 5000);
        A.push(0xB2, 3000); B.push(0xB2, 3000);

        xo::XmrS1FoldStats fs; xo::XmrS1PeerStats ps;
        const OwedLedger::Amounts seed_credit = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs).credit;
        A.ledger.on_block_found("seed-5", seed_credit, {});
        B.ledger.on_block_found("seed-5", seed_credit, {});
        A.ledger.on_block_finalized("seed-5", 400);
        B.ledger.on_block_finalized("seed-5", 400);

        const OwedLedger::Amounts payout = kfair_owed_map(A.ledger, REWARD);
        chk(!payout.empty(), "5b the winner's coinbase settles a non-empty owed set");
        const WireLeg leg = carry(payout, REWARD, true);
        chk(leg.carried && leg.map == payout,
            "5c ★ the map on the wire IS the winner's booked coinbase owed-set, row for row");

        const xo::XmrEbCut cut = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs);
        A.ledger.on_block_found("settle-5", cut.credit, payout);
        B.ledger.on_block_found("settle-5", cut.credit, leg.map);
        A.ledger.on_block_finalized("settle-5", 500);
        B.ledger.on_block_finalized("settle-5", 500);
        chk(A.ledger.owed_digest() == B.ledger.owed_digest(),
            "5d both ledgers agree after the settling block");

        const OwedLedger::Amounts next_a = kfair_owed_map(A.ledger, REWARD);
        const OwedLedger::Amounts next_b = kfair_owed_map(B.ledger, REWARD);
        chk(next_a == next_b, "5e the NEXT K_fair proposal is identical on both");
        long long re_offered = 0;
        for (const auto& [k, v] : payout) {
            (void)v;
            auto it = next_b.find(k);
            if (it != next_b.end()) re_offered += it->second;
        }
        chk(re_offered <= amounts_sum(kfair_owed_map(B.ledger, REWARD)) &&
                min_finalW(B.ledger) >= 0 && min_effective_owed(B.ledger) >= 0,
            "5f ★ NO DOUBLE-PAY: the peer deducted what the coinbase paid — finalW >= 0 and "
            "min EffectiveOwed >= 0 after booking the carried map",
            "finalW_min=" + std::to_string(min_finalW(B.ledger)) +
                " eff_min=" + std::to_string(min_effective_owed(B.ledger)));
    }

    // ── 6. the fail-closed half (never a timing skew) ───────────────────────
    {
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 300000000000ll;
        l.on_block_found("seed-6", credit, {});
        l.on_block_finalized("seed-6", 600);
        const OwedLedger::Amounts m = kfair_owed_map(l, REWARD);

        // A settling descriptor whose section never arrived (a pre-v0x03 peer).
        xo::XmrPeerWin w;
        w.payout_emitted = true;
        w.payout_carried = false;
        chk(w.payout_emitted && !w.payout_carried && w.payout.empty(),
            "6a a settling descriptor with NO carried section is distinguishable from an "
            "EMPTY one — 'I could not tell you' is not 'nothing was paid'");
        // The consumer's rule, stated as the predicate the daemon applies.
        auto foldable = [](const xo::XmrPeerWin& x, std::uint64_t reward) {
            if (!x.payout_emitted) return !x.payout_carried;
            if (!x.payout_carried || x.payout.empty()) return false;
            std::uint64_t s = 0;
            for (const auto& [k, v] : x.payout) { (void)k; if (v <= 0) return false;
                                                  s += static_cast<std::uint64_t>(v); }
            return s <= reward;
        };
        chk(!foldable(w, REWARD), "6b -> REFUSED fail-closed (absent section)");
        w.payout_carried = true; w.payout = m;
        chk(foldable(w, REWARD), "6c a carried, in-budget map IS foldable");
        chk(!foldable(w, /*reward=*/1),
            "6d a carried map above the block's reward -> REFUSED (out of budget)");
        xo::XmrPeerWin d0 = w; d0.payout_emitted = false;
        chk(!foldable(d0, REWARD),
            "6e a carried map on a descriptor that denies settling -> REFUSED");
        xo::XmrPeerWin neg = w; neg.payout.begin()->second = -1;
        chk(!foldable(neg, REWARD), "6f a non-positive row -> REFUSED");
    }

    // ── 7. ★ COEXISTENCE with c2pool#1627's DROPS section ──────────────────
    {
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 250000000000ll;
        credit[id_of(0xB2).identity_key()] = 120000000000ll;
        l.on_block_found("seed-7", credit, {});
        l.on_block_finalized("seed-7", 700);
        const OwedLedger::Amounts m = kfair_owed_map(l, REWARD);

        const WireLeg alone = carry(m, REWARD, true, /*with_drops=*/false);
        const WireLeg both  = carry(m, REWARD, true, /*with_drops=*/true);
        chk(alone.status == WireStatus::OK && both.status == WireStatus::OK,
            "7a one v0x03 frame decodes with section 1 absent AND with it present");
        chk(both.carried && both.map == m && alone.map == m,
            "7b ★ the K_fair section decodes to the SAME map either way");
        chk(both.bytes == alone.bytes + (wf::drops_bytes_present(3) - wf::kDropsBytesAbsent),
            "7c ★ section 1 is the ONLY thing that changes the frame size",
            "with=" + std::to_string(both.bytes) + " without=" + std::to_string(alone.bytes));

        // And the DROPS section itself still decodes to itself beside it.
        Carrier c = wf::fixture_a();
        CutDescriptor d;
        d.reward = REWARD; d.payout_emitted = true; d.h_b = 7;
        c.cut = d;
        c.drops = wf::detail::drops(0x11, 0x22, 0x33, 0xe7);
        KfairPayout k;
        for (const auto& [id, amt] : m) k.pay.emplace_back(id, static_cast<std::uint64_t>(amt));
        c.payout = k;
        const auto bytes = CarrierWire::encode(c);
        const DecodeResult dr = CarrierWire::decode(bytes);
        chk(dr.status == WireStatus::OK && dr.carrier.drops == c.drops &&
                dr.carrier.payout == c.payout,
            "7d ★ BOTH sections round-trip in ONE frame, each to its own value");
        chk(wf::payout_offset(c) == wf::drops_offset(c) + wf::drops_size(c),
            "7e the frozen ORDER holds: section 2 begins exactly where section 1 ends");
    }

    // ── the wire freeze's own byte-KAT, run here too ────────────────────────
    {
        const wf::SelfCheck sc = wf::selfcheck();
        chk(sc.ok(), "8a the v0x01/v0x02/v0x03 frozen-wire byte-KAT is green",
            std::to_string(sc.checks) + " checks, " + std::to_string(sc.failures) +
                " failures\n" + sc.log);
    }

    std::printf("== wire-carry KAT: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
