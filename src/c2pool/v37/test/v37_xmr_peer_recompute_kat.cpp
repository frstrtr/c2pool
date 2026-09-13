// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_peer_recompute_kat.cpp
//     canonical_coinbase_matches = (a) PEER-RECOMPUTE — the receive-side K_fair
//     payout leg, and the convergence THROUGH SETTLEMENT that it buys.
//
// THE DEFECT THIS PINS. After X2 + S-1b + S-1c two peered nodes emit the
// byte-identical owed_digest — but only until the first block whose option-B
// coinbase actually SETTLES owed. From that block the winner deducts a real
// payout map at FINALIZE (finalW -= payout) while the receiver deducts nothing,
// because the map is unbounded and is deliberately NOT on the frozen v0x02
// carrier wire (w3_wire_freeze.hpp). The receiver's only honest move was to
// REFUSE the block outright, and from then on the two owed ledgers were forked.
// Case 3 reproduces BOTH shapes of that defect directly — the refusal, and the
// "credit E_b, deduct nothing" shortcut — so this KAT goes red if either
// returns.
//
// THE FIX UNDER TEST. xmr_peer_payout_recompute.hpp. K_fair is
// OwedLedger::propose_coinbase (w4_settlement.hpp §4.6): oldest-owed-first over
// EffectiveOwed, taken O(K) off the incremental EffectiveOwedIndex ordered
// view, and DETERMINISTIC — two ledgers in the same state, asked for the same
// budget under the same caps, return the same keys in the same order with the
// same amounts. The node already runs it once per height for its OWN template,
// so the receiver does not compute a new payout: it REMEMBERS the one its own
// K_fair run proposed for that height and books it. A second CALLER of K_fair,
// never a second K_fair — and no edit to src/sharechain/v37, to the
// owed_digest() body, to fold_eb or to settle_block.
//
// WHY THE CACHED HEIGHT AND NOT A FRESH CALL (case 6). propose_coinbase is a
// pure function of the ledger STATE, and the two nodes share that state at one
// instant per height: both build h when their tip is h-1, after the finalize of
// bin h-1 and before the finalize of bin h. A receiver that called
// propose_coinbase when the descriptor landed would routinely call it ONE
// FINALIZE LATE (it learns of the block from the chain, a poll away, while the
// descriptor is a poll plus a relay hop away) — and FINALIZE moves EffectiveOwed
// by +credit and re-arms first_eligible, so the late call returns a DIFFERENT
// map. Case 6 makes that concrete: the same ledger, one finalize apart, proposes
// a different K_fair map, and the guard refuses on the digest rather than
// booking it.
//
// WHAT IS ASSERTED (a FIXED record stream: no clocks, no sockets, no RNG)
//   1  K_fair is reproducible: two ledgers fed the same events propose the
//      byte-identical map — same keys, same order, same amounts
//   2  ★ THE CLAIM: FOUR blocks, THREE of them SETTLING (a non-empty owed
//      payout), driven through FOUND(credit=E_b, payout) -> FINALIZE on BOTH
//      ledgers, the receiver's payout RECOMPUTED — owed_digest(A) ==
//      owed_digest(B) after every one of them, non-empty, and finalW never
//      negative on either side
//   3  THE DEFECT, REPRODUCED TWICE: the receiver REFUSING the settling block,
//      and the receiver crediting E_b with an EMPTY payout — each diverges
//   4  NO DOUBLE-PAY: after a settling block finalizes, the next K_fair
//      proposal on each ledger is identical and no longer contains what that
//      block already paid
//   5  the guards, one bit each: no-record, ambiguous, reward, digest, empty,
//      shape — every one leaves ok == false with its own stable code
//   6  the cut instant is load-bearing: the SAME ledger one finalize apart
//      proposes a different map, and the digest guard is what catches it
//   7  cache mechanics: re-observing the same (height, template_id) is a no-op
//      that does NOT re-stamp the digest; the ring is bounded and an aged-out
//      height is a no-record refusal, never a stale map
//   8  the NON-SETTLING shape is untouched: a win with no owed outputs still
//      books an empty payout and both nodes still converge (regression guard —
//      (a) must not have moved the pre-(a) path)
//   9  ★ THE RESERVATION GUARD. K_fair draws on EffectiveOwed = finalW -
//      Σ_pending payout, and owed_digest commits to the FINALIZED half ONLY, so
//      two nodes can hold the SAME digest and still propose different maps when
//      one has more blocks RESERVED. Observed on the 2-node rig: the winner
//      mined two rival blocks at one height and reserved both, the receiver had
//      drained one descriptor, the digests agreed and the maps differed by 47x.
//      Case 9 reproduces that and shows the reservation witness REFUSING it
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
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_peer_payout_recompute.hpp>
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>

using namespace c2pool::v37n;
using ::c2pool::v37n::settle::OwedLedger;
namespace xo = c2pool::v37n::xmr::o2;

// ── the tiny self-harness ───────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void chk(bool ok, const std::string& name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", name.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s%s%s\n", name.c_str(),
                                    detail.empty() ? "" : " — ", detail.c_str()); }
}
static std::string hex32(const ::v37::bytes32& d) { return xo::s1_hex32(d); }

// ── fixtures ────────────────────────────────────────────────────────────────
static constexpr ::v37::ChainId CHAIN      = 7;
static constexpr std::uint64_t  REWARD     = 600000000000ull;   // 0.6 XMR in piconero
static constexpr std::uint64_t  SINK_FLOOR = 1000ull;           // the mandated residual sink
static constexpr std::uint64_t  D_CONF     = 3;
static constexpr unsigned       CAP_OWED   = 0;                 // R1: 0 == UNBOUNDED

// A P2PKH identity, exactly as the sibling S-1b KAT builds one: the KIND is
// irrelevant to the fold and to K_fair (both read canonical keys and weights),
// and a Bitcoin-family kind keeps this KAT free of the ed25519 point-check
// backend so a light build still runs it.
static ::v37::PayoutDescriptor id_of(std::uint8_t tag) {
    ::v37::PayoutDescriptor d;
    ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH;
    r.payload.assign(20, tag);
    d.pay = r;
    return d;
}

// The identity -> ScriptRef resolution the coinbase builder does. A key this
// node cannot pay resolves to RAW, whose h_min is UINT64_MAX, so W4 CARRIES it
// (canon branch) instead of emitting a dust output.
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

// ── THE K_FAIR RUN: exactly what the option-B template does ─────────────────
// xmr_o2_settlement_source.hpp (KFairSource::W4Propose) withholds the mandated
// outputs from the owed budget — Σfixed and the residual-sink floor — then asks
// OwedLedger::propose_coinbase for the set, and the Owed-role outputs of the
// assembled coinbase are exactly that proposal. This is that call, and nothing
// else: the map the daemon caches per height is read off the assembled template
// that came out of this same selection.
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

// ── the reservation witness, modelled ──────────────────────────────────────
// In the daemon the count comes from FinalizeConnect::known_blocks_in(): every
// own FOUND and every peer descriptor ever offered, by height. Here it is a
// plain set so a case can make it GROW after a build, which is the shape that
// produced a silent mis-book on the 2-node rig.
static std::map<std::uint64_t, int> g_known;
static void note_known(std::uint64_t h) { ++g_known[h]; }
static std::size_t known_now(std::uint64_t lo, std::uint64_t hi) {
    std::size_t n = 0;
    for (auto it = g_known.upper_bound(lo); it != g_known.end() && it->first < hi; ++it)
        n += static_cast<std::size_t>(it->second);
    return n;
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

// The per-round work stream. Fixed, so every run of this KAT folds the same
// E_b at the same prefixes.
struct Push { std::uint8_t tag; std::uint64_t w; };
static const std::vector<Push> kRoundWork = {
    {0xA1, 1000}, {0xB2, 3000}, {0xA1, 2000}, {0xC3, 4000}, {0xB2, 1500},
};

int main() {
    std::printf("== v37 XMR canonical_coinbase_matches (a): K_fair PEER-RECOMPUTE KAT ==\n");
    learn(0xA1); learn(0xB2); learn(0xC3);

    const ::v37::bytes32 ANCHOR = OwedLedger(CHAIN).owed_digest();
    std::printf("  empty owed anchor = %s\n", hex32(ANCHOR).c_str());

    // ── 1. K_fair is REPRODUCIBLE across two independent ledgers ────────────
    {
        OwedLedger a(CHAIN), b(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 400000000000ll;
        credit[id_of(0xB2).identity_key()] = 200000000000ll;
        for (OwedLedger* l : {&a, &b}) {
            l->on_block_found("seed-1", credit, {});
            l->on_block_finalized("seed-1", 100);
        }
        chk(a.owed_digest() == b.owed_digest() && !(a.owed_digest() == ANCHOR),
            "1a two ledgers fed the same events hold the same non-empty owed commitment");
        const OwedLedger::Amounts ma = kfair_owed_map(a, REWARD);
        const OwedLedger::Amounts mb = kfair_owed_map(b, REWARD);
        chk(!ma.empty() && ma == mb,
            "1b K_fair (propose_coinbase) proposes the BYTE-IDENTICAL map on both",
            "A=" + std::to_string(ma.size()) + " keys/" + std::to_string(amounts_sum(ma)) +
                " B=" + std::to_string(mb.size()) + " keys/" + std::to_string(amounts_sum(mb)));
        // The ORDER is part of the claim: propose_coinbase yields
        // (first_eligible ASC, key ASC), and a map keyed by bytes32 preserves
        // the key order, so an equal map IS an equal selection.
        const OwedLedger::Proposal pa = a.propose_coinbase(REWARD - SINK_FLOOR, CAP_OWED,
                                                           pay_of, h_min_of);
        const OwedLedger::Proposal pb = b.propose_coinbase(REWARD - SINK_FLOOR, CAP_OWED,
                                                           pay_of, h_min_of);
        bool same_order = pa.outs.size() == pb.outs.size();
        for (std::size_t i = 0; same_order && i < pa.outs.size(); ++i)
            same_order = (pa.outs[i].key == pb.outs[i].key) &&
                         (pa.outs[i].amount == pb.outs[i].amount);
        chk(same_order, "1c the SELECTION ORDER (oldest-owed-first) is identical too");
    }

    // ── 2. ★ THE CLAIM: four blocks, three of them SETTLING ─────────────────
    ::v37::bytes32 digest_a_final{}, digest_b_final{};
    std::size_t settling_rounds = 0;
    {
        Node A, B;
        chk(A.start() && B.start(), "2a two engines up, the same lane seeded on both");

        xo::XmrKFairPayoutCache   cache_b;       // node B's own K_fair runs, per height
        xo::XmrRecomputeStats     st_b;
        xo::XmrS1FoldStats        fs_a;
        xo::XmrS1PeerStats        ps_b;

        bool ok_all = true, digests_agree = true, payouts_agree = true;
        std::uint32_t tid = 0;

        for (std::size_t round = 0; round < kRoundWork.size() - 1; ++round) {
            const std::uint64_t h_b = 500 + round;
            // The SAME admitted carrier reaches both engines, in the same order.
            ok_all &= A.push(kRoundWork[round].tag, kRoundWork[round].w);
            ok_all &= B.push(kRoundWork[round].tag, kRoundWork[round].w);

            // ---- THE TEMPLATE INSTANT, on BOTH nodes -----------------------
            // Each builds its own template for h_b while its tip is h_b-1: the
            // previous round's FINALIZE has happened, this round's has not. That
            // is the one instant the two states coincide, which is why the maps
            // agree — and it is exactly where the daemon's after_refresh hook
            // records the map (main_v37_xmr.cpp).
            ++tid;
            const OwedLedger::Amounts payout_a = kfair_owed_map(A.ledger, REWARD);
            const std::uint64_t cur_b = (h_b > D_CONF) ? h_b - D_CONF - 1 : 0;
            cache_b.observe(h_b, REWARD, tid, B.ledger.owed_digest(),
                            kfair_owed_map(B.ledger, REWARD),
                            cur_b, known_now(cur_b, h_b), &st_b);
            note_known(h_b);   // the win we are about to receive for this height

            // ---- A WINS h_b: fold E_b at its own tip, register the FOUND ----
            const xo::XmrEbCut cut = xo::fold_at_tip(A.engine, CHAIN, REWARD, fs_a);
            ok_all &= cut.folded && !cut.credit.empty();
            const std::string bid = "block-" + std::to_string(h_b);
            const ::v37::bytes32 owed_at_win_a = A.ledger.owed_digest();
            A.ledger.on_block_found(bid, cut.credit, payout_a);

            // ---- the descriptor A puts on the v0x02 wire -------------------
            xo::XmrPeerWin w;
            w.bid                = bid;
            w.h_b                = h_b;
            w.cut_next_pos       = cut.next_pos;
            w.cut_spine_digest   = cut.lane_digest;
            w.reward             = REWARD;
            w.payout_emitted     = !payout_a.empty();   // ★ R-7: the truth
            w.owed_digest_at_win = owed_at_win_a;

            // ---- B RECEIVES it: fold at the winner's cut, RECOMPUTE payout --
            const xo::XmrPeerFoldOutcome f =
                xo::fold_at_peer_cut(B.engine, CHAIN, w, ps_b);
            ok_all &= f.ok;
            OwedLedger::Amounts payout_b;
            if (w.payout_emitted) {
                ++settling_rounds;
                const xo::XmrPeerPayoutOutcome ro = xo::recompute_peer_payout(cache_b, w, st_b, known_now);
                ok_all &= ro.ok;
                payout_b = ro.payout;
                payouts_agree &= (payout_b == payout_a);
            }
            B.ledger.on_block_found(bid, f.cut.credit, payout_b);

            // ---- both finalize at the SAME bin, and must AGREE -------------
            A.ledger.on_block_finalized(bid, h_b + D_CONF);
            B.ledger.on_block_finalized(bid, h_b + D_CONF);
            digests_agree &= (A.ledger.owed_digest() == B.ledger.owed_digest());
            std::printf("    h=%llu settling=%d payout=%zu keys/%lld pico  A=%s  B=%s\n",
                        static_cast<unsigned long long>(h_b), w.payout_emitted ? 1 : 0,
                        payout_a.size(), amounts_sum(payout_a),
                        hex32(A.ledger.owed_digest()).substr(0, 16).c_str(),
                        hex32(B.ledger.owed_digest()).substr(0, 16).c_str());
        }

        digest_a_final = A.ledger.owed_digest();
        digest_b_final = B.ledger.owed_digest();

        chk(ok_all, "2b every round folded, recomputed and registered without a refusal");
        chk(settling_rounds >= 3,
            "2c at least THREE of the blocks actually SETTLED owed (non-empty coinbase payout)",
            "settling=" + std::to_string(settling_rounds));
        chk(payouts_agree,
            "2d ★ the RECOMPUTED payout is byte-identical to the winner's on every settling block");
        chk(digests_agree,
            "2e ★ owed_digest(A) == owed_digest(B) after EVERY block, settling ones included");
        chk(digest_a_final == digest_b_final && !(digest_a_final == ANCHOR),
            "2f ★ the two nodes end BYTE-EQUAL and OFF the empty anchor",
            "A=" + hex32(digest_a_final) + " B=" + hex32(digest_b_final));
        chk(st_b.applied == settling_rounds && st_b.no_record == 0 && st_b.digest_mismatch == 0,
            "2g the recompute applied on every settling block and refused none",
            "applied=" + std::to_string(st_b.applied));
        chk(min_finalW(A.ledger) >= 0 && min_finalW(B.ledger) >= 0,
            "2h SOLVENCY: finalW never goes negative on either node — no block finalized more "
            "payout than entitlement");
    }

    // ── 3. THE DEFECT, REPRODUCED (both shapes) ─────────────────────────────
    {
        // Shape 1: the receiver REFUSES the settling block (the pre-(a) rule).
        OwedLedger a(CHAIN), b(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 500000000000ll;
        for (OwedLedger* l : {&a, &b}) {
            l->on_block_found("seed-3", credit, {});
            l->on_block_finalized("seed-3", 200);
        }
        const OwedLedger::Amounts payout = kfair_owed_map(a, REWARD);
        chk(!payout.empty(), "3a the block under test really is SETTLING");

        OwedLedger::Amounts credit2;
        credit2[id_of(0xB2).identity_key()] = 300000000000ll;
        a.on_block_found("block-3", credit2, payout);
        a.on_block_finalized("block-3", 210);
        // b refuses: no FOUND at all.
        chk(!(a.owed_digest() == b.owed_digest()),
            "3b PRE-(a) DEFECT #1: a receiver that REFUSES the settling block forks the ledgers");

        // Shape 2: the receiver credits E_b but books an EMPTY payout.
        OwedLedger c(CHAIN);
        c.on_block_found("seed-3", credit, {});
        c.on_block_finalized("seed-3", 200);
        c.on_block_found("block-3", credit2, {});          // credit, deduct nothing
        c.on_block_finalized("block-3", 210);
        chk(!(a.owed_digest() == c.owed_digest()),
            "3c PRE-(a) DEFECT #2: crediting E_b with an EMPTY payout forks them too — the "
            "receiver's finalW keeps balances the winner's coinbase already paid");
    }

    // ── 4. NO DOUBLE-PAY ────────────────────────────────────────────────────
    {
        OwedLedger a(CHAIN), b(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 400000000000ll;
        credit[id_of(0xB2).identity_key()] = 100000000000ll;
        for (OwedLedger* l : {&a, &b}) {
            l->on_block_found("seed-4", credit, {});
            l->on_block_finalized("seed-4", 300);
        }
        const OwedLedger::Amounts before = kfair_owed_map(a, REWARD);
        const long long paid = amounts_sum(before);
        chk(paid > 0, "4a the first template proposes a real payout", std::to_string(paid));

        xo::XmrKFairPayoutCache cache;
        xo::XmrRecomputeStats   st;
        cache.observe(310, REWARD, 1, b.owed_digest(), kfair_owed_map(b, REWARD),
                      306, known_now(306, 310), &st);

        xo::XmrPeerWin w;
        w.bid = "block-4"; w.h_b = 310; w.reward = REWARD;
        w.payout_emitted = true; w.owed_digest_at_win = a.owed_digest();
        const xo::XmrPeerPayoutOutcome ro = xo::recompute_peer_payout(cache, w, st, known_now);
        chk(ro.ok && ro.payout == before, "4b the receiver reproduces the winner's map exactly");

        a.on_block_found("block-4", {}, before);
        b.on_block_found("block-4", {}, ro.payout);
        a.on_block_finalized("block-4", 313);
        b.on_block_finalized("block-4", 313);
        chk(a.owed_digest() == b.owed_digest(),
            "4c both ledgers agree after the settling block");

        const OwedLedger::Amounts after_a = kfair_owed_map(a, REWARD);
        const OwedLedger::Amounts after_b = kfair_owed_map(b, REWARD);
        chk(after_a == after_b, "4d the NEXT template proposes the same thing on both");
        chk(amounts_sum(after_a) < paid,
            "4e ★ NO DOUBLE-PAY: what the settled block paid is gone from the next proposal",
            "before=" + std::to_string(paid) + " after=" + std::to_string(amounts_sum(after_a)));
        chk(min_finalW(a) >= 0 && min_finalW(b) >= 0, "4f finalW stays solvent on both");
    }

    // ── 5. the guards, one bit each ─────────────────────────────────────────
    {
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 400000000000ll;
        l.on_block_found("seed-5", credit, {});
        l.on_block_finalized("seed-5", 400);
        const OwedLedger::Amounts good = kfair_owed_map(l, REWARD);

        xo::XmrPeerWin w;
        w.bid = "block-5"; w.h_b = 410; w.reward = REWARD;
        w.payout_emitted = true; w.owed_digest_at_win = l.owed_digest();

        {   // (a) no record for that height
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "no-record" && st.no_record == 1,
                "5a no template of ours for that height -> REFUSED [no-record]", o.refusal);
        }
        {   // (b) two DIFFERENT maps at the same height
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            c.observe(410, REWARD, 1, w.owed_digest_at_win, good, 406, known_now(406, 410), &st);
            OwedLedger::Amounts other = good;
            other[id_of(0xC3).identity_key()] = 5ll;
            c.observe(410, REWARD, 2, w.owed_digest_at_win, other, 406, known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "ambiguous" && st.ambiguous == 1,
                "5b two different templates for one height -> REFUSED [ambiguous]", o.refusal);
        }
        {   // (c) a different reward => a different budget => a different set
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            c.observe(410, REWARD - 1, 1, w.owed_digest_at_win, good, 406, known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "reward" && st.reward_mismatch == 1,
                "5c our template's reward != the winner's -> REFUSED [reward]", o.refusal);
        }
        {   // (d) the ledgers had already diverged at the cut
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            ::v37::bytes32 other_digest = w.owed_digest_at_win;
            other_digest[0] = static_cast<std::uint8_t>(other_digest[0] ^ 0xff);
            c.observe(410, REWARD, 1, other_digest, good, 406, known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "digest" && st.digest_mismatch == 1,
                "5d our owed_digest at the build != the winner's at the win -> REFUSED [digest]",
                o.refusal);
        }
        {   // (e) the winner emitted; our own K_fair proposed nothing
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            c.observe(410, REWARD, 1, w.owed_digest_at_win, OwedLedger::Amounts{}, 406,
                      known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "empty" && st.empty_map == 1,
                "5e winner settled but our proposal is EMPTY -> REFUSED [empty]", o.refusal);
        }
        {   // (f) an unpayable shape
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            OwedLedger::Amounts bad;
            bad[id_of(0xA1).identity_key()] = -1ll;
            c.observe(410, REWARD, 1, w.owed_digest_at_win, bad, 406, known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(!o.ok && std::string(o.code) == "shape" && st.bad_shape == 1,
                "5f a non-positive amount -> REFUSED [shape]", o.refusal);

            xo::XmrKFairPayoutCache c2; xo::XmrRecomputeStats st2;
            OwedLedger::Amounts over;
            over[id_of(0xA1).identity_key()] = static_cast<long long>(REWARD) + 1;
            c2.observe(410, REWARD, 1, w.owed_digest_at_win, over, 406, known_now(406, 410), &st2);
            const auto o2 = xo::recompute_peer_payout(c2, w, st2, known_now);
            chk(!o2.ok && std::string(o2.code) == "shape" && st2.bad_shape == 1,
                "5g Σ payout above the reward -> REFUSED [shape]", o2.refusal);
        }
        {   // the positive control, so the six refusals above are not vacuous
            xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
            c.observe(410, REWARD, 1, w.owed_digest_at_win, good, 406, known_now(406, 410), &st);
            const auto o = xo::recompute_peer_payout(c, w, st, known_now);
            chk(o.ok && std::string(o.code) == "recomputed" && o.payout == good &&
                    o.sum == static_cast<std::uint64_t>(amounts_sum(good)) && st.applied == 1,
                "5h POSITIVE CONTROL: the same win with the right record is APPLIED");
        }
    }

    // ── 6. the cut INSTANT is load-bearing ──────────────────────────────────
    {
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 100000000000ll;
        l.on_block_found("seed-6", credit, {});
        l.on_block_finalized("seed-6", 500);

        const ::v37::bytes32 digest_before = l.owed_digest();
        const OwedLedger::Amounts map_before = kfair_owed_map(l, REWARD);

        // ONE more FINALIZE — the state a receiver reaches when it learns of the
        // block from the chain before the descriptor lands.
        OwedLedger::Amounts credit2;
        credit2[id_of(0xB2).identity_key()] = 250000000000ll;
        l.on_block_found("seed-6b", credit2, {});
        l.on_block_finalized("seed-6b", 510);
        const OwedLedger::Amounts map_after = kfair_owed_map(l, REWARD);

        chk(!(map_before == map_after),
            "6a ONE finalize later the SAME ledger proposes a DIFFERENT K_fair map — which is "
            "why the receive path may not simply call propose_coinbase when the descriptor lands",
            std::to_string(amounts_sum(map_before)) + " -> " + std::to_string(amounts_sum(map_after)));
        chk(!(digest_before == l.owed_digest()),
            "6b and the owed_digest moved with it, so the guard SEES the wrong instant");

        // The guard, driven with the late record: refused on the digest.
        xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
        c.observe(520, REWARD, 1, l.owed_digest(), map_after, 516, known_now(516, 520), &st);
        xo::XmrPeerWin w;
        w.bid = "block-6"; w.h_b = 520; w.reward = REWARD;
        w.payout_emitted = true; w.owed_digest_at_win = digest_before;   // the winner's instant
        const auto o = xo::recompute_peer_payout(c, w, st, known_now);
        chk(!o.ok && std::string(o.code) == "digest",
            "6c ★ a record taken one finalize late is REFUSED, never booked", o.refusal);
    }

    // ── 7. cache mechanics ──────────────────────────────────────────────────
    {
        xo::XmrKFairPayoutCache c(3);
        xo::XmrRecomputeStats   st;
        OwedLedger::Amounts m;
        m[id_of(0xA1).identity_key()] = 42ll;
        ::v37::bytes32 d0{}; d0[0] = 0x11;
        ::v37::bytes32 d1{}; d1[0] = 0x22;

        c.observe(600, REWARD, 1, d0, m, 596, known_now(596, 600), &st);
        c.observe(600, REWARD, 1, d1, m, 596, known_now(596, 600), &st);  // SAME template id: a no-op
        chk(c.find(600) && c.find(600)->owed_digest == d0 && c.find(600)->builds == 1 &&
                st.observed == 1,
            "7a re-observing the same (height, template_id) does NOT re-stamp the digest");

        c.observe(600, REWARD, 2, d1, m, 596, known_now(596, 600), &st);  // REBUILD, same map
        chk(c.find(600) && !c.find(600)->ambiguous && c.find(600)->builds == 2,
            "7b a rebuild that proposes the SAME map at the same reward is not ambiguous");

        c.observe(601, REWARD, 3, d0, m, 597, known_now(597, 601), &st);
        c.observe(602, REWARD, 4, d0, m, 598, known_now(598, 602), &st);
        c.observe(603, REWARD, 5, d0, m, 599, known_now(599, 603), &st);  // depth 3: 600 falls out
        chk(c.size() == 3 && c.find(600) == nullptr && c.find(603) != nullptr &&
                c.oldest_height() == 601 && c.newest_height() == 603,
            "7c the ring is BOUNDED and an aged-out height is a miss, never a stale map");

        xo::XmrPeerWin w;
        w.bid = "block-7"; w.h_b = 600; w.reward = REWARD;
        w.payout_emitted = true; w.owed_digest_at_win = d0;
        const auto o = xo::recompute_peer_payout(c, w, st, known_now);
        chk(!o.ok && std::string(o.code) == "no-record",
            "7d an aged-out height REFUSES rather than guessing");
    }

    // ── 8. the NON-SETTLING shape is untouched ──────────────────────────────
    {
        OwedLedger a(CHAIN), b(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 700000000000ll;
        // payout_emitted == false: the receive path books an EMPTY payout, which
        // is exactly what it did before (a) — the whole entitlement carries.
        a.on_block_found("block-8", credit, {});
        b.on_block_found("block-8", credit, {});
        a.on_block_finalized("block-8", 700);
        b.on_block_finalized("block-8", 700);
        chk(a.owed_digest() == b.owed_digest() && !(a.owed_digest() == ANCHOR),
            "8a a NON-settling win still converges with an empty payout leg on both sides");
        chk(amounts_sum(a.finalW()) == 700000000000ll,
            "8b and the whole entitlement carries forward as owed, undeducted");
    }

    // ── 9. ★ THE RESERVATION GUARD — the rig's real silent-divergence shape ──
    // On the 2-node regtest the winner mined TWO rival blocks at one height and
    // reserved BOTH; the receiver had drained only the first descriptor when it
    // built the next height's template. The two owed_digests AGREED (they commit
    // to the finalized half only) and the two K_fair maps differed by 47x. This
    // pins the witness that refuses it.
    {
        g_known.clear();
        OwedLedger l(CHAIN);
        OwedLedger::Amounts credit;
        credit[id_of(0xA1).identity_key()] = 400000000000ll;
        l.on_block_found("seed-9", credit, {});
        l.on_block_finalized("seed-9", 800);

        note_known(805);                                // one rival, drained before the build
        xo::XmrKFairPayoutCache c; xo::XmrRecomputeStats st;
        const OwedLedger::Amounts map_at_build = kfair_owed_map(l, REWARD);
        c.observe(806, REWARD, 1, l.owed_digest(), map_at_build, 802, known_now(802, 806), &st);

        xo::XmrPeerWin w;
        w.bid = "block-9"; w.h_b = 806; w.reward = REWARD;
        w.payout_emitted = true; w.owed_digest_at_win = l.owed_digest();

        const auto ok_before = xo::recompute_peer_payout(c, w, st, known_now);
        chk(ok_before.ok && ok_before.payout == map_at_build,
            "9a with the reservation set unchanged the record is APPLIED");

        note_known(805);                                // the SECOND rival, learned late
        const auto o = xo::recompute_peer_payout(c, w, st, known_now);
        chk(!o.ok && std::string(o.code) == "reservation" && st.reservation == 1,
            "9b ★ a block in the window learned AFTER the build -> REFUSED [reservation]: our "
            "K_fair drew on a smaller reservation than the winner's, and the equal owed_digest "
            "could not have told us", o.refusal);
        chk(!(o.payout == map_at_build) && o.payout.empty(),
            "9c and nothing is handed back to book");
        g_known.clear();
    }

    std::printf("\n== %d passed, %d failed ==\n", g_pass, g_fail);
    if (g_fail == 0)
        std::printf("digest_a=%s\ndigest_b=%s\n",
                    hex32(digest_a_final).c_str(), hex32(digest_b_final).c_str());
    return g_fail == 0 ? 0 : 1;
}
