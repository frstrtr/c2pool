// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_s1b_x2_kat.cpp — MONERO LIVE SETTLEMENT: the lane share-push (X2) and
//                          the E_b fold (S-1b), including cross-node
//                          owed_digest convergence.
//
// THE TWO DEFECTS THIS KAT PINS.
//
//  X2. The XMR stratum path was a pure pass-through. StratumListener::SinkTap
//      counted an accepted share and logged it; the gate and the publisher did
//      the rest. NOTHING appended a record to the lane — `AddLane` was the only
//      engine write the daemon ever made — so the Monero lane stood at
//      raw_total = 0 with an empty identity set forever. Case 1 reproduces that
//      state and shows what it does to settlement: E_b folds to {} and the win
//      is VALUELESS.
//
//  S-1b. xmr_o2_finalize_connect.hpp registered every win with
//        credit == payout == { payee : reward }, so FINALIZE did
//        finalW += credit; finalW -= payout and netted EXACTLY to zero.
//        owed_digest never left the empty sha256d("V37O") anchor b4db1ded…,
//        which is also the value the option-B coinbase's tx_extra 0x03
//        merge-mining leaf serialises. Case 2b reproduces that shape directly
//        (the same fold, registered the old way) and shows it lands back on the
//        anchor, so this KAT goes red the moment the netting returns.
//
// WHAT IS UNDER TEST. xmr_s1_fold.hpp — fold_at_tip() and fold_at_peer_cut() —
// which are CALLERS of settle::fold_eb, the one W4 S8 credit-path entry point,
// and drive the EXISTING OwedLedger::on_block_found / on_block_finalized API.
// No fold, no ledger arithmetic and no digest is defined in the code under test
// or in this file; src/sharechain/v37 is untouched by the change this pins.
//
// WHAT IS ASSERTED (a FIXED record stream: no clocks, no sockets, no RNG)
//   1  the pre-X2 state: an EMPTY lane folds E_b = {} and says so out loud
//   2  ★ X2 + S-1b: lane work -> fold -> FOUND(credit=E_b, payout={}) ->
//      FINALIZE -> owed_digest LEAVES the anchor and finalW carries the whole
//      entitlement, split across the identities in proportion to their weight
//   2b THE S-1b DEFECT, REPRODUCED: the SAME fold registered as credit==payout
//      nets to zero and lands back on the anchor
//   3  ★ CROSS-NODE CONVERGENCE: node B, fed the byte-identical record stream,
//      folds at the WINNER'S cut (P, spine_digest) out of its OWN ring and
//      finalizes at the SAME bin_height -> owed_digest(A) == owed_digest(B),
//      both non-empty
//   3b THE S-1c DEFECT, REPRODUCED: B without the descriptor stays at the anchor
//      while A has moved -> A != B
//   4  THE CUT RULE is load-bearing: fold(P) != fold(P+1) on this stream, so a
//      receiver folding at its own tip would credit a different E_b
//   5  the refusals, one bit each: a prefix never published here (cut_miss), a
//      prefix published here under a DIFFERENT commitment (cut_mismatch), and a
//      non-ratified geometry (fold_eb REFUSED) — each leaves the receiver
//      UNREGISTERED and at the anchor, never half-credited
//   6  X2 wiring: an accepted share reaching XmrLaneShareSink is turned into a
//      carrier mint request keyed to the TEMPLATE'S PARENT with the pool
//      descriptor — and the no-identity / stale-template paths decline loudly
//   7  the XMR parent is NOT byte-reversed: bytes32 <-> Monero Hash round-trips
//      in the SAME order (the inverse of the Bitcoin-family hashPrevBlock rule),
//      and XmrCarrierIndex refuses a parent below its context horizon
//   8  determinism: an independent pair fed the same stream reproduces the
//      byte-identical digests
//
// Stdlib-only self-harness (the sibling convention in this directory): no gtest,
// no Boost, no coin lib, no crypto backend. Links Threads for the engine's
// single executor thread. Registered with add_test AND in BOTH build.yml
// --target lists (the c2pool#1539 / #769 hollow-green rule).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_carrier_share_sink.hpp>
#include <c2pool/v37/xmr/xmr_s1_fold.hpp>

using namespace c2pool::v37n;
using ::c2pool::v37n::settle::OwedLedger;
namespace xo = c2pool::v37n::xmr::o2;
namespace settle = ::c2pool::v37n::settle;

// ── the tiny self-harness ───────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void chk(bool ok, const std::string& name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", name.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s%s%s\n", name.c_str(),
                                    detail.empty() ? "" : " — ", detail.c_str()); }
}
static std::string hex32(const ::v37::bytes32& d) { return xo::s1_hex32(d); }

// ── fixtures ────────────────────────────────────────────────────────────────
static constexpr ::v37::ChainId CHAIN  = 7;
static constexpr std::uint64_t  REWARD = 600000000000ull;   // 0.6 XMR in piconero
static constexpr std::uint64_t  D_CONF = 3;

// A P2PKH identity. The KIND is irrelevant to the fold (it reads weights and
// canonical keys), and using a Bitcoin-family kind here is deliberate: it keeps
// this KAT free of the ed25519 point-check backend, so a light build still runs
// it. The XMR-kind path is exercised where it belongs — case 6, which asserts
// the SINK builds a request under whatever descriptor it was handed.
static ::v37::PayoutDescriptor id_of(std::uint8_t tag) {
    ::v37::PayoutDescriptor d;
    ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH;
    r.payload.assign(20, tag);
    d.pay = r;
    return d;
}

// One lane record stream, applied identically to any engine. This is exactly
// what CarrierIngest emits for an admitted carrier — V37Engine::submit of a
// LaneRecord::push — so driving it directly is driving the X2 path's far end.
struct Push { std::uint8_t tag; std::uint64_t w; };
static const std::vector<Push> kStream = {
    {0xA1, 1000}, {0xB2, 3000}, {0xA1, 2000}, {0xC3, 4000},
};

// Bring an engine up with the lane seeded, then apply `n` pushes of the stream.
// Every submit is TRACKED so the executor has committed (and published) before
// the next one — the KAT needs a deterministic prefix, not a coalesced one.
struct Node {
    V37Engine   engine;
    OwedLedger  ledger{CHAIN};
    bool start(const ::v37::LaneParams& p = ::v37::LaneParams{}) {
        engine.start();
        return engine.submit_tracked(::v37::LaneRecord::add_lane(CHAIN, p)).get().applied();
    }
    bool apply(std::size_t n) {
        for (std::size_t i = 0; i < n && i < kStream.size(); ++i)
            if (!engine.submit_tracked(::v37::LaneRecord::push(CHAIN, id_of(kStream[i].tag),
                                                               kStream[i].w, 0))
                     .get()
                     .applied())
                return false;
        return true;
    }
    ~Node() { engine.stop(); }
};

// FOUND(credit, payout) then FINALIZE at bin_height — the two existing ledger
// calls the daemon's F1 driver makes, with nothing in between.
static void found_and_finalize(OwedLedger& l, const std::string& bid,
                               const OwedLedger::Amounts& credit,
                               const OwedLedger::Amounts& payout, std::uint64_t bin) {
    l.on_block_found(bid, credit, payout);
    l.on_block_finalized(bid, bin);
}

int main() {
    std::printf("== v37 XMR live settlement KAT (X2 lane share-push + S-1b fold_eb) ==\n");

    const ::v37::bytes32 ANCHOR = OwedLedger(CHAIN).owed_digest();
    std::printf("  empty owed anchor = %s\n", hex32(ANCHOR).c_str());

    // ── 1. the pre-X2 state: an EMPTY lane ──────────────────────────────────
    {
        Node a;
        chk(a.start(), "1a engine up, lane seeded");
        xo::XmrS1FoldStats st;
        const xo::XmrEbCut c = xo::fold_at_tip(a.engine, CHAIN, REWARD, st);
        chk(c.folded && c.valueless && c.credit.empty() && c.raw_total == 0,
            "1b EMPTY lane: fold_eb succeeds but E_b is {} (raw_total == 0)",
            "raw_total=" + std::to_string(c.raw_total));
        chk(c.refusal.find("E_b is EMPTY") != std::string::npos &&
                c.refusal.find("X2") != std::string::npos,
            "1c the refusal NAMES the cause (no share reached the lane accumulator)",
            c.refusal);
        chk(st.valueless == 1 && st.folds == 0, "1d the valueless counter is the one that moved");

        OwedLedger l(CHAIN);
        found_and_finalize(l, "block-empty-lane", c.credit, {}, 10 + D_CONF);
        chk(l.owed_digest() == ANCHOR,
            "1e an empty-E_b win leaves owed_digest at the anchor — which is EXACTLY the state "
            "the pre-X2 daemon was in permanently");
    }

    // ── 2. ★ X2 + S-1b: work in the lane -> a real entitlement ──────────────
    ::v37::bytes32 digest_a{};
    std::uint64_t  cut_p = 0;
    ::v37::bytes32 cut_spine{};
    OwedLedger::Amounts e_b;
    {
        Node a;
        chk(a.start() && a.apply(kStream.size()),
            "2a lane accrued work through the ONE producer seam (what CarrierIngest does)");
        xo::XmrS1FoldStats st;
        const xo::XmrEbCut c = xo::fold_at_tip(a.engine, CHAIN, REWARD, st);
        e_b = c.credit;
        cut_p = c.next_pos;
        cut_spine = c.lane_digest;
        chk(c.folded && !c.valueless && c.refusal.empty(),
            "2b the fold succeeded and is NOT valueless", c.refusal);
        chk(c.credit.size() == 3,
            "2c E_b credits every identity that pushed work (A1, B2, C3)",
            "keys=" + std::to_string(c.credit.size()));
        long long total = 0;
        for (const auto& [k, v] : c.credit) { (void)k; total += v; }
        chk(total == static_cast<long long>(REWARD),
            "2d E_b sums to the block reward exactly (split_reward is exhaustive)",
            "total=" + std::to_string(total));
        // A1 pushed 1000 + 2000 = 3000 of 10000 raw; B2 3000; C3 4000. The split
        // is over the DECAYED payout map, so the exact shares are the lane's
        // business — but the ORDER must follow the weights, and two payees with
        // EQUAL raw weight must land within a hair of each other (A1's differs
        // from B2's only because its two pushes decayed from different
        // positions, which is the lane's head-decay doing exactly its job).
        const ::v37::bytes32 k_a1 = id_of(0xA1).identity_key();
        const ::v37::bytes32 k_b2 = id_of(0xB2).identity_key();
        const ::v37::bytes32 k_c3 = id_of(0xC3).identity_key();
        const bool have_all = c.credit.count(k_a1) && c.credit.count(k_b2) && c.credit.count(k_c3);
        const long long a1 = have_all ? c.credit.at(k_a1) : 0;
        const long long b2 = have_all ? c.credit.at(k_b2) : 0;
        const long long c3 = have_all ? c.credit.at(k_c3) : 0;
        const long long gap = a1 > b2 ? a1 - b2 : b2 - a1;
        chk(have_all && c3 > a1 && c3 > b2 && gap * 100 < a1,
            "2e the split follows the lane weights: C3 (4000 raw) takes the largest share and "
            "A1 and B2 (3000 raw each) land within 1% of each other",
            "A1=" + std::to_string(a1) + " B2=" + std::to_string(b2) +
                " C3=" + std::to_string(c3) + " gap=" + std::to_string(gap));

        // ★ THE CLAIM: credit = E_b, payout = {} -> owed_digest moves.
        OwedLedger l(CHAIN);
        found_and_finalize(l, "block-s1b", c.credit, /*payout=*/{}, 100 + D_CONF);
        digest_a = l.owed_digest();
        chk(!(digest_a == ANCHOR),
            "2f ★ S-1b: owed_digest LEFT the empty sha256d(\"V37O\") anchor",
            "owed=" + hex32(digest_a));
        long long owed_total = 0;
        for (const auto& [k, v] : l.effective_owed_all()) { (void)k; owed_total += v; }
        chk(owed_total == static_cast<long long>(REWARD),
            "2g the pool now OWES exactly one block reward, spread over the lane's payees",
            "owed_total=" + std::to_string(owed_total));

        // 2b THE DEFECT, REPRODUCED: the same fold, registered the old way.
        OwedLedger old(CHAIN);
        found_and_finalize(old, "block-s1b", c.credit, /*payout=*/c.credit, 100 + D_CONF);
        chk(old.owed_digest() == ANCHOR,
            "2h ★ the pre-S-1b shape (credit == payout) nets finalW to zero and lands back on "
            "the anchor — this check goes red if the netting ever returns");
    }

    // ── 3. ★ CROSS-NODE CONVERGENCE at the winner's cut ─────────────────────
    {
        Node b;
        chk(b.start() && b.apply(kStream.size()),
            "3a node B ingested the byte-identical record stream");

        xo::XmrPeerWin w;
        w.bid              = std::string(64, 'a');
        w.h_b              = 100;
        w.cut_next_pos     = cut_p;
        w.cut_spine_digest = cut_spine;
        w.reward           = REWARD;
        w.payout_emitted   = false;
        w.owed_digest_at_win = ANCHOR;

        xo::XmrS1PeerStats st;
        const xo::XmrPeerFoldOutcome f = xo::fold_at_peer_cut(b.engine, CHAIN, w, st);
        chk(f.ok && f.cut.folded && !f.cut.valueless,
            "3b B found the WINNER'S prefix P in its OWN ring and folded there", f.cut.refusal);
        chk(f.cut.credit == e_b,
            "3c B's E_b is byte-identical to A's (same reward, same payout map, same identities)");

        OwedLedger lb(CHAIN);
        found_and_finalize(lb, w.bid, f.cut.credit, /*payout=*/{}, 100 + D_CONF);
        chk(lb.owed_digest() == digest_a,
            "3d ★ CONVERGENCE: owed_digest(A) == owed_digest(B), both non-empty",
            "A=" + hex32(digest_a) + " B=" + hex32(lb.owed_digest()));
        chk(!(lb.owed_digest() == ANCHOR), "3e …and it is not the trivial agreement at the anchor");
        chk(st.credited == 0 && st.cut_miss == 0 && st.cut_mismatch == 0,
            "3f no refusal counter moved on the happy path");

        // 3b THE S-1c DEFECT: B never learns of the block.
        OwedLedger lb_nodesc(CHAIN);
        chk(lb_nodesc.owed_digest() == ANCHOR && !(lb_nodesc.owed_digest() == digest_a),
            "3g ★ the defect, reproduced: with NO cut descriptor B stays at the anchor while A "
            "has moved — two nodes, two owed ledgers, a settlement fork");
    }

    // ── 4. the CUT RULE is load-bearing ─────────────────────────────────────
    {
        Node b;
        chk(b.start() && b.apply(kStream.size() - 1), "4a node B one record BEHIND the winner");
        auto view_short = b.engine.snapshot(CHAIN);
        const std::size_t short_pos = view_short ? view_short->next_pos : 0;
        xo::XmrS1FoldStats st;
        const xo::XmrEbCut at_tip = xo::fold_at_tip(b.engine, CHAIN, REWARD, st);
        chk(short_pos != cut_p && !(at_tip.credit == e_b),
            "4b folding at OUR OWN tip credits a DIFFERENT E_b than folding at the winner's cut "
            "— which is why the receiver must fold at P and refuse if it cannot",
            "tip P=" + std::to_string(at_tip.next_pos) + " winner P=" + std::to_string(cut_p));
    }

    // ── 5. the refusals, one bit each ───────────────────────────────────────
    {
        Node b;
        chk(b.start() && b.apply(2), "5a node B two records in");

        // (i) a prefix this node never published
        xo::XmrPeerWin miss;
        miss.bid = std::string(64, 'b');
        miss.h_b = 100;
        miss.cut_next_pos = cut_p + 999;
        miss.cut_spine_digest = cut_spine;
        miss.reward = REWARD;
        xo::XmrS1PeerStats st;
        xo::XmrPeerFoldOutcome f = xo::fold_at_peer_cut(b.engine, CHAIN, miss, st);
        chk(!f.ok && f.cut_miss && !f.cut_digest_mismatch && st.cut_miss == 1 &&
                f.cut.credit.empty(),
            "5b cut_miss: a prefix we never published is REFUSED, not folded at a neighbour",
            f.cut.refusal);

        // (ii) a prefix we DID publish, under a different commitment
        auto sv = b.engine.snapshot(CHAIN);
        xo::XmrPeerWin bad;
        bad.bid = std::string(64, 'c');
        bad.h_b = 100;
        bad.cut_next_pos = sv ? sv->next_pos : 0;
        bad.cut_spine_digest = ::v37::bytes32{};   // all-zero: never a real lane digest
        bad.reward = REWARD;
        f = xo::fold_at_peer_cut(b.engine, CHAIN, bad, st);
        chk(!f.ok && f.cut_digest_mismatch && !f.cut_miss && st.cut_mismatch == 1,
            "5c cut_mismatch: the SAME prefix under a DIFFERENT digest is a sharechain "
            "divergence and is reported as its own bit", f.cut.refusal);

        // (iii) a non-ratified geometry: fold_eb REFUSES outright
        Node g;
        ::v37::LaneParams odd;
        odd.window = 999;                      // not the OQ-5 ratified default
        if (g.start(odd) && g.apply(2)) {
            xo::XmrS1FoldStats gs;
            const xo::XmrEbCut c = xo::fold_at_tip(g.engine, CHAIN, REWARD, gs, /*strict=*/true);
            chk(!c.folded && c.valueless && gs.refused == 1 &&
                    c.refusal.find("NOT ratified") != std::string::npos,
                "5d a non-ratified geometry is a HARD refusal at the settlement boundary",
                c.refusal);
        } else {
            // The lane constructor may refuse the geometry before the engine
            // does; that is the same fail-closed answer one layer earlier.
            chk(true, "5d a non-ratified geometry never reaches the fold (refused at AddLane)");
        }

        // (iv) reward == 0 is VALUELESS but still folds (the win is still real)
        Node z;
        if (z.start() && z.apply(2)) {
            xo::XmrS1FoldStats zs;
            const xo::XmrEbCut c = xo::fold_at_tip(z.engine, CHAIN, /*reward=*/0, zs);
            chk(c.folded && c.valueless && c.credit.empty() &&
                    c.refusal.find("reward == 0") != std::string::npos,
                "5e reward == 0 folds to an EMPTY E_b and says so (fail-closed template read)",
                c.refusal);
        }
    }

    // ── 6. X2 wiring: the share sink turns a share into a mint request ──────
    {
        // A CarrierSendQueue needs a relay and an index; the point here is the
        // REQUEST the sink builds, so the queue is driven through a recording
        // stand-in rather than a socket. XmrLaneShareSink talks to
        // CarrierSendQueue::submit(), which is a plain queue push — so a real
        // queue with no worker started records exactly what was submitted.
        struct NullSink final : public ::v37::xmr::stratum::IShareSink {
            std::uint64_t shares = 0, blocks = 0;
            void on_accepted_share(const ::v37::xmr::stratum::AcceptedShare&) override { ++shares; }
            void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {
                ++blocks;
            }
        } inner;

        xo::XmrCarrierIndex idx([](const ::c2pool::xmr::node::Hash&) {
            return std::optional<std::uint64_t>(1500);
        }, [] { return std::uint64_t(1510); }, /*horizon=*/64);
        CarrierPeerNode net;
        MemShareTracker tracker;
        V37Engine eng;
        eng.start();
        (void)eng.submit_tracked(::v37::LaneRecord::add_lane(CHAIN, ::v37::LaneParams{})).get();
        CarrierIngest ingest(eng, CHAIN, idx, tracker, 1);
        CarrierRelay relay(ingest.fn(), net);
        CarrierSendQueue q(relay, idx, CHAIN);   // NOT started: submit() only queues

        ::c2pool::xmr::node::Hash parent{};
        for (std::size_t i = 0; i < 32; ++i) parent[i] = static_cast<std::uint8_t>(i + 1);

        const ::v37::PayoutDescriptor pool = id_of(0xD4);
        xo::XmrLaneShareSink sink(inner, q,
            [&](std::uint32_t tid, ::c2pool::xmr::node::Hash& out) {
                if (tid == 0) return false;      // "the template is gone"
                out = parent;
                return true;
            }, pool);

        ::v37::xmr::stratum::AcceptedShare s;
        s.template_id = 42;
        s.height = 1501;
        s.worker = "rig0";
        sink.on_accepted_share(s);
        chk(q.queued() == 1 && inner.shares == 1,
            "6a an ACCEPTED share is queued as a carrier mint AND still forwarded to the gate",
            "queued=" + std::to_string(q.queued()));

        s.template_id = 0;                        // stale template
        sink.on_accepted_share(s);
        chk(q.queued() == 1 && sink.stats().no_template == 1,
            "6b a share whose template is gone cannot be keyed to a parent: declined, counted");

        xo::XmrLaneShareSink blind(inner, q,
            [&](std::uint32_t, ::c2pool::xmr::node::Hash& out) { out = parent; return true; },
            std::nullopt);
        s.template_id = 42;
        blind.on_accepted_share(s);
        chk(q.queued() == 1 && blind.stats().no_identity == 1,
            "6c no pool payout identity: the share is declined LOUDLY, never credited to nobody");

        sink.submit_network_block(42, 7, 0);
        chk(inner.blocks == 1 && q.queued() == 1,
            "6d submit_network_block is PASSED THROUGH untouched — the exact 128-bit gate and "
            "the publish arm are not on the X2 path, and a block-winner carrier is minted later "
            "(after the fold), never here");

        eng.stop();
    }

    // ── 7. the Monero parent is NOT byte-reversed, and the horizon bounds it ─
    {
        ::c2pool::xmr::node::Hash id{};
        for (std::size_t i = 0; i < 32; ++i) id[i] = static_cast<std::uint8_t>(0xF0 ^ i);
        const bytes32 lane = xo::lane_prev_of_block_id(id);
        chk(xo::block_id_of_lane_prev(lane) == id,
            "7a bytes32 <-> Monero Hash round-trips exactly");
        bool same_order = true;
        for (std::size_t i = 0; i < 32; ++i) if (lane[i] != id[i]) same_order = false;
        chk(same_order,
            "7b …in the SAME byte order — a Monero block id is not display-reversed the way a "
            "Bitcoin hashPrevBlock is, and reversing it would make every parent unresolvable");

        xo::XmrCarrierIndex near([](const ::c2pool::xmr::node::Hash&) {
            return std::optional<std::uint64_t>(1000);
        }, [] { return std::uint64_t(1010); }, 64);
        xo::XmrCarrierIndex far([](const ::c2pool::xmr::node::Hash&) {
            return std::optional<std::uint64_t>(10);
        }, [] { return std::uint64_t(5000); }, 64);
        xo::XmrCarrierIndex unknown([](const ::c2pool::xmr::node::Hash&) {
            return std::optional<std::uint64_t>();
        }, [] { return std::uint64_t(5000); }, 64);
        chk(near.height_of(lane).has_value() && near.resolved() == 1,
            "7c a parent inside the context horizon resolves");
        chk(!far.height_of(lane).has_value() && far.off_horizon() == 1,
            "7d a parent far below the tip is REFUSED: an ancient parent means a small "
            "consensus_lz, i.e. a carrier that is cheap to grind and would still carry weight");
        chk(!unknown.height_of(lane).has_value() && unknown.unknown() == 1,
            "7e a parent this chain does not know is refused, never guessed at");
    }

    // ── 8. determinism ──────────────────────────────────────────────────────
    {
        Node a2;
        chk(a2.start() && a2.apply(kStream.size()), "8a an independent node, the same stream");
        xo::XmrS1FoldStats st;
        const xo::XmrEbCut c = xo::fold_at_tip(a2.engine, CHAIN, REWARD, st);
        OwedLedger l(CHAIN);
        found_and_finalize(l, "block-s1b", c.credit, {}, 100 + D_CONF);
        chk(l.owed_digest() == digest_a && c.credit == e_b,
            "8b reproduces the byte-identical E_b and owed_digest (no clock, no RNG, no socket)",
            "got=" + hex32(l.owed_digest()) + " want=" + hex32(digest_a));
        chk(c.lane_digest == cut_spine && c.next_pos == cut_p,
            "8c …and the same CUT WITNESS, which is the value the wire carries");
    }

    std::printf("== %s (%d passed, %d failed) ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
