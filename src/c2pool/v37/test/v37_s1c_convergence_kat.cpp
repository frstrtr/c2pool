// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_s1c_convergence_kat.cpp — S-1c: TWO NODES, ONE owed_digest.
//
// THE DEFECT THIS KAT PINS. After the S-1 live fold-wiring, the node that MINED
// a block credits E_b and its owed_digest leaves the empty sha256d("V37O")
// anchor b4db1ded…. Its PEERS do not. A peer decodes the block-winning carrier,
// admits it as an ordinary share, and learns nothing at all about the block —
// so its finalW never moves and it stays at the anchor. Two nodes that ingested
// the byte-identical carrier stream therefore commit to DIFFERENT owed ledgers:
//
//     owed_digest(A) = <non-empty>      owed_digest(B) = b4db1ded…
//
// That is a settlement fork. Case 3 below reproduces it exactly, so this KAT
// goes red the moment the S-1c receive path is reverted.
//
// THE MECHANISM UNDER TEST. The winner names its fold on the wire — carrier
// wire v0x02's flat cut descriptor {won_block, bid, H_b, P, spine_digest@P,
// reward, payout_emitted, owed_digest_at_win} (w3_relay.hpp) — and the receiver
// re-runs THE SAME fold against its OWN engine at THE SAME lane prefix P, then
// drives its OWN ledger through the EXISTING on_block_found / on_block_finalized
// API (XbtcNode::on_peer_block_won). Nothing about the fold, the ledger, or the
// owed commitment is re-implemented on the receive side.
//
// THE CUT RULE, AND WHY IT IS THE WHOLE ARGUMENT. E_b = fold_eb(reward, view@P)
// is a pure function of (reward, view.payout, view.identities) at ONE lane
// prefix (w4_settlement.hpp S8). A receiver that folded at ITS OWN TIP would
// fold at a strictly LATER prefix — its tip already includes the very carrier it
// just admitted — and would credit a different E_b. Case 7 proves that is not a
// theoretical worry by folding the same reward at P and at P+1 and showing the
// two credits differ. Case 6 proves the receiver REFUSES rather than guesses
// when it cannot reproduce the carried cut.
//
// WHAT IS ASSERTED (a FIXED event stream: no clocks, no sockets, no RNG)
//   1  baseline: an untouched ledger commits to the empty anchor
//   2  ★ CONVERGENCE: A wins, the descriptor rides a REAL v0x02 frame through
//      encode -> decode, B folds at the carried cut and registers, both bury and
//      FINALIZE at the SAME bin_height -> owed_digest(A) == owed_digest(B),
//      BOTH non-empty, and equal to a pinned golden
//   3  THE DEFECT, REPRODUCED: the same stream with NO descriptor leaves the
//      peer at the anchor while the winner has moved -> A != B
//   4  determinism: a second, independent pair fed the same stream converges on
//      the byte-identical pair of digests
//   5  the double-drive guard: the winner's own descriptor coming back, and a
//      duplicate delivery, are both no-ops on the ledger
//   6  the refusals, one bit each: a prefix we never published (cut_miss), a
//      prefix we published with a DIFFERENT digest (cut_mismatch), a winner that
//      had already emitted a coinbase (payout_emitted), a descriptor that
//      arrived after we buried past H_b (too late) — every one leaves the peer
//      UNREGISTERED and at the anchor, never half-credited
//   7  the cut rule is load-bearing: fold(P) != fold(P+1) on this stream
//   8  the wire: won_block = 0 costs exactly one byte; a non-boolean flag byte
//      is REJECT_BAD_CUT; v0x01 refuses to carry a descriptor rather than drop it
//   9  ★★ DROPS-R3: the SAME convergence with HARVESTERS ATTACHED and
//      DELIBERATELY DIFFERENT local raindrop sets on the two nodes — the case
//      that diverges without the ruling. A composes its DROPS delta once and
//      carries it on a real wire-v0x03 frame; B folds the RECEIVED map and
//      CONSUMES (without crediting) its own buried harvest, so both harvesters
//      stay at one frontier. owed_digest(A) == owed_digest(B), byte for byte,
//      with a non-vacuity control (B's own harvest composes a DIFFERENT map) and
//      a DROPS-dormant control that converges on a DIFFERENT digest
//
// Stdlib-only self-harness (the sibling convention in this directory): no gtest,
// no Boost, no coin lib — MockCoinBackend + MemSettleStore only. Links Threads
// for the engine's single executor thread. Registered with add_test AND in BOTH
// build.yml --target lists (the #1539 / #769 hollow-green rule).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>
#include <c2pool/v37/v37_drop_harvest.hpp>
#include <c2pool/v37/v37_drops_enrollment.hpp>
#include <c2pool/v37/v37_share_counter.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>

using namespace c2pool::v37n::btc;
namespace settle = ::c2pool::v37n::settle;
using ::c2pool::v37n::Carrier;
using ::c2pool::v37n::CarrierWire;
using ::c2pool::v37n::CutDescriptor;
using ::c2pool::v37n::DecodeResult;
using ::c2pool::v37n::WireStatus;
using ::c2pool::v37n::WorkEvent;
using ::c2pool::v37n::cut_bid_bytes;
using ::c2pool::v37n::cut_bid_hex;
using ::c2pool::v37n::DropHarvester;
using ::c2pool::v37n::DropsCredit;
using ::c2pool::v37n::EnrollmentBook;
using ::c2pool::v37n::HarvestedDrop;
using ::c2pool::v37n::ShareCountBook;
namespace wire_freeze = ::c2pool::v37n::wire_freeze;

static int g_fails = 0;
static int g_checks = 0;
static void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("S1c-KAT FAIL: %s\n", what.c_str()); }
    else       std::printf("  ok: %s\n", what.c_str());
}

static std::string hex32(const ::v37::bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}

// The empty-fold anchor: sha256d("V37O") — what owed_digest() returns when the
// FINALIZED partition is empty. The S-1/S-1c defect's shared fingerprint.
static const char* kEmptyAnchor =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

// PINNED GOLDEN — the owed_digest BOTH nodes commit to after the fixed stream of
// case 2. A change here is a CONSENSUS-VISIBLE change to what the pool commits
// it owes; it may only move with a ruling, never with a refactor.
// It is the SAME value v37_s1_live_wiring_kat.cpp pins for the winner on this
// same fixed stream — which is the point: the receiver does not reach "a"
// convergent digest, it reaches THE winner's digest.
static const char* kOwedGolden =
    "4e13dd3f7472dae166e0d99ab778a296b8308afd6c2f55595747628800bdf0a4";

static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t tag) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    ::v37::PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}

static const ::v37::ChainId CH     = 7;
static const std::uint64_t  REWARD = 5000000000ULL;   // MockCoinBackend default
static const std::uint64_t  D_CONF = 3;
static const int            N_PUSH = 24;              // the fixed prefix length P

// A 64-hex block id: the wire carries the 32 raw bytes, the ledger keys on the
// hex string, and cut_bid_hex(cut_bid_bytes(h)) == h exactly.
static const char* kWonBid =
    "00000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566aa";

// ── ONE NODE STACK, fed the fixed stream ────────────────────────────────────
// Everything a case needs to drive one node and read what it committed. The
// coin backend is SHARED between the two nodes of a pair: two peered nodes
// watch the SAME coin chain, so they see the same tip and the same burial.
struct Node {
    std::shared_ptr<MockCoinBackend> coin;
    std::unique_ptr<XbtcNode>        node;

    explicit Node(std::shared_ptr<MockCoinBackend> c,
                  const ::v37::LaneParams& params)
        : coin(std::move(c)) {
        BtcNodeConfig cfg;
        cfg.lane_chain  = CH;
        cfg.lane_params = params;
        cfg.d_conf      = D_CONF;
        auto store = std::make_unique<MemSettleStore>();
        node = std::make_unique<XbtcNode>(cfg, std::move(store), coin, p2pkh_pay_of());
        node->open();
        node->start();
    }
    ~Node() { if (node) node->stop(); }

    // The SAME records the carrier relay would push (carrier_ingest.hpp:
    // admitted receipts -> LaneRecord::push), submitted tracked+get so the
    // arrival order is exactly the fixed order below AND every prefix 1..n is
    // separately PUBLISHED (one record per burst) — which is what puts prefix P
    // in the settlement ring on BOTH nodes.
    void push_fixed_stream(int n = N_PUSH) {
        for (int i = 0; i < n; ++i)
            node->engine()
                .submit_tracked(::v37::LaneRecord::push(
                    CH, p2pkh_desc(static_cast<std::uint8_t>(0xa0 + (i % 4))),
                    1 + (i % 3), 0))
                .get();
    }
    ::v37::bytes32 lane() const {
        auto s = node->lane_snapshot();
        return s ? s->digest : ::v37::bytes32{};
    }
    std::uint64_t next_pos() const {
        auto s = node->lane_snapshot();
        return s ? s->next_pos : 0;
    }
    ::v37::bytes32 owed() const { return node->ledger().owed_digest(); }
};

// The v0x02 descriptor the WINNER puts on the wire, built from the fold it
// actually ran (btc_node.hpp EbCut) — the same three lines main_v37_btc_dash.cpp
// runs in its mint seam.
static CutDescriptor descriptor_of_win(const std::string& bid_hex,
                                       std::uint64_t h_b, const EbCut& cut,
                                       bool payout_emitted,
                                       const ::v37::bytes32& owed_at_win) {
    CutDescriptor d;
    d.bid                = *cut_bid_bytes(bid_hex);
    d.h_b                = h_b;
    d.cut_next_pos       = cut.next_pos;
    d.cut_spine_digest   = cut.lane_digest;
    d.reward             = cut.reward;
    d.payout_emitted     = payout_emitted;
    d.owed_digest_at_win = owed_at_win;
    return d;
}

// Put a descriptor through a REAL carrier frame (encode at the current wire
// version, decode it back) so every case below exercises the wire, not a
// struct copy. Returns nullopt if the frame did not decode cleanly.
static std::optional<CutDescriptor> round_trip(const CutDescriptor& d,
                                               WireStatus* status = nullptr) {
    Carrier c = wire_freeze::fixture_a();   // any well-formed, identity-bound body
    c.cut = d;
    const std::vector<std::uint8_t> frame = CarrierWire::encode(c);
    DecodeResult dr = CarrierWire::decode(frame);
    if (status) *status = dr.status;
    if (dr.status != WireStatus::OK) return std::nullopt;
    return dr.carrier.cut;
}

static PeerWin peer_win_of(const CutDescriptor& d) {
    PeerWin w;
    w.bid                = cut_bid_hex(d.bid);
    w.h_b                = d.h_b;
    w.cut_next_pos       = d.cut_next_pos;
    w.cut_spine_digest   = d.cut_spine_digest;
    w.reward             = d.reward;
    w.payout_emitted     = d.payout_emitted;
    w.owed_digest_at_win = d.owed_digest_at_win;
    return w;
}

// ── ONE PAIRED RUN: A mines, B receives (or does not) ───────────────────────
struct PairRun {
    ::v37::bytes32 owed_a{}, owed_b{};
    ::v37::bytes32 lane_a{}, lane_b{};
    EbCut          cut_a, cut_b;
    PeerWinOutcome peer;
    bool           a_finalized = false, b_finalized = false;
    std::uint64_t  bin_a = 0, bin_b = 0;
    std::size_t    payout_outputs_a = 0;
    CutDescriptor  wire_in, wire_out;
    WireStatus     wire_status = WireStatus::OK;
    bool           wire_ok = false;
};

// `deliver` false reproduces the pre-S-1c world: B gets the carrier (its lane
// advances identically) but never learns the block happened.
static PairRun run_pair(const ::v37::LaneParams& params, bool deliver) {
    PairRun r;
    auto coin = std::make_shared<MockCoinBackend>();
    Node A(coin, params), B(coin, params);
    A.push_fixed_stream();
    B.push_fixed_stream();
    r.lane_a = A.lane();
    r.lane_b = B.lane();

    // A wins the block at a known height.
    coin->append_block("g0");
    const std::uint64_t win_h = coin->append_block(kWonBid);
    const ::v37::bytes32 owed_at_win = A.owed();
    WonBlockOutcome won = A.node->on_block_won(kWonBid, win_h, /*confirmations=*/0);
    r.cut_a            = won.cut;
    r.payout_outputs_a = won.outputs;

    // A names the fold on the wire; B reads it back off a real v0x02 frame.
    r.wire_in = descriptor_of_win(kWonBid, win_h, won.cut, won.emitted, owed_at_win);
    if (const auto got = round_trip(r.wire_in, &r.wire_status)) {
        r.wire_out = *got;
        r.wire_ok  = true;
        if (deliver) {
            r.peer  = B.node->on_peer_block_won(peer_win_of(*got));
            r.cut_b = r.peer.cut;
        }
    }

    // Bury D_conf deep; each node's OWN height-watch finalizes on the shared chain.
    for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
        coin->append_block("f" + std::to_string(i));
    for (const auto& s : A.node->poll_tip())
        if (s.bid == kWonBid) { r.a_finalized = true; r.bin_a = s.bin_height; }
    for (const auto& s : B.node->poll_tip())
        if (s.bid == kWonBid) { r.b_finalized = true; r.bin_b = s.bin_height; }

    r.owed_a = A.owed();
    r.owed_b = B.owed();
    return r;
}

int main() {
    std::printf("== v37 S-1c cross-node owed_digest convergence KAT ==\n");
    ::v37::LaneParams ratified{};   // the OQ-5 ratified default (gate-OFF V37.0)

    // ── 1. baseline ─────────────────────────────────────────────────────────
    {
        settle::OwedLedger fresh(CH);
        check(hex32(fresh.owed_digest()) == kEmptyAnchor,
              "1 empty ledger owed_digest == the sha256d(\"V37O\") anchor " +
                  std::string(kEmptyAnchor).substr(0, 8));
    }

    // ── 2. ★ CONVERGENCE ────────────────────────────────────────────────────
    PairRun c = run_pair(ratified, /*deliver=*/true);
    std::printf("   lane   A = %s\n   lane   B = %s\n", hex32(c.lane_a).c_str(), hex32(c.lane_b).c_str());
    std::printf("   owed   A = %s\n   owed   B = %s\n", hex32(c.owed_a).c_str(), hex32(c.owed_b).c_str());
    {
        check(c.lane_a == c.lane_b,
              "2a the two engines fed the same stream publish the SAME lane digest");
        check(c.cut_a.folded && !c.cut_a.credit.empty(),
              "2b the WINNER folded a non-empty E_b at its cut");
        check(c.wire_ok && c.wire_out == c.wire_in,
              "2c the cut descriptor survives a REAL v0x02 encode -> decode byte-exactly");
        check(c.peer.registered, "2d the RECEIVER registered the peer's block");
        check(c.cut_b.folded && c.cut_b.credit == c.cut_a.credit,
              "2e ★ the receiver folded the SAME E_b at the carried cut");
        check(c.cut_b.next_pos == c.cut_a.next_pos &&
              c.cut_b.lane_digest == c.cut_a.lane_digest,
              "2f ...at the SAME prefix P with the SAME lane commitment");
        check(c.peer.owed_at_win_agreed,
              "2g the VERIFY field agreed: both nodes stood at the same owed_digest at the win");
        check(c.a_finalized && c.b_finalized, "2h both height-watches FINALIZED the block");
        // FinalizeStep::bin_height == H_b + d_conf (btc_finalize_driver.hpp), and
        // d_conf is fleet-identical, so equal H_b => equal bin => equal K_fair
        // age stamps on both nodes. That is why no clock rides the wire.
        check(c.bin_a == c.bin_b && c.bin_a == 1 + D_CONF,
              "2i both finalized at the SAME bin_height == H_b + d_conf (" +
                  std::to_string(c.bin_a) + ")");
        check(hex32(c.owed_a) != kEmptyAnchor, "2j owed_digest(A) is NON-EMPTY");
        check(hex32(c.owed_b) != kEmptyAnchor, "2k owed_digest(B) is NON-EMPTY");
        check(c.owed_a == c.owed_b,
              "2l ★★ owed_digest(A) == owed_digest(B) — the two nodes CONVERGE");
        if (std::string(kOwedGolden).empty())
            std::printf("   REGEN kOwedGolden = \"%s\"\n", hex32(c.owed_a).c_str());
        else
            check(hex32(c.owed_a) == kOwedGolden,
                  "2m owed_digest == the pinned golden " + std::string(kOwedGolden).substr(0, 16));
        long long sum_a = 0, sum_b = 0;
        for (const auto& [k, v] : c.cut_a.credit) { (void)k; sum_a += v; }
        for (const auto& [k, v] : c.cut_b.credit) { (void)k; sum_b += v; }
        check(sum_a == static_cast<long long>(REWARD) && sum_b == sum_a,
              "2n sum(E_b) == the block reward on BOTH sides (exact split, no lost satoshi)");
        check(c.payout_outputs_a == 0,
              "2o a FRESH win withholds the W5 assembly, so BOTH payout maps are empty");
    }

    // ── 3. THE DEFECT, REPRODUCED ───────────────────────────────────────────
    {
        PairRun d = run_pair(ratified, /*deliver=*/false);
        check(d.owed_a == c.owed_a, "3a the winner is unaffected by whether the peer heard it");
        check(hex32(d.owed_b) == kEmptyAnchor,
              "3b ★ without the descriptor the PEER stays at the empty anchor");
        check(d.owed_a != d.owed_b,
              "3c ★ ...so A != B — the pre-S-1c settlement fork, pinned");
        check(!d.b_finalized, "3d the peer never even knew there was a block to finalize");
    }

    // ── 4. determinism ──────────────────────────────────────────────────────
    {
        PairRun e = run_pair(ratified, /*deliver=*/true);
        check(e.owed_a == c.owed_a && e.owed_b == c.owed_b,
              "4a an independent pair fed the same stream reaches the same two digests");
        check(e.owed_a == e.owed_b, "4b ...and they are still equal to each other");
        check(e.cut_b.credit == c.cut_b.credit, "4c the receive-side fold is deterministic");
    }

    // ── 5. the double-drive guard ───────────────────────────────────────────
    {
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, ratified);
        A.push_fixed_stream();
        coin->append_block("g0");
        const std::uint64_t h = coin->append_block(kWonBid);
        const ::v37::bytes32 owed_at_win = A.owed();
        WonBlockOutcome won = A.node->on_block_won(kWonBid, h, 0);
        const auto d = descriptor_of_win(kWonBid, h, won.cut, won.emitted, owed_at_win);
        const ::v37::bytes32 before = A.owed();
        // The winner's own descriptor coming back off the flood.
        PeerWinOutcome self = A.node->on_peer_block_won(peer_win_of(d));
        check(!self.registered && self.already_known,
              "5a the winner refuses to re-drive its OWN block from the wire");
        check(A.owed() == before, "5b ...and the ledger is untouched by that refusal");
        // A duplicate delivery to a genuine receiver.
        Node B(coin, ratified);
        B.push_fixed_stream();
        check(B.node->on_peer_block_won(peer_win_of(d)).registered, "5c first delivery registers");
        const ::v37::bytes32 after_first = B.owed();
        PeerWinOutcome dup = B.node->on_peer_block_won(peer_win_of(d));
        check(!dup.registered && dup.already_known, "5d a duplicate delivery is a no-op");
        check(B.owed() == after_first, "5e ...and the ledger is unchanged");
        check(B.node->s1c_stats().credited == 1 && B.node->s1c_stats().already_known == 1,
              "5f the S-1c counters record exactly one credit and one duplicate");
    }

    // ── 6. the refusals — one bit each, and never a half credit ─────────────
    {
        auto fresh_peer = [&](std::shared_ptr<MockCoinBackend> coin) {
            auto n = std::make_unique<Node>(coin, ratified);
            n->push_fixed_stream();
            return n;
        };
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, ratified);
        A.push_fixed_stream();
        coin->append_block("g0");
        const std::uint64_t h = coin->append_block(kWonBid);
        WonBlockOutcome won = A.node->on_block_won(kWonBid, h, 0);
        const auto good = descriptor_of_win(kWonBid, h, won.cut, won.emitted, A.owed());

        // (a) a prefix this node never published
        {
            auto B = fresh_peer(coin);
            auto bad = good; bad.cut_next_pos = good.cut_next_pos + 7;
            auto o = B->node->on_peer_block_won(peer_win_of(bad));
            check(!o.registered && o.cut_miss && !o.cut_digest_mismatch,
                  "6a an unpublished prefix P -> cut_miss, REFUSED");
            check(hex32(B->owed()) == kEmptyAnchor, "6b ...and the peer stays at the anchor");
        }
        // (b) a prefix we published, with a DIFFERENT lane digest
        {
            auto B = fresh_peer(coin);
            auto bad = good; bad.cut_spine_digest[0] ^= 0x01;
            auto o = B->node->on_peer_block_won(peer_win_of(bad));
            check(!o.registered && o.cut_digest_mismatch && !o.cut_miss,
                  "6c a DIFFERENT digest at a published P -> cut_mismatch, REFUSED");
            check(hex32(B->owed()) == kEmptyAnchor, "6d ...and the peer stays at the anchor");
        }
        // (c) the winner had already emitted a coinbase
        {
            auto B = fresh_peer(coin);
            auto bad = good; bad.payout_emitted = true;
            auto o = B->node->on_peer_block_won(peer_win_of(bad));
            check(!o.registered && o.refused_payout_emitted,
                  "6e payout_emitted -> fail-closed REFUSAL (payout map is not on the wire)");
            check(hex32(B->owed()) == kEmptyAnchor, "6f ...and the peer stays at the anchor");
        }
        // (d) the descriptor arrived after we buried past H_b
        {
            auto B = fresh_peer(coin);
            for (int i = 0; i <= static_cast<int>(D_CONF) + 2; ++i)
                coin->append_block("late" + std::to_string(i));
            B->node->poll_tip();                       // the cursor walks past H_b
            auto o = B->node->on_peer_block_won(peer_win_of(good));
            check(!o.registered && o.refused_too_late,
                  "6g a descriptor below our finalize cursor -> REFUSED (never strand a pending)");
            check(hex32(B->owed()) == kEmptyAnchor, "6h ...and the peer stays at the anchor");
        }
        // (e) reward == 0 on the wire: BOTH sides credit nothing — still convergent
        {
            auto B = fresh_peer(coin);
            auto z = good; z.reward = 0;
            auto o = B->node->on_peer_block_won(peer_win_of(z));
            check(o.registered && o.cut.folded && o.cut.valueless && o.cut.credit.empty(),
                  "6i reward == 0 registers VALUELESS (credits nobody) rather than refusing");
        }
    }

    // ── 7. the cut rule is load-bearing ─────────────────────────────────────
    // If folding at the receiver's TIP were equivalent to folding at the carried
    // prefix, S-1c would not need a descriptor at all. It is not: one more record
    // in the lane changes E_b.
    {
        auto coin = std::make_shared<MockCoinBackend>();
        Node B(coin, ratified);
        B.push_fixed_stream();
        auto at_p = B.node->engine().settlement_view_by_cut(CH, B.next_pos(), B.lane());
        check(at_p != nullptr, "7a the carried prefix P is readable from our own ring");
        B.push_fixed_stream(1);                        // the lane moves on (P -> P+1)
        auto at_p1 = B.node->engine().settlement_view_by_cut(CH, B.next_pos(), B.lane());
        check(at_p1 != nullptr && at_p1->next_pos == at_p->next_pos + 1,
              "7b ...and so is the next one");
        const auto e_p  = settle::fold_eb(REWARD, *at_p,  true);
        const auto e_p1 = settle::fold_eb(REWARD, *at_p1, true);
        check(e_p && e_p1, "7c both prefixes fold");
        check(e_p->credit != e_p1->credit,
              "7d ★ fold(P) != fold(P+1): folding at the receiver's tip WOULD diverge");
        // and the by-cut reader never serves a neighbouring prefix (O2.3)
        bool mismatch = false;
        check(B.node->engine().settlement_view_by_cut(CH, 999999, B.lane(), &mismatch) == nullptr &&
              !mismatch, "7e an unknown prefix returns nullptr, never a neighbour");
        check(B.node->engine().settlement_view_by_cut(CH, at_p->next_pos, ::v37::bytes32{},
                                                      &mismatch) == nullptr && mismatch,
              "7f a wrong digest at a known prefix reports the MISMATCH, not a miss");
    }

    // ── 8. the wire ─────────────────────────────────────────────────────────
    {
        Carrier bare = wire_freeze::fixture_a();
        const auto v1 = CarrierWire::encode_version(bare, 0x01);
        const auto v2 = CarrierWire::encode_version(bare, 0x02);
        check(v2.size() == v1.size() + 1 && v2[0] == 0x02 && v2.back() == 0x00,
              "8a won_block = 0 costs exactly one byte over the frozen v0x01 frame");
        // DROPS-R3: the build now EMITS v0x03, which is the v0x02 frame plus one
        // more absent-trailer byte when there is no credit map to carry.
        const auto v3 = CarrierWire::encode(bare);
        check(v3.size() == v2.size() + 1 && v3[0] == 0x03 && v3.back() == 0x00,
              "8a2 an absent DROPS credit map costs exactly one more byte");
        Carrier withcut = bare;
        withcut.cut = descriptor_of_win(kWonBid, 1, EbCut{}, false, ::v37::bytes32{});
        const auto vc = CarrierWire::encode_version(withcut, 0x02);
        check(vc.size() == v1.size() + wire_freeze::kCutDescBytesPresent,
              "8b a full descriptor costs exactly 122 bytes");
        check(CarrierWire::encode_version(withcut, 0x01).empty(),
              "8c v0x01 REFUSES to carry a descriptor (never silently dropped)");
        { auto t = vc; t[wire_freeze::cutdesc_offset(withcut) + wire_freeze::kOffWonBlock] = 0x05;
          check(CarrierWire::decode(t).status == WireStatus::REJECT_BAD_CUT,
                "8d a non-boolean won_block byte is REJECT_BAD_CUT"); }
        { auto t = vc; t[wire_freeze::cutdesc_offset(withcut) + wire_freeze::kOffCutPayoutEmit] = 0x05;
          check(CarrierWire::decode(t).status == WireStatus::REJECT_BAD_CUT,
                "8e a non-boolean payout_emitted byte is REJECT_BAD_CUT"); }
        { auto t = vc; t.pop_back();
          check(CarrierWire::decode(t).status == WireStatus::REJECT_TRUNCATED,
                "8f a short trailer is REJECT_TRUNCATED"); }
        const wire_freeze::SelfCheck sc = wire_freeze::selfcheck();
        check(sc.ok(), "8g the whole frozen-wire selfcheck (v0x01 AND v0x02 goldens) is green");
        std::printf("   wire-freeze [%s | %s]: %u checks\n", wire_freeze::layout_id(),
                    wire_freeze::layout_id_v2(), sc.checks);
    }

    // ── 9. ★★ DROPS-R3: TWO NODES, DIFFERENT RAINDROPS, ONE owed_digest ──
    //
    // THE CASE THAT DIVERGES WITHOUT THE RULING. E_b is recomputable at the
    // carried cut — the peer holds the reward, the payout map and the identity
    // view, so it re-runs the winner's fold and gets the winner's number. A
    // RAINDROP IS NOT. It is a below-target work event ONE node happened to see
    // on its own wire, and two nodes see different sets by construction. Before
    // this ruling the peer path re-folded E_b correctly and then ADDED ITS OWN
    // buried harvest, so the moment harvesters were attached the two nodes
    // credited different numbers for the SAME peer win and parted at the first
    // block. Recompute is not available: the evidence never reached the peer.
    //
    // THE FIX UNDER TEST. The winner composes its DROPS delta once, credits it,
    // and carries that same map on wire v0x03; the receiver folds the RECEIVED
    // map and its own harvest plays no part in someone else's block — but is
    // still CONSUMED at the same frontier, so the two harvesters stay in step.
    //
    // This case gives A and B DELIBERATELY DIFFERENT local raindrops (different
    // payees entirely, so the two maps cannot coincide by luck) and asserts the
    // owed_digests are BYTE-EQUAL after the peer win.
    std::printf("\n-- 9. DROPS-R3: harvester-attached cross-node convergence --\n");
    {
        // ── the fixture ──────────────────────────────────────────────────
        // Consensus target lz = 2 (h_T = 2^254 - 1), raindrops just above it, so
        // the estimate is a small, legible number instead of a hash count the
        // size of the universe. K = 4 -> six drops give J >= K comfortably.
        const unsigned DROP_LZ  = 2;
        const std::uint64_t IV  = 2;          // the harvested interval (buried)
        const int    FILLERS    = 8;          // so H_b - D_conf > IV
        auto payee = [](std::uint8_t tag) {
            ::v37::bytes32 k{};
            for (int i = 0; i < 32; ++i) k[static_cast<std::size_t>(i)] = tag;
            return k;
        };
        const ::v37::bytes32 PX = payee(0xA1);   // only NODE A ever sees these
        const ::v37::bytes32 PY = payee(0xB2);   // only NODE B ever sees these
        auto feed = [&](DropHarvester& h, const ::v37::bytes32& who,
                        std::uint8_t base) {
            HarvestedDrop d{};
            d.payee = who; d.interval = IV; d.consensus_lz = DROP_LZ; d.own_lz = 1;
            for (int i = 0; i < 6; ++i) {
                ::v37::bytes32 x{};
                x[0] = static_cast<std::uint8_t>(base + i);   // > 2^254: a near-miss
                for (int j = 1; j < 32; ++j)
                    x[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(i * 7 + j);
                d.hash = x;
                h.observe(d);
            }
        };

        ::v37::LaneParams dp = ratified;          // the ratified geometry, gate ON
        dp.subthreshold = ::v37::SubthresholdGate::for_version(1);

        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, dp), B(coin, dp);

        DropHarvester hA(dp.subthreshold.K), hB(dp.subthreshold.K);
        feed(hA, PX, 0x50);                       // A's raindrops
        feed(hB, PY, 0x60);                       // B's raindrops — DIFFERENT payee
        EnrollmentBook eA, eB;
        // EX ANTE: committed at interval 0, effective at 1; the harvest is at 2.
        eA.commit(PX, 0, 1); eA.commit(PY, 0, 1);
        eB.commit(PX, 0, 1); eB.commit(PY, 0, 1);
        ShareCountBook cA, cB;                    // the producer: armed from bin 0
        cA.arm(0); cB.arm(0);
        A.node->set_drop_harvester(&hA);
        B.node->set_drop_harvester(&hB);
        A.node->set_enrollment_book(&eA);
        B.node->set_enrollment_book(&eB);
        A.node->set_pre_harvest([&](std::uint64_t f) {
            cA.declare_into(hA, f, [&](std::uint64_t) { return DROP_LZ; }, &eA);
        });
        B.node->set_pre_harvest([&](std::uint64_t f) {
            cB.declare_into(hB, f, [&](std::uint64_t) { return DROP_LZ; }, &eB);
        });

        A.push_fixed_stream();
        B.push_fixed_stream();
        for (int i = 0; i < FILLERS; ++i) coin->append_block("d" + std::to_string(i));
        const std::uint64_t win_h = coin->append_block(kWonBid);
        check(win_h > D_CONF + IV,
              "9a the win is buried far enough that the harvested interval is eligible");
        const ::v37::bytes32 owed_at_win = A.owed();

        // ── A wins, composes ONCE, and names the map on the wire ─────────
        WonBlockOutcome won = A.node->on_block_won(kWonBid, win_h, 0);
        check(won.cut.folded, "9b the winner folded E_b at its own cut");
        check(!won.cut.drops_delta.empty(),
              "9c ★ and composed a NON-EMPTY DROPS map from its own harvest "
              "(otherwise this case would prove nothing)");
        check(won.cut.drops_delta.count(PX) == 1 && won.cut.drops_delta.count(PY) == 0,
              "9d the winner's map holds ITS OWN raindrop payee and only that one");
        check(!won.cut.drops_saturated, "9e no i64 clamp on a live-shaped cut");
        check(A.node->drop_harvester()->open_intervals() == 0,
              "9f the winner CONSUMED its harvest (F1: an interval settles once)");

        CutDescriptor cd = descriptor_of_win(kWonBid, win_h, won.cut, won.emitted,
                                             owed_at_win);
        DropsCredit dc;
        for (const auto& [k, v] : won.cut.drops_delta) dc.credit.emplace_back(k, v);
        dc.enrollment_digest = won.cut.enrollment_digest;

        // a REAL v0x03 frame, encode -> decode, not a struct copy
        Carrier frame = wire_freeze::fixture_a();
        frame.cut   = cd;
        frame.drops = dc;
        const std::vector<std::uint8_t> wire = CarrierWire::encode(frame);
        const DecodeResult dr = CarrierWire::decode(wire);
        check(dr.status == WireStatus::OK && dr.carrier.drops.has_value(),
              "9g the credit map rides a REAL v0x03 carrier frame");
        check(dr.carrier.drops.has_value() && *dr.carrier.drops == dc,
              "9h and comes back byte-exact, signed rows included");

        PeerWin pw = peer_win_of(*dr.carrier.cut);
        pw.has_drops = true;
        for (const auto& [k, v] : dr.carrier.drops->credit) pw.drops_credit[k] = v;
        pw.enrollment_digest = dr.carrier.drops->enrollment_digest;

        // ── what B WOULD have credited from its OWN harvest ──────────────
        // Computed here, off the same seam, purely to prove the divergence this
        // ruling removes is real on this very fixture.
        std::map<::v37::bytes32, long long> b_local;
        {
            auto snap = B.node->engine().settlement_view_by_cut(
                7, pw.cut_next_pos, pw.cut_spine_digest, nullptr);
            check(snap != nullptr, "9i B can read the carried prefix out of its ring");
            if (snap) {
                settle::DropsCompose bc;
                bc.price      = settle::work_price_at(pw.reward, *snap);
                bc.enrollment = &eB;
                DropHarvester probe(dp.subthreshold.K);
                feed(probe, PY, 0x60);
                probe.declare_shares(PY, IV, 0, DROP_LZ);
                b_local = settle::subthreshold_credit(dp, probe.take_buried(IV + 1), bc);
            }
        }
        check(!b_local.empty() && b_local.count(PY) == 1 && b_local.count(PX) == 0,
              "9j ★ B's OWN harvest composes a DIFFERENT map (different payee) — "
              "this is exactly the case that diverges without the ruling");
        check(b_local != pw.drops_credit,
              "9k and the two maps are not equal, so the convergence below is not "
              "a coincidence of two identical harvests");

        // ── B folds the RECEIVED map ─────────────────────────────────────
        const PeerWinOutcome po = B.node->on_peer_block_won(pw);
        check(po.registered, "9l B registered the peer's block");
        check(po.drops_carried_rows == pw.drops_credit.size(),
              "9m ★ B folded the WINNER'S map, every row of it");
        check(po.drops_local_discarded > 0,
              "9n ★ and CONSUMED its own buried harvest without crediting it — the "
              "frontier still moves, so those intervals cannot come back on B's "
              "next own win");
        check(B.node->drop_harvester()->open_intervals() == 0,
              "9o B's harvester is at the same frontier as A's");
        check(po.cut.drops_delta == pw.drops_credit,
              "9p and B's cut witness records the CARRIED map, not a local one");

        // ── bury and finalize on the shared chain ────────────────────────
        for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
            coin->append_block("z" + std::to_string(i));
        bool fa = false, fb = false;
        std::uint64_t ba = 0, bb = 0;
        for (const auto& st : A.node->poll_tip())
            if (st.bid == kWonBid) { fa = true; ba = st.bin_height; }
        for (const auto& st : B.node->poll_tip())
            if (st.bid == kWonBid) { fb = true; bb = st.bin_height; }
        check(fa && fb && ba == bb, "9q both height-watches finalized at the same bin");

        const ::v37::bytes32 oa = A.owed(), ob = B.owed();
        std::printf("   owed_digest(A) = %s\n   owed_digest(B) = %s\n",
                    hex32(oa).c_str(), hex32(ob).c_str());
        check(hex32(oa) != kEmptyAnchor && hex32(ob) != kEmptyAnchor,
              "9r both ledgers are settled, not sitting at the empty anchor");
        check(oa == ob,
              "★★ 9s BYTE-EQUAL owed_digest across two nodes with DIFFERENT local "
              "raindrop sets, after a PEER win with harvesters ATTACHED — the case "
              "that diverges today");

        // NON-VACUOUS: the DROPS map really moved the ledger. The same pair with
        // no harvesters at all lands somewhere else.
        {
            auto coin2 = std::make_shared<MockCoinBackend>();
            Node A2(coin2, dp), B2(coin2, dp);       // gate ON, NO harvester
            A2.push_fixed_stream();
            B2.push_fixed_stream();
            for (int i = 0; i < FILLERS; ++i) coin2->append_block("d" + std::to_string(i));
            const std::uint64_t wh2 = coin2->append_block(kWonBid);
            const ::v37::bytes32 oaw2 = A2.owed();
            WonBlockOutcome w2 = A2.node->on_block_won(kWonBid, wh2, 0);
            check(w2.cut.drops_delta.empty(),
                  "9t a node with no harvester composes an EMPTY map (inert seam)");
            CutDescriptor cd2 = descriptor_of_win(kWonBid, wh2, w2.cut, w2.emitted, oaw2);
            const auto got2 = round_trip(cd2);
            check(got2.has_value(), "9u the no-drops descriptor still rides the wire");
            if (got2) B2.node->on_peer_block_won(peer_win_of(*got2));
            for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
                coin2->append_block("z" + std::to_string(i));
            A2.node->poll_tip();
            B2.node->poll_tip();
            check(A2.owed() == B2.owed(),
                  "9v a DROPS-dormant pair also converges (an absent map folds as "
                  "empty, which is what that winner credited itself)");
            check(!(A2.owed() == oa),
                  "★ 9w and it lands on a DIFFERENT digest — the harvested run above "
                  "really did credit the DROPS map");
        }
    }

    std::printf("== %d checks, %d failures ==\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
