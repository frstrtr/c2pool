// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_kfloor_laneparam_kat.cpp — STEP-0 hotfix: k_floor is a LaneParam.
//
// THE HAZARD THIS KAT PINS. The W5 no-dust floor h_min(kind) = k_floor *
// output_size(kind) decides which owed balances the canonical coinbase emits
// (W4 propose_coinbase: emit iff take >= h_min, else CARRY). The payout map a
// node registers at FOUND and deducts at FINALIZE is that coinbase, so k_floor
// feeds owed_digest. It used to be the literal 1 in btc_node.hpp: node-local,
// committed nowhere. Two nodes that disagreed on it built different coinbases
// from byte-identical ledgers with nothing on any wire to say so: a SILENT
// owed_digest fork (the #1697 P0 class).
//
// THE FIX UNDER TEST. k_floor lives in ::v37::LaneParams (default 0 = no floor,
// digest-neutral; Family A runs LaneParams::family_a() = f_ref = 10), the BTC
// node reads it from there (XbtcNode::coinbase_budget), and it is committed:
//   - the canon lane digest: "KFL1" || u64 k_floor in the V37H header leaf,
//     appended iff k_floor != 0;
//   - the roundabout lane tag: rb::geometry_leaf mirrors the same block;
//   - the XMR relay HELLO lane_params_digest (asserted in xmr_relay_wire_kat).
// So two nodes with different k_floor are REFUSED explicitly (lane-digest
// mismatch at the S-1c cut rule; TAG_MISMATCH at roundabout admission), and two
// nodes with the same k_floor converge on the same coinbase.
//
// WHAT IS ASSERTED (fixed event stream: no clocks, no sockets, no RNG)
//   1  constants: f_ref = 10, the bare default is 0, family_a() / BtcNodeConfig
//      default is 10, h_min(P2WPKH) = 310 sat, h_min(P2PKH) = 340 sat, and the
//      node's coinbase budget reads the lane params (not a literal)
//   2  digest-neutral at zero: geometry_leaf(LaneParams{}) carries no KFL1 and
//      equals the pre-hotfix bytes; a k_floor-0 lane digest == the pre-hotfix
//      digest pinned below
//   3  committed when non-zero: the lane digest of the SAME stream differs for
//      k_floor 0 / 1 / 10, and the KFL1 block is byte-exact in geometry_leaf
//   4  ★ REFUSAL: A (k_floor 10) wins; B (k_floor 1 — the pre-hotfix value)
//      receives the REAL v0x02 descriptor and REFUSES it as cut_digest_mismatch,
//      stays unregistered and at the empty anchor — never a different credit
//   5  ★ CONVERGENCE: A and C (both k_floor 10): C registers, both finalize,
//      owed_digest(A) == owed_digest(C), and the buried coinbase each node
//      assembles with ITS OWN budget is byte-identical (outputs + state root)
//   6  the floor is load-bearing: over A's own ledger, a reward that leaves a
//      100-sat final take emits it under k_floor 1 (h_min 34) and CARRIES it
//      under k_floor 10 (h_min 340) — the exact fork the commitment prevents
//   7  roundabout lane tag: a carriage minted under k_floor 10 is REJECT_
//      ROUNDABOUT(TAG_MISMATCH) at a k_floor-1 validator, admitted at a
//      k_floor-10 one
//
// Stdlib-only self-harness (sibling convention): no gtest, no Boost, no coin
// lib — MockCoinBackend + MemSettleStore. Links Threads for the engine's
// executor. Registered with add_test AND on BOTH build.yml --target lists.
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>
#include <c2pool/v37/roundabout/rb_admission.hpp>

using namespace c2pool::v37n::btc;
namespace rb = ::c2pool::v37n::rb;   // cb / settle come from btc_node.hpp's namespace
using ::c2pool::v37n::Carrier;
using ::c2pool::v37n::CarrierWire;
using ::c2pool::v37n::CutDescriptor;
using ::c2pool::v37n::DecodeResult;
using ::c2pool::v37n::WireStatus;
using ::c2pool::v37n::cut_bid_bytes;
using ::c2pool::v37n::cut_bid_hex;
namespace wire_freeze = ::c2pool::v37n::wire_freeze;

static int g_fails = 0;
static int g_checks = 0;
static void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("KFLOOR-KAT FAIL: %s\n", what.c_str()); }
    else       std::printf("  ok: %s\n", what.c_str());
}

static std::string hexv(const std::vector<std::uint8_t>& v) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto b : v) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}
static std::string hex32(const ::v37::bytes32& d) {
    return hexv(std::vector<std::uint8_t>(d.begin(), d.end()));
}

// sha256d("V37Q"): owed_digest() of an empty FINALIZED partition.
static const char* kEmptyAnchor =
    "66078202d7c70e6dbf230d10b716d3f96fbd4d21dac4ba5eb3ac89ca854d54b3";

// The pre-hotfix geometry leaf of the bare default (v37_rb_lane_tag_kat A1):
// 'V37H' | 8640 | 4096 | 8 | 2160 | 1 | 568.
static const char* kGeoLeafDefault =
    "56333748c02100000000000000100000000000000800000000000000700800000000000001000000000000003802000000000000";
// The KFL1 block for k_floor = 10: 'KFL1' | u64 LE 10.
static const char* kKfl1Of10 = "4b464c310a00000000000000";

// PINNED GOLDENS. kLaneK0 is the lane digest of the fixed stream below under a
// k_floor-0 lane: it must equal what the same stream produced BEFORE the
// hotfix (k_floor did not exist, the header leaf had no KFL1), so it is the
// digest-neutral witness. kLaneK10 is the Family-A lane digest of the same
// stream (KFL1 committed). A change to either is a consensus-visible change to
// the lane commitment and may only move with a ruling.
static const char* kLaneK0  = "008a53bdc20fa3c82dc136f780944ae0dd617b9ed92b70123eb53cf669326358";
static const char* kLaneK10 = "f417aba43ec6289993557b7ded27cee7c0ec17619cd7df8059c4175fd8b922fe";

static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t tag) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    ::v37::PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}

static const ::v37::ChainId CH     = 7;
static const std::uint64_t  D_CONF = 3;
static const int            N_PUSH = 24;
static const char* kWonBid =
    "00000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566aa";

static ::v37::LaneParams with_k_floor(std::uint64_t k) {
    ::v37::LaneParams p;          // the ratified OQ-5 geometry, gates OFF
    p.k_floor = k;
    return p;
}

struct Node {
    std::shared_ptr<MockCoinBackend> coin;
    std::unique_ptr<XbtcNode>        node;

    Node(std::shared_ptr<MockCoinBackend> c, const ::v37::LaneParams& params)
        : coin(std::move(c)) {
        BtcNodeConfig cfg;
        cfg.lane_chain  = CH;
        cfg.lane_params = params;
        cfg.d_conf      = D_CONF;
        node = std::make_unique<XbtcNode>(cfg, std::make_unique<MemSettleStore>(), coin,
                                          p2pkh_pay_of());
        node->open();
        node->start();
    }
    ~Node() { if (node) node->stop(); }

    // One record per tracked submit: every prefix 1..n is PUBLISHED, so the
    // winner's prefix P is in the settlement ring of every node of a pair.
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
    ::v37::bytes32 owed() { return node->ledger().owed_digest(); }
};

static std::optional<CutDescriptor> round_trip(const CutDescriptor& d) {
    Carrier c = wire_freeze::fixture_a();
    c.cut = d;
    DecodeResult dr = CarrierWire::decode(CarrierWire::encode(c));
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

// A mines at a fixed height, names its fold on a REAL v0x02 frame, the peer
// receives it; then the shared chain buries it D_conf deep.
struct PairRun {
    ::v37::bytes32 lane_a{}, lane_b{}, owed_a{}, owed_b{};
    EbCut          cut_a;
    PeerWinOutcome peer;
    bool           wire_ok = false, a_final = false, b_final = false;
};

static PairRun run_pair(Node& A, Node& B, const std::shared_ptr<MockCoinBackend>& coin) {
    PairRun r;
    A.push_fixed_stream();
    B.push_fixed_stream();
    r.lane_a = A.lane();
    r.lane_b = B.lane();
    coin->append_block("g0");
    const std::uint64_t win_h = coin->append_block(kWonBid);
    const ::v37::bytes32 owed_at_win = A.owed();
    WonBlockOutcome won = A.node->on_block_won(kWonBid, win_h, /*confirmations=*/0);
    r.cut_a = won.cut;
    CutDescriptor d;
    d.bid                = *cut_bid_bytes(kWonBid);
    d.h_b                = win_h;
    d.cut_next_pos       = won.cut.next_pos;
    d.cut_spine_digest   = won.cut.lane_digest;
    d.reward             = won.cut.reward;
    d.payout_emitted     = won.emitted;
    d.owed_digest_at_win = owed_at_win;
    if (const auto got = round_trip(d)) {
        r.wire_ok = (*got == d);
        r.peer    = B.node->on_peer_block_won(peer_win_of(*got));
    }
    for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
        coin->append_block("f" + std::to_string(i));
    for (const auto& s : A.node->poll_tip()) if (s.bid == kWonBid) r.a_final = true;
    for (const auto& s : B.node->poll_tip()) if (s.bid == kWonBid) r.b_final = true;
    r.owed_a = A.owed();
    r.owed_b = B.owed();
    return r;
}

static bool same_outputs(const cb::CoinbaseAssembly& x, const cb::CoinbaseAssembly& y) {
    if (x.outputs.size() != y.outputs.size() || x.total_paid != y.total_paid ||
        x.payout_bytes != y.payout_bytes || x.carried != y.carried || !(x.state_root == y.state_root))
        return false;
    for (std::size_t i = 0; i < x.outputs.size(); ++i) {
        const auto& a = x.outputs[i];
        const auto& b = y.outputs[i];
        if (!(a.key == b.key) || a.amount != b.amount || a.script != b.script) return false;
    }
    return true;
}

int main() {
    std::printf("== v37 STEP-0 k_floor LaneParam KAT ==\n");
    const ::v37::LaneParams K0  = with_k_floor(0);
    const ::v37::LaneParams K1  = with_k_floor(1);    // the pre-hotfix btc_node literal
    const ::v37::LaneParams K10 = ::v37::LaneParams::family_a();

    // ── 1. constants ────────────────────────────────────────────────────────
    {
        check(::v37::K_FLOOR_F_REF == 10 && ::v37::K_FLOOR_NONE == 0, "1a f_ref = 10, none = 0");
        check(::v37::LaneParams{}.k_floor == 0, "1b the bare LaneParams{} carries no floor (digest-neutral)");
        check(K10.k_floor == 10, "1c LaneParams::family_a().k_floor == f_ref == 10");
        check(BtcNodeConfig{}.lane_params.k_floor == 10,
              "1d BtcNodeConfig's default lane params are Family A (k_floor 10)");
        check(cb::h_min(::v37::ScriptKind::P2WPKH, 10) == 310 &&
              cb::h_min(::v37::ScriptKind::P2PKH, 10) == 340,
              "1e h_min(P2WPKH) = 310 sat, h_min(P2PKH) = 340 sat at f_ref");
        auto coin = std::make_shared<MockCoinBackend>();
        Node n10(coin, K10), n1(coin, K1);
        check(n10.node->coinbase_budget().k_floor == 10 && n1.node->coinbase_budget().k_floor == 1,
              "1f XbtcNode::coinbase_budget() reads k_floor FROM THE LANE PARAMS (not a literal)");
        check(n10.node->coinbase_budget().slot_budget_C == 0 &&
              n10.node->coinbase_budget().max_payout_bytes == 0,
              "1g C and K_max stay the ratified UNBOUNDED defaults");
    }

    // ── 2 / 3. the lane commitment ──────────────────────────────────────────
    ::v37::bytes32 lane0{}, lane1{}, lane10{};
    {
        check(hexv(rb::geometry_leaf(K0)) == kGeoLeafDefault,
              "2a geometry_leaf(k_floor 0) == the pre-hotfix bytes (no KFL1 block)");
        check(hexv(rb::geometry_leaf(K10)) == std::string(kGeoLeafDefault) + kKfl1Of10,
              "3a geometry_leaf(k_floor 10) == pre-hotfix bytes || 'KFL1' || u64 10");
        check(rb::geometry_digest(K0) != rb::geometry_digest(K1) &&
              rb::geometry_digest(K1) != rb::geometry_digest(K10) &&
              rb::geometry_digest(K0) != rb::geometry_digest(K10),
              "3b geometry_digest separates k_floor 0 / 1 / 10");

        auto coin = std::make_shared<MockCoinBackend>();
        Node n0(coin, K0), n1(coin, K1), n10(coin, K10), n10b(coin, K10);
        n0.push_fixed_stream(); n1.push_fixed_stream();
        n10.push_fixed_stream(); n10b.push_fixed_stream();
        lane0 = n0.lane(); lane1 = n1.lane(); lane10 = n10.lane();
        std::printf("   lane k0  = %s\n   lane k1  = %s\n   lane k10 = %s\n",
                    hex32(lane0).c_str(), hex32(lane1).c_str(), hex32(lane10).c_str());
        if (std::string(kLaneK0).empty())
            std::printf("   REGEN kLaneK0  = \"%s\"\n", hex32(lane0).c_str());
        else
            check(hex32(lane0) == kLaneK0,
                  "2b ★ k_floor-0 lane digest == the PRE-HOTFIX digest of this stream (neutral)");
        if (std::string(kLaneK10).empty())
            std::printf("   REGEN kLaneK10 = \"%s\"\n", hex32(lane10).c_str());
        else
            check(hex32(lane10) == kLaneK10, "3c Family-A (k_floor 10) lane digest golden");
        check(lane0 != lane1 && lane1 != lane10 && lane0 != lane10,
              "3d ★ the SAME stream commits to a DIFFERENT lane digest per k_floor");
        check(n10b.lane() == lane10, "3e same k_floor, same stream -> the SAME lane digest");
    }

    // ── 4. ★ REFUSAL: different k_floor ─────────────────────────────────────
    {
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, K10), B(coin, K1);
        PairRun r = run_pair(A, B, coin);
        check(r.cut_a.folded && !r.cut_a.credit.empty(), "4a the winner (k_floor 10) folded a non-empty E_b");
        check(r.wire_ok, "4b the cut descriptor rode a REAL v0x02 frame byte-exactly");
        check(r.lane_a != r.lane_b, "4c the two nodes' lanes commit to DIFFERENT digests");
        check(!r.peer.registered, "4d ★ the k_floor-1 peer did NOT register the win");
        check(r.peer.cut_digest_mismatch && !r.peer.cut_miss && r.peer.repair_wanted,
              "4e ★ ...refused EXPLICITLY as cut_digest_mismatch (P published here with another digest)");
        check(!r.peer.repaired, "4f no repair can accommodate it (the replay uses OUR params)");
        check(r.a_final && !r.b_final, "4g only the winner finalized the block");
        check(hex32(r.owed_b) == kEmptyAnchor,
              "4h the refusing peer holds the empty anchor — nothing was credited under another floor");
        check(r.owed_a != r.owed_b,
              "4i the disagreement is VISIBLE (A != B), not hidden behind a plausible credit");
    }

    // ── 5. ★ CONVERGENCE: same k_floor ──────────────────────────────────────
    {
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, K10), C(coin, K10);
        PairRun r = run_pair(A, C, coin);
        check(r.lane_a == r.lane_b, "5a same k_floor -> same lane digest");
        check(r.peer.registered && !r.peer.cut_digest_mismatch && !r.peer.cut_miss,
              "5b the k_floor-10 peer REGISTERED the win at the carried cut");
        check(r.peer.cut.credit == r.cut_a.credit, "5c ...with the SAME E_b");
        check(r.a_final && r.b_final, "5d both finalized");
        check(hex32(r.owed_a) != kEmptyAnchor && r.owed_a == r.owed_b,
              "5e ★ owed_digest(A) == owed_digest(C), non-empty");

        const std::uint64_t R = 5000000000ULL;
        auto pay = p2pkh_pay_of();
        cb::CoinbaseAssembly ca = cb::assemble(A.node->ledger(), R, A.node->coinbase_budget(), pay);
        cb::CoinbaseAssembly cc = cb::assemble(C.node->ledger(), R, C.node->coinbase_budget(), pay);
        check(!ca.outputs.empty(), "5f the buried coinbase pays owed balances");
        check(same_outputs(ca, cc),
              "5g ★ same k_floor -> the IDENTICAL coinbase (outputs, amounts, scripts, state root)");

        // ── 6. the floor is load-bearing over the SAME ledger ────────────────
        const std::uint64_t first = ca.outputs.front().amount;
        const std::uint64_t R2    = first + 100;   // leaves a 100-sat final take
        cb::CoinbaseBudget b1  = A.node->coinbase_budget(); b1.k_floor = 1;
        cb::CoinbaseBudget b10 = A.node->coinbase_budget();
        cb::CoinbaseAssembly lo = cb::assemble(A.node->ledger(), R2, b1, pay);
        cb::CoinbaseAssembly hi = cb::assemble(A.node->ledger(), R2, b10, pay);
        check(lo.outputs.size() == 2 && lo.outputs.back().amount == 100,
              "6a k_floor 1 (h_min 34): the 100-sat final take is EMITTED");
        check(hi.outputs.size() == 1 && hi.total_paid == first,
              "6b k_floor 10 (h_min 340): the 100-sat final take CARRIES");
        check(!same_outputs(lo, hi),
              "6c ★ different k_floor over the SAME ledger -> DIFFERENT coinbases "
              "(the silent fork the lane commitment now refuses)");
    }

    // ── 7. roundabout lane tag ──────────────────────────────────────────────
    {
        const rb::LaneTagContext t10 = rb::LaneTagContext::of(CH, K10, 1);
        const rb::LaneTagContext t1  = rb::LaneTagContext::of(CH, K1, 1);
        check(!(t10 == t1), "7a lane-tag contexts differ by k_floor");
        rb::RoundaboutGate g = rb::RoundaboutGate::btc_candidate();
        rb::Map map = rb::genesis_map(CH);
        ::v37::bytes32 id; id.fill(0xA1);
        const rb::RbIndex my = map.assign(id, 0);
        const rb::RbCarriage c = rb::make_carriage(t10, map, id, 0);
        check(rb::check_roundabout(g, t10, map, my, id, c).ok(),
              "7b a k_floor-10 carriage is admitted by a k_floor-10 validator");
        const rb::RbCheck x = rb::check_roundabout(g, t1, map, my, id, c);
        check(x.disp == rb::RbDisposition::REJECT_ROUNDABOUT && x.reason == rb::RbReason::TAG_MISMATCH,
              "7c ★ ...and REJECT_ROUNDABOUT(TAG_MISMATCH) at a k_floor-1 validator");
    }

    std::printf("== %d checks, %d failures ==\n", g_checks, g_fails);
    std::printf(g_fails ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return g_fails ? 1 : 0;
}
