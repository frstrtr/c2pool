// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_drops_enrol_repl_kat — ENROL-REPL: the XMR DROPS enrolment book is
// node-local, so the booked DROPS delta must be the WINNER's, carried.
//
// THE DEFECT. Under the flip every XMR node composed the sub-threshold credit
// of every lane block from its OWN EnrollmentBook. Enrolment is decided at the
// node's own native tip, so two nodes that enrol the same payees at different
// tips (a late join, a restart, a partition) credit different intervals, book
// different deltas for the SAME block, and their owed_digests fork.
//
// THE FIX (the BTC/DASH DROPS-R3 rule): the winner composes ONCE and carries
// the delta plus its enrolment-book digest on FB_BLOCK_WON v0x02; every node,
// the winner included, books the CARRIED map after the same deterministic
// check, and only advances its own harvest at the same frontier.
//
//   E-DIVERGE  two nodes, the SAME replicated raindrop/share stream, the same
//              payees enrolled 16 tips apart; 50 lane blocks, alternating
//              winners, each booked by both through XmrFinalizeDriver. Base:
//              each composes from its own book -> owed_digest forks. Fix: the
//              winner's carried delta -> equal owed_digest at every block.
//   E-WIRE     FB_BLOCK_WON v0x02: round trip, exact sizes (161 + 40 n), the
//              v0x01 frame unchanged (127 B), a flip-0 decoder refuses v0x02;
//              malformed trailers (zero row, unsorted, duplicate, truncated,
//              over the row bound) are refused.
//   E-VERIFY   a carried delta whose frame does not bind to the on-chain
//              commitment, or a non-empty delta under an EMPTY book, is
//              refused and books EMPTY on both nodes: still no fork.
//   E-SHELL    main_v37_xmr.cpp books the carried delta (set_carried), keeps
//              the received trailer, composes the own win once at booking,
//              waits (relay-repair HOLD) instead of composing locally; the
//              node books has_carried_drops; the relay re-offers the frames
//              only under DROPS.
// ===========================================================================
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/xmr/xmr_finalize_driver.hpp>
#include <c2pool/v37/xmr/xmr_settle_store.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif
#ifndef V37_XMR_SRC_DIR
#define V37_XMR_SRC_DIR ""
#endif

namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;
namespace xr = ::c2pool::v37n::xmr;
namespace rl = ::c2pool::v37n::xmr::relay;
using ::v37::bytes32;
using Amounts = std::map<bytes32, long long>;

static int g_fail = 0, g_pass = 0;
static void check(bool ok, const char* what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what); }
    else    { ++g_fail; std::printf("  FAIL %s\n", what); }
}
static bool meets_diff(const bytes32& h, std::uint64_t d) {
    unsigned __int128 carry = 0;
    for (int w = 0; w < 4; ++w) {
        std::uint64_t word = 0;
        for (int i = 0; i < 8; ++i) word |= static_cast<std::uint64_t>(h[static_cast<std::size_t>(w * 8 + i)]) << (8 * i);
        const unsigned __int128 p = static_cast<unsigned __int128>(word) * d + carry;
        carry = p >> 64;
    }
    return carry == 0;
}
static bytes32 key(int i) { bytes32 k{}; k[0] = 0xB0; k[31] = static_cast<std::uint8_t>(i); return k; }
static bytes32 blk(std::uint64_t h) { bytes32 k{}; k[0] = 0xB1; std::memcpy(k.data() + 8, &h, 8); return k; }
static bytes32 rand_hash(std::mt19937_64& rng) {
    bytes32 h{};
    for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(h.data() + w * 8, &v, 8); }
    return h;
}
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = n_shares;
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return dx::rescale_price(wp, 1);
}
static std::string slurp(const std::string& path) {
    std::ifstream in(path);
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}
static std::string hex8(const bytes32& b) {
    char o[17];
    for (int i = 0; i < 8; ++i) std::snprintf(o + 2 * i, 3, "%02x", b[static_cast<std::size_t>(i)]);
    return o;
}

// One node: its DROPS bundle (own tip clock, own enrolment book) + its own
// settlement ledger driven through the production finalize driver.
struct Node {
    std::unique_ptr<dx::XmrDropsWiring> w;
    ::c2pool::v37n::settle::OwedLedger ledger{7};
    ::c2pool::v37n::settle::SettleHW hw{};
    xr::MemSettleStore store;
    xr::XmrFinalizeDriver drv{ledger, hw, store, 7, /*d_conf=*/1, 0, 0, nullptr};
    std::uint64_t enrol_at = 0;
    bool enrolled = false;
    // XmrNode::buried_harvest, verbatim in shape: declare S, then release.
    std::vector<st::HarvestedReceipt> take(std::uint64_t won_height, std::uint64_t d_conf) {
        const std::uint64_t frontier = won_height > d_conf ? won_height - d_conf : 0;
        w->core().declare_at_frontier(frontier);
        return w->core().harvester().take_buried(frontier);
    }
    st::DropsCompose ctx(const st::WorkPrice& p) const {
        st::DropsCompose c; c.price = p; c.enrollment = &w->core().enrollment(); return c;
    }
    void book(const std::string& bid, std::uint64_t h, const Amounts& base, const std::vector<st::HarvestedReceipt>* local_rows,
              const st::DropsCompose* local_ctx, const Amounts* carried) {
        xr::FoundBlock fb;
        fb.bid = bid; fb.height = h; fb.credit = base;
        fb.params = ::v37::LaneParams::for_version(1);
        if (carried) { fb.has_carried_drops = true; fb.carried_drops = *carried; }
        else { fb.harvested = *local_rows; fb.drops = *local_ctx; }
        drv.on_block_found(fb);
        drv.advance_to_tip(h + 1, blk(h + 1));
    }
};

int main() {
    const auto params = ::v37::LaneParams::for_version(1);
    const std::uint64_t sd = 1024, reward = 600000000000ULL, n_sum = 1000, D = 10, T0 = 5000;
#if defined(C2POOL_XMR_DROPS_CARRY)
    const bool fix = true;
#else
    const bool fix = false;
#endif
    std::printf("v37_xmr_drops_enrol_repl_kat (%s tree)\n", fix ? "ENROL-REPL" : "BASE: no carriage");

    // ── E-DIVERGE ──────────────────────────────────────────────────────
    std::printf("E-DIVERGE: same replicated harvest, enrolment 16 tips apart, 50 lane blocks booked by both nodes\n");
    long long mism = 0, first_mism = -1, carried_nonzero = 0, local_would_differ = 0, delta_rows = 0;
    std::uint64_t booked_carried = 0, booked_local = 0;
    std::string dA, dB;
    {
        Node A, B;
        A.w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, sd, 1); A.enrol_at = T0;
        B.w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, sd, 1); B.enrol_at = T0 + 16;  // the late enrolment
        const bytes32 P1 = key(1), P2 = key(2), P3 = key(3) /* never enrolled */;
        std::mt19937_64 rng(0xE7201ULL);
        const std::uint64_t floor = dx::drops_floor_diff(sd);
        const Amounts base{{P1, 4000000000LL}, {P2, 3000000000LL}, {P3, 2000000000LL}};
        int blocks = 0;
        for (std::uint64_t iv = T0 + 1; blocks < 50; ++iv) {
            for (Node* n : {&A, &B}) {
                n->w->observe_native_tip(iv - 1);
                if (!n->enrolled && iv - 1 >= n->enrol_at) {
                    n->w->enroll_at_tip(P1); n->w->enroll_at_tip(P2); n->w->arm_at_tip(); n->enrolled = true;
                }
            }
            for (const bytes32& who : {P1, P2, P3})
                for (int k = 0; k < 700; ++k) {
                    const bytes32 h = rand_hash(rng);
                    for (Node* n : {&A, &B}) {                 // the relay replicates every event to both
                        if (meets_diff(h, sd)) n->w->on_share_pushed(who, iv);
                        else if (meets_diff(h, floor)) n->w->on_raindrop(who, iv, h);
                    }
                }
            if (iv < T0 + 12) continue;                        // let the first intervals bury
            const std::uint64_t hb = iv + D;                   // a lane block settling every interval below iv
            const std::string bid = "blk" + std::to_string(hb);
            const st::WorkPrice wp = price_of(reward, n_sum);
            Node& win = (blocks % 2 == 0) ? A : B;
            Node& peer = (blocks % 2 == 0) ? B : A;
            const auto rw = win.take(hb, D), rp = peer.take(hb, D);
            const auto cw = win.ctx(wp), cp = peer.ctx(wp);
#if defined(C2POOL_XMR_DROPS_CARRY)
            // the winner composes ONCE and carries it on the wire; both decode + verify + book it
            const dx::DropsCarry carry = dx::compose_carry(params, rw, cw);
            rl::BlockWon bw; bw.chain_id = 7; bw.bid = blk(hb); bw.h_b = hb; bw.reward = reward;
            bw.drops = rl::BlockWon::Drops{carry.delta, carry.enrollment_digest};
            const auto frame = rl::encode_block_won(bw);
            rl::BlockWon got; std::string why;
            const bool dec = rl::decode_block_won(frame, got, &why, /*accept_drops=*/true);
            const dx::DropsCarry rx = dec && got.drops ? dx::DropsCarry{got.drops->delta, got.drops->enrollment_digest} : dx::DropsCarry{};
            const bool ok = dec && got.drops && dx::verify_carry(rx, got == bw).empty();
            const Amounts booked = ok ? rx.delta : Amounts{};
            if (st::subthreshold_credit(params, rp, cp) != booked) ++local_would_differ;   // what the peer's OWN book says
            if (!booked.empty()) ++carried_nonzero;
            delta_rows += static_cast<long long>(booked.size());
            win.book(bid, hb, base, nullptr, nullptr, &booked);
            peer.book(bid, hb, base, nullptr, nullptr, &booked);
            booked_carried += 2;
#else
            // base: every node composes from its OWN book (the only path the base tree has)
            if (!st::subthreshold_credit(params, rw, cw).empty()) ++carried_nonzero;
            win.book(bid, hb, base, &rw, &cw, nullptr);
            peer.book(bid, hb, base, &rp, &cp, nullptr);
            booked_local += 2;
#endif
            ++blocks;
            if (A.ledger.owed_digest() != B.ledger.owed_digest()) { ++mism; if (first_mism < 0) first_mism = blocks; }
        }
        dA = hex8(A.ledger.owed_digest()); dB = hex8(B.ledger.owed_digest());
        std::printf("       blocks=50 booked carried=%llu local=%llu | blocks with a non-empty delta=%lld (rows %lld) | "
                    "peer's own-book composition would differ on %lld blocks\n",
                    (unsigned long long)booked_carried, (unsigned long long)booked_local, carried_nonzero, delta_rows, local_would_differ);
        std::printf("       owed_digest mismatches=%lld (first at block %lld) | final A=%s B=%s\n", mism, first_mism, dA.c_str(), dB.c_str());
        check(carried_nonzero > 0, "the scenario is live: DROPS deltas are non-empty (not a trivially dormant compare)");
        check(mism == 0, "★ two nodes with DIFFERENT enrolment books book the same wins -> EQUAL owed_digest at every block");
        check(fix && local_would_differ > 0, "the enrolment books really diverge: the peer's own-book composition differs from the carried one");
    }

    // ── E-WIRE ────────────────────────────────────────────────────────────
    std::printf("E-WIRE: FB_BLOCK_WON v0x02 (flip-only DROPS carriage)\n");
#if defined(C2POOL_XMR_DROPS_CARRY)
    {
        rl::BlockWon b; b.chain_id = 7; b.bid = blk(1); b.h_b = 11; b.cut_next_pos = 5; b.reward = 99; b.payout_emitted = true;
        const auto v1 = rl::encode_block_won(b);
        check(v1.size() == 127 && v1[1] == 0x01, "no carriage -> the v0x01 frame, 127 bytes, unchanged");
        rl::BlockWon d1; check(rl::decode_block_won(v1, d1, nullptr, false) && d1 == b, "v0x01 round-trips on a flip-0 decoder");
        b.drops = rl::BlockWon::Drops{{{key(1), 5}, {key(2), -7}, {key(9), 1LL << 40}}, key(0x33)};
        const auto v2 = rl::encode_block_won(b);
        std::printf("       sizes: v0x01=%zu v0x02(3 rows)=%zu v0x02(0 rows)=%zu\n", v1.size(), v2.size(),
                    [&] { auto e = b; e.drops->delta.clear(); return rl::encode_block_won(e).size(); }());
        check(v2.size() == 161 + 40 * 3 && v2[1] == 0x02, "v0x02 = 127 + u16 n + 40 n + digest 32");
        rl::BlockWon d2; std::string why;
        check(rl::decode_block_won(v2, d2, &why, true) && d2 == b, "v0x02 round-trips (delta rows + enrolment digest)");
        check(!rl::decode_block_won(v2, d2, &why, false), "★ a flip-0 decoder REFUSES v0x02 (master's accept set)");
        check(rl::kBlockWonDropsLive == ::c2pool::v37n::kActivateConsensusV1, "the live decoder accepts v0x02 only under the flip");
        auto tamper = [&](auto f) { auto x = v2; f(x); rl::BlockWon o; return !rl::decode_block_won(x, o, nullptr, true); };
        check(tamper([](std::vector<std::uint8_t>& x) { std::memset(x.data() + 129 + 32, 0, 8); }), "malformed: a zero delta row is refused");
        check(tamper([](std::vector<std::uint8_t>& x) { std::swap_ranges(x.begin() + 129, x.begin() + 169, x.begin() + 169); }),
              "malformed: rows out of order are refused");
        check(tamper([](std::vector<std::uint8_t>& x) { std::copy(x.begin() + 129, x.begin() + 169, x.begin() + 169); }),
              "malformed: a duplicate payee is refused");
        check(tamper([](std::vector<std::uint8_t>& x) { x.pop_back(); }), "malformed: a truncated trailer is refused");
        check(tamper([](std::vector<std::uint8_t>& x) { x[127] = 0x01; x[128] = 0x01; }), "malformed: a row count over the bound is refused");
        auto big = b; big.drops->delta.clear();
        for (int i = 0; i < 257; ++i) { bytes32 k{}; k[0] = static_cast<std::uint8_t>(i >> 8); k[1] = static_cast<std::uint8_t>(i); big.drops->delta[k] = 1; }
        check(rl::encode_block_won(big).empty(), "the encoder refuses more than kBlockWonDropsMaxRows rows");
    }
#else
    check(false, "FB_BLOCK_WON carries no DROPS delta on the base tree");
#endif

    // ── E-VERIFY ─────────────────────────────────────────────────────────
    std::printf("E-VERIFY: a mismatched or inconsistent carried delta is refused and books EMPTY on every node\n");
#if defined(C2POOL_XMR_DROPS_CARRY)
    {
        const dx::DropsCarry good{{{key(1), 1234}}, key(0x44)};
        check(dx::verify_carry(good, true).empty(), "a bound, canonical delta under a non-empty book is booked");
        check(!dx::verify_carry(good, false).empty(), "★ refused: the frame does not bind to the on-chain commitment");
        check(!dx::verify_carry(dx::DropsCarry{{{key(1), 1234}}, ::c2pool::v37n::empty_enrollment_digest()}, true).empty(),
              "refused: a non-empty delta composed under an EMPTY enrolment book");
        check(!dx::verify_carry(dx::DropsCarry{{{key(1), 0}}, key(0x44)}, true).empty(), "refused: a zero row");
        check(dx::verify_carry(dx::DropsCarry{{}, ::c2pool::v37n::empty_enrollment_digest()}, true).empty(),
              "an empty delta (a dormant winner) is booked");
        Node A, B;
        A.w = dx::XmrDropsWiring::make_for_test(4, sd, 1); B.w = dx::XmrDropsWiring::make_for_test(4, sd, 1);
        const Amounts base{{key(1), 777}};
        const Amounts booked = dx::verify_carry(good, /*binds=*/false).empty() ? good.delta : Amounts{};
        A.book("x", 100, base, nullptr, nullptr, &booked);
        B.book("x", 100, base, nullptr, nullptr, &booked);
        check(A.ledger.owed_digest() == B.ledger.owed_digest() && booked.empty(), "a refused delta books EMPTY on both nodes: no fork");
    }
#else
    check(false, "no carried-delta check on the base tree");
#endif

    // ── E-SHELL ──────────────────────────────────────────────────────────
    std::printf("E-SHELL: the live shell, node and relay use the carriage (source pins)\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        const std::string nd = slurp(std::string(V37_XMR_SRC_DIR) + "/xmr_node.hpp");
        const std::string rn = slurp(std::string(V37_XMR_SRC_DIR) + "/relay/xmr_relay_node.hpp");
        check(!sh.empty() && !nd.empty() && !rn.empty(), "sources readable");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        // DROPS-ENROL-LANE (defect 4) superseded the wait on the winner: every node
        // composes the lane block from the lane prefix; the carried delta is its witness.
        check(sh.find("drops->set_carried(lane.carry.delta)") != std::string::npos,
              "★ the booking callback books the LANE composition (every node derives the same; never a node-local book)");
        check(sh.find("verify_carry(*wit->second.drops, binds, lane.carry.enrollment_digest)") != std::string::npos,
              "... the carried trailer is checked against the lane-derived digest");
        check(sh.find("awaiting the winner's carried DROPS delta") == std::string::npos &&
              sh.find("cut-pending: relay repair of P=") != std::string::npos,
              "no wait on the winner's delta; an underivable lane prefix is HELD as a relay repair (never a timeout refusal)");
        check(sh.find("compose_carry(cfg.lane_params, out.lc.rows, dctx)") != std::string::npos &&
              sh.find("bw.drops = relay::BlockWon::Drops{carry.delta, carry.enrollment_digest}") != std::string::npos,
              "the own win carries its lane composition (FB_BLOCK_WON v0x02)");
#else
        check(sh.find("drops->set_carried(wit->second.drops->delta)") != std::string::npos,
              "★ the booking callback books the WINNER's carried delta (never this node's own book)");
        check(sh.find("verify_carry(*wit->second.drops, binds)") != std::string::npos, "... after the deterministic check");
        check(sh.find("awaiting the winner's carried DROPS delta") != std::string::npos &&
              sh.find("cut-pending: relay repair of P=") != std::string::npos,
              "no carried delta yet -> HELD as a relay repair (never a local composition, never a timeout refusal)");
        check(sh.find("compose_carry(cfg.lane_params, rows, dctx)") != std::string::npos &&
              sh.find("bw.drops = relay::BlockWon::Drops{carry.delta, carry.enrollment_digest}") != std::string::npos,
              "the own win composes ONCE at booking and carries it (FB_BLOCK_WON v0x02)");
#endif
        check(sh.find("wc.drops = c2pool::v37n::xmr::drops::DropsCarry{bw.drops->delta") != std::string::npos,
              "a received v0x02 trailer is kept for the booking");
        check(nd.find("fb.has_carried_drops = true;") != std::string::npos && nd.find("m_drops_carried()") != std::string::npos,
              "XmrNode books has_carried_drops (compose_credit_from_delta) when a carried delta is handed over");
        check(rn.find("if (m_o.drops_floor_diff == 0) return;") != std::string::npos && rn.find("reoffer_won_to(p);") != std::string::npos,
              "the relay re-offers recent FB_BLOCK_WON frames on HELLO, only under DROPS");
    }

    std::printf("v37_xmr_drops_enrol_repl_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "RED" : "GREEN");
    return g_fail ? 1 : 0;
}
