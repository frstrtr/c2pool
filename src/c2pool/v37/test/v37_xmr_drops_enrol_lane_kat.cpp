// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_enrol_lane_kat -- DROPS-ENROL-LANE (DROPS defect 4, flip 1).
//
// THE DEFECT. A late-joining or restarted winner composed fewer raindrop rows
// than the other nodes (l40: winner rows differ on 25/76 blocks): its share
// counts S were known only for intervals after IT armed (covers(iv)) and its
// EnrollmentBook took effect from ITS own tip. Both are node-local, so only
// the winner could compose the carried delta, and a winner that dies right
// after publishing stalls every node (awaiting its delta).
//
// THE FIX (operator ruling 09-26, flip-1 gated): S and the enrolment are a
// pure function of the REPLICATED lane prefix [0, P) up to the block's
// on-chain credit cut P (an enrol-set payee enrols at its first share on the
// prefix, effective from that bin + 1); verify_carry refuses a trailer whose
// enrollment_digest differs from the lane-derived digest; any node composes.
//
//   EL1  two nodes armed/enrolled 35 tips apart, the SAME replicated inputs:
//        the composed rows + book digest + delta are identical (base: the
//        late node withholds the intervals below its arm -> fewer rows).
//   EL2  a carried trailer whose enrollment_digest was forged (a payee claimed
//        enrolled earlier than the lane shows) is REFUSED; the honest one is
//        accepted (base: verify_carry accepts the forged digest).
//   EL3  a node that never enrolled or armed locally (the dead-winner case: no
//        frame will ever come) composes the winner's exact delta + digest from
//        the lane prefix (base: its local composition credits nothing).
//   EL4  the lane book is order-free, ex ante (effective from first bin + 1),
//        restricted to the enrol set, and a function of P.
//   EL5  the HELLO digest: unchanged for an empty set (flip 0 / nobody), and
//        distinct per enrol set, order-free.
//   EL6  the own-order prefix: a gap in our lane log or an unresolvable bin
//        HOLDs (nullopt); a reloaded receipt's bin resolves from its prev_id.
//   EL7  source pins: the shell composes every lane block from the lane prefix
//        before the carried-delta check, never waits on the winner, and the
//        enrol set rides HELLO only when DROPS is live.
//
// RED on the base (#1801, v37/xmr-drops-restart-2): the checks run the base's
// behaviour and fail; GREEN on the fix.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;

struct HNode {   // the XmrNode seam shape
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook*) {}
    void set_pre_harvest(std::function<void(std::uint64_t)>) {}
    void set_drops_price_fn(std::function<st::WorkPrice()>) {}
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
};
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares);
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return dx::rescale_price(wp, 1);
}
static std::string slurp(const std::string& p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}

// the canonical chain: lane blocks at these heights
static const std::set<std::uint64_t> kLanes = {130, 170};
static bytes32 pid_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xEE; std::memcpy(b.data() + 8, &bin, 8); return b; }

// One replicated input stream: receipts (payee, bin) in lane order + raindrops.
struct Stream {
    struct R { bytes32 payee; std::uint64_t bin; };
    std::vector<R> receipts;                                   // lane order, position = index
    std::vector<std::pair<R, bytes32>> drops;                  // (payee, bin) -> pow_le
};
static Stream make_stream(const bytes32& P, const bytes32& Q, const bytes32& R, std::uint32_t K) {
    Stream s;
    std::mt19937_64 rng(0xE1A7E5ULL);
    for (std::uint64_t bin = 101; bin <= 165; ++bin) {
        s.receipts.push_back({P, bin}); s.receipts.push_back({Q, bin});
        if (bin >= 131) s.receipts.push_back({R, bin});        // R: the late joiner's miner
        for (const auto& who : {P, Q, R}) {
            if (who == R && bin < 131) continue;
            for (std::uint32_t k = 0; k < K + 1; ++k) {
                bytes32 pow{};
                for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(pow.data() + w * 8, &v, 8); }
                pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));   // H >= 2^246: N >= 2^224 (a raindrop, not a share)
                s.drops.push_back({{who, bin}, pow});
            }
        }
    }
    return s;
}

struct NodeH {
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode node;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    NodeH(std::uint64_t enrol_tip, const std::vector<bytes32>& enrol, bool enrol_locally) {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        w->attach(node);
        w->attach_chain_order(node, kD);
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = kLanes.lower_bound(h);
            if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
        w->observe_native_tip(enrol_tip);
        if (enrol_locally) { for (const auto& p : enrol) w->enroll_at_tip(p); w->arm_at_tip(); }
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        w->set_enrol_set(std::set<bytes32>(enrol.begin(), enrol.end()));
#endif
    }
    void feed(const Stream& s) {
        std::uint64_t pos = 0;
        for (const auto& r : s.receipts) {
            w->on_share_pushed(r.payee, r.bin);
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
            w->on_share_lane(r.payee, r.bin, pos, 1, pid_of(r.bin));
#endif
            ++pos;
        }
        for (const auto& [r, pow] : s.drops) (void)w->on_raindrop(r.payee, r.bin, pow);
    }
    // THE composition of the lane block won at h with cut P: rows, digest, delta
    struct Out { std::size_t rows = 0; std::string cells; bytes32 digest{}; std::map<bytes32, long long> delta; };
    Out compose(std::uint64_t h, std::uint64_t P) {
        Out o;
        const auto rg = w->range_for(h);
        if (!rg) return o;
        st::DropsCompose dctx; dctx.price = price_of(600000000000ULL, 1000);
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        const auto lp = w->own_prefix(P, [](const bytes32&) { return std::optional<std::uint64_t>{}; }, nullptr);
        if (!lp) return o;
        const auto lc = w->compose_lane(rg->first, rg->second, *lp);
        dctx.enrollment = &lc.book;
        const auto carry = dx::compose_carry(params, lc.rows, dctx);
        for (const auto& r : lc.rows) o.cells += hex(r.payee).substr(0, 6) + "@" + std::to_string(r.interval) + ",";
        o.rows = lc.rows.size(); o.digest = carry.enrollment_digest; o.delta = carry.delta;
#else
        (void)P;   // the base: the node's local share book + its own enrolment book
        const auto rows = node.range(h);
        dctx.enrollment = &w->core().enrollment();
        const auto carry = dx::compose_carry(params, rows, dctx);
        for (const auto& r : rows) o.cells += hex(r.payee).substr(0, 6) + "@" + std::to_string(r.interval) + ",";
        o.rows = rows.size(); o.digest = carry.enrollment_digest; o.delta = carry.delta;
#endif
        return o;
    }
};

int main() {
    Checker C;
    const bytes32 P = b32_of(0x31), Q = b32_of(0x32), R = b32_of(0x33), X = b32_of(0x34);
    const std::vector<bytes32> enrol = {P, Q, R};
    const ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    const Stream s = make_stream(P, Q, R, params.subthreshold.K);
    const std::uint64_t Pcut = s.receipts.size() - 30;   // the on-chain cut: a strict prefix of the lane
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
    std::printf("fix tree (C2POOL_XMR_DROPS_LANE_ENROL)\n");
#else
    std::printf("BASE tree (no C2POOL_XMR_DROPS_LANE_ENROL): the checks run the base's node-local composition\n");
#endif

    std::printf("EL1: late join / restart -- the same replicated inputs, enrolled + armed 35 tips apart\n");
    NodeH early(100, enrol, true), late(135, enrol, true);
    early.feed(s); late.feed(s);
    const auto oe = early.compose(170, Pcut), ol = late.compose(170, Pcut);
    std::printf("  range [120,160): early rows=%zu late rows=%zu delta payees %zu/%zu\n", oe.rows, ol.rows, oe.delta.size(), ol.delta.size());
    C(oe.rows > 0 && !oe.delta.empty(), "EL1 the composition is non-trivial (rows + a non-zero delta)");
    C(oe.rows == ol.rows && oe.cells == ol.cells, "EL1 ★ the late node composes the SAME rows as the early node (no interval withheld)");
    C(oe.digest == ol.digest, "EL1 ★ ... under the SAME enrolment book digest");
    C(oe.delta == ol.delta, "EL1 ★ ... and books the SAME delta (owed_digest cannot fork on it)");

    std::printf("EL2: a carried trailer with a FORGED enrollment_digest\n");
    {
        dx::DropsCarry honest; honest.delta = oe.delta; honest.enrollment_digest = oe.digest;
        ::c2pool::v37n::EnrollmentBook fb;   // the forger claims R enrolled from 101 (the lane shows its first share at 131)
        (void)fb.commit(P, 100, 102); (void)fb.commit(Q, 100, 102); (void)fb.commit(R, 100, 101);
        dx::DropsCarry forged = honest; forged.enrollment_digest = fb.book_digest();
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        const std::string rh = dx::verify_carry(honest, true, oe.digest);
        const std::string rf = dx::verify_carry(forged, true, oe.digest);
#else
        const std::string rh = dx::verify_carry(honest, true);
        const std::string rf = dx::verify_carry(forged, true);
#endif
        std::printf("  honest: \"%s\" forged: \"%s\"\n", rh.c_str(), rf.c_str());
        C(forged.enrollment_digest != oe.digest, "EL2 the forged digest differs from the lane-derived one");
        C(rh.empty(), "EL2 the honest trailer (digest == the lane derivation) is accepted");
        C(!rf.empty(), "EL2 ★ the forged trailer (enrollment_digest != the lane derivation) is REFUSED");
    }

    std::printf("EL3: the winner dies after publishing -- a node that never enrolled or armed composes its delta\n");
    {
        NodeH bystander(160, enrol, /*enrol_locally=*/false);
        bystander.feed(s);
        const auto ob = bystander.compose(170, Pcut);
        std::printf("  winner rows=%zu digest=%s… | bystander rows=%zu digest=%s…\n", oe.rows, hex(oe.digest).substr(0, 12).c_str(),
                    ob.rows, hex(ob.digest).substr(0, 12).c_str());
        C(ob.rows == oe.rows && ob.cells == oe.cells, "EL3 ★ any node composes the winner's rows from the lane prefix");
        C(ob.digest == oe.digest && ob.delta == oe.delta, "EL3 ★ ... the winner's exact delta + digest (no frame needed: no stall)");
    }

    std::printf("EL4: the lane enrolment book is a pure, ex-ante function of (enrol set, [0,P))\n");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
    {
        dx::LanePrefix lp; lp.P = Pcut;
        for (std::uint64_t i = 0; i < Pcut; ++i) lp.shares.push_back({s.receipts[i].payee, s.receipts[i].bin});
        lp.shares.push_back({X, 105});   // a payee outside the enrol set
        const std::set<bytes32> es(enrol.begin(), enrol.end());
        const auto b1 = dx::lane_enrollment(lp, es);
        auto shuf = lp; std::mt19937_64 g(7); std::shuffle(shuf.shares.begin(), shuf.shares.end(), g);
        C(dx::lane_enrollment(shuf, es).book_digest() == b1.book_digest(), "EL4 order-free: a repaired (reordered) prefix derives the same book");
        C(b1.find(R) && b1.find(R)->effective_from == 132 && !b1.enrolled(R, 131) && b1.enrolled(R, 132),
          "EL4 ex ante: R's enrolment record is its first share (bin 131), effective from 132");
        C(b1.find(P) && b1.find(P)->effective_from == 102, "EL4 P enrols at its first share (101) -> from 102");
        C(!b1.find(X) && !b1.enrolled(X, 150), "EL4 a payee outside the enrol set is never enrolled");
        dx::LanePrefix early_p; early_p.P = 40;
        for (std::uint64_t i = 0; i < 40; ++i) early_p.shares.push_back({s.receipts[i].payee, s.receipts[i].bin});
        C(!dx::lane_enrollment(early_p, es).find(R), "EL4 a function of P: before R's first share is on the prefix, R is not enrolled");
        C(dx::lane_enrollment(lp, {}).book_digest() == ::c2pool::v37n::empty_enrollment_digest(), "EL4 an empty enrol set = the empty book");
    }
#else
    C(false, "EL4 the base has no lane-derived enrolment (the book is decided at each node's own tip)");
#endif

    std::printf("EL5: the enrol set rides HELLO (flip 1, non-empty set only)\n");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
    {
        const bytes32 d = b32_of(0x51);
        C(dx::hello_digest_with_enrol(d, {}) == d, "EL5 an empty set leaves the HELLO digest unchanged (flip 0 / nobody enrolled)");
        const auto a = dx::hello_digest_with_enrol(d, {P, Q}), b = dx::hello_digest_with_enrol(d, {Q, P}), c = dx::hello_digest_with_enrol(d, {P});
        C(a == b && a != c && a != d, "EL5 order-free, and a different set = a different HELLO digest (refused at HELLO)");
    }
#else
    C(false, "EL5 the base does not bind the enrol set into HELLO");
#endif

    std::printf("EL6: the own-order prefix HOLDs on a gap or an unresolvable bin\n");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
    {
        auto w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        w->on_share_lane(P, 101, 0, 1, pid_of(101));
        w->on_share_lane(Q, 0, 1, 2, pid_of(102));   // a reloaded receipt (bin unknown), 2 lane positions
        w->on_share_lane(P, 102, 3, 1, pid_of(102));
        std::string why;
        auto none = [](const bytes32&) { return std::optional<std::uint64_t>{}; };
        auto some = [](const bytes32& pid) { std::uint64_t b = 0; std::memcpy(&b, pid.data() + 8, 8); return std::optional<std::uint64_t>{b}; };
        C(!w->own_prefix(4, none, &why) && why.find("not resolvable") != std::string::npos, "EL6 an unresolvable bin HOLDs");
        const auto lp = w->own_prefix(4, some, &why);
        C(lp && lp->shares.size() == 3 && lp->shares[1].bin == 102, "EL6 a reloaded receipt's bin resolves from its prev_id");
        C(!w->own_prefix(5, some, &why), "EL6 P beyond our contiguous lane log HOLDs");
        w->on_share_lane(P, 110, 9, 1, pid_of(110));   // a gap [4,9)
        C(w->lane_gaps() == 1 && !w->own_prefix(10, some, &why) && w->own_prefix(4, some, &why),
          "EL6 a gap in our log: prefixes past it HOLD (the relay repair order is used), below it stay derivable");
    }
#else
    C(false, "EL6 the base keeps no lane-position share log");
#endif

    std::printf("EL7: source pins (main_v37_xmr.cpp)\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "EL7 shell source readable");
        const auto bk = sh.find("fo.book_from_chain_ex = [&]");
        const auto cl = sh.find("if (!drops_compose_lane(h, bid, bk, booking_price, why, drops_lane)) return false;");
        const auto tk = sh.find("if (!drops_take_carry(h, bid, bk, why, true, drops_lane)) return false;");
        C(bk != std::string::npos && cl != std::string::npos && tk != std::string::npos && bk < cl && cl < tk,
          "EL7 ★ every lane block is composed from the lane prefix BEFORE the carried-delta check");
        C(sh.find("awaiting the winner's carried DROPS delta") == std::string::npos,
          "EL7 ★ no booking waits on the winner's frame (the dead-winner stall is gone)");
        C(sh.find("verify_carry(*wit->second.drops, binds, lane.carry.enrollment_digest)") != std::string::npos &&
          sh.find("drops->set_carried(lane.carry.delta)") != std::string::npos,
          "EL7 the carried trailer is checked against the lane digest; the lane composition is what is booked");
        const auto hl = sh.find("if (drops_live)   // ★ DROPS-ENROL-LANE (flip 1): the enrol set is pool consensus");
        C(hl != std::string::npos, "EL7 the enrol set is mixed into HELLO only when DROPS is live (flip 0: master's HELLO)");
        C(sh.find("drops->on_share_lane(") != std::string::npos, "EL7 the relay ingest feeds the lane-position share log");
    }
    return C.done("v37_xmr_drops_enrol_lane_kat");
}
