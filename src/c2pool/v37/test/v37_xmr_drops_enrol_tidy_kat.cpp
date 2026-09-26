// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_enrol_tidy_kat -- DROPS-ENROL-TIDY (follow-ups of
// DROPS-ENROL-LANE, flip 1 only; nothing here exists at flip 0).
//
//   ET1  THE LANE-LOG BOUND. The per-node lane-position log is folded below
//        Q = lane_prune_point(oldest open cut, lane_next, H): after the fold the
//        composition at the oldest still-reachable cut (base_P) and at the
//        on-chain cut is byte-identical to an unpruned twin's (rows, book
//        digest, delta, inputs, receipt count), verify_carry accepts the
//        pre-fold carriage against the post-fold digest, a repaired
//        (winner-side) prefix composes the same, an entry below the bound is
//        GONE, a cut below the folded base answers nullopt (relay repair, never
//        a different composition), an unresolvable reloaded bin is never
//        folded, a rewrite below the base makes the own prefix refuse, and over
//        a 6000-receipt lane the log never exceeds the stated bound
//        (base: nothing is ever pruned -- RED).
//   ET2  THE TIP BOOK IS RETIRED. The lane-only wiring advances the harvest
//        range bookkeeping without reading the node-local share book or a tip
//        enrolment book (rows {}, nothing withheld), and the shell no longer
//        enrols at the tip, arms a share book or tees shares into it, and hands
//        the node no enrolment book (source pins).
//   ET3  ENROL-SET MISMATCH AT HELLO. Two nodes of one pool with different
//        --drops-enrol lists are refused with an explicit reason naming both
//        enrol-set digests (base: the generic lane_params_digest refusal); the
//        flip-1 HELLO trailer round-trips; a HELLO without it (flip 0) keeps
//        its 174-byte frame.
//
// RED on the base (#1805, v37/xmr-drops-enrol-lane), GREEN on the fix.
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
namespace rl = ::c2pool::v37n::xmr::relay;

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;

struct HNode {   // the XmrNode seam shape
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    const ::c2pool::v37n::EnrollmentBook* book = nullptr;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook* b) { book = b; }
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
static const std::set<std::uint64_t> kLanes = {130, 170};
static bytes32 pid_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xEE; std::memcpy(b.data() + 8, &bin, 8); return b; }
static std::optional<std::uint64_t> bin_of_pid(const bytes32& pid) { std::uint64_t b = 0; std::memcpy(&b, pid.data() + 8, 8); return b; }

struct Stream {
    struct R { bytes32 payee; std::uint64_t bin; };
    std::vector<R> receipts;
    std::vector<std::pair<R, bytes32>> drops;
};
static Stream make_stream(const bytes32& P, const bytes32& Q, const bytes32& R, std::uint32_t K) {
    Stream s;
    std::mt19937_64 rng(0x7D1D7ULL);
    for (std::uint64_t bin = 101; bin <= 165; ++bin) {
        s.receipts.push_back({P, bin}); s.receipts.push_back({Q, bin});
        if (bin >= 131) s.receipts.push_back({R, bin});
        for (const auto& who : {P, Q, R}) {
            if (who == R && bin < 131) continue;
            for (std::uint32_t k = 0; k < K + 1; ++k) {
                bytes32 pow{};
                for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(pow.data() + w * 8, &v, 8); }
                pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));
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
    explicit NodeH(const std::vector<bytes32>& enrol) {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        w->attach(node);
        w->attach_chain_order(node, kD);
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = kLanes.lower_bound(h);
            if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
        w->set_enrol_set(std::set<bytes32>(enrol.begin(), enrol.end()));
    }
    void feed(const Stream& s, bool reload_bin0_at = false, std::uint64_t at = 0) {
        std::uint64_t pos = 0;
        for (const auto& r : s.receipts) {
            const bool zero = reload_bin0_at && pos == at;
            w->on_share_lane(r.payee, zero ? 0 : r.bin, pos, 1, pid_of(r.bin));
            ++pos;
        }
        for (const auto& [r, pow] : s.drops) (void)w->on_raindrop(r.payee, r.bin, pow);
    }
    struct Out { bool ok = false; std::string cells; bytes32 digest{}; std::map<bytes32, long long> delta; std::uint64_t inputs = 0; std::size_t receipts = 0; };
    Out compose_prefix(std::uint64_t h, const dx::LanePrefix& lp) {
        Out o;
        const auto rg = w->range_for(h);
        if (!rg) return o;
        const auto lc = w->compose_lane(rg->first, rg->second, lp);
        st::DropsCompose dctx; dctx.price = price_of(600000000000ULL, 1000); dctx.enrollment = &lc.book;
        const auto carry = dx::compose_carry(params, lc.rows, dctx);
        for (const auto& r : lc.rows) o.cells += hex(r.payee).substr(0, 6) + "@" + std::to_string(r.interval) + ",";
        o.ok = true; o.digest = carry.enrollment_digest; o.delta = carry.delta; o.inputs = lc.inputs; o.receipts = lc.prefix_shares;
        return o;
    }
    Out compose(std::uint64_t h, std::uint64_t P, std::string* why = nullptr) {
        const auto lp = w->own_prefix(P, bin_of_pid, why);
        if (!lp) return Out{};
        return compose_prefix(h, *lp);
    }
};
static bool same(const NodeH::Out& a, const NodeH::Out& b) {
    return a.ok && b.ok && a.cells == b.cells && a.digest == b.digest && a.delta == b.delta && a.inputs == b.inputs && a.receipts == b.receipts;
}

int main() {
    Checker C;
    const bytes32 P = b32_of(0x31), Q = b32_of(0x32), R = b32_of(0x33);
    const std::vector<bytes32> enrol = {P, Q, R};
    const ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    const Stream s = make_stream(P, Q, R, params.subthreshold.K);
    const std::uint64_t N = s.receipts.size();
    const std::uint64_t Pcut = N - 30;   // the on-chain cut of the lane block at h=170
    const std::uint64_t H = 60;          // the relay vault horizon (positions) of this KAT
#if defined(C2POOL_XMR_DROPS_ENROL_TIDY)
    std::printf("fix tree (C2POOL_XMR_DROPS_ENROL_TIDY)\n");
#else
    std::printf("BASE tree (no C2POOL_XMR_DROPS_ENROL_TIDY): nothing is pruned, the tip book still runs\n");
#endif

    std::printf("ET1: the lane-position log is folded below the oldest reachable cut\n");
    {
        NodeH twin(enrol), node(enrol);
        twin.feed(s); node.feed(s);
        const auto before = node.compose(170, Pcut);
        C(before.ok && !before.delta.empty(), "ET1 the composition at the on-chain cut is non-trivial");
#if defined(C2POOL_XMR_DROPS_ENROL_TIDY)
        const std::uint64_t Qp = dx::XmrDropsWiring::lane_prune_point(Pcut, N, H);
        const std::uint64_t M = dx::XmrDropsWiring::kLanePosMargin;
        std::printf("  lane N=%llu cut P=%llu H=%llu margin=%llu -> prune point Q=%llu\n", (unsigned long long)N,
                    (unsigned long long)Pcut, (unsigned long long)H, (unsigned long long)M, (unsigned long long)Qp);
        C(Qp == std::min<std::uint64_t>(Pcut, N - H - 1) - M, "ET1 Q = min(oldest open cut, lane_next - H - 1) - margin");
        C(dx::XmrDropsWiring::lane_prune_point(std::nullopt, N, H) == 0, "ET1 no cut known yet -> nothing is pruned");
        C(dx::XmrDropsWiring::lane_prune_point(Pcut, 10, H) == 0, "ET1 a lane shorter than the horizon -> nothing is pruned");
        const std::size_t folded = node.w->prune_lane_log(Qp, bin_of_pid);
        const auto ls = node.w->lane_log_stats();
        std::printf("  folded=%zu entries=%zu base_P=%llu base_payees=%zu base_counts=%zu\n", folded, ls.entries,
                    (unsigned long long)ls.base_P, ls.base_payees, ls.base_counts);
        C(folded == Qp && ls.base_P == Qp && ls.entries == N - Qp, "ET1 ★ every entry below Q is folded, the rest kept");
        C(!node.w->lane_log_has(0) && !node.w->lane_log_has(Qp - 1) && node.w->lane_log_has(Qp),
          "ET1 ★ an entry below the bound is GONE from the log; the first reachable one stays");
        const auto after = node.compose(170, Pcut);
        C(same(before, after), "ET1 ★ compose at the on-chain cut after the fold == before (rows, digest, delta, inputs, receipts)");
        const auto t_at = twin.compose(170, ls.base_P), n_at = node.compose(170, ls.base_P);
        C(same(t_at, n_at), "ET1 ★ compose at the OLDEST still-reachable cut (the folded base) == the unpruned twin's");
        dx::DropsCarry carry; carry.delta = before.delta; carry.enrollment_digest = before.digest;
        C(dx::verify_carry(carry, true, after.digest).empty(), "ET1 ★ verify_carry accepts the pre-fold carriage against the post-fold lane digest");
        dx::LanePrefix rep; rep.P = Pcut;   // the relay repair: the winner-side order, every receipt listed
        for (std::uint64_t i = 0; i < Pcut; ++i) rep.shares.push_back({s.receipts[i].payee, s.receipts[i].bin});
        std::mt19937_64 g(11); std::shuffle(rep.shares.begin(), rep.shares.end(), g);
        C(same(before, node.compose_prefix(170, rep)), "ET1 ★ a repaired (winner-side) prefix composes the same on the pruned node");
        std::string why;
        C(!node.w->own_prefix(Qp - 1, bin_of_pid, &why) && why.find("below our folded lane-log base") != std::string::npos,
          "ET1 a cut below the folded base answers nullopt (the relay repair), never a different composition");
    }
    {   // an unresolvable reloaded bin below Q is never folded
        NodeH n1(enrol);
        n1.feed(s, /*reload_bin0_at=*/true, 20);
        auto none = [](const bytes32&) { return std::optional<std::uint64_t>{}; };
        const std::size_t f1 = n1.w->prune_lane_log(80, none);
        C(f1 == 20 && n1.w->lane_log_stats().base_P == 20 && n1.w->lane_log_has(20),
          "ET1 the fold stops at an unresolvable reloaded bin (nothing unresolvable is folded)");
        const std::size_t f2 = n1.w->prune_lane_log(80, bin_of_pid);
        C(f2 == 60 && n1.w->lane_log_stats().base_P == 80, "ET1 ... and continues once its bin resolves from the prev_id");
        NodeH n2(enrol); n2.feed(s);
        C(same(n1.compose(170, Pcut), n2.compose(170, Pcut)), "ET1 ... composing exactly the unpruned result");
        n1.w->on_share_lane(P, 150, 10, 1, pid_of(150));   // a rewrite below the base
        std::string why;
        C(!n1.w->own_prefix(Pcut, bin_of_pid, &why) && n1.w->lane_log_stats().stale,
          "ET1 a rewrite below the folded base makes the own prefix refuse (relay repair), never a stale fold");
    }
    {   // bounded over a long lane: prune at every 10th receipt, the open cut 5 behind the tip
        auto w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        std::size_t mx = 0;
        for (std::uint64_t pos = 0; pos < 6000; ++pos) {
            w->on_share_lane(pos % 2 ? P : Q, 101 + pos / 3, pos, 1, pid_of(101 + pos / 3));
            if (pos % 10 == 9) w->prune_lane_log(dx::XmrDropsWiring::lane_prune_point(pos + 1 - 5, pos + 1, H), bin_of_pid);
            mx = std::max(mx, w->lane_log_stats().entries);
        }
        const std::size_t bound = H + 1 + dx::XmrDropsWiring::kLanePosMargin + 10;
        const auto ls = w->lane_log_stats();
        std::printf("  6000 receipts: entries=%zu max=%zu (bound H+1+margin+stride=%zu) base_payees=%zu\n", ls.entries, mx, bound, ls.base_payees);
        C(mx <= bound && ls.base_payees == 2, "ET1 ★ over 6000 receipts the log stays <= H + 1 + margin (+ the prune stride); the fold holds 2 payees");
#else
        (void)H;
        C(false, "ET1 the base has no lane-log bound (m_lane_pos grows with every receipt)");
#endif
    }

    std::printf("ET2: the tip-based book and the node-local share book are retired\n");
    {
#if defined(C2POOL_XMR_DROPS_ENROL_TIDY)
        NodeH n(enrol);
        n.w->set_lane_only();
        n.feed(s);
        const auto rows130 = n.node.range(130), rows170 = n.node.range(170);
        const auto cs = n.w->chain_stats();
        C(rows130.empty() && rows170.empty() && cs.withheld == 0 && cs.lo == 120 && cs.hi == 160 && cs.marks == 2,
          "ET2 lane-only: the harvest seam advances the range bookkeeping (range [120,160)) and derives no rows, withholds nothing");
        NodeH m(enrol); m.feed(s);
        C(same(n.compose(170, Pcut), m.compose(170, Pcut)), "ET2 ... and the lane composition is unchanged");
#else
        C(false, "ET2 the base has no lane-only wiring (the tip book + share book still run)");
#endif
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "ET2 shell source readable");
        C(sh.find("drops->on_share_pushed(") == std::string::npos, "ET2 ★ the shell no longer tees shares into a node-local share book");
        C(sh.find("drops->enroll_at_tip(") == std::string::npos && sh.find("drops->arm_at_tip(") == std::string::npos,
          "ET2 ★ the shell no longer enrols at the native tip or arms a share book");
        C(sh.find("node.set_enrollment_book(nullptr);") != std::string::npos && sh.find("drops->set_lane_only();") != std::string::npos,
          "ET2 the node gets NO tip enrolment book; the wiring is lane-only");
        C(sh.find("drops_prune_lane_log();") != std::string::npos && sh.find("lane_prune_point(oldest, drops->lane_contig(), H)") != std::string::npos,
          "ET2 the shell folds its lane log below the oldest reachable cut (finalize cursor + vault horizon)");
    }

    std::printf("ET3: an enrol-set mismatch is refused at HELLO by name\n");
    {
        rl::Hello a; a.network = 3; a.chain_id = 7; a.share_diff = 8; a.node_nonce = 1;
        a.pool = rl::PoolId{b32_of(0x71), 1, 0}; a.pool->genesis = b32_of(0x72);
        rl::Hello b = a; b.node_nonce = 2;
        const bytes32 base = b32_of(0x51);
        const auto ea = dx::enrol_set_digest({P, Q, R}), eb = dx::enrol_set_digest({P, Q});
        a.lane_params_digest = dx::hello_digest_with_enrol(base, {P, Q, R});
        b.lane_params_digest = dx::hello_digest_with_enrol(base, {P, Q});
#if defined(C2POOL_XMR_DROPS_ENROL_TIDY)
        a.enrol_set = ea; b.enrol_set = eb;
        const auto fa = rl::encode_hello(a);
        rl::Hello a2; std::string why;
        if constexpr (rl::kHelloEnrolSetLive) {
            C(fa.size() == rl::kHelloBytesEnrolSet && fa.size() == 206 && rl::decode_hello(fa, a2, &why) && a2 == a,
              "ET3 the flip-1 HELLO carries the enrol-set digest (206 B) and round-trips");
        } else {
            std::vector<std::uint8_t> f206 = fa; f206.resize(rl::kHelloBytesEnrolSet, 0);
            C(fa.size() == rl::kHelloBytesPoolGenesis && !rl::decode_hello(f206, a2, &why) && why == "hello: wrong length",
              "ET3 flip 0: no enrol-set trailer is emitted and a 206-byte HELLO is refused (wrong length), as master");
        }
        rl::Hello z = a; z.enrol_set.reset();
        rl::Hello z2;
        C(rl::encode_hello(z).size() == rl::kHelloBytesPoolGenesis && rl::decode_hello(rl::encode_hello(z), z2) && !z2.enrol_set,
          "ET3 without it (flip 0) the HELLO is the unchanged 174-byte POOL-LINEAGE frame");
        rl::Hello c = b; c.enrol_set.reset(); c.lane_params_digest = base;
        const std::string mc = rl::hello_mismatch(a, c);
        C(mc.find("ENROL_SET_MISMATCH") == 0 && mc.find("theirs=none") != std::string::npos,
          "ET3 a peer without an enrol set is named as such (theirs=none)");
        rl::Hello t = a; t.node_nonce = 9;
        C(rl::hello_mismatch(a, t).empty(), "ET3 the same enrol set (and the same everything) is still compatible");
#else
        (void)ea; (void)eb;
#endif
        const std::string m = rl::hello_mismatch(a, b);
        std::printf("  refusal: %s\n", m.c_str());
        const std::string sa = hex(ea).substr(0, 12), sb = hex(eb).substr(0, 12);
        C(m.find("enrol-set digest differs") != std::string::npos && m.find("ours=" + sa) != std::string::npos &&
          m.find("theirs=" + sb) != std::string::npos,
          "ET3 ★ the refusal names the enrol set and prints BOTH short enrol-set digests (base: generic lane_params_digest refusal)");
        C(m.find("--drops-enrol") != std::string::npos, "ET3 ... and says every node of a pool must use the identical --drops-enrol list");
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(sh.find("if (drops_live && !drops->enrol_set().empty())") != std::string::npos &&
          sh.find("ro.enrol_set_digest = c2pool::v37n::xmr::drops::enrol_set_digest(drops->enrol_set());") != std::string::npos,
          "ET3 the shell sends the enrol-set digest only when DROPS is live with a non-empty set (flip 0: master's HELLO)");
    }
    return C.done("v37_xmr_drops_enrol_tidy_kat");
}
