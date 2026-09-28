// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_carry_suffix_kat -- DROPS-CARRY-SUFFIX (capstone attempt 5, flip 1).
//
// THE DEFECT (stagenet, RC8, h=2217148). The winner composed its block's DROPS
// delta from its own lane order [0, P) (2180 receipts, book 1f9a7b5afcbf). The
// receivers' own orders differed at P, so they took the relay repair; the
// serving peer's vault no longer retained [0, 2200), the repair served the
// SUFFIX [2200, 4360), and the DROPS prefix builder composed from that suffix
// alone, labelled [0, P) (1080 receipts, book 32c87e0ab360). Every payee's first
// bin moved later and S shrank: a different book, a different delta, "carried
// REFUSED" on both receivers, and the owed ledger split (the winner's next
// lane roots were refused on the minority: lane_root_refused -> LIABILITY).
//
// THE FIX. The DROPS prefix of a suffix repair is OUR lane log over [0, a0)
// (the base the settlement replay verified) + the served [a0, P), and it must
// cover exactly [0, P) (XmrDropsWiring::merged_prefix); otherwise it HOLDs.
//
//   CS1  CONTROL a0 == 0 (the whole order served): the receiver derives the
//        winner's book + delta (base and fix).
//   CS2  CAPSTONE a0 > 0: three cuts, each repaired from a suffix. The receiver
//        derives the winner's prefix receipts, book digest and delta; the
//        winner's carried trailer verifies (base: suffix only -> RED).
//   CS3  our folded lane-log base reaches past a0: HOLD (retry), never partial.
//   CS4  our log does not tile [0, a0) (a gap / a receipt straddling a0): HOLD.
//   CS4b a SHADOW base (our own [0, a0) is not the winner's; the relay replay
//        reached the spine from a reconstructed winner-side order): [0, a0)
//        comes from that order's DROPS record -> the winner's book + delta.
//   CS5  the served list is not [a0, P) (one receipt missing / one past P):
//        HOLD with retry=false (the shell's drops-ALARM prefix-positions).
//   CS6  LEDGER (M1): three nodes book three lane blocks (winners W, R1, W);
//        owed_digest equal on all nodes after every block, and no node refuses
//        a later winner's committed lane root (base: split + lane_root_refused).
//   CS7  NEVER-A-CLAWBACK + ONE RULE (M5): every node's journalled booking of
//        every block is identical to the winner's and is re-derived unchanged
//        after later blocks (no booked row is ever reduced or rewritten); the
//        winner's own block composed through the receivers' route
//        (merged_prefix of its own order) equals its own_prefix composition.
//   CS8  source pins: the shell builds the repaired prefix through
//        merged_prefix with repair_a0 + the verified-base check, ALARMs a
//        carried mismatch, and books the lane composition either way.
//
// RED on the base (1823f754 = RC8 d263379a): the checks run the base shell's
// rule (the served ids alone are the prefix) and fail; GREEN on the fix.
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
#include <c2pool/v37/v37_subthreshold_estimator.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;
static constexpr std::uint32_t kPushes = 2;   // fee model: payee push + donation push per receipt

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
static bytes32 pid_of(std::uint64_t bin) { bytes32 b{}; b[0] = 0xEE; std::memcpy(b.data() + 8, &bin, 8); return b; }
static std::optional<std::uint64_t> bin_of_pid(const bytes32& pid) { std::uint64_t b = 0; std::memcpy(&b, pid.data() + 8, 8); return b; }

// the canonical chain: lane blocks at these heights
static const std::set<std::uint64_t> kLanes = {130, 170, 210};

// One replicated input stream: the WINNER-side lane order (receipt i at lane
// positions [2i, 2i+2)) + the raindrops every node holds (the backfill done).
struct Rcpt { bytes32 payee; std::uint64_t bin; std::uint16_t give; };
struct Stream {
    std::vector<Rcpt> order;                                 // the winner's lane order
    std::vector<std::pair<Rcpt, bytes32>> drops;             // (payee, bin) -> pow_le
};
static Stream make_stream(const std::vector<bytes32>& who, std::uint32_t K) {
    Stream s;
    std::mt19937_64 rng(0xCA55E77EULL);
    const std::uint16_t give[4] = {0, 655, 6553, 0};
    const std::uint64_t from[4] = {101, 101, 115, 150};      // payee 3 is a late miner
    for (std::uint64_t bin = 101; bin <= 205; ++bin) {
        for (int i = 0; i < 4; ++i) {
            if (bin < from[i]) continue;
            const int n = (i == 1 && bin % 3 == 0) ? 2 : 1;   // uneven receipt counts per bin
            for (int j = 0; j < n; ++j) s.order.push_back({who[i], bin, give[i]});
            for (std::uint32_t k = 0; k < K + 1; ++k) {
                bytes32 pow{};
                for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(pow.data() + w * 8, &v, 8); }
                pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));   // a raindrop, not a share
                s.drops.push_back({{who[i], bin, give[i]}, pow});
            }
        }
    }
    return s;
}
// A receiver's OWN order: the winner's over [0, keep) receipts, then the rest
// in its own (relay-arrival) order -- its digest at P differs from the spine.
static std::vector<Rcpt> diverged(const std::vector<Rcpt>& w, std::size_t keep, std::uint64_t seed) {
    std::vector<Rcpt> o(w);
    std::mt19937_64 g(seed);
    for (std::size_t a = keep; a < o.size(); a += 8)   // relay-arrival reorders, within a few bins
        std::shuffle(o.begin() + static_cast<std::ptrdiff_t>(a), o.begin() + static_cast<std::ptrdiff_t>(std::min(a + 8, o.size())), g);
    return o;
}

struct NodeH {
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode node;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    NodeH() {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, kShareDiff, 1);
        w->attach(node);
        w->attach_chain_order(node, kD);
        w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = kLanes.lower_bound(h);
            if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
        w->observe_native_tip(100);
        w->set_enrol_mode(dx::EnrolMode::Auto);   // the capstone's auto-enrol
    }
    void feed(const std::vector<Rcpt>& order, const Stream& s) {
        std::uint64_t pos = 0;
        for (const auto& r : order) {
            w->on_share_lane(r.payee, r.bin, pos, kPushes, pid_of(r.bin), r.give);
            pos += kPushes;
        }
        for (const auto& [r, pow] : s.drops) (void)w->on_raindrop(r.payee, r.bin, pow);
    }
    struct Out {
        bool ok = false; std::size_t rows = 0, receipts = 0; std::uint64_t positions = 0;
        bytes32 digest{}; std::map<bytes32, long long> delta; std::string why; bool retry = true;
    };
    Out compose(std::uint64_t h, const dx::LanePrefix& lp, const bytes32& don) {
        Out o;
        const auto rg = w->range_for(h);
        if (!rg) { o.why = "range undecidable"; return o; }
        const auto lc = w->compose_lane(rg->first, rg->second, lp);
        st::DropsCompose dctx; dctx.price = price_of(600000000000ULL, 1000);
        dctx.enrollment = &lc.book;
        auto carry = dx::compose_carry(params, lc.rows, dctx);
        dx::split_give_author(carry.delta, lp, don);
        o.ok = true; o.rows = lc.rows.size(); o.receipts = lc.prefix_shares; o.digest = carry.enrollment_digest;
        o.delta = carry.delta;
#if defined(C2POOL_XMR_DROPS_CARRY_SUFFIX)
        o.positions = lp.positions;
#endif
        return o;
    }
    // the winner / own-order route (unchanged by the fix)
    Out compose_own(std::uint64_t h, std::uint64_t P, const bytes32& don) {
        std::string why;
        const auto lp = w->own_prefix(P, bin_of_pid, &why);
        if (!lp) { Out o; o.why = why; return o; }
        return compose(h, *lp, don);
    }
    // the receiver's repaired route: `served` = the winner's receipts over [a0, P)
    Out compose_repaired(std::uint64_t h, std::uint64_t P, std::uint64_t a0, const std::vector<Rcpt>& served, const bytes32& don) {
#if defined(C2POOL_XMR_DROPS_CARRY_SUFFIX)
        std::vector<dx::ServedShare> sv;
        for (const auto& r : served) sv.push_back(dx::ServedShare{r.payee, r.bin, r.give, kPushes});
        dx::PrefixWhy pw;
        const auto lp = w->merged_prefix(P, a0, sv, bin_of_pid, &pw);
        if (!lp) { Out o; o.why = pw.text; o.retry = pw.retry; return o; }
        return compose(h, *lp, don);
#else
        (void)a0;   // the BASE shell rule (main_v37_xmr.cpp drops_lane_prefix): the served ids ARE "[0, P)"
        dx::LanePrefix lp; lp.P = P;
        for (const auto& r : served) lp.shares.push_back(dx::LaneShare{r.payee, r.bin, r.give});
        return compose(h, lp, don);
#endif
    }
};

// The owed ledger of one node: share credit E_b (the settlement view at the
// cut -- the same on every node, the spine-verified prefix) + the booked DROPS
// delta, digested exactly like OwedLedger::owed_digest (V37Q).
struct Ledger {
    std::map<bytes32, long long> fw;
    std::vector<bytes32> hist;                                   // owed_digest after every booking (genesis first)
    std::map<std::uint64_t, std::map<bytes32, long long>> journal;   // h -> the booked rows (E_b + delta)
    std::uint64_t lane_root_refused = 0, liability = 0;
    bytes32 digest() const {
        std::map<std::array<std::uint8_t, 32>, long long> m;
        for (const auto& [k, v] : fw) { std::array<std::uint8_t, 32> a{}; std::memcpy(a.data(), k.data(), 32); m[a] = v; }
        const auto d = ::c2pool::v37::subthreshold::owed_digest(m, {});
        bytes32 b{}; std::memcpy(b.data(), d.data(), 32);
        return b;
    }
    Ledger() { hist.push_back(digest()); }
    // book block h whose coinbase commits `root` (the winner's owed_digest at win)
    void book(std::uint64_t h, const bytes32& root, const std::map<bytes32, long long>& rows, std::uint64_t reward) {
        if (std::find(hist.begin(), hist.end(), root) == hist.end()) {   // cba lane_root_refused
            ++lane_root_refused; liability += reward;                     // whole reward -> node-local LIABILITY
            return;
        }
        journal[h] = rows;
        for (const auto& [k, v] : rows) fw[k] += v;
        hist.push_back(digest());
    }
};
static std::map<bytes32, long long> share_credit(const std::vector<Rcpt>& o, std::uint64_t lo, std::uint64_t hi, std::uint64_t reward) {
    std::map<bytes32, std::uint64_t> n; std::uint64_t tot = 0;
    for (std::uint64_t i = lo / kPushes; i < hi / kPushes && i < o.size(); ++i) { ++n[o[i].payee]; ++tot; }
    std::map<bytes32, long long> e;
    for (const auto& [k, c] : n) e[k] = static_cast<long long>(reward * c / (tot ? tot : 1));
    return e;
}
static std::map<bytes32, long long> plus(std::map<bytes32, long long> a, const std::map<bytes32, long long>& b) {
    for (const auto& [k, v] : b) a[k] += v;
    for (auto it = a.begin(); it != a.end();) it = it->second == 0 ? a.erase(it) : std::next(it);
    return a;
}
static std::vector<Rcpt> slice(const std::vector<Rcpt>& o, std::uint64_t a, std::uint64_t b) {
    return std::vector<Rcpt>(o.begin() + static_cast<std::ptrdiff_t>(a / kPushes), o.begin() + static_cast<std::ptrdiff_t>(b / kPushes));
}

int main() {
    Checker C;
    const std::vector<bytes32> who = {b32_of(0x41), b32_of(0x42), b32_of(0x43), b32_of(0x44)};
    const bytes32 DON = b32_of(0x77);
    const ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    const Stream s = make_stream(who, params.subthreshold.K);
    const std::vector<Rcpt>& W = s.order;
    const auto pos_of_bin = [&](std::uint64_t b) {
        std::uint64_t n = 0; for (const auto& r : W) if (r.bin < b) ++n; return n * kPushes;
    };
    const std::size_t dv = static_cast<std::size_t>(pos_of_bin(140) / kPushes);   // the receivers' orders diverge above here
    const std::vector<Rcpt> R1 = diverged(W, dv, 1), R2 = diverged(W, dv, 2);
    struct Blk { std::uint64_t h, P, a0; int winner; };
    // block 1 below the divergence (every node's own order reaches the spine);
    // blocks 2, 3 above it, repaired from a SUFFIX [a0, P) (the peer's vault horizon)
    const std::vector<Blk> blocks = {{130, pos_of_bin(115), 0, 0}, {170, pos_of_bin(165), pos_of_bin(128), 1}, {210, pos_of_bin(200), pos_of_bin(138), 0}};
    const std::uint64_t kReward = 600000000000ULL;
#if defined(C2POOL_XMR_DROPS_CARRY_SUFFIX)
    std::printf("fix tree (C2POOL_XMR_DROPS_CARRY_SUFFIX)\n");
#else
    std::printf("BASE tree (no C2POOL_XMR_DROPS_CARRY_SUFFIX): a repaired prefix is the served ids alone (the RC8 shell rule)\n");
#endif
    std::printf("lane: %zu receipts (%zu positions), divergence at %zu receipts; cuts P=%llu/%llu/%llu a0=%llu/%llu/%llu\n",
                W.size(), W.size() * kPushes, dv, (unsigned long long)blocks[0].P, (unsigned long long)blocks[1].P,
                (unsigned long long)blocks[2].P, (unsigned long long)blocks[0].a0, (unsigned long long)blocks[1].a0,
                (unsigned long long)blocks[2].a0);

    NodeH nW, nR1, nR2;
    nW.feed(W, s); nR1.feed(R1, s); nR2.feed(R2, s);
    NodeH* nodes[3] = {&nW, &nR1, &nR2};
    const std::vector<Rcpt>* orders[3] = {&W, &R1, &R2};
    const char* names[3] = {"W", "R1", "R2"};

    std::printf("CS1: CONTROL a0 == 0 -- the whole winner-side order served\n");
    {
        const auto& b = blocks[2];
        const auto ow = nW.compose_own(b.h, b.P, DON);
        const auto o2 = nR2.compose_repaired(b.h, b.P, 0, slice(W, 0, b.P), DON);
        std::printf("  W receipts=%zu digest=%s… | R2 receipts=%zu digest=%s…\n", ow.receipts, hex(ow.digest).substr(0, 12).c_str(),
                    o2.receipts, hex(o2.digest).substr(0, 12).c_str());
        C(ow.ok && ow.rows > 0 && !ow.delta.empty(), "CS1 the winner's composition is non-trivial (rows + a non-zero delta)");
        C(o2.ok && o2.receipts == ow.receipts && o2.digest == ow.digest && o2.delta == ow.delta,
          "CS1 a whole-order repair derives the winner's receipts, book digest and delta");
    }

    std::printf("CS2 + CS6: three lane blocks, winners W, R1, W; receivers repair blocks 2 and 3 from a SUFFIX\n");
    Ledger L[3];
    std::uint64_t carried_refused = 0, split_blocks = 0, suffix_repairs = 0;
    std::vector<bytes32> digest_after[3];
    std::uint64_t prevP = 0;
    std::map<std::uint64_t, std::map<bytes32, long long>> win_rows;   // the winner's booking of each block
    std::map<std::uint64_t, std::vector<NodeH::Out>> outs;
    for (const auto& b : blocks) {
        const std::vector<Rcpt>& wo = *orders[b.winner];
        const auto ow = nodes[b.winner]->compose_own(b.h, b.P, DON);   // the winner's own composition (carried v0x02)
        const bytes32 root = L[b.winner].hist.back();                  // its owed_digest at win (the coinbase 03 root)
        const auto eb = share_credit(wo, prevP, b.P, kReward);
        win_rows[b.h] = plus(eb, ow.delta);
        for (int i = 0; i < 3; ++i) {
            NodeH::Out o;
            const bool own_spine = i == b.winner || b.P <= dv * kPushes;   // our digest at P is the spine
            if (own_spine) o = nodes[i]->compose_own(b.h, b.P, DON);
            else { o = nodes[i]->compose_repaired(b.h, b.P, b.a0, slice(wo, b.a0, b.P), DON); if (b.a0) ++suffix_repairs; }
            const bool carried_ok = o.ok && o.digest == ow.digest && o.delta == ow.delta;   // verify_carry(+delta) on this node
            if (!own_spine && !carried_ok) ++carried_refused;
            std::printf("  h=%llu %s %s receipts=%zu positions=%llu digest=%s… delta_payees=%zu | carried %s%s\n",
                        (unsigned long long)b.h, names[i], own_spine ? "own   " : "suffix", o.receipts, (unsigned long long)o.positions,
                        hex(o.digest).substr(0, 12).c_str(), o.delta.size(), carried_ok ? "AGREES" : "REFUSED",
                        o.ok ? "" : (" (HOLD: " + o.why + ")").c_str());
            outs[b.h].push_back(o);
            if (o.ok) L[i].book(b.h, root, plus(eb, o.delta), kReward);
        }
        bool split = false;
        for (int i = 0; i < 3; ++i) { digest_after[i].push_back(L[i].hist.back()); if (L[i].hist.back() != L[0].hist.back()) split = true; }
        if (split) ++split_blocks;
        std::printf("  h=%llu owed_digest W=%s… R1=%s… R2=%s…%s\n", (unsigned long long)b.h, hex(L[0].hist.back()).substr(0, 12).c_str(),
                    hex(L[1].hist.back()).substr(0, 12).c_str(), hex(L[2].hist.back()).substr(0, 12).c_str(), split ? "  SPLIT" : "");
        prevP = b.P;
    }
    const std::uint64_t refused_roots = L[0].lane_root_refused + L[1].lane_root_refused + L[2].lane_root_refused;
    const std::uint64_t liab = L[0].liability + L[1].liability + L[2].liability;
    std::printf("METRICS suffix_repairs=%llu carried_refused=%llu split_blocks=%llu lane_root_refused=%llu liability_pico=%llu\n",
                (unsigned long long)suffix_repairs, (unsigned long long)carried_refused, (unsigned long long)split_blocks,
                (unsigned long long)refused_roots, (unsigned long long)liab);
    C(suffix_repairs >= 3, "CS2 the scenario repairs >= 3 bookings from a suffix (a0 > 0)");
    C(carried_refused == 0, "CS2 ★ every suffix-repaired receiver derives the winner's book digest + delta (carried AGREES)");
    C(split_blocks == 0, "CS6 ★ owed_digest equal on W, R1, R2 after every lane block (one ledger)");
    C(refused_roots == 0 && liab == 0, "CS6 ★ no node refuses a later winner's lane root (0 lane_root_refused, 0 LIABILITY)");

    std::printf("CS7: never a clawback, one rule for the winner's own block and a peer's\n");
    {
        bool same_as_winner = true, no_reduction = true;
        for (int i = 0; i < 3; ++i)
            for (const auto& [h, rows] : L[i].journal) if (rows != win_rows[h]) same_as_winner = false;
        // re-drive every repaired booking after the later blocks: the journalled rows are re-derived unchanged
        for (std::size_t k = 0; k < blocks.size(); ++k) {
            const auto& b = blocks[k];
            for (int i = 0; i < 3; ++i) {
                if (i == b.winner || b.P <= dv * kPushes) continue;
                const auto o = nodes[i]->compose_repaired(b.h, b.P, b.a0, slice(*orders[b.winner], b.a0, b.P), DON);
                if (!o.ok || o.delta != outs[b.h][static_cast<std::size_t>(i)].delta) no_reduction = false;
            }
        }
        for (int i = 0; i < 3; ++i) if (L[i].journal.size() != blocks.size()) no_reduction = false;
        C(same_as_winner, "CS7 ★ every node journals, for every block, exactly the winner's booking (E_b + its carried delta)");
        C(no_reduction, "CS7 ★ a re-drive after later blocks re-derives every booked row unchanged (no booked row reduced or rewritten)");
#if defined(C2POOL_XMR_DROPS_CARRY_SUFFIX)
        const auto& b = blocks[2];
        const auto own = nW.compose_own(b.h, b.P, DON);
        const auto via = nW.compose_repaired(b.h, b.P, b.a0, slice(W, b.a0, b.P), DON);   // the receivers' route, on the winner
        C(via.ok && own.ok && via.digest == own.digest && via.delta == own.delta && via.receipts == own.receipts,
          "CS7 ★ the winner's own block through the receivers' route (merged_prefix) == its own_prefix composition");
        C(via.positions == b.P && own.positions == b.P, "CS7 both routes cover exactly [0,P) (prefix_positions == P)");
#else
        C(false, "CS7 the base has no merged route: a receiver's rule for the winner's block differs from the winner's");
#endif
    }

#if defined(C2POOL_XMR_DROPS_CARRY_SUFFIX)
    const auto& b3 = blocks[2];
    const auto served3 = slice(W, b3.a0, b3.P);
    std::vector<dx::ServedShare> sv3;
    for (const auto& r : served3) sv3.push_back(dx::ServedShare{r.payee, r.bin, r.give, kPushes});
    const auto ref3 = nW.compose_own(b3.h, b3.P, DON);
    std::printf("CS3: our folded lane-log base reaches past a0\n");
    {
        NodeH x; x.feed(R1, s);
        const std::size_t folded = x.w->prune_lane_log(b3.a0 + 10 * kPushes, bin_of_pid);
        dx::PrefixWhy pw;
        const auto lp = x.w->merged_prefix(b3.P, b3.a0, sv3, bin_of_pid, &pw);
        std::printf("  folded=%zu -> %s\n", folded, lp ? "composed" : pw.text.c_str());
        C(folded > 0 && !lp && pw.retry && pw.text.find("folded") != std::string::npos, "CS3 ★ HOLD (retry): never a prefix from a fold past a0");
        NodeH y; y.feed(R1, s);
        (void)y.w->prune_lane_log(b3.a0 - 12 * kPushes, bin_of_pid);   // a fold below a0: the merged prefix still holds [0,P)
        const auto oy = y.compose_repaired(b3.h, b3.P, b3.a0, served3, DON);
        C(oy.ok && oy.digest == ref3.digest && oy.delta == ref3.delta && oy.positions == b3.P,
          "CS3 a fold below a0 composes the winner's book + delta (the folded base counts as [0,base_end))");
    }
    std::printf("CS4: our log does not tile [0, a0)\n");
    {
        NodeH g;
        std::uint64_t pos = 0;
        for (std::size_t i = 0; i < R1.size(); ++i, pos += kPushes)
            if (i != 7) g.w->on_share_lane(R1[i].payee, R1[i].bin, pos, kPushes, pid_of(R1[i].bin), R1[i].give);
        dx::PrefixWhy pw;
        C(!g.w->merged_prefix(b3.P, b3.a0, sv3, bin_of_pid, &pw) && pw.retry, "CS4 ★ a gap below a0 HOLDs (retry)");
        NodeH t; t.feed(R1, s);
        std::vector<dx::ServedShare> sv_odd(sv3.begin() + 1, sv3.end());
        C(!t.w->merged_prefix(b3.P, b3.a0 + 1, sv_odd, bin_of_pid, &pw) && pw.text.find("straddles") != std::string::npos,
          "CS4 ★ a0 inside one of our receipts HOLDs");
    }
    std::printf("CS4b: a SHADOW base -- our own [0,a0) is not the winner's, a reconstructed winner-side order is\n");
    {
        // R3's own order diverges early (at bin 110); an earlier repair of the winner's cut P1 = bin 118
        // (a0 = bin 108, below R3's divergence) left the winner-side order as a shadow + its DROPS record.
        const std::size_t dv3 = static_cast<std::size_t>(pos_of_bin(110) / kPushes);
        const std::vector<Rcpt> R3 = diverged(W, dv3, 3);
        NodeH r3; r3.feed(R3, s);
        const std::uint64_t P1 = pos_of_bin(118), a01 = pos_of_bin(108), a02 = pos_of_bin(114);
        std::vector<dx::ServedShare> sv1, sv2;
        for (const auto& r : slice(W, a01, P1)) sv1.push_back(dx::ServedShare{r.payee, r.bin, r.give, kPushes});
        for (const auto& r : slice(W, a02, b3.P)) sv2.push_back(dx::ServedShare{r.payee, r.bin, r.give, kPushes});
        dx::PrefixWhy pw; dx::PrefixRecord rec1, rec2;
        const auto lp1 = r3.w->merged_prefix(P1, a01, sv1, bin_of_pid, &pw, nullptr, &rec1);
        C(lp1 && rec1.P == P1 && rec1.list.size() == P1 / kPushes, "CS4b the first repair records the winner-side order receipt by receipt");
        const auto lp2 = r3.w->merged_prefix(b3.P, a02, sv2, bin_of_pid, &pw, &rec1, &rec2);
        C(lp2 && lp2->positions == b3.P, "CS4b the shadow-based prefix covers [0,P)");
        if (lp2) {
            const auto o = r3.compose(b3.h, *lp2, DON);
            C(o.digest == ref3.digest && o.delta == ref3.delta && o.receipts == ref3.receipts,
              "CS4b ★ [0,a0) from the shadow record: the winner's book + delta (the replay's shadow base, mirrored)");
        }
        const auto lpo = r3.w->merged_prefix(b3.P, a02, sv2, bin_of_pid, &pw);   // what the shell must NOT do
        if (lpo) { const auto o = r3.compose(b3.h, *lpo, DON);
            std::printf("  own [0,a0) instead (a shadow cut, the shell HOLDs this): receipts=%zu digest %s the winner's, delta %s\n",
                        o.receipts, o.digest == ref3.digest ? "==" : "!=", o.delta == ref3.delta ? "==" : "!="); }
        {   // a record folded below a0 (the bounded record) composes the same; folded past a0 it HOLDs
            dx::PrefixRecord f1 = rec1, f2 = rec1;
            const std::size_t nf = r3.w->fold_record(f1, a02 - 6 * kPushes);
            const auto lpf = r3.w->merged_prefix(b3.P, a02, sv2, bin_of_pid, &pw, &f1);
            const bool same = lpf && r3.compose(b3.h, *lpf, DON).delta == ref3.delta && r3.compose(b3.h, *lpf, DON).digest == ref3.digest;
            (void)r3.w->fold_record(f2, a02 + 2 * kPushes);
            C(nf > 0 && same && !r3.w->merged_prefix(b3.P, a02, sv2, bin_of_pid, &pw, &f2) && pw.retry,
              "CS4b a record folded below a0 composes the winner's book + delta; folded past a0 it HOLDs");
        }
        dx::PrefixRecord shortrec = rec1; shortrec.list.resize(shortrec.list.size() / 2);
        C(!r3.w->merged_prefix(b3.P, a02, sv2, bin_of_pid, &pw, &shortrec) && pw.retry, "CS4b a record that does not reach a0 HOLDs");
    }
    std::printf("CS5: the served list is not [a0, P)\n");
    {
        NodeH t; t.feed(R1, s);
        dx::PrefixWhy pw;
        std::vector<dx::ServedShare> missing(sv3.begin(), sv3.end() - 1);
        const auto m1 = t.w->merged_prefix(b3.P, b3.a0, missing, bin_of_pid, &pw);
        std::printf("  missing one -> %s\n", pw.text.c_str());
        C(!m1 && !pw.retry && pw.text.find("!= P") != std::string::npos, "CS5 ★ one served receipt missing: HOLD + ALARM (retry=false)");
        std::vector<dx::ServedShare> extra(sv3); extra.push_back(sv3.back());
        C(!t.w->merged_prefix(b3.P, b3.a0, extra, bin_of_pid, &pw) && !pw.retry, "CS5 ★ a served receipt at or past P: HOLD + ALARM");
        C(!t.w->merged_prefix(b3.P, b3.P + 2, {}, bin_of_pid, &pw) && !pw.retry, "CS5 a0 past P: HOLD + ALARM");
        const auto ok = t.w->merged_prefix(b3.P, b3.a0, sv3, bin_of_pid, &pw);
        C(ok && ok->positions == b3.P && ok->receipts() == ref3.receipts, "CS5 the exact [a0,P) list merges to P positions, the winner's receipts");
    }
#else
    C(false, "CS3 the base has no merged prefix (a fold past a0 is not detected)");
    C(false, "CS4 the base does not check that our log tiles [0,a0)");
    C(false, "CS4b the base has no shadow-record route (a shadow-based suffix composes from the suffix alone)");
    C(false, "CS5 the base composes from a served list of any length (no positions invariant)");
#endif

    std::printf("CS8: source pins (main_v37_xmr.cpp)\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "CS8 shell source readable");
        const auto dp = sh.find("auto drops_lane_prefix = [&]");
        const auto ra = sh.find("relay_node->repair_a0(P, cc.spine_digest, &peer_a0)", dp == std::string::npos ? 0 : dp);
        const auto mp = sh.find("drops->merged_prefix(P, a0, served, drops_bin_of, &pw, shadow_rec, &rec)", dp == std::string::npos ? 0 : dp);
        const auto end = sh.find("auto drops_compose_lane = [&]");
        C(dp != std::string::npos && ra != std::string::npos && mp != std::string::npos && dp < ra && ra < mp && mp < end,
          "CS8 ★ the repaired DROPS prefix = merged_prefix(P, repair_a0, served) (never the served ids alone)");
        C(sh.find("rbi->second.base == static_cast<int>(relay::RepairReplayer::kOwn)") != std::string::npos &&
          sh.find("replay_base[key] = ReplayBase{static_cast<int>(base_used), a0,") != std::string::npos,
          "CS8 ★ our [0,a0) is used only when the settlement replay reached the spine from OUR order (else HOLD)");
        C(sh.find("shadow_rec = &ri->second; own_base = true;") != std::string::npos && sh.find("drops_store_record(pkey, std::move(rec));") != std::string::npos &&
          sh.find("if (drops_on_replay) drops_on_replay(key, P, a0, replay_base[key], ids);") != std::string::npos,
          "CS8 ★ a SHADOW base takes [0,a0) from that shadow's DROPS record (recorded when the relay replay verifies the order)");
        C(sh.find("drops-ALARM carry-mismatch:") != std::string::npos && sh.find("drops-ALARM prefix-positions:") != std::string::npos,
          "CS8 a carried mismatch and a partial prefix are ALARMs");
        C(sh.find("drops->set_carried(lane.carry.delta)") != std::string::npos &&
          sh.find("if (!drops_compose_lane(h, bid, bk, booking_price, why, drops_lane)) return false;") != std::string::npos,
          "CS8 every node, the winner included, books its own lane composition (the trailer is a witness)");
        C(sh.find("lp->positions < bk.credit_cut.next_pos") != std::string::npos, "CS8 the determinism guard runs before every compose");
    }
    return C.done("v37_xmr_drops_carry_suffix_kat");
}
