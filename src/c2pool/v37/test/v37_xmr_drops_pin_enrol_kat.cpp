// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_pin_enrol_kat -- the merge of master (#1857 DROPS-SET-PIN)
// into the XMR lane branch (A3 RAINDROP ENROL, gap 4 canonical order).
//
// THE SEAM. Master composes a lane block's DROPS rows from exactly the
// winner's pinned raindrop set (compose_lane_pinned). The branch enrols a
// DROPS-only payee at its first raindrop bin + 1 (and keeps the V37G registry
// of enrolments with the payee's ref). A plain merge takes master's pinned
// composer, which builds the book by the share rule alone: the raindrop
// enrolment and the registry vanish from every live composition, and a
// payee ref is lost on the live raindrop path (on_raindrop_id takes only the
// identity). The fix: the pinned composer enrols from the PINNED members only
// (never from what a node happens to retain), reads the booking-point
// registry, and the live raindrop path keeps the ref.
//
//   PE1  PINNED ENROL: two nodes, one holding an extra DROPS-only payee's
//        raindrops outside the pinned set, compose the same book digest, rows
//        and enrol_add; the pinned DROPS-only payee X is enrolled at its first
//        pinned bin + 1 with its ref; the unpinned payee Z is not enrolled
//        (base: X is not enrolled at all, RED).
//   PE2  REGISTRY: a registry record for X is honoured (min of registry and
//        raindrop) and X leaves enrol_add (base: the registry is ignored, RED).
//   PE3  REFUSED SET: a set naming a raindrop outside the range books EMPTY
//        rows, no enrol_add, and the book of the share rule + registry alone
//        (the same on every node).
//   PE4  LONG REF: a raindrop whose ref the V37G length byte cannot hold is
//        kept as an INVALID member: a set naming it is REFUSED alike on every
//        node, never a HOLD on a missing member (base: HOLD forever, RED).
//   PE5  source pins: the shell composes with the pinned set AND the
//        booking-point registry, feeds raindrops with their ref, and asks the
//        ONE composed-order rule (composed_order_check) from both the
//        settlement replay and the DROPS prefix composition.
//   PE6  ONE WON-FRAME VERSION: under the window rule (A4c: no one-shot
//        delta) the own win still leaves as FB_BLOCK_WON v0x03 with a
//        0-row delta, the book digest and the pinned set; it round-trips
//        and a flip-0 decoder refuses it.
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
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

#if defined(C2POOL_XMR_DROPS_PIN_ENROL)
#define PE_FIX 1
#else
#define PE_FIX 0
#endif

using namespace gap2test;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;
namespace rl = ::c2pool::v37n::xmr::relay;

static int g_fail = 0, g_pass = 0;
static void C(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    (ok ? g_pass : g_fail)++;
}

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;
static const std::set<std::uint64_t> kLanes = {130, 170};   // range(130) = [0,120)
static const ::v37::LaneParams kParams = ::v37::LaneParams::for_version(1);

struct HNode {   // the XmrNode seam shape
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook*) {}
    void set_pre_harvest(std::function<void(std::uint64_t)>) {}
    void set_drops_price_fn(std::function<st::WorkPrice()>) {}
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
};
static std::string slurp(const std::string& p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}
static ::v37::ScriptRef ref_of(std::uint8_t seed) {
    std::array<std::uint8_t, 32> b{}, a{};
    for (int i = 0; i < 32; ++i) { b[i] = static_cast<std::uint8_t>(seed + i); a[i] = static_cast<std::uint8_t>(seed * 3 + i); }
    return ::v37::xmr::make_xmr_std(b, a);
}
// the id a raindrop gets without a receipt (XmrDropsWiring::on_raindrop)
static bytes32 drop_id(const bytes32& payee, std::uint64_t bin, const bytes32& pow) {
    std::vector<std::uint8_t> b = {'V', '3', '7', 'D', 'R', 'O', 'P', 'I', 'D'};
    b.insert(b.end(), payee.begin(), payee.end());
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(bin >> (8 * i)));
    b.insert(b.end(), pow.begin(), pow.end());
    return ::v37::sha256d(b);
}
struct Drop {
    ::v37::ScriptRef ref; std::uint64_t bin; bytes32 pow;
    bytes32 id() const { return drop_id(::v37::xmr::xmr_identity_key(ref), bin, pow); }
};
// P, Q share every bin 101..165 (the lane prefix). X (DROPS-only) raindrops at
// 112 and 115 inside range(130) = [0,120) and at 125 outside it; Z (DROPS-only)
// raindrops at 105 that only node B holds (never pinned by the winner A).
struct World {
    ::v37::ScriptRef rP = ref_of(0x31), rQ = ref_of(0x32), rX = ref_of(0x34), rZ = ref_of(0x36);
    bytes32 P = ::v37::xmr::xmr_identity_key(rP), Q = ::v37::xmr::xmr_identity_key(rQ);
    bytes32 X = ::v37::xmr::xmr_identity_key(rX), Z = ::v37::xmr::xmr_identity_key(rZ);
    std::vector<std::pair<bytes32, std::uint64_t>> shares;
    std::vector<Drop> x_in, x_out, z_only;
    explicit World(std::uint32_t K) {
        std::mt19937_64 rng(0x91E7E7A3ULL);
        auto rain = [&](std::vector<Drop>& v, const ::v37::ScriptRef& r, std::uint64_t bin) {
            for (std::uint32_t k = 0; k < K + 1; ++k) {
                bytes32 pow{};
                for (int w = 0; w < 4; ++w) { const std::uint64_t u = rng(); std::memcpy(pow.data() + w * 8, &u, 8); }
                pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));   // a raindrop, never a share
                v.push_back({r, bin, pow});
            }
        };
        for (std::uint64_t bin = 101; bin <= 165; ++bin) { shares.push_back({P, bin}); shares.push_back({Q, bin}); }
        for (std::uint64_t bin : {112, 115}) rain(x_in, rX, bin);
        rain(x_out, rX, 125);
        rain(z_only, rZ, 105);
    }
};
static std::unique_ptr<dx::XmrDropsWiring> make_w(HNode& n) {
    auto w = dx::XmrDropsWiring::make_for_test(kParams.subthreshold.K, kShareDiff, 1);
    w->attach_chain_order(n, kD);
    w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
        auto it = kLanes.lower_bound(h);
        if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
        return *std::prev(it);
    });
    w->set_enrol_mode(dx::EnrolMode::Auto);
    w->set_raindrop_enrol(true);
    return w;
}
static bool feed(dx::XmrDropsWiring& w, const Drop& d) {
#if PE_FIX
    return w.on_raindrop_id(d.id(), d.ref, d.bin, d.pow);   // the live relay path: receipt id + ref
#else
    return w.on_raindrop(d.ref, d.bin, d.pow);              // the merge as git left it: no id+ref entry point
#endif
}
static void feed(dx::XmrDropsWiring& w, const std::vector<Drop>& v) { for (const auto& d : v) (void)feed(w, d); }
struct Out {
    std::vector<bytes32> missing;
    std::string refused;
    bytes32 digest{};
    std::size_t rows = 0;
    st::DropsEnrolRegistry add;
    std::uint64_t effX = 0, effZ = 0, effP = 0;
    bool same(const Out& o) const {
        bool sa = add.size() == o.add.size();
        for (auto a = add.begin(), b = o.add.begin(); sa && a != add.end(); ++a, ++b)
            sa = a->first == b->first && a->second.eff == b->second.eff && a->second.ref == b->second.ref;
        return missing == o.missing && refused == o.refused && digest == o.digest && rows == o.rows && sa;
    }
};
static Out compose(dx::XmrDropsWiring& w, const World& W, const std::vector<bytes32>& pin, const st::DropsEnrolRegistry& reg) {
    Out o;
    const auto rg = w.range_for(130);
    if (!rg) { o.refused = "range undecidable"; return o; }
    dx::LanePrefix lp;
    lp.P = W.shares.size();
    for (const auto& [p, b] : W.shares) lp.shares.push_back(dx::LaneShare{p, b, 0});
#if PE_FIX
    const auto pc = w.compose_lane_pinned(rg->first, rg->second, lp, pin, &reg);
#else
    (void)reg;
    const auto pc = w.compose_lane_pinned(rg->first, rg->second, lp, pin);
#endif
    o.missing = pc.missing; o.refused = pc.refused;
    o.digest = pc.lc.digest; o.rows = pc.lc.rows.size(); o.add = pc.lc.enrol_add;
    if (const auto* r = pc.lc.book.find(W.X)) o.effX = r->effective_from;
    if (const auto* r = pc.lc.book.find(W.Z)) o.effZ = r->effective_from;
    if (const auto* r = pc.lc.book.find(W.P)) o.effP = r->effective_from;
    return o;
}

int main() {
    std::printf("v37_xmr_drops_pin_enrol_kat (%s)\n", PE_FIX ? "fix" : "base");
    const std::uint32_t K = kParams.subthreshold.K;
    const World W(K);
    HNode na, nb;
    auto A = make_w(na), B = make_w(nb);
    A->observe_native_tip(140); B->observe_native_tip(140);
    feed(*A, W.x_in); feed(*A, W.x_out);
    feed(*B, W.z_only); feed(*B, W.x_out); feed(*B, W.x_in);   // another arrival order + Z's extra raindrops
    const auto rg = A->range_for(130);
    C(rg && rg->first == 0 && rg->second == 120, "range(130) = [0,120)");
    const auto pin = A->pinned_ids(0, 120, 16384);   // the winner A pins what it holds over the range
    C(pin.size() == W.x_in.size(), "the winner pins exactly X's in-range raindrops");

    // PE1 PINNED ENROL
    const st::DropsEnrolRegistry none;
    const Out a = compose(*A, W, pin, none), b = compose(*B, W, pin, none);
    std::printf("    PE1 A: effX=%llu effZ=%llu effP=%llu rows=%zu add=%zu | B: effX=%llu effZ=%llu add=%zu missing=%zu refused='%s'\n",
                (unsigned long long)a.effX, (unsigned long long)a.effZ, (unsigned long long)a.effP, a.rows, a.add.size(),
                (unsigned long long)b.effX, (unsigned long long)b.effZ, b.add.size(), b.missing.size(), b.refused.c_str());
    C(a.missing.empty() && a.refused.empty() && b.missing.empty() && b.refused.empty(), "PE1 both nodes compose (no HOLD, no refusal)");
    C(a.same(b), "PE1 A and B compose the same book digest, rows and enrol_add (B's extra raindrops ignored)");
    C(a.effX == 113, "PE1 the pinned DROPS-only payee X is enrolled at its first pinned bin 112 + 1 = 113");
    const auto ax = a.add.find(W.X);
    C(ax != a.add.end() && ax->second.eff == 113 && ax->second.ref == W.rX, "PE1 enrol_add carries X {eff 113, the ref its raindrop named}");
    C(b.effZ == 0 && b.add.find(W.Z) == b.add.end(), "PE1 Z (held by B only, never pinned) is not enrolled");
    C(a.effP == 102, "PE1 P keeps its lane-share enrolment (first share 101 + 1)");

    // PE2 REGISTRY
    st::DropsEnrolRegistry reg;
    reg[W.X].eff = 108; reg[W.X].ref = W.rX;
    const Out a2 = compose(*A, W, pin, reg), b2 = compose(*B, W, pin, reg);
    C(a2.same(b2), "PE2 with a registry both nodes still agree");
    C(a2.effX == 108, "PE2 the registry record (eff 108) wins: min(registry 108, raindrop 113)");
    C(a2.add.find(W.X) == a2.add.end(), "PE2 a registered payee is not enrolled again (no enrol_add)");

    // PE3 REFUSED SET
    std::vector<bytes32> bad = pin;
    bad.push_back(W.x_out.front().id());
    std::sort(bad.begin(), bad.end());
    const Out a3 = compose(*A, W, bad, reg), b3 = compose(*B, W, bad, reg);
    const Out e3 = compose(*A, W, {}, reg);
    C(!a3.refused.empty() && a3.missing.empty() && a3.same(b3), "PE3 a set naming an out-of-range raindrop is refused alike on A and B");
    C(a3.rows == 0 && a3.add.empty(), "PE3 a refused set books no rows and enrols nobody by raindrop");
    C(a3.digest == e3.digest, "PE3 its book is the share rule + registry alone (== the empty set's book)");

    // PE4 LONG REF
    Drop lr = W.x_in.front();
    lr.ref.payload.resize(300, 0x5A);
    lr.pow[0] ^= 0x01;
    const bool took = feed(*B, lr);
    std::vector<bytes32> withlong = pin;
    withlong.push_back(lr.id());
    std::sort(withlong.begin(), withlong.end());
    const Out b4 = compose(*B, W, withlong, none);
    std::printf("    PE4 took=%d missing=%zu refused='%s'\n", took ? 1 : 0, b4.missing.size(), b4.refused.c_str());
    C(!took, "PE4 a raindrop whose ref exceeds the V37G length byte is not harvested");
    C(b4.missing.empty() && !b4.refused.empty(), "PE4 a set naming it is REFUSED (an invalid member), never a HOLD on a missing one");

    // PE6 ONE WON-FRAME VERSION
    {
        rl::BlockWon bw;
        bw.chain_id = 0x584D52; bw.bid[0] = 0xB1; bw.h_b = 130; bw.cut_next_pos = W.shares.size(); bw.reward = 600000000000ULL;
        bw.payout_emitted = true;
        bw.drops = rl::BlockWon::Drops{{}, a.digest, pin};   // the window rule's carry: no delta rows
        const auto f = rl::encode_block_won(bw);
        rl::BlockWon back; std::string why;
        const bool ok = rl::decode_block_won(f, back, &why, true);
        std::printf("    PE6 frame %zu B version 0x%02x decode=%d %s\n", f.size(), f.size() > 1 ? f[1] : 0, ok ? 1 : 0, why.c_str());
        C(f.size() == rl::kBlockWonDropsMinBytes + 4 + 32 * pin.size() && f.size() > 1 && f[1] == rl::kFbBlockWonSetVersion,
          "PE6 the window-rule own win is a v0x03 frame with a 0-row delta + digest + pinned set");
        C(ok && back == bw, "PE6 it round-trips (delta empty, digest and set exact)");
        rl::BlockWon b0;
        C(!rl::decode_block_won(f, b0, nullptr, false), "PE6 a flip-0 decoder refuses it (gate OFF stays v0x01)");
    }

    // PE5 source pins
    const std::string sh = slurp(V37_XMR_SHELL_SRC);
    C(!sh.empty(), "PE5 shell source readable");
    C(sh.find("compose_lane_pinned(rgo->first, rgo->second, *lp, ids, &reg)") != std::string::npos,
      "PE5 the shell composes from the pinned set WITH the booking-point registry");
    C(sh.find("on_raindrop_id(a.id, ::v37::xmr::xmr_identity_key(a.r.payee)") == std::string::npos &&
      sh.find("(void)drops->on_raindrop_id(a.id, a.r.payee, a.bin, a.pow)") != std::string::npos,
      "PE5 every live raindrop is fed with its receipt id AND its ref");
    C(sh.find("const auto oc = composed_order_check(a0, served, own_is_prefix);") != std::string::npos &&
      sh.find("composed_order_check(a0, ent, base == nullptr && a0 > 0)") != std::string::npos &&
      sh.find("relay::check_composed_order(") != std::string::npos &&
      sh.find("relay::check_composed_order(") == sh.rfind("relay::check_composed_order("),
      "PE5 ONE composed-order rule: the replay and the DROPS prefix composition both ask composed_order_check");
    C(sh.find("wire_witness(lane.carry)") != std::string::npos && sh.find("wire_witness(drops_lane.carry)") != std::string::npos,
      "PE5 the own-win and early carries bound the WIRE witness only (gap 3)");

    std::printf("v37_xmr_drops_pin_enrol_kat: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
