// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_drops_wiring_kat — DROPS on the XMR lane: the live shell wiring.
//
// THE DEFECT. XmrNode carries the DROPS T3 seams and the XMR finalize driver
// composes compose_credit_replace() at every FOUND, but main_v37_xmr.cpp built
// no DropsWiring and called no seam, so after the operator flip every XMR node
// was gate-ON and DORMANT: harvester null, book null, price invalid — it
// converges and credits nobody. xmr/xmr_drops_wiring.hpp is what the shell now
// holds; this KAT proves the object and pins the shell's use of it.
//
//   X-SHELL    main_v37_xmr.cpp CONSTRUCTS the XMR bundle, ATTACHES it to the
//              node, feeds the TipBin from the native height watch (tip_best in
//              pump_tip — never a frontier), drains replicated raindrops into
//              the harvester, tees every pushed share into the share counter,
//              and hands the node the price at the booking cut. RED on the base:
//              the shell there wires none of it.
//   X-DORMANT  gate OFF is master: make() is nullptr in a default build and for
//              LaneParams{} in any build; the gate-ON geometry for_version(1)
//              builds the bundle only under the flip.
//   X-CLOCK    ★ the enrolment clock is the NATIVE TIP, not the burial
//              frontier: tip T -> open bin T+1 -> effective T+2; the frontier
//              handed to pre_harvest moves nothing; a lower tip (reorg) cannot
//              lower it; no tip -> REFUSED, never back-dated.
//   X-GEOM     the Monero difficulty test maps EXACTLY onto the fixed lz
//              geometry: lz(N) >= 32 <=> H * share_diff < 2^256, for random and
//              boundary hashes over several share_diffs.
//   X-PRICE    the rescaled WorkPrice prices ONE share of estimated work exactly
//              like ONE real share at the cut (fee model OFF and ON weights).
//   X-E2E      raindrops + share counts -> declare at the frontier -> take_buried
//              -> subthreshold_credit (the function XmrFinalizeDriver calls):
//              an enrolled drop-only payee is credited > 0, a non-enrolled one
//              gets nothing, and the composed total tracks the true work within
//              10% over 400 intervals (the unbiased E-2 Hhat_comb rule).
// ===========================================================================
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <fstream>
#include <functional>
#include <random>
#include <regex>
#include <sstream>
#include <string>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;
using ::v37::bytes32;

static int g_fail = 0, g_pass = 0;
static void check(bool ok, const char* what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what); }
    else    { ++g_fail; std::printf("  FAIL %s\n", what); }
}

// Independent oracle for the Monero share rule: H (LE 256-bit) * d < 2^256.
static bool meets_diff(const bytes32& h, std::uint64_t d) {
    if (d == 0) return false;
    unsigned __int128 carry = 0;
    for (int w = 0; w < 4; ++w) {
        std::uint64_t word = 0;
        for (int i = 0; i < 8; ++i) word |= static_cast<std::uint64_t>(h[static_cast<std::size_t>(w * 8 + i)]) << (8 * i);
        const unsigned __int128 p = static_cast<unsigned __int128>(word) * d + carry;
        carry = p >> 64;
    }
    return carry == 0;
}

// The four seams, recorded — the shape XmrNode exposes.
struct FakeNode {
    ::c2pool::v37n::DropHarvester* harvester = nullptr;
    const ::c2pool::v37n::EnrollmentBook* book = nullptr;
    std::function<void(std::uint64_t)> pre_harvest;
    std::function<st::WorkPrice()> price;
    void set_drop_harvester(::c2pool::v37n::DropHarvester* h) { harvester = h; }
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook* b) { book = b; }
    void set_pre_harvest(std::function<void(std::uint64_t)> f) { pre_harvest = std::move(f); }
    void set_drops_price_fn(std::function<st::WorkPrice()> f) { price = std::move(f); }
    // XmrNode::on_network_block_won's DROPS body, verbatim in shape.
    std::map<bytes32, long long> found(const ::v37::LaneParams& p, std::uint64_t won_height, std::uint64_t d_conf,
                                       std::size_t* rows_out = nullptr) {
        st::DropsCompose dctx;
        if (price) dctx.price = price();
        dctx.enrollment = book;
        std::vector<st::HarvestedReceipt> rows;
        if (harvester) {
            const std::uint64_t frontier = won_height > d_conf ? won_height - d_conf : 0;
            if (pre_harvest) pre_harvest(frontier);
            rows = harvester->take_buried(frontier);
        }
        if (rows_out) *rows_out = rows.size();
        return st::subthreshold_credit(p, rows, dctx);
    }
};

static bytes32 key(int i) { bytes32 k{}; k[0] = 0xA0; k[31] = static_cast<std::uint8_t>(i); return k; }
static bytes32 rand_hash(std::mt19937_64& rng) {
    bytes32 h{};
    for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(h.data() + w * 8, &v, 8); }
    return h;
}
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares, std::uint64_t rw) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares) * rw;   // SUM w_raw
    // << 62 (Q) into U256 limbs
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.sum_weight.v[2] = static_cast<std::uint64_t>(s >> 66);
    wp.valid = true;
    return wp;
}

static std::string slurp(const char* path) {
    std::ifstream in(path);
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

int main() {
    std::printf("v37_xmr_drops_wiring_kat (kDropsWiringArmed=%d, V37_XMR_SHELL_SRC=%s)\n",
                (int)::c2pool::v37n::kDropsWiringArmed, V37_XMR_SHELL_SRC);

    // ── X-SHELL ──────────────────────────────────────────────────────────
    std::printf("X-SHELL: main_v37_xmr.cpp wires the bundle\n");
    {
        const std::string src = slurp(V37_XMR_SHELL_SRC);
        check(!src.empty(), "the XMR shell source is readable");
        check(src.find("XmrDropsWiring::make(cfg.lane_params") != std::string::npos,
              "the shell CONSTRUCTS the XMR DropsWiring from the lane geometry (base: never)");
        check(src.find("drops->attach(node)") != std::string::npos,
              "the shell ATTACHES harvester + enrolment book + pre-harvest + price to XmrNode (base: harvester null)");
        check(src.find("drops->observe_native_tip(tip_best)") != std::string::npos,
              "★ the TipBin is fed from the NATIVE height watch (pump_tip's tip_best)");
        // Every clock feed names a TIP variable; none is fed a frontier.
        std::regex feed(R"(observe_native_tip\(([^)]*)\))");
        int feeds = 0, tip_feeds = 0;
        for (auto it = std::sregex_iterator(src.begin(), src.end(), feed); it != std::sregex_iterator(); ++it) {
            ++feeds;
            const std::string a = (*it)[1].str();
            if (a == "tip_best" || a == "best") ++tip_feeds;
        }
        check(feeds >= 2 && feeds == tip_feeds,
              "★ every observe_native_tip() call is fed a TIP (tip_best / best), never a burial frontier");
#ifdef C2POOL_XMR_DROPS_ENROL_TIDY
        // DROPS-ENROL-TIDY: enrolment + S are lane-derived; the tip book is retired.
        check(src.find("drops_try_enrol") == std::string::npos && src.find("drops->enroll_at_tip(") == std::string::npos &&
              src.find("drops->arm_at_tip(") == std::string::npos &&
              src.find("node.set_enrollment_book(nullptr);") != std::string::npos && src.find("drops->set_lane_only();") != std::string::npos,
              "★ no enrolment / arm at the native tip any more: the node gets NO tip book and the wiring is lane-only "
              "(enrolment is a pure function of the lane prefix)");
#else
        check(src.find("drops->observe_native_tip(tip_best); drops_try_enrol();") != std::string::npos &&
              src.find("if (!t.valid || !now_bin || *now_bin < t.height) return;") != std::string::npos &&
              src.find("if (!drops_tip_synced()) return;") != std::string::npos &&
              src.find("return drops_peer_height > 0 && nb && *nb >= drops_peer_height;") != std::string::npos,
              "★ enrolment + arm wait until the NATIVE tip clock has reached the served template's bin AND the "
              "best peer's height (READY is not at-the-tip: no enrolment against a half-synced index)");
#endif
        check(src.find("set_pre_harvest(") == std::string::npos,
              "the frontier reaches the bundle ONLY through attach()'s pre_harvest (no hand-rolled hook)");
        check(src.find("drops->on_raindrop(") != std::string::npos && src.find("drain_drops()") != std::string::npos,
              "replicated raindrops (own + peers') are drained into the harvester");
#ifdef C2POOL_XMR_DROPS_ENROL_TIDY
        check(src.find("drops->on_share_pushed(") == std::string::npos && src.find("drops->on_share_lane(") != std::string::npos,
              "every pushed share enters the lane-position log only (S is counted from the lane prefix; no node-local share book)");
#else
        check(src.find("drops->on_share_pushed(") != std::string::npos,
              "every pushed share is teed into the share counter (S is never UNKNOWN)");
#endif
        check(src.find("drops->set_cut_price(booking_price)") != std::string::npos,
              "the booking callback hands the node the WorkPrice at THIS cut");
        check(src.find("ro.drops_floor_diff = drops_live ? drops->floor_diff() : 0") != std::string::npos,
              "the relay receiver takes raindrops ONLY when the bundle is live (0 = master's receiver)");
    }

    // ── X-DORMANT ────────────────────────────────────────────────────────
    std::printf("X-DORMANT: gate OFF is master\n");
    {
        check(dx::XmrDropsWiring::make(::v37::LaneParams{}, 1024, 1) == nullptr,
              "LaneParams{} (gate OFF) -> nullptr in ANY build");
        const auto on = ::v37::LaneParams::for_version(1);
        check(on.subthreshold.enabled, "for_version(1) carries the DROPS gate");
        const bool built = dx::XmrDropsWiring::make(on, 1024, 1) != nullptr;
        check(built == ::c2pool::v37n::kDropsWiringArmed,
              "for_version(1) builds the bundle IFF the build took the flip (default build: nullptr)");
        check(dx::XmrDropsWiring::make(on, 0, 1) == nullptr || !::c2pool::v37n::kDropsWiringArmed,
              "no share difficulty -> nothing to normalise against -> nullptr");
    }

    // ── X-CLOCK ──────────────────────────────────────────────────────────
    std::printf("X-CLOCK: the enrolment clock is the NATIVE TIP, not the burial frontier\n");
    {
        auto w = dx::XmrDropsWiring::make_for_test(4, 1024, 1);
        FakeNode n;
        w->attach(n);
        check(n.harvester && n.book && n.pre_harvest && n.price, "attach() hands over all four seams");
        const bytes32 early = key(1), p = key(2), q = key(3);
        check(w->enroll_at_tip(early) == ::c2pool::v37n::EnrollOutcome::TipUnknown,
              "no tip yet -> enrolment REFUSED (never back-dated to genesis)");
        check(!w->arm_at_tip(), "no tip yet -> share-count book NOT armed");
        const std::uint64_t T = 3000, D_CONF = 10;
        w->observe_native_tip(T);
        check(w->now_interval() && *w->now_interval() == T + 1,
              "native tip T -> now = T+1 (the bin being drawn: an XMR event's bin is its TEMPLATE height)");
        // the frontier the node hands pre_harvest on a win at T: T - D_conf
        n.pre_harvest(T - D_CONF);
        check(*w->now_interval() == T + 1, "★ pre_harvest(frontier) does NOT move the ex-ante clock");
        check(w->enroll_at_tip(p) == ::c2pool::v37n::EnrollOutcome::Enrolled, "enrol at the tip");
        const auto* r = w->core().enrollment().find(p);
        check(r && r->effective_from == T + 2,
              "★ effective_from == tip+2: strictly after the open bin (NOT frontier+1)");
        check(r && r->effective_from != T - D_CONF + 1, "the frontier-sourced effective_from is NOT what was recorded");
        check(!w->core().enrollment().enrolled(p, T + 1) && w->core().enrollment().enrolled(p, T + 2),
              "not enrolled for the open bin, enrolled from the next one (ex ante)");
        w->observe_native_tip(T - 5);   // a reorg to a lower tip
        check(*w->now_interval() == T + 1, "a lower tip (reorg) cannot lower the clock (monotone)");
        w->observe_native_tip(T + 7);
        check(w->enroll_at_tip(q) == ::c2pool::v37n::EnrollOutcome::Enrolled &&
              w->core().enrollment().find(q)->effective_from == T + 9, "the clock follows the tip forward");
        check(w->enroll_at_tip(p) == ::c2pool::v37n::EnrollOutcome::AlreadyEnrolled &&
              w->core().enrollment().find(p)->effective_from == T + 2, "a re-enrolment cannot move the first commitment");
        // price is one-shot: a win not booked through a fold never reuses a price
        w->set_cut_price(price_of(1000000, 100, 1));
        check(n.price().valid, "the booked cut's price is handed over");
        check(!n.price().valid, "…exactly once (the next FOUND without a fold gets INVALID = credits zero)");
    }

    // ── X-GEOM ───────────────────────────────────────────────────────────
    std::printf("X-GEOM: the difficulty test maps exactly onto lz=%u\n", dx::kXmrDropsLz);
    {
        std::mt19937_64 rng(0x5eedULL);
        int mism = 0, n = 0;
        for (std::uint64_t sd : {1ULL, 2ULL, 3ULL, 16ULL, 1000ULL, 1024ULL, 120000ULL, 4294967295ULL}) {
            for (int i = 0; i < 20000; ++i) {
                bytes32 h = rand_hash(rng);
                // bias half the samples to the boundary region
                if (i & 1) { for (int b = 31; b >= 24; --b) h[static_cast<std::size_t>(b)] = 0; h[23] = static_cast<std::uint8_t>(rng() & 0x3f); }
                const bool share = ::c2pool::v37n::leading_zero_bits(dx::normalized_hash(h, sd)) >= dx::kXmrDropsLz;
                if (share != meets_diff(h, sd)) ++mism;
                ++n;
            }
            // exact boundary: H = ceil(2^256/sd) - 1 is the largest share, +1 is not
            if (sd > 1) {
                // q = floor((2^256 - 1) / sd)
                std::array<std::uint64_t, 4> q{}; unsigned __int128 rem = 0;
                for (int wi = 3; wi >= 0; --wi) { const unsigned __int128 cur = (rem << 64) | ~0ULL; q[static_cast<std::size_t>(wi)] = static_cast<std::uint64_t>(cur / sd); rem = cur % sd; }
                auto to_le = [](const std::array<std::uint64_t, 4>& v) { bytes32 b{}; for (int wi = 0; wi < 4; ++wi) std::memcpy(b.data() + wi * 8, &v[static_cast<std::size_t>(wi)], 8); return b; };
                const bytes32 hq = to_le(q);
                auto q1 = q; for (int wi = 0; wi < 4; ++wi) { if (++q1[static_cast<std::size_t>(wi)]) break; }
                const bytes32 hq1 = to_le(q1);
                const bool a = ::c2pool::v37n::leading_zero_bits(dx::normalized_hash(hq, sd)) >= dx::kXmrDropsLz;
                const bool b = ::c2pool::v37n::leading_zero_bits(dx::normalized_hash(hq1, sd)) >= dx::kXmrDropsLz;
                if (a != meets_diff(hq, sd) || b != meets_diff(hq1, sd)) ++mism;
                n += 2;
            }
        }
        std::printf("       %d hashes, %d mismatches\n", n, mism);
        check(mism == 0, "lz(normalized_hash(H, d)) >= 32  <=>  H * d < 2^256  (random + boundary, 8 difficulties)");
        check(dx::drops_floor_diff(1) == 1 && dx::drops_floor_diff(64) == 1 && dx::drops_floor_diff(6400) == 100,
              "raindrop floor = max(1, share_diff / 64)");
    }

    // ── X-PRICE ──────────────────────────────────────────────────────────
    std::printf("X-PRICE: one share of estimated work prices like one real share\n");
    {
        for (std::uint64_t rw : {1ULL, 65535ULL}) {
            const std::uint64_t reward = 600000000000ULL, n = 1000;
            const st::WorkPrice raw = price_of(reward, n, rw);
            const st::WorkPrice sc = dx::rescale_price(raw, rw);
            ::c2pool::v37::subthreshold::u320 one_share{}; one_share.w[0] = 1ULL << dx::kXmrDropsLz;
            const long long e = st::entitlement_of_work(sc, one_share);
            const long long want = static_cast<long long>(reward / n);
            char msg[160];
            std::snprintf(msg, sizeof msg, "receipt weight %llu: 2^lz estimated attempts -> %lld piconero == reward/SUM-shares %lld",
                          (unsigned long long)rw, e, want);
            check(e == want, msg);
        }
        check(!dx::rescale_price(st::WorkPrice{}, 1).valid, "an invalid price stays invalid (credits zero)");
    }

    // ── X-E2E ────────────────────────────────────────────────────────────
    std::printf("X-E2E: raindrops + share counts -> declare -> take_buried -> subthreshold_credit\n");
    {
        const auto params = ::v37::LaneParams::for_version(1);
        const std::uint64_t sd = 1024, reward = 600000000000ULL, n_sum = 1000, D_CONF = 10;
        auto w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, sd, 1);
        FakeNode node;
        w->attach(node);
        const std::uint64_t T0 = 5000;
        w->observe_native_tip(T0);
        const bytes32 A = key(10) /*enrolled*/, B = key(11) /*NOT enrolled*/;
        w->enroll_at_tip(A);
        w->arm_at_tip();
        std::mt19937_64 rng(0xD20B5ULL);
        const std::uint64_t floor = dx::drops_floor_diff(sd);
        double true_shares_A = 0;
        std::uint64_t sharesA = 0, dropsA = 0;
        long long credited_A = 0, credited_B = 0, rows_total = 0;
        std::uint64_t first_iv = T0 + 2, last_iv = T0 + 2 + 400;
        for (std::uint64_t iv = T0 + 1; iv < last_iv; ++iv) {
            w->observe_native_tip(iv - 1);       // the tip moves: bin iv is open
            for (const bytes32& who : {A, B}) {
                const int attempts = 700;         // ~0.68 share expected per interval
                for (int k = 0; k < attempts; ++k) {
                    const bytes32 h = rand_hash(rng);
                    if (meets_diff(h, sd)) { w->on_share_pushed(who, iv); if (who == A && iv >= first_iv) ++sharesA; }
                    else if (meets_diff(h, floor)) { w->on_raindrop(who, iv, h); if (who == A) ++dropsA; }
                }
                if (who == A && iv >= first_iv) true_shares_A += static_cast<double>(attempts) / static_cast<double>(sd);
            }
            // a lane block won at height iv + D_CONF settles every interval below iv
            w->set_cut_price(price_of(reward, n_sum, 1));
            std::size_t rows = 0;
            const auto delta = node.found(params, iv + D_CONF, D_CONF, &rows);
            rows_total += static_cast<long long>(rows);
            if (auto it = delta.find(A); it != delta.end()) credited_A += it->second;
            if (auto it = delta.find(B); it != delta.end()) credited_B += it->second;
        }
        // flush the tail
        w->set_cut_price(price_of(reward, n_sum, 1));
        { const auto delta = node.found(params, last_iv + 2 * D_CONF, D_CONF);
          if (auto it = delta.find(A); it != delta.end()) credited_A += it->second;
          if (auto it = delta.find(B); it != delta.end()) credited_B += it->second; }
        const auto s = w->core().stats();
        const double per_share = static_cast<double>(reward / n_sum);
        // E_b pays A's real shares at per_share each; the delta REPLACES that with Hhat.
        const double composed_shares = static_cast<double>(sharesA) + static_cast<double>(credited_A) / per_share;
        std::printf("       raindrops harvested=%llu (A %llu) rows=%lld withheld=%llu declared=%llu | A: shares=%llu true=%.1f "
                    "composed=%.1f (delta %lld) | B delta %lld\n",
                    (unsigned long long)s.harvested, (unsigned long long)dropsA, rows_total, (unsigned long long)s.withheld,
                    (unsigned long long)s.declared, (unsigned long long)sharesA, true_shares_A, composed_shares, credited_A, credited_B);
        check(s.harvested > 0 && rows_total > 0, "raindrops are harvested and released as buried rows");
        check(credited_A > 0, "★ an ENROLLED payee receives sub-threshold credit > 0 (not dormant)");
        check(credited_B == 0, "a NOT-enrolled payee receives nothing (R-SYBIL)");
        const double rel = composed_shares / true_shares_A - 1.0;
        check(rel > -0.10 && rel < 0.10, "E_b shares + DROPS delta tracks A's TRUE work within 10% (unbiased Hhat_comb)");
        check(s.withheld == 0 || s.withheld < s.declared, "intervals are declared, not withheld (S is known)");
    }

    std::printf("v37_xmr_drops_wiring_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "RED" : "GREEN");
    return g_fail ? 1 : 0;
}
