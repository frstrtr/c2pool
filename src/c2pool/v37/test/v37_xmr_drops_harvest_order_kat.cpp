// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_harvest_order_kat -- RAIN-BACKFILL-2 (DROPS defect 3, harvest
// order).
//
// The harvest of an XMR lane block won at h must be a PURE function of the
// canonical chain: range(h) = [frontier(prev_lane(h)), frontier(h)) with
// prev_lane(h) the lane block the canonical chain carries nearest below h and
// frontier(x) = x - D_conf. The first RAIN-BACKFILL derived lo from the marks
// THIS node had set while booking and erased every mark at or above a
// re-booking; a node that booked canonical h+1 BEFORE canonical h during a
// reorg (measured on the rig: 138 before 137) lost the mark of h+1 and composed
// h+2 over [frontier(h), frontier(h+2)) -- interval frontier(h) harvested twice
// -- while every in-order node composed [frontier(h+1), frontier(h+2)).
//
// Two XmrDropsWiring bundles (the XmrNode seam shape) fed the SAME raindrops +
// share counts over intervals 1002..1059; a canonical lane chain 1020..1060
// with two non-lane heights (1027, 1041):
//
//   O1  IN ORDER: node Y books the canonical chain in order; every range is
//       the expected [frontier(prev_lane), frontier(h)) and the ranges tile
//       the intervals once each
//   O2  OUT OF ORDER: node X books canonical blocks out of order (h+1 before
//       h at four places, the rig's 138-before-137 shape) and two siblings the
//       chain replaces (1024' then canonical 1025 then canonical 1024; 1040');
//       the LAST booking of every canonical height on X composes exactly Y's
//       rows + credit (0 differing blocks)
//   O3  NO DOUBLE HARVEST: summed over the canonical chain, X and Y harvest
//       every (payee, interval) exactly once (= the rows over the union)
//   O4  THE RIG SHAPE, literally: sibling 137', canonical 138, canonical 137,
//       then 139 -> 139 composes [frontier(138), frontier(139)) (1 interval),
//       never [frontier(137), frontier(139)) (2 intervals)
//
// RED on the base (#1773 + the first RAIN-BACKFILL: marks-derived ranges; or
// #1773 alone: take_buried() consumes in booking order); GREEN on the fix.
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>   // C2POOL_XMR_RAIN_BACKFILL (the first slice's marker)
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

using namespace gap2test;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;

static constexpr std::uint64_t kD = 10;

// the XmrNode seam shape (buried_harvest), both arms
struct HNode {
    ::c2pool::v37n::DropHarvester* harvester = nullptr;
    const ::c2pool::v37n::EnrollmentBook* book = nullptr;
    std::function<void(std::uint64_t)> pre_harvest;
    std::function<st::WorkPrice()> price;
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester* h) { harvester = h; }
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook* b) { book = b; }
    void set_pre_harvest(std::function<void(std::uint64_t)> f) { pre_harvest = std::move(f); }
    void set_drops_price_fn(std::function<st::WorkPrice()> f) { price = std::move(f); }
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
    std::vector<st::HarvestedReceipt> harvest(std::uint64_t won) {
        if (!harvester) return {};
        if (range) return range(won);
        const std::uint64_t frontier = won > kD ? won - kD : 0;
        if (pre_harvest) pre_harvest(frontier);
        return harvester->take_buried(frontier);
    }
};

static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares);
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return wp;
}

struct Booked {
    std::size_t rows = 0;
    std::string key;                                   // rows + credit
    std::set<std::pair<std::string, std::uint64_t>> cells;   // (payee, interval)
    std::uint64_t lo = 0, hi = 0;
    bool has_range = false;
};

struct Harness {
    std::unique_ptr<dx::XmrDropsWiring> w;
    HNode node;
    ::v37::LaneParams params = ::v37::LaneParams::for_version(1);
    const std::set<std::uint64_t>* lanes;   // the CANONICAL chain's lane heights
    explicit Harness(const std::vector<bytes32>& enrol, const std::set<std::uint64_t>* canon) : lanes(canon) {
        w = dx::XmrDropsWiring::make_for_test(params.subthreshold.K, 1024, 1);
        w->attach(node);
#if defined(C2POOL_XMR_RAIN_BACKFILL)
        w->attach_chain_order(node, kD);
#endif
#if defined(C2POOL_XMR_HARVEST_CHAIN_PURE)
        // the canonical chain's answer (the shell walks the best chain's block ids)
        w->set_prev_lane_fn([this](std::uint64_t h) -> std::optional<std::uint64_t> {
            auto it = lanes->lower_bound(h);
            if (it == lanes->begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
            return *std::prev(it);
        });
#endif
        w->observe_native_tip(1000);
        for (const auto& p : enrol) w->enroll_at_tip(p);
        w->arm_at_tip();
    }
    Booked book(std::uint64_t won) {
        w->set_cut_price(price_of(600000000000ULL, 1000));
        const auto rows = node.harvest(won);
        st::DropsCompose dctx; dctx.price = node.price ? node.price() : st::WorkPrice{}; dctx.enrollment = node.book;
        Booked b;
        b.rows = rows.size();
        b.key = std::to_string(rows.size()) + ":";
        for (const auto& r : rows) {
            b.key += hex(r.payee).substr(0, 8) + "@" + std::to_string(r.interval) + ",";
            b.cells.emplace(hex(r.payee), r.interval);
        }
        b.key += "|";
        for (const auto& [k, v] : st::subthreshold_credit(params, rows, dctx)) b.key += hex(k).substr(0, 8) + "=" + std::to_string(v) + ",";
#if defined(C2POOL_XMR_RAIN_BACKFILL)
        const auto cs = w->chain_stats();
        b.lo = cs.lo; b.hi = cs.hi; b.has_range = true;
#endif
        return b;
    }
};

static void feed(Harness& h, const bytes32& P, const bytes32& Q) {
    std::mt19937_64 rng(0x0DDE12ULL);
    for (std::uint64_t iv = 1002; iv < 1060; ++iv) {
        h.w->observe_native_tip(iv - 1);
        for (const bytes32& who : {P, Q}) {
            for (int k = 0; k < 24; ++k) {
                bytes32 hsh{};
                for (int wd = 0; wd < 4; ++wd) { const std::uint64_t v = rng(); std::memcpy(hsh.data() + wd * 8, &v, 8); }
                hsh[31] = static_cast<std::uint8_t>(1 + (hsh[31] % 15));   // a raindrop at share_diff 1024
                h.w->on_raindrop(who, iv, hsh);
            }
            if ((iv + (who == P ? 0 : 1)) % 3 == 0) h.w->on_share_pushed(who, iv);
        }
    }
    h.w->observe_native_tip(1070);
}

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_harvest_order_kat (chain-pure harvest %s) ==\n",
#if defined(C2POOL_XMR_HARVEST_CHAIN_PURE)
                "present"
#elif defined(C2POOL_XMR_RAIN_BACKFILL)
                "ABSENT: marks-derived ranges (first RAIN-BACKFILL)"
#else
                "ABSENT: take_buried() only"
#endif
    );
    const bytes32 P = ::v37::xmr::xmr_identity_key(payee_of("A")), Q = ::v37::xmr::xmr_identity_key(payee_of("B"));

    std::set<std::uint64_t> canon;
    for (std::uint64_t h = 1020; h <= 1060; ++h) if (h != 1027 && h != 1041) canon.insert(h);
    auto frontier = [](std::uint64_t h) { return h > kD ? h - kD : 0; };
    auto expected = [&](std::uint64_t h) {
        auto it = canon.lower_bound(h);
        const std::uint64_t lo = it == canon.begin() ? 0 : frontier(*std::prev(it));
        return std::make_pair(lo, frontier(h));
    };

    // ── O1 in order ──────────────────────────────────────────────────────────
    Harness Y({P, Q}, &canon);
    feed(Y, P, Q);
    std::map<std::uint64_t, Booked> ybook;
    for (std::uint64_t h : canon) ybook[h] = Y.book(h);
    {
        std::size_t bad = 0, cmp = 0;
        for (const auto& [h, b] : ybook) {
            if (!b.has_range) continue;
            ++cmp;
            if (std::make_pair(b.lo, b.hi) != expected(h)) {
                ++bad;
                if (bad <= 3) std::printf("    Y h=%llu range [%llu,%llu) want [%llu,%llu)\n", (unsigned long long)h, (unsigned long long)b.lo,
                                          (unsigned long long)b.hi, (unsigned long long)expected(h).first, (unsigned long long)expected(h).second);
            }
        }
        std::printf("    O1 in-order node: %zu canonical blocks, %zu ranges compared, %zu off the canonical formula\n", ybook.size(), cmp, bad);
        C(ybook.size() == canon.size() && ybook[1030].rows > 0, "O1 the in-order node composes every canonical block, non-trivially");
        C(cmp == canon.size() && bad == 0,
          "O1 every in-order range == [frontier(prev canonical lane block), frontier(h)) (the non-lane heights 1027/1041 fold into the next)");
    }

    // ── O2 out of order + siblings ───────────────────────────────────────────
    Harness X({P, Q}, &canon);
    feed(X, P, Q);
    std::map<std::uint64_t, Booked> xlast;   // the last booking at every height (the canonical one)
    {
        // h+1 before h at four places (the rig's 138-before-137 shape), and two
        // siblings the chain replaces (1024' before 1025, 1040' before 1040)
        const std::set<std::uint64_t> deferred = {1024, 1035, 1048, 1052};
        std::vector<std::uint64_t> seq;
        for (std::uint64_t h : canon) {
            if (deferred.count(h)) continue;
            seq.push_back(h);
            if (deferred.count(h - 1)) seq.push_back(h - 1);
        }
        std::size_t ooo = 0;
        for (std::size_t i = 1; i < seq.size(); ++i) if (seq[i] < seq[i - 1]) ++ooo;
        for (std::uint64_t h : seq) {
            if (h == 1025) (void)X.book(1024);   // X's own sibling 1024', replaced by the chain
            if (h == 1040) (void)X.book(1040);   // a sibling 1040', replaced by the canonical 1040
            xlast[h] = X.book(h);
        }
        std::size_t differ = 0, range_differ = 0;
        for (std::uint64_t h : canon) {
            const auto& a = xlast[h]; const auto& b = ybook[h];
            if (a.key != b.key) {
                ++differ;
                if (differ <= 4) std::printf("    DIFF h=%llu X rows=%zu [%llu,%llu) vs Y rows=%zu [%llu,%llu)\n", (unsigned long long)h, a.rows,
                                             (unsigned long long)a.lo, (unsigned long long)a.hi, b.rows, (unsigned long long)b.lo, (unsigned long long)b.hi);
            }
            if (a.has_range && (a.lo != b.lo || a.hi != b.hi)) ++range_differ;
        }
        std::printf("    O2 out-of-order node: %zu bookings (%zu out of order, 2 siblings), %zu canonical blocks compared, %zu differ in rows+credit, %zu in range\n",
                    seq.size() + 2, ooo, canon.size(), differ, range_differ);
        C(ooo >= 4, "O2 the booking sequence really is out of order (h+1 before h at 4 places)");
        C(differ == 0 && range_differ == 0,
          "O2 ★ every canonical block composes the SAME rows + credit + range on the out-of-order node as on the in-order node");
    }

    // ── O3 no double harvest along the canonical chain ───────────────────────
    {
        auto total = [&](const std::map<std::uint64_t, Booked>& m, std::size_t& dup) {
            std::set<std::pair<std::string, std::uint64_t>> seen;
            std::size_t n = 0; dup = 0;
            for (std::uint64_t h : canon) for (const auto& c : m.at(h).cells) { ++n; if (!seen.insert(c).second) ++dup; }
            return n;
        };
        std::size_t dx_ = 0, dy_ = 0;
        const std::size_t tx = total(xlast, dx_), ty = total(ybook, dy_);
        // union: every (payee, interval) with a raindrop in [1002, frontier(1060)) -- two payees, every interval
        const std::size_t want = 2 * (frontier(1060) - 1002);
        std::printf("    O3 cells harvested along the canonical chain: X=%zu (dup %zu) Y=%zu (dup %zu) want %zu\n", tx, dx_, ty, dy_, want);
        C(ty == want && dy_ == 0, "O3 the in-order node harvests every (payee, interval) exactly once");
        C(tx == want && dx_ == 0, "O3 ★ the out-of-order node harvests every (payee, interval) exactly once (no interval twice, none skipped)");
    }

    // ── O4 the rig's literal shape (137' / 138 / 137 / 139) ─────────────────
    {
        std::set<std::uint64_t> c2;
        for (std::uint64_t h = 1030; h <= 1045; ++h) c2.insert(h);
        Harness A({P, Q}, &c2), B({P, Q}, &c2);
        feed(A, P, Q); feed(B, P, Q);
        for (std::uint64_t h = 1030; h <= 1036; ++h) { (void)A.book(h); (void)B.book(h); }
        (void)A.book(1037);                 // A's own sibling 137'
        const Booked a138 = A.book(1038);   // canonical 138 BEFORE canonical 137
        const Booked a137 = A.book(1037);   // canonical 137
        const Booked a139 = A.book(1039);
        const Booked b137 = B.book(1037), b138 = B.book(1038), b139 = B.book(1039);
        std::printf("    O4 A: 138 rows=%zu [%llu,%llu) 137 rows=%zu [%llu,%llu) 139 rows=%zu [%llu,%llu) | B: 137 rows=%zu 138 rows=%zu 139 rows=%zu [%llu,%llu)\n",
                    a138.rows, (unsigned long long)a138.lo, (unsigned long long)a138.hi, a137.rows, (unsigned long long)a137.lo,
                    (unsigned long long)a137.hi, a139.rows, (unsigned long long)a139.lo, (unsigned long long)a139.hi, b137.rows, b138.rows,
                    b139.rows, (unsigned long long)b139.lo, (unsigned long long)b139.hi);
        C(a137.key == b137.key && a138.key == b138.key, "O4 canonical 137 and 138 compose identically on A (138 booked first) and B");
        C(a139.key == b139.key && (!a139.has_range || (a139.lo == frontier(1038) && a139.hi == frontier(1039))),
          "O4 ★ 139 composes [frontier(138), frontier(139)) on A exactly as on B -- never [frontier(137), frontier(139))");
    }

    return C.done("v37_xmr_drops_harvest_order_kat");
}
