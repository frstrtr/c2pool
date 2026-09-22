// v37_rb_map_churn_kat — S3 churn + bounded-load MEASUREMENT (prints numbers).
//
// Real-unit simulation on the BTC candidate gate (H_ref = 86 PH/s, 600 s bins,
// 144-bin map period => T = 86400 s, S = 256, eps = 1/4, delta = 1/8). A
// population of 3000 honest identities (heavy-tailed hashrates, total scaled
// to 600 PH/s => k = 4 at steady state) is driven through map periods. Each
// period: shares follow Map_e (n and assignment of the CURRENT map), the
// per-roundabout PoW-backed W_i is the work that landed on roundabout i, and
// Map_{e+1} = derive_map(Map_e, {W_i, h_obs}, gate). Churn is measured between
// consecutive maps with rb_map.hpp churn().
//
// Scenarios: (a) power-of-two crossings (±10% multiplicative walk per period)
//            (b) join/leave (5% of identities replaced per period)
//            (c) split 4->8 and merge 8->4 (total ramps up, then down)
//            (d) adversarial weight churn: 8.7-17% of hashrate on ground identities
//                whose stripes ALL home at roundabout 0, oscillating x1 / x2
//                every period, measured at eps = 1/8, 1/4, 1/2.
//
// Hard checks (non-hollow): every move is explained by an override
// (moved <= |ovr_prev| + |ovr_next|), final max load <= cap whenever every
// stripe fit, honest scenarios never hit an unfit stripe, split/merge happen
// when the ramp says they must, determinism of the whole run.
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <vector>

#include <c2pool/v37/roundabout/rb_map.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::ok;

static constexpr u64 PH = 1000000000000000ull;   // 1 PH/s in H/s
static constexpr u64 TH = 1000000000000ull;

struct Agg {
    const char* name;
    int periods = 0;
    double stripes = 0, n_changes = 0, compared = 0, moved = 0, created = 0, removed = 0;
    double moved_load_ppm = 0, ovr = 0, home_ppm = 0, final_ppm = 0;
    std::size_t unfit = 0, max_moved = 0;
    bool explained = true, capped = true;
    void add(const ChurnStats& c, const DeriveReport& r, std::size_t ovr_prev, std::size_t ovr_next) {
        ++periods;
        stripes += double(r.stripes);
        n_changes += double(c.n_changes);
        compared += double(c.compared);
        moved += double(c.moved);
        created += double(c.created);
        removed += double(c.removed);
        moved_load_ppm += c.total_load ? double(u128(c.moved_load * 1000000u / c.total_load)) : 0.0;
        ovr += double(r.overridden);
        home_ppm += double(max_over_mean_ppm(r.load_home));
        final_ppm += double(max_over_mean_ppm(r.load_final));
        unfit += r.unfit;
        max_moved = std::max(max_moved, c.moved);
        if (c.moved > ovr_prev + ovr_next) explained = false;
        if (r.unfit == 0)
            for (u128 l : r.load_final) if (l > r.cap) capped = false;
    }
    void print() const {
        const double p = periods ? periods : 1;
        std::printf("   CHURN %-34s periods=%d stripes=%.0f n_chg/p=%.1f moved/p=%.2f (%.3f%% of compared, max %zu) "
                    "moved_load=%.0f ppm created/p=%.1f removed/p=%.1f overrides/p=%.1f "
                    "max/mean home=%.4f final=%.4f unfit=%zu\n",
                    name, periods, stripes / p, n_changes / p, moved / p,
                    compared ? 100.0 * moved / compared : 0.0, max_moved, moved_load_ppm / p,
                    created / p, removed / p, ovr / p, home_ppm / p / 1e6, final_ppm / p / 1e6, unfit);
    }
};

struct Sim {
    RoundaboutGate g;
    Map map;
    std::map<bytes32, u64> rate;       // H/s
    std::set<bytes32> adversary;
    rbkat::SplitMix64 rng;
    Sim(const RoundaboutGate& gg, std::uint64_t seed) : g(gg), map(genesis_map(0)), rng(seed) {}

    u64 draw_rate() {
        // heavy tail: 70% 20-200 TH, 25% 0.2-1 PH, 5% 1-5 PH
        const u64 c = rng.below(100);
        if (c < 70) return 20 * TH + rng.below(180 * TH);
        if (c < 95) return 200 * TH + rng.below(800 * TH);
        return 1 * PH + rng.below(4 * PH);
    }
    void populate(int n) { for (int i = 0; i < n; ++i) rate[rng.key()] = draw_rate(); }
    u128 honest_total() const {
        u128 t = 0;
        for (const auto& [k, r] : rate) if (!adversary.count(k)) t += r;
        return t;
    }
    void scale_honest_to(u128 target) {
        const u128 t = honest_total();
        if (t == 0) return;
        for (auto& [k, r] : rate)
            if (!adversary.count(k)) r = static_cast<u64>(u128(r) * target / t);
    }

    // One map period. Returns churn(Map_e, Map_{e+1}).
    ChurnStats step(DeriveReport& rep, std::size_t& ovr_prev, std::size_t& ovr_next,
                    bool honest_only_churn = false) {
        const u128 T = g.period_seconds();
        PeriodInput in;
        in.W_by_rb.assign(map.k(), u128(0));
        std::map<bytes32, u128> work;
        std::vector<bytes32> ids;
        for (const auto& [k, r] : rate) {
            const u128 h = u128(r) * T;
            work[k] = h;
            in.ids.push_back(IdWork{k, h});
            const std::uint32_t n = map.n_of(k);      // shares follow the CURRENT map
            for (std::uint32_t s = 0; s < n; ++s)
                *in.W_by_rb[map.assign(k, Stripe(s))] += stripe_load(h, n, Stripe(s));
            if (!honest_only_churn || !adversary.count(k)) ids.push_back(k);
        }
        Map nx = derive_map(map, in, g, &rep);
        ChurnStats c = churn(map, nx, work, ids);
        ovr_prev = map.overrides.size();
        ovr_next = nx.overrides.size();
        map = std::move(nx);
        return c;
    }
    void warm(int periods) {
        DeriveReport r; std::size_t a, b;
        for (int i = 0; i < periods; ++i) step(r, a, b);
    }
};

static RoundaboutGate btc() { return RoundaboutGate::btc_candidate(); }

int main() {
    std::printf("v37_rb_map_churn_kat  (BTC candidate: H_ref=86 PH/s, T=86400 s, S=256, eps=1/4, delta=1/8)\n");
    const int P = 30;

    // ── (a) power-of-two crossings ─────────────────────────────────────────
    Agg a{"(a) pow2 crossings +-10%/period"};
    {
        Sim s(btc(), 0xA11CE);
        s.populate(3000);
        s.scale_honest_to(u128(600) * PH);
        s.warm(6);
        ok(s.map.m == 2, "a0 steady state k = 4 at 600 PH/s");
        for (int e = 0; e < P; ++e) {
            for (auto& [k, r] : s.rate) r = static_cast<u64>(u128(r) * (90 + s.rng.below(21)) / 100);
            s.scale_honest_to(u128(600) * PH);
            DeriveReport rep; std::size_t op, on;
            ChurnStats c = s.step(rep, op, on);
            a.add(c, rep, op, on);
        }
        a.print();
        ok(a.explained, "a1 every moved stripe is explained by an override");
        ok(a.capped, "a2 final max load <= cap");
        ok(a.unfit == 0, "a3 no unfit stripe (honest)");
        ok(s.map.m == 2, "a4 k stays 4 (total held at 600 PH/s)");
    }

    // ── (b) join / leave ────────────────────────────────────────────────────
    Agg b{"(b) join/leave 5%/period"};
    {
        Sim s(btc(), 0xB0B);
        s.populate(3000);
        s.scale_honest_to(u128(600) * PH);
        s.warm(6);
        for (int e = 0; e < P; ++e) {
            std::vector<bytes32> keys;
            for (const auto& kv : s.rate) keys.push_back(kv.first);
            for (int i = 0; i < 150; ++i) s.rate.erase(keys[s.rng.below(keys.size())]);
            while (s.rate.size() < 3000) s.rate[s.rng.key()] = s.draw_rate();
            s.scale_honest_to(u128(600) * PH);
            DeriveReport rep; std::size_t op, on;
            ChurnStats c = s.step(rep, op, on);
            b.add(c, rep, op, on);
        }
        b.print();
        ok(b.explained, "b1 every moved stripe is explained by an override");
        ok(b.capped && b.unfit == 0, "b2 capped, no unfit");
    }

    // ── (c) split 4->8 then merge 8->4 ──────────────────────────────────────
    Agg cs{"(c) split 4->8 (split period)"}, cm{"(c) merge 8->4 (merge period)"}, cr{"(c) ramp periods (no k change)"};
    {
        Sim s(btc(), 0xC5C5);
        s.populate(3000);
        s.scale_honest_to(u128(600) * PH);
        s.warm(6);
        // split line at k=4: H/4 >= 2*86*(9/8) PH => total >= 774 PH/s
        const u64 ramp_up[] = {700, 760, 800, 820, 820, 820};
        // merge line at k=8: H/8 < 86*(7/8) PH => total < 602 PH/s
        const u64 ramp_dn[] = {700, 640, 600, 560, 560, 560};
        bool split_seen = false, merge_seen = false;
        std::size_t split_moved_in_family = 0;
        for (u64 tot : ramp_up) {
            s.scale_honest_to(u128(tot) * PH);
            const unsigned m0 = s.map.m;
            DeriveReport rep; std::size_t op, on;
            ChurnStats c = s.step(rep, op, on);
            if (s.map.m == m0 + 1) { split_seen = true; cs.add(c, rep, op, on); split_moved_in_family = c.renumbered; }
            else cr.add(c, rep, op, on);
        }
        ok(split_seen && s.map.m == 3, "c1 ramp to 800+ PH/s splits k 4->8");
        for (u64 tot : ramp_dn) {
            s.scale_honest_to(u128(tot) * PH);
            const unsigned m0 = s.map.m;
            DeriveReport rep; std::size_t op, on;
            ChurnStats c = s.step(rep, op, on);
            if (s.map.m + 1 == m0) { merge_seen = true; cm.add(c, rep, op, on); }
            else cr.add(c, rep, op, on);
        }
        ok(merge_seen && s.map.m == 2, "c2 ramp below 602 PH/s merges k 8->4");
        cs.print(); cm.print(); cr.print();
        std::printf("   CHURN (c) split: %zu stripes renumbered j->2j/2j+1 in-family (not moves)\n",
                    split_moved_in_family);
        ok(cs.explained && cm.explained && cr.explained, "c3 every cross-parent move is explained by an override");
        ok(cs.unfit == 0 && cm.unfit == 0 && cr.unfit == 0, "c4 no unfit stripe");
    }

    // ── (d) adversarial weight churn ────────────────────────────────────────
    // 40 ground identities whose stripes s < 8 ALL home at roundabout 0 under
    // m = 2 (grinding cost ~4^8 keys each). Each oscillates 1.3 PH/s (n = 4)
    // <-> 2.6 PH/s (n = 8) every period: 52 <-> 104 PH/s on one roundabout,
    // i.e. 8.7% .. 17% of the pool, all aimed at roundabout 0.
    std::vector<bytes32> ground;
    {
        rbkat::SplitMix64 gr(0x6121D);
        while (ground.size() < 40) {
            const bytes32 k = gr.key();
            bool all0 = true;
            for (Stripe t = 0; t < 8 && all0; ++t) all0 = rb_home(stripe_key(0, k, t), 2) == 0;
            if (all0) ground.push_back(k);
        }
    }
    const std::pair<std::uint32_t, std::uint32_t> eps_set[] = {{1, 8}, {1, 4}, {1, 2}};
    const char* eps_names[] = {"(d) adversary eps=1/8 (honest churn)", "(d) adversary eps=1/4 (honest churn)",
                               "(d) adversary eps=1/2 (honest churn)"};
    for (int ei = 0; ei < 3; ++ei) {
        RoundaboutGate g = btc();
        g.eps_num = eps_set[ei].first; g.eps_den = eps_set[ei].second;
        Agg d{eps_names[ei]};
        Sim s(g, 0xDEAD);
        s.populate(3000);
        s.scale_honest_to(u128(600) * PH);
        s.warm(6);
        const unsigned mA = s.map.m;
        ok(mA == 2, "d0 steady state k = 4 before the adversary");
        for (const auto& k : ground) { s.adversary.insert(k); s.rate[k] = 1300 * TH; }
        s.warm(2);
        for (int e = 0; e < P; ++e) {
            for (const auto& k : s.adversary) s.rate[k] = (e & 1) ? 1300 * TH : 2600 * TH;
            DeriveReport rep; std::size_t op, on;
            ChurnStats c = s.step(rep, op, on, /*honest_only_churn=*/true);
            d.add(c, rep, op, on);
        }
        d.print();
        ok(d.explained, "d1 every honest move is explained by an override");
        ok(d.capped, "d2 bounded-load cap holds under the adversary");
        ok(s.map.m == mA, "d3 adversary oscillation does not flip k");
    }

    // ── determinism of an entire run ───────────────────────────────────────
    {
        auto run = []() {
            Sim s(btc(), 0x5EED);
            s.populate(800);
            s.scale_honest_to(u128(500) * PH);
            s.warm(4);
            for (int e = 0; e < 5; ++e) {
                for (auto& [k, r] : s.rate) r = static_cast<u64>(u128(r) * (80 + s.rng.below(41)) / 100);
                DeriveReport rep; std::size_t a1, b1;
                s.step(rep, a1, b1);
            }
            return s.map.digest();
        };
        const bytes32 d1 = run(), d2 = run();
        ok(d1 == d2, "z1 two independent full simulations -> identical final map digest");
        std::printf("   final map digest %s\n", rbkat::hx(d1).c_str());
    }

    return rbkat::finish("v37_rb_map_churn_kat");
}
