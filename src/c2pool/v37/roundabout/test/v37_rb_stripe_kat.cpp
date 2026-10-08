// v37_rb_stripe_kat — S3 map-derivation library: stripe primitives + the
// structural properties of the pure map derivation.
//
//   A  stripe_key goldens (independent Python sha256d reference)
//   B  n(id) power-of-two law (integer, boundaries exact), stripe_load Σ
//   C  salt-free prefix stability: home_{m+1} >> 1 == home_m for every key
//   D  determinism: repeated + independently-ordered inputs -> identical map
//   E  split moves EXACTLY the parent's stripes (2j / 2j+1), no overrides
//   F  merge is the exact reverse
//   G  epoch-independence of placement (no salt anywhere)
//   H  trigger truth table (split/merge boundaries exact, hysteresis, k_max)
//   I  missing summaries decay then W = 0, never veto (epoch always advances)
//   J  OFF / ill-formed gate -> the k = 1 map
#include <algorithm>
#include <map>
#include <vector>

#include <c2pool/v37/roundabout/rb_map.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::fill;
using rbkat::hx;
using rbkat::ok;

// Test gate: H_ref = 2560 /s, T = 100 s => U = H_ref*T = 256000, per-stripe
// unit u*T = 1000 exactly (S = 256).
static RoundaboutGate tgate(std::uint32_t k_max = 64) {
    RoundaboutGate g = RoundaboutGate::candidate(2560, 1, 100, k_max);
    return g;
}
static RoundaboutGate no_overflow(RoundaboutGate g) {   // cap never binds
    g.eps_num = 65536; g.eps_den = 1;
    return g;
}

static Map map_at(ChainId c, unsigned m, MapEpoch e = 0) {
    Map mp = genesis_map(c);
    mp.m = m;
    mp.epoch = e;
    mp.last_W.assign(std::size_t(1) << m, 0);
    mp.missed.assign(std::size_t(1) << m, 0);
    return mp;
}

static std::vector<IdWork> population(std::uint64_t seed, int n, u64 maxw) {
    rbkat::SplitMix64 r(seed);
    std::vector<IdWork> v;
    for (int i = 0; i < n; ++i) v.push_back(IdWork{r.key(), u128(1 + r.below(maxw))});
    return v;
}

static PeriodInput input_with(u128 Wtotal, RbIndex k, std::vector<IdWork> ids) {
    PeriodInput in;
    for (RbIndex i = 0; i < k; ++i) in.W_by_rb.push_back(Wtotal / k + (i < Wtotal % k ? 1 : 0));
    in.ids = std::move(ids);
    return in;
}

int main() {
    std::printf("v37_rb_stripe_kat\n");

    // ── A: stripe_key goldens (py/ref.py sha256d('V37RB'||u32 c||id||u16 s)) ──
    {
        ok(hx(stripe_key(0, fill(0xA1), 0)) ==
               "0659174d171786d4913a3e27121c005b880a30f91a720d832d6c6395beaaeea5", "A1 stripe_key(0,A1,0)");
        ok(hx(stripe_key(0, fill(0xA1), 1)) ==
               "6a331044fd1a8c27310c9c9c0c9c4f1afa39e1b8b5cbcb5ef4f8de535bc5c860", "A2 stripe_key(0,A1,1)");
        ok(hx(stripe_key(7, fill(0xB2), 255)) ==
               "fd2798526891fda5175dbbf1b78ffe9e8b63932fd612a953cd6d550953b62fbd", "A3 stripe_key(7,B2,255)");
        ok(hx(stripe_key(0x01020304, fill(0x00), 65535)) ==
               "8a3de06d84cad149a50e867b3e6cd0a597a38d4fce709cd1a404bfc1cb736495", "A4 stripe_key(0x01020304,00,65535)");
        ok(stripe_key(0, fill(0xA1), 0) != stripe_key(1, fill(0xA1), 0), "A5 chain_id separates keys");
        // rb_home = top m bits: 0x06.. => m=1 ->0, m=4 -> 0x0, m=8 -> 0x06
        const bytes32 k0 = stripe_key(0, fill(0xA1), 0);
        ok(rb_home(k0, 0) == 0 && rb_home(k0, 8) == 0x06 && rb_home(k0, 12) == 0x065 &&
               rb_home(k0, 16) == 0x0659, "A6 rb_home = top m bits");
    }

    // ── B: n(id) law ───────────────────────────────────────────────────────
    {
        const RoundaboutGate g = tgate();
        ok(ref_work_per_period(g) == 256000, "B0 U = H_ref*T");
        struct Row { u128 h; std::uint32_t n; } rows[] = {
            {0, 1}, {1, 1}, {1000, 1}, {1001, 2}, {2000, 2}, {2001, 4}, {4000, 4},
            {4001, 8}, {128000, 128}, {128001, 256}, {256000, 256}, {~u128(0), 256}};
        bool all = true;
        for (const auto& r : rows) {
            const auto n = n_of(r.h, g);
            if (n != r.n) { all = false; std::printf("   n_of(%s)=%u want %u\n", rbkat::u128s(r.h).c_str(), n, r.n); }
        }
        ok(all, "B1 n = 2^ceil(log2(max(1,h/u))), capped at S, exact boundaries");
        // n changes ONLY on x2: every h in (1000*2^j, 1000*2^(j+1)] maps to one n.
        bool pow2 = true;
        for (u128 h = 1; h <= 70000; h += 37) { if (!is_pow2_u64(n_of(h, g))) pow2 = false; }
        ok(pow2, "B2 n is always a power of two");
        ok(n_of(5000000, RoundaboutGate{}) == 1, "B3 OFF gate -> n = 1");
        bool sum = true;
        for (u128 h : {u128(0), u128(1), u128(7), u128(1000), u128(999999), (u128(1) << 90) + 5})
            for (std::uint32_t n : {1u, 2u, 4u, 64u, 256u}) {
                u128 t = 0;
                for (std::uint32_t s = 0; s < n; ++s) t += stripe_load(h, n, Stripe(s));
                if (t != h) sum = false;
            }
        ok(sum, "B4 sum_s stripe_load == h_obs exactly");
    }

    // ── C: salt-free prefix stability ───────────────────────────────────────
    {
        rbkat::SplitMix64 r(0xC0FFEE);
        bool pref = true;
        for (int i = 0; i < 20000; ++i) {
            const bytes32 sk = stripe_key(3, r.key(), Stripe(r.below(256)));
            for (unsigned m = 0; m < 16; ++m)
                if ((rb_home(sk, m + 1) >> 1) != rb_home(sk, m)) pref = false;
        }
        ok(pref, "C1 home_{m+1}>>1 == home_m (20000 keys x 16 levels)");
    }

    const auto pop = population(0xD1D1, 400, 6000);   // n up to 8

    // ── D: determinism ──────────────────────────────────────────────────────
    {
        const RoundaboutGate g = tgate();
        const Map prev = map_at(5, 2, 10);
        const PeriodInput in = input_with(4 * 256000, 4, pop);
        DeriveReport r1, r2;
        const Map a = derive_map(prev, in, g, &r1);
        const Map b = derive_map(prev, in, g, &r2);
        // independent ordering + duplicates split in two entries summing to h
        PeriodInput in2 = in;
        std::vector<IdWork> ids2;
        for (const auto& w : in.ids) {
            const u128 h1 = w.h_obs / 3;
            ids2.push_back(IdWork{w.id_key, w.h_obs - h1});
            if (h1) ids2.push_back(IdWork{w.id_key, h1});
            ids2.push_back(IdWork{w.id_key, 0});
        }
        std::reverse(ids2.begin(), ids2.end());
        in2.ids = ids2;
        const Map c = derive_map(prev, in2, g);
        ok(a == b && a.digest() == b.digest(), "D1 repeated derivation byte-identical");
        ok(a == c && a.digest() == c.digest(), "D2 reordered/duplicated input -> identical map");
        ok(a.epoch == 11 && a.m == 2, "D3 epoch advances by 1, hold at m=2");
        std::printf("   D map digest %s  stripes=%zu overrides=%zu n>1 ids=%zu\n",
                    hx(a.digest()).c_str(), r1.stripes, a.overrides.size(), a.n.size());
        ok(r1.overridden == a.overrides.size(), "D4 report matches stored overrides");
    }

    // ── E: split moves exactly the parent's stripes ────────────────────────
    {
        const RoundaboutGate g = no_overflow(tgate());
        const Map prev = map_at(5, 2, 20);
        const Map par = derive_map(prev, input_with(4 * 256000, 4, pop), g);  // hold m=2
        const Map ch = derive_map(par, input_with(4 * 2 * 256000 * 9 / 8 + 8, 4, pop), g);
        ok(par.m == 2 && ch.m == 3, "E0 trigger split m 2->3");
        ok(par.overrides.empty() && ch.overrides.empty(), "E1 no overrides (cap not binding)");
        bool exact = true;
        std::map<RbIndex, std::size_t> parent_cnt, child_cnt;
        for (const auto& w : pop) {
            const std::uint32_t n = ch.n_of(w.id_key);
            for (std::uint32_t s = 0; s < n; ++s) {
                const RbIndex j = par.assign(w.id_key, Stripe(s));
                const RbIndex c = ch.assign(w.id_key, Stripe(s));
                if ((c >> 1) != j) exact = false;
                ++parent_cnt[j];
                ++child_cnt[c];
            }
        }
        bool part = true;
        for (RbIndex j = 0; j < 4; ++j)
            if (parent_cnt[j] != child_cnt[2 * j] + child_cnt[2 * j + 1]) part = false;
        ok(exact, "E2 every stripe of j lands in 2j or 2j+1");
        ok(part, "E3 child stripe sets partition exactly the parent's");
    }

    // ── F: merge is the reverse ────────────────────────────────────────────
    {
        const RoundaboutGate g = no_overflow(tgate());
        const Map prev = map_at(5, 3, 30);
        const Map big = derive_map(prev, input_with(8 * 256000, 8, pop), g);   // hold m=3
        const Map sm = derive_map(big, input_with(8 * 256000 * 7 / 8 - 8, 8, pop), g);
        ok(big.m == 3 && sm.m == 2, "F0 trigger merge m 3->2");
        bool rev = true;
        for (const auto& w : pop)
            for (std::uint32_t s = 0; s < sm.n_of(w.id_key); ++s)
                if (sm.assign(w.id_key, Stripe(s)) != (big.assign(w.id_key, Stripe(s)) >> 1)) rev = false;
        ok(rev, "F1 merged rb == old rb >> 1 for every stripe");
        // split(merge(x)) returns the original homes
        const Map again = derive_map(sm, input_with(4 * 2 * 256000 * 9 / 8 + 8, 4, pop), g);
        bool round = again.m == 3;
        for (const auto& w : pop)
            for (std::uint32_t s = 0; s < again.n_of(w.id_key); ++s)
                if (again.assign(w.id_key, Stripe(s)) != big.assign(w.id_key, Stripe(s))) round = false;
        ok(round, "F2 split(merge(map)) restores every stripe's roundabout");
    }

    // ── G: epoch independence (no salt) ─────────────────────────────────────
    {
        const RoundaboutGate g = tgate();
        const PeriodInput in = input_with(4 * 256000, 4, pop);
        const Map a = derive_map(map_at(5, 2, 4), in, g);
        const Map b = derive_map(map_at(5, 2, 999), in, g);
        ok(a.overrides == b.overrides && a.n == b.n && a.m == b.m, "G1 same inputs at different epochs -> same placement");
        ok(a.digest() != b.digest(), "G2 ...but the epoch is committed in map_digest");
    }

    // ── H: trigger truth table ─────────────────────────────────────────────
    {
        const RoundaboutGate g = tgate(8);
        const u128 U = 256000;
        // split iff H*8 >= 2*k*U*9 ; merge iff H*8 < k*U*7
        ok(trigger(2 * 1 * U * 9 / 8, 0, g) == +1, "H1 k=1 exactly at split line -> split");
        ok(trigger(2 * 1 * U * 9 / 8 - 1, 0, g) == 0, "H2 k=1 one below -> hold");
        ok(trigger(2 * 4 * U * 9 / 8, 2, g) == +1, "H3 k=4 at split line -> split");
        ok(trigger(4 * U * 7 / 8, 2, g) == 0, "H4 k=4 exactly at merge line -> hold (strict <)");
        ok(trigger(4 * U * 7 / 8 - 1, 2, g) == -1, "H5 k=4 one below merge line -> merge");
        ok(trigger(0, 0, g) == 0, "H6 m=0 never merges");
        ok(trigger(u128(1) << 100, 3, g) == 0, "H7 k=k_max never splits");
        // hysteresis: after a split at the split line each child sits at
        // >= H_ref*(1+delta) > merge line
        const u128 Hs = 2 * 2 * U * 9 / 8;
        ok(trigger(Hs, 1, g) == +1 && trigger(Hs, 2, g) == 0, "H8 post-split k holds (no flap)");
        // one step per period even when far above
        const Map m1 = derive_map(map_at(1, 0), input_with(u128(1) << 80, 1, {}), g);
        ok(m1.m == 1, "H9 one step per period");
    }

    // ── I: missing summaries ───────────────────────────────────────────────
    {
        RoundaboutGate g = tgate(8);
        g.miss_grace = 3;
        Map mp = map_at(9, 1, 0);
        // hold band at k=2: 448000 <= H < 1152000
        PeriodInput in;
        in.W_by_rb = {u128(600000), u128(400000)};
        DeriveReport r;
        mp = derive_map(mp, in, g, &r);
        ok(r.H_total == 1000000 && mp.m == 1, "I0 both present");
        in.W_by_rb = {u128(600000), std::nullopt};
        mp = derive_map(mp, in, g, &r);
        ok(r.H_total == 600000 + 200000 && mp.missed[1] == 1 && mp.m == 1, "I1 missing once -> halved");
        mp = derive_map(mp, in, g, &r);
        ok(r.H_total == 600000 + 100000 && mp.missed[1] == 2 && mp.m == 1, "I2 missing twice -> quartered");
        mp = derive_map(mp, in, g, &r);
        ok(mp.missed[1] == 3 && r.H_total == 600000 && mp.m == 1, "I3 missed G periods -> W = 0");
        ok(mp.epoch == 4, "I4 epoch advanced every period (never vetoed)");
        in.W_by_rb = {u128(600000)};       // shorter vector == missing tail
        mp = derive_map(mp, in, g, &r);
        ok(r.H_total == 600000 && mp.epoch == 5 && mp.missed[1] == 3, "I5 absent tail entry treated as missing");
        in.W_by_rb = {u128(600000), u128(500000)};
        mp = derive_map(mp, in, g, &r);
        ok(mp.missed[1] == 0 && r.H_total == 1100000 && mp.m == 1, "I6 summary returns -> counted again");
    }

    // ── J: OFF / ill-formed -> k = 1 ───────────────────────────────────────
    {
        const PeriodInput in = input_with(u128(1) << 90, 1, pop);
        const Map off = derive_map(genesis_map(2), in, RoundaboutGate{});
        ok(off.m == 0 && off.n.empty() && off.overrides.empty() && off.k() == 1, "J1 OFF gate -> k=1, no state");
        RoundaboutGate bad = tgate();
        bad.S = 255;
        const Map ill = derive_map(genesis_map(2), in, bad);
        ok(!bad.well_formed() && ill.m == 0 && ill.overrides.empty(), "J2 ill-formed gate -> k=1 fail-safe");
        bool zero = true;
        for (const auto& w : pop) if (off.assign(w.id_key, 0) != 0 || off.n_of(w.id_key) != 1) zero = false;
        ok(zero, "J3 OFF map assigns every id to roundabout 0 with n = 1");
    }

    return rbkat::finish("v37_rb_stripe_kat");
}
