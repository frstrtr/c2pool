// V37 MRR roundabout — standalone unit tests, ORIGIN-BIN temporal model.
// (no gtest; tiny CHECK harness — compiles with nothing but g++ -std=c++20)
//
// The consensus gate: ReferenceLane is an INDEPENDENT implementation of the
// origin-bin lane definition whose per-miner weights are recomputed by full
// scan over the durable records after every operation; the fast incremental
// Lane must match it bit-exact, every push, across epoch rebuilds, bin-band
// folds, and time-window evictions.

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "../v37_descriptor.hpp"
#include "../v37_lane.hpp"
#include "../v37_roundabout.hpp"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                    \
    } while (0)

#define CHECK_MSG(cond, fmt, ...)                                            \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::printf("FAIL %s:%d: " fmt "\n", __FILE__, __LINE__,         \
                        __VA_ARGS__);                                        \
        }                                                                    \
    } while (0)

using namespace v37;

struct XorShift64 {
    u64 s;
    explicit XorShift64(u64 seed) : s(seed ? seed : 0x9e3779b97f4a7c15ull) {}
    u64 next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s;
    }
    u64 range(u64 lo, u64 hi) { return lo + next() % (hi - lo + 1); }
};

static bytes32 test_key(MinerId m) {
    std::uint8_t b[4] = {
        static_cast<std::uint8_t>(m), static_cast<std::uint8_t>(m >> 8),
        static_cast<std::uint8_t>(m >> 16), static_cast<std::uint8_t>(m >> 24)};
    return sha256d(b, 4);
}

// ── ReferenceLane: independent naive origin-bin implementation ────────────
struct ReferenceLane {
    LaneParams p;
    DecayTables tab;
    bool started = false;
    u64 t = 0, B = 0, events = 0;
    std::map<u64, OpenBin> open;
    std::vector<std::deque<Bucket>> levels;

    explicit ReferenceLane(const LaneParams& pp) : p(pp) {
        tab.init(p.half_life, p.epoch_bins,
                 p.epoch_bins + p.fine_bins + p.n_ctx + 2,
                 p.window_bins / p.epoch_bins + 4);
        levels.resize(p.level_caps.size());
    }

    u128 scaled_for(u64 w, u64 bin) const {
        return (bin >= B) ? u128(w) * tab.inv_decay[bin - B]
                          : u128(w) * tab.decay[B - bin];
    }

    void push(MinerId m, u64 w, std::uint32_t flags, u64 bin) {
        if (!started) { started = true; t = bin; B = bin; }
        else if (bin > t) {
            t = bin;
            while (t - B >= p.epoch_bins) rebuild();
            fold_ready();
            evict_old();
        }
        open[bin].bin = bin;
        open[bin].entries.push_back({w, scaled_for(w, bin), m, flags});
        events += 1;
    }

    void rebuild() {
        u64 Bn = B + p.epoch_bins;
        for (auto& [b, ob] : open)
            for (auto& s : ob.entries)
                s.w_scaled = (b >= Bn) ? u128(s.w_raw) * tab.inv_decay[b - Bn]
                                       : u128(s.w_raw) * tab.decay[Bn - b];
        B = Bn;
    }

    void fold_ready() {
        while (!open.empty()) {
            u64 band = open.begin()->first / p.rollup;
            u64 lo = band * p.rollup, hi = lo + p.rollup - 1;
            if (hi + p.fine_bins >= t) break;
            Bucket b; b.bin_lo = lo; b.bin_hi = hi; b.epoch_tag = B;
            std::map<MinerId, CompEntry> agg;
            for (u64 bi = lo; bi <= hi; ++bi) {
                auto it = open.find(bi);
                if (it == open.end()) continue;
                for (const auto& s : it->second.entries) {
                    b.scaled_sum += U256::from_u128(s.w_scaled);
                    b.raw_work += s.w_raw;
                    auto& e = agg[s.miner];
                    e.miner = s.miner;
                    e.scaled += U256::from_u128(s.w_scaled);
                    e.raw += s.w_raw;
                }
                open.erase(it);
            }
            for (auto& [m, e] : agg) b.comp.push_back(e);
            levels[0].push_back(std::move(b));
            cascade();
        }
    }

    void cascade() {
        for (std::size_t k = 0; k + 1 < levels.size(); ++k) {
            if (levels[k].size() < p.level_caps[k]) continue;
            Bucket b; b.epoch_tag = B;
            std::map<MinerId, CompEntry> agg;
            for (u64 i = 0; i < p.rollup && !levels[k].empty(); ++i) {
                Bucket c = levels[k].front();
                levels[k].pop_front();
                u64 f = tab.epoch_shift[(B - c.epoch_tag) / p.epoch_bins];
                if (i == 0) b.bin_lo = c.bin_lo;
                b.bin_hi = c.bin_hi;
                b.scaled_sum += c.scaled_sum.mul_q(f);
                b.raw_work += c.raw_work;
                for (const auto& e : c.comp) {
                    auto& a = agg[e.miner];
                    a.miner = e.miner;
                    a.scaled += e.scaled.mul_q(f);
                    a.raw += e.raw;
                }
            }
            for (auto& [m, e] : agg) b.comp.push_back(e);
            levels[k + 1].push_back(std::move(b));
        }
    }

    void evict_old() {
        for (;;) {
            std::size_t best = SIZE_MAX;
            for (std::size_t k = 0; k < levels.size(); ++k) {
                if (levels[k].empty()) continue;
                if (best == SIZE_MAX ||
                    levels[k].front().bin_lo < levels[best].front().bin_lo)
                    best = k;
            }
            if (best == SIZE_MAX) return;
            if (levels[best].front().bin_hi + p.window_bins >= t) return;
            levels[best].pop_front();
        }
    }

    std::map<MinerId, U256> scan_acc() const {
        std::map<MinerId, U256> out;
        for (const auto& [b, ob] : open)
            for (const auto& s : ob.entries)
                out[s.miner] += U256::from_u128(s.w_scaled);
        for (const auto& lvl : levels)
            for (const auto& bkt : lvl) {
                u64 f = tab.epoch_shift[(B - bkt.epoch_tag) / p.epoch_bins];
                for (const auto& e : bkt.comp)
                    out[e.miner] += e.scaled.mul_q(f);
            }
        return out;
    }
    u128 scan_raw() const {
        u128 r = 0;
        for (const auto& [b, ob] : open)
            for (const auto& s : ob.entries) r += s.w_raw;
        for (const auto& lvl : levels)
            for (const auto& bkt : lvl) r += bkt.raw_work;
        return r;
    }
};

// Small origin-bin geometry exercising every mechanism quickly:
// W=64 bins, fine=8, R=4 bins/bucket, caps={20}, HL=16, E=32, n_ctx=2, D=16.
static LaneParams small_params() {
    LaneParams p;
    p.window_bins = 64;
    p.fine_bins = 8;
    p.rollup = 4;
    p.level_caps = {20};
    p.half_life = 16;
    p.epoch_bins = 32;
    p.n_ctx = 2;
    p.journal_depth = 16;
    return p;
}

// Deterministic clock driver: advances the bin occasionally; emits mostly
// on-time work plus receipts crediting recent past bins.
struct Driver {
    XorShift64 rng;
    u64 bin;
    explicit Driver(u64 seed, u64 start_bin = 1000) : rng(seed), bin(start_bin) {}
    void step(const LaneParams& p, MinerId& m, u64& w, u64& b) {
        if (rng.range(1, 8) == 1) bin += (rng.range(1, 12) == 1) ? 2 : 1;
        m = static_cast<MinerId>(rng.range(0, 9));
        w = rng.range(1, u64(1) << 62);
        b = bin;
        if (rng.range(1, 6) == 1) {                       // a receipt
            u64 back = rng.range(1, p.n_ctx);
            b = (bin > back) ? bin - back : bin;
        }
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

static void test_sha256() {
    auto h = sha256(reinterpret_cast<const std::uint8_t*>("abc"), 3);
    static const std::uint8_t want[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    CHECK(std::memcmp(h.data(), want, 32) == 0);
    auto d = sha256d(reinterpret_cast<const std::uint8_t*>("hello"), 5);
    static const std::uint8_t want2[32] = {
        0x95, 0x95, 0xc9, 0xdf, 0x90, 0x07, 0x51, 0x48, 0xeb, 0x06, 0x86,
        0x03, 0x65, 0xdf, 0x33, 0x58, 0x4b, 0x75, 0xbf, 0xf7, 0x82, 0xa5,
        0x10, 0xc6, 0xcd, 0x48, 0x83, 0xa4, 0x19, 0x83, 0x3d, 0x50};
    CHECK(std::memcmp(d.data(), want2, 32) == 0);
}

static void test_fixed_point() {
    U256 a(5), b(7);
    CHECK((a + b) == U256(12));
    CHECK((b - a) == U256(2));
    CHECK(a < b);
    U256 big = U256::from_u128((u128(0x0123456789abcdefULL) << 64) |
                               0xfedcba9876543210ULL);
    big += big;
    CHECK(big.mul_q(Q_ONE) == big);
    CHECK(mul_q64(Q_ONE, Q_ONE) == Q_ONE);
    CHECK(U256::ratio_q(U256(5), U256(10)) == Q_ONE / 2);
    CHECK(U256::ratio_q(U256(10), U256(10)) == Q_ONE);
    CHECK(U256::ratio_q(U256(0), U256(10)) == 0);
    CHECK(U256::ratio_q(U256(1), U256()) == Q_ONE);

    DecayTables t1, t2;
    t1.init(2160, 4096, 8192, 8);
    t2.init(2160, 4096, 8192, 8);
    CHECK(t1.decay == t2.decay);
    CHECK(t1.inv_decay == t2.inv_decay);
    CHECK(t1.epoch_shift == t2.epoch_shift);
    u64 expect_per = Q_ONE - static_cast<u64>(
        (u128(Q_ONE) * LN2_MICRO) / (u128(1000000) * 2160));
    CHECK(t1.decay_per == expect_per);
    for (std::size_t d = 1; d < t1.decay.size(); ++d)
        CHECK(t1.decay[d] < t1.decay[d - 1]);
    u64 half = t1.decay[2160];
    CHECK(half > (Q_ONE / 2) - (Q_ONE >> 12) &&
          half < (Q_ONE / 2) + (Q_ONE >> 12));
    CHECK(u128(t1.inv_decay.back()) < (u128(4) << FRAC_BITS));
}

static void test_headroom_guard() {
    DecayTables bad;
    bool threw = false;
    try { bad.init(54, 128, 200, 4); } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
    LaneParams def;   // ratified defaults (E/HL = 256/144 = 1.78) construct
    Lane ok(def);
    CHECK(ok.tables().inv_decay.size() == def.epoch_bins);
}

static void test_lane_vs_reference(const LaneParams& p, u64 pushes, u64 seed,
                                   const char* tag) {
    Lane lane(p);
    ReferenceLane ref(p);
    Driver drv(seed);
    for (u64 i = 0; i < pushes; ++i) {
        MinerId m; u64 w, b;
        drv.step(p, m, w, b);
        lane.push(m, w, 0, b);
        ref.push(m, w, 0, b);

        CHECK_MSG(lane.clock() == ref.t, "%s clock @%llu", tag,
                  (unsigned long long)i);
        CHECK_MSG(lane.epoch_base() == ref.B, "%s B @%llu", tag,
                  (unsigned long long)i);
        CHECK_MSG(lane.event_count() == ref.events, "%s events @%llu", tag,
                  (unsigned long long)i);
        if (lane.acc() != ref.scan_acc()) {
            ++g_failures;
            std::printf("FAIL %s: acc != reference at push %llu\n", tag,
                        (unsigned long long)i);
            return;
        }
        ++g_checks;
        CHECK_MSG(lane.raw_total() == ref.scan_raw(), "%s raw @%llu", tag,
                  (unsigned long long)i);
        for (const auto& lvl : lane.levels())
            for (const auto& bkt : lvl)
                CHECK_MSG(bkt.bin_hi + p.window_bins >= lane.clock(),
                          "%s window @%llu", tag, (unsigned long long)i);
        U256 sum;
        for (const auto& [mm, a] : lane.acc()) sum += a;
        CHECK_MSG(sum == lane.acc_total(), "%s acc_total @%llu", tag,
                  (unsigned long long)i);
    }
    auto pm = lane.payout_map();
    U256 pm_sum;
    for (const auto& [m, w] : pm) pm_sum += w;
    U256 tot = lane.decayed_total();
    CHECK(!(tot < pm_sum));
    CHECK((tot - pm_sum) < U256(pm.size() + 1));
}

// THE fairness headline: same origin bin -> same decayed value per unit of
// raw work, whether accounted on time or carried late as a receipt.
static void test_origin_fairness() {
    LaneParams p = small_params();
    Lane l(p);
    for (int i = 0; i < 50; ++i) l.push(0, 7, 0, 1000 + i / 10);
    u64 b = l.clock();
    l.push(1, 5000, 0, b);                 // miner 1: on time, bin b
    l.push(0, 7, 0, b + 1);                // clock advances
    l.push(0, 7, 0, b + 2);                // clock advances again
    l.push(2, 5000, L0F_RECEIPT, b);       // miner 2: same work, LATE, bin b
    CHECK(l.decayed_weight(1) == l.decayed_weight(2));
    // equality must survive an epoch rebuild (both re-derived from the same
    // (w_raw, bin) durable records): push until the base advances
    u64 B0 = l.epoch_base();
    while (l.epoch_base() == B0)
        l.push(0, 7, 0, l.clock() + 1);
    CHECK(l.decayed_weight(1) == l.decayed_weight(2));
}

static void test_digest_and_rewind() {
    LaneParams p = small_params();
    Lane a(p), b(p);
    Driver d1(42), d2(42);
    for (int i = 0; i < 500; ++i) {
        MinerId m; u64 w, bb;
        d1.step(p, m, w, bb); a.push(m, w, 0, bb);
        d2.step(p, m, w, bb); b.push(m, w, 0, bb);
    }
    CHECK(a.digest(test_key) == b.digest(test_key));
    // NOTE (origin-bin semantics): swapping arrival order WITHIN one bin
    // converges to identical accounting state -> identical digests, by
    // design. Sensitivity is to STATE: different origin bins must differ.
    Lane c0(p), d0(p);
    c0.push(1, 100, 0, 50); c0.push(2, 200, 0, 50);
    d0.push(2, 200, 0, 50); d0.push(1, 100, 0, 50);
    CHECK(c0.digest(test_key) == d0.digest(test_key));
    Lane c(p), d(p);
    c.push(1, 100, 0, 50); c.push(2, 200, 0, 51);
    d.push(1, 100, 0, 51); d.push(2, 200, 0, 51);
    CHECK(!(c.digest(test_key) == d.digest(test_key)));

    // rewind: bit-exact, covering same-bin pushes, receipts, clock advance
    Lane e(p);
    Driver d3(7);
    for (int i = 0; i < 300; ++i) {
        MinerId m; u64 w, bb;
        d3.step(p, m, w, bb);
        e.push(m, w, 0, bb);
    }
    while (e.clock() - e.epoch_base() >= p.epoch_bins - 4)
        e.push(0, 1, 0, e.clock() + 1);
    auto snap = e.digest(test_key);
    u64 t0 = e.clock();
    e.push(3, 11, 0, t0);
    e.push(4, 12, 0, t0 > 1 ? t0 - 1 : t0);
    e.push(5, 13, 0, t0 + 1);
    CHECK(e.rewind(3));
    CHECK(e.digest(test_key) == snap);

    // forced fold at the rewind landing
    Lane g(p);
    Driver d4(21);
    for (int i = 0; i < 200; ++i) {
        MinerId m; u64 w, bb;
        d4.step(p, m, w, bb);
        g.push(m, w, 0, bb);
    }
    while (g.clock() - g.epoch_base() >= p.epoch_bins - p.rollup - 6)
        g.push(0, 1, 0, g.clock() + 1);
    auto snap2 = g.digest(test_key);
    std::size_t buckets_before = g.levels()[0].size();
    g.push(1, 99, 0, g.clock() + p.rollup);
    CHECK(g.levels()[0].size() >= buckets_before);
    CHECK(g.rewind(1));
    CHECK(g.digest(test_key) == snap2);
    CHECK(g.levels()[0].size() == buckets_before);

    // rewind refusal at the rebuild boundary
    Lane f(p);
    f.push(0, 10, 0, 100);
    for (u64 i = 1; i <= p.epoch_bins; ++i) f.push(0, 10, 0, 100 + i);
    f.push(0, 10, 0, f.clock());
    f.push(0, 10, 0, f.clock());
    // journal: [sentinel, (folds/evicts), P_trigger, P, P] -> 3 pushes
    CHECK(!f.rewind(3));
    CHECK(f.rewind(2));
}

static void test_review_guards() {
    LaneParams p = small_params();
    {
        LaneParams bad = p; bad.fine_bins = bad.n_ctx;
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        LaneParams bad = p; bad.window_bins = p.fine_bins;
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        LaneParams bad = p; bad.level_caps = {2, 20};
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        LaneParams bad = p; bad.level_caps = {};
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        Lane l(p);
        bool threw = false;
        try { l.push(0, 0, 0, 10); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        Lane l(p);
        l.push(0, 5, 0, 100);
        bool threw = false;
        try { l.push(0, 5, 0, 100 - p.n_ctx - 1); }
        catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {
        Lane l(p);
        l.push(0, 5, 0, 10);
        bool threw = false;
        try { l.epoch_rebuild(); } catch (const std::logic_error&) { threw = true; }
        CHECK(threw);
    }
    {
        Roundabout rb;
        LaneParams bad = p; bad.window_bins = 1;
        bool threw = false;
        try { rb.add_lane(5, bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
        CHECK(rb.lane_count() == 0 && rb.lane(5) == nullptr);
        rb.add_lane(5, p);
        CHECK(rb.lane(5) != nullptr);
    }
    {
        LaneParams p2 = p; p2.half_life = 24;
        Lane x(p), y(p2);
        for (int i = 0; i < 50; ++i) { x.push(1, 100, 0, 10 + i / 5);
                                       y.push(1, 100, 0, 10 + i / 5); }
        CHECK(!(x.digest(test_key) == y.digest(test_key)));
    }
}

static void test_descriptor() {
    auto mk = [](std::initializer_list<int> v) {
        std::vector<std::uint8_t> s;
        for (int x : v) s.push_back(static_cast<std::uint8_t>(x));
        return s;
    };
    std::vector<std::uint8_t> p2pkh = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2pkh.push_back(static_cast<std::uint8_t>(i));
    p2pkh.push_back(0x88); p2pkh.push_back(0xac);
    auto r1 = canonicalize_script(p2pkh);
    CHECK(r1.kind == ScriptKind::P2PKH && r1.payload.size() == 20);
    std::vector<std::uint8_t> p2sh = {0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2sh.push_back(static_cast<std::uint8_t>(i));
    p2sh.push_back(0x87);
    CHECK(canonicalize_script(p2sh).kind == ScriptKind::P2SH);
    std::vector<std::uint8_t> p2wpkh = {0x00, 0x14};
    for (int i = 0; i < 20; ++i) p2wpkh.push_back(static_cast<std::uint8_t>(i));
    auto r2 = canonicalize_script(p2wpkh);
    CHECK(r2.kind == ScriptKind::P2WPKH);
    CHECK(!(r1 == r2));
    MinerIntern intern;
    PayoutDescriptor d1; d1.pay = r1;
    PayoutDescriptor d2; d2.pay = r2;
    CHECK(intern.intern(d1) != intern.intern(d2));
    CHECK(intern.intern(d1) == intern.intern(d1));
    std::vector<std::uint8_t> p2wsh = {0x00, 0x20};
    for (int i = 0; i < 32; ++i) p2wsh.push_back(1);
    CHECK(canonicalize_script(p2wsh).kind == ScriptKind::P2WSH);
    std::vector<std::uint8_t> p2tr = {0x51, 0x20};
    for (int i = 0; i < 32; ++i) p2tr.push_back(2);
    CHECK(canonicalize_script(p2tr).kind == ScriptKind::P2TR);
    auto exotic = mk({0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef});
    auto r3 = canonicalize_script(exotic);
    CHECK(r3.kind == ScriptKind::RAW && r3.payload.size() == 32);
    CHECK(canonicalize_script(exotic) == r3);
    PayoutDescriptor d3; d3.pay = r3;
    CHECK(!d3.valid());
    d3.raw_script = exotic;
    CHECK(d3.valid());
    d3.raw_script.push_back(0x00);
    CHECK(!d3.valid());
    d3.raw_script = exotic;
    PayoutDescriptor d3b; d3b.pay = r3; d3b.raw_script = p2pkh;
    CHECK(!d3b.valid());
    PayoutDescriptor d3c;
    d3c.pay.kind = ScriptKind::RAW;
    auto th = sha256d(p2pkh);
    d3c.pay.payload.assign(th.begin(), th.end());
    d3c.raw_script = p2pkh;
    CHECK(!d3c.valid());
    PayoutDescriptor d3d; d3d.pay = r1; d3d.raw_script = p2pkh;
    CHECK(!d3d.valid());
    PayoutDescriptor d3e; d3e.pay = r1;
    d3e.pay.payload.resize(5);
    CHECK(!d3e.valid());
    PayoutDescriptor d4; d4.pay = r1; d4.attribution = r2;
    CHECK(!d4.valid(false));
    CHECK(d4.valid(true));
    PayoutDescriptor d5; d5.pay = r1;
    d5.aux = {{98, r2}, {99, r2}};
    CHECK(d5.valid());
    d5.aux = {{99, r2}, {98, r2}};
    CHECK(!d5.valid());
    d5.aux = {{98, r2}, {98, r2}};
    CHECK(!d5.valid());
    PayoutDescriptor d6; d6.pay = r1;
    PayoutDescriptor d7; d7.pay = r1; d7.aux = {{98, r2}};
    CHECK(d6.canonical_bytes() != d7.canonical_bytes());
    CHECK(d6.identity_key() == d7.identity_key());
    PayoutDescriptor d8; d8.pay = r1;
    d8.aux.resize(0x10000);
    for (std::size_t i = 0; i < d8.aux.size(); ++i) {
        d8.aux[i].chain_id = static_cast<std::uint32_t>(i);
        d8.aux[i].ref = r2;
    }
    CHECK(!d8.valid());
    d8.aux.resize(0xffff);
    CHECK(d8.valid());
}

static void test_roundabout() {
    Roundabout rb;
    rb.add_lane(1, small_params());
    LaneParams p2;
    p2.window_bins = 32; p2.fine_bins = 4; p2.rollup = 2;
    p2.level_caps = {8}; p2.half_life = 8; p2.epoch_bins = 16;
    p2.n_ctx = 2; p2.journal_depth = 8;
    rb.add_lane(2, p2);
    CHECK(rb.lane_count() == 2);

    std::vector<std::uint8_t> p2pkh = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2pkh.push_back(static_cast<std::uint8_t>(i));
    p2pkh.push_back(0x88); p2pkh.push_back(0xac);
    PayoutDescriptor d; d.pay = canonicalize_script(p2pkh);

    MinerId m1 = rb.push(1, d, 1000, 0, 500);
    MinerId m2 = rb.push(2, d, 2000, 0, 700);
    CHECK(m1 == m2);
    auto agg = rb.aggregate_decayed();
    CHECK(agg.size() == 1 && !agg.begin()->second.is_zero());

    PayoutDescriptor bad = d;
    bad.attribution = d.pay;
    bool threw = false;
    try { rb.push(1, bad, 1, 0, 500); } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);

    rb.remove_lane(2);
    CHECK(rb.lane_count() == 1 && rb.lane(2) == nullptr);
}

static void test_digest_canonical_identity() {
    auto mk_desc = [](std::uint8_t fill) {
        std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i) s.push_back(fill);
        s.push_back(0x88); s.push_back(0xac);
        PayoutDescriptor d; d.pay = canonicalize_script(s);
        return d;
    };
    PayoutDescriptor dx = mk_desc(0xaa), dy = mk_desc(0xbb);
    LaneParams p = small_params();
    Roundabout rb1, rb2;
    rb1.add_lane(1, p); rb1.add_lane(2, p);
    rb2.add_lane(1, p); rb2.add_lane(2, p);

    rb1.push(1, dx, 100, 0, 50); rb1.push(2, dy, 300, 0, 80);
    rb1.push(1, dy, 200, 0, 50); rb1.push(2, dx, 400, 0, 80);

    rb2.push(2, dy, 300, 0, 80); rb2.push(2, dx, 400, 0, 80);
    rb2.push(1, dx, 100, 0, 50); rb2.push(1, dy, 200, 0, 50);

    CHECK(rb1.miners().intern(dx) != rb2.miners().intern(dx));
    CHECK(rb1.lane_digest(1) == rb2.lane_digest(1));
    CHECK(rb1.lane_digest(2) == rb2.lane_digest(2));
    CHECK(!(rb1.lane_digest(1) == rb1.lane_digest(2)));
}

static void test_merkle_proofs() {
    LaneParams p = small_params();
    Lane l(p);
    Driver d(77);
    for (int i = 0; i < 400; ++i) {
        MinerId m; u64 w, b;
        d.step(p, m, w, b);
        l.push(m, w, 0, b);
    }
    bytes32 root = l.digest(test_key);
    int proved = 0;
    for (const auto& [m, a] : l.acc()) {
        bytes32 leaf;
        Lane::MerkleProof proof;
        CHECK(l.acc_proof(m, test_key, leaf, proof));
        CHECK(Lane::verify_proof(root, leaf, proof));
        bytes32 badleaf = leaf; badleaf[0] ^= 1;
        CHECK(!Lane::verify_proof(root, badleaf, proof));
        Lane::MerkleProof p2 = proof;
        p2.index = (p2.index + 1) % p2.leaf_count;
        CHECK(!Lane::verify_proof(root, leaf, p2));
        ++proved;
    }
    CHECK(proved >= 5);
    bytes32 leaf;
    Lane::MerkleProof proof;
    MinerId m0 = l.acc().begin()->first;
    CHECK(l.acc_proof(m0, test_key, leaf, proof));
    l.push(m0, 12345, 0, l.clock());
    bytes32 root2 = l.digest(test_key);
    CHECK(!(root2 == root));
    CHECK(!Lane::verify_proof(root2, leaf, proof));
    Lane::MerkleProof p3; bytes32 lf3;
    CHECK(!l.acc_proof(4040404u, test_key, lf3, p3));
}

static void test_vesting() {
    LaneParams p = small_params();
    p.vest_threshold_shares = 32;
    Lane l(p);
    u64 b = 100;
    for (int i = 0; i < 200; ++i) {
        if (i % 12 == 11) ++b;
        l.push(1, 1000, 0, b);
    }
    l.push(2, 1000, 0, b);
    u64 v1 = l.vesting_factor(1), v2 = l.vesting_factor(2);
    CHECK(v1 == Q_ONE);
    CHECK(v2 < Q_ONE / 16);
    auto pm = l.payout_map();
    auto vm = l.vested_payout_map();
    CHECK(vm[1] == pm[1].mul_q(Q_ONE));
    CHECK(vm[2] < pm[2]);
    u64 prev = v2;
    for (int i = 0; i < 40; ++i) {
        l.push(2, 1000, 0, b);
        u64 now = l.vesting_factor(2);
        CHECK(now >= prev);
        prev = now;
    }
    LaneParams p0 = small_params();
    p0.vest_threshold_shares = 0;
    Lane l0(p0);
    l0.push(7, 123, 0, 5);
    CHECK(l0.vesting_factor(7) == Q_ONE);
    Lane x(p), y(p);
    Driver dx(9), dy(9);
    for (int i = 0; i < 300; ++i) {
        MinerId m; u64 w, bb;
        dx.step(p, m, w, bb); x.push(m, w, 0, bb);
        dy.step(p, m, w, bb); y.push(m, w, 0, bb);
    }
    for (MinerId m = 0; m <= 9; ++m)
        CHECK(x.vesting_factor(m) == y.vesting_factor(m));
    LaneParams pv = small_params();
    pv.vest_threshold_shares = 64;
    Lane c(small_params()), d(pv);
    c.push(1, 100, 0, 9); d.push(1, 100, 0, 9);
    CHECK(!(c.digest(test_key) == d.digest(test_key)));
}

int main() {
    test_sha256();
    test_fixed_point();
    test_headroom_guard();
    // small origin-bin geometry: receipts, folds, evictions, 2+ epochs
    test_lane_vs_reference(small_params(), 4000, 1234, "small");
    // ratified default geometry across at least one epoch rebuild
    {
        LaneParams def;
        test_lane_vs_reference(def, 24000, 99, "default");
    }
    test_origin_fairness();
    test_digest_and_rewind();
    test_review_guards();
    test_descriptor();
    test_roundabout();
    test_digest_canonical_identity();
    test_merkle_proofs();
    test_vesting();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
