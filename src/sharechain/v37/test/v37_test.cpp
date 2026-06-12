// V37 MRR roundabout — standalone unit tests (no gtest dependency; tiny
// CHECK harness so the suite compiles with nothing but g++ -std=c++20).
//
// The consensus gate (spec §8 / brief component 7): ReferenceLane below is
// an INDEPENDENT implementation of the lane definition whose per-miner
// weights are recomputed by full scan over the durable records after every
// operation; the fast incremental Lane must match it bit-exact, every push,
// including across epoch rebuilds, folds, and evictions.

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

// Deterministic PRNG (consensus tests must not depend on platform RNG).
struct XorShift64 {
    u64 s;
    explicit XorShift64(u64 seed) : s(seed ? seed : 0x9e3779b97f4a7c15ull) {}
    u64 next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s;
    }
    u64 range(u64 lo, u64 hi) { return lo + next() % (hi - lo + 1); }
};

// ── ReferenceLane: independent naive implementation of the definition ─────
// Same fixed op order as Lane (rebuild / fold / cascade / insert / evict at
// the same positionally defined points), but no incremental accumulators:
// per-miner weights are derived by FULL SCAN of the durable records.
struct ReferenceLane {
    LaneParams p;
    DecayTables tab;
    u64 next_pos = 0, B = 0, cover = 0;
    std::deque<L0Slot> l0;
    std::vector<std::deque<Bucket>> levels;

    explicit ReferenceLane(const LaneParams& pp) : p(pp) {
        tab.init(p.half_life, p.epoch_len(), p.epoch_len() + p.c0,
                 p.window / p.epoch_len() + 4);
        levels.resize(p.level_caps.size());
    }

    void push(MinerId m, u64 w_raw, std::uint32_t flags) {
        if (next_pos - B == p.epoch_len()) rebuild();
        if (l0.size() == p.c0) fold_l0();
        cascade();
        u64 pos = next_pos++;
        u128 ws = u128(w_raw) * tab.inv_decay[pos - B];
        l0.push_back({pos, w_raw, ws, m, flags});
        cover += 1;
        while (cover > p.window) evict();
    }

    void rebuild() {
        u64 Bn = B + p.epoch_len();
        for (auto& s : l0)
            s.w_scaled = u128(s.w_raw) * tab.decay[Bn - s.pos];
        B = Bn;
    }

    void fold_l0() {
        Bucket b; b.epoch_tag = B;
        std::map<MinerId, CompEntry> agg;
        for (u64 i = 0; i < p.rollup; ++i) {
            const L0Slot& s = l0.front();
            if (i == 0) b.pos_lo = s.pos;
            b.pos_hi = s.pos;
            b.scaled_sum += U256::from_u128(s.w_scaled);
            b.raw_work += s.w_raw;
            auto& e = agg[s.miner];
            e.miner = s.miner;
            e.scaled += U256::from_u128(s.w_scaled);
            e.raw += s.w_raw;
            l0.pop_front();
        }
        for (auto& [m, e] : agg) b.comp.push_back(e);
        levels[0].push_back(std::move(b));
    }

    void cascade() {
        for (std::size_t k = 0; k + 1 < levels.size(); ++k) {
            if (levels[k].size() < p.level_caps[k]) continue;
            Bucket b; b.epoch_tag = B;
            std::map<MinerId, CompEntry> agg;
            for (u64 i = 0; i < p.rollup; ++i) {
                Bucket c = levels[k].front();
                levels[k].pop_front();
                u64 f = tab.epoch_shift[(B - c.epoch_tag) / p.epoch_len()];
                if (i == 0) b.pos_lo = c.pos_lo;
                b.pos_hi = c.pos_hi;
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

    void evict() {
        std::size_t best = SIZE_MAX;
        for (std::size_t k = 0; k < levels.size(); ++k) {
            if (levels[k].empty()) continue;
            if (best == SIZE_MAX ||
                levels[k].front().pos_lo < levels[best].front().pos_lo)
                best = k;
        }
        Bucket b = levels[best].front();
        levels[best].pop_front();
        cover -= (b.pos_hi - b.pos_lo + 1);
    }

    // The reference computation: scan everything, no incremental state.
    std::map<MinerId, U256> scan_acc() const {
        std::map<MinerId, U256> out;
        for (const auto& s : l0)
            out[s.miner] += U256::from_u128(s.w_scaled);
        for (const auto& lvl : levels)
            for (const auto& b : lvl) {
                u64 f = tab.epoch_shift[(B - b.epoch_tag) / p.epoch_len()];
                for (const auto& e : b.comp) out[e.miner] += e.scaled.mul_q(f);
            }
        return out;
    }
    u128 scan_raw() const {
        u128 r = 0;
        for (const auto& s : l0) r += s.w_raw;
        for (const auto& lvl : levels)
            for (const auto& b : lvl) r += b.raw_work;
        return r;
    }
};

// Injective deterministic id -> key map for single-node lane tests (real
// deployments resolve through MinerIntern::key — see the canonical-identity
// regression test below).
static bytes32 test_key(MinerId m) {
    std::uint8_t b[4] = {
        static_cast<std::uint8_t>(m), static_cast<std::uint8_t>(m >> 8),
        static_cast<std::uint8_t>(m >> 16), static_cast<std::uint8_t>(m >> 24)};
    return sha256d(b, 4);
}

// ── tests ──────────────────────────────────────────────────────────────────

static void test_sha256() {
    auto h = sha256(reinterpret_cast<const std::uint8_t*>("abc"), 3);
    static const std::uint8_t want[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    CHECK(std::memcmp(h.data(), want, 32) == 0);
    // sha256d("hello") — standard known double-hash vector
    auto d = sha256d(reinterpret_cast<const std::uint8_t*>("hello"), 5);
    static const std::uint8_t want2[32] = {
        0x95, 0x95, 0xc9, 0xdf, 0x90, 0x07, 0x51, 0x48, 0xeb, 0x06, 0x86,
        0x03, 0x65, 0xdf, 0x33, 0x58, 0x4b, 0x75, 0xbf, 0xf7, 0x82, 0xa5,
        0x10, 0xc6, 0xcd, 0x48, 0x83, 0xa4, 0x19, 0x83, 0x3d, 0x50};
    CHECK(std::memcmp(d.data(), want2, 32) == 0);
}

static void test_fixed_point() {
    // U256 basics
    U256 a(5), b(7);
    CHECK((a + b) == U256(12));
    CHECK((b - a) == U256(2));
    CHECK(a < b);
    // mul_q identity: x * 1.0 == x, including via the 5-limb path
    U256 big = U256::from_u128((u128(0x0123456789abcdefULL) << 64) | 0xfedcba9876543210ULL);
    big += big;  // ensure multi-limb
    CHECK(big.mul_q(Q_ONE) == big);
    CHECK(mul_q64(Q_ONE, Q_ONE) == Q_ONE);

    // Table generation: deterministic, monotonic, V36-lineage formula
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
    for (std::size_t j = 1; j < t1.inv_decay.size(); ++j)
        CHECK(t1.inv_decay[j] > t1.inv_decay[j - 1]);
    // Half-life sanity: decay[half_life] ~ 0.5. The V36-lineage per-step
    // factor is first-order (1 - ln2/HL), so (1-x)^HL deviates from exactly
    // 0.5 by ~ln2^2/(2*HL) ~ 5.5e-5 relative — allow 2^-12 slack.
    u64 half = t1.decay[2160];
    CHECK(half > (Q_ONE / 2) - (Q_ONE >> 12) && half < (Q_ONE / 2) + (Q_ONE >> 12));
    // Inverse headroom: inv_decay max < 4.0 (E/HL = 4096/2160 -> 2^1.9).
    // Compare in u128: 4.0 in Q62 == 2^64, which overflows u64.
    CHECK(u128(t1.inv_decay.back()) < (u128(4) << FRAC_BITS));
    // Roundtrip: decay[j] * inv_decay[j] ~ 1.0 from below
    for (std::size_t j : {std::size_t(1), std::size_t(100), std::size_t(4095)}) {
        u64 rt = mul_q64(t1.decay[j], t1.inv_decay[j]);
        CHECK(rt <= Q_ONE && rt > Q_ONE - (Q_ONE >> 40));
    }
}

// Small geometry exercising every mechanism quickly:
// W=256 = C0(128) + 16 buckets x 8; E=128; HL=64 (=W/4); D=16.
// NOTE: E/HL must keep lambda^-(E-1) < 4.0 (inverse-decay u64 headroom) —
// the table generator now enforces this (see test_headroom_guard).
static LaneParams small_params() {
    LaneParams p;
    p.window = 256;
    p.c0 = 128;
    p.rollup = 8;
    p.level_caps = {16};
    p.half_life = 64;
    p.journal_depth = 16;
    return p;
}

static void test_headroom_guard() {
    // E/HL = 128/54 = 2.37: lambda^-(127) ~ 2^2.35 > 4.0 -> must throw,
    // never silently wrap the inverse table.
    LaneParams bad = small_params();
    bad.half_life = 54;
    bool threw = false;
    try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);
    // Ratified default geometry (4096/2160 = 1.896) constructs fine.
    LaneParams def;
    Lane ok(def);
    CHECK(ok.tables().inv_decay.size() == def.epoch_len());
}

static void test_lane_vs_reference(const LaneParams& p, u64 pushes, u64 seed,
                                   const char* tag) {
    Lane lane(p);
    ReferenceLane ref(p);
    XorShift64 rng(seed);
    u128 pushed_raw = 0, evicted_raw = 0;
    for (u64 i = 0; i < pushes; ++i) {
        MinerId m = static_cast<MinerId>(rng.range(0, 12));
        u64 w = rng.range(1, u64(1) << 62);  // full-range raw work
        u128 before = lane.raw_total();
        lane.push(m, w, 0);
        ref.push(m, w, 0);
        pushed_raw += w;
        u128 after = lane.raw_total();
        if (after < before + w) evicted_raw += (before + w - after);

        CHECK_MSG(lane.next_pos() == ref.next_pos, "%s pos @%llu", tag,
                  (unsigned long long)i);
        CHECK_MSG(lane.epoch_base() == ref.B, "%s B @%llu", tag,
                  (unsigned long long)i);
        CHECK_MSG(lane.cover() == ref.cover, "%s cover @%llu", tag,
                  (unsigned long long)i);
        // THE GATE: incremental accumulators == full-scan reference,
        // bit-exact, after every operation.
        if (lane.acc() != ref.scan_acc()) {
            ++g_failures;
            std::printf("FAIL %s: acc != reference scan at push %llu\n", tag,
                        (unsigned long long)i);
            return;
        }
        ++g_checks;
        CHECK_MSG(lane.raw_total() == ref.scan_raw(), "%s raw @%llu", tag,
                  (unsigned long long)i);
        // Conservation: raw work is exact bookkeeping (F-1)
        CHECK_MSG(lane.raw_total() == pushed_raw - evicted_raw,
                  "%s conservation @%llu", tag, (unsigned long long)i);
        // Window: quantized — never exceeds W (OQ-1)
        CHECK_MSG(lane.cover() <= p.window, "%s window @%llu", tag,
                  (unsigned long long)i);
        // acc_total invariant: equals sum of acc entries exactly
        U256 sum;
        for (const auto& [mm, a] : lane.acc()) sum += a;
        CHECK_MSG(sum == lane.acc_total(), "%s acc_total @%llu", tag,
                  (unsigned long long)i);
    }
    // Payout map truncation bound: per-miner mul_q truncates < 1 ulp each
    auto pm = lane.payout_map();
    U256 pm_sum;
    for (const auto& [m, w] : pm) pm_sum += w;
    U256 tot = lane.decayed_total();
    CHECK(!(tot < pm_sum));  // pm_sum <= tot
    U256 diff = tot - pm_sum;
    CHECK(diff < U256(pm.size() + 1));
}

static void test_digest_and_rewind() {
    LaneParams p = small_params();
    // Determinism: identical sequences -> identical digests
    Lane a(p), b(p);
    XorShift64 r1(42), r2(42);
    for (int i = 0; i < 500; ++i) {
        a.push(static_cast<MinerId>(r1.range(0, 5)), r1.range(1, 1000000), 0);
        b.push(static_cast<MinerId>(r2.range(0, 5)), r2.range(1, 1000000), 0);
    }
    CHECK(a.digest(test_key) == b.digest(test_key));
    // Sensitivity: different order -> different digest
    Lane c(p), d(p);
    c.push(1, 100, 0); c.push(2, 200, 0);
    d.push(2, 200, 0); d.push(1, 100, 0);
    CHECK(!(c.digest(test_key) == d.digest(test_key)));

    // Rewind: bit-exact state restoration (OQ-7), within one epoch
    Lane e(p);
    XorShift64 r3(7);
    // run to mid-epoch so the rewind span cannot cross a rebuild
    for (int i = 0; i < 300; ++i)
        e.push(static_cast<MinerId>(r3.range(0, 5)), r3.range(1, 1000000), 0);
    while ((e.next_pos() - e.epoch_base()) > p.epoch_len() - 20 ||
           (e.next_pos() - e.epoch_base()) < 16) {
        e.push(0, 1, 0);
    }
    auto snap = e.digest(test_key);
    XorShift64 r4(11);
    for (int i = 0; i < 10; ++i)
        e.push(static_cast<MinerId>(r4.range(0, 5)), r4.range(1, 1000000), 0);
    CHECK(e.rewind(10));
    CHECK(e.digest(test_key) == snap);

    // Rewind across an epoch rebuild must refuse (journal cleared)
    Lane f(p);
    for (u64 i = 0; i < p.epoch_len() + 4; ++i) f.push(0, 10, 0);
    CHECK(!f.rewind(8));   // boundary at E crossed 4 pushes ago, only 4 journaled
    // REVIEW REGRESSION: rewind landing exactly on the rebuild-triggering
    // push must refuse — the journal cannot restore the pre-rebuild frame.
    CHECK(!f.rewind(4));   // d == pushes-since-rebuild, sentinel present
    CHECK(f.rewind(2));    // shallow rewind still fine

    // Regression: rewind landing exactly on a push that triggered a fold
    // must undo that fold too (state = before the share arrived).
    Lane g(p);
    XorShift64 r5(21);
    for (int i = 0; i < 200; ++i)
        g.push(static_cast<MinerId>(r5.range(0, 5)), r5.range(1, 1000000), 0);
    // Drive L0 to exactly full so the NEXT push folds, staying mid-epoch.
    while (g.l0().size() != p.c0 ||
           (g.next_pos() - g.epoch_base()) >= p.epoch_len() - 4)
        g.push(0, 7, 0);
    auto snap_fold = g.digest(test_key);
    std::size_t buckets_before = g.levels()[0].size();
    g.push(1, 99, 0);                       // folds 8 slots, then inserts
    CHECK(g.levels()[0].size() == buckets_before + 1);
    CHECK(g.rewind(1));
    CHECK(g.digest(test_key) == snap_fold);          // fold undone with its push
    CHECK(g.levels()[0].size() == buckets_before);

    // Randomized rewind sweep: snapshot / push k <= D / rewind k must be a
    // bit-exact no-op wherever it lands in the fold/evict cycle (mid-epoch).
    Lane h(p);
    XorShift64 r6(31);
    for (int i = 0; i < 150; ++i)
        h.push(static_cast<MinerId>(r6.range(0, 5)), r6.range(1, 1000000), 0);
    for (int round = 0; round < 50; ++round) {
        // keep the span clear of the epoch boundary (journal is cleared there)
        while ((h.next_pos() - h.epoch_base()) >= p.epoch_len() - (p.journal_depth + 2) ||
               (h.next_pos() - h.epoch_base()) < p.journal_depth + 2)
            h.push(0, 3, 0);
        u64 k = r6.range(1, p.journal_depth);
        auto snap = h.digest(test_key);
        for (u64 i = 0; i < k; ++i)
            h.push(static_cast<MinerId>(r6.range(0, 5)), r6.range(1, 1000000), 0);
        CHECK(h.rewind(k));
        if (!(h.digest(test_key) == snap)) {
            ++g_failures;
            std::printf("FAIL rewind sweep round %d (k=%llu)\n", round,
                        (unsigned long long)k);
            return;
        }
        ++g_checks;
        // replay so rounds keep advancing through fold/evict alignments
        for (u64 i = 0; i < k; ++i)
            h.push(static_cast<MinerId>(r6.range(0, 7)), r6.range(1, 1000000), 0);
    }
}

static void test_descriptor() {
    auto mk = [](std::initializer_list<int> v) {
        std::vector<std::uint8_t> s;
        for (int x : v) s.push_back(static_cast<std::uint8_t>(x));
        return s;
    };
    // P2PKH
    std::vector<std::uint8_t> p2pkh = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2pkh.push_back(static_cast<std::uint8_t>(i));
    p2pkh.push_back(0x88); p2pkh.push_back(0xac);
    auto r1 = canonicalize_script(p2pkh);
    CHECK(r1.kind == ScriptKind::P2PKH && r1.payload.size() == 20);
    // P2SH
    std::vector<std::uint8_t> p2sh = {0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2sh.push_back(static_cast<std::uint8_t>(i));
    p2sh.push_back(0x87);
    CHECK(canonicalize_script(p2sh).kind == ScriptKind::P2SH);
    // P2WPKH — same h160 as the P2PKH above
    std::vector<std::uint8_t> p2wpkh = {0x00, 0x14};
    for (int i = 0; i < 20; ++i) p2wpkh.push_back(static_cast<std::uint8_t>(i));
    auto r2 = canonicalize_script(p2wpkh);
    CHECK(r2.kind == ScriptKind::P2WPKH);
    // S-1: same payload, different kind -> DIFFERENT identity
    CHECK(!(r1 == r2));
    MinerIntern intern;
    PayoutDescriptor d1; d1.pay = r1;
    PayoutDescriptor d2; d2.pay = r2;
    CHECK(intern.intern(d1) != intern.intern(d2));
    CHECK(intern.intern(d1) == intern.intern(d1));  // stable
    // P2WSH / P2TR
    std::vector<std::uint8_t> p2wsh = {0x00, 0x20};
    for (int i = 0; i < 32; ++i) p2wsh.push_back(1);
    CHECK(canonicalize_script(p2wsh).kind == ScriptKind::P2WSH);
    std::vector<std::uint8_t> p2tr = {0x51, 0x20};
    for (int i = 0; i < 32; ++i) p2tr.push_back(2);
    CHECK(canonicalize_script(p2tr).kind == ScriptKind::P2TR);
    // Exotic -> kind 255, total function, deterministic
    auto exotic = mk({0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef});  // OP_RETURN...
    auto r3 = canonicalize_script(exotic);
    CHECK(r3.kind == ScriptKind::RAW && r3.payload.size() == 32);
    CHECK(canonicalize_script(exotic) == r3);
    // kind-255 descriptor must carry the raw script
    PayoutDescriptor d3; d3.pay = r3;
    CHECK(!d3.valid());
    d3.raw_script = exotic;
    CHECK(d3.valid());
    // REVIEW REGRESSIONS: raw_script must BIND to the identity payload
    d3.raw_script.push_back(0x00);          // different script, same payload
    CHECK(!d3.valid());
    d3.raw_script = exotic;
    PayoutDescriptor d3b; d3b.pay = r3; d3b.raw_script = p2pkh;
    CHECK(!d3b.valid());                    // wrong script entirely
    PayoutDescriptor d3c;                   // template smuggled under kind 255
    d3c.pay.kind = ScriptKind::RAW;
    auto th = sha256d(p2pkh);
    d3c.pay.payload.assign(th.begin(), th.end());
    d3c.raw_script = p2pkh;                 // canonicalizes to P2PKH, not RAW
    CHECK(!d3c.valid());
    PayoutDescriptor d3d; d3d.pay = r1; d3d.raw_script = p2pkh;
    CHECK(!d3d.valid());                    // template kinds carry no script
    PayoutDescriptor d3e; d3e.pay = r1;
    d3e.pay.payload.resize(5);              // bad payload width
    CHECK(!d3e.valid());
    // Attribution MUST be absent under V37.0 rules; OK when rule flipped
    PayoutDescriptor d4; d4.pay = r1; d4.attribution = r2;
    CHECK(!d4.valid(false));
    CHECK(d4.valid(true));
    // Aux: sorted unique ok; unsorted / duplicate rejected
    PayoutDescriptor d5; d5.pay = r1;
    d5.aux = {{98, r2}, {99, r2}};
    CHECK(d5.valid());
    d5.aux = {{99, r2}, {98, r2}};
    CHECK(!d5.valid());
    d5.aux = {{98, r2}, {98, r2}};
    CHECK(!d5.valid());
    // Canonical bytes: deterministic; aux changes bytes but NOT identity
    PayoutDescriptor d6; d6.pay = r1;
    PayoutDescriptor d7; d7.pay = r1; d7.aux = {{98, r2}};
    CHECK(d6.canonical_bytes() != d7.canonical_bytes());
    CHECK(d6.identity_key() == d7.identity_key());
}

static void test_roundabout() {
    Roundabout rb;
    rb.add_lane(1, small_params());
    LaneParams p2 = small_params();
    p2.window = 112; p2.c0 = 64; p2.level_caps = {6}; p2.half_life = 32;
    rb.add_lane(2, p2);   // runtime add, different geometry (per-lane params)
    CHECK(rb.lane_count() == 2);

    std::vector<std::uint8_t> p2pkh = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) p2pkh.push_back(static_cast<std::uint8_t>(i));
    p2pkh.push_back(0x88); p2pkh.push_back(0xac);
    PayoutDescriptor d; d.pay = canonicalize_script(p2pkh);

    MinerId m1 = rb.push(1, d, 1000, 0);
    MinerId m2 = rb.push(2, d, 2000, 0);
    CHECK(m1 == m2);  // one identity across lanes (global intern)
    auto agg = rb.aggregate_decayed();
    CHECK(agg.size() == 1 && !agg.begin()->second.is_zero());

    // Invalid descriptor (attribution set) rejected at the boundary
    PayoutDescriptor bad = d;
    bad.attribution = d.pay;
    bool threw = false;
    try { rb.push(1, bad, 1, 0); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);

    rb.remove_lane(2);
    CHECK(rb.lane_count() == 1 && rb.lane(2) == nullptr);
}

// CONSENSUS REGRESSION (C-1): intern ids are node-local — two nodes seeing
// the same per-lane share sequences but a different cross-lane interleaving
// assign different ids to the same miners. The lane digest must be identical
// anyway, because it serializes canonical identity keys, never intern ids.
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

    // Node 1 sees lane 1 first; node 2 sees lane 2 first. Per-lane order is
    // identical (consensus order): lane1 = [dx, dy], lane2 = [dy, dx].
    rb1.push(1, dx, 100, 0); rb1.push(2, dy, 300, 0);
    rb1.push(1, dy, 200, 0); rb1.push(2, dx, 400, 0);

    rb2.push(2, dy, 300, 0); rb2.push(2, dx, 400, 0);
    rb2.push(1, dx, 100, 0); rb2.push(1, dy, 200, 0);

    // Intern ids genuinely diverge between the nodes...
    CHECK(rb1.miners().intern(dx) != rb2.miners().intern(dx));
    // ...but the consensus digests must not.
    CHECK(rb1.lane_digest(1) == rb2.lane_digest(1));
    CHECK(rb1.lane_digest(2) == rb2.lane_digest(2));
    // Sanity: digests still distinguish different lane contents.
    CHECK(!(rb1.lane_digest(1) == rb1.lane_digest(2)));
}

// Guards added by the formal review pass: geometry validation, zero-work
// rejection, public epoch_rebuild misuse, add_lane exception safety, aux
// count bound, geometry committed in the digest.
static void test_review_guards() {
    LaneParams p = small_params();
    {   // window < C0: refused at construction, not a mid-push logic_error
        LaneParams bad = p; bad.window = 64;
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {   // inner level cap below the roll-up factor: refused
        LaneParams bad = p; bad.level_caps = {4, 568};
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {   // no bucket levels at all: refused (eviction needs buckets)
        LaneParams bad = p; bad.level_caps = {};
        bool threw = false;
        try { Lane l(bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {   // zero-work share: refused (digest/rewind exactness)
        Lane l(p);
        bool threw = false;
        try { l.push(0, 0, 0); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
    {   // public epoch_rebuild() off the positional boundary: refused
        Lane l(p);
        l.push(0, 5, 0);
        bool threw = false;
        try { l.epoch_rebuild(); } catch (const std::logic_error&) { threw = true; }
        CHECK(threw);
    }
    {   // add_lane exception safety: failed construction leaves no entry
        Roundabout rb;
        LaneParams bad = p; bad.window = 1;
        bool threw = false;
        try { rb.add_lane(5, bad); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
        CHECK(rb.lane_count() == 0 && rb.lane(5) == nullptr);
        rb.add_lane(5, p);              // chain id is NOT bricked
        CHECK(rb.lane(5) != nullptr);
    }
    {   // aux count beyond the canonical u16 field: invalid
        std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i) s.push_back(1);
        s.push_back(0x88); s.push_back(0xac);
        PayoutDescriptor d; d.pay = canonicalize_script(s);
        d.aux.resize(0x10000);
        for (std::size_t i = 0; i < d.aux.size(); ++i) {
            d.aux[i].chain_id = static_cast<std::uint32_t>(i);
            d.aux[i].ref = d.pay;
        }
        CHECK(!d.valid());
        d.aux.resize(0xffff);
        CHECK(d.valid());
    }
    {   // lane geometry is digest-committed: same pushes, different
        // half_life -> different digests (attributable parameter mismatch)
        LaneParams p2 = p; p2.half_life = 96;
        Lane a(p), b(p2);
        for (int i = 0; i < 50; ++i) { a.push(1, 100, 0); b.push(1, 100, 0); }
        CHECK(!(a.digest(test_key) == b.digest(test_key)));
    }
}

int main() {
    test_sha256();
    test_fixed_point();
    test_headroom_guard();
    // small geometry: 5+ epochs, constant folding + eviction churn
    test_lane_vs_reference(small_params(), 1500, 1234, "small");
    // default OQ-5 geometry: cross two epoch rebuilds (>8192 pushes)
    {
        LaneParams def;  // defaults = ratified OQ-5 values
        test_lane_vs_reference(def, 9500, 99, "default");
    }
    test_digest_and_rewind();
    test_descriptor();
    test_roundabout();
    test_digest_canonical_identity();
    test_review_guards();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
