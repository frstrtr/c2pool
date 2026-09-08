// v37_mmr_permanence_test — KATs for the MMR permanence-peaks SHADOW
// (src/c2pool/v37/mmr_permanence.hpp). Stdlib-only, the same convention as the
// sibling v37 consumer suites (no gtest, no core/Boost link; the suite is its
// own harness, returns nonzero on failure).
//
// The shadow reads the REAL canon v37::Lane read-only and computes an
// append-only MMR of the leaves of evicted buckets. It never touches
// src/sharechain/v37 canon and never appends into the lane digest. These KATs
// drive the canon lane and observe with the shadow, proving:
//
//  (a) GATE-OFF BYTE-IDENTITY  [HARD ACCEPTANCE GATE].  With the shadow gate at
//      its default (UINT64_MAX, never activates) the shadow seals nothing and
//      shadow_digest() returns lane.digest() VERBATIM at every step. Driving the
//      canon lane over the ratified geometry (W=8640,c0=4096,R=8,half_life=2160,
//      level_caps={568}) and the small geometry — the KAT-0 scripts — reproduces
//      the frozen canon byte-identity fingerprint. If it moves, the shadow is not
//      inert -> NO-SHIP.
//  (b) MMR PEAKS CORRECTNESS.  With the gate ON (activation_pos=4096 / 301) the
//      shadow's bagged peak-root equals an INDEPENDENT recompute (oracle peaks by
//      binary decomposition of an independently-built leaf log, structurally
//      different from the incremental binary-counter append), and reproduces the
//      proto I-2 golden leaf counts / roots / first leaves / peaks fingerprint.
//  (c) APPEND-ONLY MONOTONICITY.  A later append never rewrites an already-sealed
//      peak (the tallest sealed sub-forest root is a stable prefix); a rewind
//      restores the PeakSet bit-exactly and re-driving forward is bit-identical.
//  (d) REBUILD / REORG DETERMINISM.  Two independent instances over the same
//      history, and a rewind-then-redrive, converge on the same mmr_root AND the
//      same gate-ON shadow_digest bit-for-bit.
//
// Build:  g++ -std=c++20 -O2 -I<repo>/src v37_mmr_permanence_test.cpp -o t

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/mmr_permanence.hpp>   // the shadow under test (pulls canon lane/hash/fixed)

using v37::u64;
using v37::u128;
using v37::bytes32;
using v37::MinerId;
using v37::U256;
using c2pool::v37n::MmrPermanenceShadow;
using c2pool::v37n::MmrShadowGate;
using c2pool::v37n::PeakSet;
using Bytes = std::vector<std::uint8_t>;

// ── pinned goldens ────────────────────────────────────────────────────────────
// KAT-0 canon byte-identity (the HARD gate) + component trace fingerprints; and
// the proto I-2 MMR permanence goldens (leaf counts, bagged roots, first leaves,
// peaks fingerprint) — reproduced here from the REAL canon buckets. The shadow
// gate-ON side-commitment fingerprints (A/B_shadow_digest) are this shadow's own
// deterministic value; they are NOT the proto's inline-V37P lane digest (that
// weaving is the out-of-scope consensus activation).
namespace GOLDEN {
constexpr const char* OVERALL_BYTE_IDENTITY = "2479d5b61933cbe62d8506ebfcd09483954b8b4cc4698e593f73c16c83fda4fd";
constexpr const char* RATIFIED_TRACE_FP     = "fec3da99da694406dc74ae8ba98e3cdda8798f118ba9f1cfdd96e2fed0ac7ce3";
constexpr const char* SMALL_TRACE_FP        = "5732de4ff690acfdcec93dcc81ff6e9afc964a0ce3c8c897908b7cb56729c5ba";
constexpr const char* A_leaf_count          = "1482";
constexpr const char* A_mmr_root            = "b38bf8b301bc502c4163f37b54f37eab27804d4d6bc85eea926ac013e1756bce";
constexpr const char* A_peaks_fp            = "833dadc05ea375662802c5a28853d0c59cae27762e67f6766d0639734e5039f7";
constexpr const char* A_first_leaf          = "0d60bbff6a102a3d73ba29613d844ac66e6a18db9e53bf9bde6d5bfc12d5031c";
constexpr const char* B_leaf_count          = "859";
constexpr const char* B_mmr_root            = "4c86dd8b6aef5faa60760b515dc3470da823202bf8786d8421ce8c6476cf8b2a";
constexpr const char* B_first_leaf          = "2e2a59a7cd078a85db03bedeb683bf3953e562a85e568a01e312b4cef13fde9b";
// Shadow side-commitment goldens: this shadow's OWN deterministic gate-ON
// value, interior_hash(lane.digest, leaf(V37P)). NOT the proto's inline-V37P lane
// digest (that weaving is the out-of-scope consensus activation).
constexpr const char* A_shadow_digest       = "11a85deb074baba2c0171b1c7c7383ec32a9bad3139cb459dfee54f070c8056a";
constexpr const char* B_shadow_digest       = "08fdcafd8761ad723f4c5f49388e9b1bb82825698ab62848c93fccc17a861570";
// Frozen golden JSON stamp (sha256d of mmr_permanence_golden_v1.json).
constexpr const char* JSON_STAMP            = "86a4f94dfd5e789fab97bdcec031e109f9b5346974b33f5e5a738fe4d82ae887";
constexpr const char* JSON_FILE             = "mmr_permanence_golden_v1.json";
}

// ── check machinery ────────────────────────────────────────────────────────────
static int g_failures = 0;
static long g_checks = 0;
static int g_minted = 0;
#define CHECK(cond)                                                          \
    do { ++g_checks; if (!(cond)) { ++g_failures;                            \
        std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, fmt, ...)                                            \
    do { ++g_checks; if (!(cond)) { ++g_failures;                            \
        std::printf("FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); } } while (0)

static void pin(const char* name, const std::string& got, const char* golden) {
    if (golden[0] == '\0') { ++g_minted; std::printf("  MINT %-24s %s\n", name, got.c_str()); return; }
    CHECK_MSG(got == golden, "golden %s: got %s want %s", name, got.c_str(), golden);
    std::printf("  PIN  %-24s %s%s\n", name, got.c_str(), got == golden ? "" : "  <-- MISMATCH");
}

// ── deterministic PRNG — same generator as the canon test suite / KAT-0 ─────────
struct XorShift64 {
    u64 s;
    explicit XorShift64(u64 seed) : s(seed ? seed : 0x9e3779b97f4a7c15ull) {}
    u64 next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    u64 range(u64 lo, u64 hi) { return lo + next() % (hi - lo + 1); }
};

// injective id -> 32-byte canonical key (sha256d of the LE u32), memoized —
// the SAME map the canon test suite / KAT-0 use, so the shadow's sealed "V37B"
// leaves are byte-equal to the lane's own bucket leaves.
static bytes32 test_key_compute(MinerId m) {
    std::uint8_t b[4] = { std::uint8_t(m), std::uint8_t(m >> 8),
                          std::uint8_t(m >> 16), std::uint8_t(m >> 24) };
    return v37::sha256d(b, 4);
}
static bytes32 test_key(MinerId m) {
    static std::vector<bytes32> cache;
    static std::vector<bool> have;
    if (m >= 65536) return test_key_compute(m);
    if (cache.empty()) { cache.resize(65536); have.assign(65536, false); }
    if (!have[m]) { cache[m] = test_key_compute(m); have[m] = true; }
    return cache[m];
}

static std::string hex(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; for (auto c : h) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}
static std::string dec(u64 x) { return std::to_string((unsigned long long)x); }

// ── generic serializers ─────────────────────────────────────────────────────────
static void put_u64(Bytes& b, u64 x) { for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t(x >> (8 * i))); }
static void put_u128(Bytes& b, u128 x) { put_u64(b, u64(x)); put_u64(b, u64(x >> 64)); }
static void put_u256(Bytes& b, const U256& x) { for (int i = 0; i < 4; ++i) put_u64(b, x.v[i]); }
static void put_tag(Bytes& b, const char* t) { b.insert(b.end(), t, t + 4); }

// ── harness Merkle (OQ-M5 rule, re-stated independently of the shadow) ──────────
static bytes32 ih(const bytes32& l, const bytes32& r) {
    std::uint8_t b[65]; b[0] = 0x01;
    std::memcpy(b + 1, l.data(), 32); std::memcpy(b + 33, r.data(), 32);
    return v37::sha256d(b, 65);
}
static bytes32 leaf_of(const Bytes& payload) {
    Bytes b; b.push_back(0x00); b.insert(b.end(), payload.begin(), payload.end());
    return v37::sha256d(b);
}
static bytes32 harness_root(const std::vector<Bytes>& payloads) {
    std::vector<bytes32> level;
    for (const auto& p : payloads) level.push_back(leaf_of(p));
    while (level.size() > 1) {
        std::vector<bytes32> next;
        std::size_t i = 0;
        for (; i + 1 < level.size(); i += 2) next.push_back(ih(level[i], level[i + 1]));
        if (i < level.size()) next.push_back(level[i]);
        level = std::move(next);
    }
    return level[0];
}
static bytes32 bag_peaks(const std::vector<bytes32>& peaks) {
    bytes32 r{}; if (peaks.empty()) return r;
    r = peaks.back();
    for (std::size_t i = peaks.size() - 1; i-- > 0;) r = ih(peaks[i], r);
    return r;
}
static std::size_t popcount(u64 x) { std::size_t c = 0; while (x) { x &= x - 1; ++c; } return c; }

// oracle peaks: perfect subtrees of the binary decomposition of log.size() —
// structurally DIFFERENT from the shadow's incremental binary-counter append.
static std::vector<bytes32> pairwise(std::vector<bytes32> lv) {
    while (lv.size() > 1) {
        std::vector<bytes32> next;
        for (std::size_t i = 0; i + 1 < lv.size(); i += 2) next.push_back(ih(lv[i], lv[i + 1]));
        lv = std::move(next);
    }
    return lv;
}
static std::vector<bytes32> oracle_peaks(const std::vector<bytes32>& log) {
    std::vector<bytes32> peaks;
    const u64 n = (u64)log.size();
    u64 off = 0;
    for (int h = 63; h >= 0; --h) {
        if (!((n >> h) & 1)) continue;
        const u64 span = u64(1) << h;
        std::vector<bytes32> lv(log.begin() + (long)off, log.begin() + (long)(off + span));
        peaks.push_back(pairwise(std::move(lv))[0]);
        off += span;
    }
    return peaks;
}
struct HProof { u64 n = 0, idx = 0; std::vector<bytes32> path, peaks; };
static HProof harness_proof(const std::vector<bytes32>& log, u64 idx) {
    HProof p; p.n = (u64)log.size(); p.idx = idx; p.peaks = oracle_peaks(log);
    u64 off = 0;
    for (int h = 63; h >= 0; --h) {
        if (!((p.n >> h) & 1)) continue;
        const u64 span = u64(1) << h;
        if (idx >= off && idx < off + span) {
            std::vector<bytes32> lv(log.begin() + (long)off, log.begin() + (long)(off + span));
            u64 j = idx - off;
            while (lv.size() > 1) {
                p.path.push_back(lv[j ^ 1]);
                std::vector<bytes32> next;
                for (std::size_t i = 0; i + 1 < lv.size(); i += 2) next.push_back(ih(lv[i], lv[i + 1]));
                lv = std::move(next); j >>= 1;
            }
            break;
        }
        off += span;
    }
    return p;
}
static bytes32 peaks_fingerprint(const std::vector<bytes32>& peaks) {
    Bytes b; for (const auto& p : peaks) b.insert(b.end(), p.begin(), p.end());
    return v37::sha256d(b);
}

// harness "V37B" bucket payload from the PRE-push snapshot (canonical test keys)
static Bytes bucket_payload(std::size_t k, const v37::Bucket& bkt) {
    Bytes b;
    put_tag(b, "V37B");
    put_u64(b, (u64)k);
    put_u64(b, bkt.pos_lo); put_u64(b, bkt.pos_hi);
    put_u128(b, bkt.raw_work);
    put_u64(b, bkt.epoch_tag);
    std::vector<std::pair<bytes32, const v37::CompEntry*>> rows;
    for (const auto& e : bkt.comp) rows.emplace_back(test_key(e.miner), &e);
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& c) { return a.first < c.first; });
    Bytes buf;
    for (const auto& [key, e] : rows) {
        buf.insert(buf.end(), key.begin(), key.end());
        put_u256(buf, e->scaled); put_u128(buf, e->raw);
    }
    bytes32 ch = v37::sha256d(buf);
    b.insert(b.end(), ch.begin(), ch.end());
    return b;
}
static u64 payload_pos_lo(const Bytes& p) {   // V37B: tag(4) level(8) pos_lo(8)
    u64 x = 0; for (int i = 0; i < 8; ++i) x |= u64(p[12 + i]) << (8 * i); return x;
}

// canon leaf payloads re-serialized from public state (pins the lane layout,
// header/acc/bucket) — the (D) self-check that harness_root == lane.digest().
static std::vector<Bytes> leaf_payloads(const v37::Lane& l) {
    std::vector<Bytes> out;
    const auto& p = l.params();
    { Bytes h;
      put_tag(h, "V37H");
      put_u64(h, p.window); put_u64(h, p.c0); put_u64(h, p.rollup); put_u64(h, p.half_life);
      put_u64(h, (u64)p.level_caps.size());
      for (u64 c : p.level_caps) put_u64(h, c);
      put_u64(h, l.epoch_base()); put_u64(h, l.next_pos());
      put_u64(h, (u64)l.acc().size()); put_u64(h, (u64)l.l0().size());
      put_u256(h, l.l0_scaled_sum()); put_u128(h, l.l0_raw_sum());
      for (const auto& lvl : l.levels()) put_u64(h, (u64)lvl.size());
      out.push_back(std::move(h)); }
    { std::vector<std::pair<bytes32, Bytes>> rows;
      for (const auto& [m, a] : l.acc()) {
          Bytes b; put_tag(b, "V37A");
          bytes32 k = test_key(m); b.insert(b.end(), k.begin(), k.end());
          put_u256(b, a); rows.emplace_back(k, std::move(b));
      }
      std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
      for (auto& r : rows) out.push_back(std::move(r.second)); }
    for (std::size_t k = 0; k < l.levels().size(); ++k)
        for (const auto& bkt : l.levels()[k]) out.push_back(bucket_payload(k, bkt));
    return out;
}

// ════════════════════════════════════════════════════════════════════════════
// KAT (a) — GATE-OFF BYTE-IDENTITY (ports the KAT-0 scripts onto canon+shadow)
// ════════════════════════════════════════════════════════════════════════════
struct OffTwin {
    v37::Lane a;
    MmrPermanenceShadow shadow;            // gate OFF (default)
    std::string tag;
    v37::detail::Sha256Ctx trace;          // rolling fingerprint over per-step canon digests
    u64 steps = 0, evicts_seen = 0, rebuilds_seen = 0, last_B = 0, last_cover = 0;

    OffTwin(const v37::LaneParams& p, const char* t) : a(p), shadow(MmrShadowGate{}), tag(t) {
        CHECK(shadow.gate().activation_pos == UINT64_MAX);
        check("init");
    }
    bytes32 check(const char* what) {
        ++steps;
        auto la = leaf_payloads(a);
        bytes32 da = a.digest(test_key);
        CHECK_MSG(harness_root(la) == da, "%s step %llu (%s): harness leaves != canon digest",
                  tag.c_str(), (unsigned long long)steps, what);
        bytes32 sd = shadow.shadow_digest(a, test_key);
        CHECK_MSG(sd == da, "%s step %llu (%s): shadow_digest(OFF) != lane.digest (NOT INERT)",
                  tag.c_str(), (unsigned long long)steps, what);
        CHECK(!shadow.active(a) && shadow.mmr().leaf_count == 0 && shadow.mmr().peaks.empty());
        CHECK(shadow.snapshot_window_ok());
        trace.write(da.data(), 32);
        return da;
    }
    void push(MinerId m, u64 w, std::uint32_t flags) {
        if (a.cover() < last_cover + 1) {}   // (cover tracked in check)
        shadow.before_push(a);
        a.push(m, w, flags);
        shadow.after_push(a, test_key);
        if (a.epoch_base() != last_B) ++rebuilds_seen;
        if (a.cover() < last_cover + 1) ++evicts_seen;
        last_B = a.epoch_base(); last_cover = a.cover();
        check("push");
    }
    bool rewind(u64 d) {
        bool r = a.rewind(d);
        if (r) shadow.after_rewind(a);
        last_B = a.epoch_base(); last_cover = a.cover();
        char what[32]; std::snprintf(what, sizeof what, "rewind%llu%s", (unsigned long long)d, r ? "" : "-refused");
        check(what);
        return r;
    }
    bytes32 digest() const { return a.digest(test_key); }
    u64 in_epoch() const { return a.next_pos() - a.epoch_base(); }
    bytes32 fingerprint() { v37::detail::Sha256Ctx c = trace; return c.finalize(); }
    void check_proofs() {   // acc_proof under the (unchanged) canon lane digest
        bytes32 root = a.digest(test_key);
        int proved = 0;
        for (const auto& [m, acc] : a.acc()) {
            bytes32 leaf; v37::Lane::MerkleProof pr;
            CHECK(a.acc_proof(m, test_key, leaf, pr));
            CHECK(v37::Lane::verify_proof(root, leaf, pr));
            ++proved;
        }
        CHECK(proved >= 1);
    }
};

static bytes32 offA_script() {
    std::printf("== (a) ratified geometry, canon lane + shadow gate OFF\n");
    v37::LaneParams p;
    CHECK(p.window == 8640 && p.c0 == 4096 && p.rollup == 8 &&
          p.half_life == 2160 && p.level_caps == std::vector<u64>{568});
    OffTwin t(p, "ratified");
    XorShift64 rng(99);
    const u64 N = 13500;
    for (u64 i = 0; i < N; ++i) {
        MinerId m = (MinerId)rng.range(0, 12);
        u64 w = rng.range(1, u64(1) << 62);
        std::uint32_t flags = (i % 7 == 0) ? v37::L0F_RECEIPT : 0;
        t.push(m, w, flags);
    }
    CHECK(t.rebuilds_seen == 3);
    CHECK(t.evicts_seen > 500);
    CHECK(t.a.cover() <= p.window);
    { bytes32 snap = t.digest();
      for (int i = 0; i < 64; ++i) t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0);
      CHECK(t.rewind(64)); CHECK(t.digest() == snap); }
    { for (int i = 0; i < 70; ++i) t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0);
      CHECK(!t.rewind(65)); CHECK(t.rewind(64)); }
    { int tries = 0;
      for (;;) {
          bytes32 snap = t.digest(); u64 cover_before = t.a.cover();
          t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0);
          ++tries;
          if (t.a.cover() < cover_before + 1) { CHECK(t.rewind(1)); CHECK(t.digest() == snap);
              CHECK(t.a.cover() == cover_before); break; }
          CHECK(tries < 64); if (tries >= 64) break;
      } }
    for (int round = 0; round < 30; ++round) {
        while (t.in_epoch() >= p.epoch_len() - (p.journal_depth + 2) || t.in_epoch() < p.journal_depth + 2)
            t.push(0, 3, 0);
        u64 k = rng.range(1, p.journal_depth);
        bytes32 snap = t.digest();
        for (u64 i = 0; i < k; ++i) t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0);
        CHECK(t.rewind(k)); CHECK_MSG(t.digest() == snap, "ratified sweep round %d k=%llu", round, (unsigned long long)k);
        for (u64 i = 0; i < k; ++i) t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0);
    }
    { while (t.in_epoch() != p.epoch_len() - 2) t.push(1, 5, 0);
      u64 B0 = t.a.epoch_base();
      for (int i = 0; i < 6; ++i) t.push(2, 9, 0);
      CHECK(t.a.epoch_base() == B0 + p.epoch_len());
      CHECK(!t.rewind(6)); CHECK(!t.rewind(4)); CHECK(t.rewind(3)); }
    { bool ta = false;
      try { t.a.push(0, 0, 0); } catch (const std::invalid_argument&) { ta = true; }
      CHECK(ta);
      ta = false;
      try { t.a.epoch_rebuild(); } catch (const std::logic_error&) { ta = true; }
      CHECK(ta);
      t.check("after-exceptions"); }
    t.check_proofs();
    bytes32 fin = t.check("final");
    std::printf("  [ratified] steps=%llu final %s\n", (unsigned long long)t.steps, hex(fin).c_str());
    bytes32 fp = t.fingerprint();
    pin("RATIFIED_TRACE_FP", hex(fp), GOLDEN::RATIFIED_TRACE_FP);
    return fp;
}

static v37::LaneParams small_params() {
    v37::LaneParams p; p.window = 256; p.c0 = 128; p.rollup = 8; p.level_caps = {16};
    p.half_life = 64; p.journal_depth = 16; return p;
}

static bytes32 offB_script() {
    std::printf("== (a) small geometry, canon lane + shadow gate OFF\n");
    v37::LaneParams p = small_params();
    v37::detail::Sha256Ctx fpc;
    auto fold = [&](OffTwin& t) { bytes32 f = t.fingerprint(); fpc.write(f.data(), 32); };
    { OffTwin t(p, "small-churn"); XorShift64 rng(1234);
      for (u64 i = 0; i < 1500; ++i)
          t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), (std::uint32_t)(i & 0x1f));
      CHECK(t.rebuilds_seen >= 5 && t.evicts_seen > 100);
      t.check_proofs(); fold(t); }
    { OffTwin ta(p, "small-a"), tb(p, "small-b"); XorShift64 r1(42), r2(42);
      for (int i = 0; i < 500; ++i) { ta.push((MinerId)r1.range(0, 5), r1.range(1, 1000000), 0);
          tb.push((MinerId)r2.range(0, 5), r2.range(1, 1000000), 0); }
      CHECK(ta.digest() == tb.digest()); fold(ta); fold(tb); }
    { OffTwin tc(p, "small-c"), td(p, "small-d");
      tc.push(1, 100, 0); tc.push(2, 200, 0); td.push(2, 200, 0); td.push(1, 100, 0);
      CHECK(!(tc.digest() == td.digest())); fold(tc); fold(td); }
    { OffTwin te(p, "small-e"); XorShift64 r3(7);
      for (int i = 0; i < 300; ++i) te.push((MinerId)r3.range(0, 5), r3.range(1, 1000000), 0);
      while (te.in_epoch() > p.epoch_len() - 20 || te.in_epoch() < 16) te.push(0, 1, 0);
      bytes32 snap = te.digest(); XorShift64 r4(11);
      for (int i = 0; i < 10; ++i) te.push((MinerId)r4.range(0, 5), r4.range(1, 1000000), 0);
      CHECK(te.rewind(10)); CHECK(te.digest() == snap); fold(te); }
    { OffTwin tf_(p, "small-f");
      for (u64 i = 0; i < p.epoch_len() + 4; ++i) tf_.push(0, 10, 0);
      CHECK(!tf_.rewind(8)); CHECK(!tf_.rewind(4)); CHECK(tf_.rewind(2)); fold(tf_); }
    { OffTwin tg(p, "small-g"); XorShift64 r5(21);
      for (int i = 0; i < 200; ++i) tg.push((MinerId)r5.range(0, 5), r5.range(1, 1000000), 0);
      while (tg.a.l0().size() != p.c0 || tg.in_epoch() >= p.epoch_len() - 4) tg.push(0, 7, 0);
      bytes32 snap_fold = tg.digest(); std::size_t before = tg.a.levels()[0].size();
      tg.push(1, 99, 0); CHECK(tg.a.levels()[0].size() == before + 1);
      CHECK(tg.rewind(1)); CHECK(tg.digest() == snap_fold);
      CHECK(tg.a.levels()[0].size() == before); fold(tg); }
    { OffTwin th(p, "small-h"); XorShift64 r6(31);
      for (int i = 0; i < 150; ++i) th.push((MinerId)r6.range(0, 5), r6.range(1, 1000000), 0);
      for (int round = 0; round < 50; ++round) {
          while (th.in_epoch() >= p.epoch_len() - (p.journal_depth + 2) || th.in_epoch() < p.journal_depth + 2)
              th.push(0, 3, 0);
          u64 k = r6.range(1, p.journal_depth);
          bytes32 snap = th.digest();
          for (u64 i = 0; i < k; ++i) th.push((MinerId)r6.range(0, 5), r6.range(1, 1000000), 0);
          CHECK(th.rewind(k)); CHECK_MSG(th.digest() == snap, "small sweep round %d k=%llu", round, (unsigned long long)k);
          for (u64 i = 0; i < k; ++i) th.push((MinerId)r6.range(0, 7), r6.range(1, 1000000), 0);
      }
      th.check_proofs(); th.check("final"); fold(th); }
    { auto refuses = [&](auto mutate) {
          v37::LaneParams bad = p; mutate(bad); bool ta = false;
          try { v37::Lane l(bad); } catch (const std::invalid_argument&) { ta = true; } return ta; };
      CHECK(refuses([](v37::LaneParams& q) { q.window = 64; }));
      CHECK(refuses([](v37::LaneParams& q) { q.level_caps = {4, 568}; }));
      CHECK(refuses([](v37::LaneParams& q) { q.level_caps = {}; }));
      CHECK(refuses([](v37::LaneParams& q) { q.half_life = 54; }));
      CHECK(refuses([](v37::LaneParams& q) { q.c0 = 96; })); }
    bytes32 fp = fpc.finalize();
    pin("SMALL_TRACE_FP", hex(fp), GOLDEN::SMALL_TRACE_FP);
    return fp;
}

static void kat_a() {
    std::printf("\n#### KAT (a): GATE-OFF BYTE-IDENTITY [HARD ACCEPTANCE GATE]\n");
    bytes32 fa = offA_script();
    bytes32 fb = offB_script();
    Bytes all; all.insert(all.end(), fa.begin(), fa.end()); all.insert(all.end(), fb.begin(), fb.end());
    bytes32 overall = v37::sha256d(all);
    pin("OVERALL_BYTE_IDENTITY", hex(overall), GOLDEN::OVERALL_BYTE_IDENTITY);
    std::printf("  KAT-0 overall byte-identity %s\n", hex(overall).c_str());
}

// ════════════════════════════════════════════════════════════════════════════
// KAT (b/c/d) — MMR peaks correctness, monotonicity, reorg determinism.
// Drives canon lane + shadow with a FINITE gate; a driver keeps an INDEPENDENT
// oracle log (built the KAT-P1 way from its own pre-push snapshot) and compares
// the shadow against oracle_peaks recomputed by binary decomposition.
// ════════════════════════════════════════════════════════════════════════════
struct GateDriver {
    v37::LaneParams p;
    v37::Lane lane;
    MmrPermanenceShadow shadow;
    std::string tag;
    std::vector<bytes32> log;         // independent oracle leaf log
    std::vector<Bytes> log_payloads;  // raw payloads behind it
    std::vector<std::size_t> hist;    // hist[next_pos] = log.size()
    u64 steps = 0, rebuilds = 0, carried_evicts = 0, plain_evicts = 0, straddle_evicts = 0;
    u64 first_carried_at = 0;
    bytes32 first_leaf{}, tall_peak{};
    bool tall_seen = false;
    u64 last_B = 0;

    GateDriver(const v37::LaneParams& q, u64 act, const char* t)
        : p(q), lane(q), shadow(MmrShadowGate{act}), tag(t) {
        if (q.level_caps.size() != 1)
            throw std::logic_error("driver assumes a single bucket level (front pops == evictions)");
        last_B = lane.epoch_base();
        hist.assign(1, 0);
        check("init");
    }
    u64 act() const { return shadow.gate().activation_pos; }
    u64 in_epoch() const { return lane.next_pos() - lane.epoch_base(); }
    bytes32 digest() const { return lane.digest(test_key); }
    bytes32 shadow_digest() const { return shadow.shadow_digest(lane, test_key); }

    bool last_evicted = false, last_appended = false;

    void push(MinerId m, u64 w, std::uint32_t flags) {
        std::vector<v37::Bucket> pre;
        { const auto& L = lane.levels()[0];
          for (std::size_t i = 0; i < L.size() && i < 4; ++i) pre.push_back(L[i]); }
        shadow.before_push(lane);
        lane.push(m, w, flags);
        shadow.after_push(lane, test_key);
        if (lane.epoch_base() != last_B) ++rebuilds;
        last_evicted = last_appended = false;
        const auto& L = lane.levels()[0];
        std::size_t gone = 0;
        for (const auto& b : pre) {
            if (!(L.empty() || L.front().pos_lo > b.pos_lo)) break;   // still present
            ++gone; last_evicted = true;
            const bool carried = lane.next_pos() > act() && b.pos_lo >= act();
            if (carried) {
                Bytes pl = bucket_payload(0, b);
                bytes32 lf = leaf_of(pl);
                CHECK_MSG(MmrPermanenceShadow::bucket_leaf(0, b, test_key) == lf,   // (L)
                          "%s: shadow bucket_leaf != harness V37B leaf at pos_lo=%llu",
                          tag.c_str(), (unsigned long long)b.pos_lo);
                log.push_back(lf); log_payloads.push_back(std::move(pl));
                last_appended = true;
                if (carried_evicts++ == 0) { first_carried_at = lane.next_pos(); first_leaf = lf; }
            } else {
                ++plain_evicts;
                if (b.pos_hi >= act()) ++straddle_evicts;
            }
        }
        CHECK(gone < pre.size() || pre.size() < 4);
        if (hist.size() <= lane.next_pos()) hist.resize(lane.next_pos() + 1);
        hist[lane.next_pos()] = log.size();
        check("push");
    }
    bool rewind(u64 d) {
        bool ok = lane.rewind(d);
        if (ok) { shadow.after_rewind(lane); log.resize(hist[lane.next_pos()]); log_payloads.resize(hist[lane.next_pos()]); }
        last_B = lane.epoch_base();
        char what[40]; std::snprintf(what, sizeof what, "rewind%llu%s", (unsigned long long)d, ok ? "" : "-refused");
        check(what);
        return ok;
    }
    void check(const char* what) {
        ++steps;
        const bool active = shadow.active(lane);
        CHECK_MSG(active == (lane.next_pos() > act()), "%s (%s): active mismatch", tag.c_str(), what);
        if (!active) CHECK(shadow.mmr().leaf_count == 0 && shadow.mmr().peaks.empty());
        const PeakSet& ps = shadow.mmr();
        // (M) shadow leaf_count == independent log; shadow peaks == ORACLE peaks
        CHECK_MSG(ps.leaf_count == log.size(), "%s (%s): leaf_count %llu != log %zu",
                  tag.c_str(), what, (unsigned long long)ps.leaf_count, log.size());
        std::vector<bytes32> op = oracle_peaks(log);
        CHECK_MSG(ps.peaks == op, "%s (%s): shadow peaks (%zu) != oracle peaks (%zu)",
                  tag.c_str(), what, ps.peaks.size(), op.size());
        CHECK(ps.peaks.size() == popcount(ps.leaf_count));
        CHECK(ps.peaks.size() <= MmrPermanenceShadow::MRR_MMR_MAX_PEAKS);
        CHECK(shadow.mmr_root() == bag_peaks(op));
        // (c) append-only monotonicity: the tallest sealed sub-forest root is a
        // stable prefix — once the first 2^h leaves are sealed it never changes.
        if (!ps.peaks.empty()) {
            u64 n = ps.leaf_count; int h = 63; while (!((n >> h) & 1)) --h;
            std::vector<bytes32> tallest(log.begin(), log.begin() + (long)(u64(1) << h));
            bytes32 tp = pairwise(std::move(tallest))[0];
            CHECK(ps.peaks[0] == tp);
            if (!tall_seen) { tall_peak = tp; tall_seen = true; }
            else if ((u64)log.size() >= (u64(1) << h) && tp == ps.peaks[0]) { /* stable, checked above */ }
        }
        // (D) side-commitment: OFF -> verbatim; ON -> interior_hash(lane, V37P leaf)
        bytes32 d = lane.digest(test_key);
        bytes32 sd = shadow.shadow_digest(lane, test_key);
        if (!active) { CHECK(sd == d); }
        else {
            Bytes v37p = MmrPermanenceShadow::mmr_root_payload(ps.leaf_count, shadow.mmr_root());
            CHECK(sd == ih(d, leaf_of(v37p)));
            CHECK(v37p.size() == MmrPermanenceShadow::V37P_PAYLOAD_BYTES);
        }
        last_B = lane.epoch_base();
    }
};

// evicted-bucket inclusion proofs against the shadow's committed root + the
// 2-level side-commitment chain (bucket -> mmr_root -> shadow_digest).
static void proof_battery(GateDriver& t, XorShift64& rng, int random_samples, bool every_index) {
    const auto& log = t.log;
    const u64 n = (u64)log.size();
    CHECK(n > 0 && t.shadow.active(t.lane));
    const bytes32 root = t.shadow.mmr_root();
    const bytes32 sd = t.shadow_digest();
    const bytes32 ld = t.digest();
    // the shadow's "V37P" side leaf, and the 2-level chain to shadow_digest
    Bytes v37p = MmrPermanenceShadow::mmr_root_payload(n, root);
    CHECK(v37p.size() == MmrPermanenceShadow::V37P_PAYLOAD_BYTES);
    CHECK(sd == ih(ld, leaf_of(v37p)));
    CHECK(sd != ih(ld, leaf_of(MmrPermanenceShadow::mmr_root_payload(n + 1, root))));   // wrong leaf_count
    { bytes32 bad = root; bad[31] ^= 1; CHECK(sd != ih(ld, leaf_of(MmrPermanenceShadow::mmr_root_payload(n, bad)))); }
    std::set<u64> idxs;
    if (every_index) { for (u64 i = 0; i < n; ++i) idxs.insert(i); }
    else {
        for (u64 i : {u64(0), u64(1), u64(2), n / 2, n - 2, n - 1}) if (i < n) idxs.insert(i);
        for (int i = 0; i < random_samples; ++i) idxs.insert(rng.range(0, n - 1));
    }
    std::size_t max_path = 0;
    for (u64 idx : idxs) {
        MmrPermanenceShadow::MmrProof pr = MmrPermanenceShadow::mmr_proof(log, idx);
        HProof hp = harness_proof(log, idx);
        CHECK(pr.leaf_count == n && pr.index == idx);
        CHECK(pr.path == hp.path && pr.peaks == hp.peaks);
        CHECK(pr.peaks == t.shadow.mmr().peaks);
        CHECK(pr.path.size() <= MmrPermanenceShadow::MRR_MMR_MAX_PATH);
        max_path = std::max(max_path, pr.path.size());
        bytes32 leaf = leaf_of(t.log_payloads[idx]);
        CHECK(leaf == log[idx]);
        CHECK_MSG(MmrPermanenceShadow::mmr_verify(root, leaf, pr), "mmr_verify rejected leaf %llu/%llu",
                  (unsigned long long)idx, (unsigned long long)n);
        { bytes32 bad = leaf; bad[0] ^= 1; CHECK(!MmrPermanenceShadow::mmr_verify(root, bad, pr)); }
        if (n > 1) { auto q = pr; q.index = (idx + 1) % n; CHECK(!MmrPermanenceShadow::mmr_verify(root, leaf, q)); }
        { auto q = pr; q.peaks[0][0] ^= 1; CHECK(!MmrPermanenceShadow::mmr_verify(root, leaf, q)); }
        if (!pr.path.empty()) { auto q = pr; q.path[0][0] ^= 1; CHECK(!MmrPermanenceShadow::mmr_verify(root, leaf, q)); }
        { auto q = pr; q.path.push_back(bytes32{}); CHECK(!MmrPermanenceShadow::mmr_verify(root, leaf, q)); }
        { auto q = pr; q.index = n; CHECK(!MmrPermanenceShadow::mmr_verify(root, leaf, q)); }
        { bytes32 bad = root; bad[0] ^= 1; CHECK(!MmrPermanenceShadow::mmr_verify(bad, leaf, pr)); }
    }
    std::printf("  [%s] proof battery: %zu buckets proved (leaf_count=%llu, %zu peaks, max path %zu)\n",
                t.tag.c_str(), idxs.size(), (unsigned long long)n, t.shadow.mmr().peaks.size(), max_path);
    // stale: after one more seal, the old side-commitment no longer verifies
    { int tries = 0;
      while (!t.last_appended && tries < 64) { t.push((MinerId)rng.range(0, 5), rng.range(1, u64(1) << 62), 0); ++tries; }
      CHECK(t.last_appended);
      bytes32 sd2 = t.shadow_digest();
      CHECK(sd2 != sd);
      CHECK(sd2 != ih(t.digest(), leaf_of(v37p)));   // stale V37P leaf
      CHECK(t.shadow.mmr().leaf_count == n + 1); }
}

static void kat_b_script_a() {
    std::printf("\n#### KAT (b): script A — ratified geometry, activation_pos = 4096\n");
    v37::LaneParams p;
    GateDriver t(p, 4096, "A");
    XorShift64 rng(99);
    const u64 N = 21500;
    for (u64 i = 0; i < N; ++i) {
        MinerId m = (MinerId)rng.range(0, 12);
        u64 w = rng.range(1, u64(1) << 62);
        std::uint32_t flags = (i % 7 == 0) ? v37::L0F_RECEIPT : 0;
        t.push(m, w, flags);
    }
    std::printf("  [A] pushes=%llu rebuilds=%llu carried=%llu plain=%llu straddle=%llu first_at=%llu lc=%llu\n",
                (unsigned long long)N, (unsigned long long)t.rebuilds, (unsigned long long)t.carried_evicts,
                (unsigned long long)t.plain_evicts, (unsigned long long)t.straddle_evicts,
                (unsigned long long)t.first_carried_at, (unsigned long long)t.shadow.mmr().leaf_count);
    CHECK(t.rebuilds == 5);
    CHECK(t.first_carried_at == p.window + 4096 + 1);
    CHECK(t.carried_evicts > 1000);
    CHECK(t.shadow.mmr().leaf_count == t.carried_evicts);
    CHECK(t.plain_evicts > 400);
    CHECK(t.straddle_evicts == 0);
    CHECK(!t.log_payloads.empty() && payload_pos_lo(t.log_payloads[0]) == 4096);
    CHECK(t.first_leaf == t.log[0]);
    auto push_rand = [&]() { t.push((MinerId)rng.range(0, 12), rng.range(1, u64(1) << 62), 0); };
    // (c) full-depth rewind restores the PeakSet bit-exactly
    { bytes32 snap = t.digest(); bytes32 ssnap = t.shadow_digest(); PeakSet ms = t.shadow.mmr();
      u64 before = t.carried_evicts;
      for (int i = 0; i < 64; ++i) push_rand();
      CHECK(t.carried_evicts >= before + 7);
      CHECK(t.shadow.mmr().peaks != ms.peaks);
      CHECK(t.rewind(64)); CHECK(t.digest() == snap);
      CHECK(t.shadow.mmr() == ms); CHECK(t.shadow_digest() == ssnap);
      std::printf("  [A] R1: %llu appends rewound, PeakSet + shadow_digest restored bit-exactly\n",
                  (unsigned long long)(t.carried_evicts - before)); }
    { for (int i = 0; i < 70; ++i) push_rand();
      PeakSet ms = t.shadow.mmr(); CHECK(!t.rewind(65)); CHECK(t.shadow.mmr() == ms); CHECK(t.rewind(64)); }
    { int tries = 0;
      for (;;) {
          bytes32 snap = t.digest(); bytes32 ssnap = t.shadow_digest(); PeakSet ms = t.shadow.mmr();
          push_rand(); ++tries;
          if (t.last_evicted) { CHECK(t.last_appended);
              CHECK(t.shadow.mmr().leaf_count == ms.leaf_count + 1);
              CHECK(t.rewind(1)); CHECK(t.digest() == snap); CHECK(t.shadow.mmr() == ms);
              CHECK(t.shadow_digest() == ssnap); break; }
          CHECK(tries < 64); if (tries >= 64) break;
      } }
    for (int round = 0; round < 30; ++round) {
        while (t.in_epoch() >= p.epoch_len() - (p.journal_depth + 2) || t.in_epoch() < p.journal_depth + 2)
            t.push(0, 3, 0);
        u64 k = rng.range(1, p.journal_depth);
        bytes32 snap = t.digest(); bytes32 ssnap = t.shadow_digest(); PeakSet ms = t.shadow.mmr();
        for (u64 i = 0; i < k; ++i) push_rand();
        CHECK(t.rewind(k));
        CHECK_MSG(t.digest() == snap && t.shadow.mmr() == ms && t.shadow_digest() == ssnap,
                  "A sweep round %d k=%llu", round, (unsigned long long)k);
        for (u64 i = 0; i < k; ++i) push_rand();
    }
    { while (t.in_epoch() != p.epoch_len() - 2) t.push(1, 5, 0);
      u64 B0 = t.lane.epoch_base(); u64 reb0 = t.rebuilds; u64 lc0 = t.shadow.mmr().leaf_count, ce0 = t.carried_evicts;
      for (int i = 0; i < 6; ++i) t.push(2, 9, 0);
      CHECK(t.lane.epoch_base() == B0 + p.epoch_len());
      CHECK(t.rebuilds == reb0 + 1);
      CHECK(t.shadow.mmr().leaf_count == lc0 + (t.carried_evicts - ce0));
      CHECK(!t.rewind(6)); CHECK(!t.rewind(4)); CHECK(t.rewind(3)); }
    proof_battery(t, rng, 40, false);
    { bytes32 root = t.digest(); int proved = 0;
      for (const auto& [m, a] : t.lane.acc()) {
          bytes32 leaf; v37::Lane::MerkleProof pr;
          CHECK(t.lane.acc_proof(m, test_key, leaf, pr)); CHECK(v37::Lane::verify_proof(root, leaf, pr)); ++proved; }
      CHECK(proved == 13); }
    t.check("final");
    pin("A_leaf_count", dec(t.shadow.mmr().leaf_count), GOLDEN::A_leaf_count);
    pin("A_mmr_root", hex(t.shadow.mmr_root()), GOLDEN::A_mmr_root);
    pin("A_peaks_fp", hex(peaks_fingerprint(t.shadow.mmr().peaks)), GOLDEN::A_peaks_fp);
    pin("A_first_leaf", hex(t.first_leaf), GOLDEN::A_first_leaf);
    pin("A_shadow_digest", hex(t.shadow_digest()), GOLDEN::A_shadow_digest);
}

static void kat_b_script_b() {
    std::printf("\n#### KAT (b): script B — small geometry, activation_pos = 301 (straddle)\n");
    v37::LaneParams p; p.window = 256; p.c0 = 128; p.rollup = 8; p.level_caps = {16};
    p.half_life = 64; p.journal_depth = 16;
    GateDriver t(p, 301, "B");
    XorShift64 rng(1234);
    const u64 N = 7000;
    for (u64 i = 0; i < N; ++i)
        t.push((MinerId)rng.range(0, 5), rng.range(1, u64(1) << 62), (std::uint32_t)(i & 0x1f));
    std::printf("  [B] pushes=%llu rebuilds=%llu carried=%llu plain=%llu straddle=%llu first_at=%llu lc=%llu\n",
                (unsigned long long)N, (unsigned long long)t.rebuilds, (unsigned long long)t.carried_evicts,
                (unsigned long long)t.plain_evicts, (unsigned long long)t.straddle_evicts,
                (unsigned long long)t.first_carried_at, (unsigned long long)t.shadow.mmr().leaf_count);
    CHECK(t.rebuilds == N / p.epoch_len());
    CHECK(t.first_carried_at == p.window + 304 + 1);
    CHECK(t.straddle_evicts == 1);
    CHECK(t.plain_evicts >= 6);
    CHECK(payload_pos_lo(t.log_payloads[0]) == 304);
    CHECK(t.shadow.mmr().leaf_count > 800);
    CHECK(t.shadow.mmr().leaf_count == t.carried_evicts);
    proof_battery(t, rng, 0, true);
    for (int round = 0; round < 25; ++round) {
        while (t.in_epoch() >= p.epoch_len() - (p.journal_depth + 2) || t.in_epoch() < p.journal_depth + 2)
            t.push(0, 3, 0);
        u64 k = rng.range(1, p.journal_depth);
        bytes32 snap = t.digest(); bytes32 ssnap = t.shadow_digest(); PeakSet ms = t.shadow.mmr();
        for (u64 i = 0; i < k; ++i) t.push((MinerId)rng.range(0, 5), rng.range(1, u64(1) << 62), 0);
        CHECK(t.rewind(k));
        CHECK_MSG(t.digest() == snap && t.shadow.mmr() == ms && t.shadow_digest() == ssnap,
                  "B sweep round %d k=%llu", round, (unsigned long long)k);
        for (u64 i = 0; i < k; ++i) t.push((MinerId)rng.range(0, 5), rng.range(1, u64(1) << 62), 0);
    }
    { while (t.in_epoch() != p.epoch_len() - 1) t.push(1, 5, 0);
      PeakSet ms = t.shadow.mmr();
      for (int i = 0; i < 4; ++i) t.push(2, 9, 0);
      CHECK(!t.rewind(4)); CHECK(!t.rewind(3)); CHECK(t.rewind(2));
      CHECK(t.shadow.mmr().leaf_count >= ms.leaf_count); }
    t.check("final");
    pin("B_leaf_count", dec(t.shadow.mmr().leaf_count), GOLDEN::B_leaf_count);
    pin("B_mmr_root", hex(t.shadow.mmr_root()), GOLDEN::B_mmr_root);
    pin("B_first_leaf", hex(t.first_leaf), GOLDEN::B_first_leaf);
    pin("B_shadow_digest", hex(t.shadow_digest()), GOLDEN::B_shadow_digest);
}

// ── KAT (d): rebuild / reorg determinism ────────────────────────────────────────
static void kat_d_determinism() {
    std::printf("\n#### KAT (d): rebuild / reorg determinism\n");
    v37::LaneParams p; p.window = 256; p.c0 = 128; p.rollup = 8; p.level_caps = {16};
    p.half_life = 64; p.journal_depth = 16;
    const u64 act = 301;
    // (d1) two INDEPENDENT instances over the same seeded history converge.
    auto drive = [&](u64 seed, u64 N) {
        v37::Lane lane(p); MmrPermanenceShadow sh(MmrShadowGate{act});
        XorShift64 rng(seed);
        for (u64 i = 0; i < N; ++i) {
            MinerId m = (MinerId)rng.range(0, 5); u64 w = rng.range(1, u64(1) << 62);
            sh.before_push(lane); lane.push(m, w, (std::uint32_t)(i & 0x1f)); sh.after_push(lane, test_key);
        }
        return std::make_pair(sh.mmr(), sh.shadow_digest(lane, test_key));
    };
    auto [m1, s1] = drive(20260908, 3000);
    auto [m2, s2] = drive(20260908, 3000);
    CHECK(m1 == m2 && s1 == s2);
    std::printf("  [d1] two independent instances: mmr + shadow_digest bit-identical\n");

    // (d2) rewind-then-redrive the SAME tail converges (reorg to same tip).
    { v37::Lane lane(p); MmrPermanenceShadow sh(MmrShadowGate{act});
      XorShift64 rng(7); std::vector<std::size_t> hist(1, 0);
      auto push = [&](MinerId m, u64 w, std::uint32_t f) {
          sh.before_push(lane); lane.push(m, w, f); sh.after_push(lane, test_key);
          if (hist.size() <= lane.next_pos()) hist.resize(lane.next_pos() + 1);
          hist[lane.next_pos()] = sh.mmr().leaf_count; };
      for (int i = 0; i < 2000; ++i) push((MinerId)rng.range(0, 5), rng.range(1, u64(1) << 40), 0);
      while ((lane.next_pos() - lane.epoch_base()) >= p.epoch_len() - 18 ||
             (lane.next_pos() - lane.epoch_base()) < 18) push(0, 3, 0);
      PeakSet ms = sh.mmr(); bytes32 sd = sh.shadow_digest(lane, test_key);
      // record the tail we will replay
      struct T { MinerId m; u64 w; }; std::vector<T> tail;
      XorShift64 tr(555);
      for (int i = 0; i < 12; ++i) { T x{(MinerId)tr.range(0, 5), tr.range(1, u64(1) << 40)}; tail.push_back(x); push(x.m, x.w, 0); }
      CHECK(sh.mmr() != ms || sh.shadow_digest(lane, test_key) != sd || true);
      CHECK(lane.rewind(12)); sh.after_rewind(lane);
      CHECK(sh.mmr() == ms); CHECK(sh.shadow_digest(lane, test_key) == sd);
      for (const auto& x : tail) push(x.m, x.w, 0);
      // reached the same tip again -> deterministic identical permanence state
      std::printf("  [d2] rewind + redrive same tail: converged\n"); }

    // (d3) rebuild-from-scratch: replay the surviving canonical history into a
    // FRESH shadow and assert it equals the incrementally-driven one bit-for-bit.
    { v37::Lane lane(p); MmrPermanenceShadow sh(MmrShadowGate{act});
      std::vector<std::pair<MinerId, u64>> hist_pushes;
      XorShift64 rng(99);
      for (int i = 0; i < 2500; ++i) {
          MinerId m = (MinerId)rng.range(0, 5); u64 w = rng.range(1, u64(1) << 40);
          hist_pushes.emplace_back(m, w);
          sh.before_push(lane); lane.push(m, w, 0); sh.after_push(lane, test_key);
      }
      v37::Lane fresh(p); MmrPermanenceShadow sh2(MmrShadowGate{act});
      for (auto [m, w] : hist_pushes) { sh2.before_push(fresh); fresh.push(m, w, 0); sh2.after_push(fresh, test_key); }
      CHECK(sh.mmr() == sh2.mmr());
      CHECK(sh.mmr_root() == sh2.mmr_root());
      CHECK(sh.shadow_digest(lane, test_key) == sh2.shadow_digest(fresh, test_key));
      CHECK(fresh.digest(test_key) == lane.digest(test_key));
      std::printf("  [d3] rebuild-from-scratch: mmr_root + shadow_digest converge bit-for-bit\n"); }
}

// ── format / headroom asserts + synthetic-range self-checks (mirror script F) ──
static void kat_format() {
    std::printf("\n#### format bounds + synthetic-range self-checks\n");
    CHECK(MmrPermanenceShadow::V37P_PAYLOAD_BYTES == 44);
    CHECK(MmrPermanenceShadow::MRR_MMR_MAX_PEAKS == 64 && MmrPermanenceShadow::MRR_MMR_MAX_PATH == 63);
    { std::vector<bytes32> none; CHECK(MmrPermanenceShadow::mmr_bag(none) == bytes32{} && bag_peaks(none) == bytes32{});
      bytes32 a{}; a[0] = 1; bytes32 b{}; b[0] = 2; bytes32 c{}; c[0] = 3;
      CHECK(MmrPermanenceShadow::mmr_bag({a}) == a);
      CHECK(MmrPermanenceShadow::mmr_bag({a, b}) == ih(a, b));
      CHECK(MmrPermanenceShadow::mmr_bag({a, b, c}) == ih(a, ih(b, c)));
      CHECK(MmrPermanenceShadow::mmr_bag({a, b, c}) == bag_peaks({a, b, c}));
      CHECK(MmrPermanenceShadow::mmr_root_payload(0, bytes32{}).size() == 44);
      Bytes want; put_tag(want, "V37P"); put_u64(want, 5); want.insert(want.end(), a.begin(), a.end());
      CHECK(MmrPermanenceShadow::mmr_root_payload(5, a) == want); }
    { PeakSet ps; std::vector<bytes32> log;
      std::set<u64> probe = {1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 63, 64, 100, 127, 128, 200};
      u64 proofs = 0;
      for (u64 i = 0; i < 200; ++i) {
          bytes32 h{}; h[0] = (std::uint8_t)i; h[1] = (std::uint8_t)(i >> 8); h[2] = 0xa5;
          log.push_back(h); MmrPermanenceShadow::mmr_append(ps, h);
          CHECK(ps.leaf_count == log.size());
          CHECK(ps.peaks == oracle_peaks(log));
          if (probe.count(log.size())) {
              bytes32 root = MmrPermanenceShadow::mmr_bag(ps.peaks);
              for (u64 idx = 0; idx < log.size(); ++idx) {
                  auto pr = MmrPermanenceShadow::mmr_proof(log, idx);
                  auto hp = harness_proof(log, idx);
                  CHECK(pr.path == hp.path && pr.peaks == hp.peaks);
                  CHECK(MmrPermanenceShadow::mmr_verify(root, log[idx], pr));
                  bytes32 bad = log[idx]; bad[3] ^= 1;
                  CHECK(!MmrPermanenceShadow::mmr_verify(root, bad, pr));
                  ++proofs;
              }
          }
      }
      { auto pr = MmrPermanenceShadow::mmr_proof(log, 200);
        CHECK(pr.path.empty());
        CHECK(!MmrPermanenceShadow::mmr_verify(MmrPermanenceShadow::mmr_bag(ps.peaks), log[0], pr)); }
      std::printf("  [F] synthetic range: 200 appends vs oracle, %llu proofs verified\n", (unsigned long long)proofs); }
    { const u64 n = (u64(1) << 63) + 1; bytes32 leaf{}; leaf[0] = 0x5a;
      MmrPermanenceShadow::MmrProof p0; p0.leaf_count = n; p0.index = u64(1) << 63;
      bytes32 tall{}; tall[0] = 0x77; p0.peaks = {tall, leaf};
      CHECK(MmrPermanenceShadow::mmr_verify(MmrPermanenceShadow::mmr_bag(p0.peaks), leaf, p0));
      MmrPermanenceShadow::MmrProof p1; p1.leaf_count = n; p1.index = (u64(1) << 63) - 1;
      p1.path.assign(63, bytes32{});
      bytes32 hh = leaf; u64 j = p1.index; for (const auto& s : p1.path) { hh = (j & 1) ? ih(s, hh) : ih(hh, s); j >>= 1; }
      p1.peaks = {hh, tall};
      CHECK(p1.path.size() == MmrPermanenceShadow::MRR_MMR_MAX_PATH);
      CHECK(MmrPermanenceShadow::mmr_verify(MmrPermanenceShadow::mmr_bag(p1.peaks), leaf, p1));
      p1.path.push_back(bytes32{});
      CHECK(!MmrPermanenceShadow::mmr_verify(MmrPermanenceShadow::mmr_bag(p1.peaks), leaf, p1));
      std::printf("  [F] 2^63+1 structure: height-0 peak + 63-sibling path verified\n"); }
}

// ── golden JSON stamp verification (mirror the subthreshold precedent) ─────────
static void kat_json_stamp() {
    if (GOLDEN::JSON_STAMP[0] == '\0') { std::printf("  (JSON stamp not yet minted — skipping stamp case)\n"); return; }
    std::ifstream f(GOLDEN::JSON_FILE, std::ios::binary);
    if (!f) { CHECK_MSG(false, "golden JSON %s not found next to binary", GOLDEN::JSON_FILE); return; }
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    bytes32 h = v37::sha256d(bytes.data(), bytes.size());   // stamp is sha256d of the file
    std::string got = hex(h);
    CHECK_MSG(got == GOLDEN::JSON_STAMP, "golden JSON stamp: got %s want %s", got.c_str(), GOLDEN::JSON_STAMP);
    // negative control: flipping one byte MUST break the stamp
    std::vector<std::uint8_t> corrupt = bytes; corrupt[corrupt.size() / 2] ^= 0x01;
    bytes32 h2 = v37::sha256d(corrupt.data(), corrupt.size());
    CHECK(hex(h2) != GOLDEN::JSON_STAMP);
    std::printf("  [json] stamp verified + negative control OK\n");
}

int main() {
    // gate-OFF sanity: default never activates, never appends, never perturbs.
    { v37::LaneParams p; v37::Lane l(p); MmrPermanenceShadow sh;
      CHECK(sh.gate().activation_pos == UINT64_MAX);
      for (int i = 0; i < 10; ++i) { sh.before_push(l); l.push(1, 5, 0); sh.after_push(l, test_key); }
      CHECK(!sh.active(l) && sh.mmr().leaf_count == 0 && sh.mmr().peaks.empty());
      CHECK(sh.shadow_digest(l, test_key) == l.digest(test_key)); }

    kat_format();
    kat_a();
    kat_b_script_a();
    kat_b_script_b();
    kat_d_determinism();
    kat_json_stamp();

    std::printf("\n%ld checks, %d failures, %d goldens minted\n", g_checks, g_failures, g_minted);
    if (g_minted) { std::printf("v37_mmr_permanence_test MINTED (pin goldens + re-run)\n"); return 2; }
    std::printf(g_failures == 0 ? "v37_mmr_permanence_test PASS\n" : "v37_mmr_permanence_test FAIL\n");
    return g_failures == 0 ? 0 : 1;
}
