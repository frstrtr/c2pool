// V37 lane executor — standalone unit tests (same tiny CHECK harness as
// v37_test.cpp; no gtest, compiles with nothing but g++ -std=c++20).
//
// W1 gate (A2 bring-up): the LaneExecutor is the O1 message-passing surface
// over Lane/Roundabout. These tests pin:
//   (1) differential equivalence — the same record stream through the
//       executor and through a direct Roundabout/Lane yields identical
//       digests, payout maps, and counters at EVERY step, including across
//       epoch rebuilds and rewinds (the executor adds no semantics);
//   (2) snapshot immutability — mutating the lane after receive() cannot
//       change a held snapshot (O1.1: versions are retained, not mutated);
//   (3) surface audit — the public API exposes no reference into lane
//       state, no lock, and no second writer (O1.2/O1.5), checked as
//       compile-time-evaluable type traits;
//   (4) deterministic replay — two executors fed the same stream agree
//       bit-exactly on every disposition, version, and digest.
//
// NOTE: no decay-table numeric value is pinned anywhere here — only
// structural equalities and executor-vs-direct comparisons, which hold on
// either decay-table construction (the F-1/OI-7 adjudication is pending).

#include <cstdio>
#include <memory>
#include <type_traits>
#include <vector>

#include "../v37_lane_executor.hpp"

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

// Same small geometry as v37_test.cpp: 5+ epochs of churn in 1500 pushes.
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

// Valid V37.0 P2PKH descriptor, one identity per fill byte.
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = canonicalize_script(s);
    return d;
}

static bool payout_equal(const std::map<MinerId, U256>& a,
                         const std::map<MinerId, U256>& b) {
    if (a.size() != b.size()) return false;
    auto ia = a.begin();
    for (auto ib = b.begin(); ib != b.end(); ++ia, ++ib)
        if (ia->first != ib->first || !(ia->second == ib->second))
            return false;
    return true;
}

// Compare an executor snapshot against the direct Roundabout/Lane state.
static bool snapshot_matches(const LaneSnapshot& s, const Roundabout& rb,
                             const Lane& l, ChainId chain) {
    return s.digest == rb.lane_digest(chain) &&
           payout_equal(s.payout, l.payout_map()) &&
           s.next_pos == l.next_pos() && s.epoch_base == l.epoch_base() &&
           s.cover == l.cover() && s.acc_total == l.acc_total() &&
           s.decayed_total == l.decayed_total() &&
           s.raw_total == l.raw_total();
}

// ── (1) differential equivalence: executor vs direct, every step ──────────
// The same stream (pushes + interleaved rewinds) drives an executor and a
// direct Roundabout. Small geometry -> the 1500-push run crosses ~10 epoch
// rebuilds and constant fold/evict churn; the periodic rewinds land on fold
// boundaries and hit the journal-refusal path near rebuilds. At every step
// the published snapshot must match the direct state bit-exactly.
static void test_differential_equivalence() {
    const ChainId chain = 1;
    LaneExecutor ex;
    CHECK(ex.submit(LaneRecord::add_lane(chain, small_params())).applied());

    Roundabout rb;
    rb.add_lane(chain, small_params());
    Lane* dl = rb.lane(chain);

    std::vector<PayoutDescriptor> descs;
    for (std::uint8_t f = 0; f < 6; ++f) descs.push_back(mk_desc(f));

    XorShift64 rng(1234);
    std::uint64_t expect_version = 1;  // AddLane established version 1
    int rewinds_applied = 0, rewinds_refused = 0;

    for (u64 i = 0; i < 1500; ++i) {
        const PayoutDescriptor& d = descs[rng.range(0, descs.size() - 1)];
        u64 w = rng.range(1, 1000000);

        SubmitResult r = ex.submit(LaneRecord::push(chain, d, w, 0));
        MinerId direct_id = rb.push(chain, d, w, 0);
        CHECK_MSG(r.applied(), "push not applied @%llu",
                  (unsigned long long)i);
        // Same stream -> same intern order -> same node-local ids.
        CHECK_MSG(r.miner == direct_id, "intern id divergence @%llu",
                  (unsigned long long)i);
        ++expect_version;
        CHECK_MSG(r.lane_version == expect_version, "version @%llu",
                  (unsigned long long)i);

        auto snap = ex.receive(chain);
        CHECK(snap != nullptr);
        CHECK_MSG(snapshot_matches(*snap, rb, *dl, chain),
                  "executor/direct divergence @%llu", (unsigned long long)i);
        CHECK(snap->version == expect_version);

        // Span reads answered FROM the snapshot == live-lane span reads.
        if (i % 101 == 0 && dl->next_pos() > 4) {
            u64 hi = dl->next_pos() - 1;
            u64 lo = hi - rng.range(1, std::min<u64>(hi, 64));
            CHECK(snap->raw_work_in_span(lo, hi) ==
                  dl->raw_work_in_span(lo, hi));
        }

        // Interleaved rewinds: identical dispositions AND identical state,
        // including refusals (journal exhausted / epoch-rebuild sentinel).
        if (i % 97 == 96) {
            u64 depth = rng.range(1, 24);
            SubmitResult rw = ex.submit(LaneRecord::rewind(chain, depth));
            bool direct_ok = dl->rewind(depth);
            CHECK_MSG(rw.applied() == direct_ok,
                      "rewind disposition divergence @%llu d=%llu",
                      (unsigned long long)i, (unsigned long long)depth);
            if (rw.applied()) {
                ++expect_version;
                ++rewinds_applied;
            } else {
                CHECK(rw.status == SubmitStatus::RefusedJournal);
                ++rewinds_refused;
            }
            CHECK(rw.lane_version == expect_version);
            auto s2 = ex.receive(chain);
            CHECK_MSG(snapshot_matches(*s2, rb, *dl, chain),
                      "post-rewind divergence @%llu", (unsigned long long)i);
        }
    }
    // The schedule must have exercised BOTH rewind paths, or the test is
    // vacuous on one of them.
    CHECK_MSG(rewinds_applied > 0 && rewinds_refused > 0,
              "rewind coverage: %d applied / %d refused", rewinds_applied,
              rewinds_refused);
    // ... and crossed at least one epoch rebuild.
    CHECK(ex.receive(chain)->epoch_base > 0);
}

// ── (2) snapshot immutability: publication copies, never aliases ──────────
static void test_snapshot_immutability() {
    const ChainId chain = 7;
    LaneExecutor ex;
    CHECK(ex.submit(LaneRecord::add_lane(chain, small_params())).applied());
    PayoutDescriptor d0 = mk_desc(0xaa), d1 = mk_desc(0xbb);

    XorShift64 rng(77);
    for (int i = 0; i < 300; ++i)
        CHECK(ex.submit(LaneRecord::push(chain, (i & 1) ? d1 : d0,
                                         rng.range(1, 5000), 0))
                  .applied());

    auto snap = ex.receive(chain);
    // Deep copies of everything the snapshot claims, taken NOW.
    const bytes32 digest0 = snap->digest;
    const auto payout0 = snap->payout;
    const u64 next_pos0 = snap->next_pos;
    const std::uint64_t version0 = snap->version;
    const u128 span0 = snap->raw_work_in_span(0, next_pos0 - 1);

    // Caching: a second receive with no mutation republishes the SAME
    // snapshot object (content is a pure function of the committed prefix).
    CHECK(ex.receive(chain) == snap);

    // Mutate hard: pushes across a fold boundary, then a rewind.
    for (int i = 0; i < 200; ++i)
        CHECK(ex.submit(LaneRecord::push(chain, d0, rng.range(1, 5000), 0))
                  .applied());
    CHECK(ex.submit(LaneRecord::rewind(chain, 3)).applied());

    // The held snapshot is bit-identical to what was copied at publication.
    CHECK(snap->digest == digest0);
    CHECK(payout_equal(snap->payout, payout0));
    CHECK(snap->next_pos == next_pos0);
    CHECK(snap->version == version0);
    CHECK(snap->raw_work_in_span(0, next_pos0 - 1) == span0);

    // The NEW snapshot moved on (so the old one is genuinely retained, not
    // "unchanged because nothing changed").
    auto snap2 = ex.receive(chain);
    CHECK(snap2 != snap);
    CHECK(snap2->version > version0);
    CHECK(!(snap2->digest == digest0));

    // The old snapshot outlives republication (O1.1: readers holding an
    // older snapshot remain valid) — use_count proves shared retention.
    CHECK(snap.use_count() >= 1 && snap->next_pos == next_pos0);
}

// ── (3) surface audit: O1.2/O1.5 as checkable type traits ─────────────────
// A compiler cannot see caller-held locks (O1.2's own wording); the
// achievable form is lock-gone-from-surface: the executor contains no lock
// at all, and no public entry returns a reference into lane state. The
// traits below are compile-time constants evaluated here as runtime CHECKs
// so they land in the pass/fail tally; the same facts are static_asserted
// in v37_lane_executor.hpp itself. The complementary F-D1 call-site grep
// (no Lane accessor use outside the executor) is CI's static audit gate
// (FM-5/FM-6), not a unit test.
static void test_surface_audit() {
    // submit returns its disposition by value.
    CHECK((std::is_same_v<decltype(std::declval<LaneExecutor&>().submit(
                              std::declval<const LaneRecord&>())),
                          SubmitResult>));
    // receive returns shared ownership of a CONST snapshot — no mutable
    // path to published state exists in the type system.
    CHECK((std::is_same_v<decltype(std::declval<LaneExecutor&>().receive(
                              ChainId{})),
                          std::shared_ptr<const LaneSnapshot>>));
    // No public query returns a reference.
    CHECK(!std::is_reference_v<decltype(std::declval<const LaneExecutor&>()
                                            .version(ChainId{}))>);
    CHECK(!std::is_reference_v<decltype(std::declval<const LaneExecutor&>()
                                            .ops_committed())>);
    // O1.5: the writer cannot be duplicated.
    CHECK(!std::is_copy_constructible_v<LaneExecutor>);
    CHECK(!std::is_copy_assignable_v<LaneExecutor>);
    CHECK(!std::is_move_constructible_v<LaneExecutor>);
    CHECK(!std::is_move_assignable_v<LaneExecutor>);
    // Snapshot reads work through const access only.
    CHECK((std::is_invocable_r_v<u128, decltype(&LaneSnapshot::
                                                    raw_work_in_span),
                                 const LaneSnapshot&, u64, u64>));
}

// Deterministic rejection dispositions (validation is part of the fold
// discipline — same prefix + same record => same rejection on every node),
// and rejections leave state and version untouched.
static void test_rejections() {
    const ChainId chain = 3;
    LaneExecutor ex;

    // Bad geometry refused (c0 not a power of two).
    LaneParams bad = small_params();
    bad.c0 = 100;
    CHECK(ex.submit(LaneRecord::add_lane(chain, bad)).status ==
          SubmitStatus::RejectedBadGeometry);
    CHECK(ex.version(chain) == 0 && ex.receive(chain) == nullptr);

    CHECK(ex.submit(LaneRecord::add_lane(chain, small_params())).applied());
    CHECK(ex.submit(LaneRecord::add_lane(chain, small_params())).status ==
          SubmitStatus::RejectedDuplicateLane);

    PayoutDescriptor d = mk_desc(0x11);
    CHECK(ex.submit(LaneRecord::push(99, d, 10, 0)).status ==
          SubmitStatus::RejectedUnknownChain);
    CHECK(ex.submit(LaneRecord::push(chain, d, 0, 0)).status ==
          SubmitStatus::RejectedZeroWork);
    PayoutDescriptor invalid = d;
    invalid.attribution = d.pay;  // V37.0: attribution MUST be absent
    CHECK(ex.submit(LaneRecord::push(chain, invalid, 10, 0)).status ==
          SubmitStatus::RejectedInvalidDescriptor);

    CHECK(ex.submit(LaneRecord::push(chain, d, 10, 0)).applied());
    auto before = ex.receive(chain);

    // Rewind deeper than the journal: refused, nothing moves.
    CHECK(ex.submit(LaneRecord::rewind(chain, 1000)).status ==
          SubmitStatus::RefusedJournal);
    auto after = ex.receive(chain);
    CHECK(after == before);  // same published object: version untouched
    CHECK(after->digest == before->digest);

    // Rewind depth 0 is an applied no-op.
    SubmitResult z = ex.submit(LaneRecord::rewind(chain, 0));
    CHECK(z.applied() && z.lane_version == before->version);

    CHECK(ex.submit(LaneRecord::remove_lane(chain)).applied());
    CHECK(ex.receive(chain) == nullptr);
    CHECK(ex.submit(LaneRecord::rewind(chain, 1)).status ==
          SubmitStatus::RejectedUnknownChain);
}

// ── (4) deterministic replay: two executors, one stream, bit-equality ─────
// Mixed stream (two lanes, six identities, pushes + rewinds, some of them
// refused) fed to two independently constructed executors: every
// disposition, version, digest, and payout map must agree bit-exactly. Op
// ORDER is the consensus input (the Lanes.tla op-order pin); nothing here
// depends on scheduling because the core is single-threaded by design.
static void test_deterministic_replay() {
    LaneExecutor a, b;
    LaneParams p1 = small_params();
    LaneParams p2 = small_params();
    p2.window = 112; p2.c0 = 64; p2.level_caps = {6}; p2.half_life = 32;
    p2.journal_depth = 8;

    std::vector<LaneRecord> stream;
    stream.push_back(LaneRecord::add_lane(1, p1));
    stream.push_back(LaneRecord::add_lane(2, p2));
    std::vector<PayoutDescriptor> descs;
    for (std::uint8_t f = 0; f < 6; ++f) descs.push_back(mk_desc(f));
    XorShift64 rng(4242);
    for (int i = 0; i < 900; ++i) {
        ChainId c = (rng.next() & 1) ? 1 : 2;
        if (i % 89 == 88)
            stream.push_back(LaneRecord::rewind(c, rng.range(1, 12)));
        else
            stream.push_back(LaneRecord::push(
                c, descs[rng.range(0, descs.size() - 1)],
                rng.range(1, 1000000), 0));
    }

    for (std::size_t i = 0; i < stream.size(); ++i) {
        SubmitResult ra = a.submit(stream[i]);
        SubmitResult rb2 = b.submit(stream[i]);
        CHECK_MSG(ra.status == rb2.status && ra.miner == rb2.miner &&
                      ra.lane_version == rb2.lane_version,
                  "replay disposition divergence @%llu",
                  (unsigned long long)i);
        if (i % 50 == 0) {
            for (ChainId c : {ChainId(1), ChainId(2)}) {
                auto sa = a.receive(c), sb = b.receive(c);
                if (!sa || !sb) { CHECK(!sa && !sb); continue; }
                CHECK_MSG(sa->digest == sb->digest &&
                              payout_equal(sa->payout, sb->payout) &&
                              sa->version == sb->version &&
                              sa->next_pos == sb->next_pos,
                          "replay snapshot divergence @%llu chain=%u",
                          (unsigned long long)i, (unsigned)c);
            }
        }
    }
    CHECK(a.ops_committed() == b.ops_committed());
    for (ChainId c : {ChainId(1), ChainId(2)}) {
        auto sa = a.receive(c), sb = b.receive(c);
        CHECK(sa && sb && sa->digest == sb->digest);
        CHECK(payout_equal(sa->payout, sb->payout));
        CHECK(sa->raw_total == sb->raw_total &&
              sa->acc_total == sb->acc_total &&
              sa->decayed_total == sb->decayed_total);
    }
}

int main() {
    test_differential_equivalence();
    test_snapshot_immutability();
    test_surface_audit();
    test_rejections();
    test_deterministic_replay();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
