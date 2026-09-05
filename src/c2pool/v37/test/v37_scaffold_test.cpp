// V37Engine (W0 node scaffold) — standalone unit tests. Same tiny CHECK
// harness as src/sharechain/v37/test/v37_test.cpp: no gtest, no core/Boost
// link; compiles with nothing but g++ -std=c++20 -pthread and an -I on src.
//
// W0 gate (A2 bring-up step W0). These pin the seam W2 will build on:
//   (1) ownership / surface audit — no Lane&/Roundabout&/LaneExecutor&
//       escapes V37Engine; the writer cannot be duplicated (compile-time
//       where expressible, O1.2/O1.5);
//   (2) F1 publication-mailbox race-freedom — a reader load()s consistent,
//       immutable snapshots while the executor thread mutates the lane; a
//       held snapshot never changes under republication;
//   (3) F2 incarnation monotonicity — the executor-minted lane incarnation
//       strictly increases across RemoveLane->AddLane even as version resets;
//   (4) submit_tracked future disposition — every SubmitStatus is reported
//       back through the future by value;
//   (5) deterministic replay — two engines fed the same ordered record
//       stream agree bit-exactly on digest, version, incarnation, ops;
//   (6) selftest invariants — genesis digest through the shell equals the
//       direct library; MPSC->single-executor preserves enqueue order and
//       loses/duplicates nothing under many producers.
//
// No decay-table numeric value is pinned here — only structural equalities
// and shell-vs-direct-library comparisons, which hold on either decay-table
// construction (the F-1/OI-7 adjudication is pending and does not gate W0).

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <future>
#include <memory>
#include <thread>
#include <type_traits>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace ::v37;
using c2pool::v37n::V37Engine;

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

// Deterministic PRNG (consensus tests must not depend on platform RNG).
struct XorShift64 {
    std::uint64_t s;
    explicit XorShift64(std::uint64_t seed)
        : s(seed ? seed : 0x9e3779b97f4a7c15ull) {}
    std::uint64_t next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s;
    }
    std::uint64_t range(std::uint64_t lo, std::uint64_t hi) {
        return lo + next() % (hi - lo + 1);
    }
};

// Small geometry: fast churn (several epochs in a few thousand pushes).
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

// Valid V37.0 P2PKH descriptor, one distinct identity per fill byte.
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = canonicalize_script(s);
    return d;
}

// Block until a submitted record has been committed AND its mailbox slot
// published: run() publishes BEFORE fulfilling the promise, so get() is a
// clean happens-before for the reader seam.
static SubmitResult submit_sync(V37Engine& e, LaneRecord r) {
    return e.submit_tracked(std::move(r)).get();
}

// ── (1) ownership / surface audit (compile-time; O1.2/O1.5) ───────────────
static_assert(!std::is_copy_constructible_v<V37Engine> &&
                  !std::is_move_constructible_v<V37Engine>,
              "the engine (hence the single writer) cannot be duplicated");
static_assert(
    std::is_same_v<decltype(std::declval<const V37Engine&>().snapshot(0)),
                   std::shared_ptr<const LaneSnapshot>>,
    "the only read path returns a shared pointer to an immutable value");
static_assert(std::is_same_v<decltype(std::declval<V37Engine&>().submit(
                                 std::declval<LaneRecord>())),
                             void>,
              "submit leaks nothing (no lane reference, no disposition)");

static void test_ownership_surface() {
    // Runtime touch: the public surface offers no way to name a Lane,
    // Roundabout, or LaneExecutor. If any accessor returning one were added,
    // the static_asserts above (and in the header) would need loosening —
    // this test exists so that regression is a visible, deliberate act.
    V37Engine e;
    e.start();
    (void)submit_sync(e, LaneRecord::add_lane(0, small_params()));
    std::shared_ptr<const LaneSnapshot> s = e.snapshot(0);
    CHECK(s != nullptr);
    // The value we hold is a snapshot, not a live handle: it stays const.
    static_assert(std::is_const_v<std::remove_reference_t<decltype(*s)>>,
                  "snapshot dereferences to const");
    e.stop();
}

// ── (6a) genesis digest through the shell == direct library ───────────────
static void test_genesis_digest_matches_direct() {
    LaneParams p = small_params();
    V37Engine e;
    e.start();
    SubmitResult add = submit_sync(e, LaneRecord::add_lane(0, p));
    CHECK(add.applied());
    auto snap = e.snapshot(0);
    CHECK(snap != nullptr);
    CHECK(snap->version == 1);
    CHECK(snap->incarnation == 1);          // first-ever lane
    CHECK(snap->payout.empty());            // no push yet
    CHECK(e.ops_committed() == 1);

    // Direct-library reference on the same params: the shell must not perturb
    // the genesis digest.
    Roundabout rb;
    rb.add_lane(0, p);
    CHECK(snap->digest == rb.lane_digest(0));
    e.stop();
}

// ── (6b) MPSC -> single executor: order preserved, single producer ────────
static void test_single_producer_order() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    const int N = 500;
    PayoutDescriptor d = mk_desc(0x11);
    for (int i = 0; i < N; ++i) {
        SubmitResult r =
            submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0));
        CHECK(r.applied());
        // version 1 was AddLane; push #i lands version i+2.
        CHECK(r.lane_version == std::uint64_t(i + 2));
    }
    CHECK(e.ops_committed() == std::uint64_t(1 + N));
    e.stop();
}

// ── (6c) MPSC -> single executor: many producers, nothing lost/duplicated ─
static void test_multi_producer_total_order() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());

    const int T = 6;      // producer threads
    const int M = 400;    // records each
    std::vector<std::thread> producers;
    std::vector<std::vector<std::future<SubmitResult>>> futs(T);
    PayoutDescriptor d = mk_desc(0x22);
    for (int t = 0; t < T; ++t) {
        producers.emplace_back([&, t] {
            for (int i = 0; i < M; ++i)
                futs[t].push_back(
                    e.submit_tracked(LaneRecord::push(0, d, 1, 0)));
        });
    }
    for (auto& th : producers) th.join();

    // Collect every applied lane_version. The committed order is SOME
    // interleaving, but it must be a strict total order: exactly the versions
    // {2 .. 1+T*M}, each once — no loss, no duplicate, no collision.
    std::vector<std::uint64_t> versions;
    for (int t = 0; t < T; ++t)
        for (auto& f : futs[t]) {
            SubmitResult r = f.get();
            CHECK(r.applied());
            versions.push_back(r.lane_version);
        }
    std::sort(versions.begin(), versions.end());
    CHECK(versions.size() == std::size_t(T * M));
    bool contiguous = true;
    for (std::size_t i = 0; i < versions.size(); ++i)
        if (versions[i] != std::uint64_t(i + 2)) contiguous = false;
    CHECK(contiguous);
    CHECK(e.ops_committed() == std::uint64_t(1 + T * M));
    e.stop();
}

// ── (2) F1 publication mailbox: reader race-freedom + immutability ────────
static void test_f1_mailbox_race_free() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());

    std::atomic<bool> done{false};
    std::atomic<bool> reader_ok{true};
    std::atomic<std::uint64_t> reads{0};
    // Reader thread: never calls receive(); only load()s the mailbox, while
    // the executor thread mutates the lane on every push below.
    std::thread reader([&] {
        std::uint64_t last_version = 0;
        while (!done.load()) {
            auto s = e.snapshot(0);
            if (!s) continue;                         // pre-first-publish
            if (s->version < last_version) reader_ok.store(false);
            last_version = s->version;
            // Touch the value fully: a torn/aliased snapshot would trip here.
            if (s->chain != 0) reader_ok.store(false);
            if (s->incarnation != 1) reader_ok.store(false);
            (void)s->raw_work_in_span(0, s->next_pos);
            reads.fetch_add(1);
        }
    });

    PayoutDescriptor d = mk_desc(0x33);
    // Grab a snapshot mid-stream and prove republication never mutates it.
    for (int i = 0; i < 100; ++i)
        CHECK(submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0))
                  .applied());
    auto held = e.snapshot(0);
    CHECK(held != nullptr);
    const bytes32 held_digest = held->digest;
    const std::uint64_t held_version = held->version;
    const std::uint64_t held_raw = held->raw_total;
    for (int i = 0; i < 3000; ++i)
        CHECK(submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0))
                  .applied());
    // The held snapshot is retained, not mutated (O1.1).
    CHECK(held->digest == held_digest);
    CHECK(held->version == held_version);
    CHECK(held->raw_total == held_raw);
    // Meanwhile the mailbox moved on.
    auto now = e.snapshot(0);
    CHECK(now->version > held_version);

    done.store(true);
    reader.join();
    CHECK(reader_ok.load());
    CHECK(reads.load() > 0);           // the reader really ran concurrently
    e.stop();
}

// ── (3) F2 incarnation monotonicity across RemoveLane -> AddLane ──────────
static void test_f2_incarnation_monotone() {
    V37Engine e;
    e.start();
    PayoutDescriptor d = mk_desc(0x44);

    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    auto s0 = e.snapshot(0);
    CHECK(s0 && s0->incarnation == 1 && s0->version == 1);
    for (int i = 0; i < 50; ++i)
        CHECK(submit_sync(e, LaneRecord::push(0, d, 7, 0)).applied());
    auto s0b = e.snapshot(0);
    CHECK(s0b->incarnation == 1);          // incarnation stable within a life
    CHECK(s0b->version > 1);

    // Tear the lane down and stand it up again on the SAME chain id.
    CHECK(submit_sync(e, LaneRecord::remove_lane(0)).applied());
    CHECK(e.snapshot(0) == nullptr);       // mailbox cleared on removal
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    auto s0c = e.snapshot(0);
    CHECK(s0c != nullptr);
    // version RESET (ABA hazard) ...
    CHECK(s0c->version == 1);
    // ... but the incarnation STRICTLY advanced (F2: no reuse for the id).
    CHECK(s0c->incarnation > s0b->incarnation);

    // A different chain id mints yet another distinct, larger incarnation.
    CHECK(submit_sync(e, LaneRecord::add_lane(5, small_params())).applied());
    auto s5 = e.snapshot(5);
    CHECK(s5 != nullptr);
    CHECK(s5->incarnation > s0c->incarnation);
    e.stop();
}

// ── (4) submit_tracked future disposition — every status by value ─────────
static void test_submit_tracked_dispositions() {
    V37Engine e;
    e.start();

    // Applied push carries the interned MinerId and the bumped version.
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    SubmitResult ok = submit_sync(e, LaneRecord::push(0, mk_desc(0x55), 9, 0));
    CHECK(ok.status == SubmitStatus::Applied);
    CHECK(ok.lane_version == 2);

    // Unknown chain.
    CHECK(submit_sync(e, LaneRecord::push(99, mk_desc(0x55), 9, 0)).status ==
          SubmitStatus::RejectedUnknownChain);
    // Zero work.
    CHECK(submit_sync(e, LaneRecord::push(0, mk_desc(0x55), 0, 0)).status ==
          SubmitStatus::RejectedZeroWork);
    // Duplicate lane.
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).status ==
          SubmitStatus::RejectedDuplicateLane);
    // Bad geometry (c0 not a power of two).
    LaneParams bad = small_params();
    bad.c0 = 130;
    CHECK(submit_sync(e, LaneRecord::add_lane(7, bad)).status ==
          SubmitStatus::RejectedBadGeometry);

    // A rejection changes no committed state: only the two applied records
    // (AddLane + the one good Push) count.
    CHECK(e.ops_committed() == 2);
    e.stop();
}

// ── (5) deterministic replay: two engines, one ordered stream ─────────────
static std::vector<LaneRecord> make_stream() {
    std::vector<LaneRecord> rec;
    XorShift64 rng(0xC0FFEE);
    std::vector<PayoutDescriptor> descs;
    for (std::uint8_t f = 1; f <= 6; ++f) descs.push_back(mk_desc(f));
    rec.push_back(LaneRecord::add_lane(0, small_params()));
    rec.push_back(LaneRecord::add_lane(1, small_params()));
    for (int i = 0; i < 1500; ++i) {
        ChainId c = ChainId(rng.range(0, 1));
        const PayoutDescriptor& d = descs[rng.range(0, descs.size() - 1)];
        std::uint64_t w = rng.range(1, 9000);
        rec.push_back(LaneRecord::push(c, d, w, 0));
        if (rng.range(0, 40) == 0) rec.push_back(LaneRecord::rewind(c, 1));
    }
    // Tear down and re-add lane 0 mid-stream: replay must agree on the fresh
    // incarnation too.
    rec.push_back(LaneRecord::remove_lane(0));
    rec.push_back(LaneRecord::add_lane(0, small_params()));
    for (int i = 0; i < 300; ++i)
        rec.push_back(LaneRecord::push(0, descs[i % descs.size()],
                                       rng.range(1, 9000), 0));
    return rec;
}

static void feed(V37Engine& e, const std::vector<LaneRecord>& rec) {
    for (const auto& r : rec) (void)submit_sync(e, r);  // serialized in order
}

static void test_deterministic_replay() {
    auto stream = make_stream();
    V37Engine a, b;
    a.start();
    b.start();
    feed(a, stream);
    feed(b, stream);
    CHECK(a.ops_committed() == b.ops_committed());
    for (ChainId c : {ChainId(0), ChainId(1)}) {
        auto sa = a.snapshot(c);
        auto sb = b.snapshot(c);
        CHECK((sa == nullptr) == (sb == nullptr));
        if (sa && sb) {
            CHECK(sa->version == sb->version);
            CHECK(sa->incarnation == sb->incarnation);
            CHECK(sa->digest == sb->digest);
            CHECK(sa->raw_total == sb->raw_total);
            CHECK(sa->next_pos == sb->next_pos);
        }
    }
    a.stop();
    b.stop();
}

int main() {
    test_ownership_surface();
    test_genesis_digest_matches_direct();
    test_single_producer_order();
    test_multi_producer_total_order();
    test_f1_mailbox_race_free();
    test_f2_incarnation_monotone();
    test_submit_tracked_dispositions();
    test_deterministic_replay();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
