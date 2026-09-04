// V37 W4 prerequisites (OI-W4-1 identity view + OI-W4-3 read-at-version ring)
// — standalone unit tests. Same tiny CHECK harness as v37_scaffold_test.cpp
// and src/sharechain/v37/test/v37_test.cpp: no gtest, no core/Boost link;
// compiles with nothing but g++ -std=c++20 -pthread and an -I on src.
//
// These pin the two W0/W1 engine follow-ons W4 is BLOCKED on (W4 settlement
// spec §11, OI-W4-1 and OI-W4-3), both observable through the W0 V37Engine
// seam and both independent of the D-B geometry ruling:
//
//   OI-W4-1 (identity view): each LaneSnapshot publishes, alongside its
//     MinerId-keyed payout map, an append-only IdentityView resolving every
//     MinerId to its canonical (key, ScriptRef) — the bytes settlement needs
//     to emit a payable output. Tested: MinerId->key/ScriptRef round-trips,
//     the view is a superset of the payout keys, it is IMMUTABLE / holds no
//     live reference (a held view never grows when new miners are interned),
//     it is digest-consistent (a direct-library replay's lane_digest matches),
//     and it is incarnation-scoped (empty again after RemoveLane->AddLane).
//
//   OI-W4-3 (read-at-version ring): V37Engine::settlement_view_at(chain,
//     incarnation, version) returns the immutable projection at a past
//     version. Tested: it returns the EXACT past projection (payout/digest/
//     next_pos equal to the snapshot held at that version), it REJECTS an
//     evicted version and a wrong incarnation with nullptr (never a
//     neighbouring version — O2.3), and the ring is dropped on RemoveLane so
//     an old incarnation's versions can never be re-read (the F2 ABA).
//
// No decay-table numeric value is pinned here — only structural equalities,
// round-trips, and shell-vs-direct-library digest comparisons, which hold on
// either decay-table construction (the F-1/OI-7 adjudication does not gate the
// identity/ring seams, which are raw identity + version structure).

#include <cstdint>
#include <cstdio>
#include <memory>
#include <type_traits>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace ::v37;
using c2pool::v37n::SettlementView;
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

// Small geometry (matches the scaffold suite): fast churn, small maps.
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

// run() publishes the mailbox slot AND appends the ring BEFORE fulfilling the
// tracked promise, so get() is a clean happens-before for both reader seams.
static SubmitResult submit_sync(V37Engine& e, LaneRecord r) {
    return e.submit_tracked(std::move(r)).get();
}

// ── compile-time surface audit (OI-W4-1 / OI-W4-3) ────────────────────────
static_assert(
    std::is_same_v<decltype(std::declval<const LaneSnapshot&>().identities),
                   std::shared_ptr<const IdentityView>>,
    "OI-W4-1: the identity view is a shared pointer to an immutable value");
static_assert(
    std::is_same_v<decltype(std::declval<const IdentityView&>().find(MinerId{})),
                   const IdentityEntry*>,
    "OI-W4-1: identity resolution hands out const, never a live reference");
static_assert(
    std::is_same_v<decltype(std::declval<const V37Engine&>().settlement_view_at(
                       ChainId{}, std::uint64_t{}, std::uint64_t{})),
                   std::shared_ptr<const SettlementView>>,
    "OI-W4-3: read-at-version returns a shared pointer to an immutable value");

// ── OI-W4-1: correctness — MinerId -> (key, ScriptRef) round-trips ────────
static void test_identity_view_roundtrip() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());

    // A fresh lane carries a non-null but EMPTY view (no push yet).
    auto s0 = e.snapshot(0);
    CHECK(s0 != nullptr);
    CHECK(s0->identities != nullptr);
    CHECK(s0->identities->size() == 0);

    // Push five distinct identities; remember each id and its descriptor.
    std::vector<PayoutDescriptor> descs;
    std::vector<MinerId> ids;
    for (std::uint8_t f = 1; f <= 5; ++f) {
        PayoutDescriptor d = mk_desc(f);
        SubmitResult r = submit_sync(e, LaneRecord::push(0, d, 10, 0));
        CHECK(r.applied());
        descs.push_back(d);
        ids.push_back(r.miner);
    }

    auto s = e.snapshot(0);
    CHECK(s != nullptr);
    CHECK(s->identities != nullptr);
    CHECK(s->identities->size() == 5);

    // Round-trip: the view resolves each MinerId to exactly the canonical key
    // (== descriptor identity_key) and the payout ScriptRef (== descriptor pay).
    for (std::size_t i = 0; i < ids.size(); ++i) {
        const IdentityEntry* ent = s->identities->find(ids[i]);
        CHECK(ent != nullptr);
        if (ent) {
            CHECK(ent->key == descs[i].identity_key());
            CHECK(ent->pay == descs[i].pay);
        }
    }

    // Superset property: every MinerId in the payout map is resolvable.
    for (const auto& [mid, w] : s->payout) {
        (void)w;
        CHECK(s->identities->contains(mid));
    }

    // Unknown id resolves to nullptr (no false hit).
    CHECK(s->identities->find(9999) == nullptr);
    e.stop();
}

// ── OI-W4-1: digest-consistency vs a direct-library replay ────────────────
// The view's keys are the SAME MinerIntern::key values Roundabout::lane_digest
// folds, so a direct Roundabout replayed in the same push order reproduces the
// snapshot digest AND agrees on every miner's canonical key.
static void test_identity_view_digest_consistent() {
    LaneParams p = small_params();
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, p)).applied());

    Roundabout rb;
    rb.add_lane(0, p);

    std::vector<PayoutDescriptor> descs;
    std::vector<MinerId> engine_ids;
    for (std::uint8_t f = 1; f <= 6; ++f) descs.push_back(mk_desc(f));
    // Same serialized push order in both the engine and the direct library.
    for (int i = 0; i < 120; ++i) {
        const PayoutDescriptor& d = descs[i % descs.size()];
        SubmitResult r =
            submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0));
        CHECK(r.applied());
        engine_ids.push_back(r.miner);
        MinerId rid = rb.push(0, d, std::uint64_t(i + 1), 0);
        // Deterministic intern order: the engine and the direct library assign
        // the same node-local MinerId to the same push.
        CHECK(rid == r.miner);
    }

    auto s = e.snapshot(0);
    CHECK(s != nullptr);
    // The consensus commitment is identical (the shell does not perturb it).
    CHECK(s->digest == rb.lane_digest(0));
    // ... and the view's keys are exactly the resolver's keys.
    for (MinerId id : engine_ids) {
        const IdentityEntry* ent = s->identities->find(id);
        CHECK(ent != nullptr);
        if (ent) {
            CHECK(ent->key == rb.miners().key(id));
            CHECK(ent->pay == rb.miners().pay_ref(id));
        }
    }
    e.stop();
}

// ── OI-W4-1: immutability / no live reference escapes ─────────────────────
// A held view is a frozen value: interning more miners into the live lane does
// NOT grow a previously published view (it would if the view aliased the live
// MinerIntern). The mailbox meanwhile advances to a larger view.
static void test_identity_view_immutable() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());

    PayoutDescriptor d1 = mk_desc(0x11);
    MinerId id1 = submit_sync(e, LaneRecord::push(0, d1, 5, 0)).miner;
    auto held = e.snapshot(0);
    CHECK(held != nullptr && held->identities != nullptr);
    const std::size_t held_size = held->identities->size();
    CHECK(held_size == 1);
    CHECK(held->identities->contains(id1));

    // Intern three MORE distinct identities into the same live lane.
    std::vector<MinerId> newer;
    for (std::uint8_t f = 0x20; f <= 0x22; ++f)
        newer.push_back(submit_sync(e, LaneRecord::push(0, mk_desc(f), 5, 0)).miner);

    // The held view is unchanged — frozen, no reference into live state.
    CHECK(held->identities->size() == held_size);
    for (MinerId id : newer) CHECK(!held->identities->contains(id));

    // The mailbox moved on to a larger, still-consistent view.
    auto now = e.snapshot(0);
    CHECK(now->identities->size() == held_size + newer.size());
    for (MinerId id : newer) CHECK(now->identities->contains(id));
    CHECK(now->identities->contains(id1));   // append-only: old id retained
    e.stop();
}

// ── OI-W4-3: read-at-version returns the EXACT past projection ────────────
static void test_read_at_version_exact() {
    V37Engine e;   // default ring depth (128) comfortably retains this run
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());

    std::vector<std::shared_ptr<const LaneSnapshot>> held;   // one per version
    held.push_back(e.snapshot(0));                            // version 1 (AddLane)
    PayoutDescriptor d = mk_desc(0x33);
    for (int i = 0; i < 40; ++i) {
        CHECK(submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0))
                  .applied());
        held.push_back(e.snapshot(0));   // versions 2..41
    }

    // Re-read a spread of past versions and require an exact projection match.
    for (std::size_t k : {std::size_t(0), std::size_t(1), std::size_t(17),
                          std::size_t(40)}) {
        auto snap = held[k];
        CHECK(snap != nullptr);
        auto sv = e.settlement_view_at(0, snap->incarnation, snap->version);
        CHECK(sv != nullptr);
        if (sv) {
            CHECK(sv->version == snap->version);
            CHECK(sv->incarnation == snap->incarnation);
            CHECK(sv->chain == snap->chain);
            CHECK(sv->next_pos == snap->next_pos);
            CHECK(sv->raw_total == snap->raw_total);
            CHECK(sv->digest == snap->digest);
            CHECK(sv->payout == snap->payout);       // exact past payout map
            // The OI-W4-1 identity view rides along on the past projection too.
            CHECK(sv->identities != nullptr);
            CHECK(sv->identities->size() == snap->identities->size());
            for (const auto& [mid, w] : sv->payout) {
                (void)w;
                CHECK(sv->identities->contains(mid));
            }
        }
    }
    e.stop();
}

// ── OI-W4-3: rejects an evicted version and a wrong incarnation ───────────
static void test_read_at_version_rejects() {
    V37Engine e(8);   // tiny ring so eviction is cheap to exercise
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    auto genesis = e.snapshot(0);
    const std::uint64_t inc = genesis->incarnation;

    PayoutDescriptor d = mk_desc(0x44);
    for (int i = 0; i < 30; ++i)   // versions 2..31; only the last 8 retained
        CHECK(submit_sync(e, LaneRecord::push(0, d, std::uint64_t(i + 1), 0))
                  .applied());
    auto tip = e.snapshot(0);
    CHECK(tip->version == 31);

    // The freshest 8 versions (24..31) are present ...
    CHECK(e.settlement_view_at(0, inc, 31) != nullptr);
    CHECK(e.settlement_view_at(0, inc, 24) != nullptr);
    // ... everything older is evicted → nullptr (never a neighbour, O2.3).
    CHECK(e.settlement_view_at(0, inc, 23) == nullptr);
    CHECK(e.settlement_view_at(0, inc, 1) == nullptr);   // genesis evicted

    // A wrong incarnation for a retained version is refused (the F2 ABA).
    CHECK(e.settlement_view_at(0, inc + 999, 31) == nullptr);
    // An unknown chain and a never-published version are refused.
    CHECK(e.settlement_view_at(7, inc, 31) == nullptr);
    CHECK(e.settlement_view_at(0, inc, 99) == nullptr);
    e.stop();
}

// ── incarnation-scoping: view + ring reset on RemoveLane -> AddLane ───────
static void test_incarnation_scoping() {
    V37Engine e;
    e.start();
    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    for (std::uint8_t f = 1; f <= 4; ++f)
        CHECK(submit_sync(e, LaneRecord::push(0, mk_desc(f), 8, 0)).applied());

    auto before = e.snapshot(0);
    const std::uint64_t old_inc = before->incarnation;
    const std::uint64_t old_ver = before->version;
    CHECK(before->identities->size() == 4);
    // The old incarnation's versions are readable right now.
    CHECK(e.settlement_view_at(0, old_inc, old_ver) != nullptr);

    // Tear the lane down and stand it up again on the SAME chain id.
    CHECK(submit_sync(e, LaneRecord::remove_lane(0)).applied());
    CHECK(e.snapshot(0) == nullptr);                       // mailbox cleared
    // The dropped ring can no longer serve the old incarnation (F2 scoping).
    CHECK(e.settlement_view_at(0, old_inc, old_ver) == nullptr);

    CHECK(submit_sync(e, LaneRecord::add_lane(0, small_params())).applied());
    auto after = e.snapshot(0);
    CHECK(after != nullptr);
    CHECK(after->incarnation > old_inc);                   // fresh incarnation
    CHECK(after->version == 1);                            // version reset
    // The identity view RESET: the fresh incarnation starts empty.
    CHECK(after->identities != nullptr);
    CHECK(after->identities->size() == 0);
    // The old incarnation's versions stay unreadable even by version number.
    CHECK(e.settlement_view_at(0, old_inc, old_ver) == nullptr);
    // The fresh incarnation's genesis version IS readable, and empty.
    auto sv_new = e.settlement_view_at(0, after->incarnation, 1);
    CHECK(sv_new != nullptr);
    if (sv_new) {
        CHECK(sv_new->payout.empty());
        CHECK(sv_new->identities && sv_new->identities->size() == 0);
    }

    // Re-populate the fresh incarnation: the view grows again from empty.
    MinerId nid = submit_sync(e, LaneRecord::push(0, mk_desc(0x77), 8, 0)).miner;
    auto grown = e.snapshot(0);
    CHECK(grown->identities->size() == 1);
    CHECK(grown->identities->contains(nid));
    e.stop();
}

int main() {
    test_identity_view_roundtrip();
    test_identity_view_digest_consistent();
    test_identity_view_immutable();
    test_read_at_version_exact();
    test_read_at_version_rejects();
    test_incarnation_scoping();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
