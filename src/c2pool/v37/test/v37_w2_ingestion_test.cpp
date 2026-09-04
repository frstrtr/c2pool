// V37 Track A2 / W2 — RDWR receipt-ingestion KAT suite. Standalone, stdlib-only
// (g++ -std=c++20 -pthread -I src), the same harness convention as
// v37_scaffold_test.cpp / v37_executor_test.cpp: no gtest, no core/Boost link.
//
// WHAT THIS PINS. The W2 admission + emitter path (src/c2pool/v37/
// w2_admission.hpp, w2_receipt.hpp) reproduces the proto RDWR admission
// reference (proto/w2-rdwr-kat/harness/rdwr_ref.py) BIT-FOR-BIT on the golden
// vectors, stamp
//   7ac46235e65022ed69afe426f5bf5f8767207ec201050b10e36b7106658d8b51
// (golden/w2_rdwr_kat_v1.json), and drives every accepted push END-TO-END
// through the W0 V37Engine::submit_tracked seam (which wraps the private W1
// executor), never touching Lane / LaneExecutor directly. Expected values are
// embedded as literals from that golden (KAT plan §2); a regenerated golden is
// a visible diff.
//
// RULING (W2-F-A, operator 2026-09-04): OPTION (a) — carrier-position credit
// for V37.0. Receipts credit at the carrier/arrival position (Lane::push's
// native behaviour); NO origin-bin positioned insert. KR-1 exercises branch (a)
// only (freshness-quirk Δ0/Δ1/Δ2 → identical credit); branch (b) is not built
// (no positioned-insert surface exists — see the spec / PR body).
//
// LEG DISCIPLINE (spec §8): only admissible-leg quantities are compared to the
// golden — raw work, identity key, push order, flags, dispositions, dedup,
// window sizes, next_pos. NO decayed value is asserted (OI-7-blocked); the lane
// digest is compared only INTRA-engine (relational), never across
// implementations (the reference has no lane).

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace c2pool::v37n;
using ::v37::LaneRecord;
using ::v37::LaneParams;
using ::v37::LaneSnapshot;
using ::v37::PayoutDescriptor;
using ::v37::SubmitResult;
using ::v37::SubmitStatus;
using ::v37::bytes32;
using ::v37::ChainId;
using V37Engine = c2pool::v37n::V37Engine;

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

// ── golden literals (from golden/w2_rdwr_kat_v1.json, stamp 7ac46235) ──────
static const char* GOLD_KA1_PUSH_DIGEST =
    "d7adff5dc35d0a4390e71d998bba3f5e92b827b6e0ea5fb5105d05d07283440f";
static const std::uint64_t GOLD_KA1_RAW_TOTAL = 768;
static const char* GOLD_KA2_PUSH_DIGEST_SINGLE =
    "92df6bd2d56e42e9bda9e77867ee307863847ecdf50a7c1e58537652da7ce271";
static const std::uint64_t GOLD_KA2_RAW_TOTAL = 1024;
static const char* GOLD_KA4_PUSH_DIGEST_ABSENT =
    "906795793bf264291191f7b5528fa8b9d60f9df0b6b18cd4e40c61f460ddc77e";
static const std::vector<std::size_t> GOLD_KA3_WINDOW_SIZES =
    {3, 4, 5, 6, 5, 5, 5, 5, 5, 5, 5};
static const std::vector<u64> GOLD_KR1_AGE_DELTAS = {0, 0, 1, 2};

// ── fixture geometry / identities (KAT plan §1) ────────────────────────────
static const ChainId CHAIN = 1;
static const ChainId OTHER_CHAIN = 2;

static LaneParams small_params() {
    LaneParams p;
    p.window = 256; p.c0 = 128; p.rollup = 8;
    p.level_caps = {16}; p.half_life = 64; p.journal_depth = 16;
    return p;
}

// Reference identity key: sha256d("payout-identity:" + name) — matches
// rdwr_ref.identity_key so the reproduced push tuples hash to the golden.
static bytes32 ref_identity(const std::string& name) {
    std::vector<std::uint8_t> v;
    const std::string pre = "payout-identity:";
    for (char c : pre) v.push_back((std::uint8_t)c);
    for (char c : name) v.push_back((std::uint8_t)c);
    return ::v37::sha256d(v);
}

// Valid V37.0 P2PKH descriptor, one distinct identity per fill byte (as in
// v37_scaffold_test) — the REAL descriptor an accepted event is pushed under.
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}

static const bytes32 ALICE = ref_identity("alice");
static const bytes32 BOB = ref_identity("bob");
static PayoutDescriptor ALICE_DESC() { return mk_desc(0x11); }
static PayoutDescriptor BOB_DESC() { return mk_desc(0x22); }

// ── concrete injectable seams (KAT plan §2) ────────────────────────────────
struct KatMainchainIndex : IMainchainIndex {
    u64 tip; u64 horizon;
    std::map<bytes32, u64> by_hash;
    explicit KatMainchainIndex(u64 t, u64 h = 64) : tip(t), horizon(h) {
        u64 lo = tip > horizon ? tip - horizon : 0;
        for (u64 x = lo; x <= tip; ++x) by_hash[mainchain_hash(x)] = x;
    }
    std::optional<u64> height_of(const bytes32& h) const override {
        auto it = by_hash.find(h);
        return it == by_hash.end() ? std::nullopt : std::optional<u64>(it->second);
    }
};

struct KatShareTracker : IShareTracker {
    std::map<bytes32, std::set<bytes32>> chained;   // identity -> chained hashes
    bool has_prev_own(const bytes32& id, const bytes32& prev) const override {
        if (prev == W2_GENESIS_PREV_OWN) return true;
        auto it = chained.find(id);
        return it != chained.end() && it->second.count(prev) != 0;
    }
    void record_share(const bytes32& id, const bytes32& h) override {
        chained[id].insert(h);
    }
};

// ── mine: grind a nonce so the event clears its own bits (real sha256d PoW) ──
static WorkEvent mine(ChainId chain_id, const bytes32& identity,
                      const PayoutDescriptor& desc, u64 origin_bin,
                      const bytes32& prev_own, unsigned lz_bits, const char* tag,
                      u64 salt = 0) {
    WorkEvent ev;
    ev.chain_id = chain_id;
    ev.identity = identity;
    ev.descriptor = desc;
    ev.prev_block_hash = mainchain_hash(origin_bin);
    ev.prev_own_share = prev_own;
    ev.lz_bits = lz_bits ? lz_bits : consensus_lz(origin_bin);
    ev.tag = tag;
    u64 base = salt << 32;
    for (u64 nonce = base; nonce < base + (u64(1) << 22); ++nonce) {
        ev.nonce = nonce;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL mine: nonce space exhausted (%s)\n", tag);
    std::abort();
}

// ── the push-sequence digest (sha256 over ordered (identity,w_raw,flags)) ──
// Exactly rdwr_ref.push_sequence_digest — the W2 emitter's consensus-input
// commitment (NOT the lane digest).
static std::string push_seq_digest(const std::vector<EmittedPush>& ps) {
    std::vector<std::uint8_t> buf;
    for (const auto& p : ps) {
        buf.insert(buf.end(), p.identity.begin(), p.identity.end());
        for (int i = 0; i < 8; ++i) buf.push_back((std::uint8_t)(p.w_raw >> (8 * i)));
        for (int i = 0; i < 4; ++i) buf.push_back((std::uint8_t)(p.flags >> (8 * i)));
    }
    bytes32 d = ::v37::sha256(buf.data(), buf.size());
    static const char* hexd = "0123456789abcdef";
    std::string out;
    for (std::uint8_t b : d) { out += hexd[b >> 4]; out += hexd[b & 0xf]; }
    return out;
}

// ── the tee sink: record each emitted tuple AND drive the real V37Engine ────
struct Tee {
    V37Engine* engine = nullptr;
    ChainId chain = CHAIN;
    std::vector<EmittedPush> records;      // tuple source (for the digest)
    std::vector<SubmitResult> results;     // engine dispositions (parallel)
    void operator()(const EmittedPush& p) {
        records.push_back(p);
        if (engine) {
            auto fut = engine->submit_tracked(
                LaneRecord::push(chain, p.descriptor, p.w_raw, p.flags));
            results.push_back(fut.get());
        }
    }
};
static RecordSink tee_sink(Tee& t) {
    return [&t](const EmittedPush& p) { t(p); };
}

// Add a lane through the engine and return its minted incarnation.
static u64 add_lane(V37Engine& e, ChainId c) {
    auto r = e.submit_tracked(LaneRecord::add_lane(c, small_params())).get();
    CHECK(r.applied());
    auto s = e.snapshot(c);
    return s ? s->incarnation : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// KP-F2 — the work(target) narrowing (W2's own pure-function unit test)
// ═══════════════════════════════════════════════════════════════════════════
static void test_work_narrowing() {
    // (a) the lz form bridges to the full-256-bit path (the consensus values).
    CHECK(work_from_target(target_of_lz(8)) == work_of_lz(8));   // 256
    CHECK(work_from_target(target_of_lz(9)) == work_of_lz(9));   // 512
    CHECK(work_from_target(target_of_lz(0)) == 1);               // max target
    CHECK(work_from_target(target_of_lz(63)) == work_of_lz(63)); // 2^63
    // (b) SATURATION, never wrap/truncate (KP-F2 / #859): a value that exceeds
    // u64 clamps to UINT64_MAX. lz>=64 overflows; an all-zero target (T=0 =>
    // attempts = 2^256) clamps rather than wrapping to a tiny/zero value.
    CHECK(work_of_lz(64) == UINT64_MAX);
    CHECK(work_from_target(target_of_lz(64)) == UINT64_MAX);
    CHECK(work_from_target(target_of_lz(200)) == UINT64_MAX);
    bytes32 zero{};                       // T = 0
    CHECK(work_from_target(zero) == UINT64_MAX);
    // (c) an exact non-power-of-two mid-range value (cross-checked vs Python
    // 2^256//(T+1)): T+1 = 5*2^192 => 2^64/5 floored.
    bytes32 t{}; t.fill(0xff); t[7] = 0x05; for (int i = 0; i < 7; ++i) t[i] = 0;
    CHECK(work_from_target(t) == 3074457345618258602ull);
    // work is never zero for any real target => admission never emits w_raw==0.
    CHECK(work_of_lz(0) == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-1 — recovery envelope: a stale share recovered at FULL work(T_origin)
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka1_recovery_envelope() {
    KatMainchainIndex idx(110);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;

    WorkEvent c0 = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KA1.c0");
    auto r0 = adm.admit(c0, {}, tee_sink(tee));
    CHECK(r0.carrier_status == CarrierStatus::OK);

    WorkEvent stale = mine(CHAIN, ALICE, ALICE_DESC(), 101, c0.hash(), 0, "KA1.stale");
    WorkEvent c1 = mine(CHAIN, ALICE, ALICE_DESC(), 102, c0.hash(), 0, "KA1.c1", 1);
    ::v37::u128 before = adm.raw_total();
    u64 pos_before = adm.next_pos();
    auto r1 = adm.admit(c1, {stale}, tee_sink(tee));

    // KA-1a receipt admitted.
    CHECK(r1.receipts.size() == 1 && r1.receipts[0].second == Disposition::OK);
    // KA-1b exactly two pushes for c1 (carrier, receipt) in that order, flags.
    CHECK(r1.pushes.size() == 2);
    CHECK(r1.pushes[0].flags == W2_CARRIER_FLAGS);
    CHECK(r1.pushes[1].flags == (W2_CARRIER_FLAGS | W2_L0F_RECEIPT));
    // KA-1c receipt push carries FULL work(T_origin).
    CHECK(r1.pushes[1].w_raw == stale.work());
    CHECK(stale.work() == 256);
    // KA-1d self-carriage: receipt push under the carrier identity + descriptor;
    // and both SubmitResult.miner equal.
    CHECK(r1.pushes[1].identity == c1.identity);
    CHECK(r1.pushes[1].descriptor.identity_key() == c1.descriptor.identity_key());
    // results: [c0][c1,stale] -> indices 1 (c1) and 2 (stale) share a miner id.
    CHECK(tee.results.size() == 3);
    CHECK(tee.results[1].miner == tee.results[2].miner);
    // KA-1e raw-work leg (model + engine agree).
    CHECK((u64)(adm.raw_total() - before) == c1.work() + stale.work());
    auto snap = e.snapshot(CHAIN);
    CHECK(snap != nullptr);
    CHECK((u64)snap->raw_total == GOLD_KA1_RAW_TOTAL);
    CHECK((u64)adm.raw_total() == GOLD_KA1_RAW_TOTAL);
    CHECK((u64)snap->raw_work_in_span(pos_before, pos_before + 1) ==
          c1.work() + stale.work());
    // KA-1f conservation: raw credited == Σ work over every target-meeting hash.
    u64 found = c0.work() + stale.work() + c1.work();
    CHECK((u64)snap->raw_total == found);
    // C++-only: applied()==true, lane_version increments by 1 per record.
    for (const auto& r : tee.results) CHECK(r.applied());
    CHECK(tee.results[0].lane_version == 2);   // AddLane=1, c0=2
    CHECK(tee.results[1].lane_version == 3);
    CHECK(tee.results[2].lane_version == 4);
    // GOLDEN: reproduced push-sequence digest over r0.pushes + r1.pushes.
    CHECK(push_seq_digest(tee.records) == GOLD_KA1_PUSH_DIGEST);
    e.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-2 — dedup idempotence + push-sequence digest equality
// ═══════════════════════════════════════════════════════════════════════════
struct Ka2Run {
    std::vector<EmittedPush> pushes;
    std::vector<std::pair<std::string, ReceiptAdmitter::Result>> outs;
    u64 raw_total = 0;
    bytes32 digest{};
};

static Ka2Run ka2_run(const std::string& mode) {
    KatMainchainIndex idx(110);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;

    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KA2.a");
    Ka2Run run;
    run.outs.push_back({"a", adm.admit(a, {}, tee_sink(tee))});
    WorkEvent st = mine(CHAIN, ALICE, ALICE_DESC(), 101, a.hash(), 0, "KA2.stale");
    WorkEvent b = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KA2.b", 1);
    WorkEvent c = mine(CHAIN, ALICE, ALICE_DESC(), 103, a.hash(), 0, "KA2.c", 2);
    if (mode == "single") {
        run.outs.push_back({"b", adm.admit(b, {st}, tee_sink(tee))});
        run.outs.push_back({"c", adm.admit(c, {}, tee_sink(tee))});
    } else if (mode == "wire-dup") {
        run.outs.push_back({"b", adm.admit(b, {st, st}, tee_sink(tee))});
        run.outs.push_back({"c", adm.admit(c, {}, tee_sink(tee))});
    } else if (mode == "cross-carrier") {
        run.outs.push_back({"b", adm.admit(b, {st}, tee_sink(tee))});
        run.outs.push_back({"c", adm.admit(c, {st}, tee_sink(tee))});
    } else if (mode == "chained-then-receipt") {
        run.outs.push_back({"b", adm.admit(b, {st}, tee_sink(tee))});
        run.outs.push_back({"c", adm.admit(c, {b}, tee_sink(tee))});
    }
    run.pushes = tee.records;
    run.raw_total = (u64)adm.raw_total();
    auto snap = e.snapshot(CHAIN);
    run.digest = snap->digest;
    e.stop();
    return run;
}

static void test_ka2_dedup() {
    Ka2Run single = ka2_run("single");
    std::string d_single = push_seq_digest(single.pushes);
    // GOLDEN: single-credit push digest.
    CHECK(d_single == GOLD_KA2_PUSH_DIGEST_SINGLE);
    CHECK(single.raw_total == GOLD_KA2_RAW_TOTAL);

    Ka2Run wire = ka2_run("wire-dup");
    // KA-2a wire-duplicate: second copy REJECT_DEDUP.
    CHECK(wire.outs[1].second.receipts.size() == 2);
    CHECK(wire.outs[1].second.receipts[0].second == Disposition::OK);
    CHECK(wire.outs[1].second.receipts[1].second == Disposition::REJECT_DEDUP);
    // KA-2b digest == single (and intra-engine lane digest equal).
    CHECK(push_seq_digest(wire.pushes) == d_single);
    CHECK(wire.digest == single.digest);

    Ka2Run cross = ka2_run("cross-carrier");
    // KA-2c later carrier's dup receipt REJECT_DEDUP, carrier stands, 1 record.
    CHECK(cross.outs[2].second.receipts[0].second == Disposition::REJECT_DEDUP);
    CHECK(cross.outs[2].second.carrier_status == CarrierStatus::OK);
    CHECK(cross.outs[2].second.pushes.size() == 1);
    // KA-2d digest == single.
    CHECK(push_seq_digest(cross.pushes) == d_single);
    CHECK(cross.digest == single.digest);

    Ka2Run ct = ka2_run("chained-then-receipt");
    // KA-2e a chained share re-presented as a receipt: REJECT_DEDUP.
    CHECK(ct.outs[2].second.receipts[0].second == Disposition::REJECT_DEDUP);
    // KA-2f raw_total identical across all dup modes.
    CHECK(wire.raw_total == single.raw_total);
    CHECK(cross.raw_total == single.raw_total);
    CHECK(ct.raw_total == single.raw_total);

    // KA-2g pruned: after N_CTX+2 the SAME hash is rejected by EXPIRY (gone from
    // the window), never a second credit.
    KatMainchainIndex idx(120);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;
    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KA2p.a");
    adm.admit(a, {}, tee_sink(tee));
    WorkEvent st = mine(CHAIN, ALICE, ALICE_DESC(), 101, a.hash(), 0, "KA2p.stale");
    WorkEvent b = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KA2p.b", 1);
    adm.admit(b, {st}, tee_sink(tee));
    CHECK(adm.window().contains(st.hash()));
    u64 late_bin = 102 + W2_DEDUP_RETENTION + 1;
    WorkEvent late = mine(CHAIN, ALICE, ALICE_DESC(), late_bin, a.hash(), 0, "KA2p.late", 3);
    auto o_late = adm.admit(late, {st}, tee_sink(tee));
    CHECK(o_late.receipts[0].second == Disposition::REJECT_EXPIRED);
    CHECK(o_late.pushes.size() == 1);              // just the late carrier
    CHECK(!adm.window().contains(st.hash()));      // pruned away, not re-credited
    e.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-3 — exact N_CTX expiry boundary + window-store bound
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka3_expiry_window() {
    KatMainchainIndex idx(120);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;

    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KA3.a");
    adm.admit(a, {}, tee_sink(tee));
    WorkEvent edge = mine(CHAIN, ALICE, ALICE_DESC(), 105 - W2_N_CTX, a.hash(), 0, "KA3.edge");
    WorkEvent over = mine(CHAIN, ALICE, ALICE_DESC(), 105 - W2_N_CTX - 1, a.hash(), 0, "KA3.over");
    WorkEvent future = mine(CHAIN, ALICE, ALICE_DESC(), 106, a.hash(), 0, "KA3.future");
    WorkEvent unres = mine(CHAIN, ALICE, ALICE_DESC(), 10, a.hash(), 0, "KA3.unres");
    WorkEvent cur = mine(CHAIN, ALICE, ALICE_DESC(), 105, a.hash(), 0, "KA3.c105", 1);
    auto o = adm.admit(cur, {edge, over, future, unres}, tee_sink(tee));

    CHECK(o.receipts[0].second == Disposition::OK);              // KA-3a Δ==N_CTX
    CHECK(o.receipts[1].second == Disposition::REJECT_EXPIRED);  // KA-3b Δ==N_CTX+1
    CHECK(o.receipts[2].second == Disposition::REJECT_EXPIRED);  // KA-3c future bin
    CHECK(o.receipts[3].second == Disposition::REJECT_EXPIRED);  // KA-3d unresolvable
    CHECK(o.carrier_status == CarrierStatus::OK);
    CHECK(o.pushes.size() == 2);                                 // KA-3e cur + edge

    // KA-3f/3g window-store bound: drive 11 carriers at bins 106..116; the store
    // holds exactly the events accounted within the N_CTX+2 horizon.
    std::vector<std::size_t> sizes;
    for (int k = 1; k <= 11; ++k) {
        u64 now = 105 + k;
        WorkEvent nxt = mine(CHAIN, ALICE, ALICE_DESC(), now, a.hash(), 0, "KA3.w", 10 + k);
        adm.admit(nxt, {}, tee_sink(tee));
        sizes.push_back(adm.window().size());
    }
    CHECK(sizes == GOLD_KA3_WINDOW_SIZES);
    CHECK(sizes.back() == (std::size_t)(W2_DEDUP_RETENTION + 1));  // steady state
    e.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-4 — binding rejection matrix (chain / payee / prev-own / R-1 / PoW)
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka4_binding_matrix() {
    // A run of {a(ALICE)@998, ob(BOB)@998, c(ALICE)@1000 with bad receipts}.
    // tip 1010 straddles the retarget at bin 1000 (lz 8->9). Fresh engine per
    // run so hashes/positions are stable.
    struct RunOut { std::vector<EmittedPush> pushes; ReceiptAdmitter::Result c_out; bytes32 digest; };
    auto run = [&](const std::vector<WorkEvent>& bad) {
        KatMainchainIndex idx(1010);
        KatShareTracker trk;
        V37Engine e; e.start();
        u64 inc = add_lane(e, CHAIN);
        ReceiptAdmitter adm(CHAIN, idx, trk, inc);
        Tee tee; tee.engine = &e; tee.chain = CHAIN;
        WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 998, W2_GENESIS_PREV_OWN, 0, "KA4.a");
        WorkEvent ob = mine(CHAIN, BOB, BOB_DESC(), 998, W2_GENESIS_PREV_OWN, 0, "KA4.bob", 5);
        adm.admit(a, {}, tee_sink(tee));
        adm.admit(ob, {}, tee_sink(tee));
        WorkEvent c = mine(CHAIN, ALICE, ALICE_DESC(), 1000, a.hash(), 0, "KA4.c", 1);
        auto c_out = adm.admit(c, bad, tee_sink(tee));
        RunOut o{tee.records, c_out, e.snapshot(CHAIN)->digest};
        e.stop();
        return o;
    };

    // Receipt-absent baseline (for exhibit hashes bound to a stable engine).
    RunOut absent = run({});
    std::string d_absent = push_seq_digest(absent.pushes);
    CHECK(d_absent == GOLD_KA4_PUSH_DIGEST_ABSENT);

    // Build exhibits (need a.hash()/ob.hash() — re-mine deterministically; the
    // preimage is a pure function of the fields, so hashes match the run above).
    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 998, W2_GENESIS_PREV_OWN, 0, "KA4.a");
    WorkEvent ob = mine(CHAIN, BOB, BOB_DESC(), 998, W2_GENESIS_PREV_OWN, 0, "KA4.bob", 5);
    WorkEvent wrong_chain = mine(OTHER_CHAIN, ALICE, ALICE_DESC(), 999, a.hash(), 0, "KA4.wrong-chain");
    WorkEvent wrong_payee = mine(CHAIN, BOB, BOB_DESC(), 999, ob.hash(), 0, "KA4.wrong-payee");
    bytes32 bad_prev; bad_prev.fill(0x77);
    WorkEvent bad_prev_ev = mine(CHAIN, ALICE, ALICE_DESC(), 999, bad_prev, 0, "KA4.bad-prev");
    // R-1: bound to bin 1000 (hard) but claiming the easy target.
    WorkEvent r1_easy = mine(CHAIN, ALICE, ALICE_DESC(), 1000, a.hash(), W2_LZ_EASY, "KA4.r1-easy-at-hard");
    // R-1 mirror: bound to bin 999 (easy) but claiming the hard target (pin is
    // equality, not >=).
    WorkEvent r1_hard = mine(CHAIN, ALICE, ALICE_DESC(), 999, a.hash(), W2_LZ_HARD, "KA4.r1-hard-at-easy");
    WorkEvent tampered = mine(CHAIN, ALICE, ALICE_DESC(), 999, a.hash(), 0, "KA4.tampered");
    tampered.nonce += 1;   // PoW no longer holds

    // batch1 (<= R_MAX): first four exhibits; batch2: the last two.
    RunOut b1 = run({wrong_chain, wrong_payee, bad_prev_ev, r1_easy});
    RunOut b2 = run({r1_hard, tampered});
    std::vector<Disposition> disp;
    for (auto& r : b1.c_out.receipts) disp.push_back(r.second);
    for (auto& r : b2.c_out.receipts) disp.push_back(r.second);
    std::vector<Disposition> want = {
        Disposition::REJECT_CHAIN, Disposition::REJECT_IDENTITY,
        Disposition::REJECT_PREV_OWN, Disposition::REJECT_R1_TARGET,
        Disposition::REJECT_R1_TARGET, Disposition::REJECT_POW};
    CHECK(disp == want);                                       // KA-4a..f
    // KA-4g each rejection: no receipt push, carrier stands (1 record for c).
    CHECK(b1.c_out.carrier_status == CarrierStatus::OK && b1.c_out.pushes.size() == 1);
    CHECK(b2.c_out.carrier_status == CarrierStatus::OK && b2.c_out.pushes.size() == 1);
    // KA-4h push digest (and intra-engine lane digest) == receipt-absent run.
    CHECK(push_seq_digest(b1.pushes) == d_absent);
    CHECK(push_seq_digest(b2.pushes) == d_absent);
    CHECK(b1.digest == absent.digest);
    CHECK(b2.digest == absent.digest);
    // KA-4i the wrong-chain receipt has VALID PoW (rejection is the binding).
    CHECK(wrong_chain.meets_own_target());
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-5 — receipt->push mapping determinism (wire order, mixed validity, R_MAX)
// ═══════════════════════════════════════════════════════════════════════════
struct Ka5Fixture {
    KatMainchainIndex idx{1010};
    KatShareTracker trk;
    V37Engine e;
    std::unique_ptr<ReceiptAdmitter> adm;
    WorkEvent a, r0, r1, r2, r3, bad, c;
    Ka5Fixture() {
        e.start();
        u64 inc = add_lane(e, CHAIN);
        adm = std::make_unique<ReceiptAdmitter>(CHAIN, idx, trk, inc);
        a = mine(CHAIN, ALICE, ALICE_DESC(), 998, W2_GENESIS_PREV_OWN, 0, "KA5.a");
        Tee boot; boot.engine = &e; boot.chain = CHAIN;
        adm->admit(a, {}, tee_sink(boot));    // 'a' at pos 0
        u64 bins[4] = {999, 1000, 1001, 999};
        r0 = mine(CHAIN, ALICE, ALICE_DESC(), bins[0], a.hash(), 0, "KA5.r0", 100);
        r1 = mine(CHAIN, ALICE, ALICE_DESC(), bins[1], a.hash(), 0, "KA5.r1", 101);
        r2 = mine(CHAIN, ALICE, ALICE_DESC(), bins[2], a.hash(), 0, "KA5.r2", 102);
        r3 = mine(CHAIN, ALICE, ALICE_DESC(), bins[3], a.hash(), 0, "KA5.r3", 103);
        bad = mine(OTHER_CHAIN, ALICE, ALICE_DESC(), 1000, a.hash(), 0, "KA5.bad");
        c = mine(CHAIN, ALICE, ALICE_DESC(), 1001, a.hash(), 0, "KA5.c", 1);
    }
    ~Ka5Fixture() { e.stop(); }
};

static void test_ka5_push_mapping() {
    {   // KA-5a/b/c: wire order [r0, bad, r1, r2] -> [c, r0, r1, r2].
        Ka5Fixture f;
        Tee tee; tee.engine = &f.e; tee.chain = CHAIN;
        auto o = f.adm->admit(f.c, {f.r0, f.bad, f.r1, f.r2}, tee_sink(tee));
        CHECK(o.pushes.size() == 4);
        std::vector<std::string> tags;
        for (auto& p : o.pushes) tags.push_back(p.tag);
        CHECK((tags == std::vector<std::string>{"KA5.c", "KA5.r0", "KA5.r1", "KA5.r2"}));
        std::vector<std::uint32_t> fl;
        for (auto& p : o.pushes) fl.push_back(p.flags & W2_L0F_RECEIPT);
        CHECK((fl == std::vector<std::uint32_t>{0, W2_L0F_RECEIPT, W2_L0F_RECEIPT, W2_L0F_RECEIPT}));
        std::vector<u64> pos;
        for (auto& p : o.pushes) pos.push_back(p.pos);
        CHECK((pos == std::vector<u64>{1, 2, 3, 4}));           // receipts DO advance next_pos
        auto snap = f.e.snapshot(CHAIN);
        CHECK(snap->next_pos == 5);                            // a + c + 3 receipts
    }
    // KA-5d: permuted wire order => different sequence, same accept SET.
    std::vector<u64> w_wire, w_perm;
    {
        Ka5Fixture f;
        auto o = f.adm->admit(f.c, {f.r0, f.bad, f.r1, f.r2});
        for (auto& p : o.pushes) w_wire.push_back(p.w_raw);
    }
    {
        Ka5Fixture f;
        auto o = f.adm->admit(f.c, {f.r2, f.r1, f.bad, f.r0});
        for (auto& p : o.pushes) w_perm.push_back(p.w_raw);
    }
    CHECK(w_wire != w_perm);                                   // order-sensitive
    {
        std::vector<u64> a = w_wire, b = w_perm;
        std::sort(a.begin(), a.end()); std::sort(b.begin(), b.end());
        CHECK(a == b);                                         // same accept set
    }
    // KA-5e: > R_MAX => whole carrier rejected at decode, ZERO pushes, next_pos
    // unchanged (emitter never fires).
    {
        Ka5Fixture f;
        auto o = f.adm->admit(f.c, {f.r0, f.r1, f.r2, f.r3, f.bad});
        CHECK(o.carrier_status == CarrierStatus::REJECT_RMAX);
        CHECK(o.pushes.empty());
        CHECK(f.adm->next_pos() == 1);                         // only 'a' pushed
        CHECK(f.e.snapshot(CHAIN)->next_pos == 1);
    }
    // KA-5f: exactly R_MAX accepted => 1 carrier + 4 receipts.
    {
        Ka5Fixture f;
        auto o = f.adm->admit(f.c, {f.r0, f.r1, f.r2, f.r3});
        CHECK(o.pushes.size() == 1 + W2_R_MAX);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-6 — SubmitStatus handling at the seam (pins executor semantics W2 honors)
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka6_submit_status() {
    V37Engine e; e.start();
    CHECK(e.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get().applied());
    // A good push, then the three Push-time rejections W2 must treat as
    // carrier-reject (never a crash) — matching v37_executor_test semantics.
    auto ok = e.submit_tracked(LaneRecord::push(CHAIN, ALICE_DESC(), 9, 0)).get();
    CHECK(ok.status == SubmitStatus::Applied);
    u64 v_after_ok = ok.lane_version;
    // Zero work: a receipt whose work narrowed to 0 would be inadmissible; the
    // executor rejects w_raw==0 and does NOT bump the version.
    auto zw = e.submit_tracked(LaneRecord::push(CHAIN, ALICE_DESC(), 0, 0)).get();
    CHECK(zw.status == SubmitStatus::RejectedZeroWork);
    CHECK(zw.lane_version == v_after_ok);
    // Invalid descriptor (attribution set): rejected, treated as carrier-reject.
    PayoutDescriptor attributed = ALICE_DESC();
    attributed.attribution = attributed.pay;   // V37.0 forbids attribution
    auto bad = e.submit_tracked(LaneRecord::push(CHAIN, attributed, 9, 0)).get();
    CHECK(bad.status == SubmitStatus::RejectedInvalidDescriptor);
    // Unknown chain.
    auto unk = e.submit_tracked(LaneRecord::push(99, ALICE_DESC(), 9, 0)).get();
    CHECK(unk.status == SubmitStatus::RejectedUnknownChain);
    e.stop();
    // After stop(): the future's get() throws; W2 must catch and drop.
    bool threw = false;
    try {
        (void)e.submit_tracked(LaneRecord::push(CHAIN, ALICE_DESC(), 9, 0)).get();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-7 — dedup window keyed on lane INCARNATION (W2-F-D / F2)
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka7_incarnation() {
    KatMainchainIndex idx(110);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc1 = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc1);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;

    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KA7.a");
    adm.admit(a, {}, tee_sink(tee));
    WorkEvent st = mine(CHAIN, ALICE, ALICE_DESC(), 101, a.hash(), 0, "KA7.stale");
    WorkEvent b = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KA7.b", 1);
    auto o_b = adm.admit(b, {st}, tee_sink(tee));
    CHECK(o_b.receipts[0].second == Disposition::OK);

    // RemoveLane -> AddLane: the executor mints a fresh incarnation; the durable
    // tracker survives, the lane-scoped window does NOT.
    CHECK(e.submit_tracked(LaneRecord::remove_lane(CHAIN)).get().applied());
    CHECK(e.snapshot(CHAIN) == nullptr);
    u64 inc2 = add_lane(e, CHAIN);
    CHECK(inc2 == inc1 + 1);                                   // KA-7a advanced
    adm.reset_incarnation(inc2);                              // W2 resets its window
    CHECK(adm.window().incarnation() == inc2);

    WorkEvent b2 = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KA7.b2", 2);
    auto o_b2 = adm.admit(b2, {st}, tee_sink(tee));
    // KA-7b same receipt hash re-admissible (window reset); a (chain,version)
    // key would wrongly say REJECT_DEDUP.
    CHECK(o_b2.receipts[0].second == Disposition::OK);
    CHECK(o_b2.carrier_status == CarrierStatus::OK);           // KA-7c
    e.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// KA-8 — L0F_RECEIPT is digest-neutral (proves spec §6 in C++)
// ═══════════════════════════════════════════════════════════════════════════
static void test_ka8_flag_neutrality() {
    // Two engines, identical push stream; A tags receipts with L0F_RECEIPT,
    // B with 0x00. digest / raw_total / next_pos / bands must be identical.
    auto build = [](std::uint32_t receipt_flag) {
        auto e = std::make_unique<V37Engine>();
        e->start();
        e->submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
        PayoutDescriptor d = ALICE_DESC();
        e->submit_tracked(LaneRecord::push(CHAIN, d, 256, 0)).get();          // carrier
        e->submit_tracked(LaneRecord::push(CHAIN, d, 256, receipt_flag)).get(); // receipt
        e->submit_tracked(LaneRecord::push(CHAIN, d, 512, receipt_flag)).get();
        return e;
    };
    auto A = build(W2_L0F_RECEIPT);
    auto B = build(0x00);
    auto sa = A->snapshot(CHAIN);
    auto sb = B->snapshot(CHAIN);
    CHECK(sa && sb);
    CHECK(sa->digest == sb->digest);
    CHECK(sa->raw_total == sb->raw_total);
    CHECK(sa->next_pos == sb->next_pos);
    CHECK(sa->bands.size() == sb->bands.size());
    bool bands_eq = sa->bands.size() == sb->bands.size();
    for (std::size_t i = 0; bands_eq && i < sa->bands.size(); ++i)
        bands_eq = sa->bands[i].pos_lo == sb->bands[i].pos_lo &&
                   sa->bands[i].pos_hi == sb->bands[i].pos_hi &&
                   sa->bands[i].raw_work == sb->bands[i].raw_work;
    CHECK(bands_eq);
    A->stop();
    B->stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// KR-1 — credit position, branch (a) ONLY (W2-F-A ruling)
// ═══════════════════════════════════════════════════════════════════════════
static void test_kr1_carrier_position_branch_a() {
    // c@102 carries [on_time@102, late1@101, late2@100] (age deltas 0,1,2=N_CTX).
    KatMainchainIndex idx(110);
    KatShareTracker trk;
    V37Engine e; e.start();
    u64 inc = add_lane(e, CHAIN);
    ReceiptAdmitter adm(CHAIN, idx, trk, inc);
    Tee tee; tee.engine = &e; tee.chain = CHAIN;

    WorkEvent a = mine(CHAIN, ALICE, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "KR1.a");
    adm.admit(a, {}, tee_sink(tee));
    WorkEvent on_time = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KR1.age0");
    WorkEvent late1 = mine(CHAIN, ALICE, ALICE_DESC(), 101, a.hash(), 0, "KR1.age1");
    WorkEvent late2 = mine(CHAIN, ALICE, ALICE_DESC(), 100, a.hash(), 0, "KR1.age2");
    WorkEvent c = mine(CHAIN, ALICE, ALICE_DESC(), 102, a.hash(), 0, "KR1.c", 1);
    auto o = adm.admit(c, {on_time, late1, late2}, tee_sink(tee));

    // Data leg (golden 7ac46235 KR-1): the age-delta vector over the whole
    // credit-placement (carrier + 3 receipts), recorded not ruled.
    std::vector<u64> deltas;
    for (auto& p : o.pushes) deltas.push_back(p.age_delta());
    CHECK(deltas == GOLD_KR1_AGE_DELTAS);                     // [0,0,1,2]
    CHECK(o.pushes[0].age_delta() == 0);                     // carrier is age 0

    // RULING (a): every accepted push — carrier and receipt, any age — is
    // credited at the CARRIER ARRIVAL POSITION, exactly as an ordinary push of
    // the same w_raw at the same position. Positions are consecutive from the
    // carrier (no age-driven placement): a receipt push at position p behaves
    // identically to a fresh share at p. Corollary (the "freshness quirk"):
    // age0/age1/age2 receive IDENTICAL credit despite Δ = 0/1/2 bins.
    std::vector<u64> positions;
    for (auto& p : o.pushes) positions.push_back(p.pos);
    CHECK((positions == std::vector<u64>{1, 2, 3, 4}));       // carrier-arrival, consecutive

    // Freshness-quirk exhibit, checked intra-engine and OI-7-agnostically: on a
    // SECOND engine, push three ORDINARY (fresh) shares of the same w_raw at the
    // same positions with flags=0; the resulting lane state (digest, raw_total,
    // bands, next_pos) is byte-identical to the receipt run. That is exactly the
    // ruling-(a) statement "receipts are credited as fresh work" — and it needs
    // no decayed-value pin (blocked by OI-7).
    V37Engine e2; e2.start();
    e2.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
    // Replay the FULL stream engine e saw (a + carrier + 3 receipts, captured
    // by the tee) with the receipt flag stripped to 0: same identities, w_raw,
    // and positions, as ordinary fresh work.
    for (auto& p : tee.records)
        e2.submit_tracked(LaneRecord::push(CHAIN, p.descriptor, p.w_raw, 0)).get();
    auto s1 = e.snapshot(CHAIN);
    auto s2 = e2.snapshot(CHAIN);
    CHECK(s1->digest == s2->digest);       // receipt push ≡ ordinary push (a)
    CHECK(s1->raw_total == s2->raw_total);
    CHECK(s1->next_pos == s2->next_pos);
    // All three receipt credits are equal (fresh work basis, Δ-independent): the
    // three receipt bands carry identical raw_work (256 each, same target/bin).
    CHECK(on_time.work() == late1.work() && late1.work() == late2.work());
    e.stop();
    e2.stop();
}

int main() {
    test_work_narrowing();
    test_ka1_recovery_envelope();
    test_ka2_dedup();
    test_ka3_expiry_window();
    test_ka4_binding_matrix();
    test_ka5_push_mapping();
    test_ka6_submit_status();
    test_ka7_incarnation();
    test_ka8_flag_neutrality();
    test_kr1_carrier_position_branch_a();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
