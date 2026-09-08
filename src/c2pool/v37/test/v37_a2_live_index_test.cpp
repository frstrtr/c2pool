// V37 Track A2 step (b)(2) — LiveMainchainIndex / SyntheticMainchainIndex KAT.
// stdlib-only (no sockets, no Boost): drives the real IMainchainIndex seam
// (w2_admission.hpp:46-49) through carrier_index.hpp with a scripted probe and
// a scripted tip, and proves the three survey gaps closed (I-1 horizon, I-2
// tri-state bounded retry, I-3 per-hash cache) plus the synthetic model's
// byte-for-byte parity with the resolver v37_a2_multinode_test.cpp:99-107 builds
// by hand, the backend-binding templates type-checked against a fake backend
// that mirrors DashRpcCoinBackend's probe_header/best_tip surface (with the D6
// byte-order reversal exercised), and an end-to-end W2 ReceiptAdmitter::admit
// over the live index (OK within the horizon; REJECT_POW beyond it / off the
// active chain).
//
// Same hollow-green guard as the sibling suites: must be on the build.yml
// --target lists (both legs) and is audited by the src/c2pool/**/test/ drift-guard.
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/carrier_index.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>

using namespace c2pool::v37n;
using ::v37::bytes32;

static int g_checks = 0, g_failures = 0;
#define CHECK(cond) do { ++g_checks; if (!(cond)) { ++g_failures; \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

using ms = std::chrono::milliseconds;
static ms elapsed_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - t0);
}

static bytes32 h32(std::uint8_t seed) { bytes32 b{}; for (auto& x : b) x = seed++; return b; }

// ── a scripted probe: per hash, a queue of answers (last one repeats) ────────
struct FakeProbe {
    std::map<bytes32, std::deque<IndexProbe>> script;
    int calls = 0;
    void set(const bytes32& h, std::vector<IndexProbe> seq) { script[h].assign(seq.begin(), seq.end()); }
    IndexProbe operator()(const bytes32& h) {
        ++calls;
        auto it = script.find(h);
        if (it == script.end() || it->second.empty()) return IndexProbe::missing();
        IndexProbe p = it->second.front();
        if (it->second.size() > 1) it->second.pop_front();
        return p;
    }
};
struct FakeTip {
    std::deque<std::optional<u64>> seq;   // last repeats
    int calls = 0;
    std::optional<u64> operator()() {
        ++calls;
        if (seq.empty()) return std::nullopt;
        auto v = seq.front();
        if (seq.size() > 1) seq.pop_front();
        return v;
    }
};
static LiveMainchainIndex::Options fast_opts(u64 horizon = 64, int patience_ms = 200,
                                             int backoff_ms = 10, int ttl_ms = 2000) {
    LiveMainchainIndex::Options o;
    o.horizon = horizon; o.unknown_patience = ms(patience_ms);
    o.unknown_backoff = ms(backoff_ms); o.cache_ttl = ms(ttl_ms);
    return o;
}
// Bind by reference so the test can inspect/mutate the scripts after construction.
static LiveMainchainIndex make(FakeProbe& p, FakeTip& t, LiveMainchainIndex::Options o) {
    return LiveMainchainIndex([&p](const bytes32& h) { return p(h); }, [&t] { return t(); }, o);
}

// ── T1-T3: resolve / cache / Missing ────────────────────────────────────────
static void test_resolve_cache_missing() {
    FakeProbe P; FakeTip T; T.seq = {110};
    const bytes32 A = h32(1), M = h32(2);
    P.set(A, {IndexProbe::have(100, true)});
    LiveMainchainIndex ix = make(P, T, fast_opts());

    auto r = ix.height_of(A);
    CHECK(r && *r == 100);
    CHECK(P.calls == 1 && T.calls == 1);
    r = ix.height_of(A);                              // cached: no probe, no tip pull (fresh)
    CHECK(r && *r == 100);
    CHECK(P.calls == 1 && T.calls == 1);
    auto st = ix.stats();
    CHECK(st.probes == 1 && st.cache_hits == 1 && st.resolved == 2 && st.tip_pulls == 1);

    const auto t0 = std::chrono::steady_clock::now();
    CHECK(!ix.height_of(M).has_value());              // Missing: nullopt, NO retry
    CHECK(elapsed_since(t0) < ms(50));
    st = ix.stats();
    CHECK(st.missing == 1 && st.unknown_retries == 0 && st.probes == 2);
    CHECK(!ix.height_of(M).has_value());              // Missing is never cached
    CHECK(ix.stats().probes == 3);

    ix.invalidate();
    r = ix.height_of(A);
    CHECK(r && *r == 100 && ix.stats().probes == 4);  // re-probed after invalidate
}

// ── T4-T5: tri-state — Unknown retried within patience, bounded ─────────────
static void test_unknown_bounded_retry() {
    FakeProbe P; FakeTip T; T.seq = {110};
    const bytes32 A = h32(3), U = h32(4);
    P.set(A, {IndexProbe::unknown(), IndexProbe::unknown(), IndexProbe::have(100, true)});
    P.set(U, {IndexProbe::unknown()});
    LiveMainchainIndex ix = make(P, T, fast_opts(64, /*patience*/200, /*backoff*/10));

    auto r = ix.height_of(A);                          // Unknown x2 then Have -> resolves
    CHECK(r && *r == 100);
    CHECK(P.calls == 3);
    CHECK(ix.stats().unknown_retries == 2);

    const auto t0 = std::chrono::steady_clock::now();
    CHECK(!ix.height_of(U).has_value());               // persistent Unknown -> nullopt after patience
    const ms e = elapsed_since(t0);
    CHECK(e >= ms(200) && e < ms(1200));
    CHECK(ix.stats().unknown_exhausted == 1);
    CHECK(P.calls >= 3 + 10);                          // it did keep asking (~patience/backoff)
    CHECK(!ix.height_of(U).has_value());               // and Unknown is never cached
}

// ── T6-T7: active-chain + horizon edges (I-1) ──────────────────────────────
static void test_inactive_and_horizon() {
    FakeProbe P; FakeTip T; T.seq = {110};
    const bytes32 I = h32(5), E = h32(6), B = h32(7), Tp = h32(8);
    P.set(I,  {IndexProbe::have(105, false)});         // known, off the active chain
    P.set(E,  {IndexProbe::have(46, true)});           // 110-46 == 64: exactly at the horizon
    P.set(B,  {IndexProbe::have(45, true)});           // 110-45 == 65: beyond
    P.set(Tp, {IndexProbe::have(110, true)});          // the tip itself
    LiveMainchainIndex ix = make(P, T, fast_opts(64));

    CHECK(!ix.height_of(I).has_value());
    CHECK(ix.stats().inactive == 1);
    auto r = ix.height_of(E);  CHECK(r && *r == 46);
    CHECK(!ix.height_of(B).has_value());
    CHECK(ix.stats().beyond_horizon == 1);
    r = ix.height_of(Tp);      CHECK(r && *r == 110);
    // a smaller horizon flips the edge
    FakeProbe P2; FakeTip T2; T2.seq = {110};
    P2.set(E, {IndexProbe::have(46, true)});
    LiveMainchainIndex ix2 = make(P2, T2, fast_opts(2));
    CHECK(!ix2.height_of(E).has_value() && ix2.stats().beyond_horizon == 1);
}

// ── T8: a header ahead of a stale tip view forces ONE refresh ──────────────
static void test_stale_tip_refresh_and_future() {
    FakeProbe P; FakeTip T; T.seq = {110, 111};         // first pull 110, then 111 forever
    const bytes32 N = h32(9), F = h32(10);
    P.set(N, {IndexProbe::have(111, true)});            // the block just past the cached tip
    P.set(F, {IndexProbe::have(200, true)});            // genuinely ahead
    LiveMainchainIndex ix = make(P, T, fast_opts());

    auto r = ix.height_of(N);
    CHECK(r && *r == 111);
    CHECK(T.calls == 2);                                // one forced refresh, not a spin
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(!ix.height_of(F).has_value());
    CHECK(elapsed_since(t0) < ms(50));                  // "future" is a verdict, not a wait
    CHECK(T.calls == 3 && ix.stats().future == 1);
}

// ── T9-T10: tip sources — none (fail-closed), push-only, push+pull ─────────
static void test_tip_sources() {
    const bytes32 A = h32(11);
    {   // no TipFn, no push: everything unresolvable within patience
        FakeProbe P; P.set(A, {IndexProbe::have(100, true)});
        LiveMainchainIndex ix([&P](const bytes32& h) { return P(h); }, nullptr, fast_opts(64, 100, 10));
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(!ix.height_of(A).has_value());
        CHECK(elapsed_since(t0) >= ms(100) && ix.stats().unknown_exhausted == 1);
        ix.observe_tip(110);                            // the height-watch push arrives
        auto r = ix.height_of(A);  CHECK(r && *r == 100);
        CHECK(ix.stats().tip_pulls == 0);               // never pulled: no TipFn
    }
    {   // push-only, stale push: a header past it is "future" (fail-closed), no spin
        FakeProbe P; P.set(A, {IndexProbe::have(111, true)});
        LiveMainchainIndex ix([&P](const bytes32& h) { return P(h); }, nullptr, fast_opts());
        ix.observe_tip(110);
        CHECK(!ix.height_of(A).has_value() && ix.stats().future == 1);
        ix.observe_tip(111);
        auto r = ix.height_of(A);  CHECK(r && *r == 111);
    }
    {   // pull fails after a good push: sticky last-known keeps resolving
        FakeProbe P; FakeTip T; T.seq = {std::nullopt};
        P.set(A, {IndexProbe::have(100, true)});
        LiveMainchainIndex ix = make(P, T, fast_opts(64, 100, 10, /*ttl*/ 0));   // ttl 0: never fresh
        ix.observe_tip(110);
        auto r = ix.height_of(A);  CHECK(r && *r == 100);
        CHECK(T.calls >= 1 && ix.stats().unknown_exhausted == 0);
    }
    {   // TipFn throws (ChainMismatch-shaped): treated as a failed pull, no propagation
        FakeProbe P; P.set(A, {IndexProbe::have(100, true)});
        LiveMainchainIndex ix([&P](const bytes32& h) { return P(h); },
                              []() -> std::optional<u64> { throw std::runtime_error("chain mismatch"); },
                              fast_opts(64, 100, 10));
        CHECK(!ix.height_of(A).has_value());            // no tip ever -> fail closed, no throw
    }
}

// ── T11: cache TTL expiry re-probes; cap clears ────────────────────────────
static void test_cache_ttl_and_cap() {
    FakeProbe P; FakeTip T; T.seq = {110};
    const bytes32 A = h32(12);
    P.set(A, {IndexProbe::have(100, true)});
    auto o = fast_opts(64, 200, 10, /*ttl*/ 30);
    o.cache_cap = 2;
    LiveMainchainIndex ix = make(P, T, o);
    CHECK(ix.height_of(A).has_value() && P.calls == 1);
    std::this_thread::sleep_for(ms(40));
    CHECK(ix.height_of(A).has_value() && P.calls == 2);   // expired -> re-probed
    // cap: 3 distinct hashes with cap 2 -> the cache was cleared once, all still resolve
    for (std::uint8_t s = 20; s < 23; ++s) { P.set(h32(s), {IndexProbe::have(100, true)}); CHECK(ix.height_of(h32(s)).has_value()); }
    CHECK(ix.stats().resolved == 5);
}

// ── T12: synthetic model parity with the multinode-test resolver ───────────
static void test_synthetic_parity() {
    auto reference = [](u64 tip, u64 horizon) {   // v37_a2_multinode_test.cpp:99-107, verbatim shape
        auto by_hash = std::make_shared<std::map<bytes32, u64>>();
        u64 lo = tip > horizon ? tip - horizon : 0;
        for (u64 x = lo; x <= tip; ++x) (*by_hash)[mainchain_hash(x)] = x;
        return [by_hash](const bytes32& h) -> std::optional<u64> {
            auto it = by_hash->find(h);
            return it == by_hash->end() ? std::nullopt : std::optional<u64>(it->second);
        };
    };
    SyntheticMainchainIndex s(110);
    auto ref = reference(110, 64);
    bool same = true;
    for (u64 x = 0; x <= 200; ++x) same = same && (s.height_of(mainchain_hash(x)) == ref(mainchain_hash(x)));
    CHECK(same);
    CHECK(s.height_of(mainchain_hash(46)) == std::optional<u64>(46));
    CHECK(!s.height_of(mainchain_hash(45)).has_value());
    CHECK(!s.height_of(mainchain_hash(111)).has_value());
    CHECK(!s.height_of(h32(1)).has_value());              // a REAL-shaped hash never resolves synthetically
    s.set_tip(120);
    CHECK(s.tip() == 120 && s.height_of(mainchain_hash(56)) == std::optional<u64>(56));
    CHECK(!s.height_of(mainchain_hash(55)).has_value());
    SyntheticMainchainIndex tiny(10, 64);                 // tip < horizon: lo clamps to 0
    CHECK(tiny.height_of(mainchain_hash(0)) == std::optional<u64>(0));
}

// ── T13: the backend-binding templates against a DashRpcCoinBackend-shaped fake
struct FakeHeaderProbe {
    enum class State : std::uint8_t { Have = 0, Missing = 1, Unknown = 2 };
    State state = State::Unknown; std::uint64_t height = 0; long long confirmations = 0;
    bool on_active_chain() const { return state == State::Have && confirmations >= 0; }
};
struct FakeCoinTip { std::uint64_t height = 0; std::string hash; };
struct FakeBackend {
    std::map<std::string, FakeHeaderProbe> by_display_hex;
    std::vector<std::string> asked;
    FakeCoinTip tip;
    bool throw_on_tip = false;
    FakeHeaderProbe probe_header(const std::string& display_hex) noexcept {
        asked.push_back(display_hex);
        auto it = by_display_hex.find(display_hex);
        if (it == by_display_hex.end()) { FakeHeaderProbe p; p.state = FakeHeaderProbe::State::Missing; return p; }
        return it->second;
    }
    FakeCoinTip best_tip() { if (throw_on_tip) throw std::runtime_error("chain mismatch"); return tip; }
};
// the D6 pin, restated locally ONLY to check the probe was asked in DISPLAY order
static std::string display_hex_of(const bytes32& internal) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) { const auto b = internal[31 - i]; s[2*i] = kHex[b >> 4]; s[2*i+1] = kHex[b & 15]; }
    return s;
}
static void test_backend_binding_templates() {
    auto be = std::make_shared<FakeBackend>();
    const bytes32 internal = h32(0);                      // 00 01 02 .. 1f
    const std::string disp = display_hex_of(internal);   // "1f1e1d...0100"
    CHECK(disp.rfind("1f1e1d", 0) == 0 && disp.substr(60) == "0100");
    FakeHeaderProbe hp; hp.state = FakeHeaderProbe::State::Have; hp.height = 100; hp.confirmations = 11;
    be->by_display_hex[disp] = hp;
    FakeHeaderProbe side = hp; side.confirmations = -1;   // dashd's "known, not on the active chain"
    be->by_display_hex[display_hex_of(h32(40))] = side;
    be->tip = FakeCoinTip{110, "deadbeef"};

    auto ix = make_live_mainchain_index<FakeBackend>(be, &display_hex_of, fast_opts());
    auto r = ix->height_of(internal);
    CHECK(r && *r == 100);
    CHECK(be->asked.size() == 1 && be->asked[0] == disp);   // asked in DISPLAY order (D6), not hex32(internal)
    CHECK(!ix->height_of(h32(40)).has_value() && ix->stats().inactive == 1);
    CHECK(!ix->height_of(h32(50)).has_value() && ix->stats().missing == 1);

    // best_tip() {0,"",0} (no good read yet) -> no tip -> fail closed within patience
    auto be2 = std::make_shared<FakeBackend>();
    be2->by_display_hex[disp] = hp;
    auto ix2 = make_live_mainchain_index<FakeBackend>(be2, &display_hex_of, fast_opts(64, 60, 10));
    CHECK(!ix2->height_of(internal).has_value() && ix2->stats().unknown_exhausted == 1);
    be2->tip = FakeCoinTip{110, "x"};
    CHECK(ix2->height_of(internal).has_value());
    // best_tip() throwing is swallowed (fail closed), never propagated to the reader thread
    be2->throw_on_tip = true;
    ix2->invalidate();
    auto ix3 = make_live_mainchain_index<FakeBackend>(be2, &display_hex_of, fast_opts(64, 60, 10));
    CHECK(!ix3->height_of(internal).has_value());
    // null backend -> Unknown -> exhausted, no crash
    auto ix4 = make_live_mainchain_index<FakeBackend>(std::shared_ptr<FakeBackend>(), &display_hex_of, fast_opts(64, 30, 10));
    CHECK(!ix4->height_of(internal).has_value());
}

// ── T14: end-to-end W2 ReceiptAdmitter over the live index ─────────────────
struct FakeTracker final : IShareTracker {
    std::set<std::pair<bytes32, bytes32>> chained;
    bool has_prev_own(const bytes32& id, const bytes32& prev) const override {
        return prev == W2_GENESIS_PREV_OWN || chained.count({id, prev}) != 0;
    }
    void record_share(const bytes32& id, const bytes32& h) override { chained.insert({id, h}); }
};
static ::v37::PayoutDescriptor desc_of(std::uint8_t fill) {
    ::v37::PayoutDescriptor d; ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH; r.payload.assign(20, fill); d.pay = r; return d;
}
static WorkEvent mine(const ::v37::PayoutDescriptor& d, const bytes32& prev_block, const bytes32& prev_own,
                      unsigned lz, const char* tag) {
    WorkEvent ev; ev.chain_id = 1; ev.identity = d.identity_key(); ev.descriptor = d;
    ev.prev_block_hash = prev_block; ev.prev_own_share = prev_own; ev.lz_bits = lz; ev.tag = tag;
    for (u64 n = 0; n < (u64(1) << 24); ++n) { ev.nonce = n; if (ev.meets_own_target()) return ev; }
    std::printf("FATAL: nonce exhausted\n"); std::abort();
}
static void test_admitter_end_to_end() {
    FakeProbe P; FakeTip T; T.seq = {110};
    const bytes32 real_parent = h32(60), older = h32(61), side = h32(62), ancient = h32(63);
    P.set(real_parent, {IndexProbe::have(100, true)});
    P.set(older,       {IndexProbe::have(99,  true)});    // within N_CTX of the carrier bin
    P.set(side,        {IndexProbe::have(101, false)});   // off the active chain
    P.set(ancient,     {IndexProbe::have(20,  true)});    // beyond the 64-block horizon
    LiveMainchainIndex ix = make(P, T, fast_opts());
    FakeTracker tracker;
    ReceiptAdmitter adm(/*chain*/1, ix, tracker, /*incarnation*/1);
    const auto d = desc_of(0xB0);

    // a carrier keyed to a REAL-shaped parent hash (not mainchain_hash) resolves
    // and is admitted, with one receipt keyed to the block before it.
    const WorkEvent c1 = mine(d, real_parent, W2_GENESIS_PREV_OWN, consensus_lz(100), "c1");
    const WorkEvent r1 = mine(d, older, W2_GENESIS_PREV_OWN, consensus_lz(99), "r1");
    auto res = adm.admit(c1, {r1});
    CHECK(res.carrier_status == CarrierStatus::OK);
    CHECK(res.pushes.size() == 2 && res.pushes[0].carrier_bin == 100 && res.pushes[1].origin_bin == 99);
    CHECK(res.pushes[0].w_raw == work_of_lz(consensus_lz(100)));
    CHECK(res.receipts.size() == 1 && res.receipts[0].second == Disposition::OK);
    CHECK(ix.stats().cache_hits >= 1);                     // :169 and :226 asked `older` twice -> one probe

    // the same parent again: dedup by W2, not by the index (index still resolves)
    CHECK(adm.admit(c1, {}).carrier_status == CarrierStatus::REJECT_DEDUP);
    // off the active chain / beyond the horizon: unresolvable -> REJECT_POW at :198-204
    const WorkEvent c2 = mine(d, side, c1.hash(), consensus_lz(101), "c2");
    CHECK(adm.admit(c2, {}).carrier_status == CarrierStatus::REJECT_POW);
    const WorkEvent c3 = mine(d, ancient, c1.hash(), consensus_lz(20), "c3");
    CHECK(adm.admit(c3, {}).carrier_status == CarrierStatus::REJECT_POW);
    // a dashd that never heard of the block: REJECT_POW, no retry stall
    const auto t0 = std::chrono::steady_clock::now();
    const WorkEvent c4 = mine(d, h32(64), c1.hash(), consensus_lz(100), "c4");
    CHECK(adm.admit(c4, {}).carrier_status == CarrierStatus::REJECT_POW);
    CHECK(elapsed_since(t0) < ms(50));
    // the SAME carriers through the synthetic index: real-shaped hashes never resolve there
    SyntheticMainchainIndex syn(110);
    FakeTracker tr2;
    ReceiptAdmitter adm2(1, syn, tr2, 1);
    CHECK(adm2.admit(c1, {r1}).carrier_status == CarrierStatus::REJECT_POW);
    const WorkEvent c5 = mine(d, mainchain_hash(100), W2_GENESIS_PREV_OWN, consensus_lz(100), "c5");
    CHECK(adm2.admit(c5, {}).carrier_status == CarrierStatus::OK);
    // seam type-erasure: both are usable as the const IMainchainIndex& the ingest takes
    const IMainchainIndex* seam = &ix; CHECK(seam->height_of(real_parent) == std::optional<u64>(100));
    seam = &syn;                       CHECK(seam->height_of(mainchain_hash(100)) == std::optional<u64>(100));
}

int main() {
    test_resolve_cache_missing();
    test_unknown_bounded_retry();
    test_inactive_and_horizon();
    test_stale_tip_refresh_and_future();
    test_tip_sources();
    test_cache_ttl_and_cap();
    test_synthetic_parity();
    test_backend_binding_templates();
    test_admitter_end_to_end();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
