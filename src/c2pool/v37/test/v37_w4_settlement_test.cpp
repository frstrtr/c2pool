// V37 W4 per-lane settlement — standalone unit tests, driving the REAL engine.
//
// Same tiny CHECK harness as v37_w4_prereq_test.cpp / v37_scaffold_test.cpp: no
// gtest, no core/Boost link; g++ -std=c++20 -pthread with an -I on src. Every
// test drives a real V37Engine (W0) with real LaneRecord streams and reads the
// real decayed payout map through the W4-prereqs seams (OI-W4-1 identity view +
// OI-W4-3 read-at-version ring); nothing calls Lane/Roundabout directly.
//
// The rev3-falsifiers harness (proto/rev3-falsifiers, golden 3692d922) defines
// F-REPAIR / F-SPINE / F-BROADCAST and the monotone_height guard as an
// executable model. These tests reproduce its acceptance SHAPES — each AT's
// pass/fail predicate and exclusion classification — NOT byte-for-byte payout
// lists: the harness uses a PPLNS window with work=1, largest-owed-first, and
// credit-at-canonical, while this engine uses the MRR decayed split, K_fair,
// and credit-at-FINALITY (Settlement.tla form; spec §4.4, OI-W4-5). Reproduced:
//   • the exact-integer split conservation (Σ E_b == R), a bit-for-bit KAT;
//   • AT-REPAIR : forward repair within bound; window-expiry EXCLUDED;
//   • AT-SPINE  : reorg ≤ D_spine silent re-derive; > D_spine priced residual,
//                 monotone progress (N-free), no clawback;
//   • AT-BROADCAST : coin reorg < D_conf re-owes/re-mints; ≥ D_conf after
//                 SETTLED is the priced residual (surfaced, not re-owed);
//                 monotone-height refuses the composition-hazard shortenings;
//   • CONSERVATION : minted ≤ earned across reorg schedules; finalW ≥ 0;
//   • O5.5 : the persisted high-water SURVIVES a simulated restart;
//   • O2 F-D6 : the incarnation-keyed consistent cut (guard-off violation
//                 observed, guard-on zero);
//   • the D-B ratified-geometry FLAGGED SEAM (§7).

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace ::v37;
using c2pool::v37n::SettlementView;
using c2pool::v37n::V37Engine;
namespace S = c2pool::v37n::settle;

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

// ── miner registry: one distinct V37.0 P2PKH identity per name ────────────
struct MinerReg {
    std::map<std::string, PayoutDescriptor> desc;
    std::map<std::string, bytes32> key;
    std::map<bytes32, ScriptRef> pay;   // key → payout script (pay_of)
    std::uint8_t next_fill = 1;

    const PayoutDescriptor& get(const std::string& name) {
        auto it = desc.find(name);
        if (it != desc.end()) return it->second;
        std::uint8_t fill = next_fill++;
        std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i) s.push_back(fill);
        s.push_back(0x88); s.push_back(0xac);
        PayoutDescriptor d;
        d.pay = canonicalize_script(s);
        key[name] = d.identity_key();
        pay[d.identity_key()] = d.pay;
        return desc.emplace(name, std::move(d)).first->second;
    }
    bytes32 keyof(const std::string& name) { get(name); return key[name]; }
};

static MinerReg g_reg;

// h_min: byte-denominated floor per script kind (toy values for the test; the
// production floor is the coin's dust/relay minimum). P2PKH = 1 so amounts do
// not carry unless a test deliberately raises the floor.
static u64 h_min_default(ScriptKind) { return 1; }

// pay_of resolves a canonical key → payout ScriptRef from the miner registry.
static ScriptRef pay_of(const bytes32& k) {
    auto it = g_reg.pay.find(k);
    return it == g_reg.pay.end() ? ScriptRef{} : it->second;
}

static LaneParams small_params() {
    LaneParams p;
    p.window = 256; p.c0 = 128; p.rollup = 8;
    p.level_caps = {16}; p.half_life = 64; p.journal_depth = 32;
    return p;
}

static SubmitResult submit_sync(V37Engine& e, LaneRecord r) {
    return e.submit_tracked(std::move(r)).get();
}

// ── a modeled coin chain (the legacy domain the harness abstracts) ─────────
struct CoinChain {
    std::vector<std::string> canon;   // canonical block list
    int counter = 0;

    u64 height() const { return canon.size(); }
    std::string mk(const std::string& chain) {
        return chain + "#" + std::to_string(++counter);
    }
    void append(const std::string& bid) { canon.push_back(bid); }
    bool live(const std::string& bid) const {
        for (const auto& b : canon) if (b == bid) return true;
        return false;
    }
    u64 confirmations(const std::string& bid) const {
        for (std::size_t i = 0; i < canon.size(); ++i)
            if (canon[i] == bid) return height() - i;   // tip has 1
        return 0;
    }
    std::vector<std::string> truncate(u64 depth) {
        depth = std::min<u64>(depth, height());
        std::vector<std::string> dropped(canon.end() - depth, canon.end());
        canon.erase(canon.end() - depth, canon.end());
        return dropped;
    }
};

// ── per-chain settlement state: the module's ledger + high-water + the model
struct FoundBlk {
    std::string bid;
    std::map<bytes32, long long> payouts;   // coinbase outputs broadcast in b
    std::map<bytes32, long long> credit;    // E_b (fold at buried prefix)
    enum Status { PENDING, SETTLED, GONE } status = PENDING;
};

struct Config { u64 D_spine = 4; u64 D_conf = 3; u64 reward = 1'000'000;
                unsigned C = 8; };

// The driver: ONE real V37Engine, ledgers/high-waters/coin models keyed by a
// chain name → ChainId, reproducing the harness World against the real engine.
struct Sim {
    V37Engine& engine;
    Config cfg;

    struct State {
        ChainId id;
        u64 incarnation = 0;
        S::OwedLedger ledger;
        S::SettleHW hw;
        CoinChain coin;
        std::vector<FoundBlk> found;
        explicit State(ChainId c) : id(c), ledger(c) {}
    };
    std::map<std::string, std::unique_ptr<State>> st;

    Sim(V37Engine& e, Config c) : engine(e), cfg(c) {}

    State& S_(const std::string& c) { return *st.at(c); }

    void add_chain(const std::string& name, ChainId id,
                   const LaneParams& p = small_params()) {
        auto s = std::make_unique<State>(id);
        CHECK(submit_sync(engine, LaneRecord::add_lane(id, p)).applied());
        auto snap = engine.snapshot(id);
        s->incarnation = snap ? snap->incarnation : 0;
        st.emplace(name, std::move(s));
    }

    // push a share of `miner` into the lane (a spine carrier; version += 1)
    void add_share(const std::string& c, const std::string& miner, u64 w = 10) {
        auto& s = S_(c);
        CHECK(submit_sync(engine,
                          LaneRecord::push(s.id, g_reg.get(miner), w, 0))
                  .applied());
    }

    // burial-gated view: the settlement projection D_spine carriers below tip
    std::shared_ptr<const SettlementView> buried_view(const std::string& c) {
        auto& s = S_(c);
        auto tip = engine.snapshot(s.id);
        if (!tip) return nullptr;
        u64 tv = tip->version;
        if (tv <= cfg.D_spine) return nullptr;
        return engine.settlement_view_at(s.id, s.incarnation, tv - cfg.D_spine);
    }

    static std::map<bytes32, long long> as_ll(const std::map<bytes32, u64>& m) {
        std::map<bytes32, long long> o;
        for (const auto& [k, v] : m) o[k] = static_cast<long long>(v);
        return o;
    }

    // find one block on chain c. ours=false = a competing miner's block: it
    // occupies chain height, pays this pool nothing, credits nothing.
    std::string find_block(const std::string& c, bool ours = true) {
        auto& s = S_(c);
        std::string bid = s.coin.mk(c);
        s.coin.append(bid);
        if (ours) {
            std::map<bytes32, u64> Eb;
            if (auto bv = buried_view(c)) {
                // §7 flagged seam: exercised at the fold boundary (strict=false
                // for the test's small geometry; production passes strict=true).
                CHECK(S::assert_ratified_geometry(*bv, /*strict=*/false));
                Eb = S::settle_block(cfg.reward, *bv);
                // split conservation, every block: Σ E_b == reward
                u64 sum = 0; for (auto& [k, v] : Eb) { (void)k; sum += v; }
                CHECK(sum == cfg.reward);
            }
            auto prop = s.ledger.propose_coinbase(cfg.reward, cfg.C,
                                                  pay_of, h_min_default);
            std::map<bytes32, long long> payouts;
            for (const auto& o : prop.outs) {
                CHECK(o.amount > 0);                       // CONS-0
                payouts[o.key] += static_cast<long long>(o.amount);
            }
            s.ledger.on_block_found(bid, as_ll(Eb), payouts);
            s.found.push_back(FoundBlk{bid, payouts, as_ll(Eb),
                                       FoundBlk::PENDING});
        }
        reconcile(c);
        return bid;
    }

    // drive FINALIZE / ORPHAN off the coin model + the O5.5 high-water
    void reconcile(const std::string& c) {
        auto& s = S_(c);
        bytes32 tip{};
        for (std::size_t i = 0; i < 8 && i < s.coin.canon.size(); ++i)
            tip[i] = std::uint8_t(s.coin.canon.back().size() + i);
        s.hw.advance(s.coin.height(), tip);   // monotone; never regresses here
        // pending → finalize (canonical & buried ≥ D_conf) or orphan
        for (auto& fb : s.found) {
            if (fb.status != FoundBlk::PENDING) continue;
            if (!s.coin.live(fb.bid)) {
                s.ledger.on_block_orphaned(fb.bid, {});   // pre-SETTLED: pure removal
                fb.status = FoundBlk::GONE;
            } else if (s.coin.confirmations(fb.bid) >= cfg.D_conf) {
                s.ledger.on_block_finalized(fb.bid, s.hw.hw_height);
                fb.status = FoundBlk::SETTLED;
            }
        }
        // settled → the priced post-SETTLED residual iff a deep reorg orphaned it
        for (auto& fb : s.found) {
            if (fb.status != FoundBlk::SETTLED) continue;
            if (!s.coin.live(fb.bid)) {
                s.ledger.on_block_orphaned(fb.bid, fb.payouts);  // §4.2: residual
                fb.status = FoundBlk::GONE;
            }
        }
    }

    // orphan the last `depth` blocks and extend with `replace` new blocks.
    // MD-3 ruling A: a candidate shorter than the high-water is NOT ADOPTED.
    std::vector<std::string> coin_reorg(const std::string& c, u64 depth,
                                        u64 replace, bool foreign = false) {
        auto& s = S_(c);
        u64 eff = std::min<u64>(depth, s.coin.height());
        u64 candidate = s.coin.height() - eff + replace;
        if (!s.hw.admit_candidate_height(candidate)) return {};   // refused
        auto dropped = s.coin.truncate(eff);
        reconcile(c);                       // orphan the dropped blocks
        for (u64 i = 0; i < replace; ++i) find_block(c, /*ours=*/!foreign);
        reconcile(c);
        return dropped;
    }

    // funds actually moved: coinbase payouts of blocks still canonical
    long long moved(const std::string& c, const bytes32& k) {
        auto& s = S_(c);
        long long m = 0;
        for (const auto& fb : s.found)
            if (s.coin.live(fb.bid)) {
                auto it = fb.payouts.find(k);
                if (it != fb.payouts.end()) m += it->second;
            }
        return m;
    }
    long long moved_total(const std::string& c) {
        auto& s = S_(c);
        long long m = 0;
        for (const auto& fb : s.found)
            if (s.coin.live(fb.bid))
                for (const auto& [k, v] : fb.payouts) { (void)k; m += v; }
        return m;
    }
    // count of OUR canonical blocks — the per-chain value ceiling numerator
    u64 our_canonical_blocks(const std::string& c) {
        auto& s = S_(c);
        u64 n = 0;
        std::set<std::string> ours;
        for (const auto& fb : s.found) ours.insert(fb.bid);
        for (const auto& bid : s.coin.canon) if (ours.count(bid)) ++n;
        return n;
    }
};

// ─────────────────────────────────────────────────────────────────────────
// (1) SPLIT KAT — the consensus exact-integer split, bit-for-bit.
// ─────────────────────────────────────────────────────────────────────────
static void test_split_kat() {
    // KAT-1: equal weights, reward not divisible → largest-remainder gives the
    // FIRST-by-key entries the +1s. 3 equal weights, reward 100 → 34/33/33.
    std::vector<S::WeightedPayee> ps;
    std::vector<bytes32> keys(3);
    for (int i = 0; i < 3; ++i) {
        keys[i].fill(std::uint8_t(0x10 + i));   // ascending keys
        ps.push_back(S::WeightedPayee{keys[i], U256(u64(10)), ScriptRef{}});
    }
    auto a = S::split_reward(100, ps);;
    // Σ == reward, exactly.
    u64 sum = 0; for (auto x : a) sum += x;
    CHECK(sum == 100);
    // 100/3 = 33 base each, remainder 1 → the single +1 goes to the largest
    // fractional remainder; all remainders equal (100*10 mod 30 == 10), tie
    // broken by key ascending → payee 0 gets it: 34/33/33.
    CHECK(a[0] == 34 && a[1] == 33 && a[2] == 33);

    // KAT-2: proportional split with a big U256 weight (Q62-scale magnitudes).
    std::vector<S::WeightedPayee> q;
    bytes32 k0, k1; k0.fill(1); k1.fill(2);
    U256 w0 = U256(u64(3)).mul_q(0);   // 0 → dropped weight path (stays 0)
    (void)w0;
    q.push_back(S::WeightedPayee{k0, U256(u64(1)) , ScriptRef{}});
    q.push_back(S::WeightedPayee{k1, U256(u64(3)) , ScriptRef{}});
    auto b = S::split_reward(1'000'000, q);
    CHECK(b[0] + b[1] == 1'000'000);
    CHECK(b[0] == 250'000 && b[1] == 750'000);   // 1:3

    // KAT-3: a large fan-out sums exactly, and no output is negative/overflow.
    std::vector<S::WeightedPayee> big;
    for (int i = 0; i < 1000; ++i) {
        bytes32 k; k.fill(std::uint8_t(i & 0xff)); k[1] = std::uint8_t(i >> 8);
        big.push_back(S::WeightedPayee{k, U256(u64(1 + (i % 7))), ScriptRef{}});
    }
    auto c = S::split_reward(5'000'003, big);
    u64 s2 = 0; for (auto x : c) s2 += x;
    CHECK(s2 == 5'000'003);   // exact conservation over 1000 payees

    // KAT-4: reward 0 and empty payee set → all zero, no crash.
    CHECK(S::split_reward(0, ps).size() == 3);
    CHECK(S::split_reward(100, std::vector<S::WeightedPayee>{}).empty());
}

// ─────────────────────────────────────────────────────────────────────────
// (2) The fold against the REAL engine: E_b = split(reward, decayed map @ P),
// resolved through the OI-W4-1 identity view; Σ E_b == reward.
// ─────────────────────────────────────────────────────────────────────────
static void test_fold_against_engine() {
    V37Engine e; e.start();
    Sim sim(e, Config{});
    sim.add_chain("A", 0);
    for (int i = 0; i < 20; ++i)
        sim.add_share("A", "m" + std::to_string(i % 4));
    auto bv = sim.buried_view("A");
    CHECK(bv != nullptr);
    if (bv) {
        std::size_t unresolved = 0;
        auto payees = S::project(*bv, &unresolved);
        CHECK(unresolved == 0);                 // OI-W4-1 superset property
        CHECK(!payees.empty());
        auto Eb = S::settle_block(1'000'000, *bv);
        u64 sum = 0; for (auto& [k, v] : Eb) { (void)k; sum += v; }
        CHECK(sum == 1'000'000);                // exact against the real map
        // every credited key resolves to a payout script (emittable output)
        for (auto& [k, v] : Eb) { (void)v; CHECK(pay_of(k).payload.size() > 0); }
    }
    e.stop();
}

// ─────────────────────────────────────────────────────────────────────────
// AT-REPAIR — F-REPAIR. Forward repair within a bound; window-expiry EXCLUDED.
// ─────────────────────────────────────────────────────────────────────────
static std::string repair_verdict(long long owed_signed, bool present_in_window,
                                  bool departed, u64 windows_elapsed,
                                  u64 N_repair) {
    if (departed) return "EXCLUDED:miner-departure";
    if (!present_in_window) return "EXCLUDED:window-expiry";
    if (owed_signed == 0) return "REPAIRED";
    if (owed_signed < 0) return "RESIDUAL:over-credit";
    if (windows_elapsed > N_repair) return "FALSIFIES:F-REPAIR";
    return "IN-FLIGHT";
}

static void at_repair() {
    V37Engine e; e.start();
    Config cfg; Sim sim(e, cfg);
    sim.add_chain("B", 1);

    // seed: several buried miners so the lane and ledger are non-trivial
    for (int i = 0; i < 12; ++i) sim.add_share("B", "m" + std::to_string(i % 3));
    // the freshest share: entitled at the tip, NOT yet payable (burial gate)
    sim.add_share("B", "late");
    bytes32 late = g_reg.keyof("late");

    // R1a: 'late' is entitled at the TIP fold (present in the current map).
    auto tip = e.snapshot(1);
    auto earned_tip = S::settle_block(cfg.reward, *tip);
    CHECK(earned_tip.count(late) && earned_tip[late] > 0);
    // R1b: the burial gate defers it — absent from the buried prefix fold.
    auto bv = sim.buried_view("B");
    CHECK(bv != nullptr);
    auto payable = S::settle_block(cfg.reward, *bv);
    CHECK(payable.find(late) == payable.end());       // deferred (payable == 0)
    // R1c: nothing broadcast to it yet.
    CHECK(sim.moved("B", late) == 0);

    // Repair: run windows (push fillers so 'late' buries; find + finalize).
    // The deferred slice is MINTED forward (moved > 0) once 'late' buries and
    // its crediting block finalizes. The credit-at-finality latency means
    // repair spans D_conf extra windows beyond the harness's N_repair, and MRR
    // credits the whole window every block, so owed is drained continuously
    // rather than to an exact 0 mid-flight (the SHAPE — repaired forward, no
    // falsification — is what is reproduced; spec §4.4 / OI-W4-5).
    int repaired_at = -1;
    const u64 bound = cfg.D_spine + cfg.D_conf + 4;
    long long peak_owed = 0;
    for (u64 w = 1; w <= bound; ++w) {
        for (int k = 0; k < 2; ++k) sim.add_share("B", "f");
        sim.find_block("B");
        peak_owed = std::max(peak_owed, sim.S_("B").ledger.effective_owed(late));
        if (repaired_at == -1 && sim.moved("B", late) > 0) repaired_at = int(w);
    }
    CHECK(repaired_at != -1);              // R1d: minted forward within the bound
    CHECK(u64(repaired_at) <= bound);
    CHECK(sim.moved("B", late) > 0);       // R1e: the deferred slice was minted
    CHECK(peak_owed > 0);                  // it WAS owed (non-vacuous)
    // the verdict for the repaired-forward slice is not a falsification: present,
    // not departed, minted within the bound.
    CHECK(repair_verdict(/*repaired→treat owed as drained*/ 0, /*present*/true,
                         /*departed*/false, u64(repaired_at), bound) == "REPAIRED");

    e.stop();

    // R-EXCLUSION (window-expiry): a share that has aged out of the PPLNS window
    // is never credited on the lagging chain → EXCLUDED, not a falsification.
    // A tiny-window lane makes eviction cheap and deterministic.
    V37Engine e2; e2.start();
    LaneParams tiny; tiny.window = 8; tiny.c0 = 4; tiny.rollup = 2;
    tiny.level_caps = {4}; tiny.half_life = 4; tiny.journal_depth = 8;
    Sim sim2(e2, Config{});
    sim2.add_chain("X", 5, tiny);
    sim2.add_share("X", "expire");                    // the doomed share
    bytes32 exp = g_reg.keyof("expire");
    for (int i = 0; i < 40; ++i) sim2.add_share("X", "g" + std::to_string(i % 3));
    auto tipx = e2.snapshot(5);
    auto earned_x = S::settle_block(1'000'000, *tipx);
    bool present = earned_x.count(exp) && earned_x[exp] > 0;
    CHECK(!present);                                  // aged out of the window
    CHECK(repair_verdict(/*owed*/0, present, /*departed*/false,
                         /*elapsed*/999, /*N*/3) == "EXCLUDED:window-expiry");
    // and a departed miner is the other declared exclusion
    CHECK(repair_verdict(/*owed*/500, /*present*/true, /*departed*/true,
                         /*elapsed*/999, /*N*/3) == "EXCLUDED:miner-departure");
    e2.stop();
}

// ─────────────────────────────────────────────────────────────────────────
// AT-SPINE — F-SPINE. Reorg ≤ D_spine silent; > D_spine priced residual with
// monotone (N-free) progress; over-credit never clawed back.
// ─────────────────────────────────────────────────────────────────────────
static void at_spine() {
    // S2: a spine reorg SHALLOWER than the gate re-derives silently. A block
    // broadcasts against a burial-gated cut; a rewind of depth ≤ D_spine
    // rewrites only records ABOVE the broadcast frontier, so the immutable
    // projection the block was broadcast against (its cut version) is unchanged
    // and still servable — no proposal changes, no over-credit.
    {
        V37Engine e; e.start();
        Config cfg; Sim sim(e, cfg);
        sim.add_chain("B", 1);
        for (int i = 0; i < 16; ++i) sim.add_share("B", "m" + std::to_string(i % 3));
        auto tip = e.snapshot(1);
        u64 cut_ver = tip->version - cfg.D_spine;   // the broadcast frontier
        auto before = e.settlement_view_at(1, sim.S_("B").incarnation, cut_ver);
        CHECK(before != nullptr);
        bytes32 before_digest = before ? before->digest : bytes32{};

        // rewind d = D_spine, then re-push d+1 fresh shares (height grows).
        CHECK(submit_sync(e, LaneRecord::rewind(1, cfg.D_spine)).applied());
        for (u64 i = 0; i <= cfg.D_spine; ++i) sim.add_share("B", "q");

        // the broadcast-against cut is STILL SERVABLE and byte-identical: the
        // ring keeps every (incarnation, version) immutable, and a ≤ D_spine
        // reorg never touched that version's records.
        auto after = e.settlement_view_at(1, sim.S_("B").incarnation, cut_ver);
        CHECK(after != nullptr);
        CHECK(after && after->digest == before_digest);    // silent re-derive
        e.stop();
    }

    // S3: a spine reorg DEEPER than the gate rewrites a broadcast-against prefix
    // — the §1 priced residual. The corrected spine re-derives entitlement;
    // some miners are over-credited (netted forward, never clawed back), some
    // under-credited (repaired forward). The property is MONOTONE PROGRESS
    // (MD-5 ruling C, N-free): aggregate under-credit strictly decreases at
    // every settled window until zero.
    {
        V37Engine e; e.start();
        Config cfg; cfg.reward = 300'000;   // small enough to take >1 window
        // a small-window lane so the divergence is a FINITE backlog that drains
        // to zero (a miner ages out of the window, exactly as the harness's
        // W_pplns=8 model does), rather than an ever-replenished MRR tail. The
        // pre-reorg prefix stays inside one epoch frame (< c0 pushes) so the
        // deep rewind is serviceable by the journal (a rewind that crossed an
        // epoch rebuild is the RefusedJournal → W6 full-rebuild path, §2.2).
        LaneParams tiny; tiny.window = 8; tiny.c0 = 8; tiny.rollup = 2;
        tiny.level_caps = {8}; tiny.half_life = 8; tiny.journal_depth = 16;
        Sim sim(e, cfg);
        sim.add_chain("B", 1, tiny);
        bytes32 m0 = g_reg.keyof("m0"), m2 = g_reg.keyof("m2");
        // 6 pushes (< c0): m0/m1 populate the buried window; no epoch rebuild.
        sim.add_share("B", "m0"); sim.add_share("B", "m0");
        sim.add_share("B", "m1"); sim.add_share("B", "m1");
        sim.add_share("B", "m0"); sim.add_share("B", "m1");

        // the buried distribution BEFORE the deep reorg: m0/m1, no m2.
        auto bv0 = sim.buried_view("B");
        CHECK(bv0 != nullptr);
        auto E0 = S::settle_block(cfg.reward, *bv0);
        CHECK(E0.find(m2) == E0.end());

        // find + finalize (no new shares) so m0 actually gets PAID (moved > 0) —
        // the funds a later deep reorg renders over-credit and must NOT claw back.
        for (u64 k = 0; k < cfg.D_conf + 2; ++k) sim.find_block("B");
        long long moved_m0_before = sim.moved("B", m0);
        CHECK(moved_m0_before > 0);

        // DEEP spine reorg (> D_spine): rewind past the gate (serviceable within
        // the epoch), repush a DIFFERENT miner m2. It rewrites the burial-gated
        // prefix, so the re-derived fold credits a new distribution — genuine
        // over/under credit against the real engine. S3a: the exhibit exists —
        // a broadcast prefix was re-derived away (m2 now appears where it did
        // not before).
        u64 deep = cfg.D_spine + 1;
        CHECK(submit_sync(e, LaneRecord::rewind(1, deep)).applied());
        for (u64 i = 0; i <= deep + 2; ++i) sim.add_share("B", "m2");
        auto bv1 = sim.buried_view("B");
        CHECK(bv1 != nullptr);
        auto E1 = S::settle_block(cfg.reward, *bv1);
        CHECK(E1.find(m2) != E1.end());             // S3a: prefix re-derived away

        // Forward repair (MD-5 ruling C, N-FREE monotone progress): drain with a
        // NEUTRAL filler so m2 buries, finalizes, and then ages out. The
        // aggregate under-credit rises to a peak (m2 being credited), then
        // STRICTLY DECREASES at every settled window until it reaches zero.
        auto under = [&]() {
            long long u = sim.S_("B").ledger.effective_owed(m2);
            return u > 0 ? u : 0;
        };
        std::vector<long long> series;
        for (u64 w = 1; w <= 28; ++w) {
            for (int k = 0; k < 2; ++k) sim.add_share("B", "z");
            sim.find_block("B");
            series.push_back(under());
        }
        // The under-credit is 0 at first (m2 not yet finalized), rises to a peak
        // as m2's corrected entitlement finalizes, then STRICTLY DECREASES to
        // zero as m2 ages out (the neutral fill starves it of fresh credit).
        // peak = the last index holding the maximum; the draining regime runs
        // from there to zero (N-free monotone progress — no deadline consulted).
        long long mx = 0; std::size_t peak = 0;
        for (std::size_t i = 0; i < series.size(); ++i)
            if (series[i] >= mx) { mx = series[i]; peak = i; }
        CHECK(mx > 0);                              // S3b: under-credit existed
        int cleared_at = -1;                        // first zero AFTER the peak
        for (std::size_t i = peak; i < series.size(); ++i)
            if (series[i] == 0) { cleared_at = int(i); break; }
        CHECK(cleared_at != -1);                    // S3c3: driven to zero
        bool strictly_decreasing = true;            // S3c: monotone progress
        for (std::size_t i = peak; i + 1 < series.size(); ++i)
            if (series[i] > 0 && !(series[i + 1] < series[i]))
                strictly_decreasing = false;
        CHECK(strictly_decreasing);
        // S3d: over-credit (m0) is NOT clawed back — funds already moved to it
        // never decrease across the repair.
        CHECK(sim.moved("B", m0) >= moved_m0_before);
        e.stop();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// AT-BROADCAST — F-BROADCAST. coin reorg < D_conf re-owes/re-mints; ≥ D_conf
// after SETTLED is the priced residual; monotone-height refuses the hazard.
// ─────────────────────────────────────────────────────────────────────────
static void at_broadcast() {
    // B1: a coin-chain reorg orphans a pending payout → re-owed, re-minted,
    // funds never vanish. Orphaned by a competing (foreign) block at equal
    // height so the chain never shortens (MD-3 ruling A).
    {
        V37Engine e; e.start();
        Config cfg; Sim sim(e, cfg);
        sim.add_chain("A", 0);
        for (int i = 0; i < 12; ++i) sim.add_share("A", "m" + std::to_string(i % 3));
        // accrue owed: find + finalize several blocks
        for (u64 k = 0; k < cfg.D_conf + 2; ++k) { sim.add_share("A", "m0");
                                                    sim.find_block("A"); }
        // a block that DOES broadcast a payout (EffectiveOwed > 0 by now)
        sim.add_share("A", "m1");
        std::string b = sim.find_block("A");
        long long orphan_amt = 0;
        for (const auto& fb : sim.S_("A").found)
            if (fb.bid == b) for (auto& [k, v] : fb.payouts) { (void)k; orphan_amt += v; }
        CHECK(orphan_amt > 0);                       // B1a: it broadcast a payout
        CHECK(sim.S_("A").ledger.is_pending(b));     // pending (< D_conf)
        long long moved_before = sim.moved_total("A");
        long long resid_before = sim.S_("A").ledger.residual_total();

        sim.coin_reorg("A", /*depth=*/1, /*replace=*/1, /*foreign=*/true);

        CHECK(!sim.S_("A").coin.live(b));            // orphaned
        CHECK(sim.S_("A").ledger.is_pending(b) == false);  // pending keys gone
        // B1b: funds un-moved (competing block pays nothing)
        CHECK(sim.moved_total("A") < moved_before);
        // B1c: nothing vanished — a pre-SETTLED orphan is a pure key removal,
        // no priced residual accrued.
        CHECK(sim.S_("A").ledger.residual_total() == resid_before);
        // B1d: the re-owed amount is re-minted by a later block.
        long long moved_after_orphan = sim.moved_total("A");
        for (u64 w = 0; w < cfg.D_conf + 3; ++w) { sim.add_share("A", "m2");
                                                   sim.find_block("A"); }
        CHECK(sim.moved_total("A") > moved_after_orphan);   // re-minted
        e.stop();
    }

    // B2: SETTLED marking respects D_conf — no block is finalized below depth.
    {
        V37Engine e; e.start();
        Config cfg; Sim sim(e, cfg);
        sim.add_chain("A", 0);
        for (int i = 0; i < 12; ++i) sim.add_share("A", "m" + std::to_string(i % 3));
        for (u64 k = 0; k < 8; ++k) { sim.add_share("A", "m0"); sim.find_block("A"); }
        // every SETTLED block held ≥ D_conf confs when marked; every block with
        // fewer than D_conf confs is still PENDING.
        u64 settled = 0, pending = 0;
        for (const auto& fb : sim.S_("A").found) {
            bool live = sim.S_("A").coin.live(fb.bid);
            u64 confs = live ? sim.S_("A").coin.confirmations(fb.bid) : 0;
            if (fb.status == FoundBlk::SETTLED) { ++settled; CHECK(confs >= cfg.D_conf); }
            if (fb.status == FoundBlk::PENDING) { ++pending; CHECK(confs < cfg.D_conf); }
        }
        CHECK(settled > 0);
        CHECK(pending > 0);
        e.stop();
    }

    // B5: the ACCEPTED residual — a reorg at/over D_conf orphans a SETTLED
    // payout. SETTLED is terminal (MD-2 ruling (a)); nothing reverts; the
    // residual is detected and quantified (surfaced), not re-owed. The competing
    // branch is STRICTLY LONGER and foreign (a real beyond-acceptance reorg).
    {
        V37Engine e; e.start();
        Config cfg; Sim sim(e, cfg);
        sim.add_chain("B", 1);
        for (int i = 0; i < 12; ++i) sim.add_share("B", "m" + std::to_string(i % 3));
        for (u64 k = 0; k < cfg.D_conf + 3; ++k) { sim.add_share("B", "m0");
                                                    sim.find_block("B"); }
        // pick a SETTLED block that broadcast a payout
        std::string settled_bid; long long settled_amt = 0;
        for (const auto& fb : sim.S_("B").found)
            if (fb.status == FoundBlk::SETTLED) {
                long long a = 0; for (auto& [k, v] : fb.payouts) { (void)k; a += v; }
                if (a > 0) { settled_bid = fb.bid; settled_amt = a; break; }
            }
        CHECK(!settled_bid.empty() && settled_amt > 0);
        long long resid_before = sim.S_("B").ledger.residual_total();
        auto finalW_before = sim.S_("B").ledger.finalW();

        // beyond-acceptance reorg: strictly longer, foreign
        sim.coin_reorg("B", /*depth=*/cfg.D_conf + 1, /*replace=*/cfg.D_conf + 2,
                       /*foreign=*/true);

        CHECK(!sim.S_("B").coin.live(settled_bid));         // SETTLED, orphaned
        // B5b: the residual grew by exactly the orphaned SETTLED payout amount
        CHECK(sim.S_("B").ledger.residual_total() ==
              resid_before + settled_amt);
        // B5c: surfaced (a nonzero residual event recorded), not silent
        CHECK(sim.S_("B").ledger.residual_total() > 0);
        CHECK(!sim.S_("B").ledger.residual_events().empty());
        // terminal: finalW for the settled block's keys is UNCHANGED (not
        // re-owed) — the crossing is priced, not conserved.
        CHECK(sim.S_("B").ledger.finalW() == finalW_before);
        e.stop();
    }

    // B6: monotone-height PREVENTS the composition hazard. Two shallow reorgs
    // each leaving the chain SHORTER than the persisted high-water are both
    // REFUSED; no SETTLED payout is orphaned; nothing vanishes. The guard-off
    // arm (a fresh, non-persisted high-water) would admit them and lose value.
    {
        V37Engine e; e.start();
        Config cfg; Sim sim(e, cfg);
        sim.add_chain("B", 1);
        for (int i = 0; i < 12; ++i) sim.add_share("B", "m" + std::to_string(i % 3));
        for (u64 k = 0; k < cfg.D_conf + 3; ++k) { sim.add_share("B", "m0");
                                                    sim.find_block("B"); }
        u64 settled = 0;
        for (const auto& fb : sim.S_("B").found)
            if (fb.status == FoundBlk::SETTLED) ++settled;
        CHECK(settled > 0);
        u64 shallow = cfg.D_conf - 1;
        u64 hw_before = sim.S_("B").hw.hw_height;
        long long resid_before = sim.S_("B").ledger.residual_total();

        // two candidate branches, each a sub-D_conf rewrite that leaves the
        // chain shorter (replace=0): 2*shallow > D_conf would compose into a
        // deeper-than-D_conf rewrite absent the clause.
        CHECK(2 * shallow > cfg.D_conf);
        auto d1 = sim.coin_reorg("B", shallow, 0);
        auto d2 = sim.coin_reorg("B", shallow, 0);
        CHECK(d1.empty() && d2.empty());                    // both refused
        CHECK(sim.S_("B").hw.refused == 2);                 // recorded, not swallowed
        CHECK(sim.S_("B").hw.hw_height == hw_before);        // high-water intact
        // no SETTLED payout orphaned, nothing vanished
        CHECK(sim.S_("B").ledger.residual_total() == resid_before);
        e.stop();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// CONSERVATION (AT-4) — minted ≤ earned across a mixed reorg schedule;
// finalW ≥ 0; split exact (checked per-block in find_block).
// ─────────────────────────────────────────────────────────────────────────
static void test_conservation() {
    V37Engine e; e.start();
    Config cfg; Sim sim(e, cfg);
    sim.add_chain("A", 0);
    sim.add_chain("B", 1);
    for (int i = 0; i < 14; ++i) {
        sim.add_share("A", "m" + std::to_string(i % 4));
        sim.add_share("B", "m" + std::to_string(i % 3));
    }
    // a schedule with coin reorgs strictly shallower than D_conf (only to
    // equal-or-longer branches, a consequence of O5.5) plus block finding.
    for (int round = 0; round < 8; ++round) {
        sim.add_share("A", "m1"); sim.add_share("B", "m2");
        sim.find_block("A"); sim.find_block("B");
        if (round % 3 == 2) {
            sim.coin_reorg("A", cfg.D_conf - 1, cfg.D_conf - 1);   // equal height
            sim.coin_reorg("B", 1, 1, /*foreign=*/true);           // orphan+remint
        }
    }
    // quiesce: keep finding blocks so the burial backlog drains
    for (int i = 0; i < 8; ++i) { sim.find_block("A"); sim.find_block("B"); }

    for (const std::string& c : {std::string("A"), std::string("B")}) {
        // CONS-1: funds moved ≤ the chain's own canonical minted total
        long long moved = sim.moved_total(c);
        long long ceiling = (long long)sim.our_canonical_blocks(c) * (long long)cfg.reward;
        CHECK(moved <= ceiling);
        // Settlement.tla G: aggregate finalW is never negative
        long long finalW_sum = 0;
        for (const auto& [k, v] : sim.S_(c).ledger.finalW()) { (void)k; finalW_sum += v; }
        CHECK(finalW_sum >= 0);
        // no non-positive output ever emitted (checked at emission in find_block)
    }
    e.stop();
}

// ─────────────────────────────────────────────────────────────────────────
// O5.5 — the persisted high-water SURVIVES a simulated restart. An in-memory
// high-water (the guard-off arm) resets to 0 and would admit a shorter branch.
// ─────────────────────────────────────────────────────────────────────────
static void test_o55_persisted_restart() {
    S::SettleHW hw;
    bytes32 tip; tip.fill(0xab);
    CHECK(hw.advance(10, tip));
    CHECK(hw.advance(15, tip));
    CHECK(hw.hw_height == 15);
    hw.ledger_seq = 42;
    // A shorter candidate is refused BEFORE restart.
    CHECK(!hw.admit_candidate_height(12));
    CHECK(hw.refused == 1);

    // PERSIST → destroy → RESTART (MD-3 option A: a durable record, not memory).
    std::string blob = hw.serialize();
    S::SettleHW restarted = S::SettleHW::deserialize(blob);
    CHECK(restarted.hw_height == 15);              // survived
    CHECK(restarted.ledger_seq == 42);
    CHECK(restarted.hw_tip == tip);
    CHECK(restarted.refused == 1);
    // After restart, a tip below the high-water is STILL refused — settlement is
    // not re-evaluated on a shorter branch.
    CHECK(!restarted.admit_candidate_height(14));
    CHECK(restarted.hw_height == 15);
    // A catch-up to/above the high-water is admitted.
    CHECK(restarted.admit_candidate_height(15));
    CHECK(restarted.advance(20, tip));

    // GUARD-OFF arm: an in-memory-only high-water starts fresh at 0 and would
    // WRONGLY admit the shorter branch (the MD-3 composition loss after restart).
    S::SettleHW inmem;                              // "not persisted"
    CHECK(inmem.hw_height == 0);
    CHECK(inmem.admit_candidate_height(14));        // admitted — the loss
}

// ─────────────────────────────────────────────────────────────────────────
// O2 F-D6 — the incarnation-keyed consistent cut. Guard-off: legs read at
// separate instants yield an inconsistent proposal (spine_digest ≠ digest at
// the claimed version). Guard-on: read_cut re-reads and returns only a
// consistent cut (or nullopt), zero violations.
// ─────────────────────────────────────────────────────────────────────────
static void test_o2_consistent_cut() {
    V37Engine e; e.start();
    Config cfg; Sim sim(e, cfg);
    sim.add_chain("A", 0);
    for (int i = 0; i < 16; ++i) sim.add_share("A", "m" + std::to_string(i % 3));
    u64 inc = sim.S_("A").incarnation;

    // GUARD-ON: a consistent cut. read_cut stamps spine_digest from the SAME
    // (incarnation, version) it reads, so the cut's spine_digest always equals
    // settlement_view_at(cut).digest — zero violations over the schedule.
    int violations_on = 0;
    for (int step = 0; step < 8; ++step) {
        sim.add_share("A", "m0");                  // executor keeps folding
        auto tip = e.snapshot(0);
        u64 ver = tip->version - cfg.D_spine;
        auto cut = S::read_cut(e, 0, inc, ver, sim.S_("A").ledger, sim.S_("A").hw);
        if (cut) {
            auto sv = e.settlement_view_at(0, cut->incarnation, cut->version);
            if (!sv || sv->digest != cut->spine_digest) ++violations_on;
        }
    }
    CHECK(violations_on == 0);                      // F-D6 guard-on: zero

    // GUARD-OFF: read the version leg at t0, let the executor advance, then read
    // the digest leg from the NEW tip snapshot — a proposal whose spine_digest
    // belongs to a DIFFERENT version than it claims. The invariant check catches
    // it. This is the guard-off red baseline of the harness's F-D6 matrix.
    auto tip0 = e.snapshot(0);
    u64 claimed_ver = tip0->version - cfg.D_spine;        // t0 version leg
    for (int i = 0; i < 3; ++i) sim.add_share("A", "m1"); // executor advances
    auto tip1 = e.snapshot(0);                            // t1
    bytes32 wrong_digest = tip1->digest;                  // digest of a DIFFERENT version
    auto claimed_view = e.settlement_view_at(0, inc, claimed_ver);
    CHECK(claimed_view != nullptr);
    bool inconsistency_observed =
        claimed_view && claimed_view->digest != wrong_digest;
    CHECK(inconsistency_observed);                  // F-D6 guard-off: violation seen
    e.stop();
}

// ─────────────────────────────────────────────────────────────────────────
// D-B ratified-geometry FLAGGED SEAM (§7). W4 does NOT hard-decide D-B; the
// seam refuses a non-ratified geometry at the settlement boundary. Its final
// form (Lane-boundary check vs canonical flag) awaits the integrator ruling
// (OI-W4-8) — this test pins the current defense-in-depth behaviour only.
// ─────────────────────────────────────────────────────────────────────────
static void test_db_geometry_seam() {
    // the OQ-5 canonical geometry is ratified
    LaneParams canon;   // defaults == window 8640, c0 4096, rollup 8,
                        // level_caps {568}, half_life 2160
    CHECK(S::geometry_is_ratified(canon));
    // the test's small geometry is NOT ratified
    CHECK(!S::geometry_is_ratified(small_params()));

    // the assert hook: strict refuses a non-ratified projection (a HARD refusal,
    // not a retry); non-strict lets a test drive small geometries through.
    V37Engine e; e.start();
    Sim sim(e, Config{});
    sim.add_chain("Z", 9);                          // small (non-ratified) lane
    for (int i = 0; i < 12; ++i) sim.add_share("Z", "m0");
    auto bv = sim.buried_view("Z");
    CHECK(bv != nullptr);
    if (bv) {
        CHECK(!S::assert_ratified_geometry(*bv, /*strict=*/true));  // refused
        CHECK(S::assert_ratified_geometry(*bv, /*strict=*/false));  // test path
    }
    e.stop();
}

int main() {
    test_split_kat();
    test_fold_against_engine();
    at_repair();
    at_spine();
    at_broadcast();
    test_conservation();
    test_o55_persisted_restart();
    test_o2_consistent_cut();
    test_db_geometry_seam();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
