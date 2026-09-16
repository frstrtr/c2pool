// v37_drops_arity1_activation_kat.cpp
//
// DROPS ACTIVATION AT ARITY 1 — the gate-ON owed_digest the DECOUPLED fleet
// actually reproduces, minted and pinned BESIDE the arity-2 golden 984c7753…
// (which this KAT also re-derives and proves UNMOVED).
//
// ★ WHY A SECOND GOLDEN EXISTS AT ALL
//   v37_node_lane_activation.hpp records the operator ruling DECOUPLE:
//   kActivationArity == 1. So when V37_ACTIVATE_CONSENSUS_V1 is taken, a live
//   node's lane geometry is
//
//       node_lane_params(lane)  ==  ::v37::LaneParams::for_version(1)
//
//   — the ONE-argument factory. It names no parent LaneKind, so it carries no
//   ridge and no window dimensions: mrr.activation_pos, nr.nr_activation_pos
//   and win.win_activation_pos all stay at UINT64_MAX and nr_version /
//   win_version stay 0. DROPS is ON; the V37.1 native ridge and the win law are
//   OFF and remain their own, separately ruled flag day.
//
//   The already-pinned activation mint 984c7753… was composed over the
//   TWO-argument geometry for_version(1, LaneKind) with the ridge ACTIVE at
//   position 4096. The ridge moves the lane's payout map, so it moves E_b, so it
//   moves owed_digest: the arity-2 arms of v37_drops_activation_kat measure
//   exactly that (its A0 ridge-OFF control lands on 9cfaf97d… while its A1
//   ridge-ON control lands on 87c5249a…, same schedule, same harvest).
//   Therefore 984c7753… is NOT the number a decoupled fleet converges on.
//   v37_node_lane_activation.hpp says so in prose. This KAT supplies the number.
//
//   ★ THIS IS AN ADDITION, NOT A REPLACEMENT. 984c7753… keeps its job — it pins
//   the CANON ACTIVATION SCHEDULE and the replace-not-add composition rule under
//   the ridge — and cases A2-UNMOVED / A2-FOLD-UNMOVED below re-derive it and
//   its all-lanes fold b03abb1f… from THIS file's own fixture copy. If either
//   moved, this KAT fails. Neither golden may be edited without the other.
//
// WHAT IS MINTED HERE
//   The SAME pinned schedule and the SAME pinned harvest as the arity-2 mint,
//   byte for byte (seed 0x5EED4096, 9000 pushes, 10 miners, 8 shares/bin,
//   blocks at 4000/4097/6000/9000, reward 50e8; harvest seed 0xD4095EEDD4095EED,
//   h_T = 2^244, K = 4, six drop payees 1001..1006, two covered payees 3 and 7,
//   ex-ante enrolment committed at interval 0 effective from interval 1), driven
//   over the ARITY-1 geometry on all four ratified lanes.
//
//   ★ THE FIXTURE COPY IS PINNED, NOT TRUSTED. This file is standalone and
//   carries its own copy of the schedule, the harvest, the enrolment book and
//   the from-spec credit rule. A copy that had drifted from the original could
//   not reproduce 984c7753… / b03abb1f… on the arity-2 arms — which it does, in
//   the same run, from the same helpers. That is what makes the arity-1 number
//   below a mint of the SAME fixture and not of a lookalike.
//
//   ARMS (each driven on all four ratified lanes)
//     B0  arity-1 geometry, drops OFF, harvest present -> 9cfaf97d… (control)
//     B1  arity-1 geometry, drops ON,  harvest EMPTY   -> 9cfaf97d… (dormant)
//     B2  arity-1 geometry, drops ON,  harvest present -> ★ THE ARITY-1 GOLDEN
//     B3  arity-1 geometry, drops ON,  K = 2           -> 9cfaf97d… (K >= 3)
//     B4  arity-1 geometry, drops ON,  J < K harvest   -> 9cfaf97d… (no fallback)
//     C0  arity-2 geometry, ridge OFF, drops OFF       -> 9cfaf97d…
//     C1  arity-2 geometry, ridge ON,  drops OFF       -> 87c5249a…
//     C2  arity-2 geometry, ridge ON,  drops ON        -> 984c7753… (UNMOVED)
//
//   ★ THE NUMBERS THIS FILE MINTS, for an operator to quote
//     arity-1 gate-ON owed_digest (all four ratified lanes, identical)
//       ae44add291dbe90aec581825a3e60ce8fd7bbc7194bc767e096da12669d8614f
//     arity-1 all-lanes fold, sha256d("V37DROPS1" || BTC || LTC || DASH || DOGE)
//       50b5d7d109a1ae5429f4be91c54fba62c031449e01509d1ce9295a0a79af8646
//     arity-1 gate-OFF anchor (same schedule, DROPS off)
//       9cfaf97de7c58a7727ff5cc1203f445fc301559fb702938a3dd61ad32d6b338e
//   and the numbers it proves UNMOVED: 984c7753… / b03abb1f… (arity 2),
//   87c5249a… (V37.1 ridge), 9cfaf97d… (pre-V37.1), b4db1ded… (empty ledger).
//
//   ★ THE GATE-OFF ANCHOR AT ARITY 1 IS 9cfaf97d…, NOT 87c5249a…. That is the
//   whole content of the decoupling: with the ridge OFF the schedule's gate-OFF
//   value is the pre-V37.1 control. B0/B1/B3/B4 are the anchors-unmoved proof at
//   arity 1 and they are NON-VACUOUS — the identical harvest that leaves them at
//   9cfaf97d… moves B2.
//
// THREE INDEPENDENT REPRODUCTIONS OF THE ARITY-1 GOLDEN, on every lane
//   (1) THE ENGINE SEAM        OwedLedger::on_block_found_with_drops() /
//                              on_block_finalized() / owed_digest() — the
//                              production settlement path, unmodified.
//   (2) A SHADOWED LEDGER      an independently accumulated (finalW,
//                              first_eligible) state hashed by the estimator
//                              module's own sub::owed_digest() — a second
//                              implementation of the same commitment, which
//                              also mirrors the ledger's ARM *and DISARM* rule
//                              (a REPLACE delta can carry a row negative).
//   (3) FROM-SPEC RE-DERIVATION spec_credit() below writes the RDWR-OQ2 rule out
//                              from the specification text — gate, K >= 3, the
//                              J >= K contribution, the per-(payee, interval)
//                              straddle dedup, ex-ante enrolment, the REPLACE
//                              composition and the R1 denomination — WITHOUT
//                              calling subthreshold_credit(). It reaches the
//                              module only for the estimator arithmetic and the
//                              u320 -> i64 fold, which is what the spec defines.
//
// ★ THE LIVE-GEOMETRY LEG (the second CTest target from this one source)
//   The mint above names the arity-1 geometry EXPLICITLY as for_version(1), so
//   it is invariant to the kActivationArity constant and to the build flag —
//   the same property that makes the arity-2 KAT's goldens stable. That leaves
//   one thing unproved: that node_lane_params() ACTUALLY hands a flipped node
//   that geometry. CMake therefore compiles this SAME file a second time as
//   v37_drops_arity1_activation_kat_livegeom with -DV37_ACTIVATE_CONSENSUS_V1=1
//   on that TEST TARGET ONLY. In that build case ARITY1-LIVEGEOM reads
//   node_lane_params(lane) directly, asserts it is field-for-field
//   for_version(1) with every position OFF, and DRIVES THE WHOLE MINT FROM IT —
//   so the golden is reproduced from the live factory, not from a restatement
//   of it.
//
//   ★★ THIS IS NOT THE FLIP AND DOES NOT TAKE IT. The definition is scoped to
//   one test executable. No product target, no default, and no CMake cache
//   variable carries it; a default build of this file (the first target) asserts
//   kActivateConsensusV1 == false and both builds mint the same value. The flip
//   remains exactly what the header says it is: the operator's hand, fleet-wide,
//   at a ruled height.
//
// BUILD (standalone; nothing in the tree is written):
//   g++-15 -std=c++20 -O2 -Wall -Wextra -I<repo>/src
//       v37_drops_arity1_activation_kat.cpp -o v37_drops_arity1_activation_kat
//
// HOLLOW-GREEN GUARD: BOTH targets are registered with add_test() in
// src/c2pool/v37/test/CMakeLists.txt AND listed on BOTH build.yml
// `cmake --build --target` allowlists (the Linux x86_64 leg and the ASan+UBSan
// leg), so CI compiles and RUNS them instead of registering a NOT_BUILT CTest
// sentinel (the c2pool#1539 unregistered-KAT class).
//
// Exit status 0 = all checks pass; 1 = at least one check failed.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/v37_node_lane_activation.hpp>   // the T1 node lane factory
#include <c2pool/v37/v37_drop_harvest.hpp>
#include <c2pool/v37/v37_drops_enrollment.hpp>

namespace settle = ::c2pool::v37n::settle;
namespace sub    = ::c2pool::v37::subthreshold;
using ::v37::bytes32;
using ::v37::LaneKind;
using ::v37::LaneParams;
using ::v37::MinerId;
using ::v37::SHIPPED_CONSENSUS_VERSION;
using ::v37::SubthresholdGate;
using ::v37::U256;
using ::v37::u64;

// ── ★ THE MINT: the arity-1 gate-ON owed_digest ───────────────────────────
// owed_digest at the pinned cut with DROPS ON and the V37.1 native ridge and the
// win law OFF — i.e. over for_version(1), the geometry kActivationArity == 1
// gives a live node. Lane-independent, and at this arity that is STRUCTURAL and
// not evidential: the one-argument factory ignores LaneKind entirely, so the
// four ratified lanes are literally the same parameter set. Case
// ARITY1-LANE-INDEP says exactly that rather than dressing it up as a finding.
static const char* GOLDEN_DROPS_ON_ARITY1 =
    "ae44add291dbe90aec581825a3e60ce8fd7bbc7194bc767e096da12669d8614f";
// The fold of the four arity-1 gate-ON digests in ratified LaneKind order
// (BTC, LTC, DASH, DOGE), under the SAME domain-separated construction the
// arity-2 fold uses: sha256d("V37DROPS1" || d0..d3). The tag separates the FOLD
// from every other hash in the tree; the ARITY is identified by which four
// digests go into it, and the two folds are different numbers because their
// inputs are.
static const char* GOLDEN_DROPS_ON_ARITY1_COMBINED =
    "50b5d7d109a1ae5429f4be91c54fba62c031449e01509d1ce9295a0a79af8646";

// ── the ARITY-2 golden, which this KAT proves UNMOVED ─────────────────────
// src/c2pool/v37/test/v37_drops_activation_kat.cpp. Minted over
// for_version(1, LaneKind) with the ridge ACTIVE at 4096. NOT the fleet value at
// arity 1; it pins the canon activation schedule and the composition rule.
static const char* GOLDEN_DROPS_ON_ARITY2 =
    "984c7753ab352255933fb63da524b93eecc916b07cc77d94b454213922f719ce";
static const char* GOLDEN_DROPS_ON_ARITY2_COMBINED =
    "b03abb1f5798ab199febc4977b4af31e624f5aab0d84e41e60310d344586bd19";
// The two superseded DROPS mints, kept as NEGATIVE assertions on both arities.
static const char* SUPERSEDED_RAW_UNENROLLED_GOLDEN =
    "d85dff58ce7734e5ff414be29f116fbc257ada5cd87ee3d95e2ffe40f554ff78";
static const char* SUPERSEDED_ADDITIVE_GOLDEN =
    "34e4b38e20d2e222622e1faafbe06c3e392d830a0a878b5e16f67bb2157d8a26";

// ── the gate-OFF anchors that MUST NOT move ───────────────────────────────
// V37.1 gate-ON ridge golden (v37_1_ridge_activation_test.cpp). At arity 2 this
// is the drops-OFF anchor; at arity 1 it is not reachable at all, because the
// ridge is OFF.
static const char* ANCHOR_RIDGE_ON =
    "87c5249ac2057d0ac6707127c59cdc605acec4ba3c0d4b4b25e9b53692eb71ee";
// The pre-V37.1 control over the identical schedule (ridge inactive). ★ THIS is
// the gate-OFF anchor at ARITY 1.
static const char* ANCHOR_RIDGE_OFF =
    "9cfaf97de7c58a7727ff5cc1203f445fc301559fb702938a3dd61ad32d6b338e";
// The empty-ledger anchor, sha256d("V37O").
static const char* ANCHOR_OWED_EMPTY =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

// ── the pinned schedule (identical to the arity-2 DROPS mint) ─────────────
static constexpr std::uint64_t SEED           = 0x5EED4096ull;
static constexpr int           N_PUSH         = 9000;
static constexpr unsigned      N_MINERS       = 10;
static constexpr u64           SHARES_PER_BIN = 8;
static constexpr u64           ACT_POS        = 4096;
static constexpr u64           REWARD         = 50ull * 100000000ull;
static constexpr int           N_BLOCKS       = 4;
static const u64  BLOCK_AT[N_BLOCKS]  = {4000, 4097, 6000, 9000};
static const char* BLOCK_ID[N_BLOCKS] = {"blk_pre", "blk_flip", "blk_mid", "blk_cut"};

// ── the pinned harvest (identical to the arity-2 DROPS mint) ──────────────
static constexpr unsigned  H_T_BIT      = 244;                        // h_T == 2^244
static constexpr u64       T_SHARE      = 1ull << (256 - H_T_BIT);    // 4096
static constexpr std::uint64_t HARVEST_SEED = 0xD4095EEDD4095EEDull;
static constexpr unsigned  N_DROPS      = 6;
static constexpr MinerId   DROP_BASE    = 1001;
static const std::uint64_t DROP_HASHES[N_DROPS] = {512, 1024, 2048, 3072, 4096, 6144};
static const MinerId       COVER_ID[2]  = {3, 7};
static const std::uint64_t COVER_HASHES[2] = {20 * T_SHARE, 12 * T_SHARE};
static constexpr std::uint64_t STARVED_HASHES = 3;          // J < K
static constexpr std::uint32_t K_CANON  = 4;                // == for_version(1).K

static long g_checks = 0;
static long g_fail = 0;
static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("  FAIL: %s\n", what); }
}
static std::string hex(const bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : d) { s += H[c >> 4]; s += H[c & 15]; }
    return s;
}
static std::string hex32(const std::array<std::uint8_t, 32>& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : d) { s += H[c >> 4]; s += H[c & 15]; }
    return s;
}

// The identity resolver. The SAME function feeds the lane push, the settlement
// view and the harvest, which is what makes all three agree on payee keys.
static bytes32 key_of(MinerId m) {
    std::uint8_t b[4] = {std::uint8_t(m), std::uint8_t(m >> 8),
                         std::uint8_t(m >> 16), std::uint8_t(m >> 24)};
    return ::v37::sha256d(b, 4);
}

// splitmix64, the generator the S8/S-1, V37.1 and estimator-module KATs use.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        s += 0x9E3779B97F4A7C15ull;
        std::uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    sub::u256 hash() {
        sub::u256 h;
        for (int i = 0; i < 4; ++i) h.w[(std::size_t)i] = next();
        return h;
    }
};

static sub::u256 share_target() {
    sub::u256 t;
    t.w[3] = 1ull << (H_T_BIT - 192);   // 2^244
    return t;
}

// One harvested payee's interval, simulated: draw `hashes` uniform 256-bit
// values from a stream pinned by (id, interval) and present every one of them to
// the module's ReceiptCollector, which does the share/near-miss split and the
// K-best retention itself.
static sub::ReceiptCollector simulate(MinerId id, u64 interval, std::uint64_t hashes,
                                      std::uint32_t K) {
    sub::ReceiptCollector rc(K, share_target());
    Rng r(HARVEST_SEED ^ (std::uint64_t(id) * 0x100000001B3ull) ^
          (interval * 0x9E3779B97F4A7C15ull));
    for (std::uint64_t i = 0; i < hashes; ++i) rc.observe(r.hash());
    return rc;
}

enum class Harvest { None, Full, Starved };

static std::vector<settle::HarvestedReceipt> harvest_for(u64 interval, Harvest mode,
                                                         std::uint32_t K) {
    std::vector<settle::HarvestedReceipt> v;
    if (mode == Harvest::None) return v;
    const bool starved = (mode == Harvest::Starved);
    for (unsigned d = 0; d < N_DROPS; ++d) {
        const MinerId id = DROP_BASE + d;
        const std::uint64_t h = starved ? STARVED_HASHES : DROP_HASHES[d];
        v.push_back(settle::HarvestedReceipt{key_of(id), interval,
                                             simulate(id, interval, h, K)});
    }
    for (unsigned c = 0; c < 2; ++c) {
        const std::uint64_t h = starved ? STARVED_HASHES : COVER_HASHES[c];
        v.push_back(settle::HarvestedReceipt{key_of(COVER_ID[c]), interval,
                                             simulate(COVER_ID[c], interval, h, K)});
    }
    return v;
}

// A stand-in for the engine's SettlementView with the field names the fold
// reads. project() / fold_eb() are templated on the view, so the production code
// paths run verbatim.
struct FakeIdView {
    std::map<MinerId, ::v37::IdentityEntry> m;
    const ::v37::IdentityEntry* find(MinerId id) const {
        auto it = m.find(id);
        return it == m.end() ? nullptr : &it->second;
    }
};
struct FakeView {
    LaneParams params{};
    u64 next_pos = 0;
    std::map<MinerId, U256> payout;
    std::shared_ptr<const FakeIdView> identities;
    bytes32 digest{};
};

struct Run {
    bytes32 owed{};
    bytes32 lane_digest{};
    u64 ledger_seq = 0;
    bool refused = false;
    bool short_run = false;
    long long est_total[N_BLOCKS] = {0, 0, 0, 0};   // the estimator's contribution
    long long eb_total[N_BLOCKS]  = {0, 0, 0, 0};   // the E_b split of the reward
    std::array<std::uint8_t, 32> shadow{};          // reproduction (2)
    std::array<std::uint8_t, 32> spec{};            // reproduction (3)
    bool spec_agrees = true;
    bool saturated = false;
};

// ── the FROM-SPEC credit rule — reproduction (3) ──────────────────────────
// The RDWR-OQ2 rule written out from the specification, deliberately NOT calling
// subthreshold_credit(). It re-derives the gate, the K >= 3 guard, the J >= K
// contribution, the per-(payee, interval) straddle dedup, the ex-ante enrolment
// filter, the mode selection AND THE REPLACE COMPOSITION from the spec text, and
// reaches the module only for the estimator ARITHMETIC and the u320 -> i64 fold.
// If this and the engine seam disagree at any block, the mint is not
// reproducible and the KAT says so.
static std::map<bytes32, long long> spec_credit(
    const ::v37::SubthresholdGate& g,
    const std::vector<settle::HarvestedReceipt>& harvested,
    std::map<std::pair<bytes32, u64>, bool>& seen,
    const settle::DropsCompose& ctx) {
    std::map<bytes32, long long> out;
    if (!g.enabled) return out;                       // gate OFF: nothing enters
    if (g.K < 3) return out;                          // K >= 3 (K = 2: infinite variance)
    for (const auto& hr : harvested) {
        const auto& rc = hr.collector;
        const std::pair<bytes32, u64> key{hr.payee, hr.interval};
        if (seen.count(key)) continue;                // straddle dedup
        // R-SYBIL: an identity that did NOT commit before the interval is not a
        // DROPS participant at all — it keeps its ordinary S*T path.
        if (!ctx.enrolled(hr.payee, hr.interval)) continue;
        if (g.mode != 1 && rc.shares() > 0) continue; // EstimateOnly refuses covered
        seen[key] = true;
        sub::u320 e{}, w{};
        if (g.mode == 1) {                            // Combined (the canon rule)
            if (rc.near_miss_count() >= g.K)
                e = sub::estimate_combined(rc.shares(), g.K, rc.h_K());
            // REPLACE: Hhat_comb covers the WHOLE interval, so the interval's
            // share-derived contribution W_shares = S*T comes back out.
            if (rc.shares() > 0)
                w = sub::divfloor(sub::coeff_times_2_256(rc.shares()),
                                  sub::promote(rc.target_hash()));
        } else {                                      // EstimateOnly
            if (rc.near_miss_count() >= g.K) e = sub::estimate_hashes(g.K, rc.h_K());
        }
        // R1: BOTH sides go through the ORDINARY share -> E_b conversion and are
        // then subtracted. Converting each side separately (not the difference)
        // is what keeps this re-derivation and the seam on the same integer.
        const long long amt = settle::entitlement_of_work(ctx.price, e)
                            - settle::entitlement_of_work(ctx.price, w);
        if (amt != 0) out[hr.payee] += amt;
    }
    return out;
}

// ── the two geometries ────────────────────────────────────────────────────
//
// ★ ARITY 1 — what a DECOUPLED flipped node builds. In a default build this is
// named explicitly, so the mint is invariant to the kActivationArity constant
// and to the build flag. In the livegeom build it is READ FROM THE FACTORY, so
// the golden is reproduced from the live seam itself.
static LaneParams geom_arity1(LaneKind lane) {
    if constexpr (::c2pool::v37n::kActivateConsensusV1)
        return ::c2pool::v37n::node_lane_params(lane);   // the LIVE flipped geometry
    else {
        (void)lane;
        return LaneParams::for_version(SHIPPED_CONSENSUS_VERSION);
    }
}
// ARITY 2 — the geometry 984c7753… was minted over. `ridge` picks the ON arm
// (positions at 4096) or the OFF control (both positions UINT64_MAX), exactly as
// the arity-2 KAT's drive() does.
static LaneParams geom_arity2(LaneKind lane, bool ridge) {
    LaneParams p = LaneParams::for_version(1, lane);
    if (ridge) {
        p.mrr.activation_pos   = ACT_POS;
        p.nr.nr_activation_pos = ACT_POS;
    } else {
        p.mrr.activation_pos   = UINT64_MAX;
        p.nr.nr_activation_pos = UINT64_MAX;
    }
    return p;
}

// Drive the pinned schedule once over a caller-supplied geometry.
//   base   the lane geometry (arity 1 or arity 2), already ridge-resolved
//   drops  the DROPS gate version: 0 = OFF, 1 = the canon ON configuration
//   mode   which harvest the blocks carry
//   K_over 0 = the canon K; otherwise force K (the K = 2 arm)
static Run drive(const LaneParams& base, unsigned drops, Harvest mode,
                 std::uint32_t K_over = 0) {
    LaneParams p = base;
    // The gate is set EXPLICITLY on both arms and never read from the factory's
    // default, so this KAT and its goldens are invariant to any later canon edit.
    p.subthreshold = SubthresholdGate::for_version(drops);
    if (K_over) p.subthreshold.K = K_over;
    const std::uint32_t K_use = p.subthreshold.K;

    Run o;
    // R-SYBIL — the ex-ante enrolment book, built BEFORE the schedule runs. Every
    // commitment is made at interval 0 to take effect at interval 1, strictly
    // earlier than the first interval this schedule harvests (bin 499).
    ::c2pool::v37n::EnrollmentBook enroll;
    for (unsigned d = 0; d < N_DROPS; ++d) enroll.commit(key_of(DROP_BASE + d), 0, 1);
    for (unsigned c = 0; c < 2; ++c)      enroll.commit(key_of(COVER_ID[c]), 0, 1);
    ::v37::Lane lane(p);
    auto idv = std::make_shared<FakeIdView>();
    for (MinerId m = 1; m <= N_MINERS; ++m)
        idv->m[m] = ::v37::IdentityEntry{key_of(m), ::v37::ScriptRef{}};

    settle::OwedLedger ledger(7);
    // Reproduction (2): an INDEPENDENT shadow of the ledger state. payout is
    // empty throughout, so EffectiveOwed == finalW and first_eligible arms on the
    // first finalize that leaves a key positive.
    std::map<bytes32, long long> sh_final;
    std::map<bytes32, u64> sh_fe;
    // Reproduction (3): a THIRD state, folded from the from-spec rule above.
    std::map<bytes32, long long> sp_final;
    std::map<bytes32, u64> sp_fe;

    Rng r(SEED);
    int nb = 0;
    for (int i = 0; i < N_PUSH; ++i) {
        ::v37::WorkAtom a{};
        a.miner       = MinerId(1 + (r.next() % N_MINERS));
        a.w_raw       = 1 + (r.next() % 1000);
        a.origin_bin  = u64(i) / SHARES_PER_BIN;
        a.carrier_bin = a.origin_bin;
        a.flags       = 0;
        a.version     = ::v37::PROV_V37;
        a.is_receipt  = false;
        a.d_net       = U256{};
        lane.push(a, key_of);

        if (nb < N_BLOCKS && lane.next_pos() == BLOCK_AT[nb]) {
            FakeView v;
            v.params     = p;
            v.next_pos   = lane.next_pos();
            v.payout     = lane.payout_map();
            v.identities = idv;
            v.digest     = lane.digest(key_of);

            auto f = settle::fold_eb(REWARD, v, true);
            if (!f) { o.refused = true; return o; }
            settle::OwedLedger::Amounts base_credit;
            for (const auto& [k, val] : f->credit) base_credit[k] = (long long)val;
            for (const auto& [k, val] : base_credit) { (void)k; o.eb_total[nb] += val; }

            const u64 bin = (BLOCK_AT[nb] - 1) / SHARES_PER_BIN;
            const auto hv = harvest_for(bin, mode, K_use);
            // The RULED composition context, both rulings, at the cut.
            settle::DropsCompose ctx;
            ctx.price      = settle::work_price_at(REWARD, v);
            ctx.enrollment = &enroll;
            bool sat = false;
            const auto est = settle::subthreshold_credit(p, hv, ctx, &sat);
            if (sat) o.saturated = true;
            for (const auto& [k, val] : est) { (void)k; o.est_total[nb] += val; }

            // Reproduction (1): the production seam.
            ledger.on_block_found_with_drops(BLOCK_ID[nb], base_credit, {}, p, hv, ctx);
            ledger.on_block_finalized(BLOCK_ID[nb], bin);

            for (const auto& [k, val] : base_credit) sh_final[k] += val;
            for (const auto& [k, val] : est)         sh_final[k] += val;
            // The ledger's own rearm rule, mirrored: ARM on the first bin a key is
            // strictly positive, DISARM the moment it is not. The disarm leg
            // matters because a REPLACE delta can carry a row negative.
            for (const auto& [k, val] : sh_final) {
                if (val > 0) { if (!sh_fe.count(k)) sh_fe[k] = bin; }
                else sh_fe.erase(k);
            }

            std::map<std::pair<bytes32, u64>, bool> spec_seen;
            const auto sp = spec_credit(p.subthreshold, hv, spec_seen, ctx);
            if (sp != est) o.spec_agrees = false;
            for (const auto& [k, val] : base_credit) sp_final[k] += val;
            for (const auto& [k, val] : sp)          sp_final[k] += val;
            for (const auto& [k, val] : sp_final) {
                if (val > 0) { if (!sp_fe.count(k)) sp_fe[k] = bin; }
                else sp_fe.erase(k);
            }
            ++nb;
        }
    }
    o.short_run   = (nb != N_BLOCKS);
    o.owed        = ledger.owed_digest();
    o.ledger_seq  = ledger.ledger_seq();
    o.lane_digest = lane.digest(key_of);
    o.shadow      = sub::owed_digest(sh_final, sh_fe);
    o.spec        = o.spec_agrees ? sub::owed_digest(sp_final, sp_fe)
                                  : std::array<std::uint8_t, 32>{};
    return o;
}

// sha256d("V37DROPS1" || d0 || d1 || d2 || d3) over four lane digests, the
// arity-2 KAT's own fold construction.
static std::array<std::uint8_t, 32> fold4(const Run r[4]) {
    std::vector<std::uint8_t> pre = {'V','3','7','D','R','O','P','S','1'};
    for (int i = 0; i < 4; ++i)
        pre.insert(pre.end(), r[i].owed.begin(), r[i].owed.end());
    return sub::detail::sha256d(pre);
}

int main() {
    std::printf("== v37_drops_arity1_activation_kat: the DECOUPLED (arity 1) DROPS "
                "gate-ON mint\n");
    std::printf("   build    : V37_ACTIVATE_CONSENSUS_V1=%d  kActivationArity=%d\n",
                (int)::c2pool::v37n::kActivateConsensusV1,
                ::c2pool::v37n::kActivationArity);
    // ACT_POS is printed as `arity2_ridge_pos` on purpose: at arity 1 there is no
    // ridge at all, and the position belongs only to the C-arms that re-derive
    // the arity-2 golden. Labelling it "ridge_pos" here would read as though the
    // mint carried one.
    std::printf("   schedule : seed=0x%llx pushes=%d miners=%u shares/bin=%llu "
                "arity2_ridge_pos=%llu reward=%llu\n",
                (unsigned long long)SEED, N_PUSH, N_MINERS,
                (unsigned long long)SHARES_PER_BIN, (unsigned long long)ACT_POS,
                (unsigned long long)REWARD);
    std::printf("   harvest  : h_T=2^%u (share difficulty %llu), K=%u, seed=0x%llx\n",
                H_T_BIT, (unsigned long long)T_SHARE, K_CANON,
                (unsigned long long)HARVEST_SEED);

    const LaneKind LK[4] = {LaneKind::BTC, LaneKind::LTC, LaneKind::DASH, LaneKind::DOGE};
    const char*    LN[4] = {"BTC", "LTC", "DASH", "DOGE"};

    // ── ARITY1-RULING: the recorded arity, and what it means ─────────────
    std::printf("\n-- ARITY1-RULING: kActivationArity == 1 (DECOUPLE) --\n");
    {
        static_assert(::c2pool::v37n::kActivationArity == 1,
                      "this KAT mints the ARITY-1 golden; if the recorded arity "
                      "ever moves, the mint below is no longer the fleet value "
                      "and this file must be re-ruled, not silently rebuilt");
        check(::c2pool::v37n::kActivationArity == 1,
              "★ the recorded flip arity is 1 — DROPS alone, the V37.1 ridge left "
              "to its own separately ruled flag day");
        check(SHIPPED_CONSENSUS_VERSION == 1,
              "the node ships V37.1, so the arity-1 factory carries the ON gate");
    }

    // ── ARITY1-GEOM: the geometry the flip actually builds ───────────────
    std::printf("\n-- ARITY1-GEOM: for_version(1) is DROPS ON with every position OFF --\n");
    {
        const LaneParams g = LaneParams::for_version(SHIPPED_CONSENSUS_VERSION);
        std::printf("   for_version(1): drops=%s K=%u mode=%u  mrr_pos=%llu "
                    "nr_pos=%llu(v%u) win_pos=%llu(v%u)\n",
                    g.subthreshold.enabled ? "ON" : "off", g.subthreshold.K,
                    g.subthreshold.mode,
                    (unsigned long long)g.mrr.activation_pos,
                    (unsigned long long)g.nr.nr_activation_pos, g.nr.nr_version,
                    (unsigned long long)g.win.win_activation_pos, g.win.win_version);
        check(g.subthreshold.enabled && g.subthreshold.K == K_CANON &&
              g.subthreshold.mode == 1,
              "arity 1 carries the canon DROPS gate: ON, K = 4, Combined");
        check(g.mrr.activation_pos == UINT64_MAX,
              "arity 1 leaves the MRR retrofit position OFF");
        check(g.nr.nr_activation_pos == UINT64_MAX && g.nr.nr_version == 0,
              "★ arity 1 leaves the V37.1 NATIVE RIDGE OFF and undeclared — this "
              "is the whole content of the DECOUPLE ruling");
        check(g.win.win_activation_pos == UINT64_MAX && g.win.win_version == 0,
              "arity 1 leaves the WIN LAW off and undeclared");
        check(settle::geometry_is_ratified(g),
              "★ W4 RATIFIES the arity-1 geometry — without this the flip would "
              "refuse every E_b fold and DROPS would be dormant for a second, "
              "quieter reason");
        // The one-argument factory ignores LaneKind, so the geometry is the SAME
        // OBJECT for all four ratified lanes. Stated as structure, not evidence.
        for (int i = 0; i < 4; ++i) {
            const LaneParams gi = geom_arity1(LK[i]);
            check(gi.subthreshold.enabled == g.subthreshold.enabled &&
                  gi.subthreshold.K == g.subthreshold.K &&
                  gi.subthreshold.mode == g.subthreshold.mode &&
                  gi.mrr.activation_pos == g.mrr.activation_pos &&
                  gi.nr.nr_activation_pos == g.nr.nr_activation_pos &&
                  gi.nr.nr_version == g.nr.nr_version &&
                  gi.win.win_activation_pos == g.win.win_activation_pos &&
                  gi.win.win_version == g.win.win_version &&
                  gi.window == g.window && gi.c0 == g.c0 && gi.rollup == g.rollup &&
                  gi.half_life == g.half_life && gi.level_caps == g.level_caps,
                  "the arity-1 geometry is identical on every ratified lane "
                  "(the one-argument factory names no LaneKind to differ on)");
        }
    }

    // ── ARITY1-LIVEGEOM: the factory, not a restatement of it ────────────
    std::printf("\n-- ARITY1-LIVEGEOM: what node_lane_params() hands a flipped node --\n");
    {
        const LaneParams want = LaneParams::for_version(SHIPPED_CONSENSUS_VERSION);
        if constexpr (::c2pool::v37n::kActivateConsensusV1) {
            // The livegeom target. -DV37_ACTIVATE_CONSENSUS_V1=1 is scoped to
            // THIS TEST EXECUTABLE by CMake; no product target takes it.
            std::printf("   this binary reads the LIVE flipped factory\n");
            for (int i = 0; i < 4; ++i) {
                const LaneParams live = ::c2pool::v37n::node_lane_params(LK[i]);
                check(live.subthreshold.enabled && live.subthreshold.K == want.subthreshold.K &&
                      live.subthreshold.mode == want.subthreshold.mode &&
                      live.subthreshold.version == want.subthreshold.version,
                      "★ LIVE: node_lane_params() hands a flipped node the ON gate");
                check(live.mrr.activation_pos == UINT64_MAX &&
                      live.nr.nr_activation_pos == UINT64_MAX &&
                      live.nr.nr_version == 0 &&
                      live.win.win_activation_pos == UINT64_MAX &&
                      live.win.win_version == 0,
                      "★ LIVE: and the ridge + win law are OFF — the DECOUPLE "
                      "ruling as the factory actually implements it");
                check(live.window == want.window && live.c0 == want.c0 &&
                      live.rollup == want.rollup && live.half_life == want.half_life &&
                      live.level_caps == want.level_caps &&
                      live.journal_depth == want.journal_depth,
                      "★ LIVE: node_lane_params() == for_version(1) field for "
                      "field, so the mint below IS the live geometry's value");
            }
            const LaneParams nk = ::c2pool::v37n::node_lane_params_no_kind();
            check(nk.subthreshold.enabled && nk.mrr.activation_pos == UINT64_MAX &&
                  nk.nr.nr_activation_pos == UINT64_MAX,
                  "★ LIVE: the XMR arm (no ratified LaneKind) lands on the SAME "
                  "arity-1 geometry, so it converges with the ratified lanes");
        } else {
            // The default target. The flip is NOT taken here, and the mint is
            // named explicitly so it is invariant to the flag.
            std::printf("   this binary is the DEFAULT build (the flip is NOT taken); "
                        "the livegeom target proves the factory\n");
            check(!::c2pool::v37n::kActivateConsensusV1,
                  "V37_ACTIVATE_CONSENSUS_V1 is OFF in this build (the shipped "
                  "default), so a default node's lane is still LaneParams{}");
            const LaneParams def = ::c2pool::v37n::node_lane_params(LaneKind::BTC);
            const LaneParams bare{};
            check(!def.subthreshold.enabled &&
                  def.mrr.activation_pos == bare.mrr.activation_pos &&
                  def.nr.nr_activation_pos == bare.nr.nr_activation_pos &&
                  def.win.win_activation_pos == bare.win.win_activation_pos,
                  "the default node lane is the OQ-5 ratified LaneParams{}, so "
                  "this PR still changes no digest on a default build");
        }
        (void)want;
    }

    // ── DROPS-EMPTY: the anchor a fresh ledger must still produce ────────
    std::printf("\n-- DROPS-EMPTY: the empty-ledger anchor --\n");
    {
        settle::OwedLedger e(7);
        std::printf("   empty owed_digest = %s\n", hex(e.owed_digest()).c_str());
        check(hex(e.owed_digest()) == ANCHOR_OWED_EMPTY,
              "empty ledger owed_digest == sha256d(\"V37O\") == b4db1ded…");
        check(e.ledger_seq() == 0, "a fresh ledger is at seq 0");
    }

    // ── drive every arm on every lane ────────────────────────────────────
    Run b0[4], b1[4], b2[4], b3[4], b4[4], c0[4], c1[4], c2[4];
    for (int i = 0; i < 4; ++i) {
        const LaneParams g1 = geom_arity1(LK[i]);
        b0[i] = drive(g1, 0, Harvest::Full);
        b1[i] = drive(g1, 1, Harvest::None);
        b2[i] = drive(g1, 1, Harvest::Full);
        b3[i] = drive(g1, 1, Harvest::Full, /*K=*/2);
        b4[i] = drive(g1, 1, Harvest::Starved);
        c0[i] = drive(geom_arity2(LK[i], false), 0, Harvest::Full);
        c1[i] = drive(geom_arity2(LK[i], true),  0, Harvest::Full);
        c2[i] = drive(geom_arity2(LK[i], true),  1, Harvest::Full);
        const Run* all[8] = {&b0[i], &b1[i], &b2[i], &b3[i], &b4[i],
                             &c0[i], &c1[i], &c2[i]};
        for (const Run* rr : all)
            check(!rr->refused && !rr->short_run,
                  "the arm completes without a settlement refusal or a short run");
    }

    // ── ARITY1-ANCHORS: the gate-OFF anchors at arity 1 ──────────────────
    std::printf("\n-- ARITY1-ANCHORS: at arity 1 the gate-OFF anchor is 9cfaf97d… --\n");
    std::printf("   B0 arity-1, drops OFF                 = %s\n", hex(b0[0].owed).c_str());
    std::printf("   B1 arity-1, drops ON, harvest EMPTY   = %s\n", hex(b1[0].owed).c_str());
    std::printf("   B3 arity-1, drops ON, K = 2           = %s\n", hex(b3[0].owed).c_str());
    std::printf("   B4 arity-1, drops ON, J < K           = %s\n", hex(b4[0].owed).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex(b0[i].owed) == ANCHOR_RIDGE_OFF,
              "★ B0: the arity-1 geometry with DROPS OFF reproduces the pre-V37.1 "
              "control 9cfaf97d… — the ridge really is inert at this arity");
        check(hex(b1[i].owed) == ANCHOR_RIDGE_OFF,
              "B1 (DORMANT): the gate is ON but nothing is harvested, so the "
              "arity-1 anchor does not move");
        check(hex(b3[i].owed) == ANCHOR_RIDGE_OFF,
              "B3: K = 2 is refused by the K >= 3 guard, so nothing is credited");
        check(hex(b4[i].owed) == ANCHOR_RIDGE_OFF,
              "B4: J < K credits 0 (no fallback inflation)");
        check(b0[i].est_total[3] == 0, "B0 credits nothing at the seam (gate OFF)");
        check(b1[i].est_total[3] == 0, "B1 credits nothing at the seam (no harvest)");
        check(b3[i].est_total[3] == 0, "B3 credits nothing at the seam (K guard)");
        check(b4[i].est_total[3] == 0, "B4 credits nothing at the seam (J < K)");
        check(hex(b0[i].owed) != ANCHOR_RIDGE_ON,
              "★ and the arity-1 anchor is NOT the ridge anchor 87c5249a… — a "
              "decoupled node lands on a different gate-OFF value than a coupled "
              "one, which is exactly why this second golden has to exist");
    }

    // ── ARITY1-MINT: the golden ──────────────────────────────────────────
    std::printf("\n-- ARITY1-MINT: the DECOUPLED gate-ON activation golden --\n");
    for (int i = 0; i < 4; ++i)
        std::printf("   %-4s arity1_gate_on_owed_digest = %s\n",
                    LN[i], hex(b2[i].owed).c_str());
    const std::array<std::uint8_t, 32> comb1 = fold4(b2);
    std::printf("   arity-1 combined (BTC|LTC|DASH|DOGE) = %s\n", hex32(comb1).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex(b2[i].owed) == GOLDEN_DROPS_ON_ARITY1,
              "★ the arity-1 gate-ON owed_digest matches the pinned DECOUPLED "
              "activation golden");
        check(b2[i].owed == b2[0].owed,
              "the arity-1 golden is the same on every lane (structurally so: "
              "for_version(1) names no LaneKind)");
        check(hex(b2[i].owed) != ANCHOR_RIDGE_OFF && hex(b2[i].owed) != ANCHOR_RIDGE_ON &&
              hex(b2[i].owed) != ANCHOR_OWED_EMPTY,
              "★ NON-VACUOUS: the same harvest that leaves B0/B1/B3/B4 at the "
              "anchor MOVES this value off every anchor");
        check(hex(b2[i].owed) != SUPERSEDED_ADDITIVE_GOLDEN &&
              hex(b2[i].owed) != SUPERSEDED_RAW_UNENROLLED_GOLDEN,
              "and it is neither superseded DROPS mint (34e4b38e… additive, "
              "d85dff58… raw/un-enrolled)");
        check(b2[i].est_total[0] != 0 || b2[i].est_total[1] != 0 ||
              b2[i].est_total[2] != 0 || b2[i].est_total[3] != 0,
              "the estimator actually credited something at the seam");
        check(!b2[i].saturated,
              "no block saturated the u320 -> i64 fold (the mint is not a clamp)");
    }
    check(hex32(comb1) == GOLDEN_DROPS_ON_ARITY1_COMBINED,
          "★ the arity-1 all-lanes fold matches the pinned value");

    // ── ARITY1-REPRO: three independent reproductions ────────────────────
    std::printf("\n-- ARITY1-REPRO: three independent producers of the same value --\n");
    std::printf("   (1) engine seam            = %s\n", hex(b2[0].owed).c_str());
    std::printf("   (2) shadowed ledger        = %s\n", hex32(b2[0].shadow).c_str());
    std::printf("   (3) from-spec re-derivation= %s\n", hex32(b2[0].spec).c_str());
    for (int i = 0; i < 4; ++i) {
        check(b2[i].spec_agrees,
              "★ the from-spec credit rule and subthreshold_credit() agree at "
              "EVERY block of the schedule, map for map");
        check(hex32(b2[i].shadow) == hex(b2[i].owed),
              "★ (2) the estimator module's own owed_digest() over an "
              "independently folded (finalW, first_eligible) state reproduces the "
              "engine seam's value");
        check(hex32(b2[i].spec) == hex(b2[i].owed),
              "★ (3) a state folded from the SPEC-WRITTEN rule — no call to "
              "subthreshold_credit() — reproduces it too");
        check(hex32(b2[i].shadow) == GOLDEN_DROPS_ON_ARITY1 &&
              hex32(b2[i].spec) == GOLDEN_DROPS_ON_ARITY1,
              "all three producers land on the pinned golden, not merely on each "
              "other");
    }

    // ── A2-UNMOVED: the arity-2 golden is exactly where it was ───────────
    std::printf("\n-- A2-UNMOVED: 984c7753… is NOT moved, replaced or re-minted --\n");
    for (int i = 0; i < 4; ++i)
        std::printf("   %-4s arity2_gate_on_owed_digest = %s\n",
                    LN[i], hex(c2[i].owed).c_str());
    const std::array<std::uint8_t, 32> comb2 = fold4(c2);
    std::printf("   arity-2 combined (BTC|LTC|DASH|DOGE) = %s\n", hex32(comb2).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex(c2[i].owed) == GOLDEN_DROPS_ON_ARITY2,
              "★ the arity-2 gate-ON golden 984c7753… still reproduces, from THIS "
              "file's own copy of the schedule and harvest — which is also what "
              "proves the copy has not drifted");
        check(hex(c1[i].owed) == ANCHOR_RIDGE_ON,
              "the V37.1 ridge anchor 87c5249a… is byte-identical (arity-2, "
              "drops OFF, harvest present)");
        check(hex(c0[i].owed) == ANCHOR_RIDGE_OFF,
              "the pre-V37.1 control 9cfaf97d… is byte-identical (arity-2 "
              "geometry, ridge OFF)");
        check(hex32(c2[i].shadow) == hex(c2[i].owed) && c2[i].spec_agrees &&
              hex32(c2[i].spec) == hex(c2[i].owed),
              "and the arity-2 value survives the same three-way reproduction");
    }
    check(hex32(comb2) == GOLDEN_DROPS_ON_ARITY2_COMBINED,
          "★ the arity-2 all-lanes fold b03abb1f… is unmoved");

    // ── ARITY-COST: the two goldens are different, and by how much ───────
    std::printf("\n-- ARITY-COST: the decoupling has a number, not a caveat --\n");
    {
        check(hex(b2[0].owed) != hex(c2[0].owed),
              "★ the arity-1 and arity-2 gate-ON owed_digests DIFFER — a fleet "
              "that took arity 2 would not converge with one that took arity 1, "
              "which is why the arity is itself the flag day");
        check(hex32(comb1) != hex32(comb2),
              "and so do the two all-lanes folds");
        check(hex(b0[0].owed) != hex(c1[0].owed),
              "the difference is already present with DROPS OFF: it is the ridge, "
              "not the estimator, that separates the two arities");
        // ★ WHERE THE DIFFERENCE COMES FROM — MEASURED, and NOT what a first
        // reading suggests. It would be natural to assume the estimator's own
        // contribution is arity-invariant (it is a function of the harvest, K and
        // the work price, and the harvest and K are identical here). It is NOT:
        // the price is work_price_at(reward, view) = (reward, SUM weight), the
        // ridge changes the lane's weight distribution AND its sum, so the same
        // Hhat and the same W_shares denominate to different satoshi at the two
        // arities. The two totals below are printed rather than asserted equal
        // precisely because the naive invariant is false, and the E_b totals are
        // printed beside them to show the other half is untouched (both arities
        // split the same 4 x 50e8).
        //
        // The estimator total is NEGATIVE at both arities and that is the REPLACE
        // composition working as ruled, not an error: the two share-covered
        // payees (ids 3 and 7) hand back a W_shares larger than their Hhat, and
        // that subtraction outweighs the six tiny drop payees' additions. A
        // positive total here would mean the additive rule had come back.
        long long e1 = 0, e2 = 0;
        for (int b = 0; b < N_BLOCKS; ++b) { e1 += b2[0].est_total[b]; e2 += c2[0].est_total[b]; }
        const long long eb1 = b2[0].eb_total[0] + b2[0].eb_total[1] +
                              b2[0].eb_total[2] + b2[0].eb_total[3];
        const long long eb2 = c2[0].eb_total[0] + c2[0].eb_total[1] +
                              c2[0].eb_total[2] + c2[0].eb_total[3];
        std::printf("   estimator credit over the 4 blocks: arity1=%lld  arity2=%lld\n",
                    e1, e2);
        std::printf("   E_b credit over the 4 blocks      : arity1=%lld  arity2=%lld\n",
                    eb1, eb2);
        check(e1 != 0 && e2 != 0, "both arities credit a non-zero estimate");
        check(e1 < 0 && e2 < 0,
              "★ the composed estimator total is NEGATIVE at both arities — the "
              "REPLACE rule handing back the covered payees' S*T. A positive "
              "total would mean the rejected additive merge had returned");
        check(e1 != e2,
              "★ MEASURED, not assumed: the estimator's own contribution is NOT "
              "arity-invariant, because the ridge moves SUM weight and therefore "
              "the price the R1 denomination divides by");
        check(eb1 == eb2 && eb1 == (long long)REWARD * N_BLOCKS,
              "the E_b half is arity-invariant: both arities split exactly the "
              "same four block rewards, so the whole difference is denomination");
        check(b2[0].ledger_seq == c2[0].ledger_seq,
              "both arities settle the same number of ledger events, so the "
              "difference is in the AMOUNTS and not in the event sequence");
    }

    // ── ARITY1-KATZERO: the canon anchor this PR cannot touch ────────────
    std::printf("\n-- ARITY1-KATZERO: the bare LaneParams{} default is untouched --\n");
    {
        const LaneParams k0{};
        check(!k0.subthreshold.enabled && k0.mrr.activation_pos == UINT64_MAX &&
              k0.nr.nr_activation_pos == UINT64_MAX && k0.nr.nr_version == 0 &&
              k0.win.win_activation_pos == UINT64_MAX && k0.win.win_version == 0,
              "the KAT-0 input LaneParams{} still has every gate OFF, so the "
              "2479d5b6 canon anchor has no way to move");
        check(!LaneParams::for_version(0).subthreshold.enabled,
              "V37.0 replay stays OFF (every pre-existing golden survives)");
    }

    std::printf("\n== v37_drops_arity1_activation_kat: %ld checks, %ld failures -> %s\n",
                g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    std::printf("arity1_drops_gate_on_owed_digest=%s\n", hex(b2[0].owed).c_str());
    std::printf("arity1_drops_gate_on_combined=%s\n", hex32(comb1).c_str());
    std::printf("arity1_gate_off_anchor=%s\n", hex(b0[0].owed).c_str());
    std::printf("arity2_drops_gate_on_owed_digest=%s\n", hex(c2[0].owed).c_str());
    std::printf("arity2_drops_gate_on_combined=%s\n", hex32(comb2).c_str());
    std::printf("v371_ridge_anchor=%s\n", hex(c1[0].owed).c_str());
    std::printf("pre_v371_anchor=%s\n", hex(c0[0].owed).c_str());
    return g_fail ? 1 : 0;
}
