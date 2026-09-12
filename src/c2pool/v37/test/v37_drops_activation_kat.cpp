// v37_drops_activation_kat.cpp
//
// DROPS ACTIVATION — the gate-ON owed_digest MINT and its regression KAT,
// minted ON TOP OF the V37.1 native ridge (Shape A, position 4096) that the
// canon already declares, and over the CORRECTED, REPLACE-NOT-ADD composition.
//
// ★ THIS GOLDEN SUPERSEDES 34e4b38e. That value was minted over the ADDITIVE
// composition, which double-counted a share-covered payee's work by 1.92..2.01x
// (DROPS-R2). It must never be reproduced by a node that has the fix.
//
// ★ THIS KAT ALSO PINS THE THREE CONSUMER SEAMS (T1/T2/T3) that make DROPS
// reachable on a live node at all: cases DROPS-T1 (the node lane factory, and
// the V37.1-ridge coupling it carries), DROPS-T2 (the W2 sub-target harvest that
// replaces the old blanket REJECT_R1_TARGET) and DROPS-T3 (the estimate-into-
// fold point, and the fact that the FOUND event persists the COMPOSED credit so
// replay cannot re-derive a different ledger).
//
// WHAT "DROPS" IS
//   The sub-threshold work estimator (purple-paper §5/§8/§15): a worker whose
//   hashes never met the share target still did work, and the K best of its
//   below-target near-misses are an exactly unbiased (UMVUE) estimate of the
//   hashes it performed. This is the "raindrops into the bucket" half of RDWR:
//   the BUCKET (owed carry-forward + h_min + oldest-owed-first K_fair) is
//   already on master; DROPS is the half that reaches the owed ledger.
//
//   THE ACTIVE STATISTIC IS THE CORRECTED, SYBIL-NEUTRAL COMBINED ESTIMATOR
//       Hhat_comb = (S + K - 1) * D'_K,   D'_K = 2^256 / (h_(K) + 1)
//   with h_(K) the K-th smallest NEAR-MISS hash and S the in-interval share
//   count. It is NEVER the as-written clamp max(S*T, Hhat), which double-counts
//   (the E-2 erratum) and is sybil-profitable. That clamp survives in the module
//   only as broken_clamp_NEVER_CONSENSUS(), the negative witness this KAT drives
//   side by side with the real seam to prove the two rules disagree and that the
//   one on the crediting path is the corrected one.
//
// WHERE THE GATE IS, AND WHAT IS ALREADY ON (master 680ec5a6)
//   CANON, src/sharechain/v37/v37_lane.hpp: SubthresholdGate::for_version(1)
//   returns {enabled = true, K = 4, mode = 1 (Combined), version = 1}, and
//   SHIPPED_CONSENSUS_VERSION == 1, so EVERY lane built through any v == 1
//   factory — for all four ratified LaneKinds; there is no per-lane switch —
//   already DECLARES the DROPS gate ON under the corrected rule. Case
//   DROPS-CANON below asserts exactly that, so this KAT is also the canon
//   conformance check for the RDWR-OQ2 "always on, all lanes" ruling.
//
//   The gate is nevertheless DORMANT on a live node, and case DROPS-DORMANT
//   pins why: with the gate ON but NOTHING harvested, the settled owed_digest is
//   byte-identical to the gate-OFF anchor. Credit moves only when a caller
//   supplies harvested near-miss receipts, and no such caller exists yet.
//
// THE MINT
//   The schedule is the V37.1 ridge activation schedule, byte for byte
//   (seed 0x5EED4096, 9000 pushes, 10 miners, 8 shares/bin, ridge at 4096,
//   blocks at 4000/4097/6000/9000), so the arms of this KAT nest exactly inside
//   the already-pinned V37.1 goldens. Onto it the mint adds ONE new, fully
//   specified input: a deterministic harvest of sub-threshold receipts, handed
//   to the REAL seam OwedLedger::on_block_found_estimator_raw_PRE_RULING().
//
//   THE HARVEST IS A SIMULATED HASH STREAM, NOT A HAND-PICKED h_K. Each
//   harvested payee draws its whole interval of hashes uniformly over the full
//   256-bit range from a pinned splitmix64 stream and presents them to the
//   module's own ReceiptCollector, which classifies them against the share
//   target h_T = 2^244 (share difficulty 4096) exactly as a node would. So S and
//   h_(K) are ORDER STATISTICS of a real stream, which is the only fixture shape
//   on which a sybil-split argument means anything.
//
//   ARMS (each driven on all four ratified lanes)
//     A0  ridge OFF, drops OFF, harvest present -> 9cfaf97d… (pre-V37.1 control)
//     A1  ridge ON,  drops OFF, harvest present -> 87c5249a… (V37.1 ANCHOR)
//     A2  ridge ON,  drops ON,  harvest EMPTY   -> 87c5249a… (the gate is dormant)
//     A3  ridge ON,  drops ON,  harvest present -> THE NEW GATE-ON GOLDEN
//     A4  ridge ON,  drops ON with K = 2        -> 87c5249a… (the K >= 3 guard)
//     A5  ridge ON,  drops ON, J < K harvest    -> 87c5249a… (J < K credits 0)
//
//   A1, A2, A4 and A5 are the gate-OFF-anchors-unmoved proof, and they are
//   NON-VACUOUS: the identical harvest that leaves them at the anchor moves A3.
//
// ★ TWO PRE-ACTIVATION FINDINGS THIS KAT WITNESSES (numbers, not opinions)
//   ★ THIS MINT SUPERSEDES d85dff58… (which superseded 34e4b38e…). Three
//   operator rulings move it:
//     R1       DENOMINATION — the estimate now goes through the ORDINARY
//              share -> E_b conversion (the Q62 weight unit a push applies, then
//              split_reward's own floor(reward * w / SUM w)), so estimated and
//              real work of equal magnitude land on the same satoshi.
//     R-SYBIL  EX-ANTE ENROLMENT — only an identity that committed to DROPS
//              BEFORE the interval is composed, and an enrolled one is composed
//              ALWAYS, downside included. The selective opt-in has no expression.
//     R3       the winner's composed map rides wire v0x03 and the S-1c peer
//              folds THAT, never its own harvest (proved in the sibling
//              v37_s1c_convergence_kat, case 9).
//
//   DROPS-R1 (DENOMINATION), as it stood before the ruling. apply_credit() returns a HASH COUNT (the low-63
//   fold of Hhat). on_block_found_estimator_raw_PRE_RULING() adds it to base_credit, which
//   is E_b — a split of the block REWARD in coin units. Hashes are added to
//   satoshi. Case DROPS-R1 pins the consequence quantitatively: across four
//   decades of simulated hashrate the credit tracks the HASH COUNT one-for-one
//   and is entirely independent of the reward, so a device doing 10^9 hashes in
//   an interval is credited 10^9 sat. A hashes-to-entitlement conversion is OWED
//   before activation.
//
//   DROPS-R2 (COMPOSITION) — ★ RULED AND FIXED IN THIS PR. Canon selects
//   Combined, which is correct: Combined is the sybil-neutral rule and
//   EstimateOnly is not (a miner that split into a share identity plus a drop
//   identity would collect E_b AND an estimate). But Combined estimates a
//   worker's TOTAL interval work, INCLUDING the work its S shares already
//   represent — so composing it ADDITIVELY onto E_b paid a share-covered worker
//   for its shares twice, at 1.92..2.01x the work performed: the E-2 "x2"
//   arriving through the merge instead of through the clamp. The operator ruled
//   shape (b): the estimate REPLACES the interval's share-derived contribution.
//
//       credit(p) = E_b(p) + SUM_i [ Hhat_comb(p,i) - W_shares(p,i) ]
//
//   apply_credit() now returns that REPLACE DELTA and cannot emit Hhat without
//   the matching -W_shares, so the additive rule has NO reachable code path. It
//   survives only as broken_add_NEVER_CONSENSUS(), a second negative witness
//   this KAT drives beside the shipped rule on the same fixture. Case
//   DROPS-REPLACE proves the exact algebra; case DROPS-NO-DOUBLE-COUNT measures
//   the composed credit at ~1.0x the true work where the rejected additive rule
//   measures ~1.9x on the same draws.
//
//   DROPS-R3 (WHOSE HARVEST) — OPEN, witnessed here, NOT fixed. Two nodes
//   observe different raindrops and would therefore compose different credit for
//   the same block. It does not desync them today, because the winner's FOUND
//   event carries the composed credit map and each node folds what it received
//   (btc_node.hpp, the S-1c peer path) — but if the harvest is ever made
//   consensus-visible, WHOSE harvest counts is an operator ruling. Stated here
//   rather than guessed.
//
// BUILD (standalone; nothing in the tree is written):
//   g++-15 -std=c++20 -O2 -Wall -Wextra -I<repo>/src
//       v37_drops_activation_kat.cpp -o v37_drops_activation_kat
//
// HOLLOW-GREEN GUARD: this target is registered with add_test() in
// src/c2pool/v37/test/CMakeLists.txt AND listed on BOTH build.yml
// `cmake --build --target` allowlists (the Linux x86_64 leg and the ASan+UBSan
// leg), so CI compiles and RUNS it instead of registering a NOT_BUILT CTest
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
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/v37_node_lane_activation.hpp>  // T1 seam
#include <c2pool/v37/w2_admission.hpp>              // T2 seam
#include <c2pool/v37/v37_drop_harvest.hpp>
#include <c2pool/v37/v37_share_counter.hpp>          // T2 seam (harvester)
#include <c2pool/v37/settle_finalize_driver.hpp>    // T3 seam

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

// ── the pinned goldens ────────────────────────────────────────────────────
//
// ★ THE MINT. owed_digest at the pinned cut with the V37.1 ridge ACTIVE and the
// DROPS gate ON over the pinned harvest. This is the RDWR-OQ2 activation value.
// It is lane-independent for the same reason the V37.1 golden is: the estimator
// credit is a function of the harvest and K alone, and E_b truncates to
// identical satoshi rows on all four lanes.
// ★ SUPERSEDES 34e4b38e20d2e222…, which was minted over the ADDITIVE
// composition and double-counted a share-covered payee (DROPS-R2). A node that
// carries the replace-not-add fix must NEVER reproduce that value.
static const char* GOLDEN_DROPS_ON =
    "984c7753ab352255933fb63da524b93eecc916b07cc77d94b454213922f719ce";
// The superseded value, kept ONLY as a negative assertion: the KAT proves the
// corrected mint is not it.
// ★ ALSO SUPERSEDED: d85dff58…, the replace-not-add mint. It was composed in
// RAW HASH COUNTS and with no enrolment question asked, so DROPS-R1
// (denomination) and R-SYBIL (ex-ante enrolment) both move it. A build that
// still reproduced it would be crediting hash counts as satoshi and crediting
// identities that never committed.
static const char* SUPERSEDED_RAW_UNENROLLED_GOLDEN =
    "d85dff58ce7734e5ff414be29f116fbc257ada5cd87ee3d95e2ffe40f554ff78";
static const char* SUPERSEDED_ADDITIVE_GOLDEN =
    "34e4b38e20d2e222622e1faafbe06c3e392d830a0a878b5e16f67bb2157d8a26";
// The fold of the four gate-ON digests in ratified LaneKind order
// (BTC, LTC, DASH, DOGE), domain-separated: sha256d("V37DROPS1" || d0..d3).
// One number an operator can quote for "the activation, all lanes".
static const char* GOLDEN_DROPS_ON_COMBINED =
    "b03abb1f5798ab199febc4977b4af31e624f5aab0d84e41e60310d344586bd19";
// ── the anchors that MUST NOT move ────────────────────────────────────────
// V37.1 gate-ON ridge golden (src/c2pool/v37/test/v37_1_ridge_activation_test.cpp).
static const char* ANCHOR_RIDGE_ON =
    "87c5249ac2057d0ac6707127c59cdc605acec4ba3c0d4b4b25e9b53692eb71ee";
// The pre-V37.1 control over the identical schedule (ridge inactive).
static const char* ANCHOR_RIDGE_OFF =
    "9cfaf97de7c58a7727ff5cc1203f445fc301559fb702938a3dd61ad32d6b338e";
// The empty-ledger anchor, sha256d("V37O").
static const char* ANCHOR_OWED_EMPTY =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

// ── the pinned schedule (identical to the V37.1 ridge activation KAT) ─────
static constexpr std::uint64_t SEED           = 0x5EED4096ull;
static constexpr int           N_PUSH         = 9000;
static constexpr unsigned      N_MINERS       = 10;
static constexpr u64           SHARES_PER_BIN = 8;
static constexpr u64           ACT_POS        = 4096;
static constexpr u64           REWARD         = 50ull * 100000000ull;
static constexpr int           N_BLOCKS       = 4;
static const u64  BLOCK_AT[N_BLOCKS]  = {4000, 4097, 6000, 9000};
static const char* BLOCK_ID[N_BLOCKS] = {"blk_pre", "blk_flip", "blk_mid", "blk_cut"};

// ── the pinned harvest ────────────────────────────────────────────────────
//   h_T        the share-target boundary: hash <= h_T is a SHARE, a hash above
//              it is a below-target near-miss ("a raindrop"). 2^244, i.e. a
//              share difficulty of 4096 — the same target the shipped module
//              KAT's sybil case uses.
//   DROPS      the tiny-hashrate / mobile payees, identities 1001..1006,
//              DISJOINT from the ten share miners, so they carry no E_b row at
//              all and their entire credit is the estimate. Their interval hash
//              counts are deliberately at or below the share difficulty, which
//              is the participation case DROPS exists for.
//   COVER      two payees that ARE share miners (ids 3 and 7) and therefore DO
//              carry a live E_b row, harvested with a hash count well above the
//              share difficulty so S > 0. They exist to witness DROPS-R2; a
//              caller honouring the "uncovered intervals only" convention would
//              never harvest them, and nothing enforces it.
//   interval   the block's own K_fair bin_height, (BLOCK_AT[b]-1)/SHARES_PER_BIN
//              — monotone across the four blocks (499, 512, 749, 1124), which
//              is the F1 contract (buried, out-of-interval, never the tip).
static constexpr unsigned  H_T_BIT      = 244;              // h_T == 2^244
static constexpr u64       T_SHARE      = 1ull << (256 - H_T_BIT);   // 4096
static constexpr std::uint64_t HARVEST_SEED = 0xD4095EEDD4095EEDull;
static constexpr unsigned  N_DROPS      = 6;
static constexpr MinerId   DROP_BASE    = 1001;
// hashes each drop payee performed in the interval (a spread of tiny devices)
static const std::uint64_t DROP_HASHES[N_DROPS] = {512, 1024, 2048, 3072, 4096, 6144};
static const MinerId       COVER_ID[2]  = {3, 7};           // real share miners
static const std::uint64_t COVER_HASHES[2] = {20 * T_SHARE, 12 * T_SHARE};
static constexpr std::uint64_t STARVED_HASHES = 3;          // J < K (arm A5)
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
    // one hash, uniform over the full 256-bit range (what a miner actually draws)
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

// The module's own low-63-bit fold of a bounded u320 (mirrors apply_credit's
// fold). Used ONLY to PREDICT a credit independently and to contrast the
// corrected rule against the broken clamp — never to produce one: every credit
// this KAT settles flows through the real seam.
static long long low63(const sub::u320& e) {
    long long a = 0;
    for (int i = 62; i >= 0; --i) a = (a << 1) | (e.bit(i) ? 1 : 0);
    return a;
}
static double u320_to_double(const sub::u320& x) {
    double v = 0.0;
    for (int i = 4; i >= 0; --i) v = v * 18446744073709551616.0 + (double)x.w[(std::size_t)i];
    return v;
}

// One harvested payee's interval, simulated: draw `hashes` uniform 256-bit
// values from a stream pinned by (id, interval) and present every one of them
// to the module's ReceiptCollector, which does the share/near-miss split and
// the K-best retention itself. `extra_shares` adds synthetic at-target hashes
// WITHOUT touching the near-miss set — the DROPS-R2 lever, and nothing else
// uses it.
static sub::ReceiptCollector simulate(MinerId id, u64 interval, std::uint64_t hashes,
                                      std::uint32_t K, std::uint64_t extra_shares = 0) {
    sub::ReceiptCollector rc(K, share_target());
    for (std::uint64_t i = 0; i < extra_shares; ++i) {
        sub::u256 s; s.w[0] = 1 + i; rc.observe(s);   // far below the target
    }
    Rng r(HARVEST_SEED ^ (std::uint64_t(id) * 0x100000001B3ull) ^
          (interval * 0x9E3779B97F4A7C15ull));
    for (std::uint64_t i = 0; i < hashes; ++i) rc.observe(r.hash());
    return rc;
}

enum class Harvest { None, Full, Starved };

// The pinned harvest for one block. Deterministic in (interval, mode, K).
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
    long long est_total[N_BLOCKS] = {0, 0, 0, 0};   // the estimator's own contribution
    long long eb_total[N_BLOCKS]  = {0, 0, 0, 0};   // the E_b split of the reward
    std::array<std::uint8_t, 32> shadow{};          // independent second digest
    std::array<std::uint8_t, 32> spec{};            // from-spec third digest
    bool saturated = false;                         // R1 i64 clamp ever fired
};

// ── the FROM-SPEC credit rule ─────────────────────────────────────────────
// The RDWR-OQ2 rule written out from the specification, deliberately NOT
// calling apply_credit() or subthreshold_credit(). It re-derives the gate, the
// K >= 3 guard, the J >= K refusal, the per-(payee, interval) straddle dedup,
// the mode selection AND THE REPLACE COMPOSITION from the spec text, and reaches
// the module only for the estimator ARITHMETIC and the u320->i64 fold, which is
// what the spec defines. If this and the engine seam disagree at any block, the
// mint is not reproducible and the KAT says so.
//
// ★ The composition is written out here IN FULL — est minus covered — precisely
// so that a future edit which quietly reverts to the additive merge fails this
// cross-check instead of silently re-minting a double-counting golden.
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
        // ★ R-SYBIL, written from the ruling text: an identity that did NOT
        // commit before the interval is not a DROPS participant at all — it
        // keeps its ordinary S*T path and contributes nothing here.
        if (!ctx.enrolled(hr.payee, hr.interval)) continue;
        if (g.mode != 1 && rc.shares() > 0) continue; // EstimateOnly refuses covered
        seen[key] = true;
        sub::u320 e{}, w{};
        if (g.mode == 1) {                            // Combined (the canon rule)
            // ★ ENROLLED: composed ALWAYS. J < K is no longer a refusal, it is
            // Hhat == 0 — the enrolled payee's whole share work comes back out
            // and nothing replaces it. That is the downside enrolment accepts,
            // and it is what makes the ex-ante choice worth nothing.
            if (rc.near_miss_count() >= g.K)
                e = sub::estimate_combined(rc.shares(), g.K, rc.h_K());
            // REPLACE: Hhat_comb covers the WHOLE interval, so the interval's
            // share-derived contribution W_shares = S*T comes back out. Written
            // from the spec's own definition of a share's work, not read off the
            // module's share_covered_work().
            if (rc.shares() > 0)
                w = sub::divfloor(sub::coeff_times_2_256(rc.shares()),
                                  sub::promote(rc.target_hash()));
        } else {                                      // EstimateOnly
            if (rc.near_miss_count() >= g.K) e = sub::estimate_hashes(g.K, rc.h_K());
        }
        // ★ R1, written from the ruling text: BOTH sides go through the ORDINARY
        // share -> E_b conversion floor(reward * work / SUM weight) — which is
        // split_reward's own expression — and are then subtracted. Converting
        // each side separately (not the difference) is what keeps this
        // re-derivation and the seam on the same integer.
        const long long amt = settle::entitlement_of_work(ctx.price, e)
                            - settle::entitlement_of_work(ctx.price, w);
        if (amt != 0) out[hr.payee] += amt;
    }
    return out;
}

// Drive the pinned schedule once.
//   ridge   V37.1 Shape A active at ACT_POS (the state of master) or inert
//   drops   the DROPS gate version: 0 = OFF, 1 = the canon ON configuration
//   mode    which harvest the blocks carry
//   K_over  0 = the canon K; otherwise force K (arm A4 uses 2)
static Run drive(LaneKind lk, bool ridge, unsigned drops, Harvest mode,
                 std::uint32_t K_over = 0) {
    LaneParams p = LaneParams::for_version(1, lk);
    if (ridge) {
        p.mrr.activation_pos   = ACT_POS;
        p.nr.nr_activation_pos = ACT_POS;
    } else {
        p.mrr.activation_pos   = UINT64_MAX;
        p.nr.nr_activation_pos = UINT64_MAX;
    }
    // The gate is set EXPLICITLY on both arms and never read from the factory's
    // default, so this KAT and its goldens are invariant to any later canon
    // edit: the OFF arm restores V37.0's gate, the ON arm is the activation.
    p.subthreshold = SubthresholdGate::for_version(drops);
    if (K_over) p.subthreshold.K = K_over;
    const std::uint32_t K_use = p.subthreshold.K;

    Run o;
    // ★ R-SYBIL — THE EX-ANTE ENROLMENT BOOK, built BEFORE the schedule runs.
    // Every commitment is made at interval 0 to take effect at interval 1,
    // strictly earlier than the first interval this schedule harvests (bin 499),
    // so no identity in this mint is choosing after seeing its own draws. A
    // payee that is NOT in this book is credited nothing at all by the seam —
    // case DROPS-ENROL below drives exactly that arm.
    ::c2pool::v37n::EnrollmentBook enroll;
    for (unsigned d = 0; d < N_DROPS; ++d) enroll.commit(key_of(DROP_BASE + d), 0, 1);
    for (unsigned c = 0; c < 2; ++c)      enroll.commit(key_of(COVER_ID[c]), 0, 1);
    ::v37::Lane lane(p);
    auto idv = std::make_shared<FakeIdView>();
    for (MinerId m = 1; m <= N_MINERS; ++m)
        idv->m[m] = ::v37::IdentityEntry{key_of(m), ::v37::ScriptRef{}};

    settle::OwedLedger ledger(7);
    // An INDEPENDENT shadow of the ledger state. payout is empty throughout, so
    // EffectiveOwed == finalW and first_eligible arms on the first finalize that
    // leaves a key positive. Hashed by the estimator module's own owed_digest(),
    // a second implementation of the same commitment.
    std::map<bytes32, long long> sh_final;
    std::map<bytes32, u64> sh_fe;
    // and a THIRD state, folded from the from-spec rule above
    std::map<bytes32, long long> sp_final;
    std::map<bytes32, u64> sp_fe;
    bool spec_agrees = true;

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
            settle::OwedLedger::Amounts base;
            for (const auto& [k, val] : f->credit) base[k] = (long long)val;
            for (const auto& [k, val] : base) { (void)k; o.eb_total[nb] += val; }

            const u64 bin = (BLOCK_AT[nb] - 1) / SHARES_PER_BIN;
            const auto hv = harvest_for(bin, mode, K_use);
            // ★★ THE RULED COMPOSITION CONTEXT — both rulings, at the cut.
            //   R1       the price is (reward, SUM weight) read from THIS view
            //            through the SAME project() the fold above ran, so an
            //            estimated hash and a real hash at this cut are worth
            //            the same satoshi.
            //   R-SYBIL  `enroll` is the ex-ante book; a payee not in it is
            //            credited nothing and keeps its ordinary S*T path.
            settle::DropsCompose ctx;
            ctx.price      = settle::work_price_at(REWARD, v);
            ctx.enrollment = &enroll;
            bool sat = false;
            const auto est = settle::subthreshold_credit(p, hv, ctx, &sat);
            if (sat) o.saturated = true;
            for (const auto& [k, val] : est) { (void)k; o.est_total[nb] += val; }

            ledger.on_block_found_with_drops(BLOCK_ID[nb], base, {}, p, hv, ctx);
            ledger.on_block_finalized(BLOCK_ID[nb], bin);

            for (const auto& [k, val] : base) sh_final[k] += val;
            for (const auto& [k, val] : est)  sh_final[k] += val;
            // The ledger's own rearm rule, mirrored: ARM on the first bin a key
            // is strictly positive, and DISARM the moment it is not (payout is
            // empty throughout, so EffectiveOwed == finalW here). The disarm leg
            // matters now that a REPLACE delta can carry a row negative — an
            // "arm only" shadow would silently diverge on exactly the covered
            // payees this fixture exists to exercise.
            for (const auto& [k, val] : sh_final) {
                if (val > 0) { if (!sh_fe.count(k)) sh_fe[k] = bin; }
                else sh_fe.erase(k);
            }

            std::map<std::pair<bytes32, u64>, bool> spec_seen;
            const auto sp = spec_credit(p.subthreshold, hv, spec_seen, ctx);
            if (sp != est) spec_agrees = false;
            for (const auto& [k, val] : base) sp_final[k] += val;
            for (const auto& [k, val] : sp)   sp_final[k] += val;
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
    o.spec        = spec_agrees ? sub::owed_digest(sp_final, sp_fe)
                                : std::array<std::uint8_t, 32>{};
    return o;
}

int main() {
    std::printf("== v37_drops_activation_kat: RDWR-OQ2 DROPS activation mint + regression\n");
    std::printf("   schedule : seed=0x%llx pushes=%d miners=%u shares/bin=%llu "
                "ridge_pos=%llu reward=%llu\n",
                (unsigned long long)SEED, N_PUSH, N_MINERS,
                (unsigned long long)SHARES_PER_BIN, (unsigned long long)ACT_POS,
                (unsigned long long)REWARD);
    std::printf("   harvest  : h_T=2^%u (share difficulty %llu), K=%u, seed=0x%llx\n"
                "              %u drop payees ids %u..%u with %llu..%llu hashes "
                "(S ~ 0), 2 covered payees ids %u,%u with %llu/%llu hashes (S > 0)\n",
                H_T_BIT, (unsigned long long)T_SHARE, K_CANON,
                (unsigned long long)HARVEST_SEED, N_DROPS, DROP_BASE,
                DROP_BASE + N_DROPS - 1,
                (unsigned long long)DROP_HASHES[0],
                (unsigned long long)DROP_HASHES[N_DROPS - 1],
                COVER_ID[0], COVER_ID[1],
                (unsigned long long)COVER_HASHES[0],
                (unsigned long long)COVER_HASHES[1]);

    const LaneKind LK[4] = {LaneKind::BTC, LaneKind::LTC, LaneKind::DASH, LaneKind::DOGE};
    const char*    LN[4] = {"BTC", "LTC", "DASH", "DOGE"};

    // ── DROPS-CANON: the RDWR-OQ2 ruling as the canon states it ──────────
    std::printf("\n-- DROPS-CANON: the canon declares DROPS ON for every lane --\n");
    {
        const SubthresholdGate g1 = SubthresholdGate::for_version(1);
        std::printf("   for_version(1) = {enabled=%s K=%u mode=%u version=%u}\n",
                    g1.enabled ? "true" : "false", g1.K, g1.mode, g1.version);
        check(g1.enabled, "canon v1 declares the DROPS gate ENABLED");
        check(g1.K == K_CANON, "canon v1 declares K == 4 (the K >= 3 guard holds)");
        check(g1.mode == 1, "canon v1 selects mode 1 = Combined, the corrected "
                            "sybil-neutral rule (never the E-2 clamp)");
        check(g1.version == 1, "canon v1 stamps the consensus version marker");
        check(SHIPPED_CONSENSUS_VERSION == 1,
              "the node ships V37.1, so shipped() carries the ON gate");
        const SubthresholdGate g0 = SubthresholdGate::for_version(0);
        check(!g0.enabled, "V37.0 replay stays OFF (pre-existing goldens survive)");
        check(!LaneParams{}.subthreshold.enabled,
              "the bare LaneParams{} default stays OFF (the KAT-0 configuration)");
        for (int i = 0; i < 4; ++i) {
            const LaneParams p = LaneParams::for_version(1, LK[i]);
            check(p.subthreshold.enabled && p.subthreshold.K == K_CANON &&
                  p.subthreshold.mode == 1,
                  "every ratified lane declares the same ON gate (all lanes, always)");
            const auto sp = settle::to_subthreshold_params(p);
            check(sp.enabled && sp.mode == sub::CreditMode::Combined,
                  "W4 translates the canon gate to CreditMode::Combined");
        }
    }

    // ── DROPS-EMPTY ──────────────────────────────────────────────────────
    std::printf("\n-- DROPS-EMPTY: the anchor a fresh ledger must still produce --\n");
    {
        settle::OwedLedger e(7);
        std::printf("   empty owed_digest        = %s\n", hex(e.owed_digest()).c_str());
        check(hex(e.owed_digest()) == ANCHOR_OWED_EMPTY,
              "empty ledger owed_digest == sha256d(\"V37O\") == b4db1ded…");
        check(e.ledger_seq() == 0, "a fresh ledger is at seq 0");
    }

    // ── drive every arm on every lane ────────────────────────────────────
    Run a0[4], a1[4], a2[4], a3[4], a4[4], a5[4];
    for (int i = 0; i < 4; ++i) {
        a0[i] = drive(LK[i], false, 0, Harvest::Full);
        a1[i] = drive(LK[i], true,  0, Harvest::Full);
        a2[i] = drive(LK[i], true,  1, Harvest::None);
        a3[i] = drive(LK[i], true,  1, Harvest::Full);
        a4[i] = drive(LK[i], true,  1, Harvest::Full, /*K=*/2);
        a5[i] = drive(LK[i], true,  1, Harvest::Starved);
        const Run* all[6] = {&a0[i], &a1[i], &a2[i], &a3[i], &a4[i], &a5[i]};
        for (const Run* rr : all)
            check(!rr->refused && !rr->short_run,
                  "the arm completes without a settlement refusal or a short run");
    }

    // ── DROPS-ANCHORS / DROPS-DORMANT ────────────────────────────────────
    std::printf("\n-- DROPS-ANCHORS: the gate-OFF anchors are UNMOVED --\n");
    std::printf("   A0 ridge OFF, drops OFF                = %s\n", hex(a0[0].owed).c_str());
    std::printf("   A1 ridge ON,  drops OFF                = %s\n", hex(a1[0].owed).c_str());
    std::printf("   A2 ridge ON,  drops ON, harvest EMPTY  = %s\n", hex(a2[0].owed).c_str());
    std::printf("   A4 ridge ON,  drops ON, K = 2          = %s\n", hex(a4[0].owed).c_str());
    std::printf("   A5 ridge ON,  drops ON, J < K          = %s\n", hex(a5[0].owed).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex(a0[i].owed) == ANCHOR_RIDGE_OFF,
              "A0 reproduces the pre-V37.1 control 9cfaf97d… on this lane");
        check(hex(a1[i].owed) == ANCHOR_RIDGE_ON,
              "A1 reproduces the V37.1 ridge anchor 87c5249a… on this lane — the "
              "harvest is present and the OFF gate admits none of it");
        check(hex(a2[i].owed) == ANCHOR_RIDGE_ON,
              "A2 (DORMANT): the canon gate is ON but nothing is harvested");
        check(hex(a4[i].owed) == ANCHOR_RIDGE_ON,
              "A4: K = 2 is refused by the K >= 3 guard, so nothing is credited");
        check(hex(a5[i].owed) == ANCHOR_RIDGE_ON,
              "A5: J < K credits 0 (no fallback inflation)");
        check(a1[i].est_total[3] == 0, "A1 credits nothing at the seam (gate OFF)");
        check(a2[i].est_total[3] == 0, "A2 credits nothing at the seam (no harvest)");
        check(a4[i].est_total[3] == 0, "A4 credits nothing at the seam (K guard)");
        check(a5[i].est_total[3] == 0, "A5 credits nothing at the seam (J < K)");
    }

    // ── DROPS-ON: the mint ───────────────────────────────────────────────
    std::printf("\n-- DROPS-ON: the gate-ON activation golden (V37.1 ridge + DROPS) --\n");
    for (int i = 0; i < 4; ++i)
        std::printf("   %-4s gate_on_owed_digest = %s\n", LN[i], hex(a3[i].owed).c_str());
    std::array<std::uint8_t, 32> comb{};
    {
        std::vector<std::uint8_t> pre = {'V','3','7','D','R','O','P','S','1'};
        for (int i = 0; i < 4; ++i)
            pre.insert(pre.end(), a3[i].owed.begin(), a3[i].owed.end());
        comb = sub::detail::sha256d(pre);
    }
    std::printf("   combined (BTC|LTC|DASH|DOGE) = %s\n", hex32(comb).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex(a3[i].owed) == GOLDEN_DROPS_ON,
              "gate-ON owed_digest matches the pinned DROPS activation golden");
        check(a3[i].owed == a3[0].owed,
              "the gate-ON golden is lane-independent (E_b truncates identically "
              "and the estimate depends only on the harvest and K)");
        check(hex(a3[i].owed) != SUPERSEDED_ADDITIVE_GOLDEN,
              "★ and it is NOT the superseded 34e4b38e… additive mint: a build that "
              "reproduced that value would still be double-counting");
        check(hex(a3[i].owed) != SUPERSEDED_RAW_UNENROLLED_GOLDEN,
              "★ nor the superseded d85dff58… raw/un-enrolled mint: a build that "
              "reproduced THAT value would be crediting hash counts as satoshi and "
              "paying identities that never enrolled");
        check(!a3[i].saturated,
              "the R1 conversion never hit its i64 clamp over the whole mint");
    }
    check(hex32(comb) == GOLDEN_DROPS_ON_COMBINED,
          "the combined all-lanes fold matches its pinned value");

    // ── DROPS-LIVE: non-vacuity ──────────────────────────────────────────
    std::printf("\n-- DROPS-LIVE: the golden is non-vacuous --\n");
    for (int i = 0; i < 4; ++i) {
        check(!(a3[i].owed == a1[i].owed),
              "gate ON differs from the V37.1 anchor over the IDENTICAL harvest");
        check(!(a3[i].owed == a0[i].owed), "gate ON differs from the pre-V37.1 control");
        check(hex(a3[i].owed) != ANCHOR_OWED_EMPTY, "the golden is a settled ledger");
        check(a3[i].ledger_seq == 8, "the ledger is at seq 8 (4 found + 4 finalized)");
        // The seam returns REPLACE DELTAS, which are SIGNED: a covered payee
        // whose estimate undershot its share work contributes a negative row.
        // "The estimator moved the ledger" is therefore != 0, not > 0. That the
        // movement is real is proved by the digest, three independent ways.
        check(a3[i].est_total[3] != 0, "the estimator really moved the ledger at the cut");
    }
    std::printf("   ON != V37.1 anchor: %s   ON != empty: %s   lanes agree: %s\n",
                (a3[0].owed == a1[0].owed) ? "NO (VACUOUS)" : "yes",
                hex(a3[0].owed) == ANCHOR_OWED_EMPTY ? "NO (VACUOUS)" : "yes",
                (a3[0].owed == a3[3].owed) ? "yes" : "NO");

    // ── DROPS-LANEDIGEST: the gate is not digested geometry ──────────────
    std::printf("\n-- DROPS-LANEDIGEST: flipping DROPS moves NO lane digest --\n");
    for (int i = 0; i < 4; ++i) {
        check(a3[i].lane_digest == a1[i].lane_digest,
              "the lane digest is DROPS-gate-invariant (the gate is not a leaf)");
        check(a3[i].lane_digest == a2[i].lane_digest,
              "the lane digest is harvest-invariant too (the harvest is settlement "
              "input, never lane state)");
    }
    {   // the KAT-0 configuration: every gate OFF, bare default LaneParams.
        LaneParams k0;
        LaneParams k0_on = k0;
        k0_on.subthreshold = SubthresholdGate::for_version(1);
        ::v37::Lane l0(k0), l1(k0_on);
        Rng r0(SEED);
        for (int i = 0; i < 1024; ++i) {
            ::v37::WorkAtom a{};
            a.miner = MinerId(1 + (r0.next() % N_MINERS));
            a.w_raw = 1 + (r0.next() % 1000);
            a.origin_bin = a.carrier_bin = u64(i) / SHARES_PER_BIN;
            a.version = ::v37::PROV_V37;
            l0.push(a, key_of);
            l1.push(a, key_of);
        }
        std::printf("   KAT-0 geometry lane digest, gate OFF = %s\n",
                    hex(l0.digest(key_of)).c_str());
        check(l0.digest(key_of) == l1.digest(key_of),
              "KAT-0 geometry: the lane digest is byte-identical with the DROPS "
              "gate ON and OFF (the gate is digest-neutral by construction)");
        check(!k0.subthreshold.enabled && k0.nr.nr_version == 0 &&
              k0.nr.nr_activation_pos == UINT64_MAX &&
              k0.mrr.activation_pos == UINT64_MAX &&
              k0.win.win_activation_pos == UINT64_MAX,
              "the KAT-0 configuration really is every-gate-OFF");
        // ★ THE KAT-0 ANCHOR 2479d5b6, HONESTLY. Its literal and its push
        // schedule are NOT in this tree — v37_lane.hpp:344 and v37_fixed.hpp:149
        // cite it as a canon reference, and nothing here can re-derive it. What
        // IS proved, and is what actually protects it: the KAT-0 INPUT is
        // ::v37::LaneParams{}; this PR changes no canon file and no default in
        // it (case DROPS-T1 asserts node_lane_params() == LaneParams{} on every
        // gate); and the lane digest over that input is byte-identical with the
        // DROPS gate ON and OFF, above. A value whose input and whose producing
        // code are both unchanged cannot move.
        check(k0.subthreshold.K == LaneParams{}.subthreshold.K &&
              k0.subthreshold.mode == LaneParams{}.subthreshold.mode &&
              k0.subthreshold.version == LaneParams{}.subthreshold.version,
              "the KAT-0 input LaneParams{} is untouched by this PR, so the "
              "2479d5b6 canon anchor has no way to move");
    }

    // ── DROPS-XCHECK: a second, independent digest implementation agrees ──
    std::printf("\n-- DROPS-XCHECK: an independent shadow reproduces the golden --\n");
    std::printf("   shadow(sub::owed_digest over an independently folded state) = %s\n",
                hex32(a3[0].shadow).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex32(a3[i].shadow) == hex(a3[i].owed),
              "the estimator module's own owed_digest() over an independently "
              "shadowed finalW/first_eligible reproduces the ledger's digest");
        check(hex32(a1[i].shadow) == hex(a1[i].owed),
              "the same shadow reproduces the gate-OFF anchor");
    }
    std::printf("   spec  (the credit rule re-derived from the specification, not "
                "through apply_credit) = %s\n", hex32(a3[0].spec).c_str());
    for (int i = 0; i < 4; ++i) {
        check(hex32(a3[i].spec) == GOLDEN_DROPS_ON,
              "a FROM-SPEC re-derivation of the gate, the K >= 3 guard, the J >= K "
              "refusal, the straddle dedup and the Combined selection reproduces the "
              "golden without calling the engine seam — the mint is reproducible");
        check(hex32(a1[i].spec) == ANCHOR_RIDGE_ON,
              "and the same from-spec path reproduces the gate-OFF anchor");
        check(hex32(a5[i].spec) == ANCHOR_RIDGE_ON,
              "and agrees with the seam on the J < K refusal");
        check(hex32(a4[i].spec) == ANCHOR_RIDGE_ON,
              "and agrees with the seam on the K >= 3 guard");
    }

    // ── DROPS-RULE: the ACTIVE rule is Hhat_comb, and the clamp is not ────
    std::printf("\n-- DROPS-RULE: the crediting rule is the corrected Hhat_comb --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        const u64 iv = 512;
        auto rc = simulate(DROP_BASE, iv, DROP_HASHES[0], K_CANON);
        std::vector<settle::HarvestedReceipt> hv{
            settle::HarvestedReceipt{key_of(DROP_BASE), iv, rc}};
        const auto credit = settle::subthreshold_credit_raw_PRE_RULING(p, hv);
        check(credit.size() == 1, "the seam credits exactly the harvested payee");
        const long long seam = credit.empty() ? -1 : credit.begin()->second;
        const long long cmb  = low63(sub::estimate_combined(rc.shares(), K_CANON, rc.h_K()));
        const long long clm  = low63(sub::broken_clamp_NEVER_CONSENSUS(
            rc.shares(), K_CANON, rc.h_K(), rc.target_hash()));
        std::printf("   drop payee, %llu hashes, S=%llu, J=%zu: seam=%lld  "
                    "estimate_combined=%lld  broken clamp=%lld\n",
                    (unsigned long long)DROP_HASHES[0],
                    (unsigned long long)rc.shares(), rc.near_miss_count(),
                    seam, cmb, clm);
        check(seam == cmb, "the seam credit IS estimate_combined (the corrected rule)");
        check(seam != 0, "the corrected rule credits a non-zero amount (non-vacuous)");

        // a covered payee separates the two rules outright
        auto rcS = simulate(COVER_ID[0], iv, COVER_HASHES[0], K_CANON);
        std::vector<settle::HarvestedReceipt> hvS{
            settle::HarvestedReceipt{key_of(COVER_ID[0]), iv, rcS}};
        const auto creditS = settle::subthreshold_credit_raw_PRE_RULING(p, hvS);
        const long long seamS = creditS.empty() ? -1 : creditS.begin()->second;
        const long long cmbS  = low63(sub::estimate_combined(rcS.shares(), K_CANON, rcS.h_K()));
        const long long clmS  = low63(sub::broken_clamp_NEVER_CONSENSUS(
            rcS.shares(), K_CANON, rcS.h_K(), rcS.target_hash()));
        const long long wshS = low63(sub::share_covered_work(rcS.shares(),
                                                             rcS.target_hash()));
        std::printf("   covered payee, %llu hashes, S=%llu: seam delta=%lld  "
                    "combined=%lld  W_shares=%lld  composed=%lld  clamp=%lld  "
                    "clamp/composed=%.4f\n",
                    (unsigned long long)COVER_HASHES[0],
                    (unsigned long long)rcS.shares(), seamS, cmbS, wshS,
                    wshS + seamS, clmS,
                    (wshS + seamS) ? (double)clmS / (double)(wshS + seamS) : 0.0);
        check(rcS.shares() > 0, "the covered fixture really does carry shares");
        check(seamS == cmbS - wshS,
              "with S > 0 the seam returns the REPLACE delta Hhat_comb - W_shares, "
              "so the COMPOSED credit is Hhat_comb and the shares are paid once");
        check(seamS != clmS, "the corrected rule and the clamp DISAGREE here — the "
                             "negative witness is live, not vacuous");
        check(clmS > wshS + seamS,
              "the clamp over-credits relative to the composed corrected rule");
    }

    // ── DROPS-SYBIL + DROPS-NO-2X ────────────────────────────────────────
    // One miner's interval of H hashes, split into n identities, routed through
    // the REAL seam. Ratios are against the TRUE hash count H, so a value of
    // 1.00 is "credited exactly the work performed": that is simultaneously the
    // no-sybil-profit test (flat in n) and the no-x2 test (never ~2.0).
    std::printf("\n-- DROPS-SYBIL + DROPS-NO-2X: split gains nothing; no x2 vs the "
                "true rate --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        const sub::u256 hT = share_target();
        const std::uint64_t Hbig = 20 * T_SHARE;      // 81920 hashes, E[S] = 20
        double comb_r[3] = {0, 0, 0}, clamp_r[3] = {0, 0, 0};
        const std::uint64_t NS[3] = {1, 20, 2000};
        for (int s = 0; s < 3; ++s) {
            const std::uint64_t n = NS[s];
            const std::uint64_t h = Hbig / n;
            const int tr = (int)std::min<std::uint64_t>(
                120, std::max<std::uint64_t>(20, 1500 / n));
            double clamp = 0, cmb = 0;
            for (int t = 0; t < tr; ++t) {
                std::vector<settle::HarvestedReceipt> hv;
                for (std::uint64_t id = 0; id < n; ++id) {
                    Rng rng(0xC0FFEEull + n * 1315423911ull +
                            (std::uint64_t)t * 2654435761ull + id);
                    sub::ReceiptCollector rc(K_CANON, hT);
                    for (std::uint64_t i = 0; i < h; ++i) rc.observe(rng.hash());
                    if (rc.has_K())
                        clamp += u320_to_double(sub::broken_clamp_NEVER_CONSENSUS(
                            rc.shares(), K_CANON, rc.h_K(), hT));
                    // ★ the COMPOSED credit, not the delta: the interval's own
                    // E_b contribution is W_shares, and the seam supplies the
                    // REPLACE delta on top. Summing deltas alone would measure
                    // ~0 and say nothing about what anyone is paid.
                    cmb += (double)low63(sub::share_covered_work(rc.shares(), hT));
                    hv.push_back(settle::HarvestedReceipt{
                        key_of(MinerId(90000 + id)), (u64)id, rc});
                }
                const auto credit = settle::subthreshold_credit_raw_PRE_RULING(p, hv);
                for (const auto& [k, v] : credit) { (void)k; cmb += (double)v; }
            }
            const double denom = (double)tr * (double)Hbig;
            comb_r[s] = cmb / denom;
            clamp_r[s] = clamp / denom;
            std::printf("   n=%-5llu identities x %-6llu hashes, %3d trials: composed "
                        "credit = %.4f x the true work   (clamp would be %.4f x)\n",
                        (unsigned long long)n, (unsigned long long)h, tr,
                        comb_r[s], clamp_r[s]);
        }
        check(comb_r[0] > 0.90 && comb_r[0] < 1.10,
              "DROPS-NO-2X: undivided, the corrected rule credits the TRUE hash "
              "count to within 10% — no x2, no systematic over-credit");
        check(comb_r[2] <= 1.05,
              "DROPS-SYBIL: a 2000-identity split collects no more than ~1.00x — "
              "splitting gains NOTHING under Hhat_comb");
        check(comb_r[2] >= 0.80, "the split is not silently starved either");
        check(clamp_r[2] > 1.3,
              "the clamp WOULD have been sybil-profitable at a 2000-split (>1.3x) "
              "— the negative witness is non-vacuous");
        check(clamp_r[2] > comb_r[2], "and the clamp is strictly worse than the rule "
                                      "that actually ships");
    }

    // ── DROPS-DEDUP: one credit per (payee, interval) ────────────────────
    std::printf("\n-- DROPS-DEDUP: one estimator credit per (payee, interval) --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        auto rc = simulate(DROP_BASE, 512, DROP_HASHES[0], K_CANON);
        std::vector<settle::HarvestedReceipt> once{
            settle::HarvestedReceipt{key_of(DROP_BASE), 512, rc}};
        std::vector<settle::HarvestedReceipt> twice = once;
        twice.push_back(settle::HarvestedReceipt{key_of(DROP_BASE), 512, rc});
        std::vector<settle::HarvestedReceipt> next_iv = once;
        next_iv.push_back(settle::HarvestedReceipt{
            key_of(DROP_BASE), 513, simulate(DROP_BASE, 513, DROP_HASHES[0], K_CANON)});
        const long long v1 = settle::subthreshold_credit_raw_PRE_RULING(p, once).begin()->second;
        const long long v2 = settle::subthreshold_credit_raw_PRE_RULING(p, twice).begin()->second;
        const long long v3 = settle::subthreshold_credit_raw_PRE_RULING(p, next_iv).begin()->second;
        std::printf("   once=%lld  replayed=%lld  two intervals=%lld\n", v1, v2, v3);
        check(v1 == v2, "replaying the SAME (payee, interval) credits it once "
                        "(the straddle dedup holds at the seam)");
        check(v3 > v1, "a DIFFERENT interval for the same payee does credit again");
    }

    // ── DROPS-R1 (★ RULED AND CLOSED): the estimate is DENOMINATED ───────
    // The defect: apply_credit's fold63 returns a HASH COUNT and E_b is a split
    // of the block REWARD in coin, so the merge dropped hashes into a satoshi
    // row. Measured by the verify pass at share difficulty 2^40: a 503,350,526
    // sat entitlement met a 3,299,038,233,853 "credit" — off by ~6553x, with the
    // SIGN of the error set by the lane's difficulty.
    //
    // The ruling: reuse the conversion the ordinary share path already uses.
    // That conversion is exactly two things, and this section pins both:
    //   (a) the Q62 UNIT — a push stores w_scaled = w_raw x InvD, so lane
    //       weights are Q62 work units, not hashes;
    //   (b) the PRICE — split_reward's own floor(reward * weight / SUM weight).
    // Put together: entitlement_of_work(price, W) == the E_b row a REAL share of
    // the same work magnitude gets at the same cut. Nothing else, no new
    // constant, and no second conversion.
    std::printf("\n-- DROPS-R1: the estimate is denominated through the SHARE path --\n");
    {
        long long est_all = 0, eb_all = 0;
        for (int b = 0; b < N_BLOCKS; ++b) {
            est_all += a3[0].est_total[b];
            eb_all  += a3[0].eb_total[b];
        }
        std::printf("   over the pinned schedule: E_b = %lld sat, DROPS delta = %lld sat "
                    "= %.4f%% of the reward paid\n",
                    eb_all, est_all,
                    eb_all ? 100.0 * (double)est_all / (double)eb_all : 0.0);
        check(eb_all == (long long)REWARD * N_BLOCKS,
              "E_b pays out exactly the block reward per block (the unit it is in)");
        check(est_all != 0, "the DROPS delta contributes a measurable amount "
                            "(signed: the REPLACE delta may net either way)");

        // ★ (1) SCALE CORRECTNESS. A composed row of work W and a REAL share row
        // of the same work W land on the SAME number of satoshi. Built on a view
        // whose weights ARE work(T) in the lane's own Q62 units, so the claim is
        // about the production conversion and not about a fixture artefact.
        sub::u256 hT216;  hT216.w[3] = (1ull << (216 - 192));      // 2^216
        {   // h_T = 2^216 - 1  (a leading-zero target of 40 bits: T = 2^40)
            sub::u256 t; t.w[3] = (1ull << (216 - 192));
            // subtract one, by hand: 2^216 - 1 sets every bit below 216
            sub::u256 hT{};
            for (unsigned b = 0; b < 216; ++b) hT.w[b >> 6] |= (1ull << (b & 63));
            // FOUR near-misses just above the target, the largest of which is the
            // K-th smallest and therefore h_(K).
            sub::ReceiptCollector rc(K_CANON, hT);
            for (int k = 0; k < 4; ++k) {
                sub::u256 h; h.w[3] = (1ull << (217 - 192)); h.w[0] = (std::uint64_t)k;
                rc.observe(h);
            }
            check(rc.near_miss_count() == K_CANON && rc.shares() == 0,
                  "R1 fixture: J == K near-misses, S == 0 (nothing to replace)");
            const sub::u320 hhat = sub::estimate_combined(0, K_CANON, rc.h_K());
            const long long raw  = low63(hhat);       // the PRE-RULING number
            check(raw > 0, "R1 fixture: the estimate is non-zero");

            // A lane in which ONE payee's weight is EXACTLY this estimate's work,
            // in the lane's own Q62 units, and the whole lane is ten times that.
            const ::v37::u128 wq = ((::v37::u128)raw) << 62;
            auto idv2 = std::make_shared<FakeIdView>();
            idv2->m[1] = ::v37::IdentityEntry{key_of(1), ::v37::ScriptRef{}};
            idv2->m[2] = ::v37::IdentityEntry{key_of(2), ::v37::ScriptRef{}};
            FakeView v2;
            v2.payout[1] = ::v37::U256::from_u128(wq);
            v2.payout[2] = ::v37::U256::from_u128(wq * 9);
            v2.identities = idv2;
            const settle::WorkPrice price = settle::work_price_at(REWARD, v2);
            check(price.valid, "R1: the price is expressible at this cut");
            const auto f2 = settle::fold_eb(REWARD, v2, /*strict=*/false);
            check(f2.has_value(), "R1: the fixture folds");
            const long long eb_x = f2 ? (long long)f2->credit.at(key_of(1)) : -1;
            bool sat = false;
            const long long ruled = settle::entitlement_of_work(price, hhat, &sat);
            std::printf("   equal-work fixture: payee-1 lane weight == the estimate's "
                        "work\n"
                        "     E_b(payee-1)                    = %lld sat\n"
                        "     entitlement_of_work(estimate)   = %lld sat   <- the RULED credit\n"
                        "     fold63(estimate) (PRE-RULING)   = %lld      <- a HASH COUNT as sat\n"
                        "     pre-ruling / E_b                = %.1f x\n",
                        eb_x, ruled, raw, eb_x ? (double)raw / (double)eb_x : 0.0);
            check(!sat, "R1: no i64 clamp on the equal-work fixture");
            check(ruled == eb_x,
                  "★ SCALE-CORRECT: a COMPOSED row of work W is credited EXACTLY the "
                  "same satoshi as a REAL SHARE row of the same work W at the same "
                  "cut — which is the whole content of the R1 ruling");
            check(raw != ruled,
                  "and it is NOT the pre-ruling number, so the fix is not vacuous");
            check(eb_x > 0 && (double)raw / (double)eb_x > 1000.0,
                  "★ THE BLOWUP, MEASURED: the pre-ruling raw hash count is more than "
                  "three orders of magnitude off the entitlement it was being added to "
                  "(the verify pass measured 503,350,526 sat vs 3,299,038,233,853)");
            // and it is a genuine proportionality, not one point: double the work,
            // double the credit.
            sub::u320 twice = hhat;
            {   // twice = hhat + hhat, limb-wise with carry
                ::v37::u128 c2 = 0;
                for (int li = 0; li < 5; ++li) {
                    ::v37::u128 t2 = (::v37::u128)hhat.w[(std::size_t)li] * 2 + c2;
                    twice.w[(std::size_t)li] = (std::uint64_t)t2;
                    c2 = t2 >> 64;
                }
            }
            const long long ruled2 = settle::entitlement_of_work(price, twice);
            check(ruled2 == 2 * ruled,
                  "R1: the conversion is exactly linear in the work (2W -> 2 x the "
                  "entitlement), so it cannot be a coincidence of one fixture");
            // gate-OFF / no-price safety: an unusable price credits NOTHING rather
            // than guessing a scale.
            settle::WorkPrice none;
            check(settle::entitlement_of_work(none, hhat) == 0,
                  "★ an invalid price credits ZERO — the seam never invents a scale");
        }
        (void)hT216;
    }

    // ── DROPS-REPLACE (★ the fix): the estimate REPLACES, never ADDS ─────
    // The exact algebra, on a covered fixture where the two rules differ. The
    // covered payee is a real share miner that DOES hold a live E_b row at this
    // cut, so the additive rule really was reachable — this is not a straw man.
    std::printf("\n-- DROPS-REPLACE: the estimate REPLACES the interval's E_b part --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        const u64 iv = 950;
        const std::uint64_t H = 20 * T_SHARE;
        auto rcS = simulate(COVER_ID[0], iv, H, K_CANON);
        check(rcS.shares() > 0, "the covered fixture really does carry shares (S > 0)");
        std::vector<settle::HarvestedReceipt> hv{
            settle::HarvestedReceipt{key_of(COVER_ID[0]), iv, rcS}};
        const auto delta_map = settle::subthreshold_credit_raw_PRE_RULING(p, hv);
        check(delta_map.size() == 1, "the seam returns exactly one row for one payee");
        const long long delta = delta_map.begin()->second;
        const long long est  = low63(sub::estimate_combined(rcS.shares(), K_CANON,
                                                            rcS.h_K()));
        const long long wsh  = low63(sub::share_covered_work(rcS.shares(),
                                                             rcS.target_hash()));
        const long long add  = sub::broken_add_NEVER_CONSENSUS(
            rcS.shares(), K_CANON, rcS.h_K(), rcS.target_hash());
        std::printf("   S=%llu  Hhat_comb=%lld  W_shares=S*T=%lld\n"
                    "   seam delta            = %lld   (== Hhat_comb - W_shares)\n"
                    "   composed  E_b + delta = W_shares + %lld = %lld   (the SHIPPED rule)\n"
                    "   rejected  E_b + Hhat  = %lld                (the ADDITIVE rule)\n",
                    (unsigned long long)rcS.shares(), est, wsh,
                    delta, delta, wsh + delta, add);
        check(delta == est - wsh,
              "the seam returns EXACTLY Hhat_comb - W_shares: the REPLACE delta");
        check(wsh + delta == est,
              "so the COMPOSED credit is exactly Hhat_comb — the estimate stands IN "
              "PLACE OF the interval's share-derived E_b contribution");
        check(add == wsh + est,
              "and the rejected additive rule would have been W_shares + Hhat_comb");
        check(add != wsh + delta,
              "the two rules DISAGREE on this fixture — the add witness is live");
        check(add > wsh + delta,
              "and the rejected rule pays MORE: that difference is the double count");
        // The exact double-count factor the ruling removed.
        const double factor = (double)add / (double)(wsh + delta);
        std::printf("   the additive rule pays %.4f x what the shipped rule pays "
                    "on this interval\n", factor);
        check(factor > 1.5, "the removed double count is of order x2, not a rounding "
                            "difference");

        // Non-vacuity of the whole section: this payee holds a LIVE E_b row.
        bool covered_has_eb = false;
        unsigned long long eb_row = 0;
        {
            LaneParams q = LaneParams::for_version(1, LaneKind::BTC);
            q.mrr.activation_pos = ACT_POS; q.nr.nr_activation_pos = ACT_POS;
            q.subthreshold = SubthresholdGate::for_version(0);
            ::v37::Lane lane(q);
            auto idv = std::make_shared<FakeIdView>();
            for (MinerId m = 1; m <= N_MINERS; ++m)
                idv->m[m] = ::v37::IdentityEntry{key_of(m), ::v37::ScriptRef{}};
            Rng r(SEED);
            for (int i = 0; i < N_PUSH; ++i) {
                ::v37::WorkAtom a{};
                a.miner = MinerId(1 + (r.next() % N_MINERS));
                a.w_raw = 1 + (r.next() % 1000);
                a.origin_bin = a.carrier_bin = u64(i) / SHARES_PER_BIN;
                a.version = ::v37::PROV_V37;
                lane.push(a, key_of);
            }
            FakeView v;
            v.params = q; v.next_pos = lane.next_pos(); v.payout = lane.payout_map();
            v.identities = idv; v.digest = lane.digest(key_of);
            auto f = settle::fold_eb(REWARD, v, true);
            if (f && f->credit.count(key_of(COVER_ID[0]))) {
                eb_row = (unsigned long long)f->credit.at(key_of(COVER_ID[0]));
                covered_has_eb = eb_row > 0;
            }
        }
        std::printf("   the harvested covered payee id=%u holds a LIVE E_b row of "
                    "%llu sat at the same cut (so the additive merge WAS reachable)\n",
                    COVER_ID[0], eb_row);
        check(covered_has_eb,
              "the covered payee carries a live E_b row: the double count this "
              "ruling removes was reachable on a real cut, not hypothetical");

        // An UNCOVERED interval is untouched by the ruling: S == 0 means there is
        // nothing to replace, so REPLACE and the old rule agree exactly there.
        auto rcU = simulate(DROP_BASE, iv, DROP_HASHES[0], K_CANON);
        std::vector<settle::HarvestedReceipt> hu{
            settle::HarvestedReceipt{key_of(DROP_BASE), iv, rcU}};
        const long long du = settle::subthreshold_credit_raw_PRE_RULING(p, hu).begin()->second;
        const long long eu = low63(sub::estimate_combined(rcU.shares(), K_CANON,
                                                          rcU.h_K()));
        check(rcU.shares() == 0, "the drop fixture really is UNCOVERED (S == 0)");
        check(du == eu, "an uncovered interval still credits the whole estimate: the "
                        "participation case DROPS exists for is unchanged");
    }

    // ── DROPS-NO-DOUBLE-COUNT: the ratio is ~1.0, not ~1.9 ───────────────
    // The headline assertion. Everything is measured against the TRUE hash count,
    // so 1.00 means "credited exactly the work performed". The shipped rule and
    // the rejected additive rule are driven on the SAME draws, so the gap between
    // them is the double count and nothing else.
    std::printf("\n-- DROPS-NO-DOUBLE-COUNT: composed ~1.0x the true work (not ~1.9x) --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        const sub::u256 hT = share_target();
        const std::uint64_t Hbig = 20 * T_SHARE;     // 81920 hashes, E[S] = 20
        const int TRIALS = 160;
        double composed = 0, added = 0, truework = 0;
        for (int t = 0; t < TRIALS; ++t) {
            const MinerId id = MinerId(88001 + t);
            Rng rng(0xD0Bull + (std::uint64_t)t * 2654435761ull);
            sub::ReceiptCollector rc(K_CANON, hT);
            for (std::uint64_t i = 0; i < Hbig; ++i) rc.observe(rng.hash());
            if (!rc.has_K()) continue;
            std::vector<settle::HarvestedReceipt> hv{
                settle::HarvestedReceipt{key_of(id), (u64)t, rc}};
            const auto c = settle::subthreshold_credit_raw_PRE_RULING(p, hv);
            const long long delta = c.empty() ? 0 : c.begin()->second;
            const long long wsh = low63(sub::share_covered_work(rc.shares(), hT));
            composed += (double)(wsh + delta);        // E_b part + REPLACE delta
            added    += (double)sub::broken_add_NEVER_CONSENSUS(
                rc.shares(), K_CANON, rc.h_K(), hT);  // the REJECTED rule
            truework += (double)Hbig;
        }
        const double rc_ratio  = composed / truework;
        const double add_ratio = added / truework;
        std::printf("   %d intervals x %llu hashes, fully share-covered (E[S]=20):\n"
                    "     SHIPPED  (replace) credit / true work = %.4f\n"
                    "     REJECTED (add)     credit / true work = %.4f\n",
                    TRIALS, (unsigned long long)Hbig, rc_ratio, add_ratio);
        check(rc_ratio > 0.85 && rc_ratio < 1.15,
              "★ NO DOUBLE COUNT: the shipped composition credits ~1.0x the work "
              "performed on a fully share-covered interval");
        check(add_ratio > 1.80 && add_ratio < 2.10,
              "★ and the rejected additive composition credits ~1.9x the SAME work "
              "on the SAME draws — the 1.92..2.01x this ruling removes");
        check(add_ratio > rc_ratio * 1.5,
              "the gap between the two rules is of order x2, so the fix is the "
              "difference between paying once and paying twice");
    }

    // ── DROPS-T1: the node lane factory, and the ridge coupling ──────────
    std::printf("\n-- DROPS-T1: the node lane factory (and what the flip couples) --\n");
    {
        // DEFAULT BUILD: the factory hands a live node the V37.0 base, so every
        // digest on a default build is master's. This is the assertion that lets
        // the T1 seam land without being a consensus change.
        const LaneParams def = ::c2pool::v37n::node_lane_params(LaneKind::BTC);
        const LaneParams bare{};
        check(!::c2pool::v37n::kActivateConsensusV1,
              "V37_ACTIVATE_CONSENSUS_V1 is OFF in this build (the shipped default)");
        check(!def.subthreshold.enabled, "T1 default: the DROPS gate is OFF");
        check(def.mrr.activation_pos == UINT64_MAX &&
              def.nr.nr_activation_pos == UINT64_MAX &&
              def.win.win_activation_pos == UINT64_MAX,
              "T1 default: the V37.1 ridge and the win law are OFF too");
        check(def.subthreshold.enabled == bare.subthreshold.enabled &&
              def.subthreshold.K == bare.subthreshold.K &&
              def.subthreshold.mode == bare.subthreshold.mode &&
              def.subthreshold.version == bare.subthreshold.version &&
              def.mrr.activation_pos == bare.mrr.activation_pos &&
              def.nr.nr_activation_pos == bare.nr.nr_activation_pos &&
              def.win.win_activation_pos == bare.win.win_activation_pos,
              "T1 default == LaneParams{} on every gate: a default build's node "
              "lane is the OQ-5 ratified default, byte for byte");
        const LaneParams no_kind = ::c2pool::v37n::node_lane_params_no_kind();
        check(!no_kind.subthreshold.enabled && no_kind.mrr.activation_pos == UINT64_MAX,
              "T1 default (XMR arm, no ratified LaneKind) is the same base");

        // ★ WHAT THE FLIP WOULD DO, stated as a fact and not taken. This is the
        // COUPLING the operator turnkey has to price in: ONE switch, TWO
        // consensus activations.
        const LaneParams on2 =
            LaneParams::for_version(SHIPPED_CONSENSUS_VERSION, LaneKind::BTC);
        const LaneParams on1 = LaneParams::for_version(SHIPPED_CONSENSUS_VERSION);
        std::printf("   for_version(1, BTC): drops=%s ridge_pos=%llu nr_pos=%llu\n"
                    "   for_version(1)     : drops=%s ridge_pos=%llu nr_pos=%llu\n",
                    on2.subthreshold.enabled ? "ON" : "off",
                    (unsigned long long)on2.mrr.activation_pos,
                    (unsigned long long)on2.nr.nr_activation_pos,
                    on1.subthreshold.enabled ? "ON" : "off",
                    (unsigned long long)on1.mrr.activation_pos,
                    (unsigned long long)on1.nr.nr_activation_pos);
        check(on2.subthreshold.enabled && on2.mrr.activation_pos == ACT_POS &&
              on2.nr.nr_activation_pos == ACT_POS,
              "★ COUPLING: the 2-argument factory turns on DROPS *and* the V37.1 "
              "native ridge at position 4096 in one act — they are NOT separable "
              "through it, and the turnkey must be taken as one flag day");
        check(on1.subthreshold.enabled && on1.mrr.activation_pos == UINT64_MAX,
              "the 1-argument factory is the ONLY way to take DROPS without the "
              "ridge (it names no parent LaneKind, so it carries no dimensions) — "
              "and it is what the XMR lane must use, ND-R6 being unruled");
        // ★ RULED: DECOUPLE. The recorded arity is 1 — the flip opens DROPS and
        // NOTHING else. Pinned here as a value, not as a preference, because it
        // is what a live node's geometry is built from: at arity 1 a shipped
        // node runs for_version(1) (DROPS on, ridge OFF), so the fleet's
        // owed_digest is NOT the GOLDEN_DROPS_ON value this KAT mints over
        // for_version(1, LaneKind). That golden pins the CANON ACTIVATION
        // SCHEDULE and the composition rule — which is what it is for — and the
        // assertions above are written against the two-argument geometry
        // explicitly, so they are invariant to this constant. Changing the arity
        // is a separate operator ruling and a separate flag day; this check is
        // what makes such a change impossible to take by accident.
        check(::c2pool::v37n::kActivationArity == 1,
              "★ the recorded arity for the flip is 1 (DROPS ALONE; the V37.1 "
              "ridge stays a separately ruled flag day)");
    }

    // ── DROPS-T2: the W2 sub-target harvest ──────────────────────────────
    std::printf("\n-- DROPS-T2: W2 admits raindrops for MEASUREMENT ONLY --\n");
    {
        using namespace ::c2pool::v37n;
        struct Idx : IMainchainIndex {
            std::map<bytes32, u64> h;
            std::optional<u64> height_of(const bytes32& p) const override {
                auto it = h.find(p);
                return it == h.end() ? std::nullopt : std::optional<u64>(it->second);
            }
        };
        struct Trk : IShareTracker {
            bool has_prev_own(const bytes32&, const bytes32&) const override { return true; }
            void record_share(const bytes32&, const bytes32&) override {}
        };
        const u64 BIN = 4;
        const unsigned CLZ = consensus_lz(BIN);
        bytes32 prev{}; prev[0] = 0xAB;
        Idx idx; idx.h[prev] = BIN;
        Trk trk;

        // Mine a carrier at the consensus target and a receipt at a STRICTLY
        // WEAKER target (a raindrop), by grinding the nonce.
        auto grind = [&](unsigned lz, u64 salt) {
            WorkEvent e{};
            e.chain_id = 7;
            e.identity = key_of(4242);
            e.prev_block_hash = prev;
            e.prev_own_share = W2_GENESIS_PREV_OWN;
            e.lz_bits = lz;
            e.tag = "t" + std::to_string(salt) + "_" + std::to_string(lz);
            for (u64 n = salt * 1000003ull; ; ++n) {
                e.nonce = n;
                if (e.meets_own_target()) return e;
            }
        };
        const WorkEvent carrier = grind(CLZ, 1);
        const WorkEvent drop    = grind(CLZ > 0 ? CLZ - 1 : 0, 2);
        check(drop.lz_bits < CLZ, "the fixture receipt really is SUB-TARGET");

        // (a) HARVEST OFF — the master behaviour, unchanged.
        {
            Trk t2; ReceiptAdmitter adm(7, idx, t2, 1);
            auto r = adm.admit(carrier, {drop});
            check(r.carrier_status == CarrierStatus::OK, "T2 off: the carrier admits");
            check(r.receipts.size() == 1 &&
                  r.receipts[0].second == Disposition::REJECT_R1_TARGET,
                  "T2 OFF: a sub-target receipt is REJECT_R1_TARGET, exactly as on "
                  "master — the harvest changes nothing until it is armed");
            check(r.drops == 0 && r.pushes.size() == 1,
                  "T2 off: no drops, and only the carrier pushed");
        }
        // (b) HARVEST ON — admitted for measurement, and NOT pushed.
        {
            Trk t2; ReceiptAdmitter adm(7, idx, t2, 1);
            std::vector<HarvestedDrop> got;
            adm.set_drop_harvest(true, [&](const HarvestedDrop& d) { got.push_back(d); });
            auto r = adm.admit(carrier, {drop});
            check(r.receipts.size() == 1 &&
                  r.receipts[0].second == Disposition::OK_SUBTARGET_DROP,
                  "T2 ON: the sub-target receipt is admitted as a raindrop");
            check(r.drops == 1 && got.size() == 1, "T2 ON: it reaches the sink");
            check(r.pushes.size() == 1,
                  "★ T2 ON: it emits NO push — only the carrier is pushed, so a "
                  "raindrop can never inflate the sharechain or move a position");
            check(r.pushes[0].w_raw == carrier.work(),
                  "and the lane's raw work is the carrier's alone");
            check(got[0].payee == carrier.identity && got[0].interval == BIN &&
                  got[0].consensus_lz == CLZ,
                  "the harvested row carries the self-carriage payee, the ORIGIN "
                  "bin (the F1 interval) and the bin's consensus target");
            // a replayed raindrop is deduped by the window like any event
            auto r2 = adm.admit(carrier, {drop});
            check(r2.carrier_status == CarrierStatus::REJECT_DEDUP,
                  "a replayed carrier is refused, so its raindrops cannot be "
                  "re-measured");
            check(got.size() == 1, "and nothing further reached the sink");
        }
        // (c) a raindrop that fails a BINDING check is still rejected on that
        //     ground: measuring unbound work would be free hashrate.
        {
            Trk t2; ReceiptAdmitter adm(7, idx, t2, 1);
            std::vector<HarvestedDrop> got;
            adm.set_drop_harvest(true, [&](const HarvestedDrop& d) { got.push_back(d); });
            WorkEvent foreign = drop;
            foreign.identity = key_of(9999);        // not the carrier's identity
            foreign.nonce = 0;
            for (u64 n = 77; ; ++n) { foreign.nonce = n; if (foreign.meets_own_target()) break; }
            auto r = adm.admit(carrier, {foreign});
            check(r.receipts[0].second == Disposition::REJECT_IDENTITY,
                  "★ a raindrop with a foreign payout identity is REJECT_IDENTITY, "
                  "not a raindrop: the harvest relaxes the TARGET check and nothing "
                  "else");
            check(got.empty() && r.drops == 0, "and it never reaches the estimator");
        }
        // (d) the harvester turns raindrops into W4 harvest rows, F1-gated.
        {
            DropHarvester h(K_CANON);
            HarvestedDrop d{};
            d.payee = key_of(4242); d.interval = BIN; d.consensus_lz = CLZ;
            for (int i = 0; i < 8; ++i) {
                d.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&i),
                                        sizeof i);
                h.observe(d);
            }
            check(h.open_intervals() == 1, "one (payee, interval) collector");
            check(h.take_buried(BIN).empty(),
                  "★ F1: an interval AT the frontier is not yet buried and is NOT "
                  "released");
            check(!h.shares_declared(key_of(4242), BIN),
                  "the interval's share count has not been declared yet");
            h.declare_shares(key_of(4242), BIN, /*S=*/0, CLZ);
            check(h.shares_declared(key_of(4242), BIN), "and now it has");
            auto rows = h.take_buried(BIN + 1);
            check(rows.size() == 1 && rows[0].interval == BIN,
                  "once buried AND declared it is released as a W4 harvest row");
            check(rows[0].collector.shares() == 0,
                  "carrying the DECLARED share count, not a guessed one");
            check(h.take_buried(BIN + 1).empty(),
                  "and it is CONSUMED: the same interval can never be folded twice");
            d.interval = BIN;
            h.observe(d);
            check(h.late_discarded() == 1,
                  "a raindrop for an already-released interval is discarded, not "
                  "folded into a second credit");
        }
        // (e) ★ FAIL-CLOSED: an interval whose share count was never declared is
        //     WITHHELD. This is the back door the double count would otherwise
        //     come back through — W2 accounts shares on the PUSH path, so a
        //     collector that only saw raindrops has S == 0, and at a realistic
        //     share target (K-1)*D_K over that stream still estimates the
        //     payee's WHOLE interval. Crediting that on top of an intact E_b row
        //     is exactly the x2 this PR removes.
        {
            DropHarvester h(K_CANON);
            HarvestedDrop d{};
            d.payee = key_of(4243); d.interval = BIN; d.consensus_lz = CLZ;
            for (int i = 0; i < 8; ++i) {
                d.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&i),
                                        sizeof i);
                h.observe(d);
            }
            auto rows = h.take_buried(BIN + 1);
            check(rows.empty(),
                  "★ an UNDECLARED interval is NEVER released to the estimator: "
                  "crediting nothing we cannot account is the conservative error, "
                  "crediting it as if the payee held no shares is the double count");
            check(h.undeclared_withheld() == 1,
                  "and it is COUNTED, so an operator sees the wiring gap instead of "
                  "the node quietly over-crediting");
            check(h.open_intervals() == 0, "the withheld interval is not retained");

            // A DECLARED covered interval releases with its real S, which is what
            // makes the REPLACE subtraction correct downstream.
            DropHarvester h2(K_CANON);
            d.payee = key_of(4244);
            for (int i = 0; i < 8; ++i) {
                d.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&i),
                                        sizeof i);
                h2.observe(d);
            }
            h2.declare_shares(key_of(4244), BIN, /*S=*/7, CLZ);
            auto rows2 = h2.take_buried(BIN + 1);
            check(rows2.size() == 1 && rows2[0].collector.shares() == 7,
                  "a declared covered interval carries its real S, so the REPLACE "
                  "composition removes the right W_shares downstream");
        }
    }

    // ── DROPS-T3: the estimate-into-fold point ───────────────────────────
    std::printf("\n-- DROPS-T3: the fold composes REPLACE and PERSISTS the result --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        const u64 iv = 700;
        auto rc = simulate(DROP_BASE + 1, iv, DROP_HASHES[1], K_CANON);
        std::vector<settle::HarvestedReceipt> hv{
            settle::HarvestedReceipt{key_of(DROP_BASE + 1), iv, rc}};
        settle::OwedLedger::Amounts base;
        base[key_of(1)] = 1000;

        // the composition helper is the single source of the composed map
        const auto composed = settle::compose_credit_replace_raw_PRE_RULING(p, base, hv);
        const auto delta    = settle::subthreshold_credit_raw_PRE_RULING(p, hv);
        check(composed.size() == base.size() + delta.size(),
              "T3: the composed map is E_b plus the harvested payees");
        check(composed.at(key_of(1)) == 1000,
              "an unharvested payee's E_b row is untouched");
        check(composed.at(key_of(DROP_BASE + 1)) == delta.begin()->second,
              "a harvested payee with no E_b row is credited the delta alone");

        // GATE OFF => the helper returns base_credit ITSELF, byte for byte.
        const LaneParams off{};
        const auto none = settle::compose_credit_replace_raw_PRE_RULING(off, base, hv);
        check(none == base,
              "★ T3 gate OFF: compose_credit_replace returns base_credit itself — "
              "the seam is inert on a default node, which is why wiring it moves "
              "no digest");

        // the driver seam agrees with the ledger seam
        settle::OwedLedger l1(7), l2(7);
        l1.on_block_found_estimator_raw_PRE_RULING("b", base, {}, p, hv);
        l2.on_block_found("b", composed, {});
        // finalize at the bin the F1 driver would stamp: found_height + D_conf.
        l1.on_block_finalized("b", iv + 2);
        l2.on_block_finalized("b", iv + 2);
        check(l1.owed_digest() == l2.owed_digest(),
              "T3: on_block_found_with_estimator == on_block_found(composed) — one "
              "composition, no second merge hiding anywhere");

        // ★ and the FinalizeDriver carries the RULED composition end to end.
        // The context is mandatory here: a candidate with a harvest but no price
        // and no enrolment book composes NOTHING, which is the fail-closed shape
        // and is asserted separately below.
        ::c2pool::v37n::EnrollmentBook enroll_t3;
        enroll_t3.commit(key_of(DROP_BASE + 1), 0, 1);
        auto idv_t3 = std::make_shared<FakeIdView>();
        idv_t3->m[1] = ::v37::IdentityEntry{key_of(1), ::v37::ScriptRef{}};
        FakeView v_t3;
        v_t3.payout[1] = ::v37::U256::from_u128(((::v37::u128)1000000) << 62);
        v_t3.identities = idv_t3;
        settle::DropsCompose ctx_t3;
        ctx_t3.price      = settle::work_price_at(REWARD, v_t3);
        ctx_t3.enrollment = &enroll_t3;

        settle::OwedLedger lr(7);
        lr.on_block_found_with_drops("b", base, {}, p, hv, ctx_t3);
        lr.on_block_finalized("b", iv + 2);

        settle::OwedLedger l3(7);
        settle::SettleHW hw3{};
        settle::FinalizeDriver drv(l3, hw3, 7, 2);
        settle::FinalizeCandidate c;
        c.bid = "b"; c.found_height = iv; c.credit = base; c.params = p; c.harvested = hv;
        c.drops = ctx_t3;
        drv.register_found(c);
        drv.advance_to(iv + 2);
        check(l3.owed_digest() == lr.owed_digest(),
              "T3: FinalizeDriver::register_found composes the same ledger as the "
              "RULED seam — the driver is wired, not decorative");
        check(!lr.owed_digest().empty() && l3.owed_digest() != l1.owed_digest(),
              "and the RULED composition is NOT the pre-ruling one (non-vacuous)");

        // ★ R3: the CARRIED-DELTA path folds a map that was composed elsewhere,
        // and lands on the same ledger as composing it here. This is the peer
        // path's arithmetic, isolated from the node and the wire.
        {
            const auto delta_r = settle::subthreshold_credit(p, hv, ctx_t3);
            settle::OwedLedger lc(7);
            lc.on_block_found_with_carried_drops("b", base, {}, delta_r);
            lc.on_block_finalized("b", iv + 2);
            check(lc.owed_digest() == lr.owed_digest(),
                  "★ R3: folding the WINNER'S composed map reproduces the winner's "
                  "own ledger exactly — which is why a peer may take it verbatim");
            settle::OwedLedger ld(7);
            settle::SettleHW hwd{};
            settle::FinalizeDriver drvd(ld, hwd, 7, 2);
            settle::FinalizeCandidate cd;
            cd.bid = "b"; cd.found_height = iv; cd.credit = base;
            cd.has_carried_drops = true; cd.carried_drops = delta_r;
            drvd.register_found(cd);
            drvd.advance_to(iv + 2);
            check(ld.owed_digest() == lr.owed_digest(),
                  "R3: and the driver's carried-delta branch does the same");
        }

        // ★ FAIL-CLOSED: a harvest with NO context composes NOTHING.
        {
            settle::OwedLedger lz(7);
            settle::FinalizeCandidate cz;
            settle::SettleHW hwz{};
            settle::FinalizeDriver drvz(lz, hwz, 7, 2);
            cz.bid = "b"; cz.found_height = iv; cz.credit = base;
            cz.params = p; cz.harvested = hv;          // no price, no enrolment book
            drvz.register_found(cz);
            drvz.advance_to(iv + 2);
            settle::OwedLedger lb(7);
            lb.on_block_found("b", base, {});
            lb.on_block_finalized("b", iv + 2);
            check(lz.owed_digest() == lb.owed_digest(),
                  "★ a harvest with no price and no enrolment book credits NOTHING — "
                  "the seam fails closed rather than guessing either ruling");
        }

        // inert by default through the driver too
        settle::OwedLedger l4(7), l5(7);
        settle::SettleHW hw4{}, hw5{};
        settle::FinalizeDriver d4(l4, hw4, 7, 2), d5(l5, hw5, 7, 2);
        settle::FinalizeCandidate c4;           // default params/harvest: inert
        c4.bid = "b"; c4.found_height = iv; c4.credit = base;
        d4.register_found(c4); d4.advance_to(iv + 2);
        l5.on_block_found("b", base, {}); l5.on_block_finalized("b", iv + 2);
        check(l4.owed_digest() == l5.owed_digest(),
              "★ T3 default: a FinalizeCandidate with no harvest settles exactly "
              "the master ledger");
    }

    // ── DROPS-ENROL (★ R-SYBIL): the SELECTIVE opt-in is CLOSED ──────────
    // THE ATTACK. The replace delta Hhat_comb - W_shares is SIGNED and correct,
    // but a payee that can decide PER INTERVAL, after the draw, whether to take
    // it keeps only the upside. Splitting hashrate multiplies the number of
    // independent draws, so the gain RISES with the identity count: the verify
    // pass measured 1.02 / 1.08 / 1.30 / 1.84 / 1.96x at n = 1 / 4 / 20 / 200 /
    // 2000 against an unconditional ~0.93..0.97x that is FLAT in n.
    //
    // THE RULING. Participation is committed EX ANTE, once, digest-bound, for an
    // interval strictly later than the one the commitment is made in. Enrolled
    // means composed ALWAYS — including J < K (Hhat == 0) and including a
    // NEGATIVE delta. Not enrolled means DROPS does not apply at all.
    //
    // WHAT THIS SECTION PROVES. The selective curve is computed here from the
    // estimator arithmetic DIRECTLY, because it has no expression in the
    // codebase to drive it through — and the curve the SHIPPED SEAM produces,
    // with the same draws and the same identities, is the unconditional one:
    // flat in n, and strictly below the selective curve at every split.
    std::printf("\n-- DROPS-ENROL: ex-ante enrolment flattens the selective curve --\n");
    {
        const LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
        // ★ THE TARGET MATTERS, AND IT IS CHOSEN TO BE REALISTIC, NOT KIND.
        // T = 256 (h_T = 2^248 - 1): at a 2000-way split each identity lands
        // about ONE share per interval, which is the regime a real small miner is
        // in and the regime in which the per-interval estimate has the variance a
        // selective attacker feeds on. At the mint's much harder target a 2000-way
        // split leaves almost every identity with S == 0 and nothing to replace,
        // and at a much weaker one the censoring at h_T damps the variance away —
        // both would understate the attack. This is the honest middle.
        sub::u256 hT;
        for (unsigned b = 0; b < 248; ++b) hT.w[b >> 6] |= (1ull << (b & 63));
        const std::uint64_t H_TOTAL = 512000;          // hashes the attacker owns
        const u64 IV = 4242;

        // ONE price for every arm, so the arms are comparable: the denominator is
        // the attacker's own work in the lane's Q62 units, i.e. it owns the lane.
        settle::WorkPrice price;
        price.reward     = REWARD;
        price.sum_weight = ::v37::U256::from_u128(((::v37::u128)H_TOTAL) << 62);
        price.valid      = true;
        sub::u320 h_true{};
        h_true.w[0] = H_TOTAL;
        const long long ent_true = settle::entitlement_of_work(price, h_true);
        check(ent_true > 0, "ENROL: the true-work entitlement is expressible");

        const unsigned NS = 5;
        const unsigned NN[NS] = {1, 4, 20, 200, 2000};
        double sel_r[NS] = {0, 0, 0, 0, 0}, enr_r[NS] = {0, 0, 0, 0, 0},
               off_r[NS] = {0, 0, 0, 0, 0};
        bool downside_taken = false;
        std::printf("   n        per-identity   SELECTIVE (opt in iff Hhat > S*T)   "
                    "ENROLLED (the shipped seam)   NOT ENROLLED\n");
        for (unsigned si = 0; si < NS; ++si) {
            const unsigned n   = NN[si];
            const std::uint64_t per = H_TOTAL / n;
            ::c2pool::v37n::EnrollmentBook book;
            std::vector<settle::HarvestedReceipt> hv;
            hv.reserve(n);
            long long sel = 0, cov_sum = 0;
            std::size_t would_opt_out = 0;
            std::map<bytes32, long long> cov_of;
            for (unsigned k = 0; k < n; ++k) {
                const MinerId id = MinerId(900001 + k);
                sub::ReceiptCollector rc(K_CANON, hT);
                Rng r(0xE47011EEull ^ (std::uint64_t(k) * 0x9E3779B97F4A7C15ull) ^
                      (std::uint64_t(n) * 0xBF58476D1CE4E5B9ull));
                for (std::uint64_t h = 0; h < per; ++h) rc.observe(r.hash());
                const sub::u320 est = rc.has_K()
                    ? sub::estimate_combined(rc.shares(), K_CANON, rc.h_K())
                    : sub::u320{};
                const sub::u320 cov = sub::share_covered_work(rc.shares(),
                                                              rc.target_hash());
                const long long e_est = settle::entitlement_of_work(price, est);
                const long long e_cov = settle::entitlement_of_work(price, cov);
                // the SELECTIVE rule, computed straight off the arithmetic — it
                // has no code path to be driven through, which is the point
                sel     += (e_est > e_cov) ? e_est : e_cov;
                if (e_est <= e_cov) ++would_opt_out;
                cov_sum += e_cov;
                cov_of[key_of(id)] = e_cov;
                // EX ANTE: committed at interval 0, effective at 1, and the
                // harvest is interval 4242 — the commitment cannot see the draw.
                book.commit(key_of(id), 0, 1);
                hv.push_back(settle::HarvestedReceipt{key_of(id), IV, rc});
            }
            // the SHIPPED seam, all enrolled
            settle::DropsCompose ctx_on;
            ctx_on.price = price;
            ctx_on.enrollment = &book;
            const auto d_on = settle::subthreshold_credit(p, hv, ctx_on);
            long long enr = cov_sum;
            for (const auto& [k, v] : d_on) {
                enr += v;
                if (v < 0 && cov_of.count(k)) downside_taken = true;
            }
            // the SHIPPED seam, NOBODY enrolled
            settle::DropsCompose ctx_off;
            ctx_off.price = price;            // no book at all
            const auto d_off = settle::subthreshold_credit(p, hv, ctx_off);
            check(d_off.empty(),
                  "★ a NON-ENROLLED identity is credited NOTHING: DROPS does not "
                  "apply to it, so it keeps its ordinary S*T entitlement whole");
            long long off = cov_sum;
            for (const auto& [k, v] : d_off) { (void)k; off += v; }

            sel_r[si] = (double)sel / (double)ent_true;
            enr_r[si] = (double)enr / (double)ent_true;
            off_r[si] = (double)off / (double)ent_true;
            std::printf("   %-8u %-14llu %-35.4f %-29.4f %.4f   (%zu/%u would have "
                        "opted OUT)\n",
                        n, (unsigned long long)per, sel_r[si], enr_r[si], off_r[si],
                        would_opt_out, n);
        }
        check(downside_taken,
              "★ the enrolled arm really does carry NEGATIVE rows: the identities a "
              "selective attacker would have opted out of are composed anyway");
        // the attack was real...
        check(sel_r[NS - 1] > sel_r[0] + 0.15,
              "the SELECTIVE curve RISES with the identity count — splitting buys a "
              "real gain, so this is not a straw man");
        check(sel_r[NS - 1] > 1.15,
              "and at a 2000-way split it recovers well over 1.15x the work performed");
        // ...and enrolment flattens it
        double lo = enr_r[0], hi = enr_r[0];
        for (unsigned si = 0; si < NS; ++si) {
            if (enr_r[si] < lo) lo = enr_r[si];
            if (enr_r[si] > hi) hi = enr_r[si];
            check(enr_r[si] > 0.80 && enr_r[si] < 1.15,
                  "★ ENROLLED: the shipped curve sits on the unconditional value at "
                  "EVERY split — no gain from splitting");
            check(enr_r[si] < sel_r[si] + 1e-9,
                  "★ and it is never above the selective curve: the choice the "
                  "attack needs is not expressible");
        }
        std::printf("   enrolled curve span over n = 1..2000: %.4f .. %.4f "
                    "(selective span %.4f .. %.4f)\n", lo, hi, sel_r[0], sel_r[NS - 1]);
        check(hi - lo < 0.15,
              "★ FLAT IN n: the enrolled curve's whole span across a 2000x split is "
              "smaller than the gain the selective rule buys — the sybil surface the "
              "signed delta opened is CLOSED");
        check(sel_r[NS - 1] - enr_r[NS - 1] > 0.15,
              "★ and at the worst split the two rules are far apart, so the KAT goes "
              "red the moment a per-interval choice is reintroduced");

        // ── the EX-ANTE rule itself, at the only entry point ──────────────
        {
            ::c2pool::v37n::EnrollmentBook b;
            const bytes32 who = key_of(123456);
            check(!b.commit(who, /*now=*/100, /*effective_from=*/100),
                  "★ 'enrol me starting now' is REFUSED: that is the choice made "
                  "after the draw");
            check(!b.commit(who, /*now=*/100, /*effective_from=*/99),
                  "★ and back-dating is refused too");
            check(b.refused() == 2 && b.size() == 0, "both refusals are counted");
            check(b.commit(who, /*now=*/100, /*effective_from=*/101),
                  "a commitment for a STRICTLY LATER interval is accepted");
            check(!b.enrolled(who, 100) && b.enrolled(who, 101) && b.enrolled(who, 4242),
                  "and it binds from that interval onwards, never before");
            check(!b.enrolled(key_of(7654321), 4242),
                  "an identity that never committed is never enrolled");
            const ::v37::bytes32 d1 = b.book_digest();
            ::c2pool::v37n::EnrollmentBook b2;
            b2.commit(who, 100, 101);
            check(b2.book_digest() == d1,
                  "the book digest is a pure function of the commitments (two nodes "
                  "told the same things agree)");
            b2.commit(key_of(999), 100, 101);
            check(!(b2.book_digest() == d1),
                  "and it moves when the set does — the witness is not vacuous");
            check(!(::c2pool::v37n::empty_enrollment_digest() == d1),
                  "the empty-book digest is distinct from a populated one");
            check(b.find(who) != nullptr &&
                  b.find(who)->commit ==
                      ::c2pool::v37n::enrollment_commit(who, 101),
                  "the record carries the domain-separated commitment it was made under");
        }
    }

    // ── DROPS-PRODUCER: declare_shares is DRIVEN, not just declared ──────
    // The verify pass's finding: declare_shares(payee, interval, S, lz) is
    // mandatory and fail-closed, and had NO producer in the tree — IShareTracker
    // exposes has_prev_own/record_share and nothing counts per (payee, bin). So
    // on a live node every harvested interval was withheld and DROPS, though
    // reachable, could never credit. ShareCountBook is that producer, fed from
    // the W2 emit stream (the carrier and every ACCEPTED receipt), which is where
    // W2 already accounts a share.
    std::printf("\n-- DROPS-PRODUCER: a real per-(payee, interval) share counter --\n");
    {
        using ::c2pool::v37n::ShareCountBook;
        using ::c2pool::v37n::DropHarvester;
        using ::c2pool::v37n::EmittedPush;
        const unsigned CLZ = 8;
        const u64 BIN = 300;
        const bytes32 A = key_of(5101), B = key_of(5102), C = key_of(5103);

        ShareCountBook book;
        check(book.count(A, BIN) == 0 && !book.armed(),
              "an unarmed book knows nothing and says so");
        // an UNARMED book drops pushes rather than pretending to have seen them
        EmittedPush e{}; e.identity = A; e.origin_bin = BIN;
        book.on_push(e);
        check(book.unarmed_dropped() == 1 && book.count(A, BIN) == 0,
              "★ an unarmed book counts NOTHING: 'not attached yet' is not 'zero'");

        book.arm(BIN);
        for (int i = 0; i < 5; ++i) book.on_push(e);        // A: 5 shares in BIN
        EmittedPush e2{}; e2.identity = B; e2.origin_bin = BIN;
        for (int i = 0; i < 2; ++i) book.on_push(e2);       // B: 2 shares in BIN
        EmittedPush e3{}; e3.identity = A; e3.origin_bin = BIN - 1;
        book.on_push(e3);                                   // BEFORE the arm point
        check(book.count(A, BIN) == 5 && book.count(B, BIN) == 2,
              "the producer counts one share per EmittedPush, keyed (payee, origin_bin)");
        check(book.pre_arm_dropped() == 1 && book.count(A, BIN - 1) == 0,
              "★ and it refuses to speak for an interval older than its arm point");
        check(!book.covers(BIN - 1) && book.covers(BIN),
              "covers() is the fail-closed frontier");

        // the tee: the engine sink still sees every push, in order, unchanged
        {
            ShareCountBook t;
            t.arm(0);
            std::vector<std::uint64_t> seen;
            auto sink = t.tee([&](const EmittedPush& p) { seen.push_back(p.pos); });
            EmittedPush x{}; x.identity = C;
            for (std::uint64_t i = 0; i < 4; ++i) { x.pos = i; x.origin_bin = 7; sink(x); }
            check(seen.size() == 4 && seen[0] == 0 && seen[3] == 3,
                  "tee() forwards every push to the engine sink, in order");
            check(t.count(C, 7) == 4, "and counts them on the way past");
        }

        // ── the whole producer -> harvester -> credit chain ───────────────
        DropHarvester h(K_CANON);
        ::c2pool::v37n::HarvestedDrop d{};
        d.interval = BIN; d.consensus_lz = CLZ;
        for (int who = 0; who < 2; ++who) {
            d.payee = who ? B : A;
            for (int i = 0; i < 8; ++i) {
                const int seed = i + 100 * who;
                d.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&seed),
                                        sizeof seed);
                h.observe(d);
            }
        }
        check(h.open_keys().size() == 2, "the harvester holds both payees' intervals");
        ::c2pool::v37n::EnrollmentBook enr;
        enr.commit(A, 0, 1);
        enr.commit(C, 0, 1);                 // C: enrolled, shares but NO raindrops
        EmittedPush e4{}; e4.identity = C; e4.origin_bin = BIN;
        for (int i = 0; i < 3; ++i) book.on_push(e4);
        const std::uint64_t cA = book.count(A, BIN), cB = book.count(B, BIN),
                            cC = book.count(C, BIN);
        const std::size_t declared =
            book.declare_into(h, BIN + 1, [](u64) { return CLZ; }, &enr);
        check(declared == 3,
              "★ declare_into declares BOTH harvested intervals AND synthesises the "
              "enrolled payee that had shares but no raindrops");
        check(h.shares_declared(A, BIN) && h.shares_declared(B, BIN) &&
              h.shares_declared(C, BIN),
              "every one of them is now DECLARED, so none is withheld");
        auto rows = h.take_buried(BIN + 1);
        check(rows.size() == 3 && h.undeclared_withheld() == 0,
              "and all three are released with an explicit S");
        std::size_t sA = 0;
        for (const auto& r : rows) if (r.payee == A) sA = (std::size_t)r.collector.shares();
        check(sA == 5, "the released interval carries the S the PRODUCER counted");
        std::printf("   producer: A=%llu shares, B=%llu, C=%llu (C had no raindrops "
                    "and is enrolled, so its interval is composed anyway)\n",
                    (unsigned long long)cA, (unsigned long long)cB,
                    (unsigned long long)cC);
        check(cA == 5 && cB == 2 && cC == 3, "the counts are the ones fed in");
        check(book.rows() == 0,
              "and declare_into FORGETS the settled rows, so the index does not grow "
              "without bound");

        // FAIL-CLOSED, end to end: an interval the book does not cover is
        // withheld by the harvester, exactly as before the producer existed.
        {
            DropHarvester h2(K_CANON);
            ShareCountBook late;
            late.arm(BIN + 10);                     // attached far too late
            ::c2pool::v37n::HarvestedDrop d2{};
            d2.payee = A; d2.interval = BIN; d2.consensus_lz = CLZ;
            for (int i = 0; i < 8; ++i) {
                d2.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&i),
                                         sizeof i);
                h2.observe(d2);
            }
            late.declare_into(h2, BIN + 1, [](u64) { return CLZ; }, &enr);
            check(!h2.shares_declared(A, BIN), "an uncovered interval is NOT declared");
            check(h2.take_buried(BIN + 1).empty() && h2.undeclared_withheld() == 1,
                  "★ and the harvester withholds it — 'unknown' still credits nothing");
        }
    }

    std::printf("\n== v37_drops_activation_kat: %ld checks, %ld failures -> %s\n",
                g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    std::printf("drops_gate_on_owed_digest=%s\n", hex(a3[0].owed).c_str());
    std::printf("drops_gate_on_combined=%s\n", hex32(comb).c_str());
    std::printf("v371_ridge_anchor=%s\n", hex(a1[0].owed).c_str());
    std::printf("pre_v371_anchor=%s\n", hex(a0[0].owed).c_str());
    return g_fail ? 1 : 0;
}
