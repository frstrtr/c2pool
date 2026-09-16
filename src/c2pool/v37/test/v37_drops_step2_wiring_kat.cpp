// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_drops_step2_wiring_kat — DROPS STEP 2: the live shell wiring, and the one
// property the seams cannot enforce for themselves.
//
// WHAT STEP 2 IS. The DROPS package (c2pool#1627) landed four consumer seams and
// a verified gate-ON mint, and NO LIVE SHELL CALLED THEM. main_v37_btc_dash.cpp
// constructed no DropHarvester, no EnrollmentBook and no ShareCountBook, and
// never called set_drop_harvest / set_drop_harvester / set_pre_harvest /
// set_enrollment_book; xmr_node.hpp had no T3 hook at all. So after the operator
// flip every node would have been gate-ON and DORMANT — converging with its
// peers and crediting NOBODY, for ever. v37_drops_wiring.hpp is those four calls
// in one object; this KAT is the proof that the object drives them and that it
// closes the residual the seams left open.
//
// ★★ THE RESIDUAL THIS KAT EXISTS FOR: now_interval.
//
// EnrollmentBook::commit(payee, now_interval, effective_from) enforces the
// ex-ante rule — effective_from strictly greater than now_interval — but
// `now_interval` IS SUPPLIED BY THE CALLER, so the rule is only as strong as the
// caller's clock. A shell that passed a STALE now (the obvious mistake being the
// BURIAL FRONTIER, which lags the tip by D_conf and is the other interval number
// the same wiring handles) would let a payee commit, at time t, to intervals it
// has ALREADY DRAWN AND SEEN — restoring exactly the per-interval selective
// choice R-SYBIL removed, and worth 1.32x at a 2000-way identity split.
//
// The fix is not a runtime check. DropsWiring keeps the book PRIVATE, publishes
// it CONST, and its only enrolment entry point — enroll_at_tip(payee) — HAS NO
// INTERVAL PARAMETER. Case W-STALE pins that structurally (the member signatures
// are static_asserted) and then MEASURES what the unreachable door was worth, so
// the assertion is not vacuous.
//
// WHAT IS PROVEN HERE
//   W-DORMANT   GATE OFF is the shipped default and is byte-identical to master:
//               make_drops_wiring() is nullopt, so the shell constructs nothing;
//               and a fold handed a FULL harvest, a valid price and a populated
//               enrolment book under LaneParams{} lands on the SAME owed_digest
//               as a fold handed no harvest at all — non-vacuously, since the
//               same harvest under the gate-ON geometry moves it.
//   W-ARITY     kActivationArity is 1 (RULED: DECOUPLE), and the geometry a
//               live arity-1 node builds — for_version(1) — IS ratified by W4,
//               carries the DROPS gate, and leaves the V37.1 ridge OFF. Without
//               that pin the arity-1 flip would refuse every fold and DROPS
//               would be dormant for a second, quieter reason.
//   W-TIP       now_interval comes from the chain TIP, is monotone across a
//               reorg, is UNKNOWN before the first tip (and enrolment is then
//               REFUSED rather than back-dated to genesis), and the enrolment it
//               records is committed_at == tip, effective_from == tip + 1.
//   W-STALE     the stale-now call is not expressible through the bundle
//               (signature pins + the frontier door provably cannot reach
//               commit), and the door it closes is measured on real draws.
//   W-E2E       the full path, end to end, on the REAL objects: raindrops
//               harvested by the REAL W2 ReceiptAdmitter through the wiring's
//               DropSink -> shares counted by the REAL ShareCountBook teed onto
//               the REAL emit stream -> declare_into at the burial frontier ->
//               take_buried -> subthreshold_credit under the REAL price and the
//               REAL ex-ante book -> OwedLedger fold -> owed_digest MOVES. And
//               the four payee shapes a live lane actually produces: drop-only
//               (positive), covered (replace), enrolled-but-silent (the
//               synthesised row that stops a payee dodging a bad interval by
//               withholding its raindrops), and NOT enrolled (nothing at all).
//   W-LOCK      a liveness + counter-consistency smoke over the wiring's own
//               lock, since Step 2 is what first makes these objects reachable
//               from three threads at once. It is a smoke, not a race proof.
//
// WHAT IS NOT PROVEN HERE, STATED PLAINLY. This KAT does not compile
// main_v37_btc_dash.cpp (a heavy-link TU with a main()). It proves the WIRING
// OBJECT the shell calls. The shell's own use of it is a four-line call site
// that is reviewed, not executed, here; what makes that safe is that the object
// leaves the shell no second way to do it wrong.
//
// BUILD (standalone; nothing in the tree is written):
//   g++-15 -std=c++20 -O2 -Wall -Wextra -I<repo>/src
//       v37_drops_step2_wiring_kat.cpp -o v37_drops_step2_wiring_kat
//
// HOLLOW-GREEN GUARD: registered with add_test() in
// src/c2pool/v37/test/CMakeLists.txt AND listed on BOTH build.yml
// `cmake --build --target` allowlists (the Linux x86_64 leg and the ASan+UBSan
// leg), so CI compiles and RUNS it instead of registering a NOT_BUILT CTest
// sentinel (the c2pool#1539 unregistered-KAT class).
//
// Exit status 0 = all checks pass; 1 = at least one check failed.
// ===========================================================================
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <c2pool/v37/v37_drops_wiring.hpp>          // ★ the Step-2 object
#include <c2pool/v37/v37_node_lane_activation.hpp>  // T1 seam, kActivationArity
#include <c2pool/v37/w2_admission.hpp>              // ReceiptAdmitter (T2)
#include <c2pool/v37/w2_receipt.hpp>                // WorkEvent, consensus_lz
#include <c2pool/v37/w4_settlement.hpp>             // fold_eb, OwedLedger (T3)

namespace n37   = ::c2pool::v37n;
namespace settle = ::c2pool::v37n::settle;
namespace sub    = ::c2pool::v37::subthreshold;
using ::v37::bytes32;
using ::v37::LaneKind;
using ::v37::LaneParams;
using ::v37::MinerId;
using ::v37::U256;
using ::v37::u64;

// ── the anchor that must not move ────────────────────────────────────────────
static const char* ANCHOR_OWED_EMPTY =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

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

// The identity resolver. The SAME function feeds the lane push, the settlement
// view and the harvest, which is what makes all three agree on payee keys.
static bytes32 key_of(MinerId m) {
    std::uint8_t b[4] = {std::uint8_t(m), std::uint8_t(m >> 8),
                         std::uint8_t(m >> 16), std::uint8_t(m >> 24)};
    return ::v37::sha256d(b, 4);
}

// splitmix64, the generator every v37 settlement KAT uses.
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

// ── the lane / view fixture ─────────────────────────────────────────────────
// A stand-in for the engine's SettlementView with the field names the fold
// reads. project() / fold_eb() / work_price_at() are templated on the view, so
// the production code paths run verbatim.
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

static constexpr u64      REWARD      = 50ull * 100000000ull;  // 50 coin
static constexpr unsigned N_LANE_MINERS = 8;
static constexpr int      N_LANE_PUSH   = 200;
// Every lane push carries the work of ONE consensus share at the easy target
// (work_of_lz(8) == 256), so SUM weight is a round, readable 200 * 256 and an
// estimated hash and a real hash are denominated against the same scale. That
// scale is chosen so neither side of the REPLACE truncates to zero satoshi —
// a fixture in which both sides floor to 0 would assert nothing.
static constexpr u64      LANE_W_RAW  = 256;

// Build the lane + the view + the price ONCE. Everything downstream reads the
// same cut, which is what DROPS-R1 (denomination) requires.
struct Cut {
    LaneParams p;
    FakeView v;
    std::shared_ptr<FakeIdView> idv;
    std::map<bytes32, long long> base;     // E_b at the cut
    settle::WorkPrice price;
};
static Cut build_cut(const LaneParams& p) {
    Cut c;
    c.p = p;
    ::v37::Lane lane(p);
    c.idv = std::make_shared<FakeIdView>();
    for (MinerId m = 1; m <= N_LANE_MINERS; ++m)
        c.idv->m[m] = ::v37::IdentityEntry{key_of(m), ::v37::ScriptRef{}};
    Rng r(0xC0FFEEull);
    for (int i = 0; i < N_LANE_PUSH; ++i) {
        ::v37::WorkAtom a{};
        a.miner       = MinerId(1 + (r.next() % N_LANE_MINERS));
        a.w_raw       = LANE_W_RAW;
        a.origin_bin  = u64(i) / 8;
        a.carrier_bin = a.origin_bin;
        a.flags       = 0;
        a.version     = ::v37::PROV_V37;
        a.is_receipt  = false;
        a.d_net       = U256{};
        lane.push(a, key_of);
    }
    c.v.params     = p;
    c.v.next_pos   = lane.next_pos();
    c.v.payout     = lane.payout_map();
    c.v.identities = c.idv;
    c.v.digest     = lane.digest(key_of);
    const auto f = settle::fold_eb(REWARD, c.v, /*strict=*/true);
    if (f) for (const auto& [k, val] : f->credit) c.base[k] = (long long)val;
    c.price = settle::work_price_at(REWARD, c.v);
    return c;
}

// Fold one block into a fresh ledger and return its owed_digest. The REAL
// OwedLedger seam, the REAL composition, the REAL finalize.
static bytes32 fold_once(const LaneParams& p,
                         const std::map<bytes32, long long>& base,
                         const std::vector<settle::HarvestedReceipt>& harvest,
                         const settle::DropsCompose& ctx, u64 bin) {
    settle::OwedLedger led(7);
    settle::OwedLedger::Amounts b;
    for (const auto& [k, v] : base) b[k] = v;
    led.on_block_found_with_drops("blk", b, {}, p, harvest, ctx);
    led.on_block_finalized("blk", bin);
    return led.owed_digest();
}

// ── raindrop / carrier grinding against the REAL W2 admitter ────────────────
struct Idx : n37::IMainchainIndex {
    std::map<bytes32, u64> h;
    std::optional<u64> height_of(const bytes32& p) const override {
        auto it = h.find(p);
        return it == h.end() ? std::nullopt : std::optional<u64>(it->second);
    }
};
struct Trk : n37::IShareTracker {
    bool has_prev_own(const bytes32&, const bytes32&) const override { return true; }
    void record_share(const bytes32&, const bytes32&) override {}
};

// Grind a work event that meets EXACTLY `lz` leading zero bits and NOT lz + 1.
// The "and not lz+1" half matters: a raindrop whose hash happens to clear the
// consensus target too is a SHARE to the estimator's collector (hash <= h_T),
// not a near-miss, and a fixture that let those through would silently stop
// reaching J >= K.
static n37::WorkEvent grind_exact(std::uint32_t chain, const bytes32& id,
                                  const bytes32& prev, unsigned lz, u64 salt,
                                  const std::string& tag) {
    n37::WorkEvent e{};
    e.chain_id        = chain;
    e.identity        = id;
    e.prev_block_hash = prev;
    e.prev_own_share  = n37::W2_GENESIS_PREV_OWN;
    e.lz_bits         = lz;
    e.tag             = tag;
    for (u64 n = salt * 1000003ull + 1; ; ++n) {
        e.nonce = n;
        const unsigned got = n37::leading_zero_bits(e.hash());
        if (got == lz) return e;
    }
}

// The synthetic mainchain hash for a bin, and the index that resolves it.
static bytes32 prev_of_bin(u64 bin) {
    std::uint8_t b[9] = {'B', 'I', 'N', 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 6; ++i) b[3 + i] = std::uint8_t(bin >> (8 * i));
    return ::v37::sha256d(b, 9);
}

// A high-variance interval for the stale-now measurement: `hashes` draws at a
// share difficulty of 4096 (h_T == 2^244) plus `S` synthetic at-target hashes,
// which move the collector's share count WITHOUT touching the near-miss set.
static constexpr unsigned H_T_BIT = 244;
static sub::u256 share_target_244() {
    sub::u256 t;
    t.w[3] = 1ull << (H_T_BIT - 192);
    return t;
}
static sub::ReceiptCollector simulate(MinerId id, u64 interval,
                                      std::uint64_t hashes, std::uint32_t K,
                                      std::uint64_t S) {
    sub::ReceiptCollector rc(K, share_target_244());
    for (std::uint64_t i = 0; i < S; ++i) { sub::u256 s; s.w[0] = 1 + i; rc.observe(s); }
    Rng r(0xD4095EEDull ^ (std::uint64_t(id) * 0x100000001B3ull) ^
          (interval * 0x9E3779B97F4A7C15ull));
    for (std::uint64_t i = 0; i < hashes; ++i) rc.observe(r.hash());
    return rc;
}

// ═══════════════════════════════════════════════════════════════════════════
int main() {
    std::printf("== v37_drops_step2_wiring_kat: the DROPS live-shell wiring\n");
    std::printf("   build: V37_ACTIVATE_CONSENSUS_V1=%d  kActivationArity=%d  "
                "kDropsWiringArmed=%d\n",
                (int)n37::kActivateConsensusV1, n37::kActivationArity,
                (int)n37::kDropsWiringArmed);

    const std::uint32_t K_CANON = LaneParams::for_version(1).subthreshold.K;

    // ── W-ARITY: what a live node's geometry IS at the ruled arity ──────────
    std::printf("\n-- W-ARITY: the ruled arity, and the geometry it builds --\n");
    {
        check(n37::kActivationArity == 1,
              "★ RULED DECOUPLE: the recorded flip arity is 1 — DROPS alone, the "
              "V37.1 ridge left to its own flag day");

        const LaneParams live = LaneParams::for_version(::v37::SHIPPED_CONSENSUS_VERSION);
        const LaneParams both =
            LaneParams::for_version(::v37::SHIPPED_CONSENSUS_VERSION, LaneKind::BTC);
        check(live.subthreshold.enabled,
              "the arity-1 geometry carries the DROPS gate ON");
        check(live.mrr.activation_pos == UINT64_MAX &&
              live.nr.nr_activation_pos == UINT64_MAX &&
              live.win.win_activation_pos == UINT64_MAX,
              "and leaves the V37.1 ridge and the win law OFF — the DECOUPLE");
        check(both.nr.nr_activation_pos == 4096,
              "(the 2-argument geometry still couples them at P = 4096; it is "
              "simply not what the ruled arity builds)");
        // ★ THE PIN THAT MATTERS MOST HERE. If W4 refused the arity-1 geometry,
        // fold_eb() would return nullopt on every block, the node would credit
        // nothing, and DROPS would be dormant for a SECOND reason that no
        // amount of wiring could fix. Asserted, not assumed.
        check(settle::geometry_is_ratified(live),
              "★ W4 RATIFIES the arity-1 live geometry — so the flip this wiring "
              "assumes does not silently refuse every E_b fold");
        check(settle::geometry_is_ratified(LaneParams{}),
              "and the V37.0 default is ratified, as before");

        // The T1 factory itself, on a default build.
        const LaneParams def = n37::node_lane_params(LaneKind::BTC);
        check(n37::kActivateConsensusV1 || !def.subthreshold.enabled,
              "T1 default build: node_lane_params() carries no DROPS gate");
    }

    // ── W-DORMANT: gate OFF constructs nothing and settles as master ────────
    std::printf("\n-- W-DORMANT: GATE OFF is master, byte for byte --\n");
    {
        check(n37::kDropsWiringArmed == n37::kActivateConsensusV1,
              "the wiring is armed by EXACTLY the consensus-activation flag and "
              "nothing else");

        // ★ THE DORMANCY PIN. On a default build the shell's
        //     auto drops = make_drops_wiring(cfg.lane_params);
        // is nullopt for EVERY geometry — including the gate-ON one — so the
        // shell constructs no harvester, no book, no counter, attaches no seam
        // and arms no harvest. There is no runtime path from a default build to
        // an active DROPS object.
        const bool on_default = n37::make_drops_wiring(LaneParams{}).has_value();
        const bool on_gateon =
            n37::make_drops_wiring(LaneParams::for_version(1)).has_value();
        if (!n37::kActivateConsensusV1) {
            check(!on_default && !on_gateon,
                  "★ default build: make_drops_wiring() is nullopt whatever the "
                  "geometry — the shell constructs NOTHING");
        } else {
            check(!on_default,
                  "activated build: a lane whose geometry carries no gate still "
                  "gets nothing (harvesting for a gated-off settlement credits "
                  "zero and only costs memory)");
            check(on_gateon, "activated build + gate-ON geometry: the bundle exists");
        }

        // ★ BYTE-IDENTITY AT THE FOLD. Hand the gate-OFF fold EVERYTHING it
        // would need to credit — a full harvest, a valid price, a populated
        // ex-ante book — and it must land on the digest it lands on with no
        // harvest at all.
        const Cut off = build_cut(LaneParams{});
        check(!off.base.empty(), "the gate-OFF cut folds a non-empty E_b");
        check(off.price.valid, "and a valid work price");

        const u64 IV = 700;
        std::vector<settle::HarvestedReceipt> harvest;
        for (unsigned d = 0; d < 6; ++d)
            harvest.push_back(settle::HarvestedReceipt{
                key_of(1001 + d), IV, simulate(1001 + d, IV, 4096, K_CANON, 0)});
        n37::EnrollmentBook book;
        for (unsigned d = 0; d < 6; ++d) book.commit(key_of(1001 + d), 0, 1);

        settle::DropsCompose ctx;
        ctx.price      = off.price;
        ctx.enrollment = &book;

        const bytes32 d_none = fold_once(off.p, off.base, {}, ctx, IV);
        const bytes32 d_full = fold_once(off.p, off.base, harvest, ctx, IV);
        check(d_none == d_full,
              "★ GATE OFF: a FULL harvest, a valid price and a populated "
              "enrolment book move owed_digest NOT ONE BIT — the shipped default "
              "settles exactly as master");
        check(settle::subthreshold_credit(off.p, harvest, ctx).empty(),
              "and the composed delta map is empty, not merely zero-valued");

        // NON-VACUOUS: the SAME harvest under the ARITY-1 LIVE geometry moves it.
        const Cut on = build_cut(LaneParams::for_version(1));
        settle::DropsCompose ctx_on;
        ctx_on.price      = on.price;
        ctx_on.enrollment = &book;
        const bytes32 e_none = fold_once(on.p, on.base, {}, ctx_on, IV);
        const bytes32 e_full = fold_once(on.p, on.base, harvest, ctx_on, IV);
        check(e_none != e_full,
              "★ non-vacuous: the very same harvest under the gate-ON geometry "
              "DOES move owed_digest, so the equality above is the gate and not "
              "a dead fixture");

        // The empty-ledger anchor, unmoved.
        settle::OwedLedger empty(7);
        check(hex(empty.owed_digest()) == ANCHOR_OWED_EMPTY,
              "the empty-ledger anchor b4db1ded… is where it has always been");
    }

    // ── W-TIP: now_interval comes from the chain tip ────────────────────────
    std::printf("\n-- W-TIP: the ex-ante clock IS the chain tip --\n");
    {
        n37::TipBin t;
        check(!t.known() && !t.now_interval().has_value(),
              "a fresh TipBin has NO now_interval — not a zero, an absence");
        t.observe_tip(1000);
        check(t.now_interval() && *t.now_interval() == 1000,
              "after the first poll it is the tip height");
        t.observe_tip(990);   // a reorg lowered the tip
        check(t.now_interval() && *t.now_interval() == 1000,
              "★ MONOTONE: a reorg that LOWERS the tip does not lower the ex-ante "
              "clock — moving it backwards is the stale-now shape with extra steps");
        t.observe_tip(1005);
        check(t.now_interval() && *t.now_interval() == 1005, "and it still advances");

        n37::DropsWiring w(K_CANON);
        const bytes32 payee = key_of(4242);
        check(w.enroll_at_tip(payee) == n37::EnrollOutcome::TipUnknown,
              "★ NO TIP, NO ENROLMENT: the bundle REFUSES rather than back-dating "
              "the commitment to interval 0");
        check(w.enrollment().size() == 0, "and nothing was recorded");
        check(!w.arm_at_tip(), "the share-count book is not armed either");

        const u64 TIP = 100;
        w.observe_tip(TIP);
        check(w.enroll_at_tip(payee) == n37::EnrollOutcome::Enrolled,
              "with a tip, the ex-ante commitment is made");
        const auto* rec = w.enrollment().find(payee);
        check(rec != nullptr, "and it is in the book");
        if (rec) {
            check(rec->committed_at == TIP,
                  "★ committed_at IS THE TIP BIN — not the burial frontier, not 0");
            check(rec->effective_from == TIP + 1,
                  "★ effective_from is TIP + 1: strictly later than every interval "
                  "whose draws the payee can already have seen");
        }
        check(!w.enrollment().enrolled(payee, TIP),
              "the interval the commitment was MADE in is NOT covered");
        check(!w.enrollment().enrolled(payee, TIP - 50),
              "and neither is any earlier one (a burial frontier lives here)");
        check(w.enrollment().enrolled(payee, TIP + 1),
              "the first covered interval is TIP + 1");
        check(w.arm_at_tip() && w.shares().covers_from() == TIP,
              "the share-count producer is armed AT THE TIP; everything earlier "
              "stays UNKNOWN and is therefore withheld, which is fail-closed");

        // Enrolment, once made, stands — even after the tip has run far ahead.
        w.observe_tip(TIP + 500);
        check(w.enroll_at_tip(payee) == n37::EnrollOutcome::AlreadyEnrolled,
              "a second commitment for the same payee is a no-op");
        check(w.enrollment().find(payee)->effective_from == TIP + 1,
              "★ and it CANNOT move the start: the first commitment stands, so a "
              "payee cannot re-time its participation around a bad interval");
    }

    // ── W-STALE: the stale-now path is not expressible, and is worth this ───
    std::printf("\n-- W-STALE: the door that is not there, and what it was worth --\n");
    {
        // (1) STRUCTURAL: the signatures themselves. enroll_at_tip takes a payee
        //     and NOTHING ELSE, and the book is reachable only as const — so
        //     EnrollmentBook::commit(payee, now, effective_from), the one call
        //     that can be handed a stale clock, has no caller inside a shell
        //     that goes through this bundle.
        static_assert(
            std::is_same_v<decltype(&n37::DropsWiring::enroll_at_tip),
                           n37::EnrollOutcome (n37::DropsWiring::*)(const bytes32&)>,
            "enroll_at_tip must take the payee ALONE: an interval parameter here "
            "is the stale-now seam, re-opened");
        static_assert(
            std::is_same_v<decltype(&n37::DropsWiring::enrollment),
                           const n37::EnrollmentBook& (n37::DropsWiring::*)() const>,
            "the enrolment book must be reachable CONST-only: a mutable reference "
            "hands commit(payee, now, effective_from) back to the caller");
        check(true, "★ STRUCTURAL: enroll_at_tip(payee) takes no interval, and "
                    "enrollment() is const — the stale-now call does not compile");

        // (2) STRUCTURAL: the OTHER door. declare_at_frontier is where the BURIAL
        //     FRONTIER enters, and it must be provably incapable of enrolling
        //     anything. Drive it hard at frontiers all over the range.
        n37::DropsWiring w(K_CANON);
        w.observe_tip(5000);
        w.arm_at_tip();
        const std::size_t before = w.enrollment().size();
        for (u64 f = 0; f < 400; ++f) w.declare_at_frontier(f);
        (void)w.pre_harvest();
        for (u64 f = 4000; f < 4400; ++f) w.pre_harvest()(f);
        check(w.enrollment().size() == before && w.enrollment().refused() == 0,
              "★ the BURIAL-FRONTIER door (declare_at_frontier / pre_harvest) "
              "enrols nothing and refuses nothing, at any frontier: it reaches "
              "declare_into and can never reach commit()");

        // (3) MEASURED: what the unreachable door was worth. Same draws, two
        //     books. The TIP-sourced one is what the wiring builds; the
        //     STALE-now one is the mistake it cannot make.
        const Cut cut = build_cut(LaneParams::for_version(1));
        const LaneParams p_on = cut.p;
        const unsigned N_IV = 400;
        const u64 IV_BASE = 200;
        const u64 TIP_AT_COMMIT = IV_BASE + N_IV;   // every draw below is PAST
        const MinerId ATTACKER = 7001;
        const bytes32 atk = key_of(ATTACKER);

        // The attacker's real, ordinary entitlement: its S shares at the cut.
        // Both rules are measured against THIS, so the ratios are "what the
        // payee gets, over what it would have got with no DROPS at all".
        n37::EnrollmentBook stale;      // committed with now = a stale frontier
        stale.commit(atk, /*now=*/IV_BASE - 1, /*effective_from=*/IV_BASE);

        n37::DropsWiring tip_w(K_CANON);
        tip_w.observe_tip(TIP_AT_COMMIT);
        check(tip_w.enroll_at_tip(atk) == n37::EnrollOutcome::Enrolled,
              "the tip-sourced book enrols the same payee at the same moment");

        settle::DropsCompose ctx_stale, ctx_tip;
        ctx_stale.price = cut.price; ctx_stale.enrollment = &stale;
        ctx_tip.price   = cut.price; ctx_tip.enrollment   = &tip_w.enrollment();

        long long base_sum = 0, honest_sum = 0, select_sum = 0;
        int positive_intervals = 0;
        std::vector<settle::HarvestedReceipt> all_rows;
        for (unsigned i = 0; i < N_IV; ++i) {
            const u64 iv = IV_BASE + i;
            // A modest interval: ~2 share-equivalents of work at a share
            // difficulty of 4096, so the estimator's variance is large and the
            // sign of the delta genuinely flips. The shares are the ones the
            // DRAWS produced — no synthetic at-target hashes here, because
            // free shares would distort the very ratio being measured.
            auto rc = simulate(ATTACKER, iv, 8192, K_CANON, /*S=*/0);
            std::vector<settle::HarvestedReceipt> one{
                settle::HarvestedReceipt{atk, iv, rc}};
            all_rows.push_back(one[0]);

            // the ordinary S*T entitlement this interval would have paid
            const sub::u320 wsh = sub::divfloor(sub::coeff_times_2_256(rc.shares()),
                                                sub::promote(rc.target_hash()));
            const long long base = settle::entitlement_of_work(cut.price, wsh);
            base_sum += base;

            const auto d = settle::subthreshold_credit(p_on, one, ctx_stale);
            const long long delta = d.count(atk) ? d.at(atk) : 0;
            honest_sum += base + delta;                       // take every interval
            select_sum += base + (delta > 0 ? delta : 0);      // take only the good
            if (delta > 0) ++positive_intervals;
        }
        const double r_honest = base_sum ? (double)honest_sum / (double)base_sum : 0.0;
        const double r_select = base_sum ? (double)select_sum / (double)base_sum : 0.0;
        std::printf("   %u intervals: unconditional=%.4fx  selective(stale-now)=%.4fx"
                    "  (%d intervals had a positive delta)\n",
                    N_IV, r_honest, r_select, positive_intervals);
        check(positive_intervals > 0 && positive_intervals < (int)N_IV,
              "the draws really do flip sign, so 'selective' is a real choice and "
              "not a constant");
        check(r_select > r_honest,
              "★ the SELECTIVE rule beats the unconditional one on the same draws "
              "— that gap IS the stale-now seam");
        check(r_honest > 0.85 && r_honest < 1.10,
              "the UNCONDITIONAL rule is ~1x — the unbiasedness R-SYBIL rests on, "
              "reproduced here so the selective number has a baseline");
        check(r_select > 1.10 && r_select < 1.60,
              "★ and the SELECTIVE rule is worth a double-digit percentage of the "
              "payee's whole entitlement (measured 1.18x here, and the module's "
              "own curve reaches 1.32x at a 2000-way split) — which is why the "
              "stale-now door is closed structurally and not by a comment");

        // ★ AND THE SHIPPED WIRING PAYS NONE OF IT. Every one of those intervals
        // is at or below the tip the commitment was made at, so the tip-sourced
        // book covers NOT ONE of them.
        const auto shipped = settle::subthreshold_credit(p_on, all_rows, ctx_tip);
        check(shipped.empty(),
              "★ THE CLOSURE: under the TIP-sourced enrolment the wiring builds, "
              "every already-drawn interval composes NOTHING — the payee keeps "
              "its ordinary S*T path and the selective gain is zero");
        const auto stale_all = settle::subthreshold_credit(p_on, all_rows, ctx_stale);
        check(!stale_all.empty(),
              "non-vacuous: the stale-now book composes those very same rows");
    }

    // ── W-E2E: the whole path on the real objects ───────────────────────────
    std::printf("\n-- W-E2E: raindrop -> produce -> enrol -> credit -> fold --\n");
    {
        // The arity-1 LIVE geometry: exactly what a flipped node builds.
        const Cut cut = build_cut(LaneParams::for_version(1));
        const LaneParams p_on = cut.p;

        const u64 ARM_TIP  = 100;   // the tip when the node booted and wired up
        const u64 B_DROP   = 120;   // the interval the raindrops belong to
        const u64 B_CARRY  = 121;   // the bin the drop-only payees' carriers sit in
        const u64 FRONTIER = 121;   // burial frontier: releases 120, keeps 121
        const u64 TIP_NOW  = 140;   // the tip when the block was won
        const std::uint32_t CHAIN = 7;
        const unsigned CLZ_D = n37::consensus_lz(B_DROP);
        const unsigned CLZ_C = n37::consensus_lz(B_CARRY);
        // Both bins sit on the same side of the retarget boundary, so a carrier
        // at 121 and a raindrop keyed to 120 are measured against one h_T; the
        // fixture would otherwise be testing the retarget, not the wiring.

        check(CLZ_D == CLZ_C, "the two fixture bins share one consensus target");
        Idx idx;
        idx.h[prev_of_bin(B_DROP)]  = B_DROP;
        idx.h[prev_of_bin(B_CARRY)] = B_CARRY;
        Trk trk;

        // THE WIRING, wired exactly as main_v37_btc_dash.cpp wires it.
        n37::DropsWiring w(p_on.subthreshold.K);
        w.observe_tip(ARM_TIP);

        const bytes32 ID_A = key_of(1001);   // drop-only at 120  (ENROLLED)
        const bytes32 ID_B = key_of(3);      // covered at 120    (ENROLLED, lane miner)
        const bytes32 ID_C = key_of(1002);   // shares, NO drops  (ENROLLED)
        const bytes32 ID_D = key_of(1003);   // drop-only at 120  (NOT enrolled)
        check(w.enroll_at_tip(ID_A) == n37::EnrollOutcome::Enrolled &&
              w.enroll_at_tip(ID_B) == n37::EnrollOutcome::Enrolled &&
              w.enroll_at_tip(ID_C) == n37::EnrollOutcome::Enrolled,
              "three payees enrol EX ANTE at the boot tip (effective from 101, "
              "strictly before the interval 120 they will be credited for)");
        check(w.arm_at_tip(), "the share-count producer arms at the boot tip");
        check(cut.base.count(ID_B) == 1,
              "the covered payee really does carry an E_b row at this cut");

        // The REAL W2 admitter, with BOTH admitter-side seams installed.
        n37::ReceiptAdmitter adm(CHAIN, idx, trk, 1);
        adm.set_drop_harvest(true, w.drop_sink());
        std::vector<n37::EmittedPush> engine_got;
        n37::RecordSink engine_sink = [&](const n37::EmittedPush& p) {
            engine_got.push_back(p);
        };
        n37::RecordSink wired_sink = w.sink_filter()(engine_sink);

        u64 salt = 1;
        auto admit_one = [&](const bytes32& id, u64 carry_bin, unsigned n_drops) {
            const bytes32 prev_c = prev_of_bin(carry_bin);
            const u64 cs = salt++;
            n37::WorkEvent carrier =
                grind_exact(CHAIN, id, prev_c, n37::consensus_lz(carry_bin), cs,
                            "c" + std::to_string(cs));
            std::vector<n37::WorkEvent> rs;
            for (unsigned i = 0; i < n_drops; ++i) {
                const u64 ds = salt++;
                rs.push_back(grind_exact(CHAIN, id, prev_of_bin(B_DROP), CLZ_D - 1,
                                         ds, "d" + std::to_string(ds)));
            }
            const auto r = adm.admit(carrier, rs, wired_sink);
            check(r.carrier_status == n37::CarrierStatus::OK, "carrier admits");
            check(r.drops == n_drops, "every sub-target receipt is a raindrop");
            check(r.pushes.size() == 1,
                  "and NONE of them is pushed: a raindrop never touches the lane");
            return r;
        };

        // A: carriers at 121 with raindrops keyed to 120 -> S(A,120) == 0.
        admit_one(ID_A, B_CARRY, 3);
        admit_one(ID_A, B_CARRY, 3);
        // B: carriers at 120 with raindrops keyed to 120 -> S(B,120) == 3.
        admit_one(ID_B, B_DROP, 2);
        admit_one(ID_B, B_DROP, 2);
        admit_one(ID_B, B_DROP, 2);
        // C: carriers at 120, NO raindrops -> shares but no harvest row.
        admit_one(ID_C, B_DROP, 0);
        admit_one(ID_C, B_DROP, 0);
        // D: like A, but never enrolled.
        admit_one(ID_D, B_CARRY, 3);
        admit_one(ID_D, B_CARRY, 3);

        check(engine_got.size() == 9,
              "★ the TEE is transparent: the engine received every carrier push, "
              "and only the carrier pushes (9 carriers, 0 raindrops)");
        check(adm.drops_harvested() == 18, "18 raindrops were harvested");
        check(w.stats().harvested == 18, "and all 18 reached the wiring's sink");
        check(w.shares().count(ID_B, B_DROP) == 3 &&
              w.shares().count(ID_C, B_DROP) == 2 &&
              w.shares().count(ID_A, B_DROP) == 0 &&
              w.shares().count(ID_A, B_CARRY) == 2,
              "★ the PRODUCER counts one share per EmittedPush at (identity, "
              "origin_bin) — the same F1 bin the harvester keys its intervals on");

        // The tip moves on; the block is won at 140 and buries interval 120.
        w.observe_tip(TIP_NOW);
        check(w.now_interval() && *w.now_interval() == TIP_NOW,
              "the ex-ante clock followed the chain tip");
        check(*w.now_interval() > FRONTIER,
              "★ and the two clocks are DISTINCT: now_interval (the tip, 140) is "
              "strictly ahead of the release frontier (121). Confusing them is "
              "precisely the residual this wiring closes");

        // ★ THE PRE-HARVEST HOOK — the exact std::function XbtcNode is given.
        auto hook = w.pre_harvest();
        hook(FRONTIER);
        check(w.stats().declared == 4,
              "declare_into declared all four (payee, interval) rows at the "
              "frontier: three the harvester held, plus the ENROLLED payee that "
              "had shares and no raindrops at all");

        auto rows = w.harvester().take_buried(FRONTIER);
        check(rows.size() == 4, "and all four are RELEASED as W4 harvest rows");
        check(w.harvester().undeclared_withheld() == 0,
              "nothing was withheld: the producer covered every released interval");
        std::map<bytes32, const sub::ReceiptCollector*> by;
        for (const auto& r : rows) {
            check(r.interval == B_DROP, "every released row is the BURIED interval");
            by[r.payee] = &r.collector;
        }
        check(by.count(ID_A) && by.at(ID_A)->shares() == 0 &&
              by.at(ID_A)->near_miss_count() >= p_on.subthreshold.K,
              "A: drop-only at 120 (its carriers sat at 121), J >= K near-misses");
        check(by.count(ID_B) && by.at(ID_B)->shares() == 3,
              "★ B: the DECLARED share count is the PRODUCED one (3), not a "
              "guessed zero — which is what makes the REPLACE subtraction right");
        check(by.count(ID_C) && by.at(ID_C)->shares() == 2 &&
              by.at(ID_C)->near_miss_count() == 0,
              "★ C: an ENROLLED payee that relayed NO raindrops still gets a row "
              "synthesised, with J = 0 — so withholding raindrops cannot dodge a "
              "bad interval");

        // ── compose under the REAL price and the REAL ex-ante book ──────────
        settle::DropsCompose ctx;
        ctx.price      = cut.price;
        ctx.enrollment = &w.enrollment();
        bool sat = false;
        const auto delta = settle::subthreshold_credit(p_on, rows, ctx, &sat);
        std::printf("   composed delta: A=%lld B=%lld C=%lld  (D present: %s)\n",
                    delta.count(ID_A) ? delta.at(ID_A) : 0,
                    delta.count(ID_B) ? delta.at(ID_B) : 0,
                    delta.count(ID_C) ? delta.at(ID_C) : 0,
                    delta.count(ID_D) ? "YES" : "no");
        check(!sat, "no i64 saturation in this fixture");
        check(delta.count(ID_A) == 1 && delta.at(ID_A) > 0,
              "★ A (drop-only, enrolled) is CREDITED: the participation case DROPS "
              "exists for, and the whole point of the wiring");
        check(delta.count(ID_C) == 1 && delta.at(ID_C) < 0,
              "★ C (enrolled, J < K) is composed NEGATIVE: Hhat is 0 and its whole "
              "share work comes back out — the downside enrolment accepts");
        check(delta.count(ID_D) == 0,
              "★ D is NOT ENROLLED and contributes NOTHING — not a zero row, "
              "nothing: it keeps its ordinary S*T path, untouched");
        check(delta.count(ID_B) == 1,
              "B (enrolled, covered) is composed by REPLACE");

        // ── fold it, for real ───────────────────────────────────────────────
        const bytes32 owed_with = fold_once(p_on, cut.base, rows, ctx, B_DROP);
        settle::DropsCompose ctx_nobody;                 // no book: nobody enrolled
        ctx_nobody.price = cut.price;
        const bytes32 owed_none = fold_once(p_on, cut.base, {}, ctx, B_DROP);
        const bytes32 owed_unenrolled = fold_once(p_on, cut.base, rows, ctx_nobody, B_DROP);
        std::printf("   owed_digest: no-harvest=%s\n                wired    =%s\n",
                    hex(owed_none).substr(0, 24).c_str(),
                    hex(owed_with).substr(0, 24).c_str());
        check(owed_with != owed_none,
              "★ END TO END: the wired harvest MOVES the settled owed_digest — "
              "DROPS is live, not dormant");
        check(owed_unenrolled == owed_none,
              "★ and with NO ex-ante book the identical harvest moves nothing: "
              "R-SYBIL is what decides, and it is decided before the draws");

        // The R3 witness that rides the wire beside the map.
        check(!(w.enrollment().book_digest() == n37::empty_enrollment_digest()),
              "the enrolment book digest is non-empty and is what a peer sees "
              "beside the composed credit map");

        // F1, twice over: a released interval can never be released again.
        check(w.harvester().take_buried(FRONTIER).empty(),
              "the released intervals are CONSUMED");
        check(w.harvester().open_intervals() == 0,
              "and nothing from bin 120 is left open");
    }

    // ── W-LOCK: the wiring is reachable from three threads now ──────────────
    std::printf("\n-- W-LOCK: concurrent feed + win (liveness + counters) --\n");
    {
        // Step 2 is what first makes these plain stdlib containers reachable from
        // the carrier reader threads AND the stratum submit thread at once, so
        // the bundle carries the lock. This is a SMOKE — it exercises the lock
        // and checks the counters add up; it is not a proof that no race exists
        // (that is what the ASan+UBSan CI leg and a TSan run are for).
        n37::DropsWiring w(4);
        w.observe_tip(10);
        w.arm_at_tip();
        const bytes32 P = key_of(9001);
        w.enroll_at_tip(P);

        constexpr int N = 4000;
        std::atomic<bool> go{false};
        auto feeder = [&] {
            while (!go.load()) { }
            auto sink = w.drop_sink();
            n37::RecordSink dev_null = [](const n37::EmittedPush&) {};
            auto tee = w.sink_filter()(dev_null);
            for (int i = 0; i < N; ++i) {
                n37::HarvestedDrop d{};
                d.payee = P;
                d.interval = 50 + (u64)(i % 4);
                d.consensus_lz = n37::consensus_lz(d.interval);
                const std::uint64_t x = (std::uint64_t)i;
                d.hash = ::v37::sha256d(reinterpret_cast<const std::uint8_t*>(&x),
                                        sizeof x);
                sink(d);
                n37::EmittedPush p{};
                p.identity = P;
                p.origin_bin = d.interval;
                tee(p);
            }
        };
        auto winner = [&] {
            while (!go.load()) { }
            for (int i = 0; i < 200; ++i) {
                auto lk = w.win_lock();
                w.declare_at_frontier(50);      // below every fed interval: a no-op
                (void)w.harvester().take_buried(50);
                (void)w.stats();
            }
        };
        std::thread t1(feeder), t2(feeder), t3(winner);
        go.store(true);
        t1.join(); t2.join(); t3.join();
        const auto st = w.stats();
        check(st.harvested == 2 * N,
              "every raindrop both feeders produced reached the harvester");
        check(st.shares_seen == 2 * N,
              "and every push both feeders produced reached the share counter");
        check(st.late == 0 && st.withheld == 0,
              "nothing was released behind the frontier, so nothing was late or "
              "withheld");
        check(w.enrollment().size() == 1,
              "and 800 frontier declarations enrolled nobody");
    }

    std::printf("\n== %ld checks, %ld failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
