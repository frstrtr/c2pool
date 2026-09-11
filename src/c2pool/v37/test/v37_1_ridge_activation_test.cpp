// kat_v371_ridge_owed_golden.cpp
//
// V37.1 GATE-ON (Shape A, native ridge at position 4096) owed_digest
// REGRESSION KAT.
//
// WHAT IT PINS
//   The V37.1 activation moves exactly one observable through the settlement
//   fold: the divided-reward map that LaneExecutor hands the view-build site
//   (`s->payout = l.payout_map()`). Gate OFF, Lane::payout_map() dispatches to
//   payout_map_positional(); gate ON (nr_active()), it dispatches to
//   nr_payout_map(). That map is the only ridge-carrying input to
//   fold_eb(reward, view) -> E_b credit -> on_block_found -> on_block_finalized
//   -> finalW -> OwedLedger::owed_digest().
//
//   So a meaningful activation golden must be a SCHEDULE golden: a share stream
//   that crosses the activation position with carrier bins, at least one block
//   found AND finalized after the crossing, and the digest cut taken after that
//   finalize. An empty or pre-crossing ledger produces sha256d("V37O") no matter
//   what the lane gate says, and pins nothing.
//
// HOW THE FIXTURE IS BUILT (important)
//   The activation position is set AT RUNTIME on a LaneParams fixture:
//       LaneParams p = LaneParams::for_version(1, LaneKind::BTC);
//       p.mrr.activation_pos = 4096;
//       p.nr.nr_activation_pos = 4096;
//   exactly as the existing S8/S-1 acceptance KAT does. This KAT does NOT edit
//   for_version() in the consensus header, so it is standalone: it runs
//   identically before and after the operator's activation commit, and the
//   golden it pins is the value that commit must reproduce.
//
//   p.win.win_activation_pos is deliberately left at UINT64_MAX (ND-R9): the
//   width law is not part of Shape A, and the schedule below carries d_net = 0
//   so the width stays at the lane default and never enters the owed value.
//
// CHECKS
//   RIDGE-OWED-EMPTY     a fresh ledger is sha256d("V37O"), the anchor
//   RIDGE-OWED-OFF       the gate-OFF control digest over the SAME schedule
//   RIDGE-OWED-ON        the gate-ON golden at the pinned cut  <-- the value
//   RIDGE-OWED-LIVE      the golden is NON-VACUOUS: ON != OFF
//   RIDGE-OWED-SHAPE     the lane structure at the cut (ridge fired, and how)
//   RIDGE-OWED-STAMP     eb_source_of() per block: OFF live-only throughout,
//                        ON live+carry from the activation share onward
//   RIDGE-OWED-ND-R10    the first read after the activation share is credit-
//                        identical to the gate-OFF read (migration is a
//                        record-only cell), and the ledger only diverges later
//   RIDGE-OWED-LANES     all four ratified lanes settle to the SAME owed
//                        digest: the lanes differ in ridge geometry and in the
//                        low limbs of the payout map, but the E_b split
//                        truncates to identical satoshi rows
//   RIDGE-OWED-OWEDFREE  the golden is NOT minted over the one number ND-R6
//                        left OWED. nr.coverage_blocks is economic policy with
//                        no derivable value, currently pinned to W_default.
//                        The lane header warns that the gate-ON golden must
//                        not be minted over it, so this check PROVES it was
//                        not: driving the same schedule with coverage_blocks
//                        far off the pin reproduces the golden byte for byte
//                        (d_net = 0 holds the width law, so the coverage
//                        factor never reaches a payout), while the NRG1 lane
//                        digest, which does commit it, moves. That is why the
//                        lane digest below is reported and NOT pinned.
//
// BUILD (headers read-only, nothing in the tree is written):
//   g++-15 -std=c++20 -O2 -Wall -Wextra -I<release>/src
//       kat_v371_ridge_owed_golden.cpp -o kat_v371_ridge_owed_golden
//
// Exit status 0 = all checks pass; 1 = at least one check failed.

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>

namespace settle = ::c2pool::v37n::settle;
using ::v37::bytes32;
using ::v37::LaneKind;
using ::v37::LaneParams;
using ::v37::MinerId;
using ::v37::U256;
using ::v37::u64;

// ── the pinned goldens ────────────────────────────────────────────────────
//
// GATE-ON golden: the owed_digest after blk_cut is finalized, with the ridge
// active from position 4096. This is the V37.1 activation regression value.
static const char* GOLDEN_OWED_ON =
    "87c5249ac2057d0ac6707127c59cdc605acec4ba3c0d4b4b25e9b53692eb71ee";
// GATE-OFF control over the identical schedule with the ridge inactive. It is
// the value today's shipped consensus produces, and it is what makes the
// gate-ON golden non-vacuous rather than a restatement of the status quo.
static const char* GOLDEN_OWED_OFF =
    "9cfaf97de7c58a7727ff5cc1203f445fc301559fb702938a3dd61ad32d6b338e";
// The empty-ledger anchor, sha256d("V37O").
static const char* GOLDEN_OWED_EMPTY =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";
// The gate-ON BTC lane digest at the same cut. REPORTED, NOT PINNED: the NRG1
// preimage commits nr.coverage_blocks, which is the one ND-R6 number still
// OWED, so pinning this hex would hold the KAT hostage to a policy value the
// operator has not ruled. The lane is pinned structurally instead (SHAPE_ON),
// and RIDGE-OWED-OWEDFREE proves the owed golden carries no such hostage.
static const char* REPORTED_LANE_ON_BTC =
    "9bad8ea04c57fa7ef09c22f5eab9917d8002040ed95985ddc51d8da948753ecc";
// coverage_blocks values used to prove the owed golden is independent of the
// OWED number. The shipped pin for BTC is w_default_bins == 144.
static const u64 COV_PROBE[] = {1, 72, 143, 288, 100000};

// ── the pinned schedule ───────────────────────────────────────────────────
static constexpr std::uint64_t SEED           = 0x5EED4096ull;
static constexpr int           N_PUSH         = 9000;
static constexpr unsigned      N_MINERS       = 10;
static constexpr u64           SHARES_PER_BIN = 8;     // buried-parent bin width
static constexpr u64           ACT_POS        = 4096;  // Shape A activation
static constexpr u64           REWARD         = 50ull * 100000000ull;
static constexpr int           N_BLOCKS       = 4;
// Block events fire on the push that makes next_pos() equal these values:
//   4000 pre-flip, 4097 the first read after the activation share,
//   6000 mid-ridge, 9000 the cut.
static const u64  BLOCK_AT[N_BLOCKS] = {4000, 4097, 6000, 9000};
static const char* BLOCK_ID[N_BLOCKS] = {"blk_pre", "blk_flip", "blk_mid", "blk_cut"};
// Lane structure expected at the cut, gate ON, per lane.
struct LaneShape { u64 W, retargets, ckpts, full_carries, cells, branch_hits; };
static const LaneShape SHAPE_ON[4] = {
    { 144, 76, 9, 59, 96, 4903},   // BTC
    { 576, 76, 9,  1, 33, 4903},   // LTC
    { 576, 76, 9,  1, 33, 4903},   // DASH
    {1440, 76, 9,  0, 33, 4903},   // DOGE
};

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

// The identity resolver. The SAME function feeds the lane push and the
// settlement view, which is what makes the two sides agree on payee keys.
static bytes32 key_of(MinerId m) {
    std::uint8_t b[4] = {std::uint8_t(m), std::uint8_t(m >> 8),
                         std::uint8_t(m >> 16), std::uint8_t(m >> 24)};
    return ::v37::sha256d(b, 4);
}

// splitmix64, the generator the S8/S-1 KAT uses.
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
};

// A stand-in for the engine's SettlementView with the field names the fold
// reads. project() / fold_eb() are templated on the view, so the production
// code paths run verbatim.
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
    u64 next_pos = 0;
    bool nr_on = false;
    LaneShape shape{0, 0, 0, 0, 0, 0};
    settle::OwedLedger::Amounts credit[N_BLOCKS];
    settle::EbSource source[N_BLOCKS];
    bool geometry_ratified = false;
    bool win_untouched = false;
    bool refused = false;      // the settlement boundary refused the geometry
    bool short_run = false;    // fewer than N_BLOCKS events fired
};

// Drive the pinned schedule once. `flip` selects gate ON (ridge at ACT_POS)
// or the gate-OFF control; everything else is identical between the two.
// `cov_override` (0 = leave the shipped pin alone) and `strict` exist only for
// RIDGE-OWED-OWEDFREE: strict=false is the fold's documented test-only escape
// so a deliberately off-pin geometry can still be driven through the seam.
static Run drive(LaneKind lk, bool flip, u64 cov_override = 0, bool strict = true) {
    LaneParams p = LaneParams::for_version(1, lk);
    // BOTH arms state their gate positions explicitly, and neither reads the
    // factory's default. That is what makes this KAT invariant to the
    // operator's activation commit: before the commit the OFF arm's assignment
    // is a no-op, after it the OFF arm restores the pre-activation control, and
    // the ON arm is the flip either way. The activation position is not part of
    // the ratified ND-R6 dimension set (nr_gate_dims_equal ignores it), so
    // forcing it does not disturb geometry_is_ratified on either arm.
    if (flip) {
        p.mrr.activation_pos   = ACT_POS;
        p.nr.nr_activation_pos = ACT_POS;
        // p.win.win_activation_pos intentionally NOT set (ND-R9).
    } else {
        p.mrr.activation_pos   = UINT64_MAX;
        p.nr.nr_activation_pos = UINT64_MAX;
    }
    if (cov_override) p.nr.coverage_blocks = cov_override;
    Run o;
    o.geometry_ratified = settle::geometry_is_ratified(p);
    o.win_untouched     = (p.win.win_activation_pos == UINT64_MAX);

    ::v37::Lane lane(p);
    auto idv = std::make_shared<FakeIdView>();
    for (MinerId m = 1; m <= N_MINERS; ++m)
        idv->m[m] = ::v37::IdentityEntry{key_of(m), ::v37::ScriptRef{}};

    settle::OwedLedger ledger(7);
    Rng r(SEED);
    int nb = 0;
    for (int i = 0; i < N_PUSH; ++i) {
        ::v37::WorkAtom a{};
        a.miner       = MinerId(1 + (r.next() % N_MINERS));   // first draw
        a.w_raw       = 1 + (r.next() % 1000);                // second draw
        a.origin_bin  = u64(i) / SHARES_PER_BIN;
        a.carrier_bin = a.origin_bin;
        a.flags       = 0;
        a.version     = ::v37::PROV_V37;
        a.is_receipt  = false;
        a.d_net       = U256{};   // width law holds at the lane default
        lane.push(a, key_of);

        if (nb < N_BLOCKS && lane.next_pos() == BLOCK_AT[nb]) {
            FakeView v;
            v.params     = p;
            v.next_pos   = lane.next_pos();
            v.payout     = lane.payout_map();   // the ONE ridge-carrying input
            v.identities = idv;
            v.digest     = lane.digest(key_of);

            auto f = settle::fold_eb(REWARD, v, strict);
            if (!f) { o.refused = true; return o; }
            settle::OwedLedger::Amounts credit;
            for (const auto& [k, val] : f->credit) credit[k] = (long long)val;
            ledger.on_block_found_with_estimator(BLOCK_ID[nb], credit, {}, p, {});
            ledger.on_block_finalized(BLOCK_ID[nb], (BLOCK_AT[nb] - 1) / SHARES_PER_BIN);
            o.credit[nb] = credit;
            o.source[nb] = f->source;
            ++nb;
        }
    }
    o.short_run = (nb != N_BLOCKS);
    o.owed        = ledger.owed_digest();
    o.ledger_seq  = ledger.ledger_seq();
    o.lane_digest = lane.digest(key_of);
    o.next_pos    = lane.next_pos();
    o.nr_on       = lane.nr_active();
    o.shape       = LaneShape{lane.nr_W_bins(), lane.nr_retargets(),
                              lane.nr_ckpts_taken(), lane.nr_full_carries(),
                              u64(lane.nr_cell_count()), lane.nr_branch_hits()};
    return o;
}

static const char* src_name(settle::EbSource s) {
    return s == settle::EbSource::LiveAndCarry ? "live+carry" : "live-only";
}

int main() {
    std::printf("== kat_v371_ridge_owed_golden: V37.1 Shape A activation regression\n");
    std::printf("   schedule: seed=0x%llx pushes=%d miners=%u shares/bin=%llu "
                "activation_pos=%llu reward=%llu\n",
                (unsigned long long)SEED, N_PUSH, N_MINERS,
                (unsigned long long)SHARES_PER_BIN, (unsigned long long)ACT_POS,
                (unsigned long long)REWARD);
    std::printf("   blocks: ");
    for (int b = 0; b < N_BLOCKS; ++b)
        std::printf("%s@%llu%s", BLOCK_ID[b], (unsigned long long)BLOCK_AT[b],
                    b + 1 == N_BLOCKS ? "\n" : ", ");

    // ── RIDGE-OWED-EMPTY ─────────────────────────────────────────────────
    std::printf("\n-- RIDGE-OWED-EMPTY --\n");
    {
        settle::OwedLedger e(7);
        std::printf("   empty owed_digest      = %s\n", hex(e.owed_digest()).c_str());
        check(hex(e.owed_digest()) == GOLDEN_OWED_EMPTY,
              "empty ledger owed_digest == sha256d(\"V37O\")");
        check(e.ledger_seq() == 0, "a fresh ledger is at seq 0");
    }

    const LaneKind LK[4] = {LaneKind::BTC, LaneKind::LTC, LaneKind::DASH, LaneKind::DOGE};
    const char*    LN[4] = {"BTC", "LTC", "DASH", "DOGE"};

    // Which side of the activation commit is this tree on? Reported, never
    // asserted: both arms below set their own gate positions, so this KAT and
    // its golden are the same before and after the operator bakes the flip.
    {
        const LaneParams canon = LaneParams::for_version(1, LaneKind::BTC);
        const bool baked = (canon.nr.nr_activation_pos != UINT64_MAX);
        std::printf("\n   canon for_version(1, BTC): mrr.activation_pos=%llu "
                    "nr.nr_activation_pos=%llu win.win_activation_pos=%llu -> %s\n",
                    (unsigned long long)canon.mrr.activation_pos,
                    (unsigned long long)canon.nr.nr_activation_pos,
                    (unsigned long long)canon.win.win_activation_pos,
                    baked ? "activation BAKED" : "activation NOT baked");
        check(canon.win.win_activation_pos == UINT64_MAX,
              "the canon leaves the window gate OFF (ND-R9) on either side of the commit");
        check(canon.nr.nr_version == 1,
              "the canon declares the native-ridge table at version 1");
        check(canon.mrr.activation_pos == canon.nr.nr_activation_pos,
              "the canon keeps the two ridge positions co-located (ruling M)");
    }

    Run off[4], on[4];
    for (int i = 0; i < 4; ++i) {
        off[i] = drive(LK[i], false);
        on[i]  = drive(LK[i], true);
        check(!off[i].refused && !off[i].short_run,
              "the control run completes without a settlement refusal");
        check(!on[i].refused && !on[i].short_run,
              "the flipped run completes without a settlement refusal");
    }

    // ── RIDGE-OWED-OFF / RIDGE-OWED-ON (the mint) ────────────────────────
    std::printf("\n-- RIDGE-OWED-OFF: the control (ridge inactive, same schedule) --\n");
    std::printf("   gate_off_owed_digest   = %s\n", hex(off[0].owed).c_str());
    check(hex(off[0].owed) == GOLDEN_OWED_OFF,
          "gate-OFF control digest matches the pinned control value");
    check(!off[0].nr_on, "the control lane never activates the ridge");
    check(off[0].next_pos == u64(N_PUSH), "the control lane consumed the whole stream");
    check(off[0].ledger_seq == 8, "the control ledger is at seq 8 (4 found + 4 finalized)");

    std::printf("\n-- RIDGE-OWED-ON: the V37.1 activation golden --\n");
    std::printf("   gate_on_owed_digest    = %s\n", hex(on[0].owed).c_str());
    std::printf("   gate_on_lane_digest    = %s  (reported, not pinned)\n",
                hex(on[0].lane_digest).c_str());
    if (hex(on[0].lane_digest) != REPORTED_LANE_ON_BTC)
        std::printf("   note: the BTC lane digest differs from the value recorded when "
                    "this golden was minted (%s). That is not a failure by itself: the "
                    "NRG1 preimage commits the OWED nr.coverage_blocks.\n",
                    REPORTED_LANE_ON_BTC);
    check(hex(on[0].owed) == GOLDEN_OWED_ON,
          "gate-ON owed_digest matches the pinned V37.1 golden");
    check(on[0].nr_on, "the flipped lane has the ridge active at the cut");
    check(on[0].next_pos == u64(N_PUSH), "the flipped lane consumed the whole stream");
    check(on[0].ledger_seq == 8, "the flipped ledger is at seq 8 (4 found + 4 finalized)");

    // ── RIDGE-OWED-LIVE: non-vacuity ─────────────────────────────────────
    std::printf("\n-- RIDGE-OWED-LIVE: the golden is non-vacuous --\n");
    check(!(on[0].owed == off[0].owed),
          "gate-ON owed_digest differs from the gate-OFF control");
    check(!(on[0].owed == off[0].owed) &&
          hex(on[0].owed) != GOLDEN_OWED_EMPTY,
          "the golden is a settled ledger, not the empty anchor");
    std::printf("   ON != OFF: %s   ON != empty: %s\n",
                (on[0].owed == off[0].owed) ? "NO (VACUOUS)" : "yes",
                hex(on[0].owed) == GOLDEN_OWED_EMPTY ? "NO (VACUOUS)" : "yes");

    // ── RIDGE-OWED-SHAPE: how the ridge actually ran ─────────────────────
    std::printf("\n-- RIDGE-OWED-SHAPE: lane structure at the cut --\n");
    for (int i = 0; i < 4; ++i) {
        const LaneShape& s = on[i].shape;
        const LaneShape& e = SHAPE_ON[i];
        std::printf("   %-4s W=%-5llu retargets=%-3llu ckpts=%-2llu full_carries=%-3llu "
                    "cells=%-3llu branch_hits=%llu\n", LN[i],
                    (unsigned long long)s.W, (unsigned long long)s.retargets,
                    (unsigned long long)s.ckpts, (unsigned long long)s.full_carries,
                    (unsigned long long)s.cells, (unsigned long long)s.branch_hits);
        check(s.W == e.W && s.retargets == e.retargets && s.ckpts == e.ckpts &&
              s.full_carries == e.full_carries && s.cells == e.cells &&
              s.branch_hits == e.branch_hits,
              "gate-ON lane structure matches the pinned shape for this lane");
        check(on[i].geometry_ratified, "the flipped fixture is a ratified geometry");
        check(on[i].win_untouched, "win_activation_pos is untouched (ND-R9)");
        check(on[i].shape.retargets > 0,
              "retargets ran and the width law held (d_net = 0)");
    }

    // ── RIDGE-OWED-STAMP / RIDGE-OWED-ND-R10 ─────────────────────────────
    std::printf("\n-- RIDGE-OWED-STAMP + ND-R10: per-block source and credit --\n");
    for (int b = 0; b < N_BLOCKS; ++b) {
        bool eq = (on[0].credit[b] == off[0].credit[b]);
        std::printf("   %-8s @%-5llu src(off)=%-10s src(on)=%-10s credit ON==OFF: %s "
                    "payees=%zu\n",
                    BLOCK_ID[b], (unsigned long long)BLOCK_AT[b],
                    src_name(off[0].source[b]), src_name(on[0].source[b]),
                    eq ? "yes" : "no", on[0].credit[b].size());
        check(off[0].source[b] == settle::EbSource::LiveOnly,
              "the control stamps live-only at every block");
        check(on[0].credit[b].size() == N_MINERS, "every block credits all ten payees");
    }
    check(on[0].source[0] == settle::EbSource::LiveOnly,
          "pre-activation block stamps live-only on the flipped lane too");
    check(on[0].source[1] == settle::EbSource::LiveAndCarry &&
          on[0].source[2] == settle::EbSource::LiveAndCarry &&
          on[0].source[3] == settle::EbSource::LiveAndCarry,
          "every read from the activation share onward stamps live+carry");
    check(on[0].credit[0] == off[0].credit[0],
          "ND-R10: the pre-activation credit is byte-identical to the control");
    check(on[0].credit[1] == off[0].credit[1],
          "ND-R10: the first post-activation read is byte-identical to the control "
          "(the migration cell is record-only)");
    check(!(on[0].credit[2] == off[0].credit[2]),
          "the ridge has diverged from the control by the mid-ridge block");
    check(!(on[0].credit[3] == off[0].credit[3]),
          "the ridge has diverged from the control at the cut");

    // ── RIDGE-OWED-LANES ─────────────────────────────────────────────────
    std::printf("\n-- RIDGE-OWED-LANES: all four ratified lanes settle identically --\n");
    for (int i = 0; i < 4; ++i) {
        std::printf("   %-4s  OFF %s\n         ON  %s\n", LN[i],
                    hex(off[i].owed).c_str(), hex(on[i].owed).c_str());
        check(off[i].owed == off[0].owed,
              "the gate-OFF control digest is lane-independent");
        check(on[i].owed == on[0].owed,
              "the gate-ON golden is lane-independent (E_b truncates to identical rows)");
        check(!(on[i].owed == off[i].owed),
              "the golden is non-vacuous on this lane too");
    }
    check(!(on[1].lane_digest == on[0].lane_digest),
          "the lanes DO differ in ridge geometry (BTC vs LTC lane digests differ)");

    // ── RIDGE-OWED-OWEDFREE ──────────────────────────────────────────────
    // The lane header is explicit that nr.coverage_blocks is economic policy
    // ND-R6 left OWED, pinned to W_default only so the mechanism runs, and
    // that the gate-ON golden must not be minted over it. Prove it was not.
    std::printf("\n-- RIDGE-OWED-OWEDFREE: the golden does not ride the OWED "
                "coverage_blocks --\n");
    std::printf("   shipped pin for BTC: coverage_blocks = %llu (== w_default_bins)\n",
                (unsigned long long)LaneParams::for_version(1, LaneKind::BTC).nr.coverage_blocks);
    for (u64 cov : COV_PROBE) {
        // strict=true: the settlement boundary must REFUSE an off-pin geometry,
        // so no off-pin coverage_blocks can reach the ledger in production.
        Run hard = drive(LaneKind::BTC, true, cov, true);
        check(hard.refused,
              "the settlement boundary refuses an off-pin coverage_blocks (strict)");
        // strict=false: the same schedule still reproduces the golden, because
        // d_net = 0 holds the width law and the coverage factor never reaches a
        // payout. The NRG1 lane digest, which does commit it, moves.
        Run soft = drive(LaneKind::BTC, true, cov, false);
        std::printf("   coverage_blocks=%-7llu owed %s   lane digest moved: %s\n",
                    (unsigned long long)cov,
                    hex(soft.owed) == GOLDEN_OWED_ON ? "== golden" : "MOVED",
                    (soft.lane_digest == on[0].lane_digest) ? "no" : "yes");
        check(!soft.refused && !soft.short_run,
              "the off-pin run completes when the seam is driven non-strict");
        check(hex(soft.owed) == GOLDEN_OWED_ON,
              "the golden is byte-identical under an off-pin coverage_blocks");
        check(!(soft.lane_digest == on[0].lane_digest),
              "the NRG1 lane digest does move with coverage_blocks (it commits it)");
        check(soft.shape.W == SHAPE_ON[0].W && soft.shape.retargets == SHAPE_ON[0].retargets,
              "the width law held at the lane default throughout (d_net = 0)");
    }

    std::printf("\n== kat_v371_ridge_owed_golden: %ld checks, %ld failures -> %s\n",
                g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    std::printf("gate_on_owed_digest=%s\n", hex(on[0].owed).c_str());
    std::printf("gate_off_owed_digest=%s\n", hex(off[0].owed).c_str());
    return g_fail ? 1 : 0;
}
