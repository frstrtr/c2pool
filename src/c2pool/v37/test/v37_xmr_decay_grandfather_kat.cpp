// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_decay_grandfather_kat -- RULES RATCHET R1, R-MIN (d): a row decays
// by the schedule of the epoch in force when it went dormant (spec sec. 7 (d),
// TLA NoOwedReductionByRatchet).
//
//   A row of key k goes dormant under epoch 1 (arm_floor F, horizon 4, half-
//   life 2) at bin g: it halves at g + 4, g + 6, g + 8 ... A synthetic epoch 2
//   (horizon 12, half-life 6: slower) is locked in and the RATCHET applied
//   after g. The row keeps epoch 1's write-off sequence -- bin for bin, amount
//   for amount, equal to a control ledger that never ratcheted -- while a row
//   that goes dormant AFTER the event follows epoch 2's schedule. The event
//   itself moves no balance (SUM finalW before == after). The V37K row carries
//   u32 sched_epoch: the two ledgers' digests differ by it alone where the
//   schedules differ. A ledger WITHOUT a table (BTC / DASH) writes no
//   sched_epoch (byte-identical V37K rows to before).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>

namespace settle = c2pool::v37n::settle;
using ::v37::bytes32;
using ::v37::u64;
using Amounts = settle::OwedLedger::Amounts;

namespace {
int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...) do { const bool _ok = (cond); ++g_checks; if (!_ok) ++g_fail; \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); std::printf(__VA_ARGS__); std::printf("\n"); } while (0)

bytes32 b32(std::uint8_t seed) { bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(seed + i); return b; }

constexpr long long F = 1000;   // arm_floor: a balance below it is dust that decays when passed by

settle::OwedLedgerRules epoch1() { settle::OwedLedgerRules r; r.arm_floor = F; r.decay_horizon = 4; r.decay_half_life = 2; return r; }
settle::OwedLedgerRules epoch2() { settle::OwedLedgerRules r; r.arm_floor = F; r.decay_horizon = 12; r.decay_half_life = 6; return r; }

settle::LedgerEpochTable table(bool with2) {
    settle::LedgerEpochTable t = settle::genesis_epoch_table(b32(0x33), epoch1());
    if (with2) { settle::EpochRow r2; r2.epoch_no = 2; r2.rules_digest = b32(0x44); r2.kind = 1; r2.state = settle::EpochState::Defined; r2.rules = epoch2(); t.rows.push_back(r2); }
    return t;
}

const bytes32 K = b32(0x01);     // the dormant row
const bytes32 M = b32(0x02);     // the miner every block credits (so the dust is "passed by")
const bytes32 N = b32(0x03);     // a row that goes dormant AFTER the event

long long owed(const settle::OwedLedger& L, const bytes32& k) { const auto m = L.effective_owed_all(); auto it = m.find(k); return it == m.end() ? 0 : it->second; }
long long sum(const settle::OwedLedger& L) { long long s = 0; for (const auto& [k, v] : L.effective_owed_all()) { (void)k; s += v; } return s; }

// A lane block at bin `h` crediting M (and optionally K / N); found + finalized at once.
void block(settle::OwedLedger& L, u64 h, bool credit_k = false, bool credit_n = false) {
    Amounts c{{M, 50000}};
    if (credit_k) c[K] = 700;   // below the floor: dust
    if (credit_n) c[N] = 600;
    const std::string bid = "b" + std::to_string(h);
    L.on_block_found(bid, c, {});
    L.on_block_finalized(bid, h);
}

void run() {
    std::printf("== R-MIN (d): the dormant row keeps epoch 1's write-off sequence across the RATCHET ==\n");
    settle::OwedLedger control(7, table(false));   // never ratchets
    settle::OwedLedger ratch(7, table(true));      // ratchets to epoch 2 after the row went dormant
    // bin 10: K credited (dust 700) -- its clock is not running (it was credited)
    block(control, 10, true); block(ratch, 10, true);
    // bin 11: a block that credits only M: K is "passed by": gone_since = 11, sched_epoch = 1
    block(control, 11); block(ratch, 11);
    CHECK(owed(control, K) == 700 && owed(ratch, K) == 700, "bin 11: K dormant with 700 on both ledgers");
    CHECK(ratch.sched_epoch_of(K) && *ratch.sched_epoch_of(K) == 1 && !control.sched_epoch_of(K).has_value() == false,
          "the ratchet ledger recorded sched_epoch 1 for K (the control ledger: epoch 1 too)");
    CHECK(control.owed_digest() == ratch.owed_digest(), "before the event the two ledgers are byte-identical (same table state, same rows)");
    // the event: lock in epoch 2 at bin 12 (h_L 12, H_act 13), apply at once (the rig's cursor is there)
    const long long before = sum(ratch);
    CHECK(ratch.lock_in_epoch(2, 12, 13) && ratch.apply_ratchet(2) && ratch.epoch_cur() == 2 && ratch.rules().decay_horizon == 12,
          "epoch 2 (horizon 12, half-life 6) locked in and applied");
    CHECK(sum(ratch) == before && owed(ratch, K) == 700, "NoOwedReductionByRatchet: the event moved no balance (SUM %lld)", before);
    // epoch 1's schedule for K: gone 11, horizon 4 -> first halving due at 15 (700 -> 350), then 17 (175), 19 (87), 21 (43) ...
    const u64 bins[] = {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
    const long long want[] = {700, 700, 700, 350, 350, 175, 175, 87, 87, 43, 43, 21, 21, 10};
    bool same = true;
    for (std::size_t i = 0; i < sizeof(bins) / sizeof(bins[0]); ++i) {
        block(control, bins[i]); block(ratch, bins[i]);
        const long long c = owed(control, K), r = owed(ratch, K);
        if (c != want[i] || r != want[i]) { same = false; std::printf("    bin %llu: control %lld ratchet %lld want %lld\n", (unsigned long long)bins[i], c, r, want[i]); }
    }
    CHECK(same, "bins 12..25: K halves at 15, 17, 19, 21, 23, 25 on BOTH ledgers (epoch 1's horizon 4 / half-life 2), never epoch 2's (first halving at 23)");
    CHECK(control.decayed_total() == ratch.decayed_total() && ratch.decayed_total() == 700 - 10, "the same total written off (%lld)", ratch.decayed_total());
    // a row that goes dormant AFTER the event follows epoch 2's schedule: credited at 26, passed by at 27, horizon 12 -> first halving at 39
    block(control, 26, false, true); block(ratch, 26, false, true);
    block(control, 27); block(ratch, 27);
    CHECK(ratch.sched_epoch_of(N) && *ratch.sched_epoch_of(N) == 2 && control.sched_epoch_of(N) && *control.sched_epoch_of(N) == 1,
          "N dormant at 27: sched_epoch 2 on the ratchet ledger, 1 on the control");
    bool n_ok = true;
    for (u64 h = 28; h <= 45; ++h) {
        block(control, h); block(ratch, h);
        // control (epoch 1): first halving at 31 (600 -> 300), 33, 35 ...; ratchet (epoch 2): first at 39 (300), then 45 (150)
        const long long want_c = h < 31 ? 600 : h < 33 ? 300 : h < 35 ? 150 : h < 37 ? 75 : h < 39 ? 37 : h < 41 ? 18 : h < 43 ? 9 : h < 45 ? 4 : 2;
        const long long want_r = h < 39 ? 600 : h < 45 ? 300 : 150;
        if (owed(control, N) != want_c || owed(ratch, N) != want_r) { n_ok = false; std::printf("    bin %llu: control N %lld (want %lld) ratchet N %lld (want %lld)\n", (unsigned long long)h, owed(control, N), want_c, owed(ratch, N), want_r); }
    }
    CHECK(n_ok, "N follows epoch 2's slower schedule on the ratchet ledger (halves at 39, 45) and epoch 1's on the control (31, 33, 35 ...)");
    // the digest commits sched_epoch per V37K row: the two ledgers differ (and would even with equal balances)
    CHECK(control.owed_digest() != ratch.owed_digest(), "the digests differ (V37Y epoch 2 vs 1, V37K rows carry sched_epoch)");
    // a ledger WITHOUT a table writes no sched_epoch: its V37K row is 48 B (key | gone | steps), the XMR one 52 B
    settle::OwedLedger plain(7, epoch1());
    block(plain, 10, true); block(plain, 11);
    CHECK(!plain.sched_epoch_of(K).has_value() && plain.epochs() == nullptr, "a ledger without a table records no sched_epoch (BTC / DASH: V37K unchanged)");
    // the clock START uses the CURRENT epoch's arm_floor: a balance below epoch 2's floor but above epoch 1's would only start under epoch 2
    settle::LedgerEpochTable t3 = table(true);
    t3.rows[1].rules.arm_floor = 5000;   // epoch 2 raises the floor
    settle::OwedLedger hi(7, t3);
    block(hi, 10, true, false);          // K = 700 < 1000: dust under epoch 1 too
    Amounts big{{M, 1}, {N, 3000}};      // N = 3000: not dust under epoch 1 (floor 1000), dust under epoch 2 (floor 5000)
    hi.on_block_found("x10", big, {}); hi.on_block_finalized("x10", 10);
    block(hi, 11);
    CHECK(hi.sched_epoch_of(K) && !hi.sched_epoch_of(N).has_value(), "epoch 1 in force: K (700) starts its clock, N (3000) does not (above epoch 1's floor)");
    CHECK(hi.lock_in_epoch(2, 12, 13) && hi.apply_ratchet(2), "ratchet to epoch 2 (floor 5000)");
    block(hi, 13);
    CHECK(hi.sched_epoch_of(N) && *hi.sched_epoch_of(N) == 2 && *hi.sched_epoch_of(K) == 1,
          "epoch 2 in force: N (3000 < 5000) starts its clock under epoch 2's floor; K keeps epoch 1");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_decay_grandfather_kat (RULES RATCHET R1, R-MIN (d): decay grandfathered by the epoch at gone_since) ===\n");
    run();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
