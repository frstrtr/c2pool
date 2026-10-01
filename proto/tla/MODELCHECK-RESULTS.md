# M1 TLA+ model-check — results log

Run host: bridge (local), TLC via bundled Temurin JRE 21.0.5 + tla2tools.jar.
Date: 2026-06-27 (Mauritius). Workstation (gh host) was unreachable; checks run locally
so the model-check obligation is discharged regardless. Push/PR pending workstation/gh.

## Settlement.tla — Settlement.cfg  → GREEN
Finality-gated owed/overlay ledger (Ledger #2). Transitions BlockFound→OverlayAdded,
BlockFinalized→OwedSettled+OverlayCleared, BlockOrphaned→OverlayReverted.
Invariants checked: TypeOK, finality-gate safety, overlay = derived ancestry fn, idempotent settle.
Result: 1,010,277 states generated, 87,885 distinct, 0 on queue. No error.

## Lanes.tla — Lanes.cfg (CanonicalOrder = TRUE)  → GREEN
In-window decayed-weight roundabout (Ledger #1). Lane invariants I1_Dedup, I2_Mono,
I3_NoStale, I3_Determinism, I4_BinClock, I_FrameSettled.
Result: 5,313 states generated, 4,368 distinct, 0 on queue. Depth 15. No error.

## Lanes.tla — Lanes_free.cfg (CanonicalOrder = FALSE)  → EXPECTED COUNTEREXAMPLE
Free interleaving of EpochRenormalize / EvictTail under truncating fixed-point.
Result: I3_Determinism VIOLATED. scaledW = 2 while canon = 1 (floor((A-B)*2/3) vs
floor(A*2/3)-floor(B*2/3); A=2,B=1). 853 states generated, 797 distinct.
This is the consensus-split path; the canonical-order fix (Lanes.cfg, GREEN) eliminates it.

## Verdict
The round-5 standing TLA+ obligation is discharged: settlement safety holds, the lane
determinism bug is demonstrated REAL under free order and PROVEN-FIXED under canonical order.

## SettlementCanon.tla — the lane coinbase recompute → GREEN

The ledger of `Settlement.tla` under the every-node coinbase recompute that master
implements (`docs/xmr-lane/coinbase-recompute.md`, `payout-threshold.md` §3): a canonical
block books its credit and payouts, a mismatch is booked debit-only (payouts debited,
credit dropped), an undecidable block is held, and the pay-in-block allocation (owed
pass, same-fraction pay-now, debt first, redistribution as a credit delta, no advance) is
a function every node evaluates at the booking point. The redistribution follows the
operator ruling of 2026-10-02 (below). Ported from the `SettlementCanon.tla` of the
closed #1883 (canonical / payout-only booking) and adapted to these rules.

```
run:              settlement-canon-2026-10-02
date:             2026-10-02 (01:57:54 to 02:01:03, UTC+4), workstation
tool:             TLC2 Version 2.19 of 08 August 2024 (rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:              OpenJDK 25.0.4.1, 6 workers, -Xmx8g, breadth-first
model sha256:     SettlementCanon.tla 199265d40e4c0cec2e61db55603567b9ff605730d359ee0c01b73cd5402987f2
config sha256:    SettlementCanon.cfg 2a448bda56f75ebd2de7a8178967066913134e95242692550bfd6ef7c79ec920
                  SettlementCanon_debt.cfg fa32931ec98512e7c88c2ec17b4830b5b75f298974ca3d2d16eb0d776dc91978
                  SettlementCanon_noslot.cfg fcf816625d9741481ad2d1355d90a1bbf23cc7cfe11909e7184d72adaf74961c
config:           Miners={m1,m2} Reward=2 SeedMax=1 Cap=1 OwedCap=1 FINALITY_DEPTH=1
                  MaxChainLen=3 Mutation="none"
debt config:      the same with Reward=3 Cap=2 MaxChainLen=2
noslot config:    the same with Cap=0 MaxChainLen=2 (no slot for any payee)
invariants:       TypeOK Conservation NonCanonicalEarnsNothing UnpaidKeyNeverNegative
                  RedistributionNeutral LedgerWithinFloat NoClaimWithoutCash
                  HonestIsCanonical UndecidableHeld
properties:       NoAdvance CanonicalNeverNegative
result:           Model checking completed. No error has been found. (all three configs)
states:           3713380 states generated, 2534260 distinct states found, 0 states left on queue.
debt states:      305124 states generated, 239444 distinct states found, 0 states left on queue.
noslot states:    50020 states generated, 39028 distinct states found, 0 states left on queue.
depth:            9, 6 and 6 with one worker (the plain README commands); 6 workers report 10, 7, 7
```

Companion runs (same tool and jar; `check-settlement-canon.sh` reproduces all of them).
A counterexample run stops at the first violation, so its distinct-state count varies
from run to run with 6 workers; the trace length does not.

| run | change | expected | result | trace |
|---|---|---|---|---|
| unreach-main | `Mutation = "degenerate_keep_credit"` on `SettlementCanon.cfg` | no error | `No error has been found.` (2,534,260 distinct states: with a slot the degenerate case is unreachable) | -- |
| unreach-debt | the same on `SettlementCanon_debt.cfg` | no error | `No error has been found.` (239,444 distinct states) | -- |
| mut-foreign-credit | `"foreign_credit"`: a debit-only block keeps its window credit | counterexample | `Invariant NonCanonicalEarnsNothing is violated.` | 3 states |
| mut-authority | `"authority"`: no verdict, a mismatch is booked like a canonical block | counterexample | `Invariant LedgerWithinFloat is violated.` (a block credits its window and pays nothing) or `Invariant UnpaidKeyNeverNegative is violated.` (a block pays a key with no balance); both 3-state paths exist, the first found wins | 3 states |
| mut-authority-cnn | the same, `CanonicalNeverNegative` checked alone | counterexample | `Action property CanonicalNeverNegative is violated.` | 6 states |
| mut-advance | `"advance"`: the redistributed cash is paid but not credited | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-advance-na | the same, `NoAdvance` checked alone | counterexample | `Action property NoAdvance is violated.` | 3 states |
| mut-debt-unbounded | `"debt_unbounded"` on `SettlementCanon_debt.cfg`: the debt pass ignores owed_left | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-redist-nobody | `"redistribute_to_nobody"`: the rule before the ruling; with nobody admitted the waiting credit comes off and the cash goes to the residual | counterexample | `Invariant RedistributionNeutral is violated.` | 3 states |
| mut-keep-unbacked | `"keep_credit_unbacked"`: with nobody admitted nothing moves; the waiting payees keep their credit, the cash goes to the residual | counterexample | `Invariant LedgerWithinFloat is violated.` (the ledger goes from 1 to 2) | 3 states |
| mut-degenerate-keep | `"degenerate_keep_credit"` on `SettlementCanon_noslot.cfg`: the same, only with no payee output at all | counterexample | `Invariant LedgerWithinFloat is violated.` | 3 states |
| mut-held-debit | `"held_debit"`: an undecidable block is booked debit-only | counterexample | `Invariant HonestIsCanonical is violated.` | 3 states |
| mut-nogate | `"nogate"`: the builder assembles before the tip is booked | counterexample | `Invariant HonestIsCanonical is violated.` (the #1861 double pay, booked debit-only) | 6 states |
| wit-negative | witness `owed[m] >= 0` | counterexample (reachability) | `Invariant WitNoNegative is violated.` (a debit-only block pays a key more than its balance; the key ends at -1) | 6 states |
| wit-redistribution | witness: canonical credit = E_b | counterexample (reachability) | `Invariant WitNoRedistribution is violated.` | 3 states |
| wit-held | witness: no block is held | counterexample (reachability) | `Invariant WitNoHeld is violated.` | 2 states |
| wit-leftover-to-owed | witness: nobody admitted never moves cash to the payees the owed pass paid | counterexample (reachability) | `Action property WitNoLeftoverToOwed is violated.` | 3 states |
| wit-debt-first | witness on `SettlementCanon_debt.cfg`: the debt step pays nothing | counterexample (reachability) | `Action property WitNoDebtFirst is violated.` | 3 states |

What "negative" means in this model: a canonical block never makes a balance negative
and never deepens a debt (`CanonicalNeverNegative`); a debit-only block may drive the key
it paid negative, and that key carries the payment as a debt (forward repair, by design;
`wit-negative`). `UnpaidKeyNeverNegative` therefore covers the keys no debit-only block
paid, both their finalized balance and their EffectiveOwed.

Solvency. Every coinbase pays all its cash out, to keys or to the residual (the donation
output), so a balance is backed only by a block that paid its cash to a key.
`NoClaimWithoutCash` says no booked block credits more in total than it pays to keys;
`LedgerWithinFloat` says the outstanding total (finalized balances plus the pending net
of booked blocks) never exceeds the genesis float. `RedistributionNeutral` says a
canonical block with a payee output books exactly its window credit in total
(`credit_delta` sums to zero). A block with no payee output can only arise with no slot
for any payee (`Cap = 0` here, `cap_owed = 0` in the code); `unreach-main` and
`unreach-debt` show it is unreachable in the other two configs.

Found and fixed: the redistribution with nobody admitted. The first version of this
model checked `x6::allocate_exact_sum` as it was, and its witness `wit-credit-cut` found
this case: one payee slot, a seeded balance on key A, and a block of 2 units whose window
credits only key B. The owed pass pays A and takes the only slot; B has no slot and
waits, so nobody is admitted. The redistribution then took the cash left off B's credit,
but `prorata` over the admitted payees' zero weight gave it to nobody, so it stayed in
the residual: B's work earned nothing in that block and `credit_delta` summed to minus
the moved amount. Keeping B's credit instead (`keep_credit_unbacked`) is no fix: the cash
still goes to the donation output and the claim has nothing behind it. Operator ruling
2026-10-02: the moved cash goes to the payees the owed pass paid in this block, pro rata
to what it paid them, merged into their outputs (no new slot) and credited to them in the
same amount, while the waiting payees' credit comes off as before; cash and credit move
together. Only with no payee output at all does no cash move: the waiting payees' credit
still comes off and the cash stays in the residual (`degenerate_keep_credit`, which keeps
that credit, breaks `LedgerWithinFloat`). The companion code change on branch
`fix/xmr-redistribute-nobody-admitted` implements this in
`src/impl/xmr/settle/xmr_coinbase.cpp` (KAT F2e in `v37_xmr_spend_floor_kat`), and the
model carries the same rule.

Not modelled: the spend floor c (no dust class, no A8 dust pass), the V37N owed base,
reorgs below FINALIZE (`Settlement.tla`), and the share rule (V37R), which is the same
recompute applied to a share.
