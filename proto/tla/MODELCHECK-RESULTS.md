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
implements (`docs/xmr-lane/coinbase-recompute.md`, `payout-threshold.md` §3): a
canonical block books its credit and payouts, a mismatch is booked debit-only
(payouts debited, credit dropped), an undecidable block is held, and the pay-in-block
allocation (owed pass, same-fraction pay-now, debt first, redistribution as a credit
delta, no advance) is a function every node evaluates at the booking point. Ported from
the `SettlementCanon.tla` of the closed #1883 (canonical / payout-only booking) and
adapted to these rules.

```
run:              settlement-canon-2026-10-02
date:             2026-10-02 (01:32:35 to 01:33:48, UTC+4), workstation
tool:             TLC2 Version 2.19 of 08 August 2024 (rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:              OpenJDK 25.0.4.1, 6 workers, -Xmx8g, breadth-first
model sha256:     SettlementCanon.tla a33483d76475fe446f35eee464392f1a943533587a8a6e455b7526e9c9f823a1
config sha256:    SettlementCanon.cfg 1baf50eaaded24d78f0c576ed32e9ab2eeb1496346689408e50ba84b38132e4a
                  SettlementCanon_debt.cfg 0e8f5465a98f7101bcc178fec5184acd30f8b4d30b715bb567f7fdb41e8ec855
config:           Miners={m1,m2} Reward=2 SeedMax=1 Cap=1 OwedCap=1 FINALITY_DEPTH=1
                  MaxChainLen=3 Mutation="none"
debt config:      the same with Reward=3 Cap=2 MaxChainLen=2
invariants:       TypeOK Conservation NonCanonicalEarnsNothing UnpaidKeyNeverNegative
                  HonestIsCanonical UndecidableHeld
properties:       NoAdvance CanonicalNeverNegative
result:           Model checking completed. No error has been found. (both configs)
states:           3713380 states generated, 2534260 distinct states found, 0 states left on queue.
debt states:      305124 states generated, 239444 distinct states found, 0 states left on queue.
depth:            9 and 6 with one worker (the plain README commands); 6 workers report 10 and 7
```

Companion runs (same tool and jar; `check-settlement-canon.sh` reproduces all of them).
A counterexample run stops at the first violation, so its distinct-state count varies
from run to run with 6 workers; the trace length does not.

| run | change | expected | result | trace |
|---|---|---|---|---|
| mut-foreign-credit | `Mutation = "foreign_credit"`: a debit-only block keeps its window credit | counterexample | `Invariant NonCanonicalEarnsNothing is violated.` | 3 states |
| mut-authority | `"authority"`: no verdict, a mismatch is booked like a canonical block | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` (a block pays a key with no balance and no credit) | 3 states |
| mut-authority-cnn | the same, `CanonicalNeverNegative` checked alone | counterexample | `Action property CanonicalNeverNegative is violated.` | 6 states |
| mut-advance | `"advance"`: the redistributed cash is paid but not credited | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-advance-na | the same, `NoAdvance` checked alone | counterexample | `Action property NoAdvance is violated.` | 3 states |
| mut-debt-unbounded | `"debt_unbounded"` on `SettlementCanon_debt.cfg`: the debt pass ignores owed_left | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-held-debit | `"held_debit"`: an undecidable block is booked debit-only | counterexample | `Invariant HonestIsCanonical is violated.` | 3 states |
| mut-nogate | `"nogate"`: the builder assembles before the tip is booked | counterexample | `Invariant HonestIsCanonical is violated.` (the #1861 double pay, booked debit-only) | 6 states |
| wit-negative | witness `owed[m] >= 0` | counterexample (reachability) | `Invariant WitNoNegative is violated.` (a debit-only block paid 2 to a key with 1) | 6 states |
| wit-redistribution | witness: canonical credit = E_b | counterexample (reachability) | `Invariant WitNoRedistribution is violated.` | 3 states |
| wit-held | witness: no block is held | counterexample (reachability) | `Invariant WitNoHeld is violated.` | 2 states |
| wit-credit-cut | witness: canonical credit sums to the sum of E_b | counterexample (reachability) | `Invariant WitCreditKept is violated.` | 3 states |
| wit-debt-first | witness on `SettlementCanon_debt.cfg`: the debt step pays nothing | counterexample (reachability) | `Action property WitNoDebtFirst is violated.` | 3 states |

What "negative" means in this model: a canonical block never makes a balance negative
and never deepens a debt (`CanonicalNeverNegative`); a debit-only block may drive the key
it paid negative, and that key carries the payment as a debt (forward repair, by design;
`wit-negative`). `UnpaidKeyNeverNegative` therefore covers the keys no debit-only block
paid, both their finalized balance and their EffectiveOwed.

Observation from `wit-credit-cut`. One payee slot, a seeded balance on key A, and a
block of 2 units whose window credits only key B (E_b = 1). The owed pass pays A its 1
and takes the only slot; B has no slot and waits, so nobody is admitted. The
redistribution then still takes the 1 unit left off B's credit, but `prorata` over the
admitted payees' zero weight gives it to nobody, so the unit stays in the residual (the
donation output) and B's work earns nothing in that block. This is what `x6::allocate_exact_sum` does when the
owed pass fills every slot and no payee of the window has an owed output; its
`credit_delta` then sums to minus the moved amount, not to zero as the comment in
`xmr_coinbase.hpp` states. Every node computes the same delta, so it is not a fork; it
is an economic edge (reachable only when the owed pass fills the whole output cap) worth
a ruling.

Not modelled: the spend floor c (no dust class, no A8 dust pass), the V37N owed base,
reorgs below FINALIZE (`Settlement.tla`), and the share rule (V37R), which is the same
recompute applied to a share.
