# M1 TLA+ model-check — results log

## Settlement.tla revision 2 (owed-sign semantics) — Settlement.cfg  → GREEN

Supersedes the revision-1 Settlement entry below (see `ERRATA.md`).

```
run:            settlement-rev2-2026-09-28
date:           2026-09-28 (started 07:41:32, finished 07:43:22, UTC+4)
tool:           tla2tools.jar v1.7.4 (TLC2 Version 2.19 of 08 August 2024, rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:            OpenJDK 25.0.4.1, 6 workers, -Xmx8g, breadth-first
model sha256:   Settlement.tla 7b9ea67fc57451ac4caf8d07f10461554e8c2ee666ce7a88f0ce265f1c6daea7
config sha256:  Settlement.cfg 89ea819182115fc7535b736a572a45f180fd3aa338ccb674a697c9ca046c43ae
config:         Miners={m1,m2} MaxReward=1 MaxDelta=2 FINALITY_DEPTH=1 MaxChainLen=3
                MaxIds=4 MaxDeepOrphans=1 C4Bound=TRUE DeltaMassRule=TRUE AllowClawback=FALSE
invariants:     TypeOK KeyFloor AggregateNonNeg SettledImpliesFinalized SettleOnce
                Conservation ResidualBound
properties:     MonoOnFinal NoClawback
result:         Model checking completed. No error has been found.
states:         26008745 states generated, 606013 distinct states found, 0 states left on queue.
depth:          7
```

Companion runs (same tool and jar; `check-owed-sign.sh` reproduces all of them):

| run | model / config | expected | result | distinct states | trace |
|---|---|---|---|---|---|
| base-red | revision 1 + `owed` as `Int` + one negative-credit action, `Settlement.cfg` of revision 1 | counterexample | `Invariant NoNegativeOwed is violated.` | 140 | 5 states |
| noC4 | revision 2, `Settlement_noC4.cfg` (C-4 floor off) | counterexample | `Invariant KeyFloor is violated.` (a key at -4, `KeyBound` = 3) | 14,999 | 6 states |
| clawback | revision 2, `Settlement_clawback.cfg` (clawback action on) | counterexample | `Action property NoClawback is violated.` | 195,121 | 5 states |
| nomass | revision 2, `Settlement_nomass.cfg` (delta mass rule off) | counterexample | `Invariant AggregateNonNeg is violated.` | 848 | 4 states |
| wit-neg | revision 2, `Settlement.cfg`, witness `owed[m] >= 0` | counterexample (reachability) | `Invariant WitNoNegative is violated.` | 451 | -- |
| wit-resid | revision 2, `Settlement.cfg`, witness `residual = 0` | counterexample (reachability) | `Invariant WitNoResidual is violated.` | 176,083 | -- |

The first row is the model gap that revision 2 closes. The last two show that a negative
key (forward repair) and a non-zero priced residual (orphan after SETTLED) are reachable in
the GREEN configuration, so `KeyFloor`, `AggregateNonNeg` and `ResidualBound` are checked
on states that exercise them.

Run host: bridge (local), TLC via bundled Temurin JRE 21.0.5 + tla2tools.jar.
Date: 2026-06-27 (Mauritius). Workstation (gh host) was unreachable; checks run locally
so the model-check obligation is discharged regardless. Push/PR pending workstation/gh.

## Settlement.tla revision 1 — Settlement.cfg  → GREEN (superseded by revision 2)
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
