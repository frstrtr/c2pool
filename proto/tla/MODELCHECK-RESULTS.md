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
