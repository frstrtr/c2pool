# M1 finding — EvictTail / EpochRenormalize canonical-ordering determinism bug

Status: CONFIRMED in TLA+ (Lanes.tla), FIXED by canonical-order pin, prototype parity verified.
Scope: V37.0 Phase-1, Ledger #1 (MRR roundabout buffer) lane accumulator.

## The bug
The lane maintains an incremental scaled-frame accumulator `scaledW`. At an epoch/bin
boundary two transitions become enabled simultaneously:

- `EpochRenormalize`: `scaledW := floor(scaledW * NUM/DEN)`   (multiply the whole aggregate by lambda)
- `EvictTail`: `scaledW := scaledW - <expiring contribution>` (a share crosses age W and leaves the window)

Under truncating fixed-point these operations DO NOT COMMUTE:

    floor((A - B) * lambda)  !=  floor(A * lambda) - floor(B * lambda)   (in general)

Counterexample A=2, B=1, lambda=2/3:
- evict-then-renorm: floor((2-1) * 2/3) = floor(2/3) = 0
- renorm-then-evict: floor(2 * 2/3) - floor(1 * 2/3) = 1 - 0 = 1

If both actions are independently enabled, two honest nodes can fire them in different
orders and derive a DIFFERENT `scaledW` from the SAME committed chain state -> different
owed/credit vector -> different coinbase transaction -> sharechain CONSENSUS SPLIT.
This is invisible to Settlement.tla, which trusts `credit` as a deterministic function of
committed state; it is exactly the faithfulness gap M1 exists to close.

Note: lambda = 1/2 (a power-of-two denominator) never exhibits the divergence, which is why
the earlier fused-Tick model (NUM=1, DEN=2) did not surface it. The hazard is reachable only
for non-dyadic lambda; the spec is now checked at lambda = 2/3.

## The fix — canonical order
Pin a single canonical order: `EpochRenormalize` fires BEFORE `EvictTail` at every boundary.
In Lanes.tla this is the `CONSTANT CanonicalOrder`: when TRUE, `EvictTail` is guarded by
`pendR = FALSE`, forcing the renorm to discharge first, so every eviction subtracts its
contribution evaluated in the post-renorm frame. The incremental `scaledW` then lands
deterministically on the ghost `canon` (the renorm-then-evict-in-new-frame value).

`I3_Determinism == Settled => scaledW = canon` is the consensus invariant.

## Model-check results (TLC, tla2tools 2026.05.26)
- Lanes_free.cfg (CanonicalOrder=FALSE, lambda=2/3): I3_Determinism VIOLATED. 8-state trace
  is the A=2,B=1,lambda=2/3 counterexample (EvictTail at age-W value, then EpochRenormalize:
  scaledW -> 0; canonical value = 1).
- Lanes.cfg (CanonicalOrder=TRUE, lambda=2/3): No error. 4,368 distinct states, depth 15.
  TypeOK, I1_Dedup, I2_Mono, I3_NoStale, I3_Determinism, I4_BinClock, I_FrameSettled all hold.
- Lanes_wide.cfg (CanonicalOrder=TRUE, lambda=1/2, W=3/MaxWeight=4/MaxShares=5/MaxClock=6):
  No error. 2,132,609 distinct states, depth 23. Same invariant set holds.

## Prototype parity — src/sharechain/v37/v37_lane.hpp
Already canonical, verified against origin/v37-dev. `push()` applies the operations in the
pinned order:
- step (1): `epoch_rebuild()` (renormalize) when `m_next_pos - m_B == epoch_len()`
- step (5): `evict_oldest_bucket()` while `m_cover > window`
so renorm precedes evict within a push. Furthermore `epoch_rebuild()` recomputes each bucket
`w_scaled = w_raw * decay[depth]` exact-per-share, and eviction removes WHOLE buckets, so the
aggregate never performs `floor((A - B) * lambda)`. The C++ matches the spec's canonical order;
there is no latent ordering bug in the prototype. The canonical order is now a NORMATIVE
consensus rule (carry to M3 spec-consolidation as a committed clause).
