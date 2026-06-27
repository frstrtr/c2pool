# T13 — checkpoint cadence vs finality-lag (M4 ⟂ M1 finality gate)

Reproduce: `cd proto/m4-sync/harness && python3 t13_checkpoint_finality_lag.py`
Raw: `out/t13-finality-lag-w50k.txt`. Closes the README NEXT item ("the checkpoint
must lag finality depth so a checkpoint is never committed over a reorg-able tip").

## The seam

T8 made the on-chain live-set checkpoint the lever that bounds trustless cold-start to
`O(W·(1+f·C))`. T9/T12 proved the *serving* layer safety-unconditional: a stateless
verifier canonical-rebuilds the served live-set and checks it against the committed
root, so a fully-sybil serving layer can deny progress but never corrupt state.

That proof has a **hidden premise: the committed root must itself be canonical.** If
consensus commits a checkpoint over a tip that a later reorg orphans, the committed
root describes a live-set on a dead branch. A cold validator trustlessly anchoring to
it rebuilds a head on the orphaned branch — and the T9 serving-layer argument does not
save it, because the *commitment* is wrong, not the server. This is exactly where M4
touches M1's finality gate (`BlockFound→OverlayAdded`, `BlockFinalized→OwedSettled`,
`BlockOrphaned→OverlayReverted`).

## Model

`D_f` = finality depth (the same parameter M1's overlay settles on). Reorg depth
`d ∈ [0..D_f]` rewrites the last `d` rounds. Checkpoint lag `L` = consensus commits the
live-set as of round `(tip − L)`. A depth-`d` reorg leaves the committed height `(T−L)`
canonical **iff** `L ≥ d`. Simulated with the real Utreexo forest: a canonical chain and
a per-`d` orphan branch that shares history up to `(max_d − d)` then diverges with
different share ids.

## Result — the safety diagonal

```
  d\L    L=0   L=1   L=2   L=4   L=8   L=12
    1   ORPH   ok    ok    ok    ok    ok
    2   ORPH  ORPH   ok    ok    ok    ok
    4   ORPH  ORPH  ORPH   ok    ok    ok
    8   ORPH  ORPH  ORPH  ORPH   ok    ok
```

Exactly `L ≥ d → ok`, `L < d → orphaned anchor` (10 orphan events = the lower triangle).
A checkpoint at lag `L` is safe against every reorg of depth `≤ L` and unsafe against any
deeper one. There is no probabilistic grey zone: orphan ⇔ the committed height sits in the
rewritten span.

## The rule

**Commit only finalized prefixes: `L ≥ D_f`.** This reuses M1's finality gate verbatim — a
checkpoint is the `BlockFinalized`/`OwedSettled`-side read of the same overlay the lane
settles on, so `BlockOrphaned` can never touch a committed checkpoint because the checkpoint
trails finality. No new mechanism: the superlight checkpoint and the settlement overlay are
gated on one and the same finality depth.

## The cost — additive, not asymptotic

The lag adds a staleness tail: cold-start delta = `(C + L)` rounds, so trustless egress =
`O(W·(1 + f·(C+L)))`. At `f=10%`, `C=5`, `L=D_f=8`: total delta `+1.3×` the W-leaf floor vs
`+0.5×` at lag-0 — a `+0.8×` one-time egress premium per cold-start, bounded, no new
asymptotic. Cadence `C` bounds the delta; finality lag `D_f` bounds safety; they compose
additively. Pick `C ≤ (k−1)/f − D_f` to keep total delta `≤ k·W`.

## Design feed (→ `v37-superlight-chain-synthesis.md`)

Checkpoint = `{≤8 forest roots + 1 shard-root}` (T9/T12) **committed at depth `≥ D_f` behind
the tip** (T13). Safety needs zero honest servers (T9) *and* a finality-lagged commitment
(T13); cadence is a pure liveness/egress knob. The checkpoint is now fully pinned to the
M1 finality gate — same depth, same overlay.
