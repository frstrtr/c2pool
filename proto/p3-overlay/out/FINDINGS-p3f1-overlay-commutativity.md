# P3-F1 — overlay-commutativity: the P3-12 invariant, tested

Harness: `harness/p3f1_overlay_commutativity.py` · raw: `out/p3f1-overlay-commutativity.txt`
Deterministic: pure sha256/integer arithmetic, no RNG/clock. Golden sha256 stable across runs:
**`d0d495569a4ddd11604d8cdd119b590e17e527d8499b26bfaf8b1176a0c32ac8`**.

## Why
P3-F1 (the headline N>1 red-team finding) asserts the single finality-gated overlay is
order-sensitive across N aux-chains: two honest nodes observing the N event streams in different
orders (peer/network skew) compute different owed-ledgers → different `assemble()` coinbase →
different sharechain-block validity → **chain split**. The GLM prose pass is the assigned item but
GLM `.45:8090` is DOWN (TCP refused), so this closes the *prototype* leg the finding itself demands
(its "required fold" is exactly P3-12: feed K legal interleavings of one event multiset, assert
identical owed-ledger + coinbase). Same golden-vector style as M4 T17/T18.

## Model
State over MINERS, owed-ledger L, finality-gated overlay, remainder pot. One fixed event multiset:
`c0` FOUND-then-ORPHANED, `c1` FOUND-then-FINALIZED. Per-chain causal order (FOUND ≺ ORPHAN/FINALIZED
of the same (chain,block)) yields **6 legal interleavings**. Ground truth (order-independent): c0
reorged out, c1 final ⇒ `L = {m3:10}`, remainder 0. Compaction modelled as the real
small-miner-equity dust-sweep: owed `< TAU=3` is swept into the remainder pot — an **irreversible
rebase that drops per-(chain,block) attribution**. `m2`'s c0-share (2) is sub-threshold, so it is
sweep-eligible *only while c0 is pending* — that is the hazard surface.

## Result — three revert semantics over all 6 interleavings

| semantics | distinct L | commutative | verdict |
|---|---|---|---|
| **B1 SNAPSHOT_WHOLE** — ORPHAN restores a whole-ledger snapshot ("restore pre-FOUND owed", literal) | 2 | **NO** | wipes interleaved cross-chain events |
| **B2 SNAPSHOT_DELTA** — ORPHAN subtracts the stale FOUND-time absolute delta | 2 | **NO** | dust-sweep folds pending c0 → stale delta misfires |
| **FIX KEYED_CRDT** — per-(chain,block) pending multiset; compact FINALIZED-only; ORPHAN = key removal | 1 | **YES** | == ground truth across all 6 → **P3-12 GREEN** |

### B1 counterexample (no compaction needed)
Orders where `c1.FOUND` falls inside the `c0.FOUND … c0.ORPHAN` window restore a snapshot taken
before `c1` existed → `c1`'s 10 is wiped: `{m3:0}` vs the correct `{m3:10}`. Two honest orders,
two ledgers, two coinbases (`4f53cda1…` vs `4035aa22…`).

### B2 counterexample (the subtle one — compaction is the trigger)
The smallest divergence is the finding's exact attack `c0.FOUND; c1.FOUND; c1.FINALIZED; c0.ORPHAN`:
- `c1.FINALIZED` dust-sweeps `m2:2` (still pending from c0, sub-threshold) into the remainder pot;
- `c0.ORPHAN` subtracts the **absolute** stale δ0 `{m1:6,m2:2}` from a ledger where m2 is already 0
  → `m2 = -2`, with `R_pot = 2` floating: `{m2:-2, m3:10, R_pot:2}`, coinbase `dd841f31…`.
- Orders where c0 is reverted *before* c1 compacts give the clean `{m3:10}`, coinbase `4035aa22…`.

Same multiset, two honest observation orders, divergent owed-ledger and coinbase = the chain-split.

## The fix (KEYED_CRDT) and the invariant it tests
Represent the overlay as a **per-(chain,block)-keyed pending multiset**; FINALIZE moves a key into a
monotonic finalized partition; ORPHAN deletes its key. Rendered `L = finalized-equity + Σ pending`.
Because ADD/FINALIZE/ORPHAN act on **distinct keys**, the final partition of keys into
{pending, finalized, reverted} is a pure function of the event multiset, independent of interleaving
— a commutative monoid / CRDT. Verified: identical L and coinbase across all 6 interleavings, equal
to ground truth.

**The decisive compaction invariant (prompt Q3, now demonstrated necessary):** *only finalized
contributions may be compacted.* B2 violates it (sweeps pending c0) and splits; FIX restricts the
dust-sweep to the finalized partition, so no still-pending contribution is ever folded and every
revert stays well-defined and order-independent. Necessity is shown by the B2 counterexample;
sufficiency follows from key-disjointness of the operations.

## Recommendation (prompt Q6)
**(A) prove-commutative-and-implement-CRDT is sound AND simpler than (B) pin-canonical-ordering** for
Phase-1: the keyed-multiset formulation needs no cross-chain total-order key, no per-chain finality-
height tie-break, and no consensus dependence on observation order. Pin into consensus:
- **I-OC1** overlay = per-(chain,block)-keyed signed-contribution multiset (no whole-ledger or
  absolute-delta snapshots);
- **I-OC2** ORPHAN(c,b) = delete key (c,b); FINALIZE(c,b) = move key to the finalized partition;
- **I-OC3** compaction (self-carry / dust-sweep / remainder-pot) acts ONLY on the finalized
  partition — never folds a pending contribution;
- **I-OC4 (P3-12)** for any legal interleaving of a fixed event multiset, final owed-ledger and
  assembled coinbase are identical.

## Scope / honesty
- Pins the SAFETY (order-invariance) of the revert/compaction rule, not a perf claim. Models N=2 with
  one block each; the keyed-disjointness argument generalises to N chains / many blocks (distinct
  keys), but a TLA+ model-check over the unbounded interleaving space is the residual obligation
  (Q6 open question) — fold alongside the M1 Settlement spec, not a standalone PR.
- Does not yet exercise F2 (two-anchor revert-then-reanchor) or F4 (cross-denomination remainder).
  KEYED_CRDT is *necessary* for both (a reanchor is a new key; the remainder pot is already a single
  deterministic sink) but each needs its own golden vector — queued.
- Consistent with the F1 triage: divergence corrupts only the non-final tip; `OwedSettled` fires at
  `BlockFinalized` (depth ≥ D_f). The harness pins that the *overlay arithmetic* never diverges in
  the first place, removing the split surface rather than relying on finality depth to mask it.

## Fold target (HELD — no push from the bridge)
I-OC1..I-OC4 + this golden vector fold into the P3 testbed-design doc's matrix (the P3-12 row) and
cross-reference the M1 Settlement spec, landing on `frstrtr/the` at the batched M1–M4 merge-checkpoint
when the push-hold lifts — GPG-signed, zero attribution, from the workstation. Harness code lands on
the `v37-dev` prototype line at the same checkpoint. Nothing pushed from the bridge. The GLM prose
pass remains queued for when `.45` returns — it can only *corroborate* a result the prototype has now
made deterministic.
