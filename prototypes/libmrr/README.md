# libmrr — V37 MRR Roundabout engine (Go proto-repo)

Reference prototype of the V37 adaptive-dimensioning MRR engine. Proto/research
only — no live risk, no production wiring. Landing is held for the merge-tap.

## Status

- **Phase 0 — Geometry extraction: complete.** `mrr.Geometry` (the six dimensions
  + `Version` + `ActivationBin`), the 36-byte canonical little-endian encoding,
  SHA-256 `Hash()`, `Validate()` over the §1.1 structural invariants, and the
  `RetargetParams` / `EpochObservables` data types that pair with it. Geometry is
  static; no retarget behavior yet.
- **m2 Drop 1 — Roundabout buffer: complete.** `mrr.Buffer` (`buffer.go`): the
  bin-clock ring that ingests scored shares into the live PPLNS-style window.
  `Ingest(id, bin, weight)` reports `Accepted`/`Duplicate`/`Expired` (never a
  silent drop); the monotone bin-clock advances when a share sits ahead of the
  head and evicts exactly the bins that leave the window. Dedup is keyed on
  share identity across the whole window; expiry is `bin <= head - window`. The
  canonical `Digest()` is order-independent (commutative) over the accepted live
  set. KAT-2 golden vectors (`mrr/testdata/kat2_buffer_vectors.json`, two
  scenarios: `w6_roundabout_core`, `w16_sliding_window`) pin per-step
  disposition, head, live sum, live count, and digest. This is the front stage
  of the m1 settlement state machine (dedup / expiry / bin-clock-convergence
  invariants). **Not** in this drop: self-carry compaction (Drop 2) and the
  finality-gated owed/overlay ledger (Drop 3).
- **m2 Drop 2 — Self-carry compaction: complete.** `mrr.Ledger`
  (`compaction.go`): the deterministic fold from the buffer's position-indexed
  live work into a position-free, per-identity accrued balance. `Fold(id, w)`
  accrues integer weight; `Compact(cs)` builds a ledger from a contribution
  batch; `Merge` folds one ledger into another. "Self-carry" is the property
  that an identity's balance persists past window expiry — a small miner's
  sub-threshold work, spread thin and forever expiring out of the live window,
  is consolidated into one durable owed total rather than forfeited
  (small-miner-equity §6; the V36 failure this removes). The canonical
  `Digest()` is invariant to fold order and to how contributions are batched
  across sub-ledgers — **compact-then-digest == digest-then-compact** — since
  accrual is a commutative, associative integer add (proved by
  `TestLedger_CompactDigestCommute`: every rotation, reverse, weight-sorted
  order, and split-compact-then-merge cut hashes identically). A zero-weight
  fold is a no-op (no phantom entry). KAT-3 golden vectors
  (`mrr/testdata/kat3_compaction_vectors.json`, two scenarios:
  `small_miner_consolidation`, `carry_forward_many_ids`) pin per-step running
  total, distinct-identity count, digest, and the hand-derived final balances.
  `TestLedger_SelfCarryOutlivesBufferExpiry` cross-links Drop 1: the same stream
  fed to both stages agrees in-window, then the buffer live sum drops on
  eviction while the ledger total is unchanged. **Not** in this drop: any
  finality gating, block-found overlay, or owed→settled transition — that is the
  finality-gated owed/overlay ledger (Drop 3), a hard scope fence.
- **m2 Drop 3 — Finality-gated owed/overlay ledger: complete.** `mrr.Settlement`
  (`overlay.go`): the finality gate that turns owed work into paid work. State is
  three integer ledgers over one identity space — `owed` (accrued, un-earmarked),
  `pending` (earmarked to a found-but-not-final block's overlay, reversible), and
  `settled` (paid by a finalized block, irreversible) — with the conservation
  invariant `accrued == owed + pending + settled` (**I-CONSERVE**) held across
  every transition. The three block transitions of the m1 settlement state
  machine are weight moves that leave I-CONSERVE invariant:
  `BlockFound → OverlayAdded` (owed→pending), `BlockFinalized → OwedSettled +
  OverlayCleared` (pending→settled), `BlockOrphaned → OverlayReverted`
  (pending→owed). `Finalize(blockID, depth)` is the **symmetric finality-gate**
  (the round-4/5 conceded fix): a payout may not settle below `finalityK` (the
  same `Geometry.FinalityDepthK` that seals the work side) — `depth < K` returns
  `NotFinal` and moves nothing. Because Found only *moves* owed into a keyed
  overlay and Orphan moves the identical weight back, a found→orphaned round trip
  restores the prior digest bit-for-bit — the reorg-safety snapshot-revert
  property (`TestSettlement_RevertRoundTrip`); found order over disjoint
  identities commutes (`TestSettlement_FoundOrderCommutes`); a found overlay
  cannot draw more than an identity's owed and is rejected atomically
  (`TestSettlement_OverdrawRejectedAtomic`, `…NoDoubleSpendAcrossBlocks`); the
  owed base seeds from a Drop-2 `Ledger` (`NewSettlementFromLedger`, reading only
  its exported sorted accessors — Drop 2 is untouched). The canonical `Digest()`
  commits owed, settled, and every keyed pending overlay in ascending order,
  domain-separated from the buffer and ledger digests. KAT-4 golden vectors
  (`mrr/testdata/kat4_overlay_vectors.json`, three scenarios:
  `single_block_lifecycle`, `reorg_revert_roundtrip`,
  `concurrent_two_blocks_split_outcome`) pin per-step disposition, owed/pending/
  settled totals, digest, the hand-derived final owed/settled balances, and the
  snapshot-revert digest pairs; `cmd/genkat4` asserts all of that plus I-CONSERVE
  at every step before it will mint. **Not** in this drop: Phase-2 delegated-carry
  / carriage-liveness and the O(1) commit-root tail hybrid — hard-stop fences.
- Phases 1 (query-side decay) and 2 (pure `retarget()` + EMA + observables +
  offline simulator) are next, per the blueprint. Phase 3 (live adaptive
  dimensioning) is **v38-fenced** — hard stop.

## The Geometry record

Canonical 36-byte encoding, fields in struct order, little-endian, fixed-width,
no varints, no padding:

| offset | size | field             |
|--------|------|-------------------|
| 0      | 4    | version           |
| 4      | 8    | activation_bin    |
| 12     | 4    | window_bins       |
| 16     | 4    | epoch_bins        |
| 20     | 4    | half_life_bins    |
| 24     | 4    | fine_span_bins    |
| 28     | 4    | fold_r_bins       |
| 32     | 4    | finality_depth_k  |

`Hash()` = SHA-256 over the 36 bytes. This is the value shares commit to.

## Determinism

No floating point, no wall-clock, no locale, no map iteration in the geometry
path (enforced by `TestNoFloatingPoint`). Encode/decode/hash/validate are pure
integer operations. The KAT-1 golden vectors (`mrr/testdata/kat1_vectors.json`)
pin the byte layout and digests; any change to a golden hash is a
consensus-breaking change and must be deliberate.

## Build + test

```
go vet ./...
go test ./... -count=1
```

Regenerate the golden vectors on a reference build and review the diff:

```
go run ./cmd/genkat  > mrr/testdata/kat1_vectors.json               # KAT-1: Geometry
go run ./cmd/genkat2 > mrr/testdata/kat2_buffer_vectors.json        # KAT-2: Buffer
go run ./cmd/genkat3 > mrr/testdata/kat3_compaction_vectors.json    # KAT-3: Compaction
go run ./cmd/genkat4 > mrr/testdata/kat4_overlay_vectors.json       # KAT-4: Overlay
```

`genkat2` asserts every hand-derived per-step disposition/sum/count/head before
it emits a vector, so a wrong implementation cannot mint a golden. `genkat3`
does the same for compaction — per-step total/count/digest and the final
per-identity balances — and additionally asserts the commutativity invariant
(reverse, weight-sorted, and split-compact-then-merge all reproduce the
canonical digest) inside the generator before minting. `genkat4` asserts each
step's disposition/totals/digest, I-CONSERVE (owed+pending+settled == accrued)
at every step, the hand-derived final owed/settled sets, and each snapshot-revert
digest pair before minting.

## Open items (flagged, non-blocking)

- The `Validate()` invariant SHAPE is frozen; the numeric magnitudes
  (`FoldRMax`, `FineMargin`, `WindowAbsMax`, and the per-dimension `Bounds`
  table) are Phase-0 defaults pending the §3.4 bounds table + Phase-2 simulator
  parameter-rationale memo. They are re-pinned there before any live wiring.
