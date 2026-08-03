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
go run ./cmd/genkat  > mrr/testdata/kat1_vectors.json          # KAT-1: Geometry
go run ./cmd/genkat2 > mrr/testdata/kat2_buffer_vectors.json   # KAT-2: Buffer
```

`genkat2` asserts every hand-derived per-step disposition/sum/count/head before
it emits a vector, so a wrong implementation cannot mint a golden.

## Open items (flagged, non-blocking)

- The `Validate()` invariant SHAPE is frozen; the numeric magnitudes
  (`FoldRMax`, `FineMargin`, `WindowAbsMax`, and the per-dimension `Bounds`
  table) are Phase-0 defaults pending the §3.4 bounds table + Phase-2 simulator
  parameter-rationale memo. They are re-pinned there before any live wiring.
