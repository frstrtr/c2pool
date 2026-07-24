# V37 MRR reference prototype (M2)

Slow reference + golden-vector source for the MRR roundabout-buffer scaled-frame
accumulator. Built fresh from the normative spec
(`c2pool-v37-mrr-roundabout-buffer.md`); the prior `v37-mrr-buffer` C++ branch is
not present on the bridge — reconcile against it if/when it surfaces.

## Files
- `mrr_ref.py` — scaled-frame per-miner decay accumulator + OQ-2 epoch exact-rebuild,
  at consensus precision (Q62 truncating, errata E-1).
- `gen_golden.py` — emits `golden/mrr_accumulator_v0.json`; checks P1 determinism,
  P2 OQ-2 re-convergence, P3 renorm-vs-rebuild residual.
- `settlement_kfair_ref.py` — owed-ledger + K_fair payout SELECTION. K_fair sort-key is
  `(first_eligible_height ASC, miner_id ASC)` — owed-height-first (F1, ratified 2026-06-27).
- `gen_golden_settlement.py` — emits `golden/settlement_kfair_v0.json`; composes K_fair
  selection with the finality-gated overlay (Settlement.tla); checks D1/F1/G/V.

## K_fair golden vectors (F1)
- D1 determinism (bit-identical replay): **PASS**
- F1 owed-height-first, every block (no fairness inversion, no idle slot while eligible): **PASS**
- G finality-gate (EffectiveOwed never negative; mirrors NoNegativeOwed / OverlayNeverExceedsOwed): **PASS**
- V value conservation (credited == still-owed + paid): **PASS**
- F1 checker is non-vacuous: an inversion (younger-owed paid over older) and an idle-slot-while-eligible
  case both trip `check_owed_height_first`. Selection order is itself consensus-relevant (fixes coinbase
  output ordering for the F2 full-output-set / soft-fork-offset commitment location).

## Status (v0)
- P1 determinism (bit-identical replay): **PASS**
- P2 epoch-boundary exact-rebuild: 3 boundaries captured
- P3 renorm drift (the path OQ-2 rejects): ~3.4e-14 relative/epoch — within the
  spec's ≲2^-63-per-op residual claim; motivates the mandatory rebuild.

## OPEN (flag for M3 spec-consolidation, not a prototype blocker)
- **Canonical decay-table generation procedure.** §8.2 mandates an integer-only,
  LN2_MICRO-anchored construction "specified in the protocol doc" — that exact routine
  is not reproduced in the corpus on this bridge. The table here is ONE documented
  integer construction (self-consistent; the OQ-2 property holds for any fixed table).
  The canonical base must be pinned before golden vectors are consensus-authoritative.
- **§8 body says Q*.64; errata E-1 pins 62 fractional bits.** Prototype follows E-1.
  Fold the wording fix into the canonical doc in M3.

## Next (M2 continuation)
- Add self-carry compaction (bucket fold, level rings R=8) + eviction golden vectors.
- Add finality-gated overlay vectors (BlockFound→OverlayAdded / Finalized / Orphaned),
  cross-checked against the M1 Settlement.tla transitions.
- Port the validated core to C++ once vectors are canonical (table base pinned).
