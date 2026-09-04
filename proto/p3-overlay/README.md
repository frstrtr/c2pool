# V37 P3-F1 — KEYED_CRDT owed-ledger overlay commutativity harness

Executable proof of the P3-F1 fix: the owed-ledger overlay as a KEYED_CRDT is
commutative across all legal revert/finalize interleavings, for all three revert
semantics considered (the interleaving enumeration that killed the ordered-log
design). Prototype code on the v37 design track — no consensus code, no coupling
to `src/`.

## Run

```
python3 harness/p3f1_overlay_commutativity.py
```

Deterministic (no wall-clock, no unseeded RNG). Expected: all interleaving
classes PASS for the KEYED_CRDT overlay; the harness also demonstrates the
counterexample for the non-keyed baseline. Reference output from the original
local run is kept in `out/p3f1-overlay-commutativity.txt`; findings prose in
`out/FINDINGS-p3f1-overlay-commutativity.md`.

## Relations

- Consumed by `proto/p3-testbed` (the multichain settlement acceptance rows),
  which composes this overlay semantics with K_fair selection.
- The corresponding settlement model is `proto/tla/Settlement.tla` (the
  TLC-green M1 settlement spec).
