# V37.0 Phase-1 — TLA+ settlement / lane specs

Formal specs + TLC model-check harness for the c2pool V37.0 Phase-1 settlement
state machine. Runnable artifacts for the V37 prototyping line (off `master`).

## Modules

| file | what it models | check |
|------|----------------|-------|
| `Settlement.tla` | finality-gated owed/overlay state machine (revision 2: signed owed) -- `BlockFound→OverlayAdded` with a signed DROPS-composed credit row, `BlockFinalized→OwedSettled+OverlayCleared`, `BlockOrphaned→OverlayReverted`, `DeepOrphan→priced residual` | `Settlement.cfg` (full), `Settlement_small.cfg` (fast), `Settlement_noC4.cfg` / `Settlement_clawback.cfg` / `Settlement_nomass.cfg` (negative controls) |
| `Lanes.tla` | per-lane Push/Tick decay vs ground-truth windowed recompute; invariants I1 (dedup), I2 (mono), I3 (no-stale / acc-bounded / determinism), I4 (bin-clock) | `Lanes.cfg` (canonical), `Lanes_wide.cfg` (wider), `Lanes_free.cfg` (negative control) |

## Verified results

Settlement (`Settlement.cfg`, revision 2): **GREEN** -- no error, 606,013 distinct
states, depth 7. Invariants `TypeOK`, `KeyFloor` (per key `>= -KeyBound`),
`AggregateNonNeg`, `SettledImpliesFinalized`, `SettleOnce`, `Conservation` (signed,
per key, over the book of SETTLED records), `ResidualBound` (orphan after SETTLED);
action properties `MonoOnFinal`, `NoClawback`. Revision 1 (`NoNegativeOwed`,
`OverlayNeverExceedsOwed`) is withdrawn: it held only because a negative value could
not be expressed. What changed and why: `ERRATA.md`. The three negative controls each
yield a counterexample for their matching property.

Lanes (`Lanes.cfg`, λ=2/3): **GREEN** — no error, 4,368 distinct states, depth 15.
`Lanes_wide.cfg` (λ=1/2): GREEN, 2,132,609 states, depth 23.
`Lanes_free.cfg`: **intentionally VIOLATES `I3_Determinism`** — an 8-state
counterexample = the consensus split that arises when `EpochRenormalize` and
`EvictTail` may freely interleave under truncating fixed-point. The canonical
order (renorm-before-evict) is therefore a committed consensus rule. See
`Lanes-determinism-finding.md`.

## Run

TLC (any JRE 17+; `tla2tools.jar` not vendored — fetch from the TLA+ release):

```
java -cp tla2tools.jar tlc2.TLC -config Settlement.cfg     Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Settlement_small.cfg Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes.cfg          Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_wide.cfg     Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_free.cfg     Lanes.tla   # expect I3_Determinism violation
```

Owed-sign checks (revision 2: base-red, spec GREEN, three negative controls, two
reachability witnesses) in one go, one verdict line per run:

```
proto/tla/check-owed-sign.sh path/to/tla2tools.jar [out-dir]
```
