# V37.0 Phase-1 — TLA+ settlement / lane specs

Formal specs + TLC model-check harness for the c2pool V37.0 Phase-1 settlement
state machine. Runnable artifacts for the V37 prototyping line (off `master`).

## Modules

| file | what it models | check |
|------|----------------|-------|
| `Settlement.tla` | finality-gated owed/overlay state machine (revision 2: signed owed) -- `BlockFound→OverlayAdded` with a signed DROPS-composed credit row, `BlockFinalized→OwedSettled+OverlayCleared`, `BlockOrphaned→OverlayReverted`, `DeepOrphan→priced residual` | `Settlement.cfg` (full), `Settlement_small.cfg` (fast), `Settlement_noC4.cfg` / `Settlement_clawback.cfg` / `Settlement_nomass.cfg` (negative controls) |
| `Lanes.tla` | per-lane Push/Tick decay vs ground-truth windowed recompute; invariants I1 (dedup), I2 (mono), I3 (no-stale / acc-bounded / determinism), I4 (bin-clock) | `Lanes.cfg` (canonical), `Lanes_wide.cfg` (wider), `Lanes_free.cfg` (negative control) |
| `PathBRatchet.tla` | the Path B rules ratchet: a committed ratchet state S (epoch_cur, rules_cur, work tallies, a window-level journal) folded by `rs_step`; nodes on different releases derive every quantity (base, open, locked, E_impl, H_hold, the attempt states, the ballot) from (S, position, their compiled table), build until H_hold and then hold; 13 invariants — `SameActivation`, `PrefixEImpl`, `FollowerNeverDiverges`, `HoldOnlyOnConfirmedLockIn`, `NoSpuriousHold`, `ActiveEqualsHoldTrigger`, `JoinerAgreesWithFollower`, `RsRootIsFunctionOfChain`, `GraceFromLockIn`, `OneOpenDeployment`, `OneOpenAcrossReleases`, `ReProposalOpen`, `BoundedState` | `G_A_n22` / `G_S_n22` / `G_B_n24` / `G_BS_n24` (GREEN, all 13); `P_overlap36_MT` (GREEN; layout MT: a re-proposal starts at or after timeout + GRACE of every earlier attempt of its epoch number, except an attempt that ends at `R1To` (gated by `Release`); the layout is a start-up `ASSUME` (`SpacedAcross`)); the `C*` controls and `P_*` probes (each violates one named invariant; `P_overlap28_MS`: layout MS, the re-proposal of epoch 2 at the earlier attempt's timeout); the `W_*` witnesses (reachability); every GREEN run has a floor on distinct states and depth; `check-ratchet.sh` runs the per-PR set, `TLC_LONG=1` adds `G_T_adv2_n18`, `G_M_n38` and `G_MT_n40` |
| `PathBSealRNP.tla` | the Path B settlement / seal state machine: carriers chain through tip pointers, each carrying a canonically-ordered list of receipt ids; a height record = max carrier height over a chain prefix; a carried bin opens at the carrier's parent record; bins fold after F confirmations and seal after Dfin; a per-node verdict (defer / accept / refuse) and the `Agreement` invariant, plus the eight seal invariants, `ChainRuledValid` and `RecordIsCarrierMax` | `V1_rnp_own_n2r4` / `V1_rnp_carriage_n2r4` (GREEN, with a floor on distinct states and depth), `V1_rnp_neg_openlocal` / `V1_rnp_neg_omitlocal` (`Agreement`), `V1_rnp_nodead` (`LegallyDead`), `V1_rnp_sharechain` (`OrphanRecovered`), `V1_rnp_probe_order` / `V1_rnp_probe_closed` (single-check witnesses); `check-seal-rnp.sh` |

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

Ratchet and seal (one verdict line per run; exit 0 only if every run matches
its expectation). `check-ratchet.sh` runs the per-PR configs (model values
L 4 / GRACE 6 / TIMEOUT 9 / EPOCH_MAX 3; about 16 minutes on 4 workers); `TLC_LONG=1` adds the
longer `G_T_adv2_n18`, `G_M_n38` and `G_MT_n40` runs (about 95 minutes in all).
A GREEN run passes only with no error, an empty queue, and at least the distinct
state count and depth on its line in the script; a model change that shrinks a
space lowers that number in the same PR:

```
proto/tla/check-ratchet.sh  path/to/tla2tools.jar [out-dir]
TLC_LONG=1 proto/tla/check-ratchet.sh path/to/tla2tools.jar
proto/tla/check-seal-rnp.sh path/to/tla2tools.jar [out-dir]
```

The `.github/workflows/tla-model-check.yml` lane runs both scripts on every PR
that touches `proto/tla/**` (a pinned, sha256-verified `tla2tools.jar`), and
nightly and on manual dispatch with `TLC_LONG=1`.

Owed-sign checks (revision 2: base-red, spec GREEN, three negative controls, two
reachability witnesses) in one go, one verdict line per run:

```
proto/tla/check-owed-sign.sh path/to/tla2tools.jar [out-dir]
```
