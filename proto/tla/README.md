# V37.0 Phase-1 — TLA+ settlement / lane specs

Formal specs + TLC model-check harness for the c2pool V37.0 Phase-1 settlement
state machine. Runnable artifacts for the V37 prototyping line (off `master`).

## Modules

| file | what it models | check |
|------|----------------|-------|
| `Settlement.tla` | finality-gated owed/overlay state machine (revision 2: signed owed) -- `BlockFound→OverlayAdded` with a signed DROPS-composed credit row, `BlockFinalized→OwedSettled+OverlayCleared`, `BlockOrphaned→OverlayReverted`, `DeepOrphan→priced residual` | `Settlement.cfg` (full), `Settlement_small.cfg` (fast), `Settlement_noC4.cfg` / `Settlement_clawback.cfg` / `Settlement_nomass.cfg` (negative controls) |
| `Lanes.tla` | per-lane Push/Tick decay vs ground-truth windowed recompute; invariants I1 (dedup), I2 (mono), I3 (no-stale / acc-bounded / determinism), I4 (bin-clock) | `Lanes.cfg` (canonical), `Lanes_wide.cfg` (wider), `Lanes_free.cfg` (negative control) |
| `SettlementCanon.tla` | the XMR lane ledger under the every-node coinbase recompute (`docs/xmr-lane/coinbase-recompute.md`): a canonical block books its credit and payouts, a mismatch is booked debit-only (payouts debited, credit dropped), an undecidable block is held; the pay-in-block allocation in abstract form with the drain rule of the operator rulings of 2026-10-02 (pay-now first: the window credited and paid at P = R - debt_paid; old balances paid only out of Delta = min(F, R * min(dh, HCap) div DrainQ); contested slots follow cash, K_o from the first owed pass; DEBT FIRST removed; redistribution as a credit delta; no advance, no claim without cash); `DrainQ = 0` is master's allocation | `SettlementCanon.cfg` (the rule, one slot), `SettlementCanon_ko.cfg` (contested slots, K_o), `SettlementCanon_noslot.cfg` (no payee slot), `SettlementCanon_master.cfg` (master, DrainQ = 0), `SettlementCanon_len3.cfg` (three blocks, long), `check-settlement-canon.sh` (negative controls, witnesses) |
| `PathBRatchet.tla` | the Path B rules ratchet: a committed ratchet state S (epoch_cur, rules_cur, work tallies, a window-level journal) folded by `rs_step`; nodes on different releases derive every quantity (base, open, locked, E_impl, H_hold, the attempt states, the ballot) from (S, position, their compiled table), build until H_hold and then hold; 13 invariants — `SameActivation`, `PrefixEImpl`, `FollowerNeverDiverges`, `HoldOnlyOnConfirmedLockIn`, `NoSpuriousHold`, `ActiveEqualsHoldTrigger`, `JoinerAgreesWithFollower`, `RsRootIsFunctionOfChain`, `GraceFromLockIn`, `OneOpenDeployment`, `OneOpenAcrossReleases`, `ReProposalOpen`, `BoundedState` | `G_A_n22` / `G_S_n22` / `G_B_n24` / `G_BS_n24` (GREEN, all 13); the `C*` controls and `P_*` probes (each violates one named invariant); the `W_*` witnesses (reachability); `check-ratchet.sh` runs the per-PR set, `TLC_LONG=1` adds `G_T_adv2_n18` and `G_M_n38` |
| `PathBSealRNP.tla` | the Path B settlement / seal state machine: carriers chain through tip pointers, each carrying a canonically-ordered list of receipt ids; a height record = max carrier height over a chain prefix; a carried bin opens at the carrier's parent record; bins fold after F confirmations and seal after Dfin; a per-node verdict (defer / accept / refuse) and the `Agreement` invariant, plus the eight seal invariants, `ChainRuledValid` and `RecordIsCarrierMax` | `V1_rnp_own_n2r4` / `V1_rnp_carriage_n2r4` (GREEN), `V1_rnp_neg_openlocal` / `V1_rnp_neg_omitlocal` (`Agreement`), `V1_rnp_nodead` (`LegallyDead`), `V1_rnp_sharechain` (`OrphanRecovered`), `V1_rnp_probe_order` / `V1_rnp_probe_closed` (single-check witnesses); `check-seal-rnp.sh` |

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

SettlementCanon, with the drain rule of the operator rulings of 2026-10-02
(`SettlementCanon.cfg`: Reward 4, DrainQ 4, HCap 2, one slot): **GREEN** — no error,
3,051,279 distinct states, depth 6. `SettlementCanon_ko.cfg` (three keys, two slots,
the contested branch and K_o): GREEN, 29,688 distinct states, depth 4.
`SettlementCanon_noslot.cfg`: GREEN, 61,636 distinct states, depth 7.
`SettlementCanon_master.cfg` (DrainQ = 0, master's allocation with DEBT FIRST): GREEN,
239,444 distinct states, depth 7, the count of the model before the rule on the same
config (the former `SettlementCanon_debt.cfg`). `SettlementCanon_len3.cfg` (three
blocks, so a block is booked on a finalized predecessor; Reward 3, DrainQ 3): GREEN,
61,514,884 distinct states, depth 10.
Invariants `TypeOK`, `Conservation`, `NonCanonicalEarnsNothing`,
`UnpaidKeyNeverNegative`, `RedistributionNeutral` (now against the window's credit at
P), `LedgerWithinFloat`, `NoClaimWithoutCash`, `HonestIsCanonical`, `UndecidableHeld`,
and new `NoNewOwed` (a canonical block never raises a balance) and `PayNowWithinWindow`
(B6); action properties `NoAdvance`, `CanonicalNeverNegative`, and new
`FloatNonIncreasing` (no step raises an EffectiveOwed), `DrainBound` (debt paid <=
Delta(dh) <= F), `SlotShare` (contested: the owed keys hold at most K_o slots, K_o from
the first owed pass), `SomeoneAdmitted` ("nobody admitted" unreachable with two or more
slots) and `MasterWhenNoFloat` (F = 0 gives master's payouts and credit). "Negative"
means: a canonical block never makes a balance negative and never deepens a debt; a
debit-only block may drive the key it paid negative (that key carries the payment as a
debt, by design), so `UnpaidKeyNeverNegative` covers the keys no debit-only block paid.
Solvency: no block credits more than it pays to keys, so the outstanding total never
exceeds the genesis float. The redistribution moves cash and credit together whenever
the block has a payee output; when the admitted payees' credit at P sums to 0 the cash
goes to the payees the owed pass paid (operator ruling 2026-10-02).
Each change of the rule has a negative control that the named property catches:
DEBT FIRST kept (`NoNewOwed`, `FloatNonIncreasing`), the window credited at R
(`NoNewOwed`), the owed pass on the whole block (`DrainBound`), no K_o (`SlotShare`,
`SomeoneAdmitted`), the unclamped slice taken off the window (`MasterWhenNoFloat`);
`HCap = DrainQ` breaks `SomeoneAdmitted`, which is why the lane rules require
`drain_h_cap < drain_q * 16`. Master itself breaks `NoNewOwed` (its short pool leaves a
window payee a balance). The nine negative controls of the model before the rule
(eleven runs) are kept and still caught, and the reachability witnesses show the checked
states include a drain payment, a window credited at P < R, a K_o cut, master's
debt-first step, a key driven negative by a debit-only block, a held block, a
redistribution and the moved cash going to the payees the owed pass paid. The model
before the rule found the nobody-admitted case of the redistribution (the cash went to
the donation output while the waiting payees lost their credit; see
`MODELCHECK-RESULTS.md`). `check-settlement-canon.sh` reruns all 35 runs;
`MODELCHECK-RESULTS.md` has the table.

## Run

TLC (any JRE 17+; `tla2tools.jar` not vendored — fetch from the TLA+ release):

```
java -cp tla2tools.jar tlc2.TLC -config Settlement.cfg     Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Settlement_small.cfg Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes.cfg          Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_wide.cfg     Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_free.cfg     Lanes.tla   # expect I3_Determinism violation
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon.cfg        SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_ko.cfg     SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_master.cfg SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_noslot.cfg SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_len3.cfg   SettlementCanon.tla   # long
proto/tla/check-settlement-canon.sh path/to/tla2tools.jar [out-dir]   # all SettlementCanon runs
TLC_LONG=1 proto/tla/check-settlement-canon.sh path/to/tla2tools.jar  # plus SettlementCanon_len3.cfg
```

Ratchet and seal (one verdict line per run; exit 0 only if every run matches
its expectation). `check-ratchet.sh` runs the per-PR configs (model values
L 4 / GRACE 6 / TIMEOUT 9 / EPOCH_MAX 3; a few minutes); `TLC_LONG=1` adds the
longer `G_T_adv2_n18` and `G_M_n38` runs (minutes to ~1 h):

```
proto/tla/check-ratchet.sh  path/to/tla2tools.jar [out-dir]
TLC_LONG=1 proto/tla/check-ratchet.sh path/to/tla2tools.jar
proto/tla/check-seal-rnp.sh path/to/tla2tools.jar [out-dir]
```

The `.github/workflows/tla-model-check.yml` lane runs both scripts on every PR
that touches `proto/tla/**` (a pinned, sha256-verified `tla2tools.jar`).

Owed-sign checks (revision 2: base-red, spec GREEN, three negative controls, two
reachability witnesses) in one go, one verdict line per run:

```
proto/tla/check-owed-sign.sh path/to/tla2tools.jar [out-dir]
```
