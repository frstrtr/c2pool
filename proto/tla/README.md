# V37.0 Phase-1 — TLA+ settlement / lane specs

Formal specs + TLC model-check harness for the c2pool V37.0 Phase-1 settlement
state machine. Runnable artifacts for the V37 prototyping line (off `master`).

## Modules

| file | what it models | check |
|------|----------------|-------|
| `Settlement.tla` | finality-gated owed/overlay state machine — `BlockFound→OverlayAdded`, `BlockFinalized→OwedSettled+OverlayCleared`, `BlockOrphaned→OverlayReverted` | `Settlement.cfg` (full), `Settlement_small.cfg` (fast) |
| `Lanes.tla` | per-lane Push/Tick decay vs ground-truth windowed recompute; invariants I1 (dedup), I2 (mono), I3 (no-stale / acc-bounded / determinism), I4 (bin-clock) | `Lanes.cfg` (canonical), `Lanes_wide.cfg` (wider), `Lanes_free.cfg` (negative control) |
| `SettlementCanon.tla` | the XMR lane ledger under the every-node coinbase recompute (`docs/xmr-lane/coinbase-recompute.md`): a canonical block books its credit and payouts, a mismatch is booked debit-only (payouts debited, credit dropped), an undecidable block is held; the pay-in-block allocation (owed pass, same-fraction pay-now, debt first, redistribution as a credit delta, no advance, no claim without cash) in abstract form | `SettlementCanon.cfg` (full), `SettlementCanon_debt.cfg` (debt-first branch), `SettlementCanon_noslot.cfg` (no payee slot), `check-settlement-canon.sh` (negative controls, witnesses) |

## Verified results

Settlement (`Settlement.cfg`): **GREEN** — no error, 87,885 distinct states,
depth 10. Invariants `TypeOK`, `NoNegativeOwed`, `OverlayNeverExceedsOwed`,
`SettledImpliesFinalized`, `MonoOnFinal`, `Conservation` (per-miner no-robbery),
`SettleOnce`. Two real bugs found + fixed en route: scalar-credit inflation
(credit must be a per-miner vector) and tip-truncation un-burying finalized
blocks (reorg modelled as same-height swap, not truncation).

Lanes (`Lanes.cfg`, λ=2/3): **GREEN** — no error, 4,368 distinct states, depth 15.
`Lanes_wide.cfg` (λ=1/2): GREEN, 2,132,609 states, depth 23.
`Lanes_free.cfg`: **intentionally VIOLATES `I3_Determinism`** — an 8-state
counterexample = the consensus split that arises when `EpochRenormalize` and
`EvictTail` may freely interleave under truncating fixed-point. The canonical
order (renorm-before-evict) is therefore a committed consensus rule. See
`Lanes-determinism-finding.md`.

SettlementCanon (`SettlementCanon.cfg`): **GREEN** — no error, 2,534,260 distinct
states, depth 9. `SettlementCanon_debt.cfg`: GREEN, 239,444 distinct states, depth 6.
`SettlementCanon_noslot.cfg`: GREEN, 39,028 distinct states, depth 6.
Invariants `TypeOK`, `Conservation`, `NonCanonicalEarnsNothing`,
`UnpaidKeyNeverNegative`, `RedistributionNeutral`, `LedgerWithinFloat`,
`NoClaimWithoutCash`, `HonestIsCanonical`, `UndecidableHeld`; action properties
`NoAdvance`, `CanonicalNeverNegative`. "Negative" now means: a canonical block never
makes a balance negative and never deepens a debt; a debit-only block may drive the key
it paid negative (that key carries the payment as a debt, by design), so
`UnpaidKeyNeverNegative` covers the keys no debit-only block paid. Solvency: no block
credits more than it pays to keys, so the outstanding total never exceeds the genesis
float. The redistribution moves cash and credit together whenever the block has a payee
output; with nobody admitted the cash goes to the payees the owed pass paid (operator
ruling 2026-10-02). This model found that case: the code cut the waiting payees' credit
and sent the cash to the donation output; the companion change on branch
`fix/xmr-redistribute-nobody-admitted` fixed it (see `MODELCHECK-RESULTS.md`). Nine
negative controls each yield a counterexample, among them the old rule
(`redistribute_to_nobody`) and keeping the credit while the cash goes to the donation
(`keep_credit_unbacked`, `degenerate_keep_credit`). Five reachability witnesses show the
checked states include a key driven negative by a debit-only block, a redistribution, a
held block, the debt-first step, and the moved cash going to the payees the owed pass
paid. `check-settlement-canon.sh` reruns all of them.

## Run

TLC (any JRE 17+; `tla2tools.jar` not vendored — fetch from the TLA+ release):

```
java -cp tla2tools.jar tlc2.TLC -config Settlement.cfg     Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Settlement_small.cfg Settlement.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes.cfg          Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_wide.cfg     Lanes.tla
java -cp tla2tools.jar tlc2.TLC -config Lanes_free.cfg     Lanes.tla   # expect I3_Determinism violation
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon.cfg      SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_debt.cfg SettlementCanon.tla
java -cp tla2tools.jar tlc2.TLC -config SettlementCanon_noslot.cfg SettlementCanon.tla
proto/tla/check-settlement-canon.sh path/to/tla2tools.jar [out-dir]   # all SettlementCanon runs
```
