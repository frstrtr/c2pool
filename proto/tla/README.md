# V37.0 Phase-1 — TLA+ settlement / lane specs

Formal specs + TLC model-check harness for the c2pool V37.0 Phase-1 settlement
state machine. Runnable artifacts for the V37 prototyping line (off `master`).

## Modules

| file | what it models | check |
|------|----------------|-------|
| `Settlement.tla` | finality-gated owed/overlay state machine — `BlockFound→OverlayAdded`, `BlockFinalized→OwedSettled+OverlayCleared`, `BlockOrphaned→OverlayReverted` | `Settlement.cfg` (full), `Settlement_small.cfg` (fast) |
| `Lanes.tla` | per-lane Push/Tick decay vs ground-truth windowed recompute; invariants I1 (dedup), I2 (mono), I3 (no-stale / acc-bounded / determinism), I4 (bin-clock) | `Lanes.cfg` (canonical), `Lanes_wide.cfg` (wider), `Lanes_free.cfg` (negative control) |
| `SettlementCanon.tla` | the XMR lane ledger under the every-node coinbase recompute (`docs/xmr-lane/coinbase-recompute.md`): a canonical block books its credit and payouts, a mismatch is booked debit-only (credit dropped, payouts debited net of each key's window credit at the cut: lane rule 31 noncanon_net), an undecidable block is held; the pay-in-block allocation in abstract form with the drain rule of the operator rulings of 2026-10-02 (pay-now first: the window credited and paid at P = R - debt_paid; old balances paid only out of Delta = min(F, R * min(dh, HCap) div DrainQ); contested slots follow cash, K_o from the first owed pass; DEBT FIRST removed; redistribution as a credit delta; no advance, no claim without cash); `DrainQ = 0` is master's allocation | `SettlementCanon.cfg` (the rule, one slot), `SettlementCanon_ko.cfg` (contested slots, K_o), `SettlementCanon_noslot.cfg` (no payee slot), `SettlementCanon_master.cfg` (master, DrainQ = 0), `SettlementCanon_len3.cfg` (three blocks, long), `check-settlement-canon.sh` (negative controls, witnesses) |

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
Lane rule 31 (`noncanon_net`, G9 review O6): a debit-only block debits only what a key
was paid above its window credit at the block's cut, so `WindowPaidKeyNeverNegative`
(every config) covers every key no debit-only block paid above that credit;
`NonCanonicalEarnsNothing` is stated as credit <= min(E, pay); the booking before the
rule (`Mutation = "debit_all"`) is its negative control. The state counts above are
unchanged by the rule.
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
