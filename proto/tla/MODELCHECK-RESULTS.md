# M1 TLA+ model-check — results log

Run host: bridge (local), TLC via bundled Temurin JRE 21.0.5 + tla2tools.jar.
Date: 2026-06-27 (Mauritius). Workstation (gh host) was unreachable; checks run locally
so the model-check obligation is discharged regardless. Push/PR pending workstation/gh.

## Settlement.tla — Settlement.cfg  → GREEN
Finality-gated owed/overlay ledger (Ledger #2). Transitions BlockFound→OverlayAdded,
BlockFinalized→OwedSettled+OverlayCleared, BlockOrphaned→OverlayReverted.
Invariants checked: TypeOK, finality-gate safety, overlay = derived ancestry fn, idempotent settle.
Result: 1,010,277 states generated, 87,885 distinct, 0 on queue. No error.

## Lanes.tla — Lanes.cfg (CanonicalOrder = TRUE)  → GREEN
In-window decayed-weight roundabout (Ledger #1). Lane invariants I1_Dedup, I2_Mono,
I3_NoStale, I3_Determinism, I4_BinClock, I_FrameSettled.
Result: 5,313 states generated, 4,368 distinct, 0 on queue. Depth 15. No error.

## Lanes.tla — Lanes_free.cfg (CanonicalOrder = FALSE)  → EXPECTED COUNTEREXAMPLE
Free interleaving of EpochRenormalize / EvictTail under truncating fixed-point.
Result: I3_Determinism VIOLATED. scaledW = 2 while canon = 1 (floor((A-B)*2/3) vs
floor(A*2/3)-floor(B*2/3); A=2,B=1). 853 states generated, 797 distinct.
This is the consensus-split path; the canonical-order fix (Lanes.cfg, GREEN) eliminates it.

## Verdict
The round-5 standing TLA+ obligation is discharged: settlement safety holds, the lane
determinism bug is demonstrated REAL under free order and PROVEN-FIXED under canonical order.

## SettlementCanon.tla — the lane coinbase recompute → GREEN

(The model of `9f8a6178d`, master's allocation before the drain rule. The section after
this one supersedes it for the module as it is now; its `SettlementCanon_master.cfg`
is this section's `SettlementCanon_debt.cfg` and reproduces its state counts.)

The ledger of `Settlement.tla` under the every-node coinbase recompute that master
implements (`docs/xmr-lane/coinbase-recompute.md`, `payout-threshold.md` §3): a canonical
block books its credit and payouts, a mismatch is booked debit-only (payouts debited,
credit dropped), an undecidable block is held, and the pay-in-block allocation (owed
pass, same-fraction pay-now, debt first, redistribution as a credit delta, no advance) is
a function every node evaluates at the booking point. The redistribution follows the
operator ruling of 2026-10-02 (below). Ported from the `SettlementCanon.tla` of the
closed #1883 (canonical / payout-only booking) and adapted to these rules.

```
run:              settlement-canon-2026-10-02
date:             2026-10-02 (01:57:54 to 02:01:03, UTC+4), workstation
tool:             TLC2 Version 2.19 of 08 August 2024 (rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:              OpenJDK 25.0.4.1, 6 workers, -Xmx8g, breadth-first
model sha256:     SettlementCanon.tla 199265d40e4c0cec2e61db55603567b9ff605730d359ee0c01b73cd5402987f2
config sha256:    SettlementCanon.cfg 2a448bda56f75ebd2de7a8178967066913134e95242692550bfd6ef7c79ec920
                  SettlementCanon_debt.cfg fa32931ec98512e7c88c2ec17b4830b5b75f298974ca3d2d16eb0d776dc91978
                  SettlementCanon_noslot.cfg fcf816625d9741481ad2d1355d90a1bbf23cc7cfe11909e7184d72adaf74961c
config:           Miners={m1,m2} Reward=2 SeedMax=1 Cap=1 OwedCap=1 FINALITY_DEPTH=1
                  MaxChainLen=3 Mutation="none"
debt config:      the same with Reward=3 Cap=2 MaxChainLen=2
noslot config:    the same with Cap=0 MaxChainLen=2 (no slot for any payee)
invariants:       TypeOK Conservation NonCanonicalEarnsNothing UnpaidKeyNeverNegative
                  RedistributionNeutral LedgerWithinFloat NoClaimWithoutCash
                  HonestIsCanonical UndecidableHeld
properties:       NoAdvance CanonicalNeverNegative
result:           Model checking completed. No error has been found. (all three configs)
states:           3713380 states generated, 2534260 distinct states found, 0 states left on queue.
debt states:      305124 states generated, 239444 distinct states found, 0 states left on queue.
noslot states:    50020 states generated, 39028 distinct states found, 0 states left on queue.
depth:            9, 6 and 6 with one worker (the plain README commands); 6 workers report 10, 7, 7
```

Companion runs (same tool and jar; `check-settlement-canon.sh` reproduces all of them).
A counterexample run stops at the first violation, so its distinct-state count varies
from run to run with 6 workers; the trace length does not.

| run | change | expected | result | trace |
|---|---|---|---|---|
| unreach-main | `Mutation = "degenerate_keep_credit"` on `SettlementCanon.cfg` | no error | `No error has been found.` (2,534,260 distinct states: with a slot the degenerate case is unreachable) | -- |
| unreach-debt | the same on `SettlementCanon_debt.cfg` | no error | `No error has been found.` (239,444 distinct states) | -- |
| mut-foreign-credit | `"foreign_credit"`: a debit-only block keeps its window credit | counterexample | `Invariant NonCanonicalEarnsNothing is violated.` | 3 states |
| mut-authority | `"authority"`: no verdict, a mismatch is booked like a canonical block | counterexample | `Invariant LedgerWithinFloat is violated.` (a block credits its window and pays nothing) or `Invariant UnpaidKeyNeverNegative is violated.` (a block pays a key with no balance); both 3-state paths exist, the first found wins | 3 states |
| mut-authority-cnn | the same, `CanonicalNeverNegative` checked alone | counterexample | `Action property CanonicalNeverNegative is violated.` | 6 states |
| mut-advance | `"advance"`: the redistributed cash is paid but not credited | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-advance-na | the same, `NoAdvance` checked alone | counterexample | `Action property NoAdvance is violated.` | 3 states |
| mut-debt-unbounded | `"debt_unbounded"` on `SettlementCanon_debt.cfg`: the debt pass ignores owed_left | counterexample | `Invariant UnpaidKeyNeverNegative is violated.` | 3 states |
| mut-redist-nobody | `"redistribute_to_nobody"`: the rule before the ruling; with nobody admitted the waiting credit comes off and the cash goes to the residual | counterexample | `Invariant RedistributionNeutral is violated.` | 3 states |
| mut-keep-unbacked | `"keep_credit_unbacked"`: with nobody admitted nothing moves; the waiting payees keep their credit, the cash goes to the residual | counterexample | `Invariant LedgerWithinFloat is violated.` (the ledger goes from 1 to 2) | 3 states |
| mut-degenerate-keep | `"degenerate_keep_credit"` on `SettlementCanon_noslot.cfg`: the same, only with no payee output at all | counterexample | `Invariant LedgerWithinFloat is violated.` | 3 states |
| mut-held-debit | `"held_debit"`: an undecidable block is booked debit-only | counterexample | `Invariant HonestIsCanonical is violated.` | 3 states |
| mut-nogate | `"nogate"`: the builder assembles before the tip is booked | counterexample | `Invariant HonestIsCanonical is violated.` (the #1861 double pay, booked debit-only) | 6 states |
| wit-negative | witness `owed[m] >= 0` | counterexample (reachability) | `Invariant WitNoNegative is violated.` (a debit-only block pays a key more than its balance; the key ends at -1) | 6 states |
| wit-redistribution | witness: canonical credit = E_b | counterexample (reachability) | `Invariant WitNoRedistribution is violated.` | 3 states |
| wit-held | witness: no block is held | counterexample (reachability) | `Invariant WitNoHeld is violated.` | 2 states |
| wit-leftover-to-owed | witness: nobody admitted never moves cash to the payees the owed pass paid | counterexample (reachability) | `Action property WitNoLeftoverToOwed is violated.` | 3 states |
| wit-debt-first | witness on `SettlementCanon_debt.cfg`: the debt step pays nothing | counterexample (reachability) | `Action property WitNoDebtFirst is violated.` | 3 states |

What "negative" means in this model: a canonical block never makes a balance negative
and never deepens a debt (`CanonicalNeverNegative`); a debit-only block may drive the key
it paid negative, and that key carries the payment as a debt (forward repair, by design;
`wit-negative`). `UnpaidKeyNeverNegative` therefore covers the keys no debit-only block
paid, both their finalized balance and their EffectiveOwed.

Solvency. Every coinbase pays all its cash out, to keys or to the residual (the donation
output), so a balance is backed only by a block that paid its cash to a key.
`NoClaimWithoutCash` says no booked block credits more in total than it pays to keys;
`LedgerWithinFloat` says the outstanding total (finalized balances plus the pending net
of booked blocks) never exceeds the genesis float. `RedistributionNeutral` says a
canonical block with a payee output books exactly its window credit in total
(`credit_delta` sums to zero). A block with no payee output can only arise with no slot
for any payee (`Cap = 0` here, `cap_owed = 0` in the code); `unreach-main` and
`unreach-debt` show it is unreachable in the other two configs.

Found and fixed: the redistribution with nobody admitted. The first version of this
model checked `x6::allocate_exact_sum` as it was, and its witness `wit-credit-cut` found
this case: one payee slot, a seeded balance on key A, and a block of 2 units whose window
credits only key B. The owed pass pays A and takes the only slot; B has no slot and
waits, so nobody is admitted. The redistribution then took the cash left off B's credit,
but `prorata` over the admitted payees' zero weight gave it to nobody, so it stayed in
the residual: B's work earned nothing in that block and `credit_delta` summed to minus
the moved amount. Keeping B's credit instead (`keep_credit_unbacked`) is no fix: the cash
still goes to the donation output and the claim has nothing behind it. Operator ruling
2026-10-02: the moved cash goes to the payees the owed pass paid in this block, pro rata
to what it paid them, merged into their outputs (no new slot) and credited to them in the
same amount, while the waiting payees' credit comes off as before; cash and credit move
together. Only with no payee output at all does no cash move: the waiting payees' credit
still comes off and the cash stays in the residual (`degenerate_keep_credit`, which keeps
that credit, breaks `LedgerWithinFloat`). The companion code change on branch
`fix/xmr-redistribute-nobody-admitted` implements this in
`src/impl/xmr/settle/xmr_coinbase.cpp` (KAT F2e in `v37_xmr_spend_floor_kat`), and the
model carries the same rule.

Not modelled: the spend floor c (no dust class, no A8 dust pass), the V37N owed base,
reorgs below FINALIZE (`Settlement.tla`), and the share rule (V37R), which is the same
recompute applied to a share.

## SettlementCanon.tla — the drain rule (operator rulings 2026-10-02) → GREEN

The section above checked master's allocation. The module now carries the drain rule of
the operator rulings of 2026-10-02 (R1 pay-now first, R2 drain per Monero height, B5 the
slot share from the first owed pass), and master's allocation stays in it as
`DrainQ = 0` (`SettlementCanon_master.cfg`, the former `SettlementCanon_debt.cfg`): the
rule and master are one function `AllocBy(E, ord, dh, rc)` of the set `rc` of the
rule's four changes in force (the drain budget, the slot share, the credit at P, no DEBT
FIRST), `{}` for master. A block carries `dh`, the Monero heights since the previous lane
block.

* Drain budget (R2, A1): `F = SUM max(0, EffectiveOwed(k))` over every key;
  `Delta(dh) = min(F, (Reward * min(dh, HCap)) div DrainQ)`. The owed pass draws on
  Delta, never on the whole block. In the lane `DrainQ = 16 * 16` and `HCap = 64`.
* Slots follow cash (R1, B5): when the window payees that need a slot and the owed keys
  exceed `Cap`, the owed pass is re-run with `K_o = max(1, (Cap * owed_paid_1) div
  Reward)` slots, `owed_paid_1` the first pass's cash.
* Pay-now first (R1): `P = Reward - debt_paid`; the window's credit is `E_b(P)`, the same
  weights split at P (exact sum, largest remainder); the admitted payees are paid it in
  full; admission is still decided on `E_b` at the whole Reward.
* DEBT FIRST is removed; the redistribution is unchanged, at `E_b(P)`, with the
  2026-10-02 fallback (the payees the owed pass paid) whenever the admitted payees'
  `E_b(P)` sums to 0.

```
run:              settlement-canon-drain-2026-10-02
date:             2026-10-02 (09:02:34 to 09:07:56, UTC+4), workstation
tool:             TLC2 Version 2.19 of 08 August 2024 (rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:              OpenJDK 25.0.4.1, 8 workers, -Xmx8g, breadth-first
command:          TLC_WORKERS=8 proto/tla/check-settlement-canon.sh tla2tools.jar <out>
model sha256:     SettlementCanon.tla de9ae75d61c5a604eb3db17cca21b6162e6fc38d1cb55cb45687ec3bb06c5ee2
config sha256:    SettlementCanon.cfg 7c89840675cf54b7364f1d3483ba6cf6a99947b11738707b026f468fa4b112f1
                  SettlementCanon_ko.cfg 3acd5f99efbaed79d6ed4578324a00ca4133c8a42c46b26a181ca7db10e4ab47
                  SettlementCanon_noslot.cfg 9413ab9e09974e10bf5671981ed4163e77edb434e2772c3eab9b106962261c8b
                  SettlementCanon_master.cfg 2e3c661ac1ccffb5d2b0f380628593f19c2ef3845ce4baa0c4e7468d8a8009af
                  SettlementCanon_len3.cfg 79aaabc46369e4af1a1f711776b7a867eaa206fb482893934ca0df7d70e8fa6f
script sha256:    check-settlement-canon.sh 173d8b16dced1ed841b806f87c149ddf3901cc9d361e92450009e122da59c850
config:           Miners={m1,m2} Reward=4 SeedMax=2 Cap=1 OwedCap=1 FINALITY_DEPTH=1
                  MaxChainLen=2 DrainQ=4 HCap=2 Mutation="none"
                  (Delta = min(F, dh), dh in 1..2: R/4 per height counted, at most R/2)
ko config:        Miners={m1,m2,m3} Reward=4 SeedMax=1 Cap=2 OwedCap=2 MaxChainLen=1
                  DrainQ=4 HCap=2 (two owed keys can fill both slots; K_o = 1)
noslot config:    Miners={m1,m2} Reward=2 SeedMax=1 Cap=0 MaxChainLen=2 DrainQ=4 HCap=2
master config:    Miners={m1,m2} Reward=3 SeedMax=1 Cap=2 OwedCap=1 MaxChainLen=2
                  DrainQ=0 HCap=1 (master's allocation; the former debt config)
len3 config:      Miners={m1,m2} Reward=3 SeedMax=1 Cap=1 OwedCap=1 MaxChainLen=3
                  DrainQ=3 HCap=2 (Delta = min(F, dh), at most 2R/3; the third block is
                  booked on a finalized first block; TLC_LONG=1 only)
invariants:       TypeOK Conservation NonCanonicalEarnsNothing UnpaidKeyNeverNegative
                  RedistributionNeutral LedgerWithinFloat NoClaimWithoutCash
                  HonestIsCanonical UndecidableHeld NoNewOwed PayNowWithinWindow
                  (master config: all but NoNewOwed)
properties:       NoAdvance CanonicalNeverNegative FloatNonIncreasing DrainBound
                  SlotShare SomeoneAdmitted MasterWhenNoFloat
                  (master config: NoAdvance CanonicalNeverNegative)
result:           Model checking completed. No error has been found. (all five configs)
states:           3904344 states generated, 3051279 distinct states found, 0 left; depth 6
ko states:        33048 states generated, 29688 distinct states found, 0 left; depth 4
noslot states:    79588 states generated, 61636 distinct states found, 0 left; depth 7
master states:    305124 states generated, 239444 distinct states found, 0 left; depth 7
len3 states:      89865444 states generated, 61514884 distinct states found, 0 left; depth 10
                  (run alone, the same TLC command as the script's green-len3, 10 workers,
                  08:40:34 to 09:01:56)
verdicts:         35 runs, 35 PASS (check-settlement-canon.sh, exit 0); green-len3 PASS
```

The master config reproduces the model before the rule exactly: 305,124 generated and
239,444 distinct states, the counts of `SettlementCanon_debt.cfg` in the section above.

Companion runs (the same invocation; each control and witness is checked against the
named property alone, so the property that catches it is the one stated). A
counterexample run stops at the first violation, so its distinct-state count varies
from run to run with several workers, and so, by a state now and then, does the trace
length (the depth reported by several workers also varies by one).

| run | change | expected | result | distinct | trace |
|---|---|---|---|---|---|
| unreach-main | `"degenerate_keep_credit"` on `SettlementCanon.cfg` | no error | `Model checking completed. No error has been found.` | 3,051,279 | - |
| unreach-master | the same on `SettlementCanon_master.cfg` | no error | `Model checking completed. No error has been found.` | 239,444 | - |
| mut-debt-first | `"debt_first_on"`: DEBT FIRST kept under the rule; `NoNewOwed` alone | counterexample | `Error: Invariant NoNewOwed is violated.` | 129,880 | 3 |
| mut-debt-first-float | the same, `FloatNonIncreasing` alone | counterexample | `Error: Action property FloatNonIncreasing is violated.` | 2,340,672 | 6 |
| mut-credit-at-r | `"credit_at_reward"`: the window credited at the whole Reward while Delta pays old balances; `NoNewOwed` alone | counterexample | `Error: Invariant NoNewOwed is violated.` | 118,810 | 3 |
| mut-delta-unb | `"delta_unbounded"`: the owed pass draws on the whole block; `DrainBound` alone | counterexample | `Error: Action property DrainBound is violated.` | 113,426 | 3 |
| mut-no-ko | `"no_ko"` on `SettlementCanon_ko.cfg`: contested, the owed pass keeps every slot; `SomeoneAdmitted` alone | counterexample | `Error: Action property SomeoneAdmitted is violated.` | 19,242 | 3 |
| mut-no-ko-share | the same, `SlotShare` alone | counterexample | `Error: Action property SlotShare is violated.` | 17,807 | 3 |
| mut-split-at-delta | `"split_at_delta"`: P = R - the slice before the clamp by F; `MasterWhenNoFloat` alone | counterexample | `Error: Action property MasterWhenNoFloat is violated.` | 110,234 | 3 |
| mut-hcap-full | no mutation; `SettlementCanon_ko.cfg` with `HCap = 4 = DrainQ` and `SeedMax = 2`; `SomeoneAdmitted` alone | counterexample | `Error: Action property SomeoneAdmitted is violated.` | 93,093 | 3 |
| mut-foreign-credit | `"foreign_credit"`: a debit-only block keeps its window credit | counterexample | `Error: Invariant NonCanonicalEarnsNothing is violated.` | 108,483 | 3 |
| mut-authority | `"authority"`: no verdict, a mismatch is booked like a canonical block; `UnpaidKeyNeverNegative` and `LedgerWithinFloat` | counterexample | `Error: Invariant LedgerWithinFloat is violated.` | 128,304 | 3 |
| mut-authority-cnn | the same, `CanonicalNeverNegative` alone | counterexample | `Error: Action property CanonicalNeverNegative is violated.` | 2,346,314 | 6 |
| mut-advance | `"advance"`: the redistributed cash is paid but not credited | counterexample | `Error: Invariant UnpaidKeyNeverNegative is violated.` | 92,001 | 3 |
| mut-advance-na | the same, `NoAdvance` alone | counterexample | `Error: Action property NoAdvance is violated.` | 91,328 | 3 |
| mut-debt-unbounded | `"debt_unbounded"` on `SettlementCanon_master.cfg`: master's debt pass ignores owed_left | counterexample | `Error: Invariant UnpaidKeyNeverNegative is violated.` | 10,098 | 4 |
| mut-redist-nobody | `"redistribute_to_nobody"`: with nobody admitted the waiting credit comes off and the cash goes to the residual | counterexample | `Error: Invariant RedistributionNeutral is violated.` | 125,823 | 3 |
| mut-keep-unbacked | `"keep_credit_unbacked"`: with nobody admitted the waiting payees keep their credit, the cash goes to the residual | counterexample | `Error: Invariant LedgerWithinFloat is violated.` | 119,047 | 3 |
| mut-degenerate-keep | `"degenerate_keep_credit"` on `SettlementCanon_noslot.cfg` | counterexample | `Error: Invariant LedgerWithinFloat is violated.` | 2,800 | 4 |
| mut-held-debit | `"held_debit"`: an undecidable block is booked debit-only | counterexample | `Error: Invariant HonestIsCanonical is violated.` | 4,696 | 3 |
| mut-nogate | `"nogate"`: the builder assembles before the tip is booked | counterexample | `Error: Invariant HonestIsCanonical is violated.` | 2,075,590 | 5 |
| wit-negative | witness `owed[m] >= 0` | reached | `Error: Invariant WitNoNegative is violated.` | 2,351,911 | 6 |
| wit-redistribution | witness: canonical credit = the window's credit at P | reached | `Error: Invariant WitNoRedistribution is violated.` | 70,855 | 3 |
| wit-held | witness: no block is held | reached | `Error: Invariant WitNoHeld is violated.` | 17 | 2 |
| wit-leftover-to-owed | witness: nobody admitted never moves cash to the payees the owed pass paid | reached | `Error: Action property WitNoLeftoverToOwed is violated.` | 126,041 | 3 |
| wit-drain | witness: a canonical block never pays beyond its credit (no drain payment) | reached | `Error: Action property WitNoDrain is violated.` | 118,824 | 3 |
| wit-split-at-p | witness: the window is always credited at the whole Reward | reached | `Error: Invariant WitNoSplitAtP is violated.` | 129,461 | 3 |
| wit-floor-fallback | witness: a payee admitted with E_b(P) summing to 0 never sends the moved cash to the owed-paid | reached | `Error: Action property WitNoFloorFallback is violated.` | 142,082 | 3 |
| wit-ko-cut | witness on `SettlementCanon_ko.cfg`: K_o never cuts an owed pass | reached | `Error: Action property WitNoKoCut is violated.` | 18,793 | 3 |
| wit-debt-first | witness on `SettlementCanon_master.cfg`: master's debt step pays nothing | reached | `Error: Action property WitNoDebtFirst is violated.` | 6,640 | 4 |
| wit-master-new-owed | `NoNewOwed` alone on `SettlementCanon_master.cfg` | counterexample (master leaves a balance) | `Error: Invariant NoNewOwed is violated.` | 13,590 | 3 |

New properties (the old ones are kept; `RedistributionNeutral` now compares a canonical
block's booked credit with the window's credit at P, `book[i].ep`, recorded at the booking
point, because a later state has the block pending and EO, F, Delta and P differ there):

| property | kind | statement | caught by |
|---|---|---|---|
| `NoNewOwed` | invariant | a canonical block books per key at most what it pays: it never raises a balance | `debt_first_on`, `credit_at_reward`; master fails it (`wit-master-new-owed`) |
| `PayNowWithinWindow` | invariant | per key `E_b(P) <= E_b(R)`, so `E_b(P) > 0` only where `E_b(R) > 0` (B6) | (by construction of the split) |
| `FloatNonIncreasing` | action, every step | no step raises any key's EffectiveOwed, and F never grows | `debt_first_on` |
| `DrainBound` | action, canonical booking | what the block pays beyond the credit it books is at most `Delta(dh)`, and `Delta(dh) <= F` | `delta_unbounded` |
| `SlotShare` | action, canonical booking | contested: the owed keys hold at most `max(1, (Cap * owed_paid_1) div Reward)` slots | `no_ko` |
| `SomeoneAdmitted` | action, canonical booking | with `Cap >= 2` and a window, some window payee is admitted ("nobody admitted" unreachable) | `no_ko`; and `HCap = DrainQ` (`mut-hcap-full`) |
| `MasterWhenNoFloat` | action, canonical booking | with `F = 0` the block's payouts and credit are master's, key for key | `split_at_delta` |

`DrainBound` and `SlotShare` are stated on what the block pays and books and on the
first pass's cash, not on the allocation's own `Delta` or `K_o` bookkeeping, so a
mutation of the knob itself (`no_ko`) is caught. `SomeoneAdmitted` needs
`HCap < DrainQ` (Delta < Reward): the module does not assume it, and `mut-hcap-full`
(the ko config with `HCap = DrainQ = 4` and `SeedMax = 2`) shows that without it two
owed keys can take both slots with `K_o = Cap`. That is the lane-rules validity
condition `1 <= drain_h_cap < drain_q * 16` of the specification.

What the new counterexamples are (3-state traces unless noted: genesis, one block mined,
booked):

* `mut-credit-at-r`: seed m1 = 1, a block with E_b = (m1 0, m2 4), dh = 1. Delta = 1, the
  owed pass pays m1 1 and takes the only slot; credited at R, m2's 4 units are cut by the
  redistribution only down to 1 (the cash left is 3), so m2 is booked 1 and paid 0.
* `wit-master-new-owed`: the same mechanism in master's allocation: seed (1, 1),
  E_b = (m1 0, m2 3); the owed pass pays m1 1, m2 is admitted and paid 2 of its 3; the
  third unit becomes m2's balance. This is the balance the rule no longer creates.
* `mut-debt-first-float` (6 states): the IOU of DEBT FIRST appears at FINALIZE, where a
  waiting payee's credit raises its EffectiveOwed.
* `mut-hcap-full`: seed (m1 0, m2 2, m3 2), E_b = (m1 1, 0, 0), dh = 4: Delta = 4 = R, the
  owed pass pays m2 and m3 2 each, K_o = max(1, 2 * 4 div 4) = 2 = Cap and m1 waits with
  nobody admitted (and P = 0 credits it nothing).
* `mut-split-at-delta`: no float, E_b = (m1 0, m2 1), dh = 1: the unclamped slice is 1,
  P = 3, m2's one unit floors to 0 at P and goes to the donation output; master pays it.
* `wit-floor-fallback`: seed m2 = 1, E_b = (1, 1), dh = 1: the owed pass pays m2 1 and
  takes the slot (m2 is admitted through its owed output), m1 waits; at P = 3 the window's
  2 units split (m1 1, m2 0), so the admitted payees' E_b(P) sums to 0 and m1's unit moves,
  with its credit, to m2, the payee the owed pass paid. A tiny-model rounding corner; with
  real share weights E_b(P) of an admitted payee is not 0.

Two model artifacts were found and fixed while the rule was first modelled
(`/mnt/ci/settle-impl/B-SPEC.md` section 8), both in the module above: (1)
`RedistributionNeutral` re-evaluated the allocation after the booking, when the block is
pending and EO, F, Delta and P differ (fixed by recording `ep` at the booking point); (2)
"nobody admitted" was first tested as "the admitted payees' E_b(P) sums to 0", which the
floor at P < R makes true with a payee admitted (fixed: `nobody` is "no payee admitted",
and the redistribution's fallback covers the sum-to-0 case, as the specification adopts).

Not modelled: the spend floor c (no dust class, no A8 dust pass; so the R5 fixes, the F4
band routed to the dust pass and the dust-decay clock started from the gross E_b set,
have nothing to act on here), the V37N owed base, the source and determinism of `dh`
(a chain fact here; B-SPEC section 3 argues it from the ledger), the float sources other
than the genesis balances that amendment A3 lists as preconditions of "no new owed" (the
empty-cut finder credit, DROPS due with the window rule off), reorgs below FINALIZE
(`Settlement.tla`) and the share rule (V37R).

## SettlementCanon.tla — the debit-only NET booking (lane rule 31, G9 review O6) → GREEN

A non-canonical lane block is booked debit-only: its credit is dropped and its payouts are
debited. Before lane rule 31 `noncanon_net` the debit was the whole payout, so a window key
the block paid within its window credit carried that pay-now as a permanent debt. Under the
rule the block books `credit = min(E, pay)` per key (the C++ booking: credit `{}` and the
payout `pay - min(E, pay)`, `paynow::debit_only_net`; the pending payout and FINALIZE are
the same), so only a payment above the key's window credit at the block's cut is a debt.
The module hard-wires the rule; Mutation `"debit_all"` is the booking before it.

* `NonCanonicalEarnsNothing` is restated: a debit-only block credits a key at most
  `min(E, pay)` (it never raises a balance and only books cash it paid); still caught by
  `foreign_credit`.
* New invariant `WindowPaidKeyNeverNegative`: a key that no debit-only block paid above its
  window credit at that block's cut has `owed >= 0` and `EffectiveOwed >= 0`. It is in every
  config. `mut-debit-all` violates it (3 states: genesis; a non-canonical block pays m2 1
  with E(m2) = 2; booked debit-only, m2's EffectiveOwed is -1).
* `WitNoNegative` stays violated (`wit-negative`): an overpayment is still a debt, the
  forward repair is kept. `wit-noncanon-net` shows the netting is reached (the strict
  `NonCanonicalCreditsNobody` of the booking before the rule is violated).

```
run:              settlement-canon-o6-2026-10-04
date:             2026-10-04 (02:50:05 to 03:01:27, UTC+4), workstation-191
tool:             TLC2 Version 2.19 of 08 August 2024 (rev 5a47802)
tla2tools sha256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
jre:              OpenJDK 25.0.4.1, 6 workers, -Xmx8g, breadth-first
command:          TLC_WORKERS=6 proto/tla/check-settlement-canon.sh tla2tools.jar <out>
model sha256:     SettlementCanon.tla 398176683918b7d39717aefa6599e6b6df560ab32e930b4a9cafad872b777ea0
config sha256:    SettlementCanon.cfg 45be6c3d4b91f880a813c271210982e275db6362022549fd7390f859ee37e08e
                  SettlementCanon_ko.cfg bf6627138920ea5cc96c17dc85aed17fb9a31f8774350a824543b418a0b43b34
                  SettlementCanon_noslot.cfg 83864fc4d171efd0c6ff118f300bca2fb287d95635065e74cef7e97b62a49c32
                  SettlementCanon_master.cfg b0c2d2788a350a1fc5ad49d39c1ceace0c8be2ba0f44bee7f9ca5ecfe6665c0e
                  SettlementCanon_len3.cfg 70bbeb78cf8e6fd6aadf8ef7ea0722776bc0fb33928ccb35d2a6409aa0c67a4d
script sha256:    check-settlement-canon.sh 3377adb6c5d3d1255146f02181d6201e6adc626d6941d192550beaa23b21a553
invariants:       the drain section's set + WindowPaidKeyNeverNegative (every config)
result:           Model checking completed. No error has been found. (green, green-ko,
                  green-noslot, green-master, green-len3)
states:           3904344 states generated, 3051279 distinct states found, 0 left; depth 6
ko states:        33048 generated, 29688 distinct, depth 3
noslot states:    79588 generated, 61636 distinct, depth 7
master states:    305124 generated, 239444 distinct, depth 7
len3 states:      89865444 generated, 61514884 distinct, 0 left; depth 10, no error
                  (run alone, the script's green-len3 command, 6 workers, 03:01:42 to 03:44:43)
verdicts:         37 runs, 37 PASS (check-settlement-canon.sh, exit 0)
```

The state counts equal the drain section's: the rule changes what a debit-only block books,
not which states are reachable. New runs of the script (the others as in the drain section):

| run | change | expected | result | distinct | trace |
|---|---|---|---|---|---|
| mut-debit-all | `"debit_all"`: a debit-only block debits its whole payout (the booking before lane rule 31); `WindowPaidKeyNeverNegative` alone | counterexample | `Error: Invariant WindowPaidKeyNeverNegative is violated.` | 98,831 | 3 |
| wit-noncanon-net | witness: `NonCanonicalCreditsNobody` (a debit-only block credits nobody) | reached | `Error: Invariant NonCanonicalCreditsNobody is violated.` | 100,851 | 3 |
| mut-foreign-credit | `"foreign_credit"` against the restated `NonCanonicalEarnsNothing` | counterexample | `Error: Invariant NonCanonicalEarnsNothing is violated.` | 94,081 | 3 |
| wit-negative | `WitNoNegative`: an overpayment is still a debt | reached | `Error: Invariant WitNoNegative is violated.` | 2,340,619 | 6 |

The research runs that chose the rule over three other candidates (keep the gross debit,
collect a debtor's pay-now, cap at E_b(P)) are not repeated here.
