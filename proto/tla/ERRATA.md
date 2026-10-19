# Settlement.tla model errata

## Revision 2 -- owed-sign semantics (2026-09-28)

**What was wrong.** Revision 1 proved `NoNegativeOwed` (per-key finalized owed `>= 0`) for a
system that could not produce a negative value: `owed` was typed `Nat`, every credit and
payout ranged over `0..MaxReward`, and `BlockFound` required `payout[m] <= EffectiveOwed(m)`
of every block. The ledger it stands for is signed by design: over-credit is netted forward
against the same key's later credit (forward repair), a carried DROPS replace delta may be
negative, and receivers book a coinbase's payout map without re-checking it. The GREEN
revision-1 run therefore did not cover the shipped semantics. Adding one action -- a pool
block whose credit row may be negative -- to the revision-1 model, with `owed` widened to
`Int`, makes TLC report `NoNegativeOwed` violated in a 5-state trace
(`check-owed-sign.sh`, run `base-red`).

**Which side was wrong.** The model (decision C-1 (a) of the owed-sign spec). The ledger
code is unchanged; this revision brings the model to it.

**What changed.**

| Item | Revision 1 | Revision 2 | Decision |
|---|---|---|---|
| sign domain | `owed \in [Miners -> Nat]` | `owed \in [Miners -> Int]`; credit row = `base + delta`, delta may be negative | C-1 (a) |
| negative credit | not expressible | `BlockFound` / `BlockOrphaned` draw a carried delta (transfer between keys); a key driven below zero is netting, legal | C-6 (a) |
| forward repair | none | a negative key is repaired only by its own later credit rows; it gets no owed-pass output while its view is `<= 0`, and pay-now within its own `E_b` nets to zero | C-1 (a), FR-004 |
| per-key invariant | `NoNegativeOwed` | `KeyFloor`: `owed[m] >= -KeyBound` | C-3 |
| aggregate invariant | none | `AggregateNonNeg`: `Sum owed >= 0` | C-3 |
| carried-delta bound | none | a block whose carried negative delta would take a key below `-(that block's own E_b)` is not a legal block | C-4 (c) |
| payout precondition | `payout[m] <= EffectiveOwed(m)` on every block | no receiver guard; payouts are bounded only by what an honest builder produces: its possibly-lagged EffectiveOwed view (owed pass), its own `E_b` (pay-now), the block's reward budget | C-5 (a) |
| `OverlayNeverExceedsOwed` | invariant | withdrawn: with no receiver guard and a lagged builder view it is not a property of the protocol | C-5 (a) |
| clawback | implicit | `NoClawback` action property: paid-to-date per key never decreases | FR-002 |
| orphan after SETTLED | outside the model | `DeepOrphan` action: an equal-height branch replaces a suffix reaching a SETTLED block; `owed` and the book are untouched, the orphaned payout mass is the priced residual; `ResidualBound` invariant | C-7 (a), MD-2 (a), MD-3 |
| `Conservation` | fold over settled chain indices | fold over the book of SETTLED records (signed credit rows, payouts, including blocks later orphaned); also pins paid-to-date | FR-003 |
| overlay | unfinalized blocks | unsettled (pending) blocks, as the ledger keeps them; FINALIZE is applied in chain order | -- |

Kept: `TypeOK` (widened), `SettledImpliesFinalized`, `SettleOnce` (restated over the book,
since a deep orphan removes a SETTLED block from the chain), `MonoOnFinal`.

**Modelling assumptions to read with the result.**

1. *Delta mass.* A carried delta in the spec config is a transfer: it lowers one key and
   raises another by the same amount, so a block never credits less than its `E_b`. With
   that rule `AggregateNonNeg` holds. Without it (`Settlement_nomass.cfg`, a delta may lower
   a key without raising another) TLC finds `AggregateNonNeg` violated. The ledger's replace
   delta is not mass-conserving per block in general, so C-3's aggregate clause holds only
   under a rule of this kind; that rule is not yet decided and is recorded here as open.
2. *Builder view.* A builder's EffectiveOwed view may lag the canonical one by the newest
   pending block. `KeyBound` is one block's `E_b` mass plus one block of over-payment from
   that lag.
3. *C-4 judged on replicated state.* The carried-delta floor is evaluated on the finalized
   partition plus the canonical pending ancestry, both of which are the same on every node
   in the model.
4. *Bounds.* Finite model: two keys, `MaxReward = 1`, `MaxDelta = 2`, `FINALITY_DEPTH = 1`,
   `MaxChainLen = 3`, `MaxIds = 4`, at most one beyond-finality orphan. These bound the
   model, not the protocol.

**Negative controls.** `Settlement_noC4.cfg` (C-4 floor off -> `KeyFloor` violated),
`Settlement_clawback.cfg` (a clawback action on -> `NoClawback` violated),
`Settlement_nomass.cfg` (delta mass rule off -> `AggregateNonNeg` violated). Witness runs in
`check-owed-sign.sh` show that a negative key and a non-zero residual are both reachable in
the spec config, so the new invariants are not vacuous.

**Results.** `MODELCHECK-RESULTS.md`, section "Revision 2".
