# V37 rev3-falsifiers — executable acceptance harness for F-REPAIR / F-SPINE / F-BROADCAST

**Status:** WP2 of the rev3 programme, slice-1 GREEN (75/75), carrying the integrator's
MD rulings of 2026-08-30. Landed into the repo via A1.0 (the Phase-A harness-corpus landing).

**Design source of truth:** `roundabout-rev3.md` (the rev3 architecture case, staged in
frstrtr/the on branch `v37/roundabout-rev3`, commit cb965e35) — §1 (the adopted
construction: per-chain settlement as a pure function of a shared accounting spine, next-window
repair, the spine burial share-depth parameter), §4 (the two post-broadcast cases and the
coin-chain confirmation-depth parameter), §9 (the falsifiers and their exclusion clauses).
**Spec counterpart:** `v37-concurrency-obligations-spec.md` (WP1 — the normative
obligations O1–O5 and the AT shapes these tests implement; prose track, frstrtr/the).

## Scope fence
Prototype code on the v37 **design** track. It models the construction; it is not c2pool
code, contains no consensus logic, touches nothing on `master` or `v37-dev`, and asserts
nothing about the shipped implementation. Its only product is: *do the three rev3 falsifiers
have executable acceptance tests that pass under the construction and fail without it.*

## Layout
```
harness/model.py         the model: Spine, Chain, the settlement fold, Guards, invariants
harness/acceptance.py    AT-REPAIR, AT-SPINE, AT-BROADCAST
harness/conservation.py  CONS — the cross-invariant, 100 seeded random reorg schedules
harness/run_all.py       run-all entry point, PASS/FAIL table, golden stamp, red matrix
golden/rev3_falsifiers_v1.json
```

## Run
```
python3 harness/run_all.py                 # green baseline: table + golden stamp   (~1.4 s)
python3 harness/run_all.py --red-matrix    # guard x test red-baseline matrix       (~15 s)
python3 harness/run_all.py --red <guard>   # one guard disabled, which checks go red
```
Deterministic: fixed seeds (`random.Random(seed)` per schedule, seeds 0..99), no wall-clock,
no unseeded RNG. The stamp is reproducible across runs; a changed stamp is a regression signal.

**Golden stamp (75/75 GREEN):**
`3692d922af75b61bc3d40b431e0c048ee5ed0412b093c05911294b3ec5af4efe`

*(previous stamp, before the rulings below:
`2f186d637dde2138c33f6843d2455334f313317a212b47a25a79244d12fc9877` at 70/70. The stamp moved
because the harness code changed — that is expected and required, not a regression.)*

## Integrator rulings folded in — 2026-08-30
Cited as: **the integrator's ruling of 2026-08-30, the reply to this harness's MD decision
mail** (the mail that carried MD-1 … MD-6 out of the "MODELLING DECISIONS rev3 does not settle"
section below). Three decisions landed; all three are implemented here, none silently.

| MD | ruling | what changed in the harness |
|----|--------|-----------------------------|
| **MD-2** | **(a), hardened — now spec-fixed** | `Config.SETTLED_TERMINAL = True` is no longer an open knob; its comment says so. B5's residual-detection semantics were confirmed correct and are unchanged in logic. A normative note on the `D_conf` floor is added below. |
| **MD-3** | **A** | New guard `monotone_height` implementing the normative clause. AT-BROADCAST/B6 is rewritten from *exhibit the hazard* to *the clause prevents the hazard*; the hazard is preserved as the `--red monotone_height` arm. |
| **MD-5** | **C** | The post-broadcast spine-repair leg becomes an N-free **monotone-progress** property instead of a deadline assertion (AT-SPINE/S3c). `N_repair` is de-aliased: it now governs leg-1 only. The B sizing question is answered as an **informational line**, not a check. |

MD-1, MD-4 and MD-6 were folded earlier and are recorded below as **FOLDED**, not as open
decisions. Nothing in this harness now waits on a modelling decision.

## The config block
The spec addendum references these three names verbatim (`harness/model.py`, `class Config`):

| name | value here | rev3 anchor |
|------|-----------|-------------|
| `N_repair` | 3 | §1/§9 repair-window parameter, counted in PPLNS windows — "a window settles when the chain finds the block that pays it". **Post-ruling scope (MD-5 = C): leg-1 only** — the lagging-chain burial-deferred repair, AT-REPAIR/R1. It does **not** govern the spine mechanism any more (see below). |
| `D_spine`  | 4 | §1 spine burial share-depth acceptance parameter, in share records |
| `D_conf`   | 3 | §4 coin-chain confirmation-depth acceptance parameter |

**`D_conf` and its normative floor (informational, MD-2).** At spec level the floor on `D_conf`
is the chain's own **coinbase maturity** — a payout cannot be considered settled before the
coinbase that funds it is spendable, so no smaller value is admissible in the real
construction. The toy `D_conf = 3` used here sits **deliberately below** that floor: the whole
point of B5 is to orphan a SETTLED payout with a beyond-acceptance reorg, and at a
maturity-sized `D_conf` that exhibit would cost a hundred-block schedule per run. Reading the
harness's `D_conf` as a recommendation would be a mistake; it is a cheap stand-in chosen to
exercise the residual, exactly as `D_spine = 4` is a cheap stand-in for the recommended 6.

`W_pplns` (8) and `BLOCK_REWARD` (1 000 000, integer, largest-remainder split) are harness
scale knobs, not rev3 parameters.

**These are toy-scale values, NOT the spec addendum's RECOMMENDED defaults** (`D_spine = 6`,
`D_conf` = the chain's own coinbase-maturity constant, `N_repair` per the spec's relation).
The divergence is material: this harness's `D_spine`/`W_pplns` ratio is 4/8 = 0.50 against
the recommended 6/8 = 0.75 over the same window. Running at the spec defaults requires
`N_repair` sized per the spec's relation `N_repair ≥ ⌈D_spine / s⌉` (s = share inflow per
settled window) — a bare `N_repair = 1` is unachievable for any `D_spine ≥ 2` at finite
inflow: the burial gate alone delays payability by `⌈D_spine / s⌉` windows
(cross-verified 2026-08-30: at `N_repair = 1, D_spine = 6` AT-REPAIR/R1d goes red with
`R1_repaired_at_window = -1`).

**Limitation:** `D_conf` is a single global integer here, applied to both chains; the
spec's O5.2 makes it per-chain. The harness models only the homogeneous case.

## The model
The **spine** is an append-only log of share records, reorg-prone (tail rewrite to depth *d*).
Two coin chains A and B each keep a single canonical block list; a coin reorg is truncate +
extend, so a block and its descendants orphan together. Each chain also carries a **persisted
height high-water** (`Chain.height_hw`, never decreases): under the MD-3 clause a candidate
branch that would leave the chain shorter than its high-water is **not adopted at all**, and
the refusal is recorded in `World.rejected_reorgs` rather than swallowed. Because of that, an
orphan is modelled the way a chain actually produces one — a **competing miner's block** at
equal or greater height (`Block.ours = False`): it occupies chain height, generates no
entitlement for this pool and broadcasts no coinbase, so our block is orphaned without the
chain ever shortening.

Per-chain settlement is a **pure fold**. For each canonical block *b* of chain *c*, *b*
generates `BLOCK_REWARD` of entitlement distributed over the PPLNS window
`spine[b.prefix − W : b.prefix]`, **read from the current spine** — nothing is cached, so a
spine reorg re-derives by construction. That per-record entitlement is `earned`. The subset
attributable to records buried ≥ `D_spine` deep in the current spine is `payable` — this *is*
the broadcast gate. A block's coinbase broadcasts `payable − ledger_paid`, **unclamped**, so
over-credit nets against future entitlement rather than being clawed back (§1: "corrected in
subsequent payouts, not clawed back"), capped at `BLOCK_REWARD`, largest-owed-first.
A payout is PENDING until it holds `D_conf` confirmations on its own chain, then SETTLED. An
orphaned PENDING payout returns to owed (funds never moved); a later block re-mints it.

## Tests

| ID | falsifier | what it establishes |
|----|-----------|---------------------|
| **AT-REPAIR** | F-REPAIR | R1 a burial-deferred in-window slice on a lagging chain is repaired within `N_repair` windows (measured: window 2). R2 an orphaned coinbase's slice returns to owed and is re-minted within `N_repair` (measured: window 1), and at quiescence every in-window miner is exactly whole. **R3 EXCLUSION** — a share aged out of the lagging chain's PPLNS window is never credited there; verdict `EXCLUDED:window-expiry`, asserted **not** a falsification. **R4 EXCLUSION** — a miner over-credited by a deep spine reorg who then departs; verdict `EXCLUDED:miner-departure`, asserted **not** a falsification, and the already-broadcast funds are not clawed back. |
| **AT-SPINE** | F-SPINE | S1 over a schedule of 8 spine reorgs at depths 1..`D_spine`, **no broadcast was ever made against a prefix a later reorg rewrote** — the gate holds (sid-by-sid check of every payout's paying prefix). S2 a reorg *shallower* than the gate re-derives **silently**: no payout emitted, none unwound, no broadcast prefix touched, no over-credit created. S3 a reorg **deeper** than the gate does re-derive a broadcast prefix away (the exhibit exists); divergence appears in both directions; the under-credit is repaired forward by **monotone progress — the N-free property of MD-5 = C** (see below), the over-credit (250 000 units) is surfaced as §1's priced residual and never clawed back. Two probes are **recorded, never asserted**: the depth at which the old `N_repair` deadline first fails (7) and the depth at which monotone progress itself first stalls (7). |
| **AT-BROADCAST** | F-BROADCAST | B1 a coin-chain reorg orphans a payout → moved no funds → **returned to owed** → re-minted by a later settlement (window 1) → every miner exactly whole. B2 SETTLED marking respects `D_conf`: nothing marked below depth, everything younger still PENDING. B3 under reorgs shallower than `D_conf` **no SETTLED payout is ever orphaned** and nothing vanishes — the loss sub-case is unreachable. B4 orphan-then-deeper-reorg never double-pays (per-chain value ceiling, per-miner high-water). B5 the accepted residual: a strictly-longer competing branch reaching `D_conf + 1` does orphan a SETTLED payout; the harness asserts the residual is **exactly bounded** by that amount (1 625 000 units) and surfaced, not silent. **B6 the MD-3 clause, asserted to PREVENT the composition hazard**: two sub-`D_conf` candidates that would each leave the chain shorter than its high-water are both refused, the high-water never falls, no SETTLED payout is orphaned, nothing vanishes. |
| **CONS** | cross-invariant | 100 seeded random schedules × 30 events (spine growth, spine reorgs at and beyond `D_spine`, block finds on both chains, coin reorgs shallower than `D_conf`), then quiescence. Checked after **every event**: CONS-0 no non-positive payout; CONS-1 no value creation (funds moved ≤ per-miner high-water entitlement, and per chain ≤ blocks × `BLOCK_REWARD`); CONS-2 ledger fidelity (what the ledger believes it paid == what actually moved); CONS-3 exact accounting (`ledger_paid + owed_signed == payable`). After quiescence: CONS-4 every positive owed drains. 12 045 payouts, 116 deep spine reorgs, 300 coin reorgs, 0 violations. |

**Note on reading the table:** AT-BROADCAST/**B5c** *requires* a recorded invariant violation
by design — the pass criterion there is that the harness **detects** the priced residual, not
that no violation ever occurs. This is now true of B5 alone: since the MD-3 ruling, **B6 asserts
the opposite** (no violation, nothing vanished), because the clause prevents the hazard rather
than the harness merely noticing it. "0 violations" in the CONS row refers to the conservation
schedule, which excludes the declared residual case (MD-6).

**Informational lines.** `run_all.py` prints an `INFORMATIONAL` block after the recorded
quantities. Nothing there is asserted. It currently carries the **B sizing** observation
required by MD-5 = C: whether steady-state payable creation per settled window stayed below one
block reward over the run. At the harness parameters it does — max 875 000 against a
1 000 000 reward — which is why the S3 exhibit drains at all; the S3 probes record where that
headroom disappears.

## Red baseline
Each mechanism rev3 requires is a named boolean in `model.Guards`. Disabling exactly one is
the red baseline — the same way a KAT proves it is testing something.

| guard disabled | site | reddens |
|---|---|---|
| `forward_repair` | `model.py:461` | AT-REPAIR (4), AT-SPINE (1), AT-BROADCAST (2), CONS (2) |
| `spine_burial` | `model.py:383` | AT-REPAIR (5), AT-SPINE (5), AT-BROADCAST (6), CONS (2) |
| `conf_depth` | `model.py:502` | AT-REPAIR (5), AT-BROADCAST (12), CONS (1) |
| `remint_on_orphan` | `model.py:422` | AT-REPAIR (4), AT-BROADCAST (9), CONS (1) |
| `canonical_history` | `model.py:377` | AT-REPAIR (2), AT-BROADCAST (5), CONS (2) |
| **`monotone_height`** *(new, MD-3 = A)* | `model.py:332` | **AT-BROADCAST (4)** — B6b/B6c/B6d/B6e |

`--red-matrix` additionally asserts the two closure conditions: **every guard reddens at least
one test**, and **every test is reddened by at least one guard**. Both hold, including for the
new guard.

**The `monotone_height` red arm is the MD-3 hazard itself.** With the clause off, the two
shortening candidates in B6 are adopted, the chain falls from height 6 to 2, the composed
rewrite (2 × 2 = 4) exceeds `D_conf` = 3, a SETTLED payout is orphaned, and 1 625 000 units go
missing with CONS-2 firing — the same failure CONS found at **11/100 schedules** before the
schedule bound (MD-6) was declared. That is the evidence the clause is load-bearing rather than
decorative. Note that `forward_repair` is what reddens AT-SPINE's new monotone-progress check
(S3c): the property is not self-satisfying.

## MODELLING DECISIONS — all six now closed

| MD | status |
|----|--------|
| MD-1 | **FOLDED** earlier (three-way split of the F-SPINE claim: S1/S2/S3) |
| MD-2 | **RULED (a), hardened, and IMPLEMENTED** — integrator ruling 2026-08-30, reply to the MD decision mail |
| MD-3 | **RULED A and IMPLEMENTED** — same ruling; guard `monotone_height`, B6 rewritten to assert prevention |
| MD-4 | **FOLDED** earlier (quiescence is where "paid == payable" is meaningful; `World.quiesce`) |
| MD-5 | **RULED C and IMPLEMENTED** — same ruling; the spine leg is N-free monotone progress. **The unfalsifiable-deadline finding is resolved by the property change**, not by choosing an N |
| MD-6 | **FOLDED** earlier (declared schedule bound in CONS) |

Nothing below is an open question any more; the text is kept because it is the argument the
rulings answer, and the spec addendum's wording should track it.

**MD-1 — FOLDED. "spine reorg deeper than the broadcast gate ⇒ no broadcast against a rewritten
prefix" is not satisfiable as literally posed.** If a reorg is deeper than `D_spine` it can by
construction reach a prefix a payout was broadcast against; that is §1's third bullet and §4's
funds-gone case, not something the gate prevents. The harness therefore splits the claim into
three: (S1) for depth ≤ `D_spine` the gate holds absolutely — the theorem `i ≤ H−D_spine−1 <
H−d` — and this is what "no broadcast against a later-rewritten prefix" can mean; (S2) shallow
reorgs repair silently pre-broadcast; (S3) deeper reorgs do reach a broadcast prefix and are
handled by forward repair + priced residual, asserted **not** a falsification. *(Folded
earlier; the S1/S2/S3 split is the wording the spec addendum should carry.)*

**MD-2 — RULED (a), HARDENED. F-BROADCAST vs. §4 on what happens to a SETTLED payout that a
deep reorg orphans.**
§4 says "an orphaned payout **below** [D_conf] returns to owed" and is silent above it; §9's
F-BROADCAST reads literally as "a payout marked SETTLED … that a reorg nevertheless orphans,
with the amount neither re-owed nor re-minted ⇒ falsifier", which would make even a beyond-
acceptance orphan a falsification and reduce `D_conf` to a label with no accounting
consequence. **The integrator ruled reading (a)** (ruling 2026-08-30, reply to the MD decision
mail): SETTLED is terminal and `D_conf` is a genuine acceptance parameter symmetric with
`D_spine`, so a reorg beyond it is a priced probabilistic residual.
`Config.SETTLED_TERMINAL = True` is therefore **spec-fixed, not an open knob** — the comment in
`model.py` now says so, and reading (b) is no longer offered as a flip. B5's residual-detection
semantics were re-examined against the ruling and are **confirmed correct** (no logic change):
it asserts the residual is exactly bounded and surfaced rather than silent, 1 625 000 units for
a competing branch that reaches depth `D_conf + 1`. The one addition is the informational note
above: the normative floor on `D_conf` is **coinbase maturity**, a spec-level constraint that
the toy value 3 deliberately sits below.

**MD-3 — RULED A. rev3 never stated that coin-chain height is non-decreasing, and the `D_conf`
gate is unsafe without it.** Confirmations are `height − block.height`; if a node can observe a
*shorter* new tip, confirmations fall, and two reorgs each shallower than `D_conf` compose into
a rewrite deeper than `D_conf`, orphaning a payout already marked SETTLED. This was found by
the CONS property test (11/100 schedules red before the schedule bound was declared).
**The integrator ruled A** (same ruling): the normative clause is that *settlement state is
only advanced or re-evaluated against a monotonically non-decreasing best-chain height*. It is
implemented as the guard `monotone_height` over a persisted per-chain high-water
(`Chain.height_hw`, never decreases while the guard is on): a candidate branch that would leave
the chain shorter than its high-water is not adopted, so the composition can never reach the
settled blocks. AT-BROADCAST/**B6 now asserts the prevention** — both candidates refused, the
high-water intact, no SETTLED payout orphaned, nothing vanished, no violation. The hazard is
kept alive as the `--red monotone_height` arm, where the 11/100-style loss returns. The
knock-on modelling consequence is that an orphan is now exhibited by a competing miner's block
at equal-or-greater height rather than by shortening the chain, which is what a real chain does
anyway.

**MD-4 — FOLDED. "paid == payable" is only meaningful at quiescence.** While the spine grows, the
`D_spine` gate keeps a standing in-flight lag by construction (the freshest `D_spine` records
are entitled but not yet payable), so a closing "everyone is whole" assertion can only be made
after miners stop submitting. The harness models this explicitly (`World.quiesce`). The spec
addendum should say the repair guarantee is about the *payable* ledger, not the *earned* one,
or F-REPAIR is trivially falsifiable by pointing at the standing lag.

**MD-5 — RULED C. `N_repair` was reused for two different mechanisms, and forward repair does
not converge uniformly. This was the one finding with real teeth.** rev3 fixes `N_repair` for
leg-1 lagging-chain repair (F-REPAIR) but gives **no window bound at all** for the forward
repair of a post-broadcast spine divergence (F-SPINE: "corrected in subsequent payouts"). The
harness reuses `N_repair` for both, and at the chosen parameters it holds — AT-SPINE/S3 uses
a depth-`D_spine + 2` = 6 reorg and clears at window 2. But the probe `S3_probe_first_depth_
not_clearing_in_N_repair` records where it stops holding: at `W_pplns = 8, D_spine = 4,
N_repair = 3` and an inflow of 2 shares per window, **depth 5 clears at window 1, depth 6 at
window 2, and depth ≥ 7 does not clear within 40 windows at all.** The cause is the coinbase
budget cap of one block reward: per window the ledger creates new payable both from the new
block's own window *and* from every older block whose frozen window gains records as they
bury, and that sum can meet or exceed one reward — so past a certain backlog size nothing
drains while the spine keeps growing. The effect is not monotone in the inflow rate either
(at depth 8, inflows of 0, 1 and 3 shares/window clear at window 2 while an inflow of 2 does
not), so it is a rate-ratio interaction, not a simple threshold. **Consequence as filed:** as
written, F-SPINE's forward-repair leg was not falsifiable-with-a-deadline — there is no N for
which "not repaired within N windows" is a verdict.

**The ruling (C) resolves that finding by changing the property, not by choosing an N.** The
post-broadcast spine-repair leg is now stated N-free:

> after the divergence, at every settled window until the aggregate under-credit (across
> miners still present and in-window) reaches zero, that aggregate MUST STRICTLY DECREASE.

`World.repair_monotone` implements it and AT-SPINE/S3c asserts it; `N_repair` is not consulted
by that path at all. The observed series for the S3 exhibit is **375 000 → 125 000 → 0**. Two
consequential clean-ups came with the ruling:

* **De-alias.** `Config.N_repair` now governs **only** the leg-1 lagging-chain repair
  (AT-REPAIR/R1). Nothing is renamed — the spec addendum cites the name verbatim — but the
  comment in `model.py` and the config table above now scope it. AT-REPAIR/R2 and
  AT-BROADCAST/B1 still pass `N_repair` to `repair_windows()`, purely as a bounded **search
  budget** for §4's coin-orphan re-mint; that is not the spine mechanism and carries no
  deadline claim about it.
* **The probes stay observations.** `S3_probe_first_depth_not_clearing_in_N_repair` (= 7) is
  kept exactly as before — it is the evidence for the finding, not an assertion — and it is
  joined by its N-free counterpart `S3_probe_first_depth_monotone_progress_stalls` (also = 7),
  the first depth at which the newly-ruled property itself would bite. Neither is asserted.
* **B sizing** is answered as an **informational line**, never a check: over the S3 run,
  steady-state payable creation per settled window stayed below one block reward (max 875 000
  against 1 000 000). That headroom is *why* the exhibit drains; the probes mark where it goes.

**MD-6 — FOLDED. Declared schedule bound in CONS.** Coin-chain reorgs are drawn strictly
shallower than `D_conf` and spine reorg branches are strictly longer. Both are *declared*
(MD-2, MD-3), not accidental: beyond-`D_conf` coin reorgs are the accepted residual, exercised
separately in B5. Since MD-3 = A, the non-decreasing-height half of the bound is no longer just
schedule discipline — `monotone_height` would refuse a shortening candidate outright, which
makes the guard inert on this schedule and leaves CONS conserving for the reason it always did.
Deep spine reorgs (beyond `D_spine`) **are** in the schedule mix, because forward repair must
conserve across them.
