# c2pool V37.0 — Payment-Layer Hardening (consolidated)

Status: for `frstrtr/the` (branch, never master-direct; attribution-gate clean).
Reconciles a payment-hardening design pass with an independent adversarial cross-check.
Both passes are complete; the eight findings below are stable, and where the two
diverged the cross-check is taken as authoritative. No model attribution appears in
this doc per the build-phase rule.

## Scope
Five payment-layer critiques of the converged V37.0 Phase-1 settlement design, plus
the two designs (M-2 hard K_fair fairness floor, M-3 covenant-free native settlement
with miner-elected sub-T opt-out) proposed to close them, plus three quantified bounds
(MM-monopoly cut, U256 fixed-point headroom, oracle→native SELECT determinism).

## Verdict summary (per critique)

| # | Critique | the design pass | Cross-check | Reconciled |
|---|----------|-------|-------------|------------|
| C1 | Hostage sub-T balance | PARTIAL→designed | DISPUTE on bounds | **Bounded, fix required** (sort key + v_X caveat) |
| C2 | Covenant creep | REFUTED | concur (V37.0 is direct queue) | **REFUTED** |
| C3 | MM-monopoly cut | PARTIAL, conclusion refuted | **REFUTED on thin lanes** | **Cut bound restated** (see F6) |
| C4 | Dual-finality | REFUTED | concur (accounting vs payout, TLA+) | **REFUTED** |
| C5 | Fixed-point overflow | PARTIAL bounded | CONFIRM (~2^147 headroom) | **Bounded, no fork** (precision proof) |

## The settlement primitive at issue
`coinbase_X = SELECT(R, X, v_X)` — for sharechain owed-state `R`, paying chain `X`,
realized block value `v_X = subsidy_X + fees_X`. SELECT sorts eligible identities by
`owed` descending, fills outputs subject to `Σ value ≤ v_X` and an output-count/weight
cap, and carries any unpaid eligible owed forward in the finality-gated owed overlay
(MRR roundabout buffer). The hardening findings all turn on two facts the original
designs under-weighted: (a) `v_X` is a per-block VALUE ceiling, and (b) `v_X` is
finder-influenced through tx selection.

## Findings

### F1 — K_fair sort key is sybil-DOSable (C1/M-2; fix required, consensus-bearing)
The `ceil(M/C)` magnitude bound HOLDS (M = pool_work / T_floor_raw is bounded by real
work, not identity count; output-count cap serializes payout). But sorting on
`last_paid_height` ascending lets never-paid sybils (`last_paid_height = 0`) jump ahead
of every honest miner ever paid → indefinite starvation. **Fix: sort on
`first_eligible_height`** (height at which `owed` first crossed `T_floor_raw`) ascending,
tie-break canonical id. Fresh sybils get a recent eligibility height → back of queue;
long-waiting honest miners hold their early position. `first_eligible_height` is a pure
function of PoW-committed state → reproducible by every verifier (consistent with the
non-custody/determinism property).

### F2 — sub-T opt-out is output-bloat grief-prone (C2/M-3; bounded, fix tightens)
Owed-descending SELECT protects honest `owed ≥ T` payouts, but the leftover/opt-out
budget can be packed with dust sybils. Mitigation (three parts): (1) **opt-out dust
floor** `≥ max(T_floor_raw, dust_relay_min)` (~546 sats) → occupying a slot costs real
hashpower with zero amplification (adversary grief-pays itself); (2) **separate bounded
opt-out budget** `W_optout`, disjoint from the primary owed budget and the K_fair
reserve → opt-outs can never displace honest payouts or fairness slots; (3) **owed-ledger
carry on overflow** → any payout that doesn't fit carries in the finality-gated overlay.
Net: degrades to one-block bounded latency, not value loss or starvation.

### F3 — K_fair value-cap exemption vs block reward (C-edge/M-2; covered by carry)
If `Σ owed` over eligible identities exceeds `v_X`, the coinbase cannot pay all in one
block. Resolution needs no new mechanism: K_fair reserve is a **weight/output-count**
budget (`W_kfair`), NOT a value guarantee; per-identity per-block payout stays capped at
available value, unpaid amount carries in the overlay. `Σowed > v_X` → bounded multi-block
latency, never over-commitment. Must be stated explicitly so the value interaction is not
left implicit.

### F4 — SELECT determinism break: v_X is finder-influenced (CORRECTNESS gap)
`SELECT(R, X, v_X)` is not pure in `(R, X)`: `v_X` includes finder-chosen fees, and the
cleared output set depends on the `Σvalue ≤ v_X` cap → finder retains discretion over
which payout set clears (self-dealing risk if finder is a pool miner). **Candidate fix:
settle owed against the consensus-fixed SUBSIDY only; treat fees as remainder-pot**, so
SELECT is independent of the discretionary fee portion. This is consensus-bearing →
bundled to integrator as decision-needed (do NOT self-decide).

### F5 — v_X value-cap omission overturns the design pass's quantified cheap-lane bounds (C1/C3; most consequential)
The design pass's liquidity-wait and MM-cut bounds treat per-block VALUE as unbounded and use only
the FIND cadence `E[find_X] = blocktime_X / poolshare_X`. But a coinbase pays at most
`v_X` of value per block. On a thin/cheap aux lane `v_X` is tiny, so when `owed > v_X` the
true wait for full liquidity is `find_cadence · ceil(owed / v_X)`, not one find cadence.
Worked NMC example: `v_X ≈ $2/block`, owed `$100`, 1% pool share, 10-min blocks → ~$2 per
~16h → ~33 days to clear $100 → at 100%/yr carrying cost ≈ **9% MM cut**, which validates
the original reviewer's 10–15% claim that the design pass marked "<4% / refuted." **Reconciled cut
bound: `r · find_cadence · ceil(owed / v_X)`.** Every "cheap-lane liquidity" claim must
carry the `v_X ≥ owed` precondition. Deferral-not-stranding still HOLDS (bounded, every
miner eventually paid), but the design pass's quantified cheap-lane bounds do NOT.

### F6 — the design pass's DOGE cheap-lane example is function-incompatible (factual error)
The design pass's "free cheap-lane liquidity for a BTC miner" example uses DOGE. DOGE is Scrypt
(merge-mined under LTC), NOT mergeable with SHA-256 hardware → a pure-BTC miner cannot
draw DOGE liquidity at all. The real SHA-256 aux set (NMC/SYS) is thin AND low-`v_X`
(F5). Scrub the DOGE example; use a same-function aux and carry the `v_X`-cap caveat.

### F7 — C5 U256 headroom confirmed (with epoch-rebase precision caveat)
Independent re-derivation: BTC per-unit raw work ≈ 2^79, ~10^9-unit window ≈ 2^30, used
≈ 2^109 of 2^256 → ~2^147 headroom. Agrees with the design pass M-6. Caveat: the Q62 decay
epoch-rebase must be a PURE, height-derived scaling of the accumulator (no truncation /
precision loss) — re-anchoring a running decay product, not clipping λ to 0. Under that
proof it is a consensus rule, not a format change / fork.

### F8 — C4 dual-finality REFUTED (concur)
Accounting finality (owed-ledger, immediate) and payout finality (coinbase, finality-gated
overlay) are distinct clocks; the TLA+ Settlement spec (M1, model-checked) proves the
overlay transitions `BlockFound→OverlayAdded`, `BlockFinalized→OwedSettled+OverlayCleared`,
`BlockOrphaned→OverlayReverted` preserve the owed invariant. No surviving split path.

## Net reconciled position
Economically-stranded does NOT survive: every finding degrades to **bounded latency, not
value loss** (deferral, not stranding), and every miner is eventually paid. Two items are
consensus-bearing and bundle to integrator as decision-needed, NOT self-decided here:
- F1 sort-key change (`first_eligible_height`) — fairness-correctness.
- F4 subsidy-only settlement vs fee-remainder-pot — SELECT determinism.
The quantified cheap-lane bounds (F5/F6) must be restated; the "<4%" headline does not
survive on thin SHA-256 aux lanes.

### Reconciled recommendation (cross-check close-out)

The independent cross-check closed with six actions; they map onto F1–F8 with no new finding:

1. **Lock C2, C4, C5.** The finality model (F8) and the U256 headroom (F7) are correct; the
   covenant scoping (C2) stands. No further work on these.
2. **Close the SELECT determinism gap (F4, consensus-bearing).** The remainder `v_X − Σ owed`
   must have a single deterministic, non-custodial destination — not finder discretion and not a
   pool-held address. Candidate resolutions: settle owed against the consensus-fixed subsidy only
   and route fees through a remainder pot, or carry the surplus forward as committed owed into the
   next block's SELECT. This is a consensus call → bundled to integrator, not self-decided.
3. **Re-derive the M-2 clear rate (F3/F5).** K_fair force-includes obey the value cap, so
   `C = min(W_kfair/w_out, v_X/T_floor_raw)`; on a low-`v_X` lane the value term binds and the wait
   is bounded by `v_X` accumulation, not find cadence. State this; drop any "exempt from the value
   cap" wording.
4. **Bound the M-3 opt-out (F2).** The elected sub-T output needs a minimum economic output size
   (≈ dust-relay floor) to avoid parent-UTXO bloat, and is honest only where it is actually
   spendable — a sub-spendability output the miner cannot CPFP (coinbase immature 100 blocks) is a
   relocated residue, not an extraction.
5. **Restate the cheap-lane bounds (F5/F6).** Scrub the DOGE/Scrypt example (function-incompatible
   for SHA-256 hardware); state plainly that the MM cut reaches ~10–15% for a large `owed` on a thin
   SHA-256 aux ecosystem, and gate every cheap-lane liquidity claim on `v_X ≥ owed`.
6. **Adopt the F1 sort-key fix.** `first_eligible_height` ascending (not `last_paid_height`), so
   fresh sybils cannot jump the fairness queue — consensus-bearing, bundled to integrator.

## Folds required downstream
- M3 consolidation doc: add the `v_X ≥ owed` precondition to every cheap-lane liquidity claim.
- M2 refimpl golden vectors: add K_fair `first_eligible_height` ordering case + a
  `Σowed > v_X` carry-overflow vector.
- decision-needed bundle to integrator: F1 + F4 (both consensus-bearing).
