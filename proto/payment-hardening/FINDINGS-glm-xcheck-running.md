# V37 Payment-Hardening — GLM cross-check of Fable report (IN PROGRESS)

Status: GLM-5.2 streaming pass LIVE (cross-check, not from-scratch). This file
accumulates confirmed/disputed verdicts as the stream lands; folds into the single
payment-hardening doc for `frstrtr/the` once the pass completes.

Source: Fable report FABLE-PAYMENT-HARDENING.md (348L). GLM tasked to confirm/dispute
each verdict + the M-2/M-3 designs + quantified bounds.

## Confirmed corrections (GLM disputes Fable, finding stands)

### C1 / M-2 — K_fair queue sort key is sybil-DOSable (DISPUTE — fix required)
- Fable's M-2: K_fair force-include gated on `owed >= T_floor_raw`; serve oldest-unpaid
  eligible identities by **`last_paid_height` ascending**, tie-break canonical id ascending.
  Claimed wait bound `ceil(M/C)`, M = pool_work / T_floor_raw, C = W_kfair / w_out.
- GLM finding: the **`ceil(M/C)` magnitude bound HOLDS** (M is bounded by total real pool
  work, not by identity count — splitting work across N sybils does not inflate M; coinbase
  output-count cap serializes payout over a bounded number of blocks).
- BUT the **fairness/liveness assumption breaks on the sort key**: never-paid sybils have
  `last_paid_height = 0`, so they sort AHEAD of every honest miner who has ever been paid
  (`last_paid_height > 0`). An adversary with a fraction of hashpower continuously mints
  fresh `owed = T_floor_raw` sybils (and can grind ids below an honest id for the tie-break),
  each jumping to the FRONT of the queue → honest miners are indefinitely starved. The
  `ceil(M/C)` bound is then a bound on queue *length*, not on any honest miner's *wait*.
- **Fix (GLM-proposed, adopt):** sort on **`first_eligible_height`** — the block height at
  which `owed` first crossed `T_floor_raw` — ascending, NOT `last_paid_height`. Fresh sybils
  then have a *recent* `first_eligible_height` and go to the BACK of the queue; a long-waiting
  honest miner keeps its early eligibility position. This restores a true per-identity wait
  bound. (Tie-break canonical id ascending is fine once the primary key is monotone-aging.)
- Consensus note: `first_eligible_height` must be a deterministic function of PoW-committed
  state (the height of the share that crossed the threshold), so it is reproducible by every
  verifier — consistent with the non-custody/determinism property already proved for the
  oracle→native SELECT.

### C2 / M-3 — sub-T direct-output opt-out is dust/output-bloat griefable (DISPUTE — bounded, fix tightens)
- Fable's M-3: a miner may elect a direct coinbase output below T (covenant-free, bears its own
  dust-spend cost) — the "hostage-killer" against a custodial pool withholding sub-T balances.
  SELECT sorts candidates by `owed` descending; opt-out (sub-T) outputs are by definition at the
  bottom and consume only leftover budget.
- GLM finding (mid-stream): the opt-out class is still **output-bloat griefable**. An adversary
  splits hashpower into N sybils, does minimal real work on each (`owed` = 1 sat … T-1), elects
  sub-T on all, and floods the leftover coinbase weight with tiny self-outputs. The owed-descending
  sort protects honest `owed >= T` payouts (included first), but the **leftover/opt-out budget**
  can be packed with dust sybils, and `owed = T+1` sybils can even occupy primary space (self-funded
  by real work — no amplification, but real output-count grief bounded by `N_out_max`).
- Steward-designed mitigation (to reconcile with GLM's final verdict — adopt, three parts):
  1. **Opt-out dust floor**: an opt-out output must be `>= max(T_floor_raw, dust_relay_min)`
     (~546 sats P2PKH). 1-sat sybils then cannot elect at all — occupying an opt-out slot costs
     real hashpower `>= dust_relay_min` per slot, with **zero amplification** (the adversary's own
     payout == its own work; it grief-pays itself).
  2. **Separate bounded opt-out budget** `W_optout` (small fixed fraction of coinbase weight),
     disjoint from the primary owed-payout budget and from the M-2 `W_kfair` reserve — so the
     opt-out class can NEVER displace honest `owed>=T` payouts or the K_fair fairness slots.
  3. **Owed-ledger carry on overflow**: any eligible payout that doesn't fit this block (primary
     or opt-out) is NOT dropped — it carries in the finality-gated owed overlay (MRR roundabout
     buffer) to the next block. Output-bloat therefore degrades to **bounded latency, not value
     loss or starvation** — consistent with the convergence verdict (deferral, not stranding).
- Net: "dust-griefable" does NOT survive as a correctness/value break; it survives only as a
  one-block-latency nuisance, fully bounded by `W_optout` + `N_out_max` + the carry overlay.

### C-edge / M-2 — K_fair value-cap exemption vs block reward (NEW — surfaced live, fix already covered)
- GLM (mid-stream) raised: K_fair force-includes are exempt from the per-output **value** cap, so if
  `Σ owed_X(w)` over eligible identities exceeds the block reward+fees `v_X`, the coinbase cannot pay
  them all in one block — a naive force-include could over-commit the coinbase or starve the remainder.
- Resolution (no new mechanism needed): the K_fair reserve is a **weight/output-count** budget
  (`W_kfair`), NOT a value guarantee; per-block payout per identity is still capped at available value,
  and any eligible-but-unpaid amount **carries in the finality-gated owed overlay** (C2 mitigation #3 /
  MRR roundabout buffer). So Σowed > v_X degrades to bounded multi-block latency, never over-commitment
  or value loss. Consensus-safe: the carry is a deterministic function of PoW-committed owed state.
- ACTION: state this explicitly in the consolidated doc (K_fair = count/weight fairness, value bounded
  by coinbase; overflow → overlay carry) so the value-cap interaction is not left implicit.

## Pending (stream still running)
- C2 final GLM conclusion (confirm the floor+budget+carry mitigation), C3..C5 verdicts,
  M-3 opt-out hostage-killer re-derivation, M-6 U256 headroom check.

(poll: /var/tmp/glm-xcheck-payment-live.txt)

## Finding #5 (2026-06-27 15:05) — SELECT determinism break (consensus-bearing)
GLM disputes Fable's non-custody/determinism proof. `coinbase_X = SELECT(R, X, v_X)` is NOT pure in (R,X):
v_X (block reward + fees) is finder-chosen via tx selection, and SELECT's cleared output set depends on the
Σvalue ≤ v_X cap. => finder retains discretion (can shape which payout set clears; self-dealing risk if finder
is a pool miner). This is a CORRECTNESS gap: per-node determinism requires v_X to be consensus-fixed, but it is
finder-elected. Candidate fix (GLM cut off): settle owed against the block-reward SUBSIDY only (consensus-fixed),
treat fees as remainder-pot, so SELECT is independent of the discretionary fee portion. -> decision-needed bundle.

## Finding #6 (2026-06-27 15:20) — v_X block-value-cap omission OVERTURNS Fable C1/C3 "refuted" (MOST CONSEQUENTIAL)
GLM's headline dispute. Fable's liquidity-wait and MM-cut bounds all treat per-block VALUE as unbounded and use
only the FIND cadence E[find_X] = blocktime_X / poolshare_X. But a coinbase can pay a miner at most v_X (block
reward + fees) of value PER block. On a thin/cheap aux lane v_X is tiny, so when owed > v_X the true wait for
FULL liquidity is find_cadence * ceil(owed / v_X), NOT one find cadence.
- Worked NMC example (GLM): v_X ≈ $2/block, owed = $100, 1% pool share, 10 min blocks => $2 every ~16h =>
  ~33 days to clear $100. At r = 100%/yr carrying cost that is a (33/365)*100% ≈ 9% MM cut — which VALIDATES
  the original reviewer's 10–15% MM-monopoly claim that Fable marked "<4% / refuted."
- Therefore Fable C3 "<4% worst-case / ~0 cheap-lane cut" is DISPUTED→REFUTED on thin lanes, and C1's
  "cheap-lane escape hatch" is unsound where v_X < owed. The escape hatch assumed cheap-lane FREQUENCY but
  ignored cheap-lane VALUE.
- Reconciliation note: this is the SAME v_X-cap mechanism already invoked benignly for K_fair (C-edge / C2
  mitigation #3): owed that doesn't fit v_X carries in the finality-gated owed overlay. So it is NOT a value
  break — every miner is still eventually paid — but it IS a LIQUIDITY-LATENCY finding: on thin lanes the
  latency (and thus the financeable MM cut) is bounded by ceil(owed/v_X) block-finds, which can be days/weeks,
  not minutes. The consolidated doc must state the cut bound as r * find_cadence * ceil(owed/v_X), and qualify
  every "cheap-lane liquidity" claim with the v_X >= owed precondition. Verdict: deferral-not-stranding still
  HOLDS (bounded, every miner paid), but Fable's QUANTIFIED cheap-lane bounds do NOT.

## Finding #7 (2026-06-27 15:20) — Fable's DOGE cheap-lane example is function-incompatible (factual error)
Fable section 3.1 uses DOGE as the "free cheap-lane liquidity" example for a BTC (SHA-256) miner. DOGE is
Scrypt (merge-mined under LTC), NOT mergeable with SHA-256 hardware — so a pure-BTC miner cannot draw DOGE
liquidity at all. Fable itself notes in C1 that "SHA-256's aux ecosystem is thin/low-value" (NMC/SYS), which
directly contradicts the DOGE example. Net: the real SHA-256 aux set is thin AND low-v_X (Finding #6), so the
multichain escape hatch is materially weaker than Fable claimed for BTC-primary miners. ACTION: scrub the DOGE
example from the consolidated doc; use a same-function aux (NMC/SYS) and carry the v_X-cap caveat.

## Finding #8 (2026-06-27 15:21) — C5 U256 headroom CONFIRMED (with epoch-rebase precision caveat)
GLM independently re-derived: BTC per-unit raw work ≈ 2^79, ~10^9-unit window ≈ 2^30, used ≈ 2^109 of 2^256 =>
~2^147 headroom. AGREES with Fable's M-6. Caveat to record: the Q62 decay epoch-rebase must be a PURE scaling
of the accumulator (deterministic, height-derived, no truncation/precision loss) — prove it is re-anchoring a
running decay product, not clipping λ to 0; under that proof it is consensus-rule (no format change), not a fork.
