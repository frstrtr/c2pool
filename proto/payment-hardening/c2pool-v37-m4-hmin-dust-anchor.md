# V37 M4 — Anchoring h_min to Bitcoin's dust_threshold(type) + a windowed live feerate

Status: DESIGN/RESEARCH draft (frstrtr/the). DESIGN-ONLY — no v37 code to c2pool master.
Supersedes the "invent k" framing in the byte-denominated h_min notes; folds the realblock-955609
flat-k witness into the new max(dust, k_live) shape.

## 1. The refinement (operator-endorsed, 2026-06-27)

Do NOT invent our own floor constant. INHERIT the one Bitcoin already defines, then lift it to track
the live fee market:

    h_min(type) = max( dust_threshold(type),  k_live · size(type) )

- **dust_threshold(type)** — Bitcoin Core's own `GetDustThreshold` = `dustRelayFee` (3 sat/vB default)
  × spend-vbytes(type). Per-type, already a protocol-recognised spendability floor:
  P2PKH 546 / P2SH 540 / P2WPKH 294 / P2WSH 330 / P2TR 330 sat. This is the **hard ALU lower bound**:
  V37 never emits a network-dust output, and it auto-tracks if `dustRelayFee` ever changes. This
  removes the "arbitrary k" objection — the per-type byte-denominated floor is Bitcoin's, not ours.

- **k_live · size(type)** — the **operational** floor. `dust_threshold` is a *correct* hard bound but a
  *poor* operational one: its k = dustRelayFee is a STATIC 3 sat/vB node-policy default, not tied to the
  real fee market (difficulty governs PoW timing only — irrelevant to value floors). At 50 sat/vB a
  294-sat "non-dust" P2WPKH output costs ~1500 sat to spend → underwater. `k_live` lifts the floor so a
  cleared output is economically spendable in the prevailing market.

`size(type)` = full serialized OUTPUT vbytes (P2WPKH 31 / P2SH 32 / P2PKH 34 / P2TR 43 / P2PK 76-uncomp).
`k_live` is in sat/vB. The `max` means: in a calm market the **dust** bound governs (admit the most small
miners); in a hot market the **live** bound governs (don't mint underwater dust). They cross over per type
at `k_live = dust_threshold(type) / size(type)`.

## 2. k_live is WINDOWED, not raw estimatesmartfee (borrow the difficulty pattern)

Raw `estimatesmartfee` spikes on a single congested block and would whipsaw the floor — a miner's
clearing-time / bounded-wait would become unpredictable, breaking the retention property. Borrow the
*pattern* of Bitcoin difficulty retargeting (NOT its value or 2016-block period): k_live is a
**windowed / EMA feerate over the last N blocks, retargeted on a cadence**, tracking the SUSTAINED fee
environment. Whipsaw-resistant ⇒ predictable bounded wait.

- Candidate parameters (to be pinned by the GLM modeling + red-team pass): window N ∈ {144, 288, 1008}
  blocks (≈1d / 2d / 1wk), EMA half-life ≈ N/2, retarget cadence = once per settlement bin (NOT per block).
- **Consensus determinism (critical):** every node MUST derive identical k_live or T_floor diverges →
  coinbase divergence → chain-split (same risk class as the byte-size determinism note). So k_live cannot
  be a free local `estimatesmartfee` read. It must be a **deterministic function of on-chain data** —
  e.g. EMA of realised block feerates (fees / block-vsize) over the trailing window, computed identically
  by all nodes from the headers/blocks they already validate. estimatesmartfee is a *local UX hint only*;
  the consensus floor uses the on-chain windowed feerate. This is the single most important constraint and
  the primary thing the red-team pass must attack (grinding/manipulating the windowed feerate).

## 3. Longitudinal validation (2545 real p2pool BTC coinbase blocks, 2011→2026)

Script: `proto/payment-hardening/hmin-dust-anchor-longitudinal.py` (deterministic; exact counting, not an
LLM job). Output mix: 656,193 P2PKH, 2,707 P2PK, 120 P2WPKH, 1 P2WSH, 20 P2SH, 182 legacy-unknown.

| epoch | outs | k sat/vB | clr% dust-only | clr% max(dust,live) | newly-deferred |
|---|---|---|---|---|---|
| 2011-2015 near-zero | 644,631 | 1-5 | 100.0% | 100.0% | 0 |
| 2016 fee mkt emerges | 6,374 | 20-40 | 100.0% | 100.0% | 0 |
| 2017 Q4 blow-off ~350 | 6,138 | 30-350 | 99.7% | 99.6% | 4 |
| 2018-2020 calm | 1,839 | 5-200 | 100.0% | 100.0% | 0 |
| 2022 bear | 57 | 4-8 | 96.5% | 96.5% | 0 |
| 2023 ordinals | 52 | 12-120 | 98.1% | 98.1% | 0 |
| 2024 runes/halving | 46 | 40-130 | 97.8% | 97.8% | 0 |
| 2025-2026 calm | 86 | 4-6 | 97.7% | 97.7% | 0 |
| **TOTAL** | **659,223** | | **100.0%** | **100.0%** | |

**Crossover (k_live where the operational term overtakes the hard dust floor):**
P2TR > 7.7 · P2WPKH > 9.5 · P2PKH > 16.1 · P2SH > 16.9 sat/vB.

**Findings.**
- F1. Real historical p2pool payout values sit well ABOVE even the fee-tracking operational floor: only
  4 outputs (all in the 2017 ~350 sat/vB blow-off) defer under max() that wouldn't under dust-only. The
  windowed floor therefore adds underwater-dust protection at **near-zero** cost to clearance — the
  bounded-wait / retention property holds across 15 years of real fee environments.
- F2. The dust bound governs the calm majority of history (k_live below the per-type crossover); the live
  bound only engages in sustained-hot epochs (2017, 2021, 2023-24 spikes). The `max` does exactly what it
  should: maximise small-miner on-chain admission when fees are cheap, refuse underwater dust when fees
  are expensive.
- F3. P2WPKH/P2TR have the lowest crossover and lowest absolute floor ⇒ mandating/preferring the compact
  type for floor-level payouts still lowers h_min and admits more small miners (carries the byte-denom
  policy lever forward).

## 4. Integration with the existing settlement rules

- **dust_threshold(type)** = hard ALU lower bound (Rule 0 floor `T_floor`); replaces the bare flat-k floor.
- **k_live windowed EMA** = operational lift; predictable because windowed (the new retention knob).
- **W_max** ASIC-coinbase-size cap = hard output-count ceiling (unchanged).
- **Roundabout accrual** carries sub-h_min owings forward losslessly (anti-forfeiture) — F1 shows this
  buffer absorbs the handful of hot-epoch deferrals without loss.
- **F4 SELECT-determinism preserved:** k_live must be the on-chain windowed feerate (§2), NOT a finder's
  local estimatesmartfee, else fee-adaptivity reintroduces finder influence on eligibility. This is the
  reconciliation with the realblock-955609 "k MUST stay flat / non-fee-adaptive" finding: the floor IS
  now fee-aware, but only via a **consensus-deterministic on-chain** feerate, so no single finder can move
  another miner's eligibility.

## 5. Open items for the GLM modeling + red-team pass (queued on .45:8090)
1. Pin window N, EMA half-life, retarget cadence (whipsaw vs responsiveness tradeoff).
2. Attack the windowed feerate: can a finder grind block feerates (self-stuffing) to push k_live and
   strand a rival's small output past its bounded wait? Quantify cost vs gain.
3. Confirm the on-chain feerate derivation is identical across nodes given orphans/reorgs in the window.
4. Enrich blocks.json with per-block vsize/weight so k_live can be derived from the dataset itself
   (current model keys k_live off an external monthly sustained-feerate series — see §6 gap).

## 6. Data gap (surfaced)
blocks.json carries no per-block vsize/weight, so a true per-block sat/vB feerate cannot be derived from
it. The validation keys k_live off an external EMA-smoothed monthly sustained-feerate series by block date
(coarse but regime-correct; the `max` crossover is the point being demonstrated). Recommend enriching the
longitudinal dataset with vsize for a fully self-contained model (open item §5.4).
