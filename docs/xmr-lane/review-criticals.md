# XMR lane: the external payout review, finding by finding

Review: [Fairness gaps in the c2pool payout ledger](https://gist.github.com/SChernykh/636eca0b73181277ea85401b6b1e24ba)
(19 September 2026; mirror: https://gist.github.com/frstrtr/24e51a4a64bb0cc3faf0af653718cece).
Tracking issues #1860 to #1869. Audit response: v37 payout fairness audit, 2026-09-28.

This record states, for the XMR lane with every node recomputing the lane
coinbase (`coinbase-recompute.md`, PR #1882), which findings the protocol now
closes by its own rules ("natively": no trusted builder, no node-local
setting), which are closed by the agreed threshold design
(`payout-threshold.md`, not yet implemented), and which stay open.

## Critical

### 01: overpaid balances go negative and are abandoned

Closed natively.

* **The honest race (H/H+1 double pay).** A template for height T is built
  only at finalize cursor `T - 1 - D_conf` (the booking-point gate). There,
  EffectiveOwed already nets every lane block below T. The owed pass never
  takes more than EffectiveOwed, and pay-now pays only the block's own E_b,
  which the same block credits. An honest block cannot create a negative row.
  Pinned by the rehearsal KAT (`v37_xmr_mainnet_rehearsal_kat` M1/M2: every
  row stays non-negative across 48 blocks and rotating, lagging builders).
* **Q1: `payout <= EffectiveOwed` is enforced.** Every node rebuilds the
  canonical coinbase at the booking point and compares bytes. A block that
  pays anything else is non-canonical (`v37_xmr_coinbase_recompute_kat`
  R5 to R10: double pay, overpay, reorder, under-take, misdirected pay-now,
  stale state).
* **The thief under a throwaway key.** A non-canonical block is booked
  debit-only (ruling 2): its credit is dropped and its on-chain payouts are
  debited. The throwaway key carries the negative row, and nobody else's
  balance changes. The thief gains exactly one block it found, which is the
  finder's power in any decentralized pool (a P2Pool finder can equally mine
  a block that pays only itself). The shortfall does not land on the queue:
  the dropped credit means the pool never owed that block to anyone.
  **Its shares.** A share's coinbase must be the canonical one, as P2Pool
  checks a share's generation transaction: the relay refuses a share mined
  on a template that pays the block elsewhere (`coinbase-recompute.md` §6,
  the `V37R` total and the anchor rule), so a thief cannot keep a found
  block and still earn credit for its shares.
* **The thief paying a ref only some nodes know.** Whether a block's outputs
  all map decides between debit-only booking (mismatch) and a ledger-neutral
  refusal. The booking decode used every ref the node had learned, including
  out-of-band ones (relay arrival, the node's own payee, the owner). A block
  paying such a ref was debited on the nodes that knew it and refused on the
  others: one block split the pool for good (rehearsal M6 reproduced it).
  Now the booking decode maps outputs only through the **booking map**: the
  booked refs plus the refs of the view at the block's own cut. A canonical
  coinbase pays only these refs, so honest blocks are unaffected, and every
  node classifies every block alike. A refused block is the finder's own
  block: the pool never credits it, so what it pays, to whom, changes no
  balance (the same bound as a withheld block).
* **Fork safety.** Every recompute input is a network constant. On mainnet,
  `lane_knob_refusal()` refuses a non-default `--d-conf`, `--settle-h-min`
  and `--settle-output-cap`, plus `--recon-max-root-age` and
  `--no-book-deferral` (audit O-4/O-5). A node that differed would book honest
  blocks debit-only.

### 02: seniority seasoned by parked sub-floor keys

Closed natively. The XMR owed floor is 0 and is now pinned on mainnet. With
no floor there is no CARRY: a key at the head of the queue is paid in full,
reaches 0 and is disarmed. A key cannot stay positive and unpaid at the head.
The spend-cost floor `c` reintroduces an owed floor, so it ships in the same
change as seniority from the floor: a balance below it has no age and is not
paid by the owed pass (`OwedLedgerRules::arm_floor`, `v37_xmr_spend_floor_kat` F7).

## High

| # | finding | XMR lane now |
|---|---|---|
| 03 | identity spam, O(N) walk | **Closed on XMR.** A key needs a full share (or DROPS near-miss work) to exist, and paid rows are pruned. A sub-floor balance has no age and the owed walk skips it. Once a lane block passes its key by, the balance decays after one lane window, halving each half-life down to 0, and the row is removed (`payout-threshold.md` §5). An active miner is never decayed. |
| 04 | no per-payee cap | **Closed (ruled 2026-09-29): rotation on payment**, no cap constant. A key paid in part walks after every other key while the paying block is pending, and its age restarts at FINALIZE (`OwedLedgerRules::rotate_on_payment`, `v37_xmr_spend_floor_kat` F8). Also closes audit O-1. |
| 05a | pre-settle orphan costs seniority | Refuted since #1704; pinned by #1876. |
| 05b | post-settle orphan | By design. The finality boundary is D_conf = 60 (coinbase maturity) and is pinned on mainnet. |
| 06 | residue owner, insolvency | The residue has one owner: the protocol donation output (fee model v1, mandatory on mainnet). **Closed:** every payee, dust included, is paid in the block while there is room. The cash of a payee without a slot is redistributed to the payees paid in the same block and comes off its credit (P2Pool's rule). It is never an advance, so no balance goes negative. Pay-now no longer fails for want of a slot, and every block pays out what it credits (`payout-threshold.md` §3; rehearsal M7: the ledger total stays at the seeded float and no balance is negative; M7b: a fresh pool keeps no balance). |
| 07 | floor depends on address kind | Not applicable: Monero has one output kind and the floor is 0. |

## Low and disclosure

| # | finding | XMR lane now |
|---|---|---|
| 08 | grindable tie-break | Closed: salted tie-break `sha256d("V37T" \|\| prev_id \|\| key)`, recomputed (R15). |
| 09 | fees not disclosed | **Legacy `src/c2pool/payout/` now reports the fees as the sharechain pays them** (ruled 2026-09-29): the dead `developer_payout.*` with its 0.5% floor is deleted; the donation is exactly the miner's give-author percent with no floor (0 leaves the 1-satoshi V36 marker) and its address is the real V36 donation script; the P2P display deducts nothing (the donation shares and the owner's substituted shares are already in PPLNS); the local/solo split keeps its owner output with no 50% cap and no rescaling (only donation + owner <= 100%); pinned by `core_test` `PayoutRules.*`. The owner fee is disclosed in stratum (#1880) and the docs (#1879). **Ruled (2026-09-29): no protocol cap.** The owner fee substitutes the payee of a job, and no other node can tell those receipts from the owner's own work, so a cap would be a rule nobody can check. Disclosure stays; the miner's protection is choice, and the incentive is to run their own all-in-one node (node, daemon and miner) at 0 fee. Later: per-job payee disclosure in stratum so a miner or proxy can check each job's payee against its rbind. |
| E-1 | paper says largest-first | Paper erratum (#1881 for the site; the in-repo `PURPLE-PAPER.md` / `purple-paper.html` are corrected here, with §6 (the window) and §8 (the fused estimator)). |
| §8/§9 | credit sub-threshold work, never pay dust | **Closed by the pay-now ruling.** A worker's share of a block is paid in that block while there is room, dust included, so a sub-threshold worker does not wait at the back of a queue on the pool's survival (`payout-threshold.md` §3, rehearsal M7b). Paper §9 corrected. |
| EST_ONLY | estimator default branches on S | **Closed.** The only factory that enables the gate selects Combined, which has no branch on S; the module default is now Combined too (#1877, carried here), and `v37_w4_estimator_wiring_test` 9 asserts no factory can select EstimateOnly. Paper §8 now describes the one fused estimator. On XMR the credit rule is now Count (row below), which has no branch at all. |
| split | N identities draw steadier income (review note) | **Closed natively: DROPS Count** (ruled 2026-09-30, first release; research `docs/research/drops-split/`). The review understated it: on the XMR geometry the K-min estimator that the XMR build shipped armed was biased -8%..+19% for small miners and paid for splitting (about one share per interval: 0.935 on one identity, 1.187 on 16). XMR now credits every hash below the drops floor at the floor target's own work, `(S + J) * att(floor)`, integer and exact on the 288-bit normalised geometry (att(floor) = 2^26 = 1/64 share, the floor exact for any share_diff). There is no K, no J < K rule and no order statistic, and it is additive over identities, so splitting changes neither the mean nor the variance (`v37_xmr_drops_count_kat` CT1..CT6). |
| window | deflation by pulsing hashrate | **Closed for XMR: variance only, not a fairness hole** (research 2026-09-30, `docs/research/window-pulse/`). Every receipt is the same work at the one lane share difficulty, so the positional window pays a pulser, the miners it deflates and a schedule-aware hopper exactly their work's worth (`v37_xmr_window_pulse_kat`, real `Lane`: 1.0000). Deflation only makes a very small miner's pay lumpier (0.1% miner, 30x pulser: no weight in 40% of blocks, same mean). The V37.1 time window is **not** to be flipped for XMR as designed: it overpays work done just before a hashrate jump (+23% for a hopper in the model). Its native-ridge width law ran to W_MAX and is fixed (`v37_1_width_law_kat`). |
