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
| 03 | identity spam, O(N) walk | A key needs a full share to exist (receipts self-carry under the carrier identity), and paid rows are pruned. With the floor, a sub-floor balance has no age and the owed walk skips it: that skip is the remaining O(sub-floor keys) cost, about 1 µs per key. Dust decay (`payout-threshold.md` §5, next) removes abandoned sub-floor rows. |
| 04 | no per-payee cap | **Closed (ruled 2026-09-29): rotation on payment**, no cap constant. A key paid in part walks after every other key while the paying block is pending, and its age restarts at FINALIZE (`OwedLedgerRules::rotate_on_payment`, `v37_xmr_spend_floor_kat` F8). Also closes audit O-1. |
| 05a | pre-settle orphan costs seniority | Refuted since #1704; pinned by #1876. |
| 05b | post-settle orphan | By design. The finality boundary is D_conf = 60 (coinbase maturity) and is pinned on mainnet. |
| 06 | residue owner, insolvency | The residue has one owner: the protocol donation output (fee model v1, mandatory on mainnet). **Closed:** every payee, dust included, is paid in the block while there is room. A payee without a slot keeps its E_b as a balance, and its cash is advanced pro rata to the payees paid in the same block (at most their own E_b). Pay-now no longer fails for want of a slot, and every block pays out what it credits (`payout-threshold.md` §3; rehearsal M7: the ledger total stays at the seeded float over 48 blocks; M7b: a fresh pool keeps no balance). Only a pool with nothing to advance against (its first blocks) sends cash to the donation output. |
| 07 | floor depends on address kind | Not applicable: Monero has one output kind and the floor is 0. |

## Low and disclosure

| # | finding | XMR lane now |
|---|---|---|
| 08 | grindable tie-break | Closed: salted tie-break `sha256d("V37T" \|\| prev_id \|\| key)`, recomputed (R15). |
| 09 | fees not disclosed | Legacy `src/c2pool/payout/` is not on the v37 path. The owner fee is disclosed in stratum (#1880) and the docs (#1879). **Ruled (2026-09-29): no protocol cap.** The owner fee substitutes the payee of a job, and no other node can tell those receipts from the owner's own work, so a cap would be a rule nobody can check. Disclosure stays; the miner's protection is choice, and the incentive is to run their own all-in-one node (node, daemon and miner) at 0 fee. Later: per-job payee disclosure in stratum so a miner or proxy can check each job's payee against its rbind. |
| E-1 | paper says largest-first | Paper erratum (#1881). |
| EST_ONLY | estimator default branches on S | #1877 (default Combined). |
| window | deflation by pulsing hashrate | Open, planned for v37.1 and disclosed. |
