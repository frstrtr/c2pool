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
The planned payout threshold would reintroduce a floor, so it ships in the
same consensus change as seniority-from-the-threshold
(`payout-threshold.md` §6, §8).

## High

| # | finding | XMR lane now |
|---|---|---|
| 03 | identity spam, O(N) walk | No floor, so the walk stops at budget 0 or the slot cap. Paid rows are pruned. Receipts self-carry under the carrier identity, so an identity costs a full share. |
| 04 | no per-payee cap | **Ruled (2026-09-29): rotation on a partial payment**, no cap constant: a key paid in part goes to the back of the queue (`payout-threshold.md` §6a). Designed, ships with the threshold. Also closes audit O-1. |
| 05a | pre-settle orphan costs seniority | Refuted since #1704; pinned by #1876. |
| 05b | post-settle orphan | By design. The finality boundary is D_conf = 60 (coinbase maturity) and is pinned on mainnet. |
| 06 | residue owner, insolvency | The residue has one owner: the protocol donation output (fee model v1, mandatory on mainnet). **Open:** when pay-now needs more output slots than the block's cap has, pay-now is dropped, E_b is credited as owed, and the residual goes to the donation output (`xmr_o2_settlement_source.hpp`, CapTooSmall). The threshold's t_fit and the lottery close this. #1871 FILL is the last-resort guard. |
| 07 | floor depends on address kind | Not applicable: Monero has one output kind and the floor is 0. |

## Low and disclosure

| # | finding | XMR lane now |
|---|---|---|
| 08 | grindable tie-break | Closed: salted tie-break `sha256d("V37T" \|\| prev_id \|\| key)`, recomputed (R15). |
| 09 | fees not disclosed | Legacy `src/c2pool/payout/` is not on the v37 path. The owner fee is disclosed in stratum (#1880) and the docs (#1879). A protocol cap on the owner fee is not yet ruled. |
| E-1 | paper says largest-first | Paper erratum (#1881). |
| EST_ONLY | estimator default branches on S | #1877 (default Combined). |
| window | deflation by pulsing hashrate | Open, planned for v37.1 and disclosed. |
