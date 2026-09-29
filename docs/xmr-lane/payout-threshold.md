# XMR lane: the spend-cost floor and crumbs

Status: **agreed design, not yet implemented** (operator discussion,
2026-09-29, revised the same day). This record keeps the decisions and their
derivations so the implementation, review and paper can cite one source. It
builds on the every-node coinbase recompute (`coinbase-recompute.md`): every
rule below is a function of inputs every node holds, so the recompute
enforces it.

## 1. Goal

Each lane block distributes its whole reward to the miners of its window, in
its own coinbase, and creates no payout that is not worth spending. Nothing
is random, nothing is a pool-chosen constant: the one bound comes from Monero's
consensus fee rule.

## 2. The floor c: the cost to spend one output

    c = quantize_up( w_input × Fl ),   Fl = Monero get_dynamic_base_fee(total, 300000)

* `Fl` is Monero's consensus minimum fee per byte (`Blockchain::check_fee` /
  `get_dynamic_base_fee`, 2021 scaling): `0.95 × R × 3000 / M²`, where `M` is
  the fee median. The fee median is never below the 300 kB penalty-free zone
  (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`), so `M = 300000` gives the
  **largest** minimum fee Monero can require. `R` is the block's own coinbase
  total, which is at least the base reward. So `c` is an upper bound on the
  real minimum cost to spend the output. Every node computes it from the
  block itself: nothing is committed, nothing is looked up.
* `w_input` is the weight one input adds to a RingCT transaction of the
  current hard fork (ring size 16, CLSAG): the input prefix, the key image,
  the CLSAG signature and the pseudo-output. It is derived from the format in
  code, not chosen.
* `quantize_up` rounds up to Monero's fee quantization (`fee_quantization_mask`).

Reference numbers: R = 0.6 XMR gives `Fl ≈ 20 000 piconero/byte` and
`c ≈ 0.000013 XMR`, about 0.002% of the block. For comparison, P2Pool's
minimum payout is about 0.00027 XMR.

**Rulings that shaped this (2026-09-29).**
* No pool-side floor (`t_share`, P2Pool's one-share rule). It is not a Monero
  rule, and it sent every sub-share (DROPS) miner to a lottery.
* **No lottery.** A lottery over sub-floor amounts was proposed and then
  dropped. Its only jobs were amounts below `c` and blocks too full for the
  payouts. Monero blocks leave thousands of free output slots, so the second
  case is rare. For the first, deterministic accumulation is exact per miner.
  A lottery also gives the builder levers to steer the draw: it chooses the
  credit cut, and cheap mempool spam raises a fit-based threshold.
* No `t_fit`. Fitting the coinbase is the output cap's job (§3). A per-block
  threshold from block weight could not be verified by receivers, which hold
  no per-block weight, and the builder could steer it.

## 3. Payouts in a lane block

* **Payees with E_b ≥ c** are paid their E_b in full, in this block (pay-now),
  as today.
* **Crumbs: payees with E_b < c** are credited their E_b but not paid. It
  stays in their balance, and they are paid once the balance reaches `c`.
* **The crumbs' cash is advanced in the same block.** It is spread pro rata
  over the payees paid in this block, at most their own E_b each. Their
  balance goes negative by that advance, and their next credits repay it.
  The block is distributed in full, and no cash goes to the donation.
* **Why this cannot grow.** A crumb balance is at most `c` per miner. The
  advances mirror the crumbs exactly, so every block pays out what it
  credits. When a crumb balance reaches `c` and is paid, that block's other
  payees receive the same amount less. The two cancel.
* **Too few output slots.** When the output cap cannot hold every payee at or
  above `c`, the payees that fit are paid in a deterministic order: largest
  E_b first, ties by the salted key. The rest become balances like crumbs,
  and their cash is advanced the same way. Cash left after the advance cap
  (a pool just started, with nothing to advance against) goes to the
  donation output. It is disclosed, and it is bounded by one block.
* **The owed queue** (K_fair, oldest first) stays as the safety net for
  balances: crumbs that reached `c`, payees that did not fit, a restart,
  DROPS carries and the seeds. In steady state it is nearly empty.
* **Builder latitude.** Receivers cannot verify the weight-aware output cap.
  A builder that claims fewer slots makes more payees wait and advances more
  to the ones paid. An advance is a debt, not a gain: a builder that takes
  one and leaves steals at most its own E_b of that block.

## 4. Published

`c` is recomputed by every node from the block's total, so nothing is added
to the 0x02 payload. Miners see the current `c` in the stratum login reply
and on the HTTP status.

## 5. Abandoned dust

Balances below `c` that belong to a payee with no work in the window
**decay to zero** by the same natural decay as the work weights (MRR). There is
no donation: the write-off only reduces the pool's liability, because the
cash behind it already paid older debts. A returning miner stops the decay.
Each write-off is a visible owed-event leaf, never a silent change.
Horizon and half-life: to be fixed at implementation (proposed: start after
one window of inactivity, half-life = the lane half-life).

## 6. Seniority from the threshold

A balance earns K_fair age only from the moment it reaches `c`, so a parked
dust balance cannot season into the head of the queue (external review 02).
This changes the W4 ledger (`first_eligible` is inside `owed_digest`), so it
is a per-ledger switch that only the XMR lane turns on. Family A lanes stay
byte-identical.

## 6a. Rotation on a partial owed payment

Ruling 2026-09-29 (external review 04 and audit O-1). A key the owed pass
pays **only in part** goes to the back of the queue: its `first_eligible`
becomes the height of that block. A key paid in full leaves the queue as
today, and re-enters at the back when a new unpaid remainder appears.

* No constant: no per-payee cap and no `C_share`. At most one key is paid in
  part per block (the walk stops when the budget runs out), so the queue
  turns over by construction.
* A working miner is unaffected for its current work: pay-now pays each
  block's E_b to the current miners pro rata, outside the queue. Only what
  pay-now did not cover joins the key's balance and waits in the queue.
* It closes O-1: without it, a key credited every block never reaches 0 and
  keeps its old place for ever.
* Like §6 it changes `first_eligible`, which is in `owed_digest`: the same
  XMR-only ledger switch, shipped in the same consensus change.

## 7. Carried forward

* **#1871 pay-now FILL** is superseded: §3 already places every piconero.
* **Postponed:** 0-fee pool-member transactions included by pool builders
  (Monero accepts any fee inside a block: `fee_good = kept_by_block ||
  check_fee`), which would lower `c` for members. Also postponed: a weighted
  multisig for the protocol donation address (governance).

## 8. Implementation order

1. `c` (Monero's fee rule from the block total and `w_input`), with KATs
   against Monero's own numbers.
2. Crumbs and the advance in pay-now, identical in the builder (X6) and the
   receiver (`xmr_paynow`), recomputed; KATs and a rehearsal scenario with
   many small miners and too few slots.
3. Seniority from `c` and rotation on a partial payment (§6, §6a), one
   XMR-only ledger switch. **Ships in the same consensus change as step 2**:
   an owed floor without it reopens external review 02.
4. Dust decay (§5).
