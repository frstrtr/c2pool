# XMR lane: the spend-cost floor and paying dust

Status: **§2, §3, §6 and §6a implemented** (the daemon turns them on from the
lane's genesis); §5 (dust decay) is next. Operator discussion 2026-09-29,
revised the same day. This record keeps the decisions and their
derivations so the implementation, review and paper can cite one source. It
builds on the every-node coinbase recompute (`coinbase-recompute.md`): every
rule below is a function of inputs every node holds, so the recompute
enforces it.

## 1. Goal

Each lane block distributes its whole reward to the miners of its window, in
its own coinbase, and records no debt it can avoid. Nothing is random,
nothing is a pool-chosen constant: the one bound comes from Monero's consensus
fee rule, and it decides only who goes first when the block has no room for
everyone.

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

Ruling (2026-09-29, revised): **pay while there is room, dust included.**
Accumulating dust as a debt only defers a payment the block could make now.
Dust outputs are allowed to pile up on chain. Consolidating them for free
into one transaction for pool members is a later stage (§7).

* **Everyone fits (the normal case):** every payee in the window, dust
  included, is paid its exact E_b in this block. No balance, no advance.
  Rehearsal M7b: a fresh pool with 40 dust miners, 24 blocks, every balance
  is 0 except the 1-piconero donation marker.
* **Order when the block has no room for everyone.** Payouts worth spending
  (E_b ≥ c) come before dust: a slot spent on an output that costs more to
  spend than it holds is the worst use of a scarce slot. Within each group
  the order is **oldest first**, the K_fair rule. The price: while the pool
  overflows (more than about 2700 payees in the window), dust waits first
  and its share of those blocks is redistributed. With room, dust is paid
  exactly like everyone. A payee with a waiting balance goes by its
  `first_eligible`, ascending.
  A payee with none is the youngest. Equal ages go by
  `sha256d("V37T" ‖ prev_id ‖ identity)`, the salted tie that nobody can grind.
  The size of E_b never decides. A payee whose cash was redistributed has no
  balance, so it is the youngest again next block, and the salted tie rotates
  who waits.
* **Short pool** (the owed pass paid old debts first): every payee with a
  slot is still paid, and each gets the same fraction of its E_b. The rest
  stays its balance, which the owed queue pays later: a partial payment, not
  an advance.
* **No packing problem.** A payment can be any amount, so filling the slots in
  order and splitting the pool pro rata uses every slot and every piconero.
  Only indivisible items need a knapsack. `v37_xmr_spend_floor_kat` F2c: a
  pool holding half of what was credited pays all 12 payees half each, and
  only the marker is left.
* **Payees that are not admitted** (no slot left). Their cash goes, in order:
  1. **Debt first.** It pays the admitted payees' old positive balances that
     the owed pass left unpaid, in admission order. The waiting payees keep
     their credit. The ledger grows by their E_b and shrinks by the debt paid,
     the same amount. A waiting dust balance then grows until it is worth a
     slot, or decays if its miner is gone (`v37_xmr_spend_floor_kat` F2d).
  2. **Then redistribution** of what is left, when there is not enough debt
     (e.g. the first overflow block). It goes to the admitted payees pro rata
     and comes off the waiting payees' credit for this block. This is
     P2Pool's rule for outputs that do not fit. Their work stays in the window
     and earns in the next blocks.
* **Never an advance** (ruling 2026-09-29). Pay-now is a flow. A miner that
  leaves or changes address never returns work paid ahead, so no payee is
  paid more than it is credited. The redistribution is booked as a credit
  delta (`allocate_exact_sum`'s `credit_delta`, Σ = 0). Every node gets the
  delta from its recompute and applies it to the E_b before the net booking.
  Rehearsal M7: no balance is ever negative.
* The part of a waiting payee's E_b that the owed pass spent on older debts
  (a short pool) stays its balance: that is the queue, not an advance.
* **Why this cannot grow.** A redistribution moves credit and cash
  together, so every block pays out what it credits. Balances come only from
  the owed pass (the queue moving old debt onto current miners), and that
  keeps the total constant.
* **Uncredited cash** (more pool than E_b credited to anyone) stays in the
  residual, which is the donation output. The fold splits the whole reward,
  so in practice only the 1-piconero marker is left.
* **The owed queue** (K_fair, oldest first) stays as the safety net for
  balances at or above `c`: payees that did not fit, a restart, DROPS carries
  and the seeds. In steady state it is empty.
* **The output cap is the wire ceiling (2700), fixed.** The coinbase takes its
  room before any transaction: the native trim reserves it, and the template's
  own pick counts the miner tx first. The transactions fill what is left of
  the free zone, and a 2700-output coinbase (about 113 kB) always fits in the
  300 kB zone. So every receiver checks exactly one cap. Before this, the
  cap came from the builder's own transaction set, which a receiver cannot
  see. A builder could claim fewer slots, push payees into waiting and take
  their cash as an advance on its own key, then abandon the key. That was
  worth about its own hashrate share of extra income per block it found
  (rehearsal M8: such a block is now non-canonical on every node).

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
* **Later: free consolidation of dust outputs.** Pool members' small
  coinbase outputs would be merged, at no fee, into one transaction included
  by pool builders. Monero accepts any fee inside a block
  (`fee_good = kept_by_block || check_fee`). This rides the 0-fee
  pool-member transaction task.
* **Postponed:** 0-fee pool-member transactions included by pool builders
  (Monero accepts any fee inside a block: `fee_good = kept_by_block ||
  check_fee`), which would lower `c` for members. Also postponed: a weighted
  multisig for the protocol donation address (governance).

## 8. Code

| rule | where | pinned by |
|---|---|---|
| `c` | `x6::spend_floor`, `fee_per_byte_at_floor`, `kInputWeight` (`src/impl/xmr/settle/xmr_coinbase.*`) | `v37_xmr_spend_floor_kat` F1 |
| dust, redistribution, slots, the owed floor | `allocate_exact_sum` under `CoinbaseInputs::spend_floor` | F2-F4, F6; rehearsal M7, M7b |
| the receive side | `paynow::net_booking(..., spend_floor)`: net of min(credit, paid) | F5 |
| seniority from the floor, rotation | `OwedLedgerRules` (`w4_settlement.hpp`), `XmrNodeConfig::ledger_*` | F7-F9; rehearsal M7 |
| the fixed output cap | `XmrBlockAssembler::build` (cap = wire ceiling under the floor); recompute accepts only it | rehearsal M8 |
| every node recomputes it | `LaneInputs::spend_floor`, `XmrCoinbaseContext::spend_floor` | rehearsal M7 (48 blocks, 3 nodes, one digest) |

The ledger's arm floor is `spend_floor(kTailSubsidy)`: Monero's tail emission
(`FINAL_SUBSIDY_PER_MINUTE` × 2 minutes) is the smallest reward of any block
since 2022, so it gives the smallest `c` any block has. A constant floor keeps
`first_eligible`, which is in `owed_digest`, a function of the finalized
ledger alone.

Rotation acts twice. At FINALIZE, the paid key's `first_eligible` moves to
that block's height. Before that, while the paying block is still pending,
the K_fair walk visits keys with a pending payout after every other key. The
pending set at the booking point is the same on every node.

## 9. Implementation order

1. `c` (Monero's fee rule from the block total and `w_input`), with KATs
   against Monero's own numbers.
2. Dust and the redistribution in pay-now, identical in the builder (X6) and the
   receiver (`xmr_paynow`), recomputed; KATs and a rehearsal scenario with
   many small miners and too few slots.
3. Seniority from `c` and rotation on a partial payment (§6, §6a), one
   XMR-only ledger switch. **Ships in the same consensus change as step 2**:
   an owed floor without it reopens external review 02.
4. Dust decay (§5).
