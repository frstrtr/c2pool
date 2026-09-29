# XMR lane: the payout threshold and the sub-threshold lottery

Status: **agreed design, not yet implemented** (operator discussion,
2026-09-29). This record keeps the decisions and their derivations so the
implementation, review and paper can cite one source. It builds on the
every-node coinbase recompute (`coinbase-recompute.md`): every rule below is a
function of inputs every node holds, so the recompute enforces it.

## 1. Goal

Grow without limit and never pay Monero's block-weight penalty. The pool
regulates itself: the coinbase never exceeds the free (penalty-free) part of
the current block, and no payout is created that is not worth spending.
There is no chosen economic constant. Every bound is derived from Monero
consensus rules or from the lane's own consensus parameters.

## 2. The threshold

    t = max(t_share, c, t_fit)

| bound | meaning | derived from |
|---|---|---|
| `t_share` | the value of one share of the window at this block's cut: `R × w_fresh / W_cut`, where `w_fresh` is the undecayed weight of one minimum-difficulty share and `W_cut` the total decayed weight in the window at the committed credit cut (V37C). P2Pool's own rule ("minimum payout = block reward / 2160") generalised to a window whose carrier count changes. | the lane's consensus window (the same view `fold_eb` credits from) |
| `c` | the cost to spend one output: `w_input × Fl`, with `Fl = R × 3000 / Mfw²` per byte, the consensus minimum fee (`Blockchain::check_fee` / `get_dynamic_base_fee`, Monero 2021 scaling). `w_input` is the weight one CLSAG input adds to a transaction. | Monero consensus (reward, median) and the tx format of the current hard fork |
| `t_fit` | the smallest threshold at which every payout at or above it fits in the free part of the block's penalty-free zone: `(zone − weight of the block's transactions − coinbase overhead) / output size`. `zone = max(median, 300000)` (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). | Monero's block-reward penalty rule |

Reference numbers (tail emission R = 0.6 XMR, median at the 300 kB floor):
`Fl ≈ 20 000 piconero/byte`, `c ≈ 0.000014 XMR`. With a full window (8640
receipts, half-life 2160, ≈ 3100 fresh-share equivalents),
`t_share ≈ 0.00019 XMR`, close to P2Pool's 0.00027.

The zone is shared **dynamically** (ruling): the coinbase uses whatever the
block's transactions leave free, so fee income is never displaced and the
threshold only rises when the block is actually full.

## 3. Payouts

* **At or above t**: the payee's E_b is paid in full, as today (the owed pass
  first, oldest debt first; then pay-now).
* **Below t: the lottery** (ruling: replaces advances and dust debt). Each
  sub-threshold payee wins exactly `t` with probability `E_b / t`, by
  systematic sampling. The payees are laid end to end by E_b, and a comb with
  step `t` and a random offset marks the winners, so the winnings sum to
  exactly the sub-threshold E_b. The remainder below `t` is added to the last
  winner. The offset is derived from the block's `prev_id`: unpredictable
  before the parent exists, identical on every node after, so the recompute
  checks it.
* **Fair in expectation, exact in the journal.** Every payee receives exactly
  its E_b on average. The journal books exactly what was paid, so there is no
  advance, no dust debt and no donation of miners' money. Only the 1-piconero
  marker goes to the donation output. This is P2Pool's fairness ("a share in
  the window pays one share's value, with probability proportional to
  hashrate") with the probability computed exactly from work.
* Net of spending fees a payee keeps `E_b × (1 − c/t)`. A larger t only lowers
  fee loss, at the cost of variance, which is why t is not raised by choice.

## 4. Published

The builder commits `t` and the median it used as a new 0x02 field (working
name `V37H`). Every node recomputes both: the median from its own chain index
at height h, and t from the formula. A wrong value makes the block
non-canonical. Miners see t in the stratum login reply and on the HTTP
status.

## 5. Abandoned dust

Owed balances below t that belong to a payee with no work in the window
**decay to zero** by the same natural decay as the work weights (MRR). There is
no donation: the write-off only reduces the pool's liability, because the
cash behind it already paid older debts. A returning miner stops the decay.
Each write-off is a visible owed-event leaf, never a silent change.
Horizon and half-life: to be fixed at implementation (proposed: start after
one window of inactivity, half-life = the lane half-life).

## 6. Seniority from the threshold

A balance earns K_fair age only from the moment it crosses t, so a parked
dust balance cannot season into the head of the queue (external review 02).
This changes the W4 ledger (`first_eligible` is inside `owed_digest`), so it
is a per-ledger switch that only the XMR lane turns on. Family A lanes stay
byte-identical.

## 7. Carried forward

* **#1871 pay-now FILL** stays as the last-resort guard for a block whose
  transactions leave almost no free zone.
* **Postponed:** 0-fee pool-member transactions included by pool builders
  (Monero accepts any fee inside a block: `fee_good = kept_by_block ||
  check_fee`), which would lower `c` for members. Also postponed: a weighted
  multisig for the protocol donation address (governance).

## 8. Implementation order

1. The threshold (`t_share`, `c`, `t_fit`), the `V37H` commitment, and its
   recompute; KATs and a rehearsal scenario with more payees than free outputs.
2. The lottery (systematic sampling on `prev_id`); a KAT that checks
   expectation over many blocks and exact sums per block.
3. Seniority from the threshold (XMR-only ledger switch).
4. Dust decay.
