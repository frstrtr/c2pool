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

    t = max(c, t_fit)

| bound | meaning | derived from |
|---|---|---|
| `c` | the cost to spend one output: `w_input × Fl`, with `Fl = R × 3000 / Mfw²` per byte, the consensus minimum fee (`Blockchain::check_fee` / `get_dynamic_base_fee`, Monero 2021 scaling). `w_input` is the weight one CLSAG input adds to a transaction. | Monero consensus (reward, median) and the tx format of the current hard fork |
| `t_fit` | the smallest threshold at which every payout at or above it fits in the free part of the block's penalty-free zone: `(zone − weight of the block's transactions − coinbase overhead) / output size`. `zone = max(median, 300000)` (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). | Monero's block-reward penalty rule |

Reference numbers (tail emission R = 0.6 XMR, median at the 300 kB floor):
`Fl ≈ 20 000 piconero/byte`, `c ≈ 0.000014 XMR`, about 0.0023% of the block.
For comparison, P2Pool's minimum payout is about 0.00027 XMR.

**No pool-side floor** (ruling, revised 2026-09-29). An earlier draft also
had `t_share`, the value of one share of the window (P2Pool's rule). It is
not a Monero rule, and it solves neither problem the threshold exists for:
`c` already rules out payouts not worth spending, and `t_fit` already keeps
the coinbase inside the free zone. It only sent every sub-share (DROPS)
miner to the lottery, which undid the precision DROPS measures their work
with. Without it, whenever the block has room, every payee at or above `c`
is paid its exact E_b in that block.

The zone is shared **dynamically** (ruling): the coinbase uses whatever the
block's transactions leave free, so fee income is never displaced and the
threshold only rises when the block is actually full.

**Why the ledger cannot grow.** Every canonical block credits its whole
reward (E_b) and pays it out: the owed pass first, then pay-now, then the
1-piconero donation marker. The total owed is therefore constant across
blocks, and paying an old debt only moves it to the current miners. The one
leak was a block whose payouts did not fit (external review 06): E_b was
credited and the residue went to the donation output. `t_fit` makes every
payout at or above `t` fit, and the lottery pays exactly the sub-threshold
sum in pieces of `t`. So every block pays out what it credits.

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

* **#1871 pay-now FILL** stays as the last-resort guard for a block whose
  transactions leave almost no free zone.
* **Postponed:** 0-fee pool-member transactions included by pool builders
  (Monero accepts any fee inside a block: `fee_good = kept_by_block ||
  check_fee`), which would lower `c` for members. Also postponed: a weighted
  multisig for the protocol donation address (governance).

## 8. Implementation order

1. The threshold (`c`, `t_fit`), the `V37H` commitment, and its
   recompute; KATs and a rehearsal scenario with more payees than free outputs.
2. The lottery (systematic sampling on `prev_id`); a KAT that checks
   expectation over many blocks and exact sums per block.
3. Seniority from the threshold and rotation on a partial payment (§6a),
   one XMR-only ledger switch. **Ships in the same
   consensus change as step 1**: a threshold without it is a sub-floor carry,
   which reopens external review 02 (parked keys season their age). Today the
   XMR floor is 0 and pinned on mainnet, so 02 is closed until then.
4. Dust decay.
