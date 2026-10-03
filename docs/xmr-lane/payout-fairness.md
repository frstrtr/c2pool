# XMR lane — payout rules, fees and known fairness limits

Status: disclosure of record for the v37 XMR lane, written in response to the
external review "Fairness gaps in the c2pool payout ledger" (2026-09-19,
https://gist.github.com/SChernykh/636eca0b73181277ea85401b6b1e24ba) and the
issues it opened (#1860 to #1869). It states what the code on `master` does
since #1884 (every node recomputes the lane coinbase). Where an older paper or
design note says otherwise, the code is the rule. The lane pays by Work
Receipt Settlement (WRS), also called pay-per-receipt (PPR). The design
records behind this page are [`coinbase-recompute.md`](coinbase-recompute.md)
and [`payout-threshold.md`](payout-threshold.md); the review is answered
finding by finding in [`review-criticals.md`](review-criticals.md).

## 1. Who gets paid, in what order

One pipeline builds a lane coinbase: `XmrOwedSettlementSource::build`
(`src/c2pool/v37/xmr/xmr_o2_settlement_source.hpp`), then `allocate_exact_sum`
and `build_coinbase` (`src/impl/xmr/settle/xmr_coinbase.{hpp,cpp}`). The
builder runs it to make a template. Every other node runs the same code to
check the block (§2). The block's reward is spent in this order:

1. **Owed balances** from earlier blocks, oldest first, each at least the
   spend-cost floor c, out of the block's debt slice
   `Delta = min(F, R × min(dh, 64) / 256)` (the drain rule, §3).
2. **Smaller balances** (below c), from what is left of that slice, in output
   slots that pay-now does not need.
3. **Pay-now**: each miner of the window is paid its share of the rest of the
   block, `P = R − debt_paid`, in this block.
4. **The residual**, whatever is left, in the donation output, which is
   always the last output.

§3 gives the rules for each step. The paper's §9 said that owed amounts are
paid "largest first". That was wrong (erratum E-1): the rule is oldest first.
The repository copy (`src/sharechain/v37/PURPLE-PAPER.md`, #1884) and the site
(#1881) are corrected.

## 2. Coinbase recompute: what every node checks

Every node recomputes the coinbase of every lane block
(`verify_lane_coinbase`, `src/c2pool/v37/xmr/xmr_coinbase_recompute.hpp`). A
block is **canonical** only if its coinbase is, byte for byte, the one the
pipeline of §1 produces from inputs every node holds at the block's booking
point: the tx public key, each output's amount, one-time key and view tag,
and the whole `tx_extra`. The inputs are:

- the ledger before the block is booked. Every node books a block at height
  h with its finalize cursor at h - 1 - D_conf
  (`src/c2pool/v37/xmr/xmr_o2_finalize_connect.hpp`), and the block must
  commit that ledger's `owed_digest`;
- the payee refs taught by booked blocks, never refs a node learned out of
  band (`XmrOwedFixture::pay_of_booked`,
  `src/c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp`);
- the payees of the window at the ledger's anchor (§3);
- the lane constants: chain id, owed floor, output cap, the donation output
  and the pool tag (`LaneInputs`);
- what the block states in the open: height, parent, total, credit cut
  (V37C), owed base (V37N) and empty-cut finder (V37F).

The verdict decides how the block is booked (`canon_check` and
`book_from_chain_ex` in `src/c2pool/v37/main_v37_xmr.cpp`):

- **Canonical.** The block is booked as usual.
- **Mismatch.** The block is booked **debit-only**: every on-chain payout,
  pay-now included, is debited, and the block's credit is dropped, as for a
  withheld block. The node prints `cba-ALARM recompute_mismatch`. Money that
  left the pool on chain is never forgotten and never clawed back. A key paid
  twice carries the second payment as a negative balance (§4). Refusing the
  block instead would leave that key undebited.
- **Undecidable.** This node cannot run the recompute yet, usually because
  the view at the block's cut is not readable here. The block is held and
  retried as `cut-pending`. It is never booked debit-only on that ground, so
  a builder is not penalised for a slow receiver.

Every input above is the same on every node, so every node reaches the same
verdict and the same `owed_digest`. Some blocks are refused before the
recompute, as before: one whose committed ledger state is unknown to a
synced node or older than the root-age bound, and one whose outputs do not
all map through the booked refs and the refs of its own cut. A refused
block's credit is not booked, and its payouts are recorded as node-local
liability.

**Shares.** A share must carry the canonical coinbase too, as P2Pool checks a
share's generation transaction. Every lane coinbase states its total as
`"V37R" || u64` in the 0x02 payload (`LaneInputs::commit_total`,
`paynow::parse_reward_total_payload`), so a node can rebuild a relayed
receipt's coinbase from its open `tx_extra` (`verify_share_coinbase`). A
share that is not canonical earns no credit and its sender gets a strike. A
share this node cannot decide is parked, not refused
(`src/c2pool/v37/xmr/relay/xmr_share_verdict.hpp`). So a miner cannot keep a
found block for itself and still be credited for its shares.

**The builder.** A template for height T is built only when the builder's
finalize cursor stands at T - 1 - D_conf, the state every receiver recomputes
from (the booking-point gate, [`coinbase-recompute.md`](coinbase-recompute.md)
§5). This removes the honest case in which two consecutive blocks pay one
balance twice (#1861, closed by #1884).

**Builder rules are consensus.** The owed order, the pay-now split, the
tie-break and the floors used to be builder policy. Every node now rebuilds
every block with its own copy of them, so a node with different rules calls
honest blocks non-canonical. This is why the settings in §7 are pinned on
mainnet.

**Alarms** (#1875). The status line `ledger-health:` reports the number of
rows, the total of finalized balances, the positive and negative rows and the
pending payouts (`OwedLedger::health`, `src/c2pool/v37/w4_settlement.hpp`).
`ledger-ALARM aggregate` fires when that total is below zero (owed-sign
ruling C-3), and `ledger-ALARM row` when one key is more than one block
reward (0.6 XMR) below zero. `ledger-ALARM overpay` fires when a booked block
pays a key more than its positive finalized balance plus its share of the
block. The status line also counts those blocks, and any cash that reached
the donation output while the block's cut stayed credited (`ledger-overpay:
... sink-unbacked`, `paynow_net` in `main_v37_xmr.cpp`). With the recompute in
place, these are cross-checks.

## 3. The owed queue, pay-now and the residual

**The spend-cost floor c.** c is the largest minimum fee Monero can require to
spend one output of the block: Monero's fee per byte at the 300 kB median
floor (`fee_per_byte_at_floor`) times the weight of one ring-16 CLSAG input
(`kInputWeight`, 659), rounded up to Monero's fee quantization (`spend_floor`,
`src/impl/xmr/settle/xmr_coinbase.cpp`). Every node computes it from the
block's own total. At a reward of 0.6 XMR, c is about 0.0000125 XMR
([`payout-threshold.md`](payout-threshold.md) §2).

**The drain rule** (operator rulings 2026-10-02,
[`settlement-drain.md`](settlement-drain.md)). Old balances are paid only out
of a bounded slice of the block, `Delta = min(F, R × min(dh, 64) / 256)`:
F is the sum of every positive balance in the ledger, dh the Monero heights
since this pool's previous lane block (ledger state, `V37Z`). That is R/256
per Monero height, the operator's "1/16 of a block" at P2Pool-main cadence,
at most a quarter of any block. The window is paid first: its E_b is split at
`P = R − debt_paid` and, when everyone has a slot, paid in full, so a
canonical block creates no new balance and the float falls to 0. With no old
balance the block is master's, byte for byte. The three numbers (Q = 16,
H_cap = 64, rule version 1) are lane rules 23-25: a node with other values is
refused at HELLO and sees our lane blocks as ordinary blocks
([`lane-rules.md`](lane-rules.md)).

**Owed pass.** Balances are paid oldest first, by `first_eligible` ascending
(K_fair). Equal ages are the normal case. They are ordered by
`sha256d("V37T" || prev_id || key)`, where `prev_id` is the parent block id: a
value the builder cannot choose and nobody can predict before the parent
exists (`OwedLedger::propose_coinbase_salted`, `w4_settlement.hpp`; turned on
by `kfair_salted_ties` in `main_v37_xmr.cpp`). Each key takes
min(balance, budget left) until the budget (Delta under the drain rule) or the
output cap of 2700 runs out. A balance below c is not taken here
(`allocate_exact_sum`); under the drain rule a take below c(R) is handed to
the dust pass instead of being skipped. When the owed outputs and the window
do not all fit, the owed pass keeps at most
`K_o = max(1, cap_owed × owed_paid_1 / R)` slots, its cash share of the block.

**Pay-now.** What the owed pass leaves pays the miners of the window, each its
E_b: its share of the block's total by window weight (`settle::split_reward`
over the payees of the view, `xmr_o2_settlement_source.hpp`). The view is the
one at the on-chain cut of the latest lane block finalized into the ledger,
the **anchor** (`OwedLedgerRules::anchor_cut`). A block therefore pays the
window as it stood at a lane block buried at least D_conf = 60 blocks (two
hours) deep, and every input of its coinbase is finalized state. Each block
still pays out everything it credits. A new pool with no anchor yet pays each
block to its finder (V37F, `src/c2pool/v37/xmr/xmr_paynow.hpp`).

**Everyone fits** (the normal case). Every payee of the window, dust
included, is paid its exact E_b in this block, and no balance is created. The
output cap is the wire ceiling of 2700 outputs, and a receiver accepts no
other cap (`candidate_caps`).

**Not everyone fits.** Slots go first to payees whose E_b is at least c, then
to dust. Within each group the order is oldest first (a payee with no waiting
balance is the youngest), with ties broken by the same salted hash. Beyond
the c line, the size of E_b never decides (`allocate_exact_sum` with
`CoinbaseInputs::spend_floor`).

**Short pool.** With the drain rule the window's E_b is split at P, the cash
the debt left, so the pool is not short for old debt. When it is short for
another reason (a DROPS due claimed with the window rule off), every payee
with a slot gets the same fraction of its E_b (`paynow_split`); the rest
stays its balance and the drain pays it later. That is a partial payment,
not an advance.

**Payees without a slot.** Their cash is redistributed: it goes to the
admitted payees pro rata and comes off the waiting payees' credit for this
block, which is P2Pool's rule for outputs that do not fit (ruling R4,
2026-10-02, to revisit before FCMP++). Master's earlier DEBT FIRST step,
which paid the admitted payees' old balances out of the waiting payees' cash
and left those waiting an IOU, is removed by the drain rule. Their work stays in
the window and earns in later blocks. Anything left after that stays in the
residual. The redistribution is a credit delta that sums to zero, and every
node gets it from its own recompute (the `credit_delta` of
`allocate_exact_sum`, applied in `paynow_net`). No payee is paid more than it
is credited: pay-now is never an advance.

**Dust balances.** A positive balance that the owed pass did not take is paid
when the block has room. In salted-hash order, each takes one free slot (none
if its payee already has an output) and is paid min(balance, cash left),
before the pay-now split (`pay_dust` in `allocate_exact_sum`; the `owed_dust`
list from `XmrOwedSettlementSource::build`). A balance never waits while a
block has a slot for it.

**The residual.** Monero requires the coinbase to sum exactly to the base
reward plus fees, so whatever is not paid is the residual. It is never
burned. With fee model v1, which mainnet requires
(`settlement_fee_model_refusal`, `src/c2pool/v37/xmr/xmr_node_config.hpp`), it
folds into the one donation output, always the last output. The declared
amount of that output, the marker, is 0 (`kDonationMarkerPico`,
`src/c2pool/v37/xmr/xmr_fee_model.hpp`). The pay-now split gives its rounding
to the miners (largest remainder), so the donation output usually carries
only the donation's own give-author share (§5) and may be a 0-amount output.
With the fee model off (test networks only), the residual goes to the node's
own `--residual-sink-*` wallet. Pay-now no longer fails for lack of a slot,
which was the gap described in #1865.

## 4. The owed ledger

On the XMR lane a balance arises only when a block cannot pay a credit in
full: a short pool, or a payee without a slot. In steady state every block
pays out what it credits and the owed queue is empty
([`payout-threshold.md`](payout-threshold.md) §3).

**No negative balances from honest blocks.** The owed pass never takes more
than a key's EffectiveOwed, pay-now never pays more than E_b, and a dust
balance is paid at most its amount. A canonical block therefore cannot make a
balance negative (`v37_xmr_mainnet_rehearsal_kat` M1, M2 and M7). A negative
balance can only come from a non-canonical block booked debit-only (§2). It
sits on the key that block paid, nets forward against that key's own future
credit, and changes no other balance. Nothing already paid on chain is
clawed back. `ledger-health:` shows such rows (§2).

**Seniority.** A balance earns K_fair age only once it reaches the arm floor,
which is c at Monero's tail emission (`OwedLedgerRules::arm_floor`, set from
`spend_floor(kTailSubsidy)` in `main_v37_xmr.cpp`). A parked dust balance
cannot season into the head of the queue (review finding 02).

**Rotation.** A key that the owed pass pays only in part goes to the back of
the queue. At FINALIZE its `first_eligible` becomes that block's height, and
while the paying block is pending the walk visits it after every other key
(`OwedLedgerRules::rotate_on_payment`; review finding 04). There is no
per-payee cap.

**Dust decay.** A balance below the arm floor decays only after its key is
passed by, that is, when a FINALIZE credits other keys but not it. From then
it is kept for 8640 Monero heights (about 12 days). After that it halves every
2160 heights (about 3 days) down to 0, and the row is removed
(`OwedLedger::decay_dust`; the constants `kXmrDustDecayHorizonHeights` and
`kXmrDustDecayHalfLifeHeights` in `xmr_node_config.hpp`). A new credit clears
the state, so an active miner is never decayed. Negative rows and balances at
or above the floor never decay. The write-off only lowers the pool's
liability; it is paid to no one, and `decayed_total()` counts it. The decay
state is part of `owed_digest` (V37K), so every node decays alike. Because
dust is paid whenever there is room, decay reaches only dust that never found
a slot.

**Sub-threshold work.** In the default XMR build, sub-threshold work
(raindrops) is credited as window weight at its bin and is paid in every lane
block whose window holds it, like a share (V37W,
`OwedLedgerRules::drops_window`). Payees enrolled by a raindrop are kept in a
ledger registry together with their payout ref (V37G, `raindrop_enrol`), so a
node that never saw the raindrop rebuilds the same coinbase. The earlier due
path (V37U, `drops_due`) is still switched on but carries nothing under the
window rule. All three are part of `owed_digest`, and a peer with another
rule set is refused at HELLO (`DROPS_RULE_MISMATCH`). Details: the due and
the registry in [`coinbase-recompute.md`](coinbase-recompute.md) §6, the
window in the comments of `OwedLedgerRules` (`w4_settlement.hpp`), and the
paper's §8 (`src/sharechain/v37/PURPLE-PAPER.md`).

**Where the BTC-family lanes differ.** The rules above are XMR-only.
`OwedLedgerRules` is off by default, so Family A ledgers are unchanged
(`w4_settlement.hpp`). On that generic path, balances can still go negative
and neither the per-key floor nor the aggregate bound is enforced (#1860). A
sub-floor balance keeps its age and parked rows are not pruned (#1887). The
tie-break is the raw identity key (#1867). There is no per-payee cap or
rotation (#1863). The floor depends on the address kind (#1866, §6).

## 5. Fees on the XMR lane

There is no fixed pool fee and no finder bonus. Mainnet requires fee model
v1 (§7), which is implemented in `src/c2pool/v37/xmr/xmr_fee_model.hpp`. Under
it, three things can reduce what a miner receives:

- **Donation output.** One output to the compiled-in donation address,
  always the last output, with a declared amount of 0. It carries the
  residual and the donation's own give-author credit (§3). The address
  follows the node's `--network` (`donation_info`); it is not a setting.
- **Give-author** (`--give-author-pct`). A share of each receipt from this
  node's jobs is credited to the donation. The value d, a 16-bit fraction of
  65535, sits inside the miner's proof-of-work-bound receipt, so every node
  folds every receipt with the value that the issuing node chose. The default
  under fee model v1 is 0.1% (d = 66; `g_give_author_pct` in
  `main_v37_xmr.cpp`, also set in `scripts/xmr-node/node.env.example`). 0 is
  allowed and opts out. A receipt takes one window position whatever its
  value: it is pushed once, at weight 65535, under a composite payee
  (descriptor kind 0x1F, `XMR_LANE_GA`,
  `src/sharechain/v37/v37_descriptor_xmr.hpp`). The settlement projection then
  splits its weight W: floor(W·d/65535) to the donation and the rest to the
  miner (`receipt_lane_pushes`, `settle::project`, `xmr_ga_split`).
- **Node-owner fee** (`--node-owner-fee-pct` with `--node-owner-address`).
  With probability p percent, a job's payee is the node owner instead of the
  miner. This is decided when the job is issued and bound into that job's
  proof of work (`choose_payee`, `owner_fee_hit`). It is never a fixed output.
  The value is set per node, and the code accepts any value up to 100%
  (`pct_to_bp`). Every stratum login reply now states the node's fee model,
  give-author and owner-fee percentages before the miner starts mining
  (`"c2pool":{"fee_model", "give_author_pct", "node_owner_fee_pct"}` in the
  login result, #1880). There is no protocol cap on the owner fee (ruled
  2026-09-29, recorded in [`review-criticals.md`](review-criticals.md)): no
  other node can tell a substituted job from the owner's own work, so a cap
  would be a rule nobody can check. Disclosure is the miner's protection,
  together with the choice of node.

`src/c2pool/payout/` is the legacy payout module of the pre-v37 LTC path. The
v37 lanes do not use it. It now reports what the V36 sharechain pays: the
donation is exactly the miner's give-author percent with no floor, and the
dead `developer_payout.*` with its 0.5% floor has been removed. See its
README.

## 6. Minimum payout

- XMR: no configured floor. `--settle-h-min` must be 0 on mainnet
  (`lane_knob_refusal`, `mainnet_ledger_knob_refusal`; #1872), because a floor
  lets a parked balance keep its queue position (review findings 02 and 03).
  The spend-cost floor c (§3) only orders payments: the owed pass skips a
  balance below c, and that balance is paid as dust when a block has room.
- BTC-family lanes: a byte-denominated floor `k_floor * output_size(kind)`
  with `k_floor = 10` sat/byte (`src/c2pool/v37/w5_coinbase.hpp`,
  `src/sharechain/v37/v37_lane.hpp`): 310 sat for P2WPKH, 320 for P2SH, 340
  for P2PKH, 430 for P2TR. A Taproot address must accumulate about 39% more
  than a P2WPKH address before it is payable, and splitting payouts across
  addresses multiplies the floor. This is block-space pricing and is
  deliberate; the paper did not say so (review finding 07).

## 7. Settings every node of a pool must share

Every node rebuilds every lane coinbase with its own settings, so a setting
that changes what a node books must be the same on every node of a pool. On
mainnet these settings are pinned, and the node refuses to start otherwise
(`settlement_fee_model_refusal`, `lane_knob_refusal` and
`mainnet_ledger_knob_refusal` in `xmr_node_config.hpp`; #1872, #1884):

- `--coinbase v37` needs `--fee-model v1`;
- `--d-conf` must be 60;
- `--settle-h-min` must be 0;
- `--settle-output-cap` must stay at its default;
- `--recon-max-root-age` and `--no-book-deferral` are refused;
- the drain rule's lane rules (`drain_q`, `drain_h_cap`, `drain_rule_version`)
  are network constants with no flag: 0 / 0 / 0 on mainnet until the
  operator's flag day, 16 / 64 / 1 on the test networks.

The fee model is part of the relay handshake, and so is the DROPS rule set.
Since the lane-rules list ([`lane-rules.md`](lane-rules.md)) every other
setting above, the drain rule's three included, is in the HELLO as the
pool's epoch-1 Deployment (RULES RATCHET R1, [`pool-genesis.md`](pool-genesis.md)):
a node with another value is refused by name at HELLO; a block of the same
pool built under other rules is a recompute Mismatch (debit-only) for the
deviant node alone. `--give-author-pct` and `--node-owner-fee-pct` may differ between
nodes: the give-author value rides in each receipt, and the owner fee only
changes a job's payee.

## 8. Known limits stated plainly

- **Window deflation.** The window is the last 8640 receipts, with a
  half-life of 2160 (`LaneParams`, `src/sharechain/v37/v37_lane.hpp`). A miner
  that pulses its hash rate pushes the older receipts of others out sooner,
  but blocks come faster in the same proportion. Every receipt is the same
  work, so the expected pay per unit of work is the same for the pulser, the
  miners it deflates and a hopper who knows the schedule. Deflation changes
  the variance, not the mean: a very small miner's pay gets lumpier
  (`docs/research/window-pulse/`, `v37_xmr_window_pulse_kat`). The
  time-denominated window designed for v37.1 is the one that can be gamed (it
  overpays work done just before a hashrate jump), and it is not to be turned
  on for XMR as designed.
- **Deep reorgs.** A lane block orphaned after it finalized (a reorg deeper
  than D_conf = 60 blocks) is a priced loss: the amount is recorded and
  surfaced, never re-owed. The loss falls on the payees of that block. Nodes
  that followed different chains through such a reorg also keep different
  ledgers ([`finality-boundary.md`](finality-boundary.md)).
- **Late receipts.** A receipt more than 30 bins (about one hour) behind the
  highest bin already in the lane order is dropped and not credited
  (`kLateTailBins`, `src/c2pool/v37/xmr/relay/xmr_order_rule.hpp`). This bound
  has not been ratified.
- **Registry growth.** The DROPS enrolment registry (V37G) gains a record for
  every payee enrolled by raindrop and is never pruned
  (`w4_settlement.hpp`). Neither is the identity-to-ref map of the DROPS
  harvest (`src/c2pool/v37/xmr/xmr_drops_wiring.hpp`).
- **No live multinode run yet** with the new DROPS rules. The evidence so
  far is the three-node rehearsal (`v37_xmr_mainnet_rehearsal_kat`) and the
  unit KATs.
- **Repair answers.** A relayed receipt that this node could not decide, but
  admitted as part of a winner's lane repair, is trusted on the winner's
  word ([`coinbase-recompute.md`](coinbase-recompute.md) §6).
- **Test flakes.** #1885, #1889 and #1890 are timing-sensitive relay tests.
  They do not touch the payout rules.
- **Merged mining.** The V36 merged-mining path has no V37 counterpart: there
  is no AuxPoW in the V37 code. On XMR the 0x03 merge-mining tag only carries
  the ledger commitment.
- **BTC-family lanes.** The review's findings on the generic path stay open
  in #1860, #1863, #1866, #1867 and #1887 (§4). #1861 was XMR-only and was
  closed by #1884.
- **Address privacy.** On the BTC-family lanes the byte floor makes address
  reuse cheaper (§6). This does not apply on XMR.
- **The drain's price.** While old balances exist the window gives up
  `min(dh, 64) / 256` of each block (6.0-6.3 % on average at P2Pool-main
  cadence, at most 25 % of one block); after that, nothing. A lane that finds
  a block less often than every 64 Monero heights drains in more days: at
  P2Pool-mini cadence 1.2 XMR takes about 1.4 days, at nano cadence about 16
  days ([`settlement-drain.md`](settlement-drain.md)). In an overflowing pool
  the sub-c waiters lose their share of those blocks to the admitted payees
  (P2Pool's rule, ruling R4).
