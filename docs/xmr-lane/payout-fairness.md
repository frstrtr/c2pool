# XMR lane — payout rules, fees and known fairness limits

Status: disclosure of record for the v37 XMR lane, written in response to the
external review "Fairness gaps in the c2pool payout ledger" (2026-09-19,
https://gist.github.com/SChernykh/636eca0b73181277ea85401b6b1e24ba) and the
issues it opened (#1860 to #1869). It states what the shipped code does, not
what the whitepaper says; where the two differ, the code is the rule and the
paper is being corrected. File and line references are to `master`.

## 1. Who gets paid, in what order

A pool block pays two kinds of outputs:

- **Owed outputs.** Balances the ledger owes from earlier blocks, paid
  **oldest first**: sort key `(first_eligible_height ASC, tie-break)`, take
  `min(owed, remaining budget)` per key, at most C outputs
  (`OwedLedger::propose_coinbase`, `src/c2pool/v37/w4_settlement.hpp`). The
  public paper's "largest-first" wording in §7.2 is wrong (erratum E-1); the
  ratified rule is oldest-first.
- **Pay-now outputs (Rule L).** What the owed pass leaves pays the miners
  whose work THIS block credits, pro rata to their share of the block, each
  at most its own share (`src/c2pool/v37/xmr/xmr_paynow.hpp`). Nothing is
  ever advanced beyond work already done.

Tie-break: keys that become owed at the same finalize step share one
`first_eligible_height`, so ties are the normal case. The XMR builder orders
each tie cohort by `sha256d("V37T" || parent block id || key)`, a value the
builder cannot choose and nobody can predict before the parent block exists
(#1874). Before that change the tie-break was the raw identity key, which a
miner could grind.

## 2. Coinbase authority: what other nodes check

On the XMR lane every node books a pool block from its **on-chain coinbase**
(`src/c2pool/v37/xmr/xmr_coinbase_authority.hpp`): each output is mapped back
to a payee identity and booked as a payout. A node's own K_fair recompute is a
cross-check that alarms on a mismatch; it never overrides the chain.

What a receiving node verifies: the block carries this pool's lineage tag,
its committed ledger digest is one this node has lived through and is not
stale, every output maps to a known payee, the on-chain credit cut
reproduces the block's share credit, the pay-now commitment is not
under-paid, and (fee model on) the donation output rule.

What it does **not** verify today: that an owed output is no larger than the
balance actually owed. A builder that over-pays a key the pool knows has the
block booked everywhere; that key's balance goes negative and nets forward
against its future credit (§4). The node prints `ledger-ALARM overpay` when
a block pays more than `max(0, finalized owed) + this block's share` (#1875).
A receiver-side bound is a consensus change and waits on an operator ruling
(owed-sign ruling C-5).

Consequence: the owed-pass order, the payout floor, the tie-break and the
debounce below are **builder policy** on this lane. Honest builders follow
them; nodes with and without them book every block identically.

## 3. Pay-now, the residual and who owns it

After the owed pass and pay-now, whatever is left is the **residual**. It is
never burned:

- fee model `v1` (`--fee-model v1`): the residual folds into the ONE mandatory
  donation output (`src/c2pool/v37/xmr/xmr_fee_model.hpp`, rule S1);
- fee model off (the binary's default): it goes to the serving node's own
  `--residual-sink` wallet, which the operator must configure.

With pay-now working, the residual is rounding only. It was not rounding when
the full pay-now did not fit the coinbase's output cap or when a cut payee had
no payable address: the builder dropped pay-now and the whole leftover went
to the residual while the block's miners were still credited in full at
FINALIZE, so the ledger owed money that had already left (#1865). The builder
now pays the miners with the largest shares first into the free slots and
the leftover shrinks to what cannot be placed (#1871). What still leaves is
counted on the status line (`ledger-overpay: ... sink-unbacked`) so an
operator can see the gap.

Open: whether a builder may pay a slotted miner beyond its own share (a
prepayment netted from its future credit) so that nothing at all leaves.
That needs an operator ruling on the bound.

## 4. The owed ledger

Balances are signed. A key can go negative when the chain books a payout
larger than its balance (a lagged or modified builder, §2) or when a
sub-threshold credit correction is negative. A negative balance is **netted
forward** against the key's future credit; nothing already paid on chain is
ever clawed back. A key that stops mining never repays its negative balance,
and that shortfall is carried by the rest of the pool.

Two rules on the XMR builder reduce how negative rows arise:

- **Debounce** (#1873). A key paid an owed output by a booked, not yet
  finalized block gets no owed output until that block settles; its pay-now
  share is still paid. While the node cannot rule out an unbooked pool block
  on its chain, the owed pass is skipped and the block pays pay-now only.
  This closes the honest case where a node builds on a block it has not yet
  booked and pays the same balances again.
- **Health alarms** (#1875). `ledger-health:` on the status line reports the
  ledger total, the negative rows and the pending payouts;
  `ledger-ALARM aggregate` fires when the total goes below zero (owed-sign
  ruling C-3).

Not enforced yet: the per-key floor and the aggregate bound of the owed-sign
rulings (C-3, C-4) as refusals. They are consensus and wait on the rulings.

## 5. Fees on the XMR lane

There is no fixed pool fee. Three things can reduce what a miner receives:

- **Donation output** (fee model `v1` only): one mandatory output to the
  compiled-in donation address, minimum 1 piconero, carrying the residual and
  the donation's own owed credit. Off by default; every node of one pool
  must run the same setting.
- **Give-author** (`--give-author-pct`, fee model `v1`): a share of THIS
  NODE's jobs is credited to the author. It is a 16-bit value inside the
  miner's own proof-of-work-bound receipt, so every node folds every receipt
  with the value the node that issued the job chose. The package's `node.env`
  sets 0.1; `--give-author-pct 0` opts out; the binary's own default is 0
  with the fee model off.
- **Node-owner fee** (`--node-owner-fee-pct` with `--node-owner-address`,
  fee model `v1`): with probability p percent, a job's payee is the node
  owner instead of the miner, decided when the job is issued and bound into
  that job's proof of work. It is never a fixed output. The value is
  node-local: today the code accepts any value up to 100% and a miner
  connecting to a node cannot learn it from the protocol before mining. A
  cap and a disclosure in the stratum login reply are pending (#1868).

There is no finder bonus.

`src/c2pool/payout/` (a 0.5% developer floor and a node-owner fee up to 50%)
is the **legacy** payout module of the pre-v37 LTC path and is not used by
the v37 lanes; see its README.

## 6. Minimum payout

- XMR: 0. Any owed balance is paid at its turn. `--settle-h-min` other than
  0 is refused on mainnet (#1872), because a floor lets a parked balance
  keep its queue position forever (review findings 02 and 03).
- BTC-family lanes: a byte-denominated floor `k_floor * output_size(kind)`
  with `k_floor = 10` sat/byte (`src/c2pool/v37/w5_coinbase.hpp`,
  `src/sharechain/v37/v37_lane.hpp`): 310 sat for P2WPKH, 320 for P2SH, 340
  for P2PKH, 430 for P2TR. A Taproot address must accumulate about 39% more
  than a P2WPKH address before it is payable, and splitting payouts across
  addresses multiplies the floor. This is block-space pricing and is
  deliberate; the paper did not say so (review finding 07).

## 7. Settings every node of a pool must share

`--d-conf`, `--settle-h-min`, `--recon-max-root-age` and
`--no-book-deferral` change what a node books into the shared ledger and are
not part of the relay handshake, so mismatched nodes split the ledger
silently. On mainnet they are pinned: D_conf 60, floor 0, the other two
refused (#1872).

## 8. Known limits stated plainly

- **Window deflation.** The share window is a fixed count of receipts
  (8640, half-life 2160) over which work weight decays. A large miner pulsing
  its hash rate up narrows the window in time and pushes everyone else's
  trailing work out of it. The time-denominated window planned for v37.1
  addresses this; the shipped window does not.
- **Deep reorgs.** A pool block orphaned after it settled (a reorg deeper
  than D_conf = 60 blocks on Monero) is a priced loss: the amount is
  recorded and surfaced, never re-owed. The loss falls on whoever was at the
  head of the owed queue in that block, not on the pool as a whole.
- **Address privacy.** On the BTC-family lanes the byte floor prices
  address reuse as a discount (§6). Not applicable on XMR.
