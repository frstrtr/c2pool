# XMR lane: every node recomputes the lane coinbase

This is the design record for turning the XMR lane's coinbase from
**coinbase authority** into a **recomputed** coinbase. It implements the
operator rulings of 2026-09-29, which answer the open questions of the v37
payout fairness audit (issues #1860 to #1869):

| ruling | question | answer |
|---|---|---|
| 1 | Who owns the exact-sum residual on mainnet (Q-D3)? | Fee model v1 is **mandatory**. The residual goes to the protocol donation output. |
| 2 | What happens to a block that breaks the rule (Q-C5)? | Its on-chain payouts are **debited** and its credit is **dropped**. |
| 3 | Behind a v37.x gate, or not? | **From the lane's genesis.** No activation gate. |

Code: `src/c2pool/v37/xmr/xmr_coinbase_recompute.hpp` (the rule),
`src/c2pool/v37/main_v37_xmr.cpp` (receiver and builder wiring),
`src/c2pool/v37/xmr/xmr_o2_settlement_provider.hpp` (the booking-point gate),
`src/c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp` (booked refs). The rule is
pinned by `v37_xmr_coinbase_recompute_kat`, which uses real assembled blocks.

## 1. The gap

Under coinbase authority (`xmr_coinbase_authority.hpp`) a receiver books
whatever payout map a lane block carries. It checks that the root matches a
digest it held, the root-age bound, the credit cut, the donation rule and that
pay-now is not under-paid. Nothing compares a payout with an owed balance.
The review's findings follow directly:

* **01b.** A modified builder can over-pay a known key.
* **01c.** An honest builder that assembled its template before booking the
  previous lane block pays one balance twice (#1861). The template provider
  re-keyed on `(height, prev_id, backlog)` only, so such a template stayed in
  service for the whole tip.
* K_fair order, the pay-now split and the committed owed base were builder
  policy, and receivers could not tell an honest builder from a dishonest one.

## 2. The rule

A lane block B at height `h` is **canonical** iff its coinbase is, byte for
byte, the coinbase the builder pipeline itself produces from inputs every node
holds at B's booking point. Compared: the tx public key R; every output's
amount, one-time key and view tag; and the whole `tx_extra`. The pipeline is
`XmrOwedSettlementSource::build` followed by X6 `allocate_exact_sum` /
`build_coinbase`. The receiver calls the same code the builder does: one
function, two callers.

| input | where every node gets it |
|---|---|
| ledger | The receiver's `OwedLedger` before B is booked. R6 books B with the finalize cursor at exactly `h - 1 - D_conf` on every node (`xmr_o2_finalize_connect.hpp`). The R4 gate lets the cursor stand there only once every chain block at or below `h - 1` is decided. That is also where a synced builder stands while it builds on the tip `h - 1`: the same finalized partition and the same pending set. B's committed `lane_commitment` must therefore equal this ledger's `owed_digest`. |
| payee refs (owed pass) | **Booked refs** only (§4). |
| pay-now payees | `settle::project` of the view at B's on-chain credit cut, which is the same view `fold_eb` books. Each payee's ref comes from the view itself. |
| lane config | Chain id, owed floor, owed-selection cap, residual sink and fixed outputs (fee model v1: the donation output, compiled in), pool tag. |
| the block | Height, `prev_id`, major version, the exact-sum total, V37C (cut), V37N (owed base), V37F (empty-cut finder), and the 0x02 payload's worker head (nonce, rbind, padding: free). |

Two builder inputs are not available to a receiver:

* **The reward hint.** The builder picks its owed takes at its own
  `base_reward + Σ(mempool fees)`, which is at least the block's final total.
  With V37N the committed base `B = Σfixed + Σtakes` fixes the takes: a greedy
  K_fair pass over the budget `B - Σfixed` reproduces them exactly.
  (`XmrOwedSettlementSource::build` gained an optional owed-budget override
  for this.) `B` may not commit fewer takes than the K_fair pass pays at the
  block's own total, because that would shift owed money to pay-now; this is
  refused as an **under-take**. Without V37N, the X6 pass at the final total
  truncates the takes to exactly the greedy pass at that total, so the
  recompute runs at the total.
* **The output cap.** The assembler resolves a weight-aware cap from its own
  transaction set. The recompute accepts the caps that can have produced the
  block's output count (`n` and `n + 1`) and the lane ceiling. A smaller cap
  only truncates the owed pass, and a builder can already force that by
  filling its block with its own transactions. This is a known latitude
  (§6).

## 3. The outcome (ruling 2)

`book_from_chain_ex` runs the recompute right after the credit fold:

* **canonical**: booking proceeds as before (RAIN-BACKFILL, DROPS, pay-now
  net booking).
* **mismatch**: `FOUND(credit = {}, payout = the gross on-chain map)`, with
  pay-now included. Money that left the pool on-chain is debited: this is
  forward repair (C-1/C-6), never a clawback, and a double-paid key carries
  the second payment as a debt. The credit is dropped and the block is
  treated as withheld. Refusing the whole block instead would leave the
  double-paid key undebited, which is strictly worse. DROPS composition is
  skipped exactly as a refusal skips it. The CUT-FLOOR still notes the
  block's cut. Alarm line: `cba-ALARM recompute_mismatch`.
* **undecided** (the view at the cut is not readable here yet): `cut-pending`,
  HELD like a relay repair, never refused.

Own wins take the same path, because every lane block is booked from the
chain view. The D2 scratch re-derivation applies the same verdict against its
scratch ledger (`minority::DecodeFn` and `ScratchQuery` carry it).

Why this ledger mutation does not repeat rework-3's fork (`r-c-rework-3.md`
§2). Rework-3 made refusals ledger-neutral because the debit depended on
wire-arrival timing. Here every input is replicated at the booking point:
the ledger (R6), the view at the cut, the lane config, the block bytes, and
the booked refs (§4). The verdict is therefore identical on every node.
`v37_xmr_coinbase_recompute_kat` R11 books a mismatch on two receivers and
checks one `owed_digest`.

## 4. Booked refs

The owed pass decides who is paid and in what order, and every node rebuilds
it. It must not depend on what a node happened to learn out of band: relay
arrival order, its own payee and owner refs, or what a restart reloaded.
Otherwise a builder that carried an owed key for lack of its ref books its
block canonical, while a receiver that knows the ref books the same block
debit-only. R13 shows that hazard.

`XmrOwedFixture` therefore keeps the **booked refs**: refs taught by booked
lane blocks (the view at each booked cut, the refs its outputs paid, its
empty-cut finder), the seeds, and the compiled-in donation.
`pay_of_booked()` resolves only these, and both owed passes use it:

* the builder's templates (`XmrSettlementTemplateProvider::set_owed_pay_of`);
* the recompute of every lane block.

The daemon learns booked refs only when a booking **succeeds**. A block that
is held and retried is therefore recomputed from the same set. The set is
persisted in `<sidecar>.refs`, because bookings below a resumed cursor are
not re-folded after a restart. Pay-now takes each payee's ref from the
projected view itself (R14).

## 5. The builder (conformance)

* **Booking-point gate.** A template for height T is assembled only when the
  finalize cursor stands at `T - 1 - D_conf`. That is the state every
  receiver recomputes it from. While the tip's lane block is unbooked or
  HELD, the template is held: `refresh()` fails with `lane template held:
  ...`, the previous job stays served, and the coinbase status line counts
  `booking-point held`. In steady state this delays the new template by one
  main-loop pass after each tip.
* **Ledger re-key.** `SettlementSnapshot::ledger_seq`: a template never
  outlives the ledger state it was built from.
* **Fee model v1 on mainnet (ruling 1).** `settlement_fee_model_refusal()`:
  `--coinbase v37` on mainnet refuses to start without `--fee-model v1`.
  With the fee model off, the residual is paid to this node's own
  `--residual-sink-*` wallet, which no other node can map or recompute. Test
  networks keep the off mode for rigs that share one sink.

## 6. Known limits and follow-ups

* **Cap latitude.** The recompute accepts any cap that reproduces the block,
  so a builder can truncate its owed pass. Its only gain is pay-now to the
  current cut, whose share of E_b it already gets. Tx stuffing gives the same
  power.
* **V37N base under a binding weight-aware cap.** The builder commits `B`
  from its snapshot's takes, which the snapshot chose at cap 2700. When the
  assembler's weight-aware cap then truncates the owed pass, `B` counts takes
  that are not paid, and the receiver's pay-now pool `total - B` is smaller
  than the one X6 paid. The excess pay-now is booked as an owed payout. The
  recompute reproduces this faithfully (R4), so it is canonical, not a fork.
  But the builder should commit the base of what it actually pays. Follow-up.
* **Builder policy is now consensus.** Before this change, builder-side rules
  on XMR (K_fair tie-break, owed debounce, pay-now fill) were digest-neutral:
  every node booked whatever the chain carried. Now every node recomputes
  with its own builder code, so a change to the builder rule is a consensus
  change: a mixed fleet calls each other's blocks non-canonical. The open
  drafts #1871 (pay-now FILL), #1873 (owed debounce) and #1874 (salted
  tie-break) must ship to every node at once, or be reworked. #1873's
  purpose, the honest H/H+1 double pay, is covered here by the booking-point
  gate (the honest case) and by the recompute (a modified builder).
* **Fee model off on test networks.** The recompute uses the node's own
  sink, so a rig must share one sink. It already had to: a block paying
  another sink does not decode.
