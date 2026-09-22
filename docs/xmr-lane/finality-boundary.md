# XMR lane — settlement finality boundary (reorg depth >= D_conf) and the divergence cap

Status: design of record for the recon-final settlement wiring
(`src/c2pool/v37/xmr/xmr_o2_finalize_connect.hpp`, R4/R5/R6). Consensus-neutral:
nothing here touches `OwedLedger`, `owed_digest()` or the W4 fold; it bounds
*when* the finalize driver is allowed to step and *what happens* when two nodes
can no longer agree.

## 1. What FINALIZE means here

A lane block mined at Monero height `H_b` is booked (pending) when the node's
chain view carries it, and **FINALIZED** by `XmrFinalizeDriver::advance_to_tip`
when the best-chain high-water reaches `H_b + D_conf` — one coin-height step at
a time, in order, with `bin_height = H_b + D_conf` (the F1 contract). FINALIZE is
`OwedLedger::on_block_finalized` → `rearm_first_eligible(bin_height)`: it reads
the **whole pending set** at that moment and stamps the K_fair age clock of every
newly-owed key. **SETTLED is terminal.** A block that later leaves the best chain
is disposed by the O3.5 rule as a *priced residual*, not un-settled: the ledger
never rewinds a FINALIZE.

Two consequences follow, and both are consensus-relevant because
`owed_digest` covers them:

1. Every node must run FINALIZE(h) against the **same pending set**. That is
   what the booking order rules below guarantee (R4 + R6).
2. A reorg deeper than the burial depth can drop a block one node has already
   SETTLED. That is the **finality boundary** (§3): out of scope to reconcile.

## 2. Chain-ordered booking — both sides (R4 + R6)

The synced node books a chain block at height `h` the moment it arrives and
then advances the driver, which finalizes `h - D_conf`. So on the synced node
`book(h)` always runs with the finalize cursor at `h - 1 - D_conf`, and
FINALIZE(h) sees exactly the lane blocks in `(h, h + D_conf]`.

A node whose cursor is *held* (its receipt feed is behind → a lane block is
`cut-pending`; or its candidate ring has not reached the winner's state →
`lane-root-unknown`) sees the chain run on while the cursor stays put. Two
things can then go wrong, one on each side of the high-water:

| side | failure | fix |
|---|---|---|
| **below** hw | the cursor steps onto `h` while a canonical lane block at height `<= h + D_conf` is still unbooked → FINALIZE(h) reads a *smaller* pending set | **R4** `booking_gate(h)`: the driver may not step onto `h` while any canonical lane block at height `<= h + D_conf` is booking-pending (retry set) |
| **above** hw | the node books chain blocks at height `> cursor + 1 + D_conf` as they arrive — *earlier, relative to the cursor, than the synced node did* → FINALIZE(cursor+1) reads a *larger* pending set | **R6** `book_chain_block` **defers** any chain block at height `> cursor + 1 + D_conf` (it holds the gate exactly like a retry) and `tick()` books deferred blocks in ascending height as the cursor reaches `h - 1 - D_conf`, re-advancing the driver between bookings (`XmrNode::readvance_settlement`) |

R4 alone was one-sided. The verify rig's RUN3 (receiver 30 s behind the feed,
no reorg at all) forked `owed_digest` at cursor 7: FINALIZE(4) ran with pending
`{5,6,7,8}` on the lagging node and `{5,6,7}` on the synced one — identical
settled sets, identical amounts, a different `first_eligible` (`eo` sign at
`rearm_first_eligible`). With R6 both nodes replay the same sequence

    book(h + D_conf) → FINALIZE(h) → book(h + 1 + D_conf) → FINALIZE(h + 1) → …

whatever their lag or poll cadence. `late_unbooked` (R4) must still read 0;
`booking deferred` (R6, status line `r6:`) is *expected* to be non-zero on a
lagging node — it is the fix working. `--no-book-deferral` switches R6 off for
an A/B comparison only.

## 3. The finality boundary: a reorg of depth >= D_conf

`D_conf` is the burial depth after which a lane block is FINALIZED. If one
daemon reorganises **`>= D_conf` blocks**, a node following the *other* daemon
may already have SETTLED a block the winning chain does not carry:

1. daemon 2 pops `k >= D_conf` blocks and regrows; daemon 1 keeps mining the
   old branch for a while;
2. node A (daemon 1) buries the old blocks `D_conf` deep and FINALIZES them
   (terminal);
3. the regrown branch overtakes; node A's chain view follows it, the old blocks
   become O3.5 *priced residuals* — but their FINALIZE events (and the
   `first_eligible` stamps they caused) stay in A's ledger;
4. node B (daemon 2) never had them: its ledger history is a different
   sequence of states.

From then on the two `owed_digest` sequences never meet again, whatever booking
order is used: SETTLED cannot be undone without rewinding the ledger, which is
exactly what O3.5 forbids. **This is out of scope to reconcile.** It is a
property of the chosen finality rule, not of the wiring.

On **mainnet `D_conf = 60`** (`--d-conf`, default 60). A `>= 60`-deep Monero
reorg has never occurred on mainnet; the 2-minute block time makes it a
two-hour reorganisation. Regtest rigs run `D_conf = 3` to make the boundary
reachable on purpose (verify RUN1: `pop_blocks 3 == D_conf` reproduced it).

Reorgs of depth `< D_conf` are inside the contract: the popped blocks were
still pending, ORPHAN removes them, the regrown blocks are booked and finalized
in chain order, and both nodes converge (verify RUN2: four pops of 1–2 with
`D_conf = 3`, 44 distinct digests identical, credit maps identical; recon-two
run a: the same with R6; run c3: three `pop_blocks 3 == D_conf` on the strong
daemon with the daemons P2P-connected also converged — 73 digests identical —
because the weak side had not buried the popped blocks before the regrown
branch overtook).

### 3.1 The general class: a FINALIZE window the other node never had

The precise condition is broader than "a SETTLED block was dropped".
`rearm_first_eligible` reads `eo(k) = finalW(k) − Σ pending payouts(k)`, so
the **payouts of every block pending in the window `(h, h + D_conf]`** enter
the sign test that arms / disarms `first_eligible` at FINALIZE(h). Two nodes
diverge permanently whenever one of them ran FINALIZE(h) with a block in that
window that the other **never books** — not merely books later (R6 handles
"later"). Ways that happens:

* a reorg of depth `>= D_conf` that drops a SETTLED block (§3);
* a **network partition** during which one daemon carried blocks the other
  never received before they were reorged away (recon-two run c4: daemons
  disconnected for 150 s, `pop_blocks 3` on the strong side; node A had
  FINALIZED 16 with pending `{17, 18, 19}` of which 19 never reached B — B can
  neither reproduce that state nor book A's regrown 17 (its `03` root is the
  post-FINALIZE(16) digest), so the R4 gate holds B at cursor 15 for good);
* by the same mechanism, a **same-height race** whose losing block sat in one
  node's pending window at FINALIZE(h) and never propagated to the other (not
  observed in any recon run — `same-height races: 0` — but natural on mainnet;
  the c2pool#1551 race gate protects the *credit*, not the pending-window
  sign test). Open item, routed to the operator.

Whatever the trigger, the shape afterwards is the same: every subsequent
peer lane block is `lane-root-unknown` here, the gate holds, the cursor
freezes — and §4 is what bounds it.

## 4. The divergence cap (R6 detector) — loud and bounded, never a silent stall

Past the boundary the *post-fork behaviour* used to be the real operational
problem: every subsequent peer lane block carries a `03` root (the winner's
`owed_digest` at the win) that this ledger never passed through, so it is
`lane-root-unknown` here; each one held the R4 gate for its whole retry bound
(600 retries per block), and the finalize cursor trailed the tip indefinitely
(~19 heights in RUN1) with nothing but a per-block "retry #n" line to show for
it.

`FinalizeConnect::divergence_check()` (once per tick) declares the lane
**DIVERGED** when either

* the cursor is more than `divergence_cap_heights` (default `2 * D_conf`)
  behind the buried frontier `hw - D_conf` **while** a canonical lane block is
  `lane-root-unknown`, for `divergence_cap_ticks` (default 20) **consecutive**
  ticks — bounded heights *and* bounded time; or
* `divergence_cap_terminal` (default 2) lane blocks have exhausted the
  root-unknown retry bound.

Honest catch-up does not trip it: a receiver one ledger event behind the winner
resolves `lane-root-unknown` within a few events (`lane_root_unknown_resolved`
counts them), which resets the persistence window; a feed-lagged receiver is
`cut-pending`, not root-unknown, and does not count.

When it fires:

* **one** terminal alarm `cba-ALARM DIVERGENCE (TERMINAL): …` on stdout *and*
  stderr, naming the lag, the cap, the held blocks and the action;
* the finalize gate holds **for good** (cursor frozen at its current height);
* no chain block is booked from then on (`divergence_dropped` counts them,
  logged every 50th) and no retry runs — the 600-per-block retry loop is gone;
* the status line reports `r6: … DIVERGED=1 alarms=1 dropped=N` on every
  status interval.

The node keeps serving templates; its coinbase is built from the frozen
ledger. **Operator action:** stop the node and re-seed its settlement store
from a converged peer (or from a known-good `settle.img` snapshot taken before
the boundary). There is no in-band recovery by design: the alternative — a
ledger that rewinds a FINALIZE — would make `owed_digest` non-monotone and is
exactly what O3.5 rules out.

Knobs: `--divergence-cap-heights <n>` (0 = `2 * D_conf`),
`--divergence-cap-ticks <n>`, `--divergence-cap-terminal <n>` (0 = off).
Self-check: `v37_xmr_o2_finalize_connect_selfcheck` FC17 (chain-ordered
deferral, both sides) and FC18 (the cap: not before the window, once at the
window, halted after it).

## 5. Verify recipe (2-daemon regtest, multiple payees, real E_b)

Both bars are the same rig, different driver
(`~/xmr-recon-two/rig/driver_*.sh` on vm905; ports distinct from the earlier
verify rigs):

* **(a) pops `< D_conf`** + moderate receiver lag: `LAGB=6000`, four
  `pop_blocks` of 1–2 with `D_conf = 3` alternating between the daemons;
* **(b) normal receiver lag, no pops:** `LAGB=30000` (30 s > the block
  interval), no `pop_blocks` at all — the RUN3 shape;
* **(c) the boundary:** `driver_c4.sh` — partition the daemons
  (`out_peers`/`in_peers` = 0 on both, 150 s; `set_bans` is unusable: banning
  127.0.0.1 also refuses the nodes' own RPC), `pop_blocks 3 == D_conf` on the
  strong side, reconnect → the diverged node must ALARM + CAP, not stall. A
  plain `pop_blocks 3` with the daemons connected (`driver_c3.sh`) converged
  three times out of three — the boundary needs a block the other side never
  saw.

Checks: distinct `owed_digest` SEQUENCE A vs B identical; FINALIZED and booked
lists identical; per-bid credit maps identical; `digcursor.py` (first cursor
whose last digest differs = the fork point; SETTLED sets); `pendset2.py` (the
AUTHORITATIVE pending set at every FINALIZE(h), from the `cba-finalize:` line
FinalizeConnect prints inside the driver's walk — the R6 invariant is "zero
differing pending sets"; the older log-order reconstruction `pendset.py` shows
spurious diffs because several events print per tick); `r4/r5:` alarms 0;
`r6:` `DIVERGED=0` for (a)/(b), `DIVERGED=1 alarms=1` on the diverged side for
(c), with `lane_root_unknown terminal=0` (the cap fired before any 600-retry
bound was spent) and the cursor frozen. Before stopping, quiesce (miners off,
both cursors at `hw − D_conf`, `waiting_now=0`) so a lagging node's digest
sequence is compared complete rather than as a truncated prefix.

Results (recon-two, D_conf = 3, 4 payees, real E_b, binary rebuilt from the
committed tree): (a) 48 distinct digests EQUAL, FINALIZED 47 EQUAL, credit maps
equal on all 50 common bids, 0/47 differing pending sets; (b) 37 distinct
digests EQUAL, FINALIZED 36 EQUAL, BOOKED 39 EQUAL, credit maps EQUAL, 0/36
differing pending sets, B deferred 14 bookings (the fix working), R4/R5 alarms
0, DIVERGED 0 on both; (c) B: `DIVERGED=1 alarms=1`, cursor frozen at 15, lag
grew to 18 with no further retries, `terminal=0`; A unaffected.
