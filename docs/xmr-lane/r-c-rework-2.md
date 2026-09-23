# XMR lane R-C rework-2: money path, halt rule, restart liveness

This is the design record for the second rework of the XMR lane's R-C
("refused lane block") handling. It covers what the branch implements, the
invariants it keeps, and the items left as design with their exact seams.
Every change is in the consumer tree (`src/c2pool/v37/xmr/`,
`src/c2pool/v37/main_v37_xmr.cpp`, `src/impl/xmr/node/`). Nothing touches the
settlement canon (`w4_settlement.hpp`, the owed_digest fold) and nothing bumps
a digest tag.

## 1. What was wrong (the verify findings this answers)

| id | defect | fix here |
|---|---|---|
| F-MONEY | A refused block's on-chain payout was never debited: `finalW += credit, -= payout` runs only at FINALIZE of a booked block, so `owed(k)` stayed over-stated and the next K_fair coinbase paid the same payees again. | §2 debit-on-refuse (M1, M2, M3(b), M4) |
| F1 | `--owed-demo-amount` seeding (`XmrOwedFixture::seed_owed`) mutated the ledger outside the write-ahead log. `RecoveryDriver` therefore replayed a digest history that never contained the states the node lived through, so a lane block committing a pre-restart state was refused after a restart, which forked the node. | seeds go through the event log (§5) |
| O3.5 | A header-fetch failure in `chain_carries` answered "not carried" and the finalize walk ORPHANED a canonical block. | tri-state carry, `Unknown` holds the walk (§5) |
| HOLD cap | After 600 attempts a root-unknown block fell into `booking_stall_timeout` -> REFUSED -> memoized, and its credit was dropped. | HELD state, never dropped (§4) |
| F2 | Lane blocks mined while the node was down, or across a ZMQ gap wider than the 64-row reconcile walk, never produced an Extend and were never booked. | gap re-drive + gap gate (§5) |
| HALT | "M=3 consecutive, >= 2 distinct roots" did not tell a forker from the majority. A live diverged builder commits a new root at every own FINALIZE, so three of its blocks in a row halted every honest node, and its own booked blocks reset its own run. | lineage vote (§3) |
| SUSPEND | The CPU miner was never told about a suspension. "Job withdrawn" was an atomic flip, and a one-pass race separated the halt from `set_lane_suspended`. | §6 |
| lag vs R6 | The lag-gate used `tip - cursor` while R6 used `(tip - D_conf) - cursor`, and auto-RESUME never fired. | one definition with hysteresis, and split counters (§6) |

## 2. Money path: debit-on-refuse

**M1: debit the attributable payout.** When a canonical lane block is not
credited for any reason and its payout map `P_b` (identity to piconero, sink
excluded) can be decoded, `FinalizeConnect` books a debit-only FOUND
`FOUND(b, credit = {}, payout = P_b)` through the existing seam
`XmrNode::on_network_block_won`. It is booked at the same chain-ordered point
where a credited booking would land, because the call runs from
`book_chain_block` after the R6 deferral. The effect is that `eo(k) -= P_b(k)`
immediately, and FINALIZE at `h + D_conf` applies `finalW(k) -= P_b(k)`. A
negative `finalW` is the canon's §4.4 "over-credit netted forward" and is
never clawed back. An ORPHAN before burial is a pure removal (nothing was paid
on the final chain). An empty-credit FOUND is already a legal ledger leaf (zero
rows are normalized away), so no tag is bumped.
Seams: `FinalizeConnect::refuse_money` / `book_debit_only`
(`xmr_o2_finalize_connect.hpp`); the rich callback
`FinalizeConnectOptions::book_from_chain_ex` / `ChainBooking`; main's
`fo.book_from_chain_ex` fills `payout` + `payout_decoded` before every
credit-side refusal (`cut_absent`, `cut_mismatch`, `fold_eb` refused, cut-pending
timeout, height mismatch).

**M2: suspense for the unattributable part.** If `P_b` cannot be attributed,
the value goes to a node-local SUSPENSE tally and never to a ledger key. There
are two cases. When the root is unknown there is no `r`, so the whole
`total`, sink included, goes to suspense. When some outputs are unmapped
(`xmr_coinbase_authority.hpp` now keeps the mapped part plus
`unmapped_total` instead of clearing the map), only `unmapped_total` goes to
suspense. The tally is persisted append-only in `<sidecar>.suspense`,
reloaded at boot, counted (`refused_unattributed`, `_pico`), and alarmed every
50 ticks while non-empty. It is never a ledger key: whether this node holds a
lane_commitment is node-local knowledge, and putting it in `owed_digest` would
fork two honest refusers.

**M3(b): late attribution through the wire descriptor.** Payout attribution
authenticates itself (`r*G == R`, and every output must map), so any
lane_commitment guess is safe to use for attribution even when it is useless
for credit. When a root-unknown block has a v0x02 wire descriptor, main
re-decodes it with the descriptor's `owed_digest_at_win` for the payout only
(`cba-attrib:` line, counter `attributed_by_wire`). The credit is still
refused.

**M4: booking kinds.** `PendingRec.kind` is one of `a` (option-A own win),
`c` (credited chain booking) or `d` (debit-only). The sidecar v2 line carries
the kind and both maps, so the boot re-drive re-registers the same FOUND. v1
re-derived `{payee: reward}` for every record, which was wrong for `c` and
`d`. v1 lines still parse. A `d` record never enters the race book as "own"
and is excluded from the R-7 credit cross-check.

**Invariants** (FC21 and FC22 assert them):
* I1: `finalW(k) = C(k) - P(k)` over SETTLED blocks, and
  `eo(k) = finalW(k) - Q(k)` (Q = pending payout). Proof by induction on the
  event log; a debit-only FOUND is the case credit = {}.
* I2: over canonical buried lane blocks,
  `sum of on-chain owed outputs = sum_k P(k) + U` (U = suspense). Before this
  change I2 failed: refused blocks were in neither P nor U.
* I3: any coinbase pays `k <= eo(k)`, and a refused block enters Q at
  booking, so the chain never pays k twice.
* I4: two honest nodes that attribute block b hold identical `payout_b`.
  Their `finalW` differs by exactly the refused credit, plus the knowledge
  delta confined to U.
* Settlement.tla G (aggregate `finalW >= 0`) may be violated per key on a
  refusing node. That is the intended §4.4 signed forward repair.

**Left as design:**
* **M3, late debit** (`h <= cursor`, `late_unbooked`): a debit at a height
  the cursor has already passed has no chain-ordered point. Booking it at
  `cursor + 1` would make the maturity check orphan it, because the bid is
  not at that height. The gate plus the F2 re-drive make `late_unbooked`
  unreachable except after a truncated gap or a boot cursor mismatch, and both
  of those are loud. Seam: the `h <= cursor` branch of
  `FinalizeConnect::book_chain_block`, plus a driver seam that finalizes a bid
  at an explicit step height.
* **M5, the lane_commitment preimage in-band** (operator-hand consensus seam,
  follow-up PR): `0x02 [nonce|pad|"V37C"|P|spine|"V37D"|lane_commitment]` is
  32 B of constant weight and verifiable as
  `mm_commitment_root(chain_id, lane_commitment) == 0x03 root`
  (`src/impl/xmr/settle/xmr_coinbase.cpp`). With it every node derives `r` for
  every lane block, so U collapses to parse failures and "refused" stops
  being a money event at all. This changes the coinbase shape, so it needs the
  coinbase-shape golden and the operator's hand (`xmr_credit_cut.hpp`).
* **Payee registry**: attribution keys are the fixture's learned refs, which
  are never pruned. A lane-wide `PayoutDescriptor` registry replaces them once
  the S-1 carrier relay feeds descriptors in. Side note: the credit-cut KAT
  fixture aliases `make_xmr_std(P1,P2)` and `make_xmr_sub(P1,P2)` to the same
  one-time output, so two identities can claim one output. The decoder picks
  the first one it finds.

## 3. Halt rule: the lineage vote

A count of refused blocks can never be the halt trigger, for three reasons.
First, one live forker commits a fresh root at every own FINALIZE. Second, a
consecutive run is a coin-flip test on a single hashrate share
(`s^M` per position). Third, any Monero miner can append a random
`03 21 00 <32 bytes>` tail, and under an unknown root such a block cannot be
told apart from a diverged lane block. The only unforgeable evidence is
on-chain PoW attributed to a lineage that is verifiably reproducible.

Each node is in one of three states (`FinalizeConnect::evaluate_vote`,
constants in `FinalizeConnectOptions`):

| state | condition | effect |
|---|---|---|
| CONVERGED | refused fraction over the last `vote_obs_window` (24) frontier lane blocks < 1/3 | normal |
| CONTESTED | refused fraction >= 1/3 with >= `vote_obs_min` (6) observations, no verified counter-lineage outvoting us | loud alarm; keeps building, keeps refusing-not-crediting (payout debited); **never halts** |
| ISOLATED | a VERIFIED counter-lineage L' holds >= `vote_k_min` (8) and >= 2/3 of the attributed blocks since its fork height (window 32) | lane production suspended synchronously through the isolation hook; booking continues; **non-terminal**: exits after `vote_exit_hold` (16) attributed blocks below 2/3 |

Attribution: a booked block counts for the node's own lineage. A refused
block whose root is in L' counts for L'. Anything else is UNATTRIBUTED. It
counts in the CONTESTED fraction, so the operator sees it, but it never votes,
which is what defeats the outsider trigger. The dead zone (1/3, 2/3) stays
CONTESTED on both sides: near 50/50 neither side halts, and the operator gets
two verified lineages to choose from. Observations are not persisted: a
restart clears the window and warm-up starts again.

`register_counter_lineage(roots, fork_height, source)` is the only way into
ISOLATED. **Its contract is that the caller has VERIFIED the lineage**, using
the W6 verifier below. No production caller exists yet, so in production a
node can only be CONVERGED or CONTESTED until the verifier lands. This is
deliberate: without verification, a refusal is not evidence.

Constants (consumer-side, not consensus): `vote_obs_window=24`,
`vote_obs_min=6`, `contest=1/3`, `vote_window=32`, `vote_k_min=8`,
`iso=2/3`, `vote_exit_hold=16`, `vote_stale_s=48h`.

Residual: outsider tags can force CONTESTED, which is loud but never a halt.
They cannot force ISOLATED.

Rejected as halt criteria: counting distinct builder identities (no identity
exists on-chain, and an unauthenticated tag is free to forge) and unweighted
peer corroboration (a vote that can be sybiled). Peers are accepted as a
source of evidence, meaning snapshots this node verifies itself, not as
voters.

## 4. HELD: the hold cap never drops

A transient failure (root unknown while the node is not yet decidable, or a
block fetch or parse failure) is retried every tick up to `retry_bound` (600).
After that it is HELD:
* it stays in the retry set, so it keeps holding the R4 gate;
* it is re-tried every `held_retry_every` (50) ticks, so a reclassification
  (decidable, which means refused with a debit) or a recovered fetch still
  lands;
* it raises `cba-ALARM HELD` and is counted (`held_now`, `held_entered`,
  `held_resolved`).

The R6 cap becomes HELD-LAG, which is non-terminal
(`docs/xmr-lane/finality-boundary.md` §4). A cut-pending timeout is still
released loudly, and its payout is now debited.

## 5. Restart liveness

**F1.** `XmrFinalizeDriver::seed_settled` writes FOUND then FINALIZE to the
write-ahead log, each before its ledger mutation and each firing the
ledger-event observer that feeds the RECON ring. `XmrNode::seed_settled_owed`
wraps it, and `XmrOwedFixture::set_seed_sink` routes `seed_owed` through it.
On a resumed store the seed is already in the log, so it is not re-applied.
KAT FC24 checks that the live digest sequence equals `boot_digest_history()`
after a restart. The control FC24n reproduces the pre-fix mismatch.

**Tri-state carry.** `XmrNode::chain_carries3` returns `Yes`, `No` or
`Unknown`. `Unknown` means the row is absent and the daemon header fetch
failed. `MonerodAdapter::ensure_row(h, fetch_failed)` reports the
difference. The driver's carry probe holds the walk at `h-1` on `Unknown`
before mutating anything at h. The booking gate treats `Unknown` as carried
(hold). A deferred or retry entry is dropped only on a positive `No`. KAT:
FC25a/b.

**F2 gap re-drive.** This is daemon-first, enabled by `enable_gap_redrive()`
before `bring_up`. The node tracks the scan height, meaning the highest height
delivered to the booking observer:
* on an Extend at `H > scan + 1`, heights `(scan, H)` are re-driven in
  ascending order through the same observers, fetching the header per height
  (`ensure_row`);
* a node-side gap gate holds the finalize walk at any h with
  `h + D_conf > scan`;
* on a resumed store the scan starts at the recovered cursor, so the boot tip
  that `initial_sync` applied before the observers existed, every block mined
  during downtime, and any deferred-but-unbooked block lost with the previous
  process are all re-driven on the first tick;
* a fetch failure stops the re-drive at that height. The gate keeps holding
  and the next tick retries;
* a gap wider than the mirror retention is truncated loudly.

KAT: FC26a/b/c; the control FC26n reproduces the pre-fix loss. The p2p-first
arm is not covered: the native index pumps every block it connects, and that
is the native arm's own contract.

## 6. Lane suspend

* Lag uses one definition everywhere: `lag = (hw - D_conf) - cursor`. The
  lane suspends at `lag > 2*D_conf` and resumes at `lag <= D_conf`. The
  suspend causes are `lag`, `isolated` and `held`, and there are split
  counters (`suspend lag/isolated/held`, `resume`) in the `suspend:` status
  line.
* On the suspend edge: `cpu_miner->stop()`, queued hits are discarded, and
  `pump_miner` drains and discards while suspended. The stratum side
  disconnects every session (a CryptoNote-stratum miner cannot be told to stop
  hashing, so the job is withdrawn by disconnect). A login while suspended is
  parked, `getjob` is refused, and the resume edge serves parked logins a
  fresh template. KAT: `v37_xmr_lane_suspend_selfcheck` LS1-LS7.
* The race is closed in two ways. The ISOLATED edge suspends synchronously
  inside `fc.tick()` through `set_isolation_hook`. The listener's sink tap
  also refuses a share or network block that was validated before the flip
  but handed off after it (`suspended_sink_refused`).

## 7. W6 verified resync (design)

A snapshot is the directory `settle.img` + `pfound.tsv` + `pfound.tsv.suspense`
+ `snapshot.meta` (chain_id, lane params hash, tip digest, event_seq, cursor,
wall time, source tag). Verification runs against a throwaway `OwedLedger`
plus the daemon:
1. Replay with `RecoveryDriver::recover(..., after_event)` and collect the
   digest sequence `D'_0..D'_n`. A torn store is REJECTED.
2. Lane params must match: chain_id, D_conf, sink identity. Until the pool-id
   GAP is closed, compare `lane_chain` and `residual_sink_identity`.
3. For every FOUND `(bid, credit, payout)`: `get_block(bid)`; the block must be
   canonical at its height (tri-state, and `Unknown` means PENDING, not
   REJECT). It is decoded with candidates `{D'_i : i < event index}`. The
   payout must equal the event's payout exactly, and the 0x02 cut must fold to
   the event's credit (`replay_view` / `fold_eb`).
4. Every FINALIZE must have `bin_height == height(bid) + D_conf` with the
   block still canonical. Every ORPHAN's block must not be canonical.
5. Completeness: every canonical lane block whose root is in `{D'}` and whose
   height is at or below the snapshot cursor is SETTLED or pending.
6. The fork point F is the last `D'_i` that is also in this node's own
   lineage. Report F and the lineage vote since `height(F)`.

The result is VERIFIED{F, vote}, PENDING, or REJECT{reason, event_seq}.
Adoption (`--resync-adopt`) only takes a VERIFIED snapshot whose vote is
>= 2/3, or runs under an explicit logged override. It archives the current
store as `*.pre-resync-<utc>` (never deleted), copies the snapshot, writes
`resync.log`, and exits 75 ("restart to adopt"). Snapshot supply follows the
`--wire-out` directory publisher pattern (`snap-<eventseq>-<digest12>.tar`
while CONVERGED). A CONTESTED node scans `--snapshot-in`, pre-filtering on
"reproduces one of my refused roots". The same payload can later travel as a
`v37-snapshot` levin command. The verifier is also the only legitimate caller
of `register_counter_lineage`.
