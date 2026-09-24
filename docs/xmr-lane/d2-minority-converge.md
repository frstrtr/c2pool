# XMR lane D2: minority converges to majority (operator ruling D2 = A, 2026-09-24)

Status: DESIGN of record for the D2 track, branch `v37/xmr-minority-converge`
(off `v37/xmr-template-dup-tx` 2c9b995a = master 19e8b7e2 + the D1 template
dup-tx fix). Consumer tree only (`src/c2pool/v37/xmr/`, `main_v37_xmr.cpp`,
`src/c2pool/v37/test/`). Nothing here touches `w4_settlement.hpp`, the
owed_digest fold, the coinbase shape or any golden: consensus bytes on the
honest path are unchanged by construction (§7). D3 (relay-repair stall ->
lane-lag suspension never resumes) is out of scope (§10).

## 1. What happens today, traced on the evidence runs

Evidence: `~/pub-verify-rig/runs-fix2-p2p` (D1 fix, late re-announce) and
`~/pub-verify-rig/runs-base-p2p` (master, monerod sync-from-peer). Three
p2p-first nodes A, B, C, settlement ON, `D_conf = 3`, one paced miner each.
S3 of `run_p2p_v2.sh` stops every monerod (so every node has 0 levin peers),
lets only A's miner run, then restarts the monerods.

### 1.1 The miner's path (A books its own isolated block)

1. A's miner hits: `register_found` (xmr_o2_finalize_connect.hpp:964) does
   NOT book on submit-OK; with the rich callback armed it logs
   `own win ... booking DEFERRED to the chain view` (:1002), enters the race
   book (`m_race.observe_own`) and fires `on_own_win_deferred`
   (main_v37_xmr.cpp:1755: recompute capture + FB_BLOCK_WON fast path).
2. The publish arm has no peer: `P2pBlockPublisher` parks it
   (xmr_p2p_block_publisher.hpp:228 `PARKED for bounded re-announce`) and
   later `LATE RELAY ... reached 3 peer(s) on re-announce 6, 91 s after the
   find` (:304). On master the block reaches the monerods when they sync
   from A's native node instead (`reached NO peer and no accepting daemon`).
3. A's own chain view carries the block, so `book_chain_block` (:805) runs
   the rich callback (main:1597). `decode_lane_coinbase`
   (xmr_coinbase_authority.hpp:84) matches the 0x03 root against A's ring;
   the commitment is A's own live digest, so it matches candidate #0
   (`cba-book: h=309 bid=b7de514a lane_commitment=a8d3c4dc (candidate #0)`,
   nodeA.log:2103). The credit cut folds on A's own lane (main:1554
   `fold_at_cut`). `CHAIN FOUND booked` (:958), FOUND written ahead, and at
   `hw = 312` the F1 driver finalizes it (`FINALIZED b7de514a h=309 SETTLED
   at bin_height=312 ledger_seq=21`, nodeA.log:2503).
4. From that FINALIZE on, A's `owed_digest` (w4_settlement.hpp:772) includes
   b7de514a's credit and payout in `finalW`; A's next template commits it
   (A's h=313 block commits `216874a9`).

### 1.2 The other nodes' path (B and C)

What the task statement expected (root-unknown -> `lane-root-refused` on the
isolated block) is NOT what the logs show for that block. B and C never
attempt b7de514a at all:

* B and C each found their OWN h=309 block on the stale template while the
  monerods were down (`cc4612` and `238fa5`; their native index adopted it,
  `race h=309 defer-unburied [own=1 other=0] hw=308`, nodeB.log:1911) and
  booked it (`CHAIN FOUND booked cc4612 h=309`, :1915).
* When the monerods came back carrying A's b7de514a at 309 and A's 51c2a61c
  at 310, the native chain index switched branch. `xmr_chain_index.hpp:1684`
  `drop_queued_extends_after_(ev_mark)` discards the per-block Extends of the
  re-applied blocks and `xmr_chain_view.hpp:196 emit_reorg` emits ONE `Reorg`
  event that carries only the new tip (310). `XmrNode::on_mainchain_event`
  (xmr_node.hpp:517) delivers only `ev.block` to the booking observer (:531);
  the F2 gap re-drive (`redrive_range`, :483) is armed only for daemon-first
  (main:1269) and would not fire anyway because `m_scan_h` already stood at
  309 (B's own block). Result on B: `ORPHANED cc4612 h=309` (nodeB.log:1965),
  `CHAIN FOUND booked 51c2a61c h=310`, and NOT ONE line mentioning b7de514a
  until A's h=313 block arrives.
* The base run is the same shape at h=310: B and C first BOOKED A's
  `04227273@310` (it arrived over monerod sync), then found their own
  `82dd0420@310`/`35d49065@310` on a stale template, their index adopted
  their own block (`ORPHANED 042272730bc3 h=310`, nodeB.log:4363) and when
  A's 311 (built on 04227273) re-established it the `Reorg` event carried
  only 311: 04227273 was never re-booked (`book_chain_block` has the
  `canonical AGAIN after an orphan -> re-booking` path at :814, but nothing
  calls it for a reorg-in block below the tip).
* The first `lane_root_refused` is therefore on A's NEXT block (fix2: h=313
  `5e0949e1` root `2f4821c9`, nodeB.log:2345; base: h=314 `aec355e2` root
  `97054c33`, nodeB.log:4809): main:1662 declares it decidable
  (`cursor >= builder cut`, ring seeded), main:1671 reclassifies
  `lane-root-unknown` -> `lane-root-refused:<root>:`, FC:875 routes it to
  `note_refused_frontier` (:1338): gate released, `refuse_money` (:1128) ->
  `add_liability` (:1148) -> `cba-ALARM LIABILITY`, one lineage-vote
  observation (`observe_frontier`, :1373). Symmetrically A refuses C's h=314
  `82588ab1` (nodeA.log:2730). FINALIZED sets: fix2 A 11 vs B/C 10, base A 12
  vs B/C 11; digest sequences fork at cursor 308/309 (fix2) and 309/310
  (base) and never meet again.

### 1.3 Two findings that shape the design

**D2-0 (root cause of both evidence forks): a same-height reorg never
delivers the replaced-in block to the booking observer.** The majority's
ledgers lack b7de514a / 04227273 not because their cut was unreproducible
(the commitment `a8d3c4dc` = D(305) was in every ring; B's own 309 committed
the same root and the same payout) but because the block was never
attempted. This is a consumer-tree booking defect, not a consensus question.
It must be fixed in this track (§7.1), separately committed, or the partition
rig will "converge" the minority away from an honest block the majority
should have credited, and the "majority unaffected" KAT would assert the
wrong ledger.

**D2 proper is still required.** With D2-0 fixed, the general class remains:
a block whose credit cut the majority genuinely cannot reproduce (the
minority's relay was cut, its miners minted receipts during isolation, the
GAP-2 repair is Exhausted or stalls past `retry_bound` ->
`relay_repair_stall_timeout` REFUSED on the majority, FC:907-917, while the
miner books it), the finality boundary (finality-boundary.md §3), the c4
partition class (§3.1). In every case the shape is the same: the miner has
FINALIZED a block the majority has REFUSED (or never had), the minority's
commitments are `lane-root-refused` on the majority and vice versa, and
nothing today ever reconciles them (the lineage vote can only reach
ISOLATED through `register_counter_lineage`, which has no production caller,
FC:1101).

### 1.4 The observation the whole design rests on

Since R-A (`V37Q`, #1704) `owed_digest` hashes `m_finalW + m_first_eligible`
and `rearm_first_eligible` (w4_settlement.hpp:860) reads finalW only. The
digest is therefore a pure function of the ORDERED SEQUENCE OF FINALIZE steps
`(bid, credit, payout, bin_height)`; FOUND and ORPHAN never move it. Two
ledgers that finalize the same blocks with the same maps at the same
`bin_height = h + D_conf` are byte-identical whatever they booked or when.
So "the majority's ledger" is computable by the minority from its OWN chain
view: refold the settled prefix over the canonical lane blocks, crediting
what the majority credits and refusing what it refuses. The only unknown is
WHICH blocks the majority refused, and the ruling fixes that: the
minority's own blocks that did not reach the majority normally.

## 2. Minority detection: the exact rule

### 2.1 Observations

One observation per canonical lane block the node decides, in chain order,
recorded from `book_chain_block` / `note_refused_frontier`:

| field | source |
|---|---|
| `h`, `bid` | the chain |
| `root` | the on-chain 0x03 root (`CoinbaseBooking::onchain_root`, xmr_coinbase_authority.hpp:116) |
| `own` | `m_race.holds_own(h, bid)` before booking (set at submit-OK, FC:999) |
| `builder` | the builder key, §2.2 |
| `verdict` | `matched` / `unmatched` / `undecided` |

`matched`: the root matched a digest in this node's full history ring
(booked, OR refused for a non-root reason: stale-root D7, unmapped output,
donation rule, credit-cut absent/mismatch, cut stall). A stale root is still
OUR lineage.
`unmatched`: decidable (main:1662 `cur >= bcut && ring seeded`) and the root
matches no ring digest = today's `lane-root-refused`.
`undecided`: `lane-root-unknown` while not decidable, fetch failure,
cut-pending, HELD. Never counted; never resets anything.

### 2.2 Distinct builders from on-chain data

The K_fair coinbase carries no builder identity by design. The one
per-builder datum under the PoW is the first 4 bytes of the 0x02 extra-nonce
payload (`extra_nonce_bytes`, xmr_block_assembly.hpp:186; read back with
`credit::extra_nonce_field`, xmr_credit_cut.hpp:55). Under GAP-2 every node
draws a node-private base in `[2^24, 2^31)` (main:2571), stratum sessions
count up from it and the in-process miner uses `base - 1`, so one node's
blocks fall in one bucket of `extra_nonce >> 20` (2048 buckets; a node would
need more than a million stratum sessions to spill into the next one).

    builder_key(block) = (LE u32 of 0x02 payload bytes 0..3) >> 20

Two unmatched blocks are from distinct builders iff their keys differ. This
is a PROXY, and the design says so: a base is self-chosen, so a deliberate
sybil (one forker running two processes) defeats it; hashrate is the defence
there (§2.4). What the proxy does defend, and the 09-22 ruling asked for, is
the accidental case: one forked or stuck node cannot look like a majority.
Without a relay (`extra_nonce_base` unset) every node's bucket is 0, the
distinct-builder condition can never be met and detection is simply
unavailable: refuse + alarm only, stated on the status line
(`minority: builders=unavailable(no relay)`).
Corroboration (optional, off-chain, never sufficient alone): the relay peer
id on the FB_BLOCK_WON frame (`ab-wire-rx ... (relay peer N)`).

### 2.3 The run

Over the observations in chain order, skipping `own` and `undecided`:

* an `unmatched` foreign block extends the current run;
* a `matched` foreign block ends it (the majority is on our lineage);
* the run is DETECTED when `length >= M` AND the number of distinct
  `builder` keys in it `>= B_min`.

Defaults `M = 3`, `B_min = 2` (`--minority-run 3 --minority-builders 2`), the
09-22 threshold. `own` blocks are skipped rather than counted as matched
because a node's own block trivially matches its own ring: in fix2 A kept
finding (310, 313) between the majority's blocks and would otherwise never
complete a run. Observations older than `vote_stale_s` (48 h) are dropped,
same as the lineage vote. A single unmatched foreign block, or M from one
builder, is exactly today's behaviour: refuse-not-credit, liability, alarm,
one vote observation, the gate released, never a halt (FC19a/FC19c stay).

### 2.4 What the threshold does and does not defend

A lone forker with hashrate share p meets "M consecutive" with probability
p^M per window (rework-2's coin-flip objection) but never `B_min = 2` with
one base. A forker running two bases needs p^M of the lane's blocks in a row
AND then, for the honest nodes to do anything but refuse, its commitments
must be REPRODUCIBLE from the honest ledger by dropping only the honest
node's own isolation-marked blocks (§3.2). A lie is not reproducible, so the
honest node HALTS (§4) rather than joining it: the cost of the sybil attack
is a bounded honest production pause, not a ledger move. That residual is
stated in §10.

### 2.5 Interaction with the existing states

* CONTESTED (>= 1/3 of the last 24 refused, >= 6 observations): a minority
  node trips both; detection (M = 3) comes first. CONTESTED stays a loud
  alarm, default no suspend (rework-3 §3), unchanged.
* ISOLATED: still needs `register_counter_lineage`. A successful
  re-derivation is exactly a VERIFIED counter-lineage, but convergence
  supersedes it (why stay suspended-and-outvoted when the ledger can join);
  ISOLATED is left as it is and not fed from D2.
* HELD / HELD-LAG: HELD blocks are `undecided`, they neither count nor
  reset. A detection never releases a HELD block; it resolves on its own
  path under the new ring after convergence.
* LAG suspension: a lagging node is mostly undecidable, so it rarely
  completes a run; if it does, convergence proceeds (the cursor is not
  moved by it, §3.4), and lag is re-evaluated after re-seed as before.
* Same-height race: a losing own block is never canonical, never observed.
* D7 stale-root: a matched historical root resets the run (our lineage).

## 3. Convergence: re-derive, verify, adopt

### 3.1 States

    CONVERGED ──(run detected)──> CONVERGING ──(match)──> CONVERGED (re-seeded)
                                      │
                                      └──(no match after bounded attempts)──> DIVERGED (halt, §4)
    DIVERGED ──(later attempt matches)──> CONVERGED (re-seeded)
    DIVERGED ──(M matched foreign blocks from >= B_min builders)──> CONVERGED (cleared, no re-seed)

CONVERGING and DIVERGED are lane-suspend causes (`LaneSuspendState::kConverging
= 16`, `kDiverged = 32`, xmr_lane_suspend_state.hpp:59 `update` gains two
parameters): the moment the run is detected the node stops emitting a
template that commits the root it is about to abandon (the same synchronous
hook shape as `set_isolation_hook`, main:963). Booking, chain follow, relay
and liability continue throughout.

### 3.2 Which blocks move to the refuse path

The candidate refuse set is tried in this order; the FIRST set whose
re-derivation reproduces the run's commitments is adopted; the check (§3.3)
is the proof, so trying two sets is not guessing.

* `R1` = own blocks booked after the fork point `F` that are
  ISOLATION-MARKED: published while the publisher had no relay peer
  (`P2pBlockPublisher` parked -> `late_reached`, or `reached NO peer`), or
  submitted while `peers_handshaked == 0`. New seam:
  `P2pBlockPublisher::set_on_isolated_own(fn(bid, h, why))`, main marks
  through `FinalizeConnect::mark_isolated_own(bid, h, why)`; persisted
  append-only in `<sidecar>.isolated` (`1 bid h t why`) so a restart keeps
  the marks. This is the ruled set (clause 4: receipts minted while isolated
  get no lane credit unless they reached the majority normally).
* `R2` = every own block booked after `F` (covers isolation the publisher
  could not see, e.g. the base-run sync-from-peer shape).

Fork point `F` = the `since` height of the newest ring state that the LAST
matched foreign observation committed (`ReconRing::Entry::since`); with no
matched foreign observation in the window, `F = cursor - 4 * D_conf`. If
`cursor - F > 4 * D_conf` (deeper than the root-age bound, rework-3 §4.5),
re-derivation is not attempted: HALT, W6 territory.

The MAJORITY blocks this node refused after `F` (its `lane-root-refused`
liability records with `h > F`) are the other half of the difference: they
must be CREDITED in the re-derived ledger, at their chain-ordered position.

### 3.3 The re-derivation (pure, testable: `xmr_minority_converge.hpp`)

Inputs: the persisted event log; `F`; the refuse set `R`; the canonical lane
blocks at heights in `(F, cursor + D_conf]` from this node's chain view
(`by_height`); a booking function `decode(h, bid, candidate_ring) ->
{credit, payout} | cut-pending | refused`; `D_conf`; the current cursor.

1. PREFIX: replay into a scratch `OwedLedger` the FOUND/FINALIZE/ORPHAN
   events of every bid whose FINALIZE has `bin_height - D_conf <= F`, in
   their original order (a FOUND with no FINALIZE is an orphan or still
   pending: it does not move the digest, dropped from the prefix). Collect
   the scratch ring `(digest, since)` exactly as `XmrNode::bring_up` does
   (xmr_node.hpp:287).
2. REFOLD, the synced node's sequence `book(h + D_conf) -> FINALIZE(h)`
   (finality-boundary.md §2): for `h = F + 1 .. cursor`, first decode and
   FOUND every canonical lane block at height `h + D_conf` not in `R` under
   the SCRATCH ring (candidates = scratch live digest + scratch history),
   then FINALIZE every pending block mined at `h` with `bin_height =
   h + D_conf`, pushing the new state to the scratch ring with `since = h`.
   Blocks in `R` are skipped and their on-chain payout (the old FOUND
   event's map) goes to the liability list. A block that decodes
   cut-pending makes the attempt UNDECIDABLE: stop, stay CONVERGING, retry
   next tick; `converge_retry_bound` (600 ticks, the R4 bound) attempts ->
   DIVERGED. A block that decodes as a hard refusal (unmapped output, cut
   mismatch) is refused in the scratch too (it would be on the majority).
3. CHECK: every `unmatched` root of the run must equal
   `mm_commitment_root(chain_id, d)` for some `d` in the scratch ring with
   root age within `cba_max_root_age` (same rule as live, D7). All M match
   -> success with this `R`; else try the next `R`; none -> DIVERGED.

Post-R-A this is deterministic on (chain, event log, R): no wall clock, no
wire input, and it is what every majority node computed.

### 3.4 Adoption (the lineage switch) and what is persisted

Order matters for restart safety; every step is idempotent by bid.

1. Write `<sidecar>.converge` (tmp+fsync+rename) = `{phase: proposed, F, R,
   released (the majority bids re-credited), evidence roots+heights, new
   event count, utc}`.
2. Archive, never delete (W6 §4b discipline): `settle.img`, `pfound.tsv`,
   `pfound.tsv.liability` copied with a `.pre-converge-<utc>` suffix.
3. Rewrite the event log in ONE `FileSettleStore` batch (remove every
   `v37s:levt:` key, put the scratch log re-sequenced from 1). `commit_sync`
   is an atomic image replace (xmr_settle_store.hpp:272 `flush`), so the
   store is either old or new, never torn. Cursor and hw keys are untouched:
   the cursor does not move (the refold ends exactly at it).
4. Marker phase `applied`.
5. In-process re-seed, `XmrNode::relineage()`: a fresh `OwedLedger` replayed
   by `RecoveryDriver` from the rewritten store (rebuilds
   `m_boot_digests/m_boot_since`), move-assigned into `m_ledger` (the
   settlement provider and the fixture hold the ledger by reference,
   xmr_o2_settlement_provider.hpp:443, so the same object must stay); the
   `XmrFinalizeDriver` is rebuilt with the recovered seq/cursor and
   `set_digest_since(boot_last_since)`; the node re-installs its composite
   booking gate and carry probe and calls `m_on_driver_rebuilt` so
   `FinalizeConnect` re-installs its ledger-event and finalize observers.
6. `FinalizeConnect`: `m_pending` = the scratch driver's pending FOUNDs
   (kind `c`, maps from the refold), sidecar rewritten; `R` bids -> liability
   per payee (payout from their old FOUND maps), `m_chain_seen[R] = true`;
   released majority bids: `LiabilityRec` removed and `<sidecar>.liability`
   rewritten (`liability RELEASED: credited after convergence`),
   `m_chain_seen` entry erased, `cba_root_unknown_seen` cleared for them;
   `m_retry/m_deferred/m_held` kept (re-attempted under the new ring).
7. main: `cba_ring.seed(node.boot_digest_history(), node.boot_digest_since())`
   (triggered from `hooks.cba_tick` when `fc.relineage_seq()` changed); the
   template provider picks the new digest up on its next refresh (its cache
   key includes the digest).
8. Marker phase `done`; suspend cause `kConverging` cleared; stratum resumes
   through `apply_suspension` exactly as today (`RESUMED -- all suspend
   causes cleared`).

Log lines (one each, plus the status line): `cba-ALARM MINORITY DETECTED:
run k=M builders=N roots=[..] F=.. -> re-deriving with R1={..}`,
`converge: R1 reproduces M/M commitments (roots ..) -> ADOPTING`,
`converge: store rewritten (N events -> N'), archived *.pre-converge-<utc>`,
`converge: own block <bid> h=.. moved to refuse/LIABILITY (payout {..});
its miners' receipts minted during isolation [P=a..b] receive NO lane
credit (they did not reach the majority through the relay)`,
`converge: majority block <bid> h=.. now CREDITED (liability released)`,
`converge: DONE ring=N cursor=c digest=..; lane production resumes`.

### 3.5 Boot with a marker present (`reseed_after_bring_up`)

* `proposed` and no `.pre-converge-<utc>` archive: nothing was mutated;
  drop the marker, log it, let live detection run again.
* `applied`: the store is already the converged log (the boot replay used
  it); finish steps 6-7 from the marker's `R`/`released` lists (idempotent:
  `add_liability` is once per bid) and mark `done`.
* `done`: informational only (`boot: converged at <utc>, F=..`).

## 4. The halt fallback (DIVERGED)

Entered when no candidate set reproduces the run, or the fork is deeper than
`4 * D_conf`, or `converge_retry_bound` attempts stayed undecidable.
`cba-ALARM DIVERGED (halt): M unmatched from N builders, re-derivation with
R1/R2 reproduced k/M -- this ledger can NOT be brought onto the majority
lineage by refusing its own blocks; lane production HALTED, stratum
WITHDRAWN, in-process miner stopped; booking/refusing continue; NOTHING
guessed, NOTHING mutated` on stdout and stderr, repeated every 50 ticks.
The ledger, store and ring are untouched. Exits: (i) a later attempt matches
(retried on every new unmatched foreign block and every 50 ticks while
undecidable), (ii) `M` matched foreign blocks from `>= B_min` builders
(the majority is demonstrably on our lineage; the run was not the
majority), (iii) the operator (W6 verified adoption + restart). Never
terminal for the node.

## 5. Restart liveness (R-C F1/F2 must not regress)

* The converged store is an ordinary event log: `RecoveryDriver::recover`
  replays it, the ring seeds from it, `pfound.tsv` re-drives the pending
  FOUNDs through `on_network_block_won` as today. No new event kind, no
  schema bump.
* Marker phases make a SIGINT/kill at any step safe (§3.5). The only
  multi-file step (archive + store rewrite + marker) is ordered so a crash
  between them leaves either the old store with `proposed` (ignored) or the
  new store with `applied` (finished at boot).
* `<sidecar>.isolated` and the vote `.obs` survive as append-only files.
* F2 gap re-drive: `m_scan_h` is unchanged by convergence.

## 6. The majority side

Honest majority nodes see the minority's blocks as `unmatched` from ONE
builder key: no run completes (KAT FC33), nothing suspends, the ledger never
moves (refusal is ledger-neutral, rework-3 §2, `ledger_mutations_on_refuse`
stays 0). Once the minority has converged its blocks match again. A restart
of a majority node during the minority's convergence is an ordinary restart.

## 7. Consensus bytes and the code plan

No change to `owed_digest`, `rearm_first_eligible`, the coinbase tail, the
credit cut, the receipt fold or any KAT golden. The re-derivation uses the
production `OwedLedger` and `RecoveryDriver` on the same maps, so a converged
node's digest is the majority's by construction.

### 7.1 D2-0, separate commit: reorg-in blocks reach the booking observer

`XmrNode::on_mainchain_event` (xmr_node.hpp:517): on `K::Reorg` with
`depth d` deliver heights `[H - d, H - 1]` from the chain view (`by_height`)
through `m_cba_extend_observer` and `m_chain_observer` in ascending order
BEFORE the tip (always, not only when the gap re-drive is armed), then the
tip as today. `book_chain_block` already re-books a block that is canonical
again (:814 `canonical AGAIN`) and dedups on ledger state, so nothing else
changes. The same-height replace (`d = 1`, replaced block at `H - 1 = h`)
is the evidence case. KAT FC30.

### 7.2 D2, the files

* NEW `src/c2pool/v37/xmr/xmr_minority_converge.hpp`: `Observation`,
  `builder_key()`, `RunDetector` (M, B_min, stale), `Refold` (§3.3, pure:
  takes the prefix events, the ordered chain lane blocks, a decode functor),
  `ConvergeMarker` (read/write/phase), `ConvergeStats`.
* `xmr_o2_finalize_connect.hpp`: observations fed from `book_chain_block` /
  `note_refused_frontier`; `mark_isolated_own`; the CONVERGING/DIVERGED
  state machine driven from `tick()` after `evaluate_vote()`; adoption
  steps 1-4, 6, 8; `set_converge_hook` (synchronous suspend, like isolation);
  `relineage_seq()`; new `Stats` fields (`minority_runs_detected`,
  `converged`, `diverged_halts`, `diverged_cleared`, `own_refused_on_converge`,
  `liability_released`, `converge_attempts`, `converge_undecidable`).
* `xmr_node.hpp`: `relineage()` (§3.4 step 5), `set_driver_rebuilt_hook`,
  D2-0 (§7.1).
* `xmr_finalize_driver.hpp`: none required (the scratch uses `OwedLedger`
  directly; the live driver is rebuilt through the constructor).
* `xmr_lane_suspend_state.hpp`: causes `kConverging`, `kDiverged`, names,
  counters `n_converging`, `n_diverged`; `update(lag, isolated, held,
  contested, converging, diverged)`.
* `xmr_coinbase_authority.hpp`: `CoinbaseBooking::extra_nonce`
  (`has_extra_nonce`) parsed from the 0x02 payload (no behaviour change).
* `xmr_p2p_block_publisher.hpp`: `set_on_isolated_own`.
* `main_v37_xmr.cpp`: `ChainBooking` gains an optional candidate-ring
  override consulted by `fetch_decode`/`book_from_chain_ex` (the scratch
  decode, §3.3 step 2), `out.extra_nonce`; converge hook -> `apply_suspension`
  causes; ring re-seed on `relineage_seq()` change; flags `--minority-run`,
  `--minority-builders`, `--minority-converge on|off|halt-only`
  (`halt-only` = detect + DIVERGED, never adopt: the operator's
  observe-only posture), `--converge-retry-bound`; status line
  `minority: state=.. run=k/M builders=n detected=.. converged=.. halted=..
  cleared=.. own_refused=.. released=.. attempts=.. undecidable=..`.
* `LS` KAT: `update` with the two new causes.
* docs: this file; `r-c-rework-3.md` §6 residual list gets a pointer;
  README row.

## 8. KATs

`FC` = `finalize_connect_selfcheck` (mock chain, `smoke::apply_row`),
`MC` = new `v37_xmr_minority_converge_selfcheck` (pure functions, no node).
"base" = 2c9b995a.

| id | proves | base | after |
|---|---|---|---|
| FC30 | D2-0: a same-height `Reorg` (depth 1) delivers the replaced-in block at `H-1` to the booking observer before the tip; a block ORPHANED then canonical again is re-booked; `late_unbooked = 0` | FAIL (never attempted) | PASS |
| MC1 | `builder_key`: two extra_nonce values from one GAP-2 base map to one key; two bases map to two; no relay (base 0) -> `builders=unavailable` | n/a (new) | PASS |
| MC2 | detector: one unmatched foreign block -> no detection (refuse-only); M from ONE builder -> no detection; M from 2 builders with own blocks interleaved -> detected; a matched foreign block inside the run resets it; undecided never counts | n/a | PASS |
| MC3 | refold is exact: a ledger built WITH own block X and a control ledger built WITHOUT X; refold(prefix, R={X}) reproduces the control's digest AND `since` at every state (FC29a shape) | n/a | PASS |
| MC4 | refold credits the previously refused majority blocks at their chain-ordered FINALIZE and reproduces the control that credited them; a cut-pending decode makes the attempt undecidable (no partial adoption) | n/a | PASS |
| FC31 | end to end on node A: own isolation-marked X booked and FINALIZED; then 3 majority blocks from 2 builder keys committing D(without X) -> DETECTED, converge hook fired (true), R1 reproduces 3/3, store rewritten + archived, X in liability per payee, released majority bids credited, ring holds the majority roots, the 4th majority block BOOKS, hook (false), cursor unchanged, `late_unbooked = 0`, `ledger_mutations_on_refuse = 0` | FAIL (stays forked; no detection) | PASS |
| FC31b | same, R1 empty (no isolation mark) -> R2 (all own since F) reproduces -> converge | FAIL | PASS |
| FC32 | mismatch -> HALT: 3 unmatched from 2 builders whose roots no candidate set reproduces -> DIVERGED, hook (true), booking continues, no store/ledger change, banner; then 3 matched foreign blocks from 2 builders -> cleared, hook (false) | FAIL (no halt; keeps building on a split ledger) | PASS |
| FC32b | fork deeper than `4*D_conf` -> DIVERGED without an attempt (W6) | FAIL | PASS |
| FC33 | majority unaffected: nodes B and C observe A's isolated X (refused) then A's next 2 blocks (unmatched, ONE builder) -> no detection, no suspend, digest sequence equals the control; `ledger_mutations_on_refuse = 0` | PASS (regression guard) | PASS |
| FC34 | restart mid-convergence: (a) marker `proposed`, old store -> boot drops the marker, live detection re-runs and converges; (b) marker `applied`, rewritten store -> boot finishes liability/release, `boot_digest_history()` equals the converged ring; (c) restart after `done` -> F1 replay identical, pending re-driven, no re-detection | FAIL (no marker) | PASS |
| FC35 | `--minority-converge halt-only`: detection -> DIVERGED, never adopts | FAIL | PASS |
| LS11 | `LaneSuspendState`: `kConverging` and `kDiverged` counted on their own rising edges, resume only when all six causes clear | FAIL (no cause) | PASS |
| goldens | every existing owed_digest / coinbase-shape / credit-cut golden and `xmr_recon_ring` FC29 unchanged | PASS | PASS (unchanged files) |

## 9. Partition rig plan (`~/mc-rig`, copied from `~/pub-verify-rig`, REGTEST only)

Host rules: vm905, one build at a time `-j4 nice -n 15`, `free -g` available
>= 12 GB before any start, `memguard.sh` SIGSTOPs the rig below 8 GB; every
long step `nohup ... > ~/mc-step.log 2>&1 &` and polled. Never the stagenet
monerod (38080-38082, `~/stagenet*`), never mainnet.

Ports (checked with `ss -ltnp` first): monerod p2p 48000/48010/48020 (rpc +1,
zmq +2, zmq-rpc +3), rpc proxies 48051-48053, wallet-rpc 48090, stratum
5960-5962 (5963 forker D1, 5964 D2), receipt relay 48100-48104, relay-cut
TCP forwarders 48110-48113, c2pool levin source IPs 127.0.0.21-25.

Topology: three regtest monerods, fixed difficulty 1, `--add-exclusive-node`
line m1-m2-m3 (as `monerod.sh`), 300 generated blocks. A connects ONLY to m1
(`--native-connect m1`), B to m2 (+m3), C to m3 (+m2). Relay: B and C
`--relay-peer` A THROUGH forwarder 48110 (-> A's 48100); A `--relay-peer` B
through forwarder 48111; C -> B direct. All three p2p-first, `--coinbase
v37`, native template, `--d-conf 3`, `--share-diff 1`, `--poll-ms 400`,
`--status-every 5`, `--relay-listen`, one `paced.py` miner each (LO/HI 45/90
s). Isolate A = `kill` m1 + close the two forwarders (A: `peers=0`, relay
peers 0); reconnect levin = restart m1; reconnect relay = reopen forwarders.
The forwarder is a 40-line python TCP splice that drops every connection
and refuses new ones while a `.cut` file exists.

| step | action | expected |
|---|---|---|
| S1 warm-up | all mining, >= 8 finds, quiesce | digests equal on all three, FINALIZED equal, `late_unbooked=0` |
| S2 isolated find, cut unreproducible (the D2 case) | pause B,C miners; isolate A; A finds 1 block (PARKED); restart m1 only (relay STILL cut) -> LATE RELAY -> block enters the chain; resume B,C; majority keeps finding >= M+3 blocks | B,C: `cut-pending: relay repair ... Exhausted` -> after `retry_bound` `relay_repair_stall_timeout` REFUSED + LIABILITY (gate released, no halt); A: FINALIZED it, then M unmatched from 2 builders -> `MINORITY DETECTED` -> `converge ... ADOPTING` -> `DONE`; A's digest sequence from the adoption cursor equals B/C's; A liability holds its block per payee; B/C digest sequences identical to their own pre-convergence sequence (majority unchanged); stratum on A `WITHDRAWN` then `RESUMED`; then reopen the relay: nothing further changes |
| S2b evidence shape (D2-0) | do NOT pause B,C; isolate A (levin + relay); A and the majority both find at the same height; reconnect everything | the loser re-books the winner (`reorg-in` delivered / `canonical AGAIN`), no `lane_root_refused`, no detection, all digests equal (the fix2/base forks do not recur) |
| S3 several isolated finds | as S2 but A finds 3 blocks before m1 returns | all 3 late-relayed and refused by B,C; A: one detection, R1 = 3 blocks, converges in one adoption |
| S4 restarts during convergence | S2 three times with a log-watch `kill -INT A` (a) right after `MINORITY DETECTED`, (b) right after `store rewritten`, and (c) a plain SIGINT of B while A converges | (a) boot drops `proposed`, re-detects, converges; (b) boot finishes from `applied`; (c) B rejoins unchanged; every boot logs `boot_digest_history` equal to the live ring, `late_unbooked=0` |
| S5 mismatch -> halt | pause A,B,C miners; forker pair D1,D2 (`--credit-mutate 1`, two processes = two bases) find 3 blocks; resume A,B,C | A,B,C: `DIVERGED (halt)` (the documented sybil residual), stratum withdrawn, ledgers untouched; after 3 honest blocks from 2 builders: `cleared`, RESUMED; digests equal throughout |
| S6 D3 evidence (report only) | during S2 note whether the B/C lag suspension (if it fires while the repair holds the gate) resumes after the REFUSED | recorded as evidence for D3; no change attempted here |

`analyze.py` grows: detection/convergence/halt/cleared counts per node,
digest sequence equality FROM the adoption cursor, FINALIZED diff (must be
exactly the refused own blocks), liability release lines, stratum edges,
`ledger_mutations_on_refuse`, boot lines after each restart. Quiesce
(miners paused, cursors at `hw - D_conf`, `waiting_now=0`) before comparing.
Tear-down: `stop.sh` shape (SIGCONT + SIGINT, then -9), monerods killed,
forwarders killed, `ss -ltnp` shows every rig port free.

## 10. Residuals and out of scope

* D3 (relay-repair stall -> lane-lag suspension never resumes; suspended
  node's digest diverges by cursor) is not touched. S6 records whether the
  convergence path incidentally recovers such a node; nothing is claimed.
* The builder key is a proxy (§2.2, §2.4): a sybil forker with enough
  hashrate can cost the honest set a bounded production pause (DIVERGED),
  never a ledger move. Making it authenticated is consensus (an in-band
  builder commitment) and the operator's hand.
* Convergence throws away the credit of receipts minted during isolation
  (ruled, clause 4) and records the own block's payout as liability on the
  minority; on the majority the same block is liability (refused) or, with
  D2-0, credit when its cut was reproducible. The over-statement stays the
  rework-3 §2 LIABILITY until a consensus carrier exists.
* A fork deeper than `4 * D_conf` is not re-derived: HALT + W6.
* `--minority-converge off` keeps today's behaviour exactly (refuse +
  alarm; no detection).

## 11. As built (implementation notes, deviations from §2-§9)

Code: `xmr_minority_converge.hpp` (pure: builder key, `evaluate_run`,
`refold`, marker/observation codecs), `xmr_o2_finalize_connect.hpp`
(observations, CONVERGING/DIVERGED state machine, adoption, boot marker
handling), `xmr_node.hpp` (`relineage()`, `chain_bid_at()`, D2-0),
`xmr_finalize_driver.hpp` (`rebase()`), `main_v37_xmr.cpp` (`book_scratch`,
flags, hooks, status line `minority:`). Where the build differs from the text:

* **Fork depth (§3.2).** The bound is applied to `bcut(first run block) - F`,
  not `cursor - F`: the cursor keeps walking while an attempt is undecidable
  (a relay repair of a majority cut in flight), which would turn a shallow fork
  into a "deep" one by waiting. Default bound `4 * D_conf`
  (`FinalizeConnectOptions::converge_max_depth`).
* **Candidate refuse sets (§3.2).** R1 (isolation-marked own blocks above F),
  R2 (every own block above F), then R0 (none forced) and every other subset of
  the own blocks above F, smallest first, bounded to 6 own blocks (64 sets).
  None is a guess: a set is adopted only when its refold books every block of
  the run, i.e. reproduces each of the majority's M on-chain commitments
  (sha256d). The subset search covers "isolated but credited by the majority"
  (the first isolated find's cut carries no isolated receipt, so the majority
  can reproduce it) when F lies below it (KAT FC31d).
* **Own blocks built on the minority lineage** need no forcing: their 0x03 root
  does not match the scratch ring, so the refold refuses them exactly as the
  majority did (`lane-root-refused`, whole reward unattributed, KAT FC31c).
* **Isolation marks (§3.2).** `P2pBlockPublisher::was_parked(bid)` (every block
  ever parked) is asked when the own win is registered; a yes is persisted in
  `<sidecar>.isolated`. No callback from the listener thread.
* **Refold decoding.** A block booked in the log being re-derived is only
  root-checked against the scratch ring (`ScratchQuery::root_only`) and keeps
  its booked maps (no second credit fold, no relay repair); a block not booked
  there is decoded in full (`book_scratch`, the same authority as
  `book_from_chain_ex`, D7 age on the scratch ring). Under the scratch lineage
  an unmatched root is a refusal (the scratch is synced by construction).
* **Adoption files (§3.4).** The new sidecar and liability bodies are written to
  `<sidecar>.converge.pfound` / `.converge.liab` with the `proposed` marker,
  before the store is touched; the boot tells an old from a rewritten store by
  (replayed owed_digest, event count) == the marker's. `applied` (or `proposed`
  with the rewritten store) is finished at boot before the sidecar is read; a
  `proposed` marker with the old store is renamed `*.dropped-<utc>`. The
  observation file `<sidecar>.mobs` is truncated at adoption and a floor height
  (in the marker) keeps consumed observations out of later runs.
* **Hooks.** `set_converge_hook` fires (true) on entry to CONVERGING (or to
  DIVERGED from CONVERGED), (false) on the return to CONVERGED;
  `set_relineage_hook` re-seeds main's RECON ring; main invalidates the
  settlement template cache on `relineage_seq()` change (the provider re-keys on
  the tip only, so a cached template would keep committing the abandoned root).
* **Test knobs.** `--converge-hold-ticks n` (rig: a window to restart the node
  while CONVERGING) and `FinalizeConnectOptions::converge_crash_after` (KAT-only
  failpoints after `proposed` / `applied`).
* **Rig (§9).** The relay cut is the existing rig knob
  `--relay-test-partition-seconds` + SIGUSR1 on A (drops every relay link,
  refuses inbound, no redial for the window), not TCP forwarders; the levin
  isolation is stopping m1 (A dials only m1). `ledger_dump.py` replays every
  node's `settle.img` independently (the R-A digest rules) and compares
  FINALIZED sets, full digest sequences and the liability files.
