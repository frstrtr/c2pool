# XMR lane R-C rework-3: node-local refuse money, contested suspend, verify fixes

This is the design record for the third rework of the XMR lane's R-C
("refused lane block") handling. It answers the NO-SHIP verify of rework-2
(findings D1 to D7) and applies the interim defaults the operator set while
the consensus rulings are pending. Every change is in the consumer tree
(`src/c2pool/v37/xmr/`, `src/c2pool/v37/main_v37_xmr.cpp`,
`src/c2pool/v37/test/`). Nothing touches the settlement canon
(`w4_settlement.hpp`, the owed_digest fold) and no digest tag is bumped.

## 1. What the rework-2 verify found

| id | finding | fix here |
|---|---|---|
| D1 | Debit-on-refuse depended on attribution, and attribution was node-local: it depended on whether the peer's v0x02 wire descriptor had arrived before booking. A, B and C matched through cursor 241. At 244 C diverged (it put forker D's block in suspense while A and B debited it), and A/B split at 253. After that the honest nodes refused each other's blocks (A refused 44, B 55, C 25 honest blocks) and ended on three final digests. With no majority halt left, nothing stopped it. | §2: refuse-side money is node-local liability, never a ledger mutation. The wire attribution is removed. |
| D2 | Suspense entries left owed over-stated: exposure was A 575.8, B 125.4 and C 281.6 XMR. | §2: that exposure is now the explicit, counted LIABILITY. §5 gives the consensus fixes. |
| D3 | The vote's observation window was not persisted: B rebooted into CONVERGED while it was forked. | §4.1: `<sidecar>.obs` |
| D4 | A one-pass suspend edge: a job push and an accepted share landed after `set_lane_suspended(true)` but before the listener disconnect. | §4.2: the suspend gate |
| D5 | HELD-LAG never registered as cause=held. | §4.3: per-cause edges |
| D6 | `cba: refused` counted get_block fetch failures. | §4.4: `fetch_failed` is its own counter |
| D7 | A forker block that committed a historical honest root (the genesis-seed state) was credited. | §4.5: the RECON root-age bound |

Rework-2 behaviour that the verify confirmed good is kept unchanged. That
covers the F1 seeds through the event log, the F2 gap re-drive, the HOLD cap
(a held block is never dropped), `--mine` stopping on suspend, the stratum
disconnect with parked logins, and lag-suspend auto-resume.

## 2. Refuse-side money is node-local (interim default (b))

**Rule.** When a lane block is refused, its on-chain reward goes to a
**node-local LIABILITY** ledger. It never goes to eo, finalW or owed_digest.
`FinalizeConnect::refuse_money` records a `LiabilityRec`:

* When the block's payout decodes from the **on-chain bytes plus this node's
  own ring alone**, the record is per payee. This happens for a matched root
  whose cut was absent, mismatched, unfoldable or stale, or whose outputs were
  partly unmapped. Any unmapped outputs are recorded as `unattributed`.
* Otherwise (no matched root, so no `r`), the whole reward, sink included, is
  recorded as `unattributed`.
* A payout that decodes completely and pays no ledger key (the whole reward
  went to the residual sink) over-states nothing, so it records no liability.

The record is persisted append-only in `<sidecar>.liability` (v2 lines) and
reloaded at boot. The rework-2 `<sidecar>.suspense` file is still read, as
unattributed. The status line reports `liability: blocks= pico= (attributed=
to N payee(s), unattributed=)`, and `cba-ALARM LIABILITY` repeats every 50
ticks while the tally is non-empty.

**Invariant, enforced in code.** `refuse_money` snapshots `ledger_seq` and
`owed_digest` before it records anything and compares them afterwards. A
change increments `ledger_mutations_on_refuse` and raises
`cba-ALARM INVARIANT`. The counter must read 0, and it is printed on the
status line.

**What was removed.**
* `FinalizeConnect::book_debit_only`, the debit-only FOUND. Rework-3 never
  writes a `kind=d` sidecar record. A legacy `d` record left by a rework-2
  store is re-driven as it was booked, because the ledger already holds it
  from the replay, and it is counted in `legacy_debit_records`.
* main's M3(b) attribution through the v0x02 wire descriptor (`cba-attrib`,
  `attributed_by_wire`). The refuse path no longer depends on wire arrival in
  any way.

**Why this closes D1.** Two honest nodes that refuse the same block now
apply the same ledger operation, which is nothing. Their ledgers are
byte-identical whatever each one knew about the block and whenever it
learned it. The only difference between them is the granularity of the
node-local liability. In the verify rig, the D1 cascade (refusing each
other's honest blocks) started from the first ledger split, and that split
can no longer happen.

**Cost (D2).** The liability is exactly the over-statement of owed(k) that
rework-2 tried to net out. A later K_fair coinbase may pay those payees
again. It is now a counted, alarmed, per-payee number rather than a fork.

**Invariants (KATs).**
* I1': `finalW(k) = C(k) - P(k)` over **settled (credited)** blocks only.
* I2': the on-chain owed outputs of the canonical lane blocks equal
  `P(settled) + LIABILITY`, so every refused piconero is on the tally and
  none of it is in the ledger (FC21).
* I4': two honest refusers have an identical owed_digest at every ledger
  event (FC22).

KATs: FC20a-e, FC21, FC22/FC22b.

## 3. CONTESTED suspends lane production (interim default)

`FinalizeConnectOptions::contested_suspends` defaults to true. The flag is
`--contested-suspend on|off`. When the lineage vote enters CONTESTED (at
least 1/3 of the last 24 frontier lane blocks refused, with at least 6
observations), the contested hook fires **synchronously inside that tick**.
main then withdraws the stratum job, stops the in-process miner and
refreshes no template. `LaneSuspendState` carries the `contested` cause. The
hook fires (false) when the vote leaves CONTESTED, and the lane auto-resumes
once every cause (lag, isolated, held, contested) is clear. Booking and
refusing-not-crediting continue, so the vote stays live.
KATs: FC28 / FC28n, LS10.

**Liveness note: operator attention required.** Outsider `03 21 00` tags or
a forker with at least 1/3 of the lane hashrate can drive every honest node
CONTESTED. While all honest builders are suspended, the observation window
refills only with the attacker's blocks, so it stays CONTESTED. The exits
are:
* the forker stops;
* `vote_stale_s` (48 h) ages the window out;
* an operator sets `--contested-suspend off`.

This is the trade the interim ruling makes: no building on a possibly split
ledger, at the price of an externally triggerable production pause. It is
never a halt of the node, which keeps following the chain, settling and
booking. The rework-2 posture (keep building while CONTESTED) is the `off`
value.

## 4. The verify fixes

### 4.1 D3: the vote window survives a restart

Each observation is appended to `<sidecar>.obs` as
`1 h bid root|- booked t_unix` before it counts. The file is rewritten with
tmp, fsync and rename once it holds more than 2x the in-memory cap.
`reseed_after_bring_up` reloads it, drops entries that `vote_stale_s` has
made stale, and re-evaluates the vote. The state, and the suspension it
causes, is restored rather than warmed up from zero. The observation time is
now wall-clock seconds, because a `steady_clock` point does not survive a
restart. `obs_restored` is on the status line.
KATs: FC27 (restored CONTESTED), FC27n (control: rework-2 reboots into
CONVERGED).

### 4.2 D4: the suspend gate

`StratumListener::set_lane_suspended` flips the flag under `m_gate_mtx`. Every
lane-job push re-checks the flag under the same lock just before it happens.
That covers `getjob`, the template push (`push_job`) and the first job
handed out by a login (which is re-parked on the race). Every share or
network-block hand-off (`SinkTap`) does the same. So once
`set_lane_suspended(true)` returns, no job can be pushed and no share can be
accepted. A hand-off already in flight either completes before the flip
(logged before the `gate closed` line) or sees the flag. In rework-2 the
template push checked only on entry, so a seed-prefetch hook running across
the flip still pushed its job. New counter: `suspended_push_refused`.
KATs: LS8 (the template-push window), LS9 (set does not return while a
hand-off is in flight; nothing is handed off after it returns).

### 4.3 D5: every suspend cause is counted on its own edge

`xmr_lane_suspend_state.hpp` (`LaneSuspendState`) replaces main's
single-cause attribution. Each cause (lag, isolated, held, contested) is
counted on its own rising edge, whether or not the lane was already
suspended. A cause that rises during a suspension is logged as
`cause ADDED`. In rework-2, HELD-LAG normally fired `divergence_cap_ticks`
after the lag bound had already suspended the lane, so it was never counted.
KAT: LS10.

### 4.4 D6: fetch failures are not refusals

main's coinbase-authority callback counts get_block transport and JSON
failures in `cba_fetch_failed`. They are transient retries in
FinalizeConnect, and they are no longer in `cba_refused`. The `cba:` status
line prints `fetch_failed=` and `stale_root=`.

### 4.5 D7: the RECON root-age bound

`xmr_recon_ring.hpp` (`ReconRing`) stores each ring state together with the
coin height at which it became current (`since`). After R-A the digest is
D(c), so it changes only when the block mined at h is finalized (since = h)
or at a seed. The finalize driver keeps `digest_since()` and sets it just
before the ledger mutation, so the ledger-event observer samples the matching
pair. The boot replay derives the same value from each Finalize event's
recorded `bin_height - D_conf` (`XmrNode::boot_digest_since`), so a
restarted node's ring is identical (FC29a).

For a block at height h with builder cut `bcut = h - 1 - D_conf`, a matched
candidate's age is `max(0, bcut - superseded)`, where `superseded` is the
next state's `since` (the live state never ages). A match older than
**`kReconMaxRootAgeDconf * D_conf = 4 * D_conf`** heights is refused as a
`stale-root` and never credited. Its payout goes to liability per payee,
because the root is known. `--recon-max-root-age N` overrides the bound, and
0 means unbounded (the rework-2 behaviour).

Derivation: an honest builder whose cursor lags the buried frontier by more
than `2 * D_conf` is lane-suspended. The state it commits was therefore
superseded less than about `2 * D_conf` before the block's cut, and 4x gives
a 2x margin. An idle lane is never stale, because its old state is still
current. The bound is deterministic: it depends only on the chain height and
the replayed ledger, with no wall clock and no wire input.
KAT: FC29b (the genesis-seed state at h=40 has age 26 > 12 and is refused;
an honest builder at the lag bound has age 6, a recent stale root 3, the
young seed state 8, and an idle current root 0, all accepted).

## 5. Long-term fixes for the liability (consensus, operator's hand)

Node-local liability is the only option that keeps honest refusers identical
without a consensus change. Both fixes below make the refusal side's money
consistent across nodes, so it can be put back into the ledger. Both change
consensus.

**(a) The lane_commitment preimage in-band in the coinbase.** Append the 32 B
`lane_commitment` to the 0x02 tail:
`0x02 [nonce|pad|"V37C"|P|spine|"V37D"|lane_commitment]`. It has constant
weight and is verifiable as
`mm_commitment_root(chain_id, lane_commitment) == 0x03 root`
(`src/impl/xmr/settle/xmr_coinbase.cpp`). With it, every node derives `r`
for every lane block from the chain alone. Payout attribution then stops
depending on what a node knows or when it learned it, and
`unattributed` collapses to parse failures.

A refuse-side debit becomes consensus-safe only if the refusal decision
itself is also deterministic. That holds for root-unknown-while-synced,
stale-root and cut-mismatch. It does not hold for the cut-pending retry-bound
release, which needs its own fix. Seams:
* `xmr_credit_cut.hpp` (tail codec);
* `xmr_coinbase_authority.hpp` (use the in-band preimage as the candidate
  when present);
* the settlement provider (emit);
* `FinalizeConnectOptions::RefuseMoney`, which gains a debit mode gated on
  the in-band preimage;
* the coinbase-shape golden.

**(c) A consensus carrier for refuse events via the GAP-2 relay.** Carry each
refusal (bid, class, the payout map decoded under the carried
lane_commitment) as a sequenced record on the S-1 carrier relay. Every node
folds it at the same relay-ordered point, so the debit lands identically
regardless of local wire timing. This needs the relay's ordering and
finality semantics (GAP-2) and a ledger event kind for relay-ordered debits.
That is canon, and the operator's hand.

Until one of these is ruled and landed, `RefuseMoney::NodeLocalLiability` is
the only value.

## 6. Residuals (stated, not hidden)

* **Credit divergence from timing.** A lane block whose cut stays
  `cut-pending` past `retry_bound` (600 ticks) is released and refused on a
  slow node while a fast node books it. This predates rework-3 (R4), it is
  loud (`booking_stall_timeout`), and it does not happen in a healthy lane.
  Rework-3 guarantees that refusal is ledger-neutral. It does not make every
  refusal decision timing-free.
* **The liability is real money.** See D2 and §5.
* **The contested-suspend liveness hazard.** See §3.
* **ISOLATED.** It still needs the W6 verified-resync verifier; no production
  caller of `register_counter_lineage` exists yet. See rework-2 §3 and §7.

## 7. Live verification (the rework-2 verify rig, re-run on this build)

The rig and sequence are the rework-2 verify ones (`~/rc2-verify-rig`,
copied to `~/rc3-rig`): four regtest monerods re-diffed to 12000, honest
nodes A, B and C (C runs `--mine 3` in-process), and 17 restarts:
* 10 plain SIGINT restarts;
* 3 restart-after-own-FOUND;
* a B downtime gap and a C `--mine` downtime (lag suspend);
* the evolving-root forker D (`--credit-mutate 1`, fresh on the genesis
  owed-demo seed, honest xmrig miners off), with 7 consecutive D blocks at
  h=241..247;
* the HOLD phase (B behind a get_block-failing proxy).

Results (`ANALYSIS.txt`):
* **D1: the honest nodes stayed byte-identical through the forker.** The
  owed_digest matched on all 155 digest-changing cursors seen by A, B and C
  (A-B, A-C and B-C: 155 shared, 0 NE). The final digest was the same on
  all three (cursor 280, `72cfef39…`). All three had the same 154
  FINALIZED set.
* Every D block was refused by every honest node: 7 of 7, **0 honest blocks
  refused** (rework-2: A 44, B 55, C 25). No D block was credited.
* **D7:** 5 of the 7 D blocks were refused as `stale_root`. The first one
  (h=241) committed the genesis-seed state, superseded at h=121, so its age
  was 116, over the bound of 12. Rework-2 credited it. The other 2 were
  root-unknown.
* **Liability was identical on all three honest nodes for every D block.**
  h=241: 1,234,567,890 pico attributed to 4 payees. h=246 and h=247: the
  whole reward, unattributed. The remaining 4 stale D blocks paid only the
  sink, so they carry no liability. `ledger_mutations_on_refuse=0`, no
  `cba-debit`, no `cba-attrib`.
* The vote reached at most 7/24 refused, so it stayed CONVERGED and no
  contested suspension was triggered (FC28 covers that path).
* **D3:** every one of the 17 reboots logged `lineage-vote window RESTORED`
  and booked and finalized again.
* **D4:** the B and C suspend windows between `gate closed` and `gate open`
  saw 0 accepted shares, 0 job pushes and 0 logins served.
* **D5:** B was suspended with `cause=lag`. HELD-LAG then fired and was
  logged as `cause ADDED cause=held` (active: lag+held), was counted, and
  resumed.
* **D6:** B, behind the proxy, showed `fetch_failed=603` with
  `cba refused=0`. It went HELD and then RESOLVED; the block was never dropped.
* **Kept from rework-2:** gap re-drive, restart-after-FOUND, lag-suspend
  auto-resume, the `--mine` stop on suspend, late_unbooked=0,
  booking_stall_timeout=0 and R-7=0.

