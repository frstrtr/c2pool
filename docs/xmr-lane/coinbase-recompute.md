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
  **Under the drain rule** ([`settlement-drain.md`](settlement-drain.md)) the
  takes are a function of the ledger, the total and dh: the K_fair pass at
  `Delta = min(F, R × min(dh, 64) / 256)`. The recompute derives F, dh and
  Delta from its own ledger (no claim field) and requires the V37N base to
  state exactly those takes: more is an **over-take** (old debt beyond
  Delta), less an under-take, both a Mismatch, and there is no rebuild at a
  committed base. The builder therefore cuts its snapshot at the template's
  final reward (`xmr_o2_settlement_provider.hpp`, a bounded fixpoint). A
  canonical drain block is booked at `P = R − debt_paid`
  (`Result::split_at`): the receiver refolds the window's E_b there before the
  net booking (`v37_xmr_coinbase_recompute_kat` R16-R19: the over-take, the
  under-take, takes at a larger hint, the window credited at R, more than K_o
  owed slots, a skipped sub-c take, another dh and a version-0 builder are
  each a Mismatch on every receiver).
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

The same map decodes a block being booked: its outputs map only through the
booked refs and the refs of the view at its own cut (`decode_blob`'s booking
map). Whether every output maps decides debit-only booking versus a
ledger-neutral refusal, so it must not depend on a ref learned out of band
either (rehearsal M6: a block paying a ref one node knows).

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
* **Lane knobs are network constants on mainnet** (review O-4/O-5).
  `lane_knob_refusal()` refuses, on mainnet, a non-default `--d-conf` (the
  booking point), `--settle-h-min` and `--settle-output-cap` (the recompute
  rebuilds with them), `--recon-max-root-age` and `--no-book-deferral`. A node
  that differs in any of them books honest blocks debit-only: a ledger fork.
  Test networks keep them; a rig must set them identically. LANE-RULES
  (operator ruling R3, [lane-rules.md](lane-rules.md)): every one of them, and
  every compiled-in rule constant, is now in the lane-rules list the HELLO
  compares by name (`LANE_RULES_MISMATCH`) as the pool's epoch-1 Deployment
  (RULES RATCHET R1: nothing on chain names a rule; a same-pool block built
  under other rules is a recompute Mismatch, and the deviant node is the one
  refused at HELLO), so a node with other values is refused at HELLO: never debit-only. `--d-conf` below 60 is refused off regtest.

## 6. Shares: the same rule (P2Pool's share rule)

A share is a block candidate, so its coinbase must be the canonical one too.
Without that a miner can mine on a template that pays the whole block to
itself, keep a found block, and still earn pool credit for every share: the
block is then booked debit-only against a throwaway key, and the shares keep
their credit. A relayed receipt hides the outputs in its Keccak midstate, so
nothing checked them.

* **The total, "V37R".** Everything the recompute needs is in the receipt's
  open `tx_extra` (V37C, V37N, V37D, V37F, V37P and the 0x03 root that
  commits the ledger state), except the coinbase total, which depends on the
  template's own transactions. The template now writes
  `"V37R" || u64 total` first in the 0x02 tail, after the final reward
  split. The field has a constant size, so its value never changes the
  coinbase size, weight or reward. Every older field is located from the
  end, so none moves. A block must state `V37R == Σ outputs`
  (`LaneInputs::commit_total`, set by the daemon).
* **The verdict.** `verify_share_coinbase` takes the opened `tx_extra`, the
  prefix hash resumed from the receipt's midstate
  (`verify::resume_prefix_hash`), and the height and parent of the hashing
  blob. It rebuilds the canonical coinbase with the receipt's own 0x02
  payload (the worker head differs per job) and compares prefix hashes.
  Mismatch: no credit. Undecidable: this node does not hold the ledger state
  the 0x03 root commits.
* **Pinned by** `v37_xmr_share_verdict_kat`: an honest share is canonical at
  any extra-nonce; a thief template is refused whether it keeps the donation
  output or not; a rewritten total is refused; a template without V37R is
  refused.
* **The anchor (ruling A, 2026-09-29).** A share's coinbase cannot be
  rebuilt from the builder's own credit cut: each node's receipt lane has its
  own order (Ruling A of the relay), so a view at another node's cut needs a
  relay repair per template. So a lane block's pay-now and E_b now come from
  the **anchor**: the on-chain cut of the latest lane block FINALIZED into the
  ledger the block builds on (`OwedLedgerRules::anchor_cut`). Every input of
  the coinbase is then finalized state, the same on every node. The block
  still commits its own V37C; that cut becomes the next anchor when the block
  finalizes, so the window keeps moving. No anchor yet (a fresh pool): the
  view credits nobody, and the empty-cut finder rule pays the finder: every
  lane block found before the pool's first lane block is final carries
  V37F (the winning job's bound login) + V37N and pays that finder
  `R - Delta`, the donation output being its 0-amount marker (its 0x02
  payload is then the widest, up to 232 B with rbind and V37R; `ecut-variant:`
  lines name a refused variant, the status line counts them). Cost:
  a block pays the window as of D_conf blocks ago (about 2 hours), like a
  PPLNS window with a lag. Each block still pays out everything it credits.
  * The ledger carries the anchor in `owed_digest` ("V37A"), set at FINALIZE
    from the cut its FOUND carried. A FOUND event persists it (settle store
    schema 2; a cutless event keeps the schema-1 bytes), and so do the
    sidecar ("cut=P:spine") and the refold. The refold re-decodes rather
    than reusing old maps, since the anchor may differ on the new lineage.
  * Booking folds E_b at the anchor of the booking-point ledger. The
    recompute, the pay-now payee resolution and the booked refs use the same
    view. A canonical block's own cut must still be reproducible (as before);
    only then does it become an anchor. A debit-only block never does.
  * The builder reads the view at its ledger's anchor (replay or repair on
    the main thread). If the view is not readable yet, it builds no template
    rather than a coinbase without its pay-now.
* **The DROPS due (handoff A5, ruling 2026-09-30).** With the DROPS gate on,
  a lane block's composed DROPS delta is never credit. It is held in the
  block's pending row as a deposit and enters the committed map `due` at its
  FINALIZE (`OwedLedgerRules::drops_due`, "V37U" in `owed_digest`). Every
  canonical lane block claims the whole `avail = due - Σ pending claims` of
  the ledger it books on: `E'(k) = max(0, E(k) + avail(k))` before the pay-now
  allocation, the negative rest written off (never carried, never a
  clawback). `XmrOwedSettlementSource::build` reads `avail` from the
  booking-point ledger, so the builder, the block recompute and the share
  verdict all apply the same due: a builder that omits or doubles it is a
  Mismatch (rehearsal M12b, share verdict S11). Pay-now arms when the view
  has payees or some `avail > 0`; the empty-cut finder only when neither.
* **The enrolment registry (handoff A3, ruling 2026-09-30).** A payee is
  enrolled for DROPS at the earliest of its first lane share + 1, the
  ledger's registry record, and its first raindrop bin + 1 inside the
  harvest range `[lo, hi)` of the block being composed. The payees enrolled
  by raindrop ride the block's FOUND as `enrol_add` {eff, payout ref}; they
  join the registry at FINALIZE ("V37G" in `owed_digest`, the finalized
  records; `OwedLedgerRules::raindrop_enrol`) and leave with an ORPHAN
  before it. The next composition reads the registry (finalized + pending)
  at its booking point, so every node derives the same book whatever
  raindrops it still holds below `lo`. The registry ref is what a DROPS-only
  payee is paid through: `build` resolves a registry key to its ref before
  the node's own resolver, and the booking decode maps outputs through the
  registry refs, so a node that never saw the payee's raindrop (a late
  joiner) recomputes an honest block as canonical (rehearsal M13b). Persisted
  in the settle store (schema 4), the FinalizeConnect sidecar ("de=") and
  the DROPS journal ("G").
* **The flag day.** The due and the registry change what every block books
  and pays, so with either rule on the HELLO enrol digest carries the DROPS
  rule tag (`drops_rule_tag`: due = 1, raindrop enrolment = 2). A peer with
  another rule set is refused at HELLO as `DROPS_RULE_MISMATCH`, naming both
  rule sets; a gate-OFF node's HELLO digest is byte-identical to before.
  Pinned by `v37_xmr_raindrop_enrol_kat` RE1..RE5.
* **The relay verdict.** The daemon publishes, per ledger state, a frozen
  copy of the ledger, the payees at its anchor, the booked refs and the lane
  config (`xmr_share_verdict.hpp`, keyed by the 0x03 root the state commits,
  the last 16 states). A verify worker decides each relayed receipt before
  RandomX:
  * canonical: admitted;
  * not canonical: refused, with a strike;
  * not decidable here (a state this node does not hold, or its anchor view
    not read yet): parked like an unknown context. Past the patience an
    unsolicited receipt is dropped. A solicited one (a repair of a winner's
    lane, which is the settlement authority under Ruling A) is admitted.
  Pinned by `v37_xmr_share_verdict_kat` S9, `v37_xmr_spend_floor_kat` F11
  (the ledger anchor, the store, a restart) and `v37_xmr_mainnet_rehearsal_kat`
  M11 / M11b (3 nodes, every block canonical, one anchor, exact
  conservation).
* **Cost.** Every share of one template has the same canonical outputs:
  they depend on the state, the parent, the height and the 0x02 tail from
  V37R on, not on the worker head. The first canonical share of a template
  is rebuilt (about 3.5 ms) and its prefix cached per state; a later share
  splices its own 0x02 payload into it and compares one Keccak (about 3 µs,
  `v37_xmr_share_verdict_kat` S10). A refused share is never cached.
* **Open.** A receipt a node could not decide but admitted as a repair
  answer is trusted on the winner's word: an honest winner never holds a
  refused receipt in its lane.

### 6.1 Share verdict and lane-prefix skew (HOLD-ROUND-2)

A FOUND changes the finder's ledger at once (its own lane block is pending, so
`prev_lane_height()` moves up) but not `owed_digest`, so its next shares commit
the same 0x03 root as before while their drain takes are cut at a smaller dh.
A receiver that has not booked that lane block yet rebuilds the takes at its
own, larger dh and sees an under-take. Stagenet attempt 7: B's shares at
h=2220693 committed 9375000000 = R*4/256, A and C rebuilt 32812500000 =
R*14/256, every share was -1, each -1 a strike: B was banned every ~3 s (86350
bans on A), so the repair of B's block never finished.

The share verdict now classifies a drain take mismatch before it strikes
(`xmr_share_verdict.hpp`, `rc::drain_skew_dh`, integer bisection over
`[1, H_cap]`, at most 7 evaluations at H_cap 64):

| case | test | verdict | relay |
|---|---|---|---|
| LATE | a lane block at or above the share's height is booked here | 4 | dropped, no strike |
| AHEAD | any UNDER-take: the drain Delta at a dh' SMALLER than ours, or a take capped by the sender's smaller F (the sender holds a lane block this node has not booked) | 2 | parked (512 per sender NODE, 4096 in all; at the cap the heaviest node's oldest goes first), re-judged at every share-state publish; no strike |
| BEHIND | an OVER-take no larger than G(H_cap) that is the Delta at a LARGER dh', or is >= our F (a take capped by the sender's larger F; both dh past H_cap included), or fits our own pass that under-fills Delta (the sender lacks a lane block we hold) | 3 | dropped, no strike |
| anything else (a take above G(H_cap); an over-take below our F off every larger dh; a mismatch in payees / outputs / tail) | | -1 | refused, a strike, as before |

**Why every regime (V2).** A share is judged only against held states with
its own 0x03 root, so the two ledgers have the same `owed_digest` and differ by
PENDING lane blocks alone: a pending payout lowers F, a pending height raises
prev_lane. With G(d) = floor(R * min(d, H_cap) / (Q * 16)) (the Delta at
F = infinity), a sender AHEAD of us has F_s <= F_r and dh_s <= dh_r, so its
take is never above ours; a sender BEHIND has F_s >= F_r and dh_s >= dh_r. The
first version inverted only the dh form (`rc::drain_skew_dh`, exact while the
take is below F on both sides) and struck everything else: once F drops below
R*dh/256 every take is F-capped and the ban loop returns. Attempt 7's F fell
from 5.0e11 to 1.65e11 in 6 h against R/4 = 1.5e11. `rc::classify_take_skew`
covers the F-capped forms and both dh past H_cap; a strike needs a take that
no ledger with this digest builds. The price: in the F-capped regime a forged
under-take parks and a forged over-take up to G(H_cap) and >= our F drops,
neither a strike (bounded, never admitted: a parked share must re-judge
canonical).

A solicited receipt (a repair answer) with any skew verdict takes the patience
path and is trusted past it (Ruling A), as before. Counters: `relay-shares:
refused= parked= ... skew ahead= behind= late= ahead_now= rejudged= evicted=`.
KATs: `v37_xmr_share_verdict_kat` S13 (B1-B4) and S14 (V2: F below R*dh/256 and
both dh past H_cap, 120 copies each through the DoS budget: strikes 0, bans 0;
forged takes above G(H_cap) still -1), `v37_xmr_relay_multinode_kat` M8 (200
AHEAD shares: bans 0, bounded, admitted after the state advances) and M9 (V4:
one budget per node across a reconnect; the heaviest node evicted first),
`v37_xmr_hold_round2_kat`.

The same numbers reach the block recompute: `rc::Result` carries `took`,
`took_canon`, `R`, `prev_lane` and `skew_dh` on a take Mismatch, and the
`cba-ALARM recompute_mismatch` line prints `prev_lane=` and `take_skew:`. The
verdict of a block stays a DECIDED Mismatch: once every lower lane block is
decided alike (`finality-boundary.md` section 4a), every node computes the same
prev_lane, so the Mismatch is uniform. Turning a skew Mismatch into a hold was
considered and rejected: a block built on a lower block that was refused
everywhere would then hold forever (`v37_xmr_coinbase_recompute_kat` R20).

## 6a. Proving a balance to a light client (paper §13)

The daemon runs `OwedLedgerRules::merkle_rows` together with the anchor rule.
`owed_digest` is then a Merkle root over the balances:

```
leaf        = sha256d("V37L" || key || i64 finalW || u64 first_eligible)   (non-zero rows, key order)
node        = sha256d("V37M" || left || right)       (an odd last node is carried up)
rest        = sha256d("V37X" || the V37K / V37U / V37G / V37A sections)
owed_digest = sha256d("V37Y" || u64 rows || root || rest)
```

The 0x03 root of every lane block commits
`keccak(domain || chain || owed_digest)`, exactly as before.

`xmr_light_proof.hpp` builds and checks the whole path from a Monero header
to one balance:

1. the hashing blob;
2. the coinbase opening: the 200-byte Keccak midstate, a tail under 136
   bytes, and tx_extra;
3. the tx-tree branch;
4. the balance path, `ceil(log2(rows))` hashes.

The device checks the returned block id against its own header chain and
Monero's PoW. No share-chain data is needed.

The proved balance is the finalized one of the state the block commits, that
is, its booking point.

Pinned by `v37_xmr_light_proof_kat` LP1..LP5:
- off is the flat digest, byte for byte;
- every key of 1..33 rows is proved;
- 1000 rows need a 10-hash path;
- every tampering is refused: balance, age, key, index, count, sibling, rest,
  0x03 root, chain, tree branch, another state.

The rehearsal runs its anchor scenarios with the rule on: three nodes, one
digest.

## 7. Known limits and follow-ups

* **HOLD-ROUND-2 open items** (VERIFY 2026-10-03; V2, V4 and DESIGN O1 are
  closed): **V3** BEHIND / LATE drops are a no-strike channel bounded only by
  the per-peer ingest burst and the 4096 verify queue (a slow skew-drop ban
  budget per node, e.g. a strike after 10k in 10 min, = O4); **V5** the
  inventory and AHEAD keys use the HELLO node nonce, which is not
  authenticated: a peer presenting another node's nonce spends that node's
  budget (bind to nonce + remote address); **V6** "refused" raindrops also
  cover "asked and never admitted" and "context unknown past the patience",
  so a node lagging on monerod holds honest raindrops as refused (fairness
  only; the pin path does not consult the set); **O2** confirm that
  `prev_lane_height()` counting a DEBIT-ONLY booking is intended for the
  drain's dh; **O3** HELLO re-offer replays receipts the peer already judged
  (an "already judged" filter); **O4** one cheap-reject budget serves
  malformed frames and verdict rejects alike (a separate, slower one for
  verdicts); **O5** the verify-queue drop and the horizon expiry are silent
  (a per-minute alarm when they jump). V1 (a withholding finder stalls the
  pool) stays the accepted price until the v37.1 set digest.
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
