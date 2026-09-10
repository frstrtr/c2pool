# fa758340 — evidence archive (captured 2026-09-10)

## What this is

`fa758340` is a delivery campaign against the **daemonless (embedded) DASH**
path in c2pool-dash: the node builds its own block template from its own derived
consensus state — masternode list, quorums, ChainLock reference, credit pool —
instead of asking `dashd` for one over `getblocktemplate`.

Four deliverables were in scope. This directory holds the primary evidence for
three of them, exactly as captured, with nothing rewritten after the fact:

| id | claim | status on 2026-09-10 |
|---|---|---|
| D2 | the embedded DIP4 coinbase special transaction (CbTx) is byte-identical to Dash Core's | CbTx leg proven; superblock leg blocked on the network, see below |
| D3 | size of the fee class the 288-block sliding UTXO window cannot price | measured on mainnet: ~39% of fee revenue |
| D4 | a cold daemonless node serves a real block template inside 60 minutes | met at 16 min 10 s, template captured |
| D6 | cross-node PPLNS payout with rebroadcast | not represented here — needs a second production node |

This is an **archive, not product code and not a filing**. Nothing here is
compiled, run by CI, or submitted anywhere. The D2 issue text below is a *draft
held back by the operator*; its presence in git is storage, not publication.

## Files

### D2 — CbTx byte-parity

- **`cbtx_byte_parity_20260910T014709Z.txt`** — the raw gtest run that is the
  proof. 8 tests across `DashEmbeddedCbtxByteParity` and
  `DashMnlistdiffRootParity`, 8 passed / 0 failed, captured 2026-09-10T01:47:09Z
  against `git_head=d7b4aed33d6408a8dfe7f75e238e89b36d644a08`. The header lines
  above the gtest output (`captured_utc`, `git_head`, `host`) were prepended at
  capture time to date the run; everything below them is the test binary's own
  stdout, unedited.
- **`d2_issue_cbtx.md`** — the prose write-up of the same result, drafted for
  submission upstream. Names the covered consensus fields (version,
  merkleRootMNList, merkleRootQuorums, bestCLHeightDiff/bestCLSig,
  creditPoolBalance), the method, and the reproduction recipe. Its section 2
  records why the *superblock* coinbase leg could not be produced: at tip
  2536334 the network reported `nextsuperblock=2542248` with zero valid
  governance triggers, so there was no funded trigger to assemble against. That
  is a network precondition, not a defect in the assembler.

**How to check it:** rebuild the named commit and rerun the named target — the
one command in `d2_issue_cbtx.md` §Reproduction. Expect `8 passed, 0 failed`.
`test_dash_embedded_gbt` is in the CI "Build tests" set, so the same assertions
run in CI and a regression there is not silent.

### D3 — the old-coin fee class

- **`d3fee.py`** — the scanner, 15 lines. One `getblock <hash> 3` per block, no
  per-input lookups, so it is soak-safe on a live node. A fee-bearing tx counts
  as *old-coin* if any input spends a prevout older than `h-288`, i.e. an output
  the `--embedded-utxo` 288-block sliding window has already pruned and therefore
  cannot value.
- **`d3fee.out`** — that scanner's run log over heights 2535178..2536177 (1000
  blocks), progress lines plus the `RESULT` line.
- **`d3_fee_oldcoin_summary.txt`** — the read-out: 19420 fee-bearing txs,
  58,438,730 duffs total fee, 22,981,557 duffs (**39.3%**) unpriceable by the
  sliding window, across 4497 txs (23.2%).

**How to check it:** the `RESULT` line in `d3fee.out` must match the summary
numbers digit for digit — it does. Independently, the scanner's total of
58,438,730 duffs is within **0.012%** of a separately captured ground-truth fee
total of 58,445,570 duffs for the same window, which is what makes this a
measurement rather than an estimate. Re-running `d3fee.py` against any archival
mainnet node with `txindex=1` over the same height range reproduces it.

Not proven here: whether the replay fold *prices* these old-coin txs correctly.
That half was build-gated at capture time. This archive establishes the size of
the class, not the accuracy of the fold.

### D4 — the served template, milestone m1

- **`d4-m1-template/MANIFEST.md`** — the account of the run: why an earlier node
  could never have produced a template (`set_embedded_template_fn` is reached
  only inside the `--stratum` branch, so without that flag `/embedded_template`
  answers `state:"unavailable"` — *not wired* — rather than failing), the exact
  launch line of the run that did produce one, and the cold-start timing chain.
- **`d4-m1-template/INDEX.txt`** — capture times and elapsed seconds from T0 for
  the three snapshots.
- **`d4-m1-template/embedded_template.2026-09-10T09:4{3,4,5}:28Z.json`** — three
  snapshots of `/embedded_template`, one per minute, beginning 16 s after the
  first template was issued.

**The claim:** from a cold empty data directory, process start at
2026-09-10T09:27:02Z, `[MN-CKPT] bridge COMPLETE` at 09:43:09Z, and the first
`[Stratum] send_notify_work: height=2536440` at 09:43:12.721Z — **16 min 10 s**
against a 60-minute budget.

**How to check it, without trusting the prose:**

1. `sha256sum d4-m1-template/*.json` must reproduce the three digests listed
   under *Captured artifacts* in `MANIFEST.md`. They do — that is what ties the
   narrative to these bytes.
2. Capture #1 must be `"state": "ok"` at `"height": 2536440` with
   `"template_age_sec": 15`, which places the sourcing at 09:43:13Z and is the
   internal check on the 16 min 10 s figure.
3. The template is corroborated off-node: the `mining.notify` prevhash observed
   on the miner's wire,
   `56cef90d3f2b651b5c72c9b6fb02bbfd82b7b0c70f1d12ea0000001100000000`, is the
   stratum chunk-reversed form of `previousblockhash`
   `00000000000000110f1d12ea82b7b0c7fb02bbfd5c72c9b63f2b651b56cef90d` in the
   JSON. A snapshot agreeing with the wire is a served template, not an
   intention to serve.
4. `state` distinguishes three things and they are not interchangeable:
   `unavailable` = endpoint not wired; `no_template_served_yet` = wired, nothing
   issued; `ok` = a template was actually issued. Only `ok` closes m1.

The coinbase in these snapshots is the canonical template coinbase — zero
extranonce, no miner payout (`coinbase_note` says so). Per-session miner payout
and extranonce vary and are not part of the capture.

### Supporting

- **`second_node_spec.md`** — written for an external operator standing up a
  second node (the D6 precondition). Explains why a *fresh* deployment cannot
  reach a served masternode set on the cold path — the checkpoint bridge replays
  from the compiled-in anchor at height 2522504 against a flat ban-state probe
  budget, exhausts it, and fails closed, so `have_mn` never arms — and lays out
  three options: ship a post-divergence cursor plus diff store (deliverable that
  day, but ages), ship a fixed binary (durable, build-gated), or run the full
  genesis-to-tip replay fold (correct, ~9-11 h, not externally deliverable
  without a confirmed known-good invocation). The recommendation is A now, B in
  parallel.

  Read this one as a **dated snapshot of a decision**, not as current advice.
  The cold-path failure it describes is the defect PR #1553 addresses; the D4 run
  above is a second cold data directory that walks through h=2529626 — where the
  pre-fix build failed closed — and finishes with `BAN-STATE PROBE: 24/147 used`
  and zero `PROBE CAP IS EXHAUSTED`. If #1553 has landed by the time you read
  this, Option B is no longer hypothetical.

## Scope of this archive

Present: the three artifacts a reader can independently re-derive (the gtest
run, the fee scan, the template snapshots), the prose that interprets them, and
the external-node spec.

Absent by intent: full run logs, scratch files, and anything from D6, which had
no evidence to archive. The live source directories on the capture host are
named in `MANIFEST.md` and are not part of this repository.

Everything here is dated 2026-09-10. Treat every number as as-of that date: the
chain tip has moved, the superblock height may have been passed, and the
build-gated halves may since have been closed.
