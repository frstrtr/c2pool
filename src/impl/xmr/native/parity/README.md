# C6 — the monerod-parity oracle

`src/impl/xmr/native/parity/` implements `contracts/parity.hpp`'s `IParityOracle`.
It runs **beside** a real monerod during bring-up and answers one question, for
as long as the pool is up:

> would the native node have said exactly what the daemon said?

It is the **M4 gate**. monerod is demoted from "required" to "optional" only when
all three seams below have been green over a sustained window, and the ledger
that records that is revocable by a single disagreement.

## The three seams

| seam | what is compared | source of truth on the other side |
|---|---|---|
| **TIP** (`P-TIP`) | tip id, prev_id, **cumulative difficulty**, difficulty, timestamp, reward, block weight, long-term weight, major version | monerod `get_info` **and** `get_last_block_header` |
| **TEMPLATE** (`P-TPL`) | the six `get_miner_data` fields the option-B assembler consumes: prev_id, major_version, difficulty, seed_hash, median_weight, already_generated_coins | monerod `get_miner_data` at the same height |
| **SUBMIT** (`P-SUB`) | acceptance of a block the native relay would submit | monerod `submit_block`, **and** the block turning up on our own verified chain |

Cumulative difficulty is the one that carries the weight of the claim. It is not
in any Monero block header — it is chain state, accumulated from the anchor
forward — so agreement over a sustained window means the native index walked the
same chain the daemon did *and* did the same arithmetic on the way.

## Void is not agreement

This is the rule the component exists to enforce, and it is structural rather
than advisory:

> A sample reaches **CLEAN** only if every required EQUALITY field in its seam
> was answered by **both** arms and every one of them matched.

Everything else follows:

* an arm that produced no answer at all → **VOID** (nothing to judge);
* arms aligned on different blocks → **VOID** (different questions);
* a seam with no required comparison → **VOID** — "agreement" over an empty set
  is not agreement, and the comparator says so in the note;
* an arm that *answered* but left a required field empty → **FAIL**. A field the
  arm owed and did not produce is a real divergence, not a transport hiccup — a
  transport hiccup yields no answer at all and lands in the VOID branch.

VOID never touches a clean streak, and the graduation policy caps the void rate.
On top of that the ledger keeps **per-field coverage**: every required EQUALITY
field must have been genuinely compared a minimum number of times. A field that
is never comparable therefore **blocks** graduation instead of being invisible to
it, and the verdict report prints `<== BLOCKER: never compared` next to it.

Coverage is keyed **per seam** (`TIP.difficulty`, `TEMPLATE.difficulty`), not by
bare field name. Three names — `prev_id`, `major_version`, `difficulty` — are
required by both tables and mean different things there, so a bare-name key would
let a long tip run silently satisfy the template seam's floor for fields nobody
ever compared there. That is the exact vacuity the floor exists to catch, so the
KAT pins it: 40 tip samples leave every `TEMPLATE.*` field at zero and named as a
shortfall.

## Files

| file | what it holds |
|---|---|
| `xmr_parity_types.hpp` | `Obs` (a value **or** an explicit absence), `FieldSet`, the frozen field tables for the three seams, `SeamResult`, the height classifier |
| `xmr_parity_comparator.hpp` | the judge: `compare_seam` for TIP/TEMPLATE, `judge_submit` for SUBMIT |
| `xmr_parity_sources.hpp` | intake: `get_info`/`get_last_block_header` bodies and presence-preserving parsers, the native tip observer over C2c's `ChainStateView`, the template observer over `node::MinerData` |
| `xmr_parity_ledger.hpp` | the revocable, hard-keyed graduation ledger and its JSON persistence |
| `xmr_parity_report.hpp` | the `[XMR-PARITY]` sample lines, the NO-SAMPLES heartbeat, the verdict report |
| `xmr_parity_oracle.hpp` | `ParityOracle`: the enqueue-only probes and the `drain()` worker |

Everything is header-only; the KAT is the only target that compiles it.

## Hot-path discipline

`on_tip`, `on_serve` and `on_submit` copy their argument into a slot and return.
All comparison happens in `drain()`, which the owner calls from its own worker.
A slow or broken oracle cannot slow, block or change a share.

TIP and TEMPLATE **coalesce** to the newest trigger — an oracle that queues
behind a burst of blocks is measuring its own queue. SUBMIT never coalesces:
every found block is its own irreplaceable sample.

`on_serve` carries the **served artefact** (`node::MinerData`), not just an epoch
tag. Re-reading the serving arm instead would give a different template whenever
the backlog moved in between, and `SERVED_MISMATCH` — the verdict that catches us
serving something *neither* arm would have produced — would become unprovable.
The serving arm is still cross-checked, but only while its epoch has not moved.

## Graduation

The ledger is hard-keyed to `{c2pool_commit, comparator_version, monerod_version,
net}`. Change any of the four and the streak restarts, because a streak earned by
other code against another daemon on another network is not evidence about this
one; a ledger on disk under a different key is discarded, loudly.
`GraduationPolicy::stagenet_m4()` carries the plan's section 3.6 numbers;
`regtest_fast()` keeps the same structure with small numbers for a harness.

Persisted at `<config>/<net>/xmr_parity_ledger.json`. `GRADUATED` is revocable at
any moment by a sentinel (a `major_version`, `difficulty`, `cumulative_difficulty`,
`seed_hash` or `already_generated_coins` disagreement; a `SERVED_MISMATCH`; a
daemon rejection while a different block landed at the same height within 60 s; a
different block id confirming at our height), and revocation is terminal for the
key.

## What it proves and what it does not

**Proves:** chain-state equivalence — the native index and template produce the
same numbers as the monerod-fed path — and, where an acceptance oracle is armed,
that a native block is accepted.

**Does not prove:** network-layer independence. Peer diversity, relay reach and
eclipse resistance are a separate gate with its own evidence (≥ 8 outbound peers
over ≥ 3 ASNs, and the rest of the M5 conditions). Relaying a block to N peers is
not evidence that anybody accepted it, and `judge_submit` returns VOID rather than
CLEAN when that is all the evidence there is.

## Regenerating the capture

`../test/gen_c6_parity_golden.py --rpc http://<host>:38081/json_rpc` takes a
read-only capture from a synced daemon (four calls, nothing written) and refuses
to emit a golden whose parts are not internally consistent. The committed capture
is monerod 0.18.5.1-release on stagenet at tip 2205017.
