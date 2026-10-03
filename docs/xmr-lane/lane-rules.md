# XMR lane: the lane rules are an EPOCH of the pool

Operator ruling R3 (2026-10-02): before the drain rule may activate, every
consensus-relevant lane parameter is committed, so that a node with different
parameters either refuses the peer explicitly or does not recognise the other's
lane blocks as its own. Never a silent `owed_digest` fork.

RULES RATCHET R1 (operator rulings 2026-10-03, the LAST flag day before the
mainnet genesis): the rules are no longer folded into anything on chain. A
pool is named by a derived genesis ([pool-genesis.md](pool-genesis.md)); its
lane blocks name the POOL and the EPOCH (`V37P` v2); the rules of every epoch
ride the relay HELLO as a Deployment list and the ledger's digest as `V37Y`
(the epoch in force) and `V37V` (the lock-ins decided). A rule change is an
epoch, decided by the miners' ballots (slices R2 / R3), never a fresh genesis.
Some of the rules are CONSTITUTIONAL (R-MIN, sec. 4): no epoch may change them.

## 1. The gap this closes

Two halves of a pool id existed before this change:

* the relay HELLO compared `chain_id`, the `lane_params_digest` (LaneParams
  geometry and gates, `share_diff`, bind mode, receipt weight, fee gate), the
  roundabout `lane_tag`, the pool genesis and, at flip 1, the DROPS enrol/rule
  digest;
* the on-chain `pool_tag` (V37P field of the V37C tail) folded `lane_tag` and
  the pool genesis only.

Every settlement rule outside LaneParams rode in no digest: `--d-conf`,
`--settle-h-min`, `--settle-output-cap`, `--recon-max-root-age`,
`--no-book-deferral`, `--owed-demo-amount`, the fee-OFF residual sink, and the
compiled-in rule constants (arm floor, dust decay 8640/2160, salted ties, spend
floor, `commit_total`, anchor cut, Merkle rows, the DROPS rule bits, the input
weight, coinbase maturity, the pool-rules version). Two nodes that differed in
one of them exchanged a clean HELLO, took each other's blocks as their own lane
blocks, recomputed them as Mismatch and booked them debit-only: the A2 fork of
the settlement study (a `Q = 0` node would book drain blocks debit-only for
ever).

## 2. The commitment

`src/c2pool/v37/xmr/xmr_lane_rules.hpp` defines ONE list, `LaneRules`, built
once by the daemon (`lane_rules_of()`, `xmr_lane_rules_build.hpp`) from the
final settlement configuration:

| id | field | id | field |
|---|---|---|---|
| 1 | d_conf | 16 | input_weight |
| 2 | settle_h_min | 17 | tail_subsidy |
| 3 | output_cap (resolved, 0 -> 2700) | 18 | coinbase_maturity |
| 4 | recon_max_root_age (resolved) | 19 | fee_version |
| 5 | book_deferral | 20 | residual_sink_id (fee ON: the donation identity) |
| 6 | arm_floor | 21 | pool_rules_version |
| 7 | rotate_on_payment | 22 | owed_demo_amount |
| 8 | decay_horizon | 23 | drain_q (0 = no drain; 16) |
| 9 | decay_half_life | 24 | drain_h_cap (0; 64) |
| 10 | anchor_cut | 25 | drain_rule_version (0; 1) |
| 11 | merkle_rows | 26 | pool_tag_codec (= 2: the V37P v2 field) |
| 12 | drops_rule | 27 | lane_params_digest (the HELLO one) |
| 13 | drops_window_rw | 28 | enrol_digest (the HELLO one, 0 without DROPS) |
| 14 | kfair_salted_ties | 29 | spend_floor |
| 15 | commit_total | 30 | empty_cut (R1: receipt admission, coinbase-recompute.md section 6.2; its EMPTY-CUT booking branch is reserved) |

Serialisation: a TLV list `u8 id | u8 len | value (little-endian)`, ids strictly
ascending, every known id present (281 bytes for v1 with field 30). A field added later takes
the next id; a reader keeps an id it does not know and refuses the peer by name.

```
rules_digest = sha256d("c2pool-v37-xmr-lane-rules-v1" || tlv)
```

The digest is the `rules_digest` of the epoch's Deployment (RULES RATCHET R1):

* **HELLO** carries the CURRENT epoch's list in the clear after the 174-byte
  pool-genesis frame, then the epoch trailer:
  `u8 enrol_flag | enrol digest 32 (iff flag 1) | u16 rules_len | TLV |
  u32 epoch_cur | u8 n_epochs | n x Deployment (61 B)` where
  `Deployment = u32 epoch_no | b32 rules_digest | u8 kind | u64 start |
  u64 timeout | u64 fixed` (521 B with the one-entry list, or 553 B with the
  enrol slot; +61 B per further epoch, n <= 64). The trailer is mandatory on a
  rules frame: entry 1 is epoch 1 (kind 0, genesis), `epoch_cur` is an entry of
  the list and the TLV is the rules of `epoch_cur` (its digest equals that
  entry's). The four legacy lengths (102/142/174/206) still decode, with no
  list. A pre-ratchet rules frame (no trailer) is refused as
  `hello: rules length mismatch`.
* **In the ledger** every `owed_digest` commits `"V37Y" | u32 epoch_no |
  b32 rules_digest | u64 H_act` (the epoch in force; epoch 1 has `H_act 0`)
  and `"V37V" | u8 n | n x (u32 epoch_no | u8 kind | u64 h_L | u64 H_act)`
  (the lock-ins decided and not yet active) FIRST in its `rest`, always, from
  the first digest. Two nodes that run different rules under the same epoch
  number commit different digests from the first byte.
* **On chain** nothing names a rule. The `V37P` v2 field names the pool and
  the epoch (`epoch_cur`, `epoch_max`); a block of my pool built under another
  epoch than the one in force at its height is "misbuilt": recomputed, found
  Mismatch, booked debit-only with an alarm (spec sec. 1.4).

`hello_mismatch()` compares the common Deployments of the two lists byte for
byte (`LANE_RULES_MISMATCH epoch=N field=rules_digest|kind|start|timeout|fixed
ours=.. theirs=..`; for the current epoch the TLV diff names the parameter and
both values, as below), accepts a peer that knows fewer epochs (a follower) or
more (I am the follower), and compares the TLVs only when both run the same
`epoch_cur`.

Fields 23-25 are the drain rule ([`settlement-drain.md`](settlement-drain.md),
operator rulings 2026-10-02): `drain_rule_version = 1, drain_q = 16,
drain_h_cap = 64` on the test networks from its flag day, `0 / 0 / 0` (master's
coinbase bytes) on mainnet until the operator's own. A rule-on node and a
rule-off node refuse each other at HELLO by name
(`LANE_RULES_MISMATCH field=drain_q ours=16 theirs=0 (+2 more: drain_h_cap
64/0, drain_rule_version 1/0)`, `v37_xmr_relay_pool_id_kat` P8c) and see each
other's blocks as Foreign, so the amendment-A2 fork (a `Q = 0` node booking
drain blocks debit-only) cannot happen. The flag day is a pool restart with a
fresh `--pool-genesis`.

## 3. The refusal and the log lines

`hello_mismatch()` compares the lists right after the pool id and before the
LaneParams digest. A difference is refused by name, with both values and every
other differing field:

```
relay: peer 3 HELLO REFUSED: LANE_RULES_MISMATCH field=d_conf ours=60 theirs=61
  (+2 more: output_cap 2700/16, drain_q 0/16) (every node of a pool runs the same
  lane rules; a peer with other rules builds ANOTHER pool: its lane blocks are
  ordinary Monero blocks here and ours there) -> drop
```

Other cases: `field=rules_absent` (the peer runs a build before this change),
`field=rules_unknown_id N` (the peer runs a newer build). A list that differs
only in fields 27/28 keeps the specific `share_diff` / `bind` /
`lane_params_digest` / `ENROL_SET_MISMATCH` / `DROPS_RULE_MISMATCH` texts. The
refusal feeds `m_last_reject` (dashboard), the discovery blacklist and a new
counter, `rules_mismatch=` on the relay status line.

At startup the node prints its whole list, so two operators can diff their
nodes without connecting them:

```
lane-rules: digest=<64 hex> (30 fields, TLV 281 B) d_conf=60 settle_h_min=0 output_cap=2700 ...
lane-rules: -> pool_tag=<64 hex> (a peer with another list is refused at HELLO as LANE_RULES_MISMATCH; ...)
```

The list the pool_tag folds is built from the HELLO digests the node will send;
the relay start recomputes them from the live DROPS wiring and refuses to start
if they differ.

## 4. Knob bounds (`lane_knob_refusal()`) and the constitution (R-MIN, `constitutional_check()`)

RULES RATCHET R1 (C16): what no epoch may change, checked fail-closed at three
points -- at start on the node's own rules, on every Deployment of the compiled
table (`v37_xmr_mainnet_readiness_kat` F, `v37_xmr_epoch_kat`), and in
`decode_hello` on a mainnet peer's TLV (`R_MIN_VIOLATION field=<name>
value=<v> (...)`):

| | rule | where |
|---|---|---|
| (a) | mainnet: `settle_h_min = 0`, `owed_demo_amount = 0` ("no premine", [pool-genesis.md](pool-genesis.md) sec. 4) | fields 2, 22 |
| (b) | mainnet: `residual_sink_id` = the fixed donation identity | field 20 |
| (c) | wherever a drain exists (`drain_rule_version >= 1`, every network): `16 * drain_q <= 256`, `drain_h_cap >= 64`, `drain_h_cap < 16 * drain_q` -- so `Delta(dh) >= R * min(dh, 64) / 256` in every epoch; mainnet runs 16 / 64 / 1 AT the floor from its genesis | fields 23, 24 |
| (d) | a dormant row decays by the schedule of the epoch in force when it went dormant (`V37K` rows carry `u32 sched_epoch`; `v37_xmr_decay_grandfather_kat`) | the ledger |

What a miner majority still decides, because it is their work: the fee
version, the DROPS bits, the coinbase fields, frame versions, the output cap,
`K_fair` ties, `commit_total`, the recon ring bound, and a FASTER drain. What
it can never do: lower, delay or redirect a balance already earned.

The knob bounds:

* `--d-conf` below Monero's coinbase maturity (60) is refused on every network
  but regtest (the regtest rigs keep 3/4/10).
* Mainnet, in addition to the earlier five: `--owed-demo-amount` is refused and
  the drain triple must equal the network constant 16 / 64 / 1 (the R-MIN
  floor; 0 / 0 / 0 is no longer a mainnet state).
* Every network: the drain triple is valid (`x6::drain_rule_refusal`):
  `version 0 <=> Q == 0 && H_cap == 0`; version 1 needs `Q >= 1` and
  `1 <= H_cap < Q * 16` (so Delta < R and the window always keeps a slot); a
  newer version is refused ("upgrade"). There is no flag for any of the three
  (`v37_xmr_cli_strict_kat` refuses `--drain-*` as unknown; rehearsal K6).

On mainnet the knobs stay pinned, so the rules digest is a build identity: two
binaries that differ in a compiled-in rule refuse each other at HELLO and book
nothing of each other's blocks.

## 5. The flag day (RULES RATCHET R1) and what comes after

* This is the LAST flag day. Old binaries refuse new pools and new binaries
  refuse old ones, by name: at HELLO as `TAG_MISMATCH field=version` (pool
  rules version 5, with the ratchet reason) and as `hello: rules length
  mismatch` (the epoch trailer); on chain each sees the other's blocks as
  ordinary Monero blocks (`V37P` v2 at `[4..49)` vs the retired v1 in the
  tail). Nothing is booked twice, nothing is held.
* Every pool restarts with a DERIVED genesis (`--pool-genesis-from`,
  [pool-genesis.md](pool-genesis.md)) on a fresh `--data-dir` (settlement
  store schema 7, GenesisRec v2 bound to the `pool_id`; a pre-R1 store is
  refused at open). Mainnet can only start that way.
* From here on a rule change is an EPOCH: a Deployment (epoch_no, rules_digest,
  kind, start, timeout / fixed) compiled per network and carried in HELLO; the
  miners' ballots (R2) and the tally (R3) lock it in; the RATCHET event switches
  the ledger's rules at `H_act`; followers that lack the epoch HOLD, never
  diverge. The "fresh genesis per rule change" practice of the earlier attempts
  is gone: the genesis is fixed for the life of the pool.

## 6. KATs

| KAT | pins |
|---|---|
| `v37_xmr_lane_rules_kat` | TLV/digest goldens, strict decode, one refusal per field (29/29, both directions), rules_absent, the 521-byte frame round trip, the property HELLO-compatible <=> equal lists (10,000 perturbations), F: R-MIN (a)-(c) and the `decode_hello` refusal of a mainnet peer |
| `v37_xmr_pool_lineage_kat` G | d_conf 60/61, drain_q 0/16, h_min -> different rules_digest -> refused at HELLO by name while the pool_id is the same; a same-pool block under other rules / another epoch_cur is a recompute Mismatch; equal rules Canonical |
| `v37_xmr_relay_pool_id_kat` P8, E | two live relay nodes, d_conf 60 vs 61: both refuse by name, counter moves, nothing crosses; equal lists interoperate with a byte-identical lane; E: the epoch trailer on the wire, a peer that knows more epochs is accepted, a differing common Deployment is refused `epoch=2 field=start` |
| `xmr_relay_wire_kat` W2r | the 521-byte HELLO golden, legacy lengths, `hello: rules length mismatch` for a pre-ratchet frame, the trailer refusals |
| `v37_xmr_epoch_kat` | V37Y / V37V layouts and the empty-ledger anchor, the Deployment codec, the RATCHET event and its leaf, settle-store schema 7 and the fail-closed matrix, GenesisRec v2 |
| `v37_xmr_mainnet_readiness_kat` F, `v37_xmr_mainnet_rehearsal_kat` K6 | R-MIN at the floor on the mainnet configuration; the raw genesis refused on mainnet; the tightened `lane_knob_refusal()` |
