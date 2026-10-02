# XMR lane: the lane rules are part of the pool id

Operator ruling R3 (2026-10-02): before the drain rule may activate, every
consensus-relevant lane parameter is committed, so that a node with different
parameters either refuses the peer explicitly or does not recognise the other's
lane blocks as its own. Never a silent `owed_digest` fork.

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
| 8 | decay_horizon | 23 | drain_q (0 = no drain) |
| 9 | decay_half_life | 24 | drain_h_cap (0) |
| 10 | anchor_cut | 25 | drain_rule_version (0) |
| 11 | merkle_rows | 26 | pool_tag_codec |
| 12 | drops_rule | 27 | lane_params_digest (the HELLO one) |
| 13 | drops_window_rw | 28 | enrol_digest (the HELLO one, 0 without DROPS) |
| 14 | kfair_salted_ties | 29 | spend_floor |
| 15 | commit_total | | |

Serialisation: a TLV list `u8 id | u8 len | value (little-endian)`, ids strictly
ascending, every known id present (278 bytes for v1). A field added later takes
the next id; a reader keeps an id it does not know and refuses the peer by name.

```
rules_digest = sha256d("c2pool-v37-xmr-lane-rules-v1" || tlv)
pool_tag     = sha256d("V37PT2" || lane_tag || pool_genesis || rules_digest)
```

The same bytes feed both bindings:

* **HELLO** carries the list in the clear after the 174-byte POOL-LINEAGE frame:
  `u8 enrol_flag | enrol digest 32 (iff flag 1) | u16 rules_len | TLV`
  (455 B, or 487 B with the enrol slot). The four legacy lengths
  (102/142/174/206) still decode, with no list.
* **On chain** the V37P field keeps its 37 bytes and version byte 1; only the
  32-byte value changes. A node with other rules computes another `pool_tag`,
  so our lane blocks are `BlockLineage::Foreign` on it: "not-lane", an ordinary
  Monero block, never booked, never recomputed, never debit-only.

Every input of `pool_tag` is a HELLO-compared field (chain_id and geometry via
`lane_tag`, the genesis, the list), so HELLO-compatible <=> the same pool_tag
(KAT `v37_xmr_lane_rules_kat` suite E, 10,000 random perturbations).

The drain placeholders (23-25) are 0, so the coinbase bytes at default rules
equal master's except the 32-byte tag value. The drain rule only sets them: a
`Q = 16` node and a `Q = 0` node already refuse each other and see each other's
blocks as Foreign, before the drain rule exists.

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
lane-rules: digest=<64 hex> (29 fields, TLV 278 B) d_conf=60 settle_h_min=0 output_cap=2700 ...
lane-rules: -> pool_tag=<64 hex> (a peer with another list is refused at HELLO as LANE_RULES_MISMATCH; ...)
```

The list the pool_tag folds is built from the HELLO digests the node will send;
the relay start recomputes them from the live DROPS wiring and refuses to start
if they differ.

## 4. Knob bounds (`lane_knob_refusal()`)

* `--d-conf` below Monero's coinbase maturity (60) is refused on every network
  but regtest (the regtest rigs keep 3/4/10).
* Mainnet, in addition to the earlier five: `--owed-demo-amount` is refused and
  `drain_q` must equal the network constant (0 until the drain rule's flag day).

On mainnet the knobs stay pinned, so the rules digest is a build identity: two
binaries that differ in a compiled-in rule refuse each other at HELLO and book
nothing of each other's blocks.

## 5. Migration (stagenet flag day)

* New nodes refuse old HELLOs as `rules_absent`; old nodes refuse the new frame
  as "hello: wrong length".
* The pool_tag preimage changed (`V37PT2`), so every pre-flag lane block is
  Foreign to a new node and every new block is Foreign to an old node: nothing
  is booked twice, nothing is held.
* Each pool restarts with a fresh `--pool-genesis` (already the capstone
  practice); a pool that keeps its genesis starts a fresh lane from the flag-day
  block.

## 6. KATs

| KAT | pins |
|---|---|
| `v37_xmr_lane_rules_kat` | TLV/digest goldens, strict decode, one refusal per field (29/29, both directions), rules_absent, frame round trip, the property HELLO-compatible <=> same pool_tag |
| `v37_xmr_pool_lineage_kat` G | d_conf 60/61, drain_q 0/16, h_min -> different tags; a real block is Foreign across rules (no lane cut, no recompute) and Canonical under equal rules; the legacy tag's Own -> Mismatch (debit-only) reproduced; default rules move only the 32 tag bytes |
| `v37_xmr_relay_pool_id_kat` P8 | two live relay nodes, d_conf 60 vs 61: both refuse by name, counter moves, nothing crosses; equal lists interoperate with a byte-identical lane |
| `xmr_relay_wire_kat` W2r | the 455-byte HELLO golden, legacy lengths, `hello: rules length mismatch` |
| `v37_xmr_mainnet_rehearsal_kat` | the tightened `lane_knob_refusal()` |
