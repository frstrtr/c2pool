# V37 roundabout split: S1-S5 as standalone modules

Header-only, stdlib-only, namespace `c2pool::v37n::rb`. Every file here is NEW.
No existing translation unit includes these headers, so every pre-existing
golden (lane digest, owed_digest, wire freeze, coinbase shape) is unchanged by
construction. `v37_rb_gate_off_kat` also re-derives the pinned lane-digest and
owed-digest goldens with all of these headers included in one translation unit.

Terminology: **roundabouts** only. "Min-viable" means the SECURITY floor.
`::v37::Roundabout` (`src/sharechain/v37/v37_roundabout.hpp`) is the canon
multichain Lane container. This module never redefines or extends it.

## Design of record (killer-design FOF verdict, 09-23; D1-D10 as recommended)

- **D1, replicated ledger.** Every node keeps one OwedLedger per coin.
  Roundabouts partition share gossip and verification only. Traffic between
  roundabouts is PoW-backed weight checkpoints (S4). No owed row ever moves.
- **D2, partitioning.** `u = H_ref/S`. `n(id) = 2^ceil(log2(max(1, h_obs/u)))`,
  capped at S. `stripe_key(id,s) = sha256d('V37RB' || u32 chain_id || id_key || u16 s)`,
  with NO salt. `rb_home` = the top m bits. Load is bounded by probing in
  canonical stripe_key order against `cap = ceil((1+eps)*mean)`.
- **Trigger.** H_hat is PoW-backed finalized work divided by time over the map
  period. Split when `H_hat/k >= 2*H_ref*(1+delta)`. Merge when
  `H_hat/k < H_ref*(1-delta)`. The map moves at most one step per period.
  `Map_e = f(finalized prefix_{e-1}, Map_{e-1}, params)`, with no vote. If a
  roundabout's summary is missing, its contribution decays, reaches W = 0 after
  G periods, and never vetoes the map.
- **D3-D5.** `H_ref` is a per-coin PARAM (BTC candidate: 86 PH/s). The map
  period is about 1 day (144 BTC bins, 720 XMR bins). Summaries come every
  ~64 bins. Defaults: S = 256, eps = 1/4, delta = 1/8, and a k_max param.

Choices this implementation makes where the design leaves room (flagged for
ratification):
- **Probe sequence.** The probe goes `home ^ 1, home ^ 2, ..., home ^ (k-1)`,
  i.e. by XOR distance, which is distance in the prefix tree. The sibling is
  tried first, so overflow stays inside the parent roundabout's stripe set
  whenever the sibling has room. If no roundabout fits, the stripe goes to the
  least-loaded one, taking the first minimum in probe order.
- **Split/merge decay state.** On a split, each child inherits half of the
  parent's `last_W` and the parent's miss count. On a merge, the parent gets
  the sum of `last_W` and the smaller miss count. A missing summary halves the
  contribution for each missed period, and the contribution is 0 at G
  (`miss_grace`, default 4).
- **Integer headroom.** The trigger compares in U256. `well_formed()` bounds
  `bin_seconds <= 2^20`, `E_map_bins <= 2^24`, and `eps/delta` terms `<= 2^16`.

## Files

| file | stage | content |
|---|---|---|
| `rb_params.hpp` | all | LE put helpers, domain tags, `top_bits`, integer helpers |
| `rb_gate.hpp` | S5 | `RoundaboutGate` (add-only, default OFF, `for_version`, `candidate`, `well_formed`) |
| `rb_stripe.hpp` | D2/S3 | `stripe_key`, `rb_home`, `n_of`, `stripe_load` |
| `rb_map.hpp` | S3 | `Map`, `derive_map` (pure), `trigger`, `load_cap`, `DeriveReport`, `churn` |
| `rb_lane_tag.hpp` | S1 | `geometry_leaf/digest`, `LaneTagContext`, `lane_tag`, `RbCarriage` (46 B), `tagged_preimage` |
| `rb_admission.hpp` | S1 | `check_roundabout` -> `REJECT_ROUNDABOUT` (+ diagnostic reason), `make_carriage` |
| `rb_cb_class.hpp` | S2 | `CbClass`, `class_bytes`, `cb_budget`, `budget_from_block` |
| `rb_checkpoint.hpp` | S4 | `Summary` + canonical bytes/parse, `merkle_root`, `summary_merkle`, `CutTokenK`, `read_cut_k` |
| `rb_settle.hpp` | S4 | `combine_payout_maps`, `settle_roundabouts` (reuses `settle::split_reward` verbatim) |

## Wiring seams (operator's hand; each one is a consensus change and a classifier-blocked canon edit or golden bump)

### S5: RoundaboutGate in LaneParams (canon `v37_lane.hpp`)
```
// v37_lane.hpp after :400 (NrGate nr{};)
+    RoundaboutGate roundabout{};   // ADD-ONLY, NOT digested; default OFF (k = 1)
// v37_lane.hpp :412-416 for_version(v)
     p.subthreshold = SubthresholdGate::for_version(v);
+    p.roundabout   = RoundaboutGate::for_version(v);   // OFF for every v today
```
This is digest-neutral: `build_leaves` (:2869-2879) appends only explicit
fields, and `geometry_is_ratified` (`w4_settlement.hpp:427-471`) does not read
the gate. Because canon is stdlib-only, `RoundaboutGate` would move into the
`::v37` namespace, or LaneParams would carry a mirror struct.

### S1: lane_tag under PoW + REJECT_ROUNDABOUT
1. PoW preimage (`w2_receipt.hpp:216-227`). The current preimage is **112 B**
   (4+32+32+32+4+8; the research note's "116 B" was wrong, and the KAT pins
   112). Add `std::optional<bytes32> lane_tag` to `WorkEvent`. `preimage()`
   appends it only when present, so the v0x01/v0x02 bytes stay a strict
   prefix: `rb::tagged_preimage` gives 144 B.
2. Wire (`w3_relay.hpp:150-156`). Add `W3_WIRE_VERSION_V3 = 0x03`, with a
   46-byte `rb::encode_carriage` trailer after the v0x02 cut-descriptor
   trailer. The v0x01/v0x02 offsets and goldens (`v37_w3_wire_freeze_kat`)
   stay untouched. Add V3 to the dual-accept list in `encode_version` (:272).
   The "v0x03 credit-map" (`c2pool#1627`) is not on master, so the tag byte is
   free. That must be reconciled if `#1627` lands first.
3. Admission (`w2_admission.hpp:66-75`). Add `REJECT_ROUNDABOUT` after
   `REJECT_CHAIN` (:72). `validate_receipt` gets a step 3d right after :178:
   ```
   if (r.chain_id != m_chain) return Disposition::REJECT_CHAIN;
   + if (m_rb && !rb::check_roundabout(m_rb->gate, m_rb->ctx, *m_rb->map, m_rb->my_rb,
   +                                   r.identity, r.carriage).ok())
   +     return Disposition::REJECT_ROUNDABOUT;
   ```
   Apply the same check at the carrier level at :199-203. Injection goes
   through a new optional `ReceiptAdmitter` ctor arg or setter
   (`{gate, ctx, map, my_rb}`, :141-144). The live sites are
   `carrier_ingest.hpp:103` and `carrier_repair.hpp:398`. When the gate is OFF,
   `m_rb` is empty and the path is byte-identical to master.
4. `LaneTagContext::of(lane_chain, LaneParams, SHIPPED_CONSENSUS_VERSION, 0)` at
   node construction (`btc_node_config.hpp:128`, `xmr_node_config.hpp:156`;
   both default to `lane_chain = 0`). This closes the **pool-id GAP**: a peer
   with a different geometry, version, chain or authority now fails with an
   explicit `REJECT_ROUNDABOUT(TAG_MISMATCH)` instead of diverging silently.

### S2: cb_class budget
1. Per-share class. The share commits the `cb_class` u8. The WINNING share's
   class sets the block's budget.
2. BTC (`btc/btc_node.hpp:326-329`, and the peer-win mirror at :541-544):
   ```
   - budget.max_payout_bytes = 0;
   + budget.max_payout_bytes = rb::cb_budget(cls, fixed_overhead, free_after_txs, lane_kmax);
   ```
   Keep the >= 1 lift. `max_payout_bytes == 0` means UNBOUNDED in w5
   (`w5_coinbase.hpp:144`).
3. On-chain commitment. The class must be recomputable from the block. For
   XMR, extend the 44-B "V37C" tail (`xmr/xmr_credit_cut.hpp:18,36`) to 45 B,
   which bumps the coinbase-shape golden (`v37_xmr_credit_cut_kat`). For BTC,
   commit the class beside the §13 state_root (`btc_node.hpp:125,343`).
   Validators call `rb::budget_from_block` and reject when
   `payout_bytes > budget`. A class byte > 5 is invalid.
4. K_fair is untouched (`w4_settlement.hpp:728-760`). The KAT proves that
   bounded outputs are an in-order prefix of the unbounded K_fair sequence.

### S3: map inputs owed
`SettlementView` (`v37_engine.hpp:77-90`) does not expose per-identity raw
work. The finalized-prefix accumulator that feeds `IdWork{id_key, h_obs}` is
still owed (candidate source: `CompEntry (miner, w_scaled, w_raw)`,
`v37_lane.hpp:616`). The per-roundabout `W_i` comes from the S4 summaries.

### S4: checkpoints + cut
The `Summary` publish cadence is `ckpt_bins`. `read_cut_k` gets one leg per
roundabout (reusing `settlement_view_at` per roundabout lane) plus the one
ledger leg. `settle_roundabouts(R_b, summaries)` replaces
`settle::settle_block(R_b, view)` at the S8 single view-build site when k > 1.
At k = 1 the two produce identical E_b (KAT E5, and gate-off KAT E2 against
the pinned owed golden).

## Measured (v37_rb_map_churn_kat; BTC candidate, 3000 identities, 600 PH/s => k = 4, 30 periods/scenario)

Deterministic run (the final map digest `e78f5397...` is pinned by the
KAT's two-run determinism check):

| scenario | stripes | n changes/period | moved/period (honest) | moved load | overrides/period | max/mean home -> final | unfit |
|---|---|---|---|---|---|---|---|
| (a) pow2 crossings, +-10%/period | 4201 | 48.2 | 0 | 0 ppm | 0 | 1.051 -> 1.051 | 0 |
| (b) join/leave 5%/period | 4287 | 72.6 | 0 | 0 ppm | 0 | 1.033 -> 1.033 | 0 |
| (c) split 4->8 (split period) | 4859 | 74 | 0 cross-parent (4048 renumbered j->2j/2j+1) | 0 ppm | 0 | 1.098 -> 1.098 | 0 |
| (c) merge 8->4 (merge period) | 4127 | 51 | 0 | 0 ppm | 0 | 1.047 -> 1.047 | 0 |
| (d) adversary, eps = 1/8 | 4426 | 0 | 129 (3.08%) | 30077 ppm | 186 | 1.312 -> 1.125 | 0 |
| (d) adversary, eps = 1/4 | 4426 | 0 | 115 (2.75%) | 26250 ppm | 78 | 1.312 -> 1.230 | 0 |
| (d) adversary, eps = 1/2 | 4426 | 0 | 0 | 0 ppm | 0 | 1.312 -> 1.312 | 0 |

Reading:
- Honest churn is **zero moves**. Power-of-two crossings and join/leave only
  create or remove stripes (on the order of 50-140 per period out of ~4200).
  Stripes that already exist never move, because stripe_key is salt-free and
  n changes only on x2.
- A split renumbers every stripe inside its family (j -> 2j or 2j+1) and moves
  nothing across parents. A merge is the exact reverse.
- Honest max/mean home load is 1.03-1.10, below the eps = 1/4 cap (1.25), so
  the bounded-load probe never fires on honest traffic.
- The adversary controls 8.7-17% of pool hashrate on 40 ground identities
  (~4^8 grinding per identity), aims every stripe at roundabout 0, and
  oscillates x2 every period. At eps = 1/4 this forces ~115 honest stripe
  moves per period (2.6% of honest load), and the cap holds (final 1.23 <=
  1.25). At eps = 1/2 there are no honest moves, but roundabout 0 runs at
  1.31x the mean. **eps trades noisy-neighbour load against adversarial
  churn.** 1/4 is a reasonable middle point, but the value is measured, not
  proven optimal.
