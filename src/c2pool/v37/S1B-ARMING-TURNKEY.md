# S-1b — `first_eligible` FINALIZED-HALF arming: the operator turnkey

**Status: NOT APPLIED.** The edit below lands inside the consensus fold body
(`src/c2pool/v37/w4_settlement.hpp`). Applying it changes `owed_digest` for
ledgers that carry a pending payout across a finalize, which is a consensus
activation and a fleet flag day. Everything in this branch is the *evidence*
for the edit: a from-spec shadow that carries both arming rules, the re-minted
goldens, and a regression KAT. The two-hunk edit itself is the operator's hand.

---

## 1. The defect

`owed_digest()` commits, over the finalized partition, key ASC:

```
"V37O" || for each finalW row : key(32) || i64 finalW (LE) || u64 first_eligible (LE)
```

`rearm_first_eligible(bin_height)` — called once per `on_block_finalized` — arms
a key at the bin where

```
EffectiveOwed(k) = finalW(k) - SUM over PENDING blocks of payout(k)
```

first goes strictly positive, and arming is **sticky** (a key already armed keeps
its bin; only a non-positive value disarms it).

The pending set is deliberately **not** synchronised across nodes. Tolerating
that relay-hop skew is precisely why the v0x03 wire-carry exists. So two honest
nodes handed the **same finalize stream** can arm the **same key at different
bins**, and from that moment their `owed_digest`s differ **forever** while their
balances stay byte-identical.

Observed live on the 2-node XMR regtest rig (`~/s1bx2-rig`, 2026-09-13): after an
independent restart both nodes replayed `events=269` from their own W6 store,
both reported one owed key at the same balance at `hw=47 cursor=44`, and the
digests still read

```
node A  6bd4726888171b9395971d16ad5d13b535e1ebb56ace7e432e48718fdb645041
node B  ec91e352f21cbf6163c27158e6be28c3e230c8f38809e8f21f2c405fdda28a47
```

## 2. The ruling

Arm on the **finalized half** — `finalW(k) > 0` — instead of on `EffectiveOwed`.
The finalize stream is byte-identical cross-node (the F1 driver agrees on bids,
heights, bins and order), so `first_eligible(k)` becomes a function of the
finalized balance alone and is identical on every honest node.

Rejected alternatives: dropping the column from the preimage (loses a payout-order
commitment); carrying it on the wire (extra wire surface plus winner-trust).

## 3. ★ THE EXACT EDIT

**File:** `src/c2pool/v37/w4_settlement.hpp`
**Function:** `OwedLedger::rearm_first_eligible(u64 bin_height)` (private)
**Shape:** one comment block and one loop replaced. No signature change, no new
member, no new call site, nothing else in the file moves.

### BEFORE

```cpp
    // Re-arm/disarm first_eligible: a key whose EffectiveOwed just went from
    // <=0 to >0 is armed at `bin_height` (its age start); a key back at <=0 is
    // disarmed. Monotone bin_height (the coin high-water) is the K_fair clock.
    void rearm_first_eligible(u64 bin_height) {
        // R3: arm/disarm over every key the index tracks. That key set is the
        // shipped (finalW ∪ pending-payout) union PLUS only keys whose eo ≤ 0
        // and which carry no fe (disarm is a no-op on them, since fe(k) is set
        // only when eo>0 and fe implies a finalW row that keeps k in the union),
        // so the resulting m_first_eligible map is identical to iterating
        // effective_owed_all() (oracle KAT v37_w4_owed_incremental_test).
        m_eo_index.for_each_eo([&](const bytes32& k, long long e) {
            if (e > 0) {
                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
            } else {
                m_first_eligible.erase(k);
            }
        });
        // Re-establish the ordered positive view from the just-updated fe.
        m_eo_index.rebuild_order([this](const bytes32& k) { return fe_at(k); });
    }
```

### AFTER

```cpp
    // Re-arm/disarm first_eligible on the FINALIZED HALF: a key whose finalW
    // just went from <=0 to >0 is armed at `bin_height` (its age start); a key
    // back at <=0 is disarmed. Monotone bin_height (the coin high-water) is the
    // K_fair clock.
    //
    // ★ WHY finalW AND NOT EffectiveOwed. EffectiveOwed subtracts the PENDING
    // payouts, and the pending set is deliberately NOT synchronised across nodes
    // — tolerating that relay-hop skew is why the v0x03 wire-carry exists. Two
    // honest nodes handed the SAME finalize stream therefore armed the same key
    // at DIFFERENT bins, and because arming is sticky their owed_digests then
    // differed FOREVER at byte-identical balances (observed live, 2-node XMR
    // rig). finalW has a byte-identical finalize stream cross-node, so arming on
    // it makes first_eligible(k) a function of the finalized balance alone.
    void rearm_first_eligible(u64 bin_height) {
        // ARM: every positive FINALIZED row, at its first such bin (sticky).
        for (const auto& [k, w] : m_finalW)
            if (w > 0 && !m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
        // DISARM: any armed key whose finalized row is gone or not positive.
        for (auto it = m_first_eligible.begin(); it != m_first_eligible.end();) {
            auto f = m_finalW.find(it->first);
            if (f == m_finalW.end() || f->second <= 0) it = m_first_eligible.erase(it);
            else ++it;
        }
        // Re-establish the ordered positive view from the just-updated fe.
        m_eo_index.rebuild_order([this](const bytes32& k) { return fe_at(k); });
    }
```

`git apply` form:

```diff
--- a/src/c2pool/v37/w4_settlement.hpp
+++ b/src/c2pool/v37/w4_settlement.hpp
@@
-    // Re-arm/disarm first_eligible: a key whose EffectiveOwed just went from
-    // <=0 to >0 is armed at `bin_height` (its age start); a key back at <=0 is
-    // disarmed. Monotone bin_height (the coin high-water) is the K_fair clock.
+    // Re-arm/disarm first_eligible on the FINALIZED HALF: a key whose finalW
+    // just went from <=0 to >0 is armed at `bin_height` (its age start); a key
+    // back at <=0 is disarmed. Monotone bin_height (the coin high-water) is the
+    // K_fair clock. See S1B-ARMING-TURNKEY.md for why finalW and not
+    // EffectiveOwed: the pending set is not synchronised across nodes, so
+    // EffectiveOwed arming forked two honest nodes forever at equal balances.
     void rearm_first_eligible(u64 bin_height) {
-        // R3: arm/disarm over every key the index tracks. That key set is the
-        // shipped (finalW ∪ pending-payout) union PLUS only keys whose eo ≤ 0
-        // and which carry no fe (disarm is a no-op on them, since fe(k) is set
-        // only when eo>0 and fe implies a finalW row that keeps k in the union),
-        // so the resulting m_first_eligible map is identical to iterating
-        // effective_owed_all() (oracle KAT v37_w4_owed_incremental_test).
-        m_eo_index.for_each_eo([&](const bytes32& k, long long e) {
-            if (e > 0) {
-                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
-            } else {
-                m_first_eligible.erase(k);
-            }
-        });
+        // ARM: every positive FINALIZED row, at its first such bin (sticky).
+        for (const auto& [k, w] : m_finalW)
+            if (w > 0 && !m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
+        // DISARM: any armed key whose finalized row is gone or not positive.
+        for (auto it = m_first_eligible.begin(); it != m_first_eligible.end();) {
+            auto f = m_finalW.find(it->first);
+            if (f == m_finalW.end() || f->second <= 0) it = m_first_eligible.erase(it);
+            else ++it;
+        }
         // Re-establish the ordered positive view from the just-updated fe.
         m_eo_index.rebuild_order([this](const bytes32& k) { return fe_at(k); });
     }
```

### Why the new body reads `m_finalW` directly and not the index

`m_eo_index` is a cache of `EffectiveOwed`. The whole point of the ruling is that
the age key must not depend on it. Sweeping `m_finalW` for the arm leg and
`m_first_eligible` for the disarm leg makes the function self-contained on the
finalized half and removes the index from the digest's dependency set entirely.
`m_eo_index.rebuild_order(...)` stays: the *ordered coinbase view* is still keyed
on `(fe ASC, key ASC)` and still has to be rebuilt after `fe` moves.

### The one invariant this leans on, and it is checked

`EffectiveOwed(k) = finalW(k) - SUM pending payout(k)` and **every reachable
payout is non-negative**: `propose_coinbase` emits `u64 take`; `btc_node.hpp`,
`xmr_o2_finalize_connect.hpp`, `xmr_o2_settlement_provider.hpp` and
`xmr_carrier_stack.hpp` all write `static_cast<long long>(amount)` from an
unsigned amount; and the v0x03 section-2 codec refuses a frame with any
`amt <= 0`. Therefore `EffectiveOwed(k) <= finalW(k)`, so

* `EffectiveOwed(k) > 0` implies `finalW(k) > 0` — the new armed set is a
  **superset** of the old one, so **every eligible key still has an `fe`** and
  `propose_coinbase` never sees a default-0 age it did not see before; and
* the *membership* of the eligible set does not move at all. Only the `fe`
  **values** move, earlier: a key is now aged from the bin its finalized balance
  first went positive, not from the bin a pending coinbase stopped covering it.

### What it does NOT change

* No balance. `finalW` is untouched; only the age column moves.
* No coinbase eligibility. Eligibility is still `EffectiveOwed > 0`.
* No wire byte. No new field, no version bump, nothing carried.
* `prune_finalized_zero_rows()` needs no edit: under the new rule a `w == 0` row
  is always unarmed, so the prune conjunct stays exactly as strong as it was.

## 4. Goldens: what moves, what does not

Every value below was produced by the from-spec shadow in
`src/c2pool/v37/test/v37_s1b_arming_kat.cpp`, which is validated as an **oracle**
by reproducing all fifteen published pre-change values byte-for-byte under the
OLD rule.

### Re-minted (the ruling moves these)

Fixture: `oes_v1::schedule_v1()` (`src/c2pool/v37/test/owed_event_mmr_golden_v1.hpp`),
chain 7, cuts 21 and 24. It is the only shipped owed fixture that carries a
pending payout across a finalize, which is the only way the two rules can differ.

| cut | value | NEW | SUPERSEDES |
|---|---|---|---|
| 21 | `owed_digest` | `dff20133e4824072c224469a1aed460620ddf7d55275aff40e944ff8f0b6bdf7` | `5e3c0cd2ff4db05b1111ef2cb8174838f238f61dae0dea258ba818528908b2e4` |
| 21 | `sc_root_gate_off` | `a436d0590f962719165869bc4ea09ed30312755dc9fbb042696b9609159cefec` | `309662e29e0bec557f8fd14be593cbcd115173e00556bd0741ad5bfa901456dd` |
| 21 | `sc_root_gate_on` | `0379deb8676d1da6b2022d158277bb06363591c8a34bddf7150924b2b1ce8444` | `d45517c7b71878891a4eede39db4ca34482ddcfe4f50a72d029f1146737205b7` |
| 24 | `owed_digest` | `dff20133e4824072c224469a1aed460620ddf7d55275aff40e944ff8f0b6bdf7` | `5e3c0cd2ff4db05b1111ef2cb8174838f238f61dae0dea258ba818528908b2e4` |
| 24 | `sc_root_gate_off` | `3f030a249bd4b36fbca505aba6add56a1cdd92072b2197182b6ec948aac4e487` | `55ff6625312a8d668ce9b60183c5ff9756a84e0fc797e0195a1d149519a0d8d8` |
| 24 | `sc_root_gate_on` | `cd57f501ae85c7c6fb636c2e49835162fa6dd3c1c91585e1b854fcec1298cbdf` | `b8380f38c64e1c2da4791d36b69df520593ddc059ef20e9d8de11ac8dbd8b1c0` |

The StateCommitment roots move **because** the `"V37S"` summary leaf carries
`owed_digest` verbatim. The MMR columns (`mmr_leaves`, `mmr_root`) do **not**
move: the record log commits event payloads, which carry no `first_eligible`.
Cuts 0, 6 and 15 do not move (no pending payout is outstanding at their
finalizes).

When the edit is applied, the table in
`src/c2pool/v37/test/owed_event_mmr_golden_v1.hpp` (`goldens_v1()`) is the one
place these six values live.

### Unmoved (proved, not assumed)

| anchor | why it does not move |
|---|---|
| `b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339` | the empty-ledger anchor is `sha256d("V37O")`. No rows, so no `fe` column exists for the rule to reach. Asserted under **both** rules. |
| `9cfaf97de7c58a7727ff5cc1203f445fc301559fb702938a3dd61ad32d6b338e` (V37.1 ridge OFF) | its schedule calls `on_block_found_with_estimator(bid, credit, {}, …)` — **payout `{}`** — immediately followed by `on_block_finalized`. |
| `87c5249ac2057d0ac6707127c59cdc605acec4ba3c0d4b4b25e9b53692eb71ee` (V37.1 ridge ON) | same schedule, same shape. |
| `984c7753ab352255933fb63da524b93eecc916b07cc77d94b454213922f719ce` (DROPS arity-2) | `on_block_found_with_drops(bid, base_credit, {}, …)` then `on_block_finalized` — payout `{}` throughout. |
| `b03abb1f5798ab199febc4977b4af31e624f5aab0d84e41e60310d344586bd19` (arity-2 fold) | a fold of four unmoved digests. |
| `ae44add291dbe90aec581825a3e60ce8fd7bbc7194bc767e096da12669d8614f` (DROPS arity-1) | same shape. |
| `50b5d7d109a1ae5429f4be91c54fba62c031449e01509d1ce9295a0a79af8646` (arity-1 fold) | a fold of four unmoved digests. |
| `4e13dd3f7472dae166e0d99ab778a296b8308afd6c2f55595747628800bdf0a4` (S-1 live wiring) | a FRESH win credits `E_b` and broadcasts nothing, so its FOUND carries an empty payout. |
| `2479d5b6…` (KAT-0) | a lane-geometry digest over `::v37::LaneParams{}`. `owed_digest` is not an input to it. |

**The shape theorem.** If every FOUND carries an empty payout and its FINALIZE is
adjacent to it, then `m_pending` holds no payout at any rearm, so
`EffectiveOwed(k) == finalW(k)` identically and the two rules agree **pointwise**
— for any credit maps, including the negative DROPS REPLACE deltas. Case `D1`
proves it on 20 000 randomised streams: zero digest divergences, zero `fe`
divergences.

> **Correction to the brief.** `9cfaf97d…` and `87c5249a…` are **not** lane
> digests — `v37_1_ridge_activation_test.cpp` mints both from
> `OwedLedger::owed_digest()`. They are unmoved for the shape reason above, not
> because they live outside the owed fold. The value that KAT reports as a lane
> digest is `9bad8ea0…`, and it is reported rather than pinned.

## 5. Evidence in this branch

`src/c2pool/v37/test/v37_s1b_arming_kat.cpp` — stdlib only, no engine, no coin
backend, no sockets, no clocks, no threads. 27 checks.

| case | what it establishes |
|---|---|
| `A0` | the shadow's own SHA-256 matches the FIPS 180-4 `"abc"` vector |
| `A1`/`A2` | `sha256d("V37O")` is the shipped empty anchor, under **both** rules |
| `B@0..24` | **ORACLE** — the OLD rule reproduces every published `owed_digest`, `ledger_seq`, gate-OFF and gate-ON StateCommitment root byte-for-byte |
| `C@0..24` | the re-mint above, plus a non-vacuity check that the fixture really does finalize with another block's payout pending |
| `D1` | shape invariance over 20 000 randomised streams |
| `E1..E6` | the live 2-node fork, reproduced from the rig's own captured W6 event stream, and closed |
| `F1`/`F2` | 3 000 randomised skews: the NEW rule forks **0**, the OLD rule forks ~39 % |

Byte-identical output at `-O0`, `-O1`, `-O2`, `-O3` and under
`-fsanitize=address,undefined` with `detect_leaks=1` — clean.

### The live fork, reproduced

The event stream is the literal content of `rig/settleA/settle.img` — the real
identity key `b9d5bd32d700531c…`, the real credits, the real payouts, the real
bins. Node B is handed the **same seventeen events**, with the same finalize
substream in the same order at the same bins; only two payout-bearing peer FOUNDs
arrive one relay hop earlier.

```
finalW = 70368609960000 piconero, one row, one key, ledger_seq 17 — on both nodes

OLD  A  fe=4  d004509fe8bc58afe6aebe5f861a31ea1ea30785b69996369914e922d3d463d9
OLD  B  fe=5  689d08268d5dd8b6683bc8ff8a2293b66af692f8bbcfebdf2eebccd5c0350b9c   FORK
NEW  A  fe=4  d004509fe8bc58afe6aebe5f861a31ea1ea30785b69996369914e922d3d463d9
NEW  B  fe=4  d004509fe8bc58afe6aebe5f861a31ea1ea30785b69996369914e922d3d463d9   EQUAL
```

Those two OLD-rule digests were independently confirmed by driving the **real,
unmodified** `OwedLedger` from `w4_settlement.hpp` with the same two orders: the
shipped consensus code forks on this stream today.

> **Honest limit.** The literal live pair `6bd47268…` / `ec91e352…` cannot be
> re-derived byte-for-byte: the 269-event stores that produced them were
> overwritten by the rig's next run, and the surviving logs record
> `EffectiveOwed`, not `finalW`, so the digest preimage is not recoverable from
> them. What is reproduced is the same defect on the same rig's real data —
> identical balances and `ledger_seq`, one row, one key, `fe` the only differing
> preimage column — which is the form the brief admits as equivalent.

## 6. Apply order

1. Land the two hunks in `src/c2pool/v37/w4_settlement.hpp` (§3).
2. Replace the six values in `goldens_v1()` in
   `src/c2pool/v37/test/owed_event_mmr_golden_v1.hpp` (§4).
3. Run `v37_s1b_arming_kat`, `v37_owed_event_mmr_kat`, `v37_w4_settlement_test`,
   `v37_w4_owed_incremental_test`, `v37_s1_live_wiring_kat`,
   `v37_s1c_convergence_kat`, `v37_1_ridge_activation_test`.
4. **One sibling file must move in the same commit.**
   `src/c2pool/v37/test/v37_w4_owed_incremental_test.cpp` carries a naive oracle
   model of the ledger and asserts the shipped incremental index is equivalent
   to it. Its `Naive::rearm` (around line 106) arms on `EffectiveOwed`:

   ```cpp
       void rearm(u64 bin_height) {
           for (const auto& [k, e] : eo_all()) {
               if (e > 0) { if (!first_eligible.count(k)) first_eligible[k] = bin_height; }
               else first_eligible.erase(k);
           }
       }
   ```

   It must become the same finalized-half sweep:

   ```cpp
       void rearm(u64 bin_height) {
           for (const auto& [k, w] : finalW)
               if (w > 0 && !first_eligible.count(k)) first_eligible[k] = bin_height;
           for (auto it = first_eligible.begin(); it != first_eligible.end();) {
               auto f = finalW.find(it->first);
               if (f == finalW.end() || f->second <= 0) it = first_eligible.erase(it);
               else ++it;
           }
       }
   ```

   Left unchanged, that suite goes red on the first case that finalizes with a
   payout pending — correctly, because the oracle would then disagree with the
   canon. No other sibling test pins `first_eligible`.
5. The flag day: every node must cross over together. A node still arming on
   `EffectiveOwed` will disagree with an upgraded peer on the first ledger that
   carries a pending payout across a finalize.
