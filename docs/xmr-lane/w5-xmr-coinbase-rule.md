# W5-XMR coinbase settlement rule (Family B: Monero / RandomX lane)

**Leg:** `w5-coinbase` of the XMR-lane foundation.
**Design of record:** `v37-monero-randomx-lane-scoping.md` §2.1–§2.5, §13–§14, §16, OQ-X4, OQ-X8, OQ-X10.
**Status:** Phase-2 design track (Family B). This leg supplies the coinbase-*derivation* rule + a working C++ reference; it is a **canon/consensus** surface (an integrator tap lands it, like the descriptor kinds). No git, no PR from this leg.
**License:** authored clean AGPL-3.0. p2pool (GPL-3.0) is *referenced* (provenance in `xmr_coinbase.cpp`), never copied.

Files:
- `src/impl/xmr/settle/xmr_coinbase.hpp` — the W5 surface (types, derivation, fence).
- `src/impl/xmr/settle/xmr_coinbase.cpp` — the derivation + exact-sum + ACCEPT check.
- `_compile_check/` — shim headers + a logic-test driver (NOT shipped). `g++ -std=c++20 -fsyntax-only` clean; the driver runs the exact-sum / K_fair / fence / ACCEPT assertions with stubbed crypto and prints `ALL W5-COINBASE CHECKS PASSED`.

---

## 0. Why the Bitcoin-family W5 does not port

Five Monero facts (all [V] in the scoping annex) reshape W5. The spine above the coinbase seam — the OWED KEYED_CRDT ledger, `owed_digest`, K_fair ordering + carry, `D_conf` floor, cut tokens — is unchanged.

| Bitcoin-family W5 assumption | Monero reality | W5-XMR consequence |
|---|---|---|
| coinbase pays script bytes straight from the descriptor | **no script**; the output is a *derived* one-time key `P_i`, spendable only via ECDH from a tx secret key `r` | need `r`; outputs are `f(r, A_i, B_i, i)` |
| coinbase built statelessly | needs a per-block `r` | **deterministic `r`** = pure function of consensus data; `R=r·G` published in `tx_extra` 0x01 |
| coinbase may underpay; remainder burnable | **exact-sum** since `HF_VERSION_EXACT_COINBASE` (13): `Σ vout == base_reward + fees` exactly; burning is a consensus failure | **residual-sink rule** (§2) — a mandated payee absorbs all unallocated budget + rounding; no burn |
| `owed_digest` in `OP_RETURN` | no `OP_RETURN` | commitment = **leaf under the 0x03 merge-mining tag** (§5), not the 0x02 nonce |
| output count bound by ASIC/extranonce | bound by **block weight + quadratic reward penalty** | **weight-aware cap `C`** (§4), ~2000–2700 |

Constants pinned by the coin: `unlock_time = height + 60` (`CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`) ⇒ **`D_conf` floor 60**; output type `txout_to_tagged_key` (since HF15); `dust = 0` (no consensus/relay dust rule); `size = 42` B/output.

---

## 1. Deterministic tx secret key `r`

```
preimage = "c2pool-v37-xmr-txkey-v1"
         || u8(monero_major_version)
         || u32_le(chain_id)
         || lane_commitment[32]          // owed_digest / lane digest
         || prev_id[32]                  // Monero parent block id
         || varint(height)
r = H_s(preimage)                        // keccak256 then reduce mod l -> reduced scalar
R = r · G                                // published in tx_extra tag 0x01
```

`H_s` is the coin layer's `hash_to_scalar` (keccak256 + `sc_reduce32`), so `r` is a canonical (`sc_check`-clean) secret key. This is **p2pool's load-bearing trick** re-expressed: p2pool uses `entropy = "tx_secret_key" || seed || monero_block_id`; here the "seed" is v37's **`lane_commitment`** (the exact owed set) and "monero_block_id" is **`prev_id`**. So a different owed set *or* a different Monero parent forces a different `r` — exactly p2pool's re-derivation when the parent changes (`PoolBlock::calculate_tx_key_seed`). `major_version` is folded in so a fork can never collide.

`r` is public to the lane network by construction (everyone re-derives it). This is safe for spending — a spend needs the recipient's private *spend* key `b`, which `r` does not reveal — and is the price of every-node verifiability. Privacy consequence: lane peers can link a coinbase output to its payee's address; miners wanting unlinkability use a dedicated subaddress per lane (scoping OQ-X5, §17 caveat B). **No circularity:** `lane_commitment` is a Merkle over `(identity_key, finalW, first_eligible)` — it does not depend on `R` or on the derived keys, which depend on `r`; both derive from the same ledger independently.

---

## 2. Exact-sum residual-sink rule (resolves OQ-X8)

`budget := base_reward + fees`. The coinbase MUST pay **exactly** `budget`. The rule is a pure, deterministic function of consensus inputs (`allocate_exact_sum`, crypto-free integer arithmetic):

```
1. fixed_sum = Σ fixed[].amount            (mandated dev/donation/finder outputs)
   require fixed_sum ≤ budget              else FixedExceedsBudget
   require output_cap ≥ fixed.size() + 1   else CapTooSmall   (room for the sink)
   cap_owed = output_cap − fixed.size() − 1

2. sort owed by (first_eligible asc, identity_key asc)     # K_fair: oldest-owed-first
   remaining = budget − fixed_sum
   for e in sorted:
       if outputs_owed ≥ cap_owed: break            # cap -> rest CARRIES
       if remaining == 0: break                     # budget spent -> rest CARRIES
       if e.owed < h_min: continue                  # below floor -> CARRY (no output)
       amt = min(e.owed, remaining)
       if amt < h_min: break                        # tiny final partial -> sink absorbs
       emit Owed(e.pay, amt); remaining -= amt

3. emit each fixed output (declared order)

4. residual = remaining                              # budget − fixed_sum − Σ owed paid
   if residual > 0: emit Sink(residual_sink, residual)
```

**Canonical output order (consensus):** `[ K_fair owed ]  ++  [ fixed ]  ++  [ sink? ]`. Owed outputs sit at stable low vout indices; admin outputs trail. The sink is present iff `residual > 0`.

**Invariant (CONS-1 for the XMR lane):** on success `Σ outputs.amount == budget`, `outputs.size() ≥ 1`, `outputs.size() ≤ output_cap`, and every amount `> 0`. Enforced by the coin — there is no burn escape hatch.

The **single residual sink** absorbs *both* surplus cases with one mechanism:
- **budget > Σ eligible owed** (bootstrap / low activity): every eligible owed paid in full; the sink takes the surplus.
- **budget < Σ eligible owed** (steady state; XMR at 0.6 XMR/block ⇒ usual case): oldest-owed-first until budget is exhausted; the last selected entry takes a **partial** (`min(owed, remaining)`) and carries its unpaid remainder; `residual == 0`, **no sink output**.
- Any owed→piconero conversion truncation (if the ledger ever denominates finer than piconero) also lands in the sink — the p2pool `split_reward` "last entry absorbs rounding" spirit, generalized.

**The sink is a lane consensus parameter** (`residual_sink`, an XMR descriptor, torsion-checked). Candidates and the open call are OQ-X8: a protocol donation/dev key, a finder, or a rule like "next-oldest carried entry." Mandated dev/donation/finder outputs are modelled as `fixed[]` — each costs one real output and is deducted from the budget before the owed pass.

Worked example (0.6 XMR tail, `budget = 600_000_000_000` pn, two owed 0.2 + 0.15 XMR, no fixed): owed outputs 200e9 and 150e9, `residual = 250e9` → sink 250e9; `Σ = 600e9`. ✓ (exercised by the driver's `build_coinbase` test.)

---

## 3. Per-output derivation (PRE-CARROT — behind the fence, §6)

For output at canonical vout index `i`, payout target `pay` (`XMR_STD`: `B‖A`; `XMR_SUB`: sub-spend `D_i ‖ A_main`), with `spend = payload[0..32)`, `view = payload[32..64)`:

```
D          = 8 · r · A                       generate_key_derivation(A, r)
P_i        = H_s(D || varint(i)) · G + B     derive_public_key(D, i, B)
view_tag_i = H("view_tag" || D || i)[0]      derive_view_tag(D, i)
output_i   = txout_to_tagged_key{ key = P_i, view_tag_i }, amount = varint (plaintext)
```

Standard CryptoNote stealth recipe (p2pool `Wallet::get_eph_public_key`), one ed25519 variable-base mult + a Keccak per payee. The **vout index `i` is the index in the final canonical list**, so keys are assigned after §2 fixes the order.

---

## 4. Weight-aware output cap `C`

A Monero coinbase output costs block weight; above the 100-block median the block's reward is cut quadratically, so over-paying is self-limiting, not forbidden. `weight_aware_output_cap(median, reserved, wire_cap)`:

```
zone     = max(median_block_weight, 300000)          # long-term-median floor (pin exact CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 in X6)
avail    = zone − reserved_nonminer_weight − 128      # 128 = coinbase fixed overhead (ver+unlock+txin_gen+tx_extra)
C        = min(avail / 42, wire_cap)                  # 42 = size(XMR output)
C        = max(C, 1)                                  # always room for the sink
```

The **penalty-free** term alone allows ~7000 outputs at the 300000-B floor; the binding term is the **wire cap** (per-carrier receipt/message ceiling, `R_MAX`-derived), landing `C ≈ 2000–2700` on mainnet (scoping §2.3). Both are lane parameters; this helper is the derivation of record.

---

## 5. Commitment placement — 0x03 MM-tree leaf (resolves OQ-X4 for Family B)

`tx_extra` layout the builder emits (`assemble_tx_extra`):

```
0x01  pubkey        R = r·G                                   (33 B)
0x02  extra-nonce   per-worker, padded (p2pool style)         (2 + n B; omitted if empty)
0x03  merge-mining  varint(field_len) || varint(depth=0) || merkle_root[32]   (~36 B)
```

The v37 owed commitment rides as the **0x03 merge-mining root**, not the 0x02 nonce (recommended by scoping OQ-X4: forward-compatible with real merge mining — the same tree that would host Tari/aux chains). Single v37 leaf:

```
mm_root = keccak256("c2pool-v37-xmr-mm-leaf-v1" || u32_le(chain_id) || lane_commitment)   ; depth = 0, root == leaf
```

`chain_id` scoping prevents a raw-commitment collision with another aux chain's slot. For a **multi-aux** tree (hosting Tari etc.) this hash is one leaf under a real Merkle root with `depth > 0` and a branch — that generalization (leaf slotting, the p2pool `merge_mining_*` endpoints) is the **template/aux leg's** concern, deliberately not wired here. `MAX_TX_EXTRA_SIZE = 1060` is txpool/relay-only (PR #8733) and does **not** bind a coinbase.

---

## 6. FCMP++ / CARROT fence (OQ-X10) — the load-bearing guard

The entire coinbase-**output** derivation (`R=r·G`, `D=8rA`, `P_i`, view tag, `txout_to_tagged_key`) is the **pre-CARROT** Monero recipe. FCMP++/CARROT is expected to rewrite address/key derivation; whether it changes *coinbase* derivation is **[?]** and must not be guessed.

- Every output-producing entry point (`build_coinbase`, `derive_tx_secret_key`, `derive_output`) is guarded on `xmr_precarrot_ok(monero_major_version)` = `major_version ≤ 16`.
- A block whose `major_version` exceeds the pin returns `ok=false, error=CarrotFence` — it **never silently builds a possibly-wrong coinbase** (driver verifies v16 builds, v17 refused).
- The pin is shared with the descriptor-kinds leg (`v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION`). `monero/master` hardforks.cpp tops at v16 as of 2026-09-05.
- **When Monero pins CARROT in a release:** add a *new* derivation path keyed on the new `major_version`; do not edit the pre-CARROT path in place.

---

## 7. ACCEPT re-derivation (W3) — "pays out to a wrong wallet at index i"

`canonical_coinbase_matches(inputs, received)` rebuilds the canonical coinbase and byte-compares it against a peer's, returning the first divergence: `IDX_R` (tx pubkey), `IDX_COUNT`, a `0..n-1` vout index (amount / one-time key / view tag — the key case is p2pool's *"pays out to a wrong wallet at index i"*), or `IDX_EXTRA` (commitment/nonce). This is p2pool's `SideChain::verify` discipline applied to the OWED list, and the W3 ACCEPT check. Cost ≈ 1 ed25519 var-base mult + Keccak per payee (~tens of ms at ~1000 payees; cacheable by structure as p2pool does), **budgeted next to the RandomX hash** in the inverted `keyed_heavy` admission order (scoping §1.4.2).

---

## 8. Cross-leg interface dependency

`xmr::coin::secret_key_to_public_key(r, R)` (= `r·G`) is **required by W5 but not yet in `xmr_derivation.hpp`**. It is a one-liner over the ref10 the primitives leg already vendors (`ge_scalarmult_base` + `ge_p3_tobytes`, both used inside `xmr_derivation.cpp::derive_public_key`). W5 forward-declares it in namespace `xmr::coin`; the **primitives leg should add the definition**. Everything else W5 needs is already on the sibling surfaces (`generate_key_derivation`, `derive_public_key`, `derive_view_tag`, `hash_to_scalar`, `BlobWriter`, `write_coinbase_prefix_head`, `tx_prefix_hash`, `coinbase_tx_hash`, `KeccakMidstate`).

---

## 9. Open questions carried

- **OQ-X8** (this leg proposes): single mandated residual sink + `fixed[]` for dev/donation/finder; the *identity* of the sink (donation key vs finder vs next-oldest-carried) is a lane-policy ruling for the operator/integrator.
- **OQ-X4** (this leg recommends): 0x03 MM-tree leaf, single-leaf now, multi-aux later — confirm at the wire freeze.
- **OQ-X10**: CARROT effect on coinbase derivation — fenced; do not build the post-CARROT path until a Monero release pins it.
- **OQ-X9** (`h_min`): `h_min` here is a piconero threshold with `dust = 0`; whether `k_live(XMR)` := consensus base fee/byte or an EMA is a W4/W5 policy choice — the sink makes W5 correct either way.
- **OQ-X7** (`XMR_SUB` width): 64-B `D_i‖A_main` assumed (p2pool single-`R` subaddress path); if the printable subaddress must be reproducible, 96 B — descriptor-kinds leg owns this.
- **KAT owed** (X8): a Python peer re-deriving `r`, the per-output `P_i`/view-tag for a known seed, and the exact-sum split on piconero amounts, cross-checked against p2pool vectors + a stagenet `submit_block`. Not in this leg (needs the vendored crypto + a daemon).
