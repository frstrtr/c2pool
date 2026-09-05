# XMR lane — whole-block template builder (v37 Family B, item 10)

Foundation slice of the Monero/RandomX settlement lane for the v37 Work-Receipts
substrate (frstrtr/c2pool, AGPL-3.0). Design of record:
`v37-monero-randomx-lane-scoping.md` §1.4/6, §2.1–2.4, §4 item 10.

This leg ports the **Monero whole-block-template plumbing** from p2pool's
`block_template.cpp` and adapts it to v37, with p2pool's **pool model (sidechain,
PPLNS, uncles) removed** and replaced by the v37 settlement seam. It is the
"the pool assembles the ENTIRE block itself" component — monerod's single-output
`get_block_template` coinbase is not usable as-is (scoping §2.2).

## Files

| File | License | Role |
|---|---|---|
| `xmr_block_template.hpp` | GPL-3 (p2pool header verbatim + provenance) | Class + v37 seam interfaces `IXmrSettlementSource`, `XmrMinerData`, `XmrTxMempoolData`, `XmrPayee`; Monero consensus constants |
| `xmr_block_template.cpp` | GPL-3 (p2pool header verbatim + provenance) | Adapted bodies: reward/penalty math, greedy + reference-DP tx selection, `create_miner_tx`, `calc_miner_tx_hash`, `calc_merkle_tree_main_branch`, hashing-blob assembly, per-worker jobs |
| `xmr_coin_primitives.hpp` | AGPL-3 (fresh, attribution-clean) | Consumer-side declaration of the primitives this leg needs from the monero-primitives leg (varint, Keccak+midstate, 128-bit mul/div, `parallel_run`) |

Intended tree home: `src/impl/xmr/` (a NEW tree; ~0% reuse below the sharechain
seam, ~100% above — scoping §3/§4.B). Does **not** touch `src/sharechain/v37`.

## Provenance (per LIC rules)

- Upstream: **SChernykh/p2pool** `src/block_template.{h,cpp}`, `src/common.h`,
  `src/pool_block.h`.
- Commit: **`128643114f9bea55bfdb95462eaeffa2e3f666bd`** (master, fetched 2026-09-05;
  Copyright (c) 2021-2026 SChernykh).
- License: p2pool is **GPL-3.0**. c2pool is **AGPL-3.0**; AGPLv3 §13 permits
  combining GPLv3 code. The two adapted files keep p2pool's GPL-3 header verbatim
  and carry a `PROVENANCE` block naming the source, commit, and what was adapted.
- The fresh façade is AGPL-3 and attribution-clean (no AI/authorship lines), per
  the repo attribution gate.

## The three ported patterns (as requested)

### 1. Penalty-aware knapsack — `max_weight = median + median/8 − miner_tx_weight`

- **Production path** (`update()`, penalty branch): p2pool's greedy fee-per-byte
  pick with 100-deep replacement, maximising `get_block_reward()` at each step.
  The quadratic penalty is `reward = base·(2·median − w)·w / median²` for
  `median < w ≤ 2·median`, zero above `2·median` (`get_block_reward`, verbatim
  128-bit `umul128`/`udiv128`). Below the median the coinbase takes every tx.
- **Reference path** (`fill_optimal_knapsack`, under `TEST_KNAPSACK_ALGORITHM=1`):
  the O(N·W) DP over `max_weight = data.median_weight + (data.median_weight / 8)
  − miner_tx_weight` — the exact expression requested. Kept only so a golden test
  can assert the greedy result is within a micronero of optimal; too slow/RAM-hungry
  for production, exactly as upstream documents.

### 2. Per-worker extra-nonce jobs — re-serialise coinbase → tx hash → tree root → 76-B blob

- Each worker gets a distinct `extra_nonce` ⇒ distinct coinbase bytes ⇒ distinct
  v2 tx hash (`calc_miner_tx_hash`) ⇒ distinct tree root (fold up the fixed main
  branch, `get_hashing_blob_nolock`) ⇒ distinct 76–80 B RandomX blob
  (`header || tree_root(32) || varint(n_tx+1)`, `HASHING_BLOB_MIN_SIZE = 76`).
- `get_hashing_blob(extra_nonce, …)` = one job; `get_hashing_blobs(start, count, …)`
  = a back-to-back batch, `parallel_run`-filled. Both report `nonce_offset` (the
  4-byte header nonce the worker mutates) and `template_id`.
- **O(1) per extra_nonce:** the Keccak midstate of the miner-tx prefix up to the
  `tx_extra` boundary is cached in `update()` (`keccak_step` into
  `m_minerTxKeccakState`); `calc_miner_tx_hash` resumes from it and only re-absorbs
  the tail bytes that carry the extra nonce + MM root (`keccak_finish`). Slow O(N)
  fallback via `keccak_custom` when the prefix is shorter than one Keccak block.
- `get_block_template_blob(template_id, extra_nonce, …)` re-materialises the full
  block for monerod `submit_block`, patching the extra nonce and MM root and
  reporting the three submitter offsets. A small non-pool double-buffer
  (`m_oldTemplates`) keeps in-flight job ids resolving across an `update()`.

### 3. miner_tx assembly — `txin_gen`, `txout_to_tagged_key`, `tx_extra` 0x01/0x02/0x03

`create_miner_tx` builds the exact CryptoNote byte layout (verified constants):

```
version = 2
unlock_time = height + 60                 (MINER_REWARD_UNLOCK_TIME; D_conf floor 60)
vin_count = 1
  TXIN_GEN (0xFF) | height                (txin_gen, height == block height)
vout_count = N
  [ amount varint | TXOUT_TO_TAGGED_KEY (3) | eph_pubkey(32) | view_tag(1) ] × N
tx_extra:
  0x01 (TX_EXTRA_TAG_PUBKEY)      | R(32)                  R = r·G
  0x02 (TX_EXTRA_NONCE)          | len | extra_nonce[len]  padded 4→≤14 B
  0x03 (TX_EXTRA_MERGE_MINING_TAG)| len | mm_data varint | root(32)
rct_type = 0                              (RCTTypeNull; not in the prefix hash)
```

- Two-pass sizing (`dry_run`): pass 1 sizes the amount varints with zeroed keys;
  the extra-nonce is padded by `max_reward_amounts_weight − reward_amounts_weight`
  so the **miner-tx weight is invariant** to how many bytes the amounts took. If
  padding would exceed `EXTRA_NONCE_MAX_SIZE` the builder returns `-3` and
  `update()` re-solves the reward on a smaller weight (upstream readjust loop).
- The v2 tx hash is `Keccak(H(prefix) || H(rct_base) || H(prunable))` with
  `H(prunable) = 0` and `H(rct_base)` the fixed `known_second_hash` constant for a
  null-RCT coinbase.
- **Exact-sum (HF13):** the coinbase must pay exactly `base_reward + fees`.
  `IXmrSettlementSource::split_reward` owns the K_fair proportional split +
  residual sink; the builder only lays out `m_rewards[i]`.

## What changed vs p2pool (pool model excised)

| p2pool | v37 | why |
|---|---|---|
| `SideChain* m_sidechain` (shares, PPLNS window, split, consensus id, merkle proof) | `IXmrSettlementSource* m_settle` | v37 has its own RDWR/work-receipts/owed-ledger model — the whole point |
| `MinerShare` + `Wallet::get_eph_public_key` | `XmrPayee` + `IXmrSettlementSource::derive_output_key` | payee is a resolved `(B,A)`, torsion pre-checked by X3; no address strings |
| `calc_sidechain_hash` → sidechain id → aux slot → `get_root_from_proof` | `IXmrSettlementSource::commitment_leaf(extra_nonce)`; single MM-tree leaf ⇒ root == leaf | v37 commitment (owed_digest/info_digest) rides the 0x03 tag directly (scoping §2.3, "MM-tree leaf recommended") |
| deterministic `r` from `keccak("tx_key_seed" ‖ mainchain(nonce/extra zeroed) ‖ sidechain data)` | `IXmrSettlementSource::tx_secret_key()/tx_public_key()` = `H(domain ‖ lane_commitment ‖ prev_id ‖ height ‖ …)` | same "every node re-derives r and checks bytes" discipline, keyed by v37 lane state |
| `m_difficulty` (mainchain) drives the job | `m_laneTarget` = v37 `T_origin` for the XMR lane | Monero header has no target field; `T_origin` lives in committed side data (scoping §1.4 item 6) |
| p2pool `merge_mining_*` aux slot machinery, subaddress/onion/i2p MM extras | **not ported** | Tari-style aux coexistence is an optional later retention feature (scoping §4 item 17); the 0x03 tag is left structurally present so it can be widened without touching the builder |
| `submit_sidechain_block`, sidechain hash blob/midstate, `init_merge_mining_merkle_proof` | **not ported** | pool model |

Behaviour kept byte-identical: reward/penalty math, greedy + DP selection, the
miner-tx byte layout, the v2 tx-hash triple, the Keccak-midstate opening, and the
tree_hash main branch. The scoping note's X0 KAT plan (reproduce hashing-blob /
block-id / tx-hash on real mainnet blocks; Keccak-midstate coinbase-opening KAT)
is the acceptance test for this leg.

## Seam contract for adjacent legs

- **monero-primitives (X1):** must supply the bodies declared in
  `xmr_coin_primitives.hpp` — `writeVarint` (LEB128), `keccak`/`keccak_step`/
  `keccak_finish`/`keccak_custom` (Monero keccak.c, rate 136), `umul128`/`udiv128`,
  `parallel_run`, `seconds_since_epoch`, and the `hash`/`difficulty_type` types.
  When trees join, delete the façade and include the real headers.
- **monerod-adapter (X2):** must fill `XmrMinerData` (from `get_miner_data`:
  major_version, height, prev_id, already_generated_coins, median_weight,
  median_timestamp, seed_hash) and the `XmrTxMempoolData` backlog, and carry the
  lane `T_origin` into `XmrMinerData::lane_target`.
- **W5-XMR / descriptor-kinds (X6/X3):** must implement `IXmrSettlementSource`
  (payee list in K_fair order with torsion-checked `(B,A)`; deterministic `r`;
  `derive_output_key`; exact-sum `split_reward` with the residual-sink rule;
  `commitment_leaf`; `merkle_tree_data`). This leg is agnostic to how those are
  computed, only that they are pure functions of committed lane state.

## Open questions (for the integrator / adjacent legs)

- **OQ-TB1 (commitment placement).** Confirmed as the 0x03 MM-tree leaf (root ==
  leaf for a 1-leaf tree). If the wire-freeze instead puts the v37 commitment in
  the 0x02 nonce (scoping OQ-X4), `create_miner_tx` and the `merkle_root_offset`
  math change slightly; the per-worker job flow does not.
- **OQ-TB2 (`merkle_tree_data` encoding).** The foundation treats it as an opaque
  varint from the seam (encodes n_chains=1). If/when Tari aux coexistence is
  admitted (item 17), the aux-slot/`get_root_from_proof` machinery returns and
  `commitment_leaf` becomes one leaf among several — additive, not a rewrite.
- **OQ-TB3 (extra-nonce width).** Kept p2pool's `EXTRA_NONCE_SIZE=4`,
  `EXTRA_NONCE_MAX_SIZE=14`. If the XMR lane wants a wider per-worker search space
  or a v37-specific nonce field, this is a lane parameter, not a consensus change.
- **OQ-TB4 (dedup guard).** The duplicate-tx-hash guard is kept as a fail-safe;
  the mempool adapter should already dedup (upstream logs and continues; here we
  skip the dup). Confirm which layer owns it.
- **OQ-TB5 (CARROT fence).** `derive_output_key` takes `hf_major` so the pre-CARROT
  derivation is pinned per Monero hard fork. If FCMP++/CARROT changes coinbase
  output-key derivation (scoping §6 risk (b), OQ-X10), only the seam impl changes.

## Manifest

```json
{
  "leg": "template-builder",
  "files": [
    "src/impl/xmr/template/xmr_block_template.hpp",
    "src/impl/xmr/template/xmr_block_template.cpp",
    "src/impl/xmr/template/xmr_coin_primitives.hpp",
    "docs/xmr-lane/x-template-builder.md"
  ],
  "ported_from": [
    {
      "upstream": "SChernykh/p2pool @ 128643114f9bea55bfdb95462eaeffa2e3f666bd (master, 2026-09-05)",
      "license": "GPL-3.0 (combined into c2pool AGPL-3.0 via AGPLv3 s13)",
      "files": ["src/block_template.h", "src/block_template.cpp", "src/common.h", "src/pool_block.h"]
    }
  ],
  "checks": "g++ -std=c++20 -fsyntax-only -Wall -Wextra clean (default; and with -DTEST_KNAPSACK_ALGORITHM=1 -DXMR_TEMPLATE_UNIT_TESTS)",
  "sidechain_ported": false
}
```
