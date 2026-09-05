# X0 leg — upstream provenance & licensing

This leg is a **feasibility proof** (a Python harness + a C++ measurement probe),
not vendored lane source. It nonetheless *ports algorithms* from BSD-3 upstreams;
this file records exactly what, from where, and under what licence, per the
c2pool porting rules (AGPL-3.0 host; preserve upstream copyright + add a
provenance line naming source/commit/what-was-adapted).

## 1. `x0_harness.py` — algorithms ported/adapted from monero-project/monero

- **Upstream:** github.com/monero-project/monero, `src/crypto/keccak.c`,
  `src/crypto/tree-hash.c` (and `hash-ops.h` decls). Files fetched from `master`
  on 2026-09-05. These are consensus-frozen: the Keccak-256 parameters and the
  CryptoNote `tree_hash` algorithm have not changed since CryptoNote and are
  fixed by Monero consensus.
- **Licence:** BSD-3-Clause, "Copyright (c) 2014-2024, The Monero Project"
  (parts originally (c) 2012-2013 The Cryptonote developers). BSD-3 is
  compatible with the AGPL-3.0 c2pool host.
- **What was adapted (re-implemented in Python, behaviour-identical):**
  - Keccak-f[1600] permutation + `keccakf_rndc` round constants (from `keccak.c`).
  - Monero `cn_fast_hash` = Keccak-256: rate 136 B, capacity 512, **original
    Keccak padding** (`temp[rest] ^= 0x01; temp[135] ^= 0x80`) — NOT SHA3's 0x06.
    The incremental `keccak_init/update/finish` form is mirrored so the sponge
    state can be frozen as a portable **midstate** (this is the whole point of
    the coinbase-opening; no stock hashlib exposes the raw 1600-bit state).
  - `tree_hash`, `tree_hash_cnt` (= `1 << floor(log2(count))`), `tree_branch`,
    `tree_branch_hash` — ported line-for-line from `tree-hash.c` (path is
    MSB-first; bit=1 ⇒ sibling is the left input).
- **Self-check:** Keccak-256("") == `c5d24601…85a470` (the Ethereum/Monero value);
  and every derived quantity is checked against ground truth returned by a public
  `monerod get_block` (block_id, miner_tx_hash). 8/8 GREEN on two real blocks.

The miner_tx (coinbase) hash rule for a v2 / `RCTTypeNull` transaction —
`H = cn_fast_hash( H(prefix) ‖ cn_fast_hash(0x00) ‖ null_hash )` — is Monero's
`cryptonote_format_utils.cpp::calculate_transaction_hash` behaviour for the
coinbase (base rct blob for `RCTTypeNull` is the single type byte `0x00`;
prunable is empty ⇒ `null_hash`). Verified: the recomputed hash matches the
daemon's `miner_tx_hash` for both blocks.

## 2. `rx_probe.cpp` — links tevador/RandomX

- **Upstream:** github.com/tevador/RandomX @ `7c761cf` ("Fix: incorrect read
  dataset size was added (#340)"), shallow clone. BSD-3-Clause, (c) 2018-2024
  tevador et al.
- **Usage:** public C API only (`randomx.h`): `randomx_get_flags`,
  `randomx_alloc_cache`, `randomx_init_cache`, `randomx_create_vm`,
  `randomx_calculate_hash`. **Light mode**: cache-only, `RANDOMX_FLAG_FULL_MEM`
  deliberately NOT set → the 2 GiB dataset is never allocated.
- **Algorithm pinned to RandomX v1** (Monero mainnet's PoW). The vendored repo
  HEAD also carries an opt-in `RANDOMX_FLAG_V2` (a *different* hash, not adopted
  by Monero) — it is NOT set here; the official v1 KAT confirms v1.
- **Build to reproduce** (light, single lib, no dataset):
  `cmake -DCMAKE_BUILD_TYPE=Release -DARCH=native .. && make -j3 randomx`
  then `g++ -std=c++20 -O2 rx_probe.cpp -I<rx>/src -L<build> -lrandomx -pthread`.
- The build tree and probe binary were **removed** after measurement (host is
  OOM/disk-pressured); `randomx-light-measurement.txt` is the captured run.

## 3. p2pool (SChernykh/p2pool) — reference only, NOT ported here

p2pool is **GPL-3**. Although AGPLv3 §13 permits combining GPLv3 code, this leg
ports **no** p2pool source. p2pool is used only as an *existence proof*
(deterministic-`r` multi-output coinbase; every node re-derives outputs) and as a
data source: block 3,755,989 is a real p2pool-found block (via p2pool.observer),
used to exercise a many-output coinbase (47 outputs) — its `tx_extra` carries the
p2pool `0x03` merge-mining tag (depth 8, root `25926afad016…`), the commitment
placement the scoping note recommends for the v37 lane.

## Reference data (not code, no licence)

- `block_3000000.raw.json`, `block_3755989.raw.json`, `seed_block_2998272.json`
  are `get_block` / `get_block_header_by_height` responses from the public daemon
  `node.monerodevs.org:18089` (Monero mainnet). They are the ground truth the
  proof checks against.
