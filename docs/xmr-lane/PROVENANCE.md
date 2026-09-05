# PROVENANCE — XMR lane (Family B) license & porting plan

**Scope.** The authoritative license/provenance plan for `src/impl/xmr/` — the
new Monero/RandomX settlement lane ("Family B") of c2pool (frstrtr/c2pool,
**AGPL-3.0**). It states, per upstream: the license, the exact files/symbols
c2pool will port, the header we preserve, the provenance line we add, the NOTICE
entry, and the AGPLv3-§13 combined-work compliance steps. It also states, for
p2pool, exactly what we will **NOT** take.

**Status.** Foundation/plan. Design of record: `v37-monero-randomx-lane-scoping.md`
(GO as a fenced Phase-2 design track; all Track-X *code* DEFERRED). This file is
the licensing gate that any later vendoring/porting PR must satisfy. Nothing here
is a git action; deliverables live under this manifest directory.

**Pins (read 2026-09-05).** Re-pin to the exact checked-out commit at vendor time
(prefer the release tag).

| Upstream | License | Pin (tag) | Commit (as read) |
|---|---|---|---|
| tevador/RandomX | BSD-3-Clause | v1.2.3 | `7c761cf007c758056dcb6eb438a32f780f81bdbd` |
| monero-project/monero | BSD-3-Clause | v0.18.5.1 | `3d3920d7487b5df7ac388b6b8577fd04d505885f` |
| SChernykh/p2pool | GPL-3.0-only | v4.18 | `128643114f9bea55bfdb95462eaeffa2e3f666bd` |

**Companion files in this manifest** (all attribution-clean, ship-ready):
`LICENSING.md` (the AGPLv3 §13 rationale), `NOTICE` (aggregated attribution for
the repo root / `third_party/`), `xmr_provenance.hpp` (machine-readable table +
compile-time provenance gate — compiles clean under `g++ -std=c++20`, three
`static_assert`s hold), `header-templates/{bsd-ported,gpl-ported,agpl-fresh}-header.txt`,
`upstream-licenses/{RandomX,Monero,p2pool}.LICENSE` (full upstream texts).

---

## 0. The three porting rules (apply to every file)

1. **Preserve the upstream copyright + license header verbatim** on any
   ported/adapted file. Never strip, reword, or relicense it. Prepend our
   `c2pool provenance` comment *above* it (never inside it).
2. **The provenance line names**: upstream repo, upstream file path, pinned
   tag + full 40-char commit, and *exactly* what was vendored/adapted.
3. **Fresh c2pool files are AGPL-3.0 and MUST be attribution-clean**: no
   `Co-Authored-By`, no `Claude`, no AI/assistant/session lines anywhere — the
   repo attribution-gate rejects them. A file mixing fresh code with an
   upstream-derived function is *not* fresh: keep the upstream header.

The header blocks to paste are in `header-templates/`. The per-file plan is the
14-row table in `xmr_provenance.hpp`; the prose below explains each upstream.

---

## 1. tevador/RandomX — BSD-3-Clause (permissive)

**License.** 3-clause BSD. Repo `LICENSE` is dual-attributed:

```
Copyright (c) 2018-2019, tevador <tevador@gmail.com>
Copyright (c) 2014-2019, The Monero Project
All rights reserved.
```

Per-file headers (e.g. `src/randomx.h`) carry the tevador line + the full 3-clause
body and disclaimer. BSD-3 permits combination into an AGPL work with no copyleft
reach-through; the only obligation is **retain the notice + disclaimer** (source
clause 1) and reproduce it in binary distributions (clause 2).

**What we port.** The RandomX library, **vendored as an unmodified subtree** at
`vendor/randomx/` (do not hand-edit; carry upstream headers as-is). We consume
only the C API needed for **light-mode verification**:

- `randomx_alloc_cache(flags)`, `randomx_init_cache(cache, key, keySize)` — the
  256 MiB Argon2d cache keyed by the Monero block hash at `seed_height(h)`.
- `randomx_create_vm(flags, cache, dataset)`, `randomx_vm_set_cache`,
  `randomx_destroy_vm`.
- `randomx_calculate_hash(vm, input, inputSize, output)` — one hash per receipt.
- Flags: `RANDOMX_FLAG_DEFAULT | JIT | LARGE_PAGES` (NO `RANDOMX_FLAG_FULL_MEM`
  by default → cache-only, no 2 GiB dataset). Constants `RANDOMX_HASH_SIZE=32`,
  `RANDOMX_ARGON_MEMORY`.
- Two-cache epoch handling (current + next, 64-block seed lag) is c2pool code in
  `src/impl/xmr/pow/` that *calls* this API; the library itself is untouched.

**Compliance steps.**
- Keep every `vendor/randomx/**` file's header verbatim; add a top-of-subtree
  `vendor/randomx/README.c2pool` provenance note (tag+commit+"vendored verbatim").
- NOTICE §1 (done, see `NOTICE`).
- Ship `third_party/licenses/RandomX.LICENSE` (staged: `upstream-licenses/RandomX.LICENSE`).
- No source changes → no relicensing question. If a build patch is ever needed,
  it goes in a *separate* c2pool file or a tracked `.patch`, not by editing the
  vendored source.

---

## 2. monero-project/monero — BSD-3-Clause (permissive)

**License.** 3-clause BSD, `Copyright (c) 2014-2024, The Monero Project`, with a
trailing `Parts of this file are originally copyright (c) 2012-2013 The Cryptonote
developers` line on many crypto files (**retain that line too**). epee carries a
distinct BSD-3 notice: `Copyright (c) 2006-2013, Andrey N. Sabelnikov`. Same
obligation as RandomX: retain notice + disclaimer; no copyleft reach-through.

**What we port** (vendored under `vendor/monero-crypto/` and `vendor/monero-epee/`,
verbatim except the epee varint extraction which is a small adaptation):

| Area | Upstream file | Symbols we use |
|---|---|---|
| **crypto-ops** (ed25519) | `src/crypto/crypto-ops.c` (+ `.h`) | `ge_scalarmult_base`, `ge_scalarmult`, `ge_p3_tobytes`, `ge_frombytes_vartime`, `sc_reduce32`, `sc_add` — back `derivation_to_scalar` / `derive_public_key` / one-time output-key + view-tag derivation (`get_eph_public_key`) and the **torsion / prime-order-subgroup check** the descriptor `valid()` needs |
| **keccak** | `src/crypto/keccak.c` (+ `.h`) | `keccak(in,inlen,md,mdlen)`, `keccak_init/update/finish` — Keccak-256 for `cn_fast_hash`, tx-prefix hash, and the coinbase-opening midstate. **Special provenance:** these two files are the *Saarinen baseline Keccak* (`// 19-Nov-11 Markku-Juhani O. Saarinen <mjos@iki.fi>`); they carry an author line rather than an embedded BSD body. Ship them under the Monero-project BSD-3 umbrella **and keep the Saarinen author line**. (Saarinen's original is public-domain-class; both dispositions are AGPL-compatible — LICENSING.md §BSD.) |
| **tree-hash** | `src/crypto/tree-hash.c` | `tree_hash`, `tree_branch`, `tree_hash_from_branch` — miner_tx is leaf 0; O(log n) inclusion proof in the receipt |
| hash decls | `src/crypto/hash-ops.h` | `cn_fast_hash` decl |
| **serialization** | `contrib/epee` (`storages/portable_storage*`, `int-util.h` varint) | CryptoNote varint read/write + blob (de)serialization for the 76–77 B hashing blob and the miner_tx prefix |

**Adaptation note.** `crypto-ops.c`, `keccak.c`, `tree-hash.c`, `hash-ops.h` are
vendored **verbatim**. The epee varint/blob layer is **adapted** (we extract just
the varint + portable-storage pieces we need into `vendor/monero-epee/`, dropping
Boost-heavy transitive includes) → keep the Sabelnikov BSD-3 header + provenance
line marking it "adapted: extracted varint/blob, removed unused epee deps".

**Keccak midstate — do NOT edit the vendored file.** The coinbase-opening KAT
needs a *midstate export* at the `tx_extra` sponge boundary. That shim is a
**separate fresh AGPL file** `src/impl/xmr/coinbase/keccak_midstate.c` that calls
into the unmodified vendored `keccak.c`, so the vendored source stays byte-identical
to upstream (verifiable by hash against the pin).

**Compliance steps.** Retain each header (incl. the Cryptonote and Saarinen lines);
NOTICE §2; ship `third_party/licenses/Monero.LICENSE`
(staged: `upstream-licenses/Monero.LICENSE`).

---

## 3. SChernykh/p2pool — GPL-3.0-only (copyleft)

**License.** GNU GPL **version 3** (the per-file header says "…as published by the
Free Software Foundation, **version 3**", i.e. GPL-3.0-**only**, not "or later").
Header verbatim:

```
This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
… GNU General Public License … version 3. …
```

**Legality of the port.** c2pool is AGPL-3.0. **AGPLv3 §13** grants explicit
permission to "link or combine any covered work with a work licensed under
version 3 of the GNU General Public License into a single combined work, and to
convey the resulting work"; **GPLv3 §13** is the mirror grant. So p2pool (GPLv3)
code is legally portable into c2pool. Consequences, enforced on every ported file:
the ported portion **stays GPL-3.0-only**, the combined work is **conveyed as
AGPL-3.0**, and the AGPL §13 network-source-offer obligation attaches to the
combination. Full argument in `LICENSING.md`.

**What we port — MONERO-PLUMBING ONLY** (adapted; header preserved; `src/impl/xmr/`):

| c2pool file | Upstream | Plumbing taken (real symbols) |
|---|---|---|
| `pow/randomx_hasher.cpp` | `src/pow_hash.cpp` | RandomX **integration pattern**: two-cache epoch handling (`m_cache[2]`, 64-block seed lag), light/dataset select, seed rotation, forced-light re-hash to flag unstable hardware |
| `coinbase/det_tx_key.cpp` | `src/block_template.cpp` (+ `src/crypto.cpp` wrappers) | **Deterministic tx secret key**: `seed = keccak("tx_key_seed" ‖ mainchain-data(nonce/extra-nonce zeroed) ‖ side-data)`, `r = generate_keys_deterministic(...)`, `R = r·G` into `tx_extra` 0x01; per-node re-derivation + byte-compare of every output (`get_eph_public_key`, view tag) |
| `coinbase/template_build.cpp` | `src/block_template.cpp` | **Whole-block template**: miner_tx assembly with `txout_to_tagged_key`, extra-nonce padding (4→14 B, weight-invariant), tree root → 76-B `get_block_hashing_blob`, `unlock_time = h + 60` |
| `rpc/monerod_adapter.cpp` | `src/p2pool.cpp`, `src/zmq_reader.cpp`, `src/json_rpc_request.cpp` | **monerod glue**: JSON-RPC `get_miner_data` / `submit_block` / `calc_pow` / `get_fee_estimate`; ZMQ subscribe `json-full-chain_main` / `json-full-miner_data` / `json-minimal-txpool_add` |
| `stratum/cryptonote_stratum.cpp` | `src/stratum_server.cpp` | **CryptoNote/XMRig stratum**: `login` / `job` / `submit`, 76-B blob job, nonce at offset 39, `seed_hash` / `next_seed_hash`, algo `rx/0`, per-worker extranonce inside `miner_tx.extra` |

Each of these is a **derivative work** → `header-templates/gpl-ported-header.txt`
(our provenance line + p2pool's verbatim GPLv3 header). Where a file is more
"pattern re-implementation" than line copy, it is still marked GPL-3.0-only and
attributed — conservative and correct.

**Prefer Monero-core over p2pool for BSD primitives.** p2pool bundles Monero and
RandomX (as submodules) and some p2pool files are themselves BSD-derived. Take the
BSD primitives (§1, §2) **from their original upstreams**, not via p2pool, so the
BSD/GPL boundary in our tree matches the actual authorship and no BSD file inherits
a GPL header by accident.

### 3.1 What we will NOT take from p2pool — the pool-model

Explicitly out of scope. Porting any of these would both (a) drag in copyleft we
don't need and (b) contradict the v37 model, which is the whole point of the lane:

- **Sidechain** — `src/side_chain.cpp`, `src/pool_block.{h,cpp}`: `SideChain`,
  `PoolBlock`, sidechain consensus IDs (main/mini/nano), `add_external_block`
  verify loop *as a sidechain*. v37 has its own spine (one `Lane` per `ChainId`)
  and its own receipt/carrier model.
- **PPLNS payout window** — `get_shares()`, `PPLNS_WINDOW = 2160`, the dynamic
  "window weight ≤ 2× mainchain difficulty" cap, one-`MinerShare`-per-wallet
  weighting. v37 uses its **OWED ledger with carry-forward** and **K_fair**.
- **Uncle mechanism** — `UNCLE_BLOCK_DEPTH = 3`, ≤ 5 uncles, 20 %/10 % uncle
  penalty. v37 has **RDWR 100 % stale recovery**, no uncles.
- **`split_reward()`** — p2pool's PPLNS proportional integer split. v37 authors
  its **own** exact-sum residual-sink split (`k_fair_xmr.cpp`, fresh AGPL). The
  exact-sum *technique* is generic; we do not lift p2pool's implementation.
- The p2pool **peer-to-peer sidechain protocol** and its share-broadcast wire.

(Optional, *later*: p2pool's `merge_mining_*` aux endpoints are a retention feature
so XMR-lane miners keep Tari-style aux revenue — a separate future decision, still
GPL-derived if taken, and still not the pool-model.)

---

## 4. How the whole distributable stays AGPL-3.0

1. **Repository license is AGPL-3.0** (root `COPYING`/`LICENSE`); the XMR lane
   adds no exception and no different top-level license.
2. **Fresh files → AGPL-3.0**, attribution-clean (`agpl-fresh-header.txt`). This
   is the whole Family-B receipt/settlement model, KATs, and glue that has no
   upstream ancestor (`xmr_provenance.hpp` rows with `upstream==nullptr`).
3. **BSD-3 components (RandomX, Monero-core, epee)** are permissive → combine
   freely; obligation is notice retention + disclaimer reproduction (headers +
   NOTICE + `third_party/licenses/`).
4. **GPL-3.0-only components (p2pool-derived)** are combined under **AGPLv3 §13 /
   GPLv3 §13**. Those files keep their GPLv3 header; the *combined work* is
   conveyed as AGPL-3.0; the AGPL §13 requirement to **offer Corresponding Source
   to network users** applies to the combination. c2pool already meets this as an
   AGPL project — the XMR lane inherits it, it is not a new obligation.
5. **Directory boundary.** BSD verbatim vendors live under `vendor/`; GPL-derived
   plumbing and fresh AGPL code live under `src/impl/xmr/`. The lane must **not**
   touch `src/sharechain/v37` consensus-digest code (design-of-record fence).
6. **CARROT/FCMP++ fence.** All coinbase-output-derivation code
   (`coinbase/det_tx_key.cpp`, `template_build.cpp`) is pinned **pre-CARROT**,
   guarded per Monero `major_version` behind a clearly-marked guard. This is a
   correctness fence, not a licensing one, but it lives beside the ported code so
   it is recorded here (OQ-X10).
7. **Provenance gate in CI.** `xmr_provenance.hpp` is the machine-readable source
   of truth: every vendored/ported file appears with a pinned 40-char commit;
   `static_assert`s enforce (a) ported rows are pinned and name a source, (b)
   p2pool-derived rows stay GPL-3.0-only (copyleft never silently upgraded to a
   more permissive license), (c) only {BSD-3, GPL-3.0-only, AGPL-3.0} appear. A CI
   step can additionally grep that no `vendor/**` byte drifted from its pin and no
   fresh file carries an upstream copyright line or an attribution/AI line.

---

## 5. Deliverables in this manifest

```
license-manifest/
  PROVENANCE.md                     <- this file (authoritative plan)
  LICENSING.md                      <- AGPLv3 §13 rationale
  NOTICE                            <- aggregated attribution (repo-root ready)
  xmr_provenance.hpp                <- machine-readable table + CI provenance gate
                                       (g++ -std=c++20 -fsyntax-only: clean;
                                        3 static_asserts hold; 14 rows)
  header-templates/
    bsd-ported-header.txt           <- for RandomX / Monero-core vendored files
    gpl-ported-header.txt           <- for p2pool-derived plumbing
    agpl-fresh-header.txt           <- for files we author (attribution-clean)
  upstream-licenses/
    RandomX.LICENSE                 <- BSD-3 (tevador + Monero)
    Monero.LICENSE                  <- BSD-3 (The Monero Project)
    p2pool.LICENSE                  <- full GPLv3 text
```

## 6. Open questions (route to integrator; OQ-X6 in the scoping note)

- **OQ-X6a.** Vendor RandomX + Monero-crypto as **git submodules** vs **checked-in
  subtree** under `vendor/`. Submodule = cleaner pin & upstream tracking; subtree =
  self-contained AGPL tarball with no fetch step (better for the source-offer
  obligation). Recommendation: **subtree** for the source-offer simplicity, pinned
  by the SHAs above, with a `.c2pool-pin` file per vendored tree.
- **OQ-X6b.** Confirm the intended repo-root license filename/text so the fresh
  header (`agpl-fresh-header.txt`, "The c2pool developers") matches the existing
  c2pool convention exactly. Placeholder copyright holder used pending confirmation.
- **OQ-X6c.** p2pool GPL-3.0-**only** (no "or later"): confirm c2pool's AGPL is
  AGPL-3.0**-or-later** vs -only. AGPLv3 §13 combination holds for AGPL-3.0
  regardless; recording it because it constrains any future AGPL version bump of
  the combined work (GPL-3.0-only parts cannot be carried into an AGPL-4 combination
  without SChernykh's relicensing).
- **OQ-X6d.** Whether to lift the p2pool `merge_mining_*` aux endpoints later
  (retention feature) — GPL-derived if taken; decide before X9.
