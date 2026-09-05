# RandomX vendoring manifest — v37 XMR lane (Family B), leg `randomx-vendor`

Foundation for the Monero/RandomX settlement lane. This leg vendors the
RandomX PoW verifier and provides c2pool's own **light-mode** verify wrapper.
It touches nothing in `src/sharechain/v37`; it is a new `src/impl/xmr/` unit.
**Light verify only** — the 256 MiB cache, never the ~2 GiB dataset.

Design of record: `v37-monero-randomx-lane-scoping.md`
(§1.1 PoW facts, §1.3 not-a-showstopper, §1.4 spec deltas, §1.5 receipt).

---

## 1. What this leg delivers

| File | License | Role |
|---|---|---|
| `third_party/randomx/randomx.h` | BSD-3 (verbatim) | RandomX C API, compile-time dep of the wrapper |
| `third_party/randomx/configuration.h` | BSD-3 (verbatim) | pinned consensus constants (Argon2 mem/iters/salt, program count) |
| `third_party/randomx/LICENSE` | BSD-3 (verbatim) | upstream license, preserved |
| `third_party/randomx/PROVENANCE.txt` | — | pin, checksums, verbatim-copy attestation |
| `randomx_verify.hpp` | AGPL-3 (c2pool, authored) | two-cache light verifier + Monero target-check |
| `randomx_verify_kat.cpp` | AGPL-3 (c2pool, authored) | KATs: official RandomX vectors + difficulty/seed-height |

The full RandomX **library sources are NOT copied** into the tree — they are
consumed as a git submodule pinned to the commit in §2 and built into one
static archive `librandomx.a`. Only the public headers are vendored (they are
the wrapper's compile-time surface).

---

## 2. Version pin

**Consensus pin (vendor this):** `tevador/RandomX @ 12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`
— the exact commit `monero-project/monero` pins at `external/randomx` on
`master` (read 2026-09-05). This is the RandomX that live Monero mainnet
(`rx/0`) consensus runs. Vendoring the *same* commit as monerod gives c2pool
bug-for-bug hash identity with the daemon whose blocks we verify against.
Verified property: this commit defines **no `RANDOMX_FLAG_V2`** (enum tops out
at `RANDOMX_FLAG_ARGON2`); it is pre-2.0.

**Acceptance gate (the pin is only valid if this passes):**
`randomx_verify_kat --engine` must reproduce the canonical rx/0 vector
`randomx("test key 000", "This is a test") == 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f`
(and the other four §8 v1 rows). This vector is invariant across every RandomX
1.x release and is what monerod produces — so it is the interop lock. If a
future re-pin ever changes an rx/0 output, this KAT fails loudly = consensus
divergence caught before shipping.

**Future-fork upgrade target (do NOT enable now):**
`tevador/RandomX @ 7c761cf007c758056dcb6eb438a32f780f81bdbd` (post-2.0 HEAD)
adds `RANDOMX_FLAG_V2` and `RANDOMX_PROGRAM_SIZE_V2 = 384`. Reserved for a
Monero hard-fork that adopts RandomX 2.0 (tracked as `PowAlgo::RX_2`; cf.
monero issue #8827). The wrapper `#ifdef`-guards every `RANDOMX_FLAG_V2` use,
so it compiles unchanged against either pin — the switch is one guarded flag,
not a re-vendor.

**Submodule wiring (integration, not this leg's job):**
```
[submodule "src/impl/xmr/third_party/randomx"]
    path = src/impl/xmr/third_party/randomx
    url  = https://github.com/tevador/RandomX
    # pinned at 12f2c2ffe2108d6cf54c391fee33c8bc3646cdab
```
CMake: `add_subdirectory(third_party/randomx)` builds `randomx` static lib;
the wrapper's include dir is `third_party/randomx/src` (or the vendored headers
here, which are byte-identical to that commit's `src/randomx.h`/`configuration.h`).

---

## 3. Build flags (JIT + large pages)

Flags are chosen for **light verify** and are all in `randomx_verify.hpp`
(`cache_flags()` / `vm_flags()`), layered over `randomx_get_flags()`:

| Flag | Cache | VM | Policy |
|---|---|---|---|
| `RANDOMX_FLAG_JIT` | yes (faster init) | yes | **ON** — light-mode SuperscalarHash/program exec needs it for the ~10-15 ms/hash figure; interpreter fallback is ~10× slower. `randomx_alloc_cache` returns NULL if JIT unsupported → wrapper must fall back to no-JIT. |
| `RANDOMX_FLAG_HARD_AES` | — | yes (via `randomx_get_flags`) | auto-detected; software AES fallback otherwise. |
| `RANDOMX_FLAG_ARGON2_SSSE3/AVX2` | yes (via `randomx_get_flags`) | — | auto-detected; speeds Argon2d cache init only. |
| `RANDOMX_FLAG_LARGE_PAGES` | opt-in | opt-in (scratchpad) | **OFF by default** — needs `vm.nr_hugepages` / `MADV_HUGEPAGE` privilege; host is OOM-pressured. Turn on per-deployment for the 256 MiB cache + 2 MiB scratchpad when hugepages are provisioned. |
| `RANDOMX_FLAG_SECURE` | — | opt-in | W^X JIT pages; on by default on OpenBSD. Small perf cost; enable on hardened hosts. |
| `RANDOMX_FLAG_FULL_MEM` | **NEVER** | **NEVER** | that is the 2080 MiB dataset / fast mode. `vm_flags()` explicitly strips it. |
| `RANDOMX_FLAG_V2` | fork-gated | fork-gated | OFF for rx/0. Absent from the consensus pin; `#ifdef`-guarded in the wrapper. |

Pinned consensus constants (from vendored `configuration.h`, do not change):
`RANDOMX_ARGON_MEMORY=262144` KiB (256 MiB), `RANDOMX_ARGON_ITERATIONS=3`,
`RANDOMX_ARGON_LANES=1`, `RANDOMX_ARGON_SALT="RandomX\x03"`,
`RANDOMX_PROGRAM_COUNT=8`, `RANDOMX_PROGRAM_ITERATIONS=2048`,
`RANDOMX_SCRATCHPAD_L3=2097152` (2 MiB). Any drift here changes every hash.

---

## 4. Two-cache (current / next) with the 64-block seed lag

Monero keys the RandomX cache with the **block id at `seed_height(h)`**:
```
seed_height(h) = (h <= 2048+64) ? 0 : (h - 64 - 1) & ~(2048-1)
```
(monero `rx_seedheight`; constants `SEEDHASH_EPOCH_BLOCKS=2048` ≈ 2.8 d,
`SEEDHASH_EPOCH_LAG=64` ≈ 2 h). The 64-block lag means the seed block is
already deep/final before its epoch begins, so the next epoch's cache can be
precomputed with zero stall. Implemented as free functions `seed_height()`,
`seed_heights()` in the wrapper (KAT-pinned in §8).

**Why exactly two caches.** A v37 XMR receipt is binned at `bin = height(prev_id)`;
within `N_CTX = 2` bins a receipt straddles an epoch boundary only when
`bin mod 2048 ∈ {63,64}`. Two resident 256 MiB caches — `current` (seed at
`seed_height(tip)`) and `next` (seed at `seed_height(tip+64)`) — always cover
every admissible receipt. Class `LightVerifier` holds both `CacheSlot`s and one
reusable light VM, re-pointing it with `randomx_vm_set_cache` (cheap) rather
than rebuilding.

**Hot-path invariants (scoping §1.4, p2pool `add_external_block` order):**
- **I1 — RandomX runs LAST.** `keyed_heavy` admission order is dedup → expiry →
  binding/structural → R-1 target-bits → **`verify()`**. `verify()` is the only
  step that costs 10-15 ms; everything cheap gates it.
- **I2 — no Argon2d on the hot path.** `verify()` NEVER keys a cache. If the
  receipt's seed is not already resident it returns `SeedNotResident`; the
  caller must have called `prefetch_epoch()` (the seconds-long Argon2d init)
  off-path on new-tip. This closes the DoS where a peer forces a cache init.
- **I3 — light only.** Per validating node: 256 MiB (+256 MiB briefly across an
  epoch rollover while both slots are keyed) + 2 MiB scratchpad per VM/thread.

Epoch rollover is hitless: on new tip, recompute `seed_heights(tip)`; if `next`
now differs, `prefetch_epoch()` re-keys the stale slot (the one not holding the
still-live seed) in the background before any receipt in the new epoch arrives.

---

## 5. The verify path (light)

`LightVerifier::verify(blob, len, seed, difficulty, out_hash)`:
1. resolve `CacheSlot` for `seed` (must be resident — I2);
2. `randomx_vm_set_cache` if the VM points elsewhere;
3. `randomx_calculate_hash(vm, blob, len, out)` — the ~10-15 ms light hash;
4. Monero acceptance test `hash * difficulty < 2^256` → `Accept` / `BelowTarget`.

`blob` is the Monero **hashing blob** (~76-77 B: serialized header ‖ 32-B merkle
root ‖ varint(tx_count)); the v37 receipt carries it (scoping §1.5). rx/0 uses
`randomx_calculate_hash` output **directly** as the PoW hash — it does NOT use
`randomx_calculate_commitment` (a 2.0 anti-outsourcing feature); that stays
fenced behind `RX_2`.

The target test (`meets_difficulty_64` / `_128`) is a faithful re-expression of
monero `difficulty.cpp` `check_hash_64`/`check_hash_128` (BSD-3 — **algorithm,
no code copied**): hash read as a little-endian 256-bit int, 256×64 (or ×128)
product checked for overflow past 2^256. `_64` is the primary path (share
targets / `T_origin` fit u64 per scoping §3); `_128` covers the full Monero
`difficulty_type`.

---

## 6. Host cost (measure in proto X0 on our hosts)

| Item | Light | (Fast, for contrast — not used) |
|---|---|---|
| per hash | ~10-15 ms (monerod figure; 14.8 ms design) | ~1-2 ms |
| resident RAM | 256 MiB cache (+256 MiB rollover) + 2 MiB/VM | +2080 MiB dataset |
| cache re-init (Argon2d, per 2048-block epoch) | seconds, serial, off-path | same |

v37 carrier rule bounds aggregate rate: `≤ (1+R_MAX)/share_interval` hashes/s.
At 10 s / R_MAX=4 → 0.5 H/s ≈ 0.75 % of one light core. Window replay on join
≈ 10,800 hashes ≈ ~160 core-s light (what a p2pool node already does syncing
its PPLNS window). **U-item:** confirm 10-15 ms on our actual (OOM-pressured)
hosts, JIT on, large-pages off.

---

## 7. Consensus fence: `rx/0` vs future RandomX 2.0

`PowAlgo` pins the RandomX variant **per Monero `major_version`**. Current
mainnet = `RX_0` (RandomX v1, `RANDOMX_FLAG_V2` OFF). RandomX 2.0 (released
2026-03-25; XMRig supports it; Monero mainnet fork table still tops at v16) is
`RX_2`, reserved and unimplemented. Enabling V2 flips every hash
(`22ec6b86…` vs `6391 83aa…` for the same input — see §8) and is therefore a
**consensus change**; it must be gated to the exact Monero fork height that
adopts it, never tracked from upstream HEAD. This mirrors the scoping-note
mandate to fence pre-CARROT coinbase derivation per hard-fork.

---

## 8. KAT vectors (`randomx_verify_kat.cpp`)

**Suite A — official RandomX engine vectors** (from tevador/RandomX
`src/tests/tests.cpp`, published test data). rx/0 = the v1 column:

| key | input | rx/0 (v1) expected hash |
|---|---|---|
| `test key 000` | `This is a test` | `639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f` |
| `test key 000` | `Lorem ipsum dolor sit amet` | `300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969` |
| `test key 000` | `sed do eiusmod…magna aliqua` | `c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8` |
| `test key 001` | `sed do eiusmod…magna aliqua` | `e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc` |
| `test key 001` | (hex, Monero-blob-shaped, nonce mid-blob) | `c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1` |

The v2 column (`22ec6b86…`, etc.) is stored too but only runs under `--v2`
against a V2-carrying pin; on the consensus pin the v2 suite is N/A by design.
Suite A needs `librandomx.a` (Argon2d init + light VM) — heavy-ish, run
deliberately (proto X0/X1), not as an on-host unit test.

**Suite B — difficulty rule + seed-height** (pure arithmetic, runs anywhere in
µs; **this is the light check and it PASSES**, 18/18):
`meets_difficulty_64/_128` boundary cases (d=1 always accepts; max-hash·2
overflows; 2^255·2 = 2^256 rejects; 128-bit-difficulty overflow) and
`seed_height`/`seed_heights` against hand-computed answers incl. the epoch
boundary at 4161 and a deep height (1000003 → 999424).

Deferred goldens (other legs, scoping §7 items 13/X0): the mainnet hashing-blob
/ block-id / tx-hash triple re-verified through this wrapper, and the
Keccak-midstate coinbase-opening KAT.

---

## 9. License compliance

- c2pool is **AGPL-3.0**. RandomX is **BSD-3** → ports in trivially.
- Copied files (`randomx.h`, `configuration.h`, `LICENSE`) are **byte-identical**
  to upstream `@12f2c2f` with the BSD-3 header intact; **not modified**, so no
  in-file provenance comment is injected (it would break auditors' byte-diff
  against upstream). Provenance is in `PROVENANCE.txt` + this manifest.
- `randomx_verify.hpp` / `randomx_verify_kat.cpp` are **freshly authored for
  c2pool, AGPL-3, attribution-clean.** No RandomX code is copied into them; only
  the C API and the (BSD-3) Monero target-check *algorithm* are used.
- **No p2pool (GPL-3) code appears in this leg** — the two-cache pattern and the
  `add_external_block` admission order are re-expressed from the design, not lifted.

---

## 10. Open questions (route to integrator)

- **OQ-X2** seed-ref in the receipt: carry the 32-B seed hash (Tari style,
  self-checking) or derive from `bin` (0 B, cannot disagree with the index)?
  Wrapper supports both (`verify()` takes an explicit `seed`); the receipt
  format decides. Recommendation: derive from bin (0 B), pass to `verify()`.
- **OQ-X (V2 timing):** when Monero pins RandomX 2.0, add `PowAlgo::RX_2` gated
  to that `major_version` and re-pin the submodule to a V2-carrying commit;
  keep both KAT columns green across the switch.
- **U (host cost):** measure light-mode ms/hash on our hosts (JIT on, HP off).
- **Integration:** JIT unsupported / `randomx_alloc_cache` NULL fallback policy
  (fall back to interpreter, or refuse to start the XMR lane?) — recommend log +
  interpreter fallback so a JIT-less host still verifies, just slower.
