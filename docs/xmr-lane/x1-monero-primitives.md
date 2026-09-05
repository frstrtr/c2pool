# Leg X1 — Monero primitives (`src/impl/xmr/coin/`)

Foundation of the v37 **Family B: XMR lane** (frstrtr/c2pool, AGPL-3). Design of
record: `v37-monero-randomx-lane-scoping.md` (§2.5, §5,
§7, §16, §B item 7). This leg delivers the Monero cryptographic primitives the
lane needs; it does **not** touch `src/sharechain/v37` consensus-digest code.

## Copied (vendored, verbatim, BSD-3 / permissive) — see `vendor/PROVENANCE.md`

monero-project/monero @ `3d3920d7`:
`vendor/keccak.{h,c}`, `vendor/hash-ops.h`, `vendor/hash.c`, `vendor/tree-hash.c`,
`vendor/crypto-ops.{h,c}`, `vendor/crypto-ops-data.c`, `vendor/int-util.h`,
`vendor/varint.h`, `vendor/difficulty.{h,cpp}`.

## Authored fresh for c2pool (AGPL-3, attribution-clean)

| file | role |
|------|------|
| `xmr_crypto_types.hpp`     | slim POD key/scalar/hash/view-tag byte-strings (drive the vendored raw `unsigned char*` API without monerod crypto.h/epee) |
| `xmr_keccak_midstate.hpp`  | Keccak-256 + **resumable midstate** (snapshot/resume `KECCAK_CTX`) — the coinbase-opening receipt head; `keccak256()` one-shot |
| `xmr_seedheight.hpp`       | RandomX `seed_height((h-64-1)&~2047)`, epoch-edge test — **consensus-fixed** (drops monerod's env override) |
| `xmr_check_hash.hpp`       | boost-free 128-bit difficulty test `hash·d ≤ 2^256−1` (oracle: `vendor/difficulty.cpp`) |
| `xmr_pow_select.hpp`       | `major_version → PoW algo` (`get_block_longhash` model) + **RandomX-v2 (#8827)** and **CARROT/FCMP++** fences |
| `xmr_blob.{hpp,cpp}`       | CryptoNote varint/blob writer; block hashing-blob; v2 RCTTypeNull coinbase tx hash; `tree_root`/`tree_branch`/verify |
| `coin_xmr.hpp`             | umbrella facade + Monero consensus constants + `get_eph_public_key` (CARROT-guarded) |
| `compat/warnings.h`        | boost-free stand-in for epee `warnings.h` (lets vendored C compile unmodified) |

## Adapted BSD-3 subset (header preserved + provenance) — NOT authored

| file | role |
|------|------|
| `xmr_derivation.{hpp,cpp}` | `generate_key_derivation` / `derivation_to_scalar` / `derive_public_key` / `derive_view_tag` — function bodies **verbatim** from monerod `src/crypto/crypto.cpp @ 3d3920d7`, re-namespaced to `xmr::coin` and retyped onto the slim POD aliases; see the .cpp header for the exact adaptation list |

## Light build/verify (host is OOM-pressured — no cmake, no dataset, no parallel)

`check/build.sh` → single-TU compiles the self-contained vendored C
(`keccak.c`, `hash.c`, `tree-hash.c`) + authored `xmr_blob.cpp`, links one
`selfcheck` binary, runs it, then `-fsyntax-only` on the libsodium-dependent TUs.
Result: **`ALL PASS (xmr-primitives selfcheck)`**, `xmr_derivation.cpp` syntax OK.
Validated at runtime:
- Keccak midstate `snapshot→resume` == one-shot at splits {0,1,135,136,137,200}
  over inputs up to 512 B (non-block-aligned and multi-block) — the coinbase
  opening mechanism, byte-exact.
- v2 RCTTypeNull coinbase tx hash `keccak(H(prefix)‖keccak(0x00)‖0³²)`,
  `tree_root`, coinbase `tree_branch` + verify, tamper rejection, single-tx root.
- `check_hash` 64- and 128-bit paths (boundary cases at 2^255).
- `seed_height` / epoch math against the rx-slow-hash.c formula.
- `pow_select` fences (pre-RX rejected; v12–v16 → RandomXv1; pre-CARROT true).

`crypto-ops.c` was **not** compiled here (needs libsodium `crypto_verify_32`,
absent on this host); it links in the c2pool tree as it does for monerod. The
ed25519 derivation path is therefore syntax-verified only in this leg — a full
KAT (p2pool output-key / view-tag vectors) is deferred to X1's test milestone
where libsodium is available.

## Open questions / fences carried

1. **[U3 / X0-KAT]** The Keccak-midstate split boundary and byte-identity vs
   monerod `keccak.c` must be pinned by a mainnet-block coinbase-opening KAT
   before consensus trust. (Mechanism proven equal here; the *choice of split
   point* on a real miner_tx prefix is a design decision.)
2. **[U7 / OQ-X10 — CARROT/FCMP++ fence]** All coinbase-output derivation is
   declared **pre-CARROT**, gated by `coinbase_derivation_is_pre_carrot()`.
   `CARROT_MAJOR_VERSION` is an unassigned sentinel today; when Monero schedules
   CARROT this guard must fail (not silently derive with the old rule) until the
   derivation layer is rewritten.
3. **[#8827 — RandomX v2 fence]** `RANDOMX_V2_MAJOR_VERSION` is an unassigned
   sentinel; pin it when Monero activates the double-Blake2b finalisation and
   route to a distinct verifier build.
4. **check_hash vs difficulty.cpp** — the boost-free header must be
   cross-checked against the vendored oracle on the RandomX test vectors +
   recent mainnet blocks in X1's KATs (semantics matched by construction here).
5. **Difficulty width** — the lane treats `work(T)`/share targets as u64
   (scoping S6.2); the 128-bit path exists for completeness. `work(T)` (w_raw)
   itself is defined by the LANE layer, not this leg.
6. **Subaddress payees [U5/OQ-X7]** — `get_eph_public_key` here takes explicit
   (view_pub_A, spend_pub_B); the subaddress case (main view + subaddress spend,
   single `R=rG`) is a W5-executor concern, not a primitive change.
