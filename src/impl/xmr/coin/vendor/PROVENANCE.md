# Vendored upstream sources — provenance (c2pool XMR lane, leg X1)

All files in this `vendor/` directory are **copied verbatim** (byte-for-byte,
license headers preserved as shipped upstream) from **monero-project/monero**.
They are NOT authored by c2pool. Per the c2pool porting rule LIC-1: the original
copyright + license header of each file is retained unchanged; this file is the
provenance record naming the upstream source, commit, license, and any external
dependency. c2pool is AGPL-3.0; BSD-3-Clause code combines into AGPL-3 without
issue (AGPLv3 §13 / BSD-3 compatibility).

- **Upstream repo:** https://github.com/monero-project/monero
- **Commit pinned:** `3d3920d7487b5df7ac388b6b8577fd04d505885f` (branch `master`, fetched 2026-09-05)
- **Fetch method:** blobless sparse checkout (`--filter=blob:none`, sparse-set
  `src/crypto src/common src/cryptonote_basic contrib/epee/include/int-util.h`).

| vendored file       | upstream path                                | license           | sha256 (this copy) | notes / external deps |
|---------------------|----------------------------------------------|-------------------|--------------------|-----------------------|
| `keccak.h`          | `src/crypto/keccak.h`                         | Saarinen baseline¹ | `dde2bdb5…d3be7`   | Keccak-256 + incremental `KECCAK_CTX` (midstate) |
| `keccak.c`          | `src/crypto/keccak.c`                         | Saarinen baseline¹ | `56aec12b…c98b39`  | `keccak1600` squeezes the FULL 200-B state — use `cn_fast_hash` for a 32-B digest |
| `hash-ops.h`        | `src/crypto/hash-ops.h`                       | BSD-3-Clause      | `60c6c002…03d1c4`  | decls: `cn_fast_hash`, `tree_hash`, `tree_branch`, `tree_branch_hash`, `is_branch_in_tree`; also `#define RX_BLOCK_VERSION 12` |
| `hash.c`            | `src/crypto/hash.c`                           | BSD-3-Clause      | `56a62dc7…7f112c`  | `cn_fast_hash` = Keccak-256 (32-B out via `union hash_state`) |
| `tree-hash.c`       | `src/crypto/tree-hash.c`                      | BSD-3-Clause      | `1869b24e…ce5cb1`  | `tree_hash` / `tree_path` / `tree_branch` / `tree_branch_hash` / `is_branch_in_tree` |
| `crypto-ops.h`      | `src/crypto/crypto-ops.h`                     | BSD-3-Clause      | `b09aa33f…bedc5f`  | ed25519 `ge_*`, `sc_*` (raw `unsigned char*` API) |
| `crypto-ops.c`      | `src/crypto/crypto-ops.c`                     | BSD-3-Clause      | `239a9608…84ced`   | **needs libsodium** (`<sodium/crypto_verify_32.h>`) + `warnings.h` at build |
| `crypto-ops-data.c` | `src/crypto/crypto-ops-data.c`                | BSD-3-Clause      | `b5e25225…d5d5a9`  | ed25519 precomputed base tables (`ge_base`, `fe_d`, …) |
| `int-util.h`        | `contrib/epee/include/int-util.h`             | BSD-3-Clause (epee)| `227d6bdb…351f64d` | `mul128`, `SWAP64LE`; **needs `-D_GNU_SOURCE`** (BYTE_ORDER) |
| `varint.h`          | `src/common/varint.h`                         | BSD-3-Clause      | `5db99e35…18868f`  | `tools::write_varint` / `read_varint` (CryptoNote LEB128) |
| `difficulty.h`      | `src/cryptonote_basic/difficulty.h`           | BSD-3-Clause      | `c5f1674b…772965`  | `difficulty_type = boost::multiprecision::uint128_t`; `check_hash*` decls |
| `difficulty.cpp`    | `src/cryptonote_basic/difficulty.cpp`         | BSD-3-Clause      | `96f4776d…0100e57`² | reference oracle for `check_hash` (boost path); lane runtime uses boost-free `../xmr_check_hash.hpp` |

¹ `keccak.{h,c}` carry only upstream's original attribution line
  (`19-Nov-11 Markku-Juhani O. Saarinen <mjos@iki.fi> // A baseline Keccak
  (3rd round) implementation.`) — the public Keccak reference, a permissive
  license. Monero ships them without adding its own BSD-3 block; that header is
  preserved exactly as upstream has it. No header was added or removed.

² sha over the first 16 hex shown in the table is truncated for readability;
  the full digests are recorded in the build log. Re-verify against the pinned
  commit with the fetch method above.

## Not vendored here (but referenced by the vendored files)

- **`warnings.h`** — upstream `contrib/epee/include/warnings.h` supplies the
  compiler-diagnostic macros that `crypto-ops.c` / `hash-ops.h` include, but it
  pulls `<boost/preprocessor/stringize.hpp>` and carries no license header.
  Replaced by an **authored, boost-free** stand-in at `../compat/warnings.h`
  (AGPL-3) with the identical macro surface, placed on the include path via
  `-Icompat`. The vendored files are therefore used **unmodified**.
- **libsodium** — external, links in the c2pool build tree exactly as it does
  for monerod (`crypto-ops.c` uses `crypto_verify_32`).
- **boost** — `difficulty.{h,cpp}` use `boost::multiprecision`. The lane's hot
  path avoids this via `../xmr_check_hash.hpp`; the vendored pair is kept as the
  cross-check oracle only.

## Deliberately NOT vendored

`crypto.h` / `crypto.cpp` (the C++ derivation layer) were **not** copied whole —
they drag epee / mlocker / RNG / MLSAG. Instead the four coinbase-derivation
functions were extracted as a BSD-3 subset into `../xmr_derivation.cpp` (see its
own header + provenance), and slim POD key/scalar/hash types were authored in
`../xmr_crypto_types.hpp`.
