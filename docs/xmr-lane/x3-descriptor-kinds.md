# XMR PayoutDescriptor kinds — canon-change itemization (P-1 tap required)

**Leg:** X3 (X-track Wave 2, Monero/RandomX lane, Family B).
**Base:** `v37/xmr-x1-primitives` @ 11e63a8a (X1 PR #1502, stacked on foundation
#1500). Reuses X1's vendored Monero crypto-ops; re-vendors nothing.
**Status:** code built + KAT-green in this leg. **Freezing the kind bytes is a
ratified-canon change and REQUIRES an integrator tap (P-1).** This note is the
reference for that tap; nothing here is a self-approval.

---

## 1. What is being frozen (the P-1 item)

Two new `ScriptKind` bytes are reserved for the Monero coinbase payout target,
whose target is a pair of ed25519 public keys, not a Bitcoin output script:

| Kind      | Byte   | Payload (64 B)                              | Identity |
|-----------|--------|---------------------------------------------|----------|
| `XMR_STD` | `0x10` | spend_pub `B` (32) ‖ view_pub `A` (32)      | standard address |
| `XMR_SUB` | `0x11` | sub-spend `D_i` (32) ‖ main-view `A` (32)   | subaddress |

These bytes are **consensus** ("every script has exactly one canon"). Once
tapped they become named enumerators `ScriptKind::XMR_STD` / `ScriptKind::XMR_SUB`.
Pre-tap they are used as `static_cast<ScriptKind>(0x10/0x11)` (the enum has a
fixed `std::uint8_t` underlying type, so any in-range byte is well-defined).

Why NOT reuse kind-255 `RAW`: `RAW` means "these raw bytes ARE the output
script." The Monero coinbase (`miner_tx`) has **no** output script — the on-chain
output is a *derived* one-time (stealth) key `P_i = H_s(8 r A ‖ i) G + B`, never
the descriptor bytes. Settling a Monero payout under kind-255 would silently
mis-settle. A distinct kind family is mandatory. `identity = exact (kind,
payload)` (canon S-1/S-3): main address and subaddress are two distinct
identities, as they must be.

---

## 2. Exact canon-side edits the tap authorizes

The extension lives in `src/sharechain/v37/v37_descriptor_xmr.hpp` and does NOT
rewrite `v37_descriptor.hpp`. On tap, fold these into the canon:

1. **`enum class ScriptKind`** (`v37_descriptor.hpp`): add
   `XMR_STD = 0x10,` and `XMR_SUB = 0x11,`.
2. **`PayoutDescriptor::ref_well_formed`**: add
   `case ScriptKind::XMR_STD: case ScriptKind::XMR_SUB: return r.payload.size() == 64;`
   (currently unknown kinds return `false`).
3. **`PayoutDescriptor::valid`**: for an XMR `pay` (or XMR aux ref) invoke the
   torsion / prime-order check on **both** 32-byte halves
   (`v37::xmr::xmr_ref_valid`). Keep the existing rule that XMR kinds carry no
   `raw_script` and no attribution under V37.0.
4. **h_min table** (byte-denominated): add the XMR row —
   `size(kind) = 42 B` (miner-tx output worst case), `dust(kind) = 0` (Monero has
   no consensus/relay dust rule; `validate_miner_transaction` sums plaintext
   amounts). Rows are in `v37_descriptor_xmr.hpp` (`xmr_size` / `xmr_dust`).

`identity_key()` needs **no** change: it serializes `VERSION ‖ kind ‖ len ‖
payload`, and the `u8` length field already fits 64. The identity_key KAT
goldens are computed with SHA-256 only and hold with no crypto backend
(verified GREEN this leg).

---

## 3. The validity rule: a REAL prime-order / torsion check

`valid()` for an XMR kind requires each 32-byte half to be a **canonical,
on-curve ed25519 point in the prime-order (torsion-free) subgroup** — rejecting
small-subgroup and non-canonical points. Without this, an attacker can register
a descriptor whose points carry a torsion component (the class p2pool guards
with `Wallet::torsion_check()`).

**Backend (finalized this leg):**
`src/sharechain/v37/v37_descriptor_xmr_point_check_ref10.cpp`, guarded by
`V37_XMR_HAVE_MONERO_CRYPTO`. Algorithm, on X1's vendored crypto-ops
(`src/impl/xmr/coin/vendor/crypto-ops.{c,h}`, BSD-3, ref10):

```
1. ge_frombytes_vartime(&P, pt) != 0            -> non-canonical / off-curve : reject
2. ge_p3_is_point_at_infinity_vartime(&P)       -> identity (order 1)        : reject
3. [L]P == 𝒪   (L = ed25519 group order)         -> prime-order subgroup       : accept
```

Step 3 is the exact cofactor test: the group is `Z_L × Z_8` and `gcd(L,8)=gcd(5,8)=1`,
so `[L]P = 𝒪` **iff** `P` is torsion-free. This rejects every small-order point
AND any mixed prime+torsion point, using **only** the `ge_*` primitives X1 already
vendored.

> **Change from the foundation draft:** the draft backend called
> `fcmp_pp::mul8_is_identity` + `fcmp_pp::torsion_check_vartime`
> (`fcmp_pp_crypto.h`). **`fcmp_pp` is NOT in the tree** (it is X6 territory and
> is FCMP-fenced out of this wave), so that path could never build. Finalized to
> the crypto-ops `[L]P == 𝒪` test, which is mathematically exact and buildable in
> the CI-gated lane today. Header comment updated to match.

The header stays **fail-closed**: with no backend installed, `is_valid_point()`
returns `false`, so an XMR descriptor cannot be declared valid without the real
crypto check. It never silently passes.

**FCMP++/CARROT fence:** the `(B,A)`/`(D_i,A)` payloads and this torsion rule are
pinned to pre-CARROT Monero (`major_version <= 16`, `xmr_precarrot_ok()`). A lane
building a coinbase for a block whose `major_version` exceeds this MUST NOT reuse
these kinds unreviewed. Coinbase-output derivation is X6, fenced out here.

---

## 4. KATs (all GREEN this leg, light single-TU g++ -std=c++20, no cmake/RandomX)

- **Descriptor round-trip + identity_key** (`test/v37_descriptor_xmr_test.cpp`,
  header-only, no crypto backend): `check_identity_kats()` recomputes
  `sha256d(01 10 40 ‖ B ‖ A)` / `sha256d(01 11 40 ‖ D_i ‖ A)` and matches the
  goldens; XMR_STD preimage is 67 B; fail-closed (no backend ⇒ invalid);
  wrong-width reject; XMR-aux-on-BTC-identity settles. → `ALL XMR DESCRIPTOR
  KATS/CHECKS GREEN`.
- **Torsion accept/reject** (`test/xmr_torsion_kat.cpp`, links vendored
  crypto-ops.c + crypto-ops-data.c + the finalized backend):
  - ACCEPT: ed25519 basepoint; real spend/view/sub-spend pubkeys.
  - REJECT: order-1 (identity), order-2, order-4, both order-8 torsion points.
  - REJECT: a **runtime-constructed mixed point** `B + T2` (on-curve, canonical,
    non-identity, non-small-order, but torsion-carrying) — the descriptor attack;
    caught only by `[L]P`.
  - Descriptor-level: `xmr_ref_valid` rejects a ref whose spend half is a torsion
    point / whose view half is the identity; accepts one built from real
    pubkeys. → `ALL XMR TORSION KATS GREEN`.

**CI target to add (lane build, gated by `V37_XMR_HAVE_MONERO_CRYPTO`):**
`xmr_torsion_kat` linking `crypto-ops.c` + `crypto-ops-data.c`. The header-only
`v37_descriptor_xmr_test` runs with no crypto and can join the default matrix.

---

## 5. ChainLimits XMR sibling (`src/core/coin/utxo.hpp` — additive, no tap)

Added next to `LTC_LIMITS` / `DOGE_LIMITS` / `DGB_LIMITS`
(patch `patches/chainlimits_xmr.diff`):

```cpp
static constexpr ChainLimits XMR_LIMITS = {9'223'372'036'854'775'807LL, 60, 0};
//                                          max_money(int64 ceiling), 60, pegout=0
```

- `coinbase_maturity = 60`: monero-project `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`
  = 60 (a mined output unlocks at `height + 60`; the D_conf floor the settlement
  executor enforces — matches X1's `XMR_COINBASE_MATURITY = 60`).
- `pegout_maturity = 0`: Monero has no MWEB/pegout.
- `max_money`: **denomination + range caveat.** Monero amounts are piconero
  (1 XMR = 1e12 atomic units, NOT the 1e8-sat BTC convention) and there is no
  fixed cap (`MONEY_SUPPLY` is the `((uint64_t)-1)` sentinel; tail emission is
  0.6 XMR/block forever). `money_range()`'s ceiling is `int64_t`, so `INT64_MAX`
  guards only against negative / overflowed amounts and never falsely rejects a
  real coinbase output. Supply-cap / per-output validity are Monero consensus'
  job (`validate_miner_transaction`); c2pool re-derives `(P_i, view_tag_i)` and
  byte-compares outputs.

Adding `XMR_LIMITS` (a constant) is **not** consensus and needs no tap. Parity
constants `XMR_MIN_BLOCKS_TO_KEEP = 60` and `XMR_MINING_GATE_DEPTH = 70` added
alongside their DGB siblings.

---

## 6. Antecedent bug fixed (`src/core/address_validator.cpp` — shared core, real bug)

Patch `patches/address_validator_monero_fix.diff` (`.hpp` + `.cpp`).

`validate_monero_address()` mislabeled a **subaddress** as an integrated address:

```cpp
} else if (address[0] == '8') {
    result.type = AddressType::MONERO_INTEGRATED;   // WRONG
    result.requires_memo = true;                    // WRONG (subaddr has no payment ID)
}
```

Reality (Monero mainnet base58 network bytes): `'4'` = standard (byte 18) /
integrated (byte 19); `'8'` = **subaddress** (byte 42). Standard vs integrated is
**length**, not leading char — both start `'4'`; an integrated address embeds an
8-byte payment ID and encodes to **106** chars vs a standard address's 95.

Fix (minimal + safe):
- `'4'` + length 106 ⇒ `MONERO_INTEGRATED` (`requires_memo = true`); else
  `MONERO_STANDARD`.
- `'8'` ⇒ new `AddressType::MONERO_SUBADDRESS` (no memo).
- New enum value appended **before** `INVALID` (existing values keep their
  ordinals; nothing serializes `AddressType`). `get_address_type_name()` gains
  its `"Monero Subaddress"` case (the `switch` has a `default:`, so this is
  additive-safe for `-Werror=switch`).
- Corrected the misleading `initialize_monero_configs()` comment.

Patched file passes `g++ -std=c++20 -fsyntax-only` against the tree include roots.

---

## 7. Provenance / licensing

- `v37_descriptor_xmr.hpp`, `v37_descriptor_xmr_point_check_ref10.cpp`,
  `test/xmr_torsion_kat.cpp`, `test/v37_descriptor_xmr_test.cpp`: fresh c2pool,
  **AGPL-3.0-or-later**, attribution-clean.
- The backend **calls** (does not copy) X1's vendored Monero crypto-ops
  (BSD-3, ref10). No new vendoring.
- The decode → reject-identity → require-prime-order sequence mirrors, in intent
  only, p2pool `Wallet::torsion_check()` (GPL-3.0, combinable into AGPL-3.0 under
  AGPLv3 §13); no p2pool source text reproduced. Monero-plumbing intent only — no
  pool-model (sidechain/PPLNS/uncles/split_reward) is touched.
