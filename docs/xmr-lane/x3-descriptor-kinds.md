# V37 PayoutDescriptor — Monero (XMR) payout-target kinds

**Family B: XMR / RandomX settlement lane.** Ratified-canon change. **Requires an integrator tap** (kind bytes are consensus: "every script has exactly one canon").

Design of record: `v37-monero-randomx-lane-scoping.md` §2.3, §13, §14, §16, §16.1, §19.
Reference implementation (this leg): `v37_descriptor_xmr.hpp` (+ `xmr_point_check_ref10.cpp`, `v37_descriptor_xmr_test.cpp`).

---

## 1. What changes and why

The Monero coinbase (`miner_tx`) has **no output script of any kind** (scoping §13.1/§13.2). The payout target is a pair of ed25519 public keys; the on-chain output is a *derived* one-time (stealth) key

```
R   = r·G                                  (tx pubkey, tx_extra tag 0x01)
D   = 8·r·A                                 (A = recipient view pub)
P_i = H_s(D‖i)·G + B                        (B = recipient spend pub)   # main addr
view_tag_i = first byte of H("view_tag"‖D‖i)
```

never the descriptor bytes themselves. Therefore the canon's `RAW = 255` ("these raw bytes ARE the output script") is the **wrong** container — RAW semantics would treat 64 key-bytes as a script and silently mis-settle. A distinct non-script kind family is mandatory.

Two kinds are reserved:

| kind | byte | payload (64 B) | meaning |
|---|---|---|---|
| `XMR_STD` | `0x10` | `spend_pub B (32) ‖ view_pub A (32)` | standard address, mainnet prefix 18 ("4…") |
| `XMR_SUB` | `0x11` | `sub_spend D_i (32) ‖ main_view A (32)` | subaddress, prefix 42 ("8…"), p2pool v4.11 model |

Both payloads are **64 bytes** (payout-minimal; see OQ-X7 for the 96-byte alternative). Identity is the exact `(kind, payload)` of `pay` (canon S-1) so a main address and a subaddress are two distinct identities — correct.

**Canon rule 1 restated** (whole descriptor surface): "scripts, never address strings" → **"payout-target bytes, never address strings."** The base58 `4…`/`8…` string is decoded and checksum-verified **once** at the boundary; the canon only ever holds the raw 32-byte key material.

### Torsion / prime-order rule (the one new validity rule)

Every 32-byte payload half is an ed25519 point encoding and **must** be validated to lie in the prime-order subgroup (torsion-free, not small-order). Reference sequence — mirrors `SChernykh/p2pool src/wallet.cpp Wallet::torsion_check()`:

1. `ge_frombytes_vartime(&P, pt) == 0` — decodes to a canonical on-curve point;
2. `!fcmp_pp::mul8_is_identity(P)` — reject small-order points (8·P == 𝒪);
3. `fcmp_pp::torsion_check_vartime(P)` — require the prime-order subgroup.

The header is **fail-closed**: with no crypto backend installed, `xmr_ref_valid()` returns `false`. XMR descriptors can never be declared valid without the real check.

### h_min table rows (scoping §2.3, §16)

| field | value | source |
|---|---|---|
| `size(XMR_STD)` / `size(XMR_SUB)` | **42** (bytes) | coinbase out = 1 type + 32 key + 1 view_tag + varint amount[5..8] = 39–42; take worst case |
| `dust(XMR_*)` | **0** | Monero has **no** consensus/relay dust rule; p2pool routinely pays ~0.00027 XMR |
| `k_live(XMR)` | Monero consensus base fee/byte at settlement height | scoping §16 (OQ-X9) — *not* fixed here |

---

## 2. Exact canon-side edits (the integrator tap)

Minimal, additive edits to `src/sharechain/v37/v37_descriptor.hpp`. Nothing existing changes value; the canonical serialization is untouched (`append_ref`'s u8 length field already fits 64).

1. **`enum class ScriptKind`** — add two enumerators:
   ```cpp
   XMR_STD = 0x10,   // payload: spend_pub B (32) ‖ view_pub A (32)  = 64
   XMR_SUB = 0x11,   // payload: sub_spend D_i (32) ‖ main_view A (32) = 64
   ```

2. **`ref_well_formed(const ScriptRef&)`** — add to the switch:
   ```cpp
   case ScriptKind::XMR_STD:
   case ScriptKind::XMR_SUB: return r.payload.size() == 64;
   ```

3. **Comment §6.3** — restate rule 1 as "payout-target bytes, never address strings"; note that XMR kinds carry no `raw_script` (RAW-only invariant already covers this: the existing `else` branch rejects a non-empty `raw_script` for any non-RAW kind).

4. **`valid()`** — invoke the torsion check for XMR kinds. Introduce a consensus crypto seam (a `xmr_point_check_fn`, as in `v37_descriptor_xmr.hpp`), fail-closed by default:
   ```cpp
   if (r.kind == ScriptKind::XMR_STD || r.kind == ScriptKind::XMR_SUB) {
       if (!xmr_point_ok(r.payload.data()))      return false;  // spend/sub-spend
       if (!xmr_point_ok(r.payload.data() + 32)) return false;  // view
   }
   ```
   This is the only edit that pulls in external crypto; keep it behind the same seam so the header-only surface still builds without Monero crypto.

Until the tap lands, the extension header `v37_descriptor_xmr.hpp` carries the identical logic out-of-tree (`xmr_ref_valid`, `xmr_descriptor_valid`) so the lane can proceed.

---

## 3. KATs

### 3.1 identity_key goldens (HARD — SHA-256 only, no backend)

`identity_key = sha256d(identity_preimage)` where
`identity_preimage = VERSION(0x01) ‖ kind ‖ len(0x40) ‖ payload` (67 bytes).

**XMR_STD**
```
B (spend_pub) = 75b625d552092c5d10e405ea7974abd8eaa43488778e4a8be9f84d6305ef46b5
A (view_pub)  = f1b6e0906eb3cbb997475d0acb173479845d7e06e146f0186026f3ac9329ae7a
preimage      = 0110 40 ‖ B ‖ A
identity_key  = 25aa4c3f55281bcc52bd7c051ff1778054dd92cef93624748ef206156b34bacc
```

**XMR_SUB**
```
D_i (sub_spend) = abcb58157baaae8eab436b16eea3899a996ca915123659cb237b888834ef26a4
A_main (view)   = f1b6e0906eb3cbb997475d0acb173479845d7e06e146f0186026f3ac9329ae7a
preimage        = 0111 40 ‖ D_i ‖ A_main
identity_key    = e321192903e638cb42fc37452b3633ef0152f12eaf1fdca7fb6aac7aba2e0555
```

`B`, `A`, `D_i` are **real ed25519 public keys** (clamped-scalar·basepoint ⇒ prime-order points, reproducible from fixed seeds), so they double as torsion-**PASS** inputs when a backend is installed. Verified GREEN by `v37_descriptor_xmr_test.cpp` (single-TU `g++ -std=c++20 -Wall -Wextra`).

### 3.2 torsion spec vectors (run against the installed backend)

| vector | 32-byte encoding | expected |
|---|---|---|
| ed25519 basepoint | `5866666666…66` | **PASS** (prime-order) |
| order-1 identity | `0100000000…00` | **FAIL** (`mul8_is_identity` ⇒ small-order) |

---

## 4. FCMP++ / CARROT fence

FCMP++/CARROT may rewrite coinbase-output derivation and address semantics. These descriptor kinds and the torsion rule are **pinned pre-CARROT**: Monero hard-fork `major_version <= 16` (`XMR_PRECARROT_MAX_MAJOR_VERSION`; `monero/master hardforks.cpp` tops at v16 as of 2026-09-05). `xmr_precarrot_ok(major_version)` gates any lane building a coinbase past v16 — do **not** reuse these kinds unreviewed beyond the fence. Note the torsion primitives themselves already live under p2pool's `fcmp_pp` namespace, a signal that FCMP++ touches exactly this surface.

---

## 5. Open questions

- **OQ-X7** — `XMR_SUB` payload width. This leg uses **64 B** (`D_i ‖ A_main`), payout-minimal and consistent with p2pool v4.11 (one shared `R`, main view key + subaddress spend key, **no** `TX_EXTRA_TAG_ADDITIONAL_PUBKEYS`). The scoping P1 §5 alternative is **96 B** (`D_i ‖ C_i ‖ A_main`) if the canon must reproduce the printable subaddress. Ruling needed before the tap; if 96 B wins, `ref_well_formed` gets a second width and `XMR_PAYLOAD_LEN` becomes kind-dependent.
- **Crypto seam** — `valid()` must call a torsion check, which pulls ed25519 ops into the otherwise-pure descriptor header. Ruling: keep it behind a fail-closed function-pointer seam (this leg's choice) vs. a compile-time backend. Either way the header-only build must not hard-require Monero crypto.
- **OQ-X9** (downstream, not this leg) — `k_live(XMR)` definition and whether a policy spend-economics floor replaces `dust = 0`.

---

## 6. License / provenance

- `v37_descriptor_xmr.hpp`, `xmr_point_check_ref10.cpp`, `v37_descriptor_xmr_test.cpp`: **fresh c2pool sources, AGPL-3.0-or-later, attribution-clean.**
- `xmr_point_check_ref10.cpp` **calls** (does not copy) Monero `crypto-ops.{h,c}` `ge_frombytes_vartime`/`ge_p3` (BSD-3, ref10-derived) and `fcmp_pp_crypto.h` `mul8_is_identity`/`torsion_check_vartime` (BSD-3). The 4-step validation *sequence* is re-expressed from `SChernykh/p2pool src/wallet.cpp Wallet::torsion_check()` (GPL-3.0, combinable under AGPLv3 §13); no p2pool source text is reproduced.
