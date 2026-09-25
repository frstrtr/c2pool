# CARROT / FCMP++ coinbase-output seam (XMR lane) — SCAFFOLD

**Status: SCAFFOLD. No conformant CARROT derivation is implemented, and the
fence is NOT lifted.** `build_coinbase()` still returns `BuildError::CarrotFence`
for every Monero `major_version` in the CARROT regime. This document records why,
what the seam looks like, and exactly what is missing before it can be filled in.

Files:

* `src/impl/xmr/settle/xmr_carrot.hpp` — the seam (header-only, refusing stubs).
* `src/impl/xmr/settle/xmr_coinbase.{hpp,cpp}` — the version gate and the two arms.
* `src/impl/xmr/test/xmr_carrot_gate_kat.cpp` — the KAT that pins both halves.
* `src/sharechain/v37/v37_descriptor_xmr.hpp` — CANON. Holds the fence constant
  `XMR_PRECARROT_MAX_MAJOR_VERSION = 16`. **Not touched by this wave.**

---

## 1. What changed: a fence became a version gate

Before, `build_coinbase()` held one body behind a flat fence. Now it dispatches:

| `monero_major_version` | regime | arm |
| --- | --- | --- |
| `<= 16` (`W5_PRECARROT_MAX_MAJOR_VERSION`) | `CoinbaseRegime::PreCarrot` | `build_coinbase_precarrot()` |
| `>= 17` (`W5_CARROT_MIN_MAJOR_VERSION`) | `CoinbaseRegime::Carrot` | `build_coinbase_carrot()` |

`build_coinbase_precarrot()` is the old body, unmoved. `build_coinbase_carrot()`
is a scaffold that refuses. Both arms re-check the regime themselves, so calling
an arm directly cannot bypass the gate, and the dispatcher fails closed on a
value outside the (exhaustive) enum.

**Net behaviour change for a v17 block: none.** It was refused with
`CarrotFence` before and it is refused with `CarrotFence` now; only
`BuiltCoinbase::detail` is richer, so an operator reading a log learns *why*.

**Net behaviour change for a v16 block: none, to the byte.** See §4.

## 2. Why a scaffold and not an implementation

Verified against primary sources on 2026-09-17 (not aggregators — several
articles claiming FCMP++ "activated in Q1 2026" are contradicted by the code and
by the release history, and are simply false):

* `monero-project/monero` `master` **and** `release-v0.18`:
  `src/hardforks/hardforks.cpp` mainnet table ends at `{ 16, 2689608 }`
  (v16, activated 2022-06-30). There is no v17 row.
* `master` has **no** `src/carrot_core` directory and **no** `HF_VERSION_CARROT`
  / FCMP++ constants in `src/cryptonote_config.h`.
* Newest upstream release is the v0.18.5.x line (CLI 0.18.5.1, 2026-07-08).
  There is no v0.19 / FCMP++ release.
* CARROT + FCMP++ live on the `seraphis-migration/monero` fork
  (`fcmp++-stage`, `fcmp++-beta-stressnet`), where `cryptonote_config.h` sets
  `HF_VERSION_FCMP_PLUS_PLUS = HF_VERSION_CARROT = 17`,
  `FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10000`, `MAX_TX_EXTRA_SIZE = 1060`, and
  the mainnet rows `{ 17, 2689609 }` / `{ 18, 2689610 }` are explicitly
  commented *"Mock values for tests"*.
* Upstream integration is in flight, not merged: `carrot_core` (#9559, open),
  FCMP++ integration (#9436, draft), `carrot_impl` (#9697, draft), RandomX V2 +
  PoW commitments in v17 (#10038, open and contested).
* No mainnet fork height and no fork date have been announced.

So **17 is the de-facto expected fork number, but it is not pinned by any
upstream release**, and there are **no published reference vectors for a CARROT
*coinbase* enote**. Implementing the derivation now would mean inventing
conformance and pinning a KAT to our own guess. An approximately-right coinbase
does not fail a test — it pays the block reward to keys nobody can spend.

## 3. The derivation, as far as it is captured

Sources of record: `jeffro256/carrot` `carrot.md` (design text — carries no
version, no status marker, no test vectors) and the reference implementation on
`seraphis-migration/monero` `fcmp++-stage`
(`src/carrot_core/{enote_utils,payment_proposal,hash_functions}.cpp`,
`{transcript_fixed.h,config.h}`, `src/carrot_impl/format_utils.cpp`). The code is
authoritative wherever the prose under-specifies: the keyed hashing and the
length-prefixed transcript are implementation facts the text writes as plain
concatenation.

Primitives:

* `H_b^{key}(x)` = BLAKE2b, `digest_length = b`, `key_length = (key ? 32 : 0)`,
  fanout 1, depth 1, `personal = "Monero"` zero-padded to 16 bytes; keyed form is
  standard keyed BLAKE2b.
* `SecretDerive = H_32`; view tag = `H_3` (**3 bytes**, not the pre-CARROT 1);
  masks = `H_16`; `ScalarDerive = sc_reduce(H_64(x))`.
* transcript = `u8(len(ds)) || ds` (no NUL) `|| fields`, each field raw and
  fixed-width, integers little-endian (`u64` amount = 8 B LE).
* X25519 scalar mults are **unclamped** throughout; base `B` has `x = 9`.
* `ConvertPointE(K)`: `x = (1 + y) / (1 - y)` from the Ed25519 `y` coordinate.

Per coinbase output, payee MAIN address (`K_s` spend, `K_v` view), amount `a`,
height `h`:

1. `input_context = 'C' || u64le(h) || 24 zero bytes` (33 bytes).
2. `anchor_norm` = 16 bytes, **must be non-zero**. Sender-chosen; `monerod` uses
   random (`gen_janus_anchor()`).
3. `d_e = ScalarDerive( tr("Carrot sending key normal", anchor_norm[16],
   input_context[33], K_s[32], K_v[32], pid[8] = 0) )` (unkeyed; `pid` must be null).
4. `D_e = d_e * B` (X25519, unclamped; 32-byte x-coordinate, carried in
   `tx_extra`). The subaddress form `d_e * ConvertPointE(K_s^j)` is **forbidden**
   for a coinbase (the reference throws `bad_address_type`).
5. `s_sr = d_e * ConvertPointE(K_v)` (unclamped; `K_v` must be in the
   prime-order subgroup — the v37 descriptor torsion rule already guarantees it).
6. `s_sr_ctx = H_32^{key = s_sr}( tr("Carrot sender-receiver secret", D_e[32],
   input_context[33]) )`.
7. `k_g = ScalarDerive^{key = s_sr_ctx}( tr("Carrot coinbase extension G",
   u64le(a), K_s[32]) )`; `k_t` likewise with `"Carrot coinbase extension T"`.

## 4. What the KAT pins

`src/impl/xmr/test/xmr_carrot_gate_kat.cpp` (`add_test` name
`xmr_carrot_gate_kat`, on both `build.yml` legs) defends two properties that pull
in opposite directions:

**(A) The gate moved no byte of the pre-CARROT coinbase.** Case 1 pins a complete
v16 coinbase — `r`, `R`, every one-time key `P_i`, every view tag, the
merge-mining root, `tx_extra`, the whole serialized prefix, the prefix hash and
the coinbase tx hash — against goldens captured from the pre-gate tree
(`origin/master` 854336be) by running the identical input vector through the
unmodified `build_coinbase()`. Mainnet Monero is at v16 today, so this is a
today-mainnet coinbase, not a hypothetical one. The payout targets are the
official `monero-project` `tests/crypto/tests.txt` consensus points, so the
derivations run against real on-curve keys.

**(B) The CARROT arm still fails closed.** Every `major_version` 17..255 is
refused with `CarrotFence` and produces no outputs, no keys and no prefix; each
arm refuses on its own; the seam stubs refuse and wipe their outputs; and the
CANON fence `XMR_PRECARROT_MAX_MAJOR_VERSION` is asserted still 16.

## 5. Gap list — what must exist before the fence can lift

| | missing |
| --- | --- |
| G1 | the assembly of `K_o` from `K_s`, `k_g`, `k_t` and the generators |
| G2 | the exact view-tag transcript (which fields, in which order) |
| G3 | the anchor encryption, and whether a coinbase enote carries `anchor_enc` at all |
| G4 | the serialized coinbase output / `tx_extra` layout under FCMP++ (output type tag, where `D_e` lives, `MAX_TX_EXTRA_SIZE = 1060`) |
| G5 | the v17 consensus caps bounding the K_fair output count — `FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10000`, `REJECT_MANY_MINER_OUTPUTS`, `REJECT_UNLOCK_TIME`, `REJECT_LARGE_EXTRA`, the 2026 scaling rules |
| G6 | whether v17 also changes the PoW hashing blob (RandomX v2 + commitments, `monero-project/monero#10038`) — that would move the W3 receipt/oracle seam, not this one |
| G7 | **reference vectors for a CARROT coinbase enote. None are published.** Without G7 no KAT can pin conformance, so the fence must stay up. |

## 6. Operator seam — the decisions this wave does NOT make

1. **The deterministic anchor.** `anchor_norm` is sender-chosen randomness.
   `monerod` picks it at random; a pool cannot, because every node must
   re-derive the identical coinbase byte for byte. This is the CARROT-regime
   analogue of `derive_tx_secret_key()` and it is a **v37 design decision, not a
   conformance item**. Choosing it wrongly is a silent privacy failure
   (Janus-style address linkage), not a build error. For reference, P2Pool (Go
   consensus v5, `carrot/p2pool.go`) defines its own:
   `anchor = H_16^{key = seed}("P2Pool deterministic Carrot output randomness"
   || input_context || K_s || K_v || u32le(nonce))`, `nonce` incremented until
   the result is non-zero. v37 needs its own ruling.
2. **Lifting the CANON fence.** `XMR_PRECARROT_MAX_MAJOR_VERSION` lives in
   `src/sharechain/v37/v37_descriptor_xmr.hpp`. Raising it is a consensus change
   and an operator ruling; this wave deliberately leaves canon untouched, and the
   KAT asserts that it did.
3. **Flipping `carrot::DERIVATION_IMPLEMENTED`.** Only together with (a) a
   derivation matching a tagged upstream release, (b) reference vectors pinned in
   a KAT, and (c) 1 and 2 above. A `static_assert` fires if anyone flips the flag
   while the stubs are still refusing.
4. **Adding the seam's translation unit.** The stubs are `inline` in the header
   today precisely so the scaffold touches no other target's source list. A real
   derivation needs a `.cpp`, and the seven CMake source lists that already
   compile `settle/xmr_coinbase.cpp` must gain it in the same commit.
