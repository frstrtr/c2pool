# c2pool V37 Share Format — Addendum B: the Family-B (Monero / RandomX) receipt envelope

**Status:** design addendum, Phase-2 / Track-X. Extends `docs/c2pool-v37-share-format.md`
(the Family-A RDWR envelope) without changing it. Design of record:
`v37-monero-randomx-lane-scoping.md` §1.4, §1.5, §2.4, §2.5, §3.2, §16 (item P-2 of the
GO/NO-GO list: *"Share-format addendum for non-Bitcoin receipt envelopes"*). Nothing here
is wired into Phase-1 or the A2 W0–W6 cascade; it is the paper the XMR lane is built against
once the Family-A C++ engine runs end-to-end and Monero pins FCMP++/CARROT timing.

Companion code in this leg (drop-in for a NEW `src/impl/xmr/` tree, above the sharechain
seam, never included from `src/sharechain/v37/*`): `xmr_receipt.hpp` (§B2), `xmr_admission.hpp`
(§B1/§B3/§B4), `_compile_check.cpp` (self-test, not shipped).

Everything here is a *lane-local* extension selected by one new digest-committed lane
attribute (§B1). A Family-A lane that leaves that attribute at its default is byte-identical
to today; a `keyed_heavy` lane opts into all of §B2–§B7.

---

## B0. Why the base envelope does not fit Monero as-is

The Family-A receipt (§3) is a **250-B, μs-verify, PoW-first** proof: an 80-B Bitcoin-family
header whose SHA256d hash is checked *first* against `T_origin` read from `header.bits`, then
bindings, context, and a dedup on that same hash. Three of those assumptions break on Monero,
and they break in a way that a per-coin template add (DGB/BCH pattern) cannot patch — this is a
second chain **family** (scoping §0):

1. **The PoW input is not the header.** RandomX hashes the ~77-B *hashing blob*
   (`get_block_hashing_blob` = `serialize(block_header) || tree_root(32) || varint(n_tx)`), and
   the commitment the receipt must open lives in the coinbase, which is inside the tree the blob
   roots — not in the header. ⇒ a larger, structured receipt (§B2).
2. **The PoW is the most expensive step, not the cheapest.** A RandomX light verify is
   ~10–15 ms with a 256-MiB per-epoch cache; every other check is microseconds. PoW-first
   (§3 order) would let a replayed or expired receipt force a 15-ms evaluation. ⇒ the admission
   order must be inverted for this class (§B3).
3. **The header has no target field.** `block_header = {major, minor, timestamp, prev_id,
   nonce}`. There is nowhere to read `T_origin`. ⇒ `T_origin` must be opened from committed
   side data (§B4).

The precedent that all of this is *implementable and self-contained* is Monero p2pool
(every node re-hashes every share: `SideChain::add_external_block` → `PoolBlock::get_pow_hash`
→ `check_pow`) and Tari's `MoneroPowData` (RFC-0132 / `pow_data.rs`: a stand-alone Monero proof
carrying header, RandomX key, tx count, tree root, coinbase Merkle proof, coinbase Keccak
midstate, coinbase `tx_extra`). Addendum B is those two, expressed as a v37 receipt.

---

## B1. `pow_verify_class` — a new digest-committed lane attribute

Add to `LaneParams` (consensus; folded into the lane digest exactly where `n_ctx` is):

```
pow_verify_class ∈ { stateless_cheap = 0,   // SHA256d / X11 — Family-A §3 order
                     memory_light    = 1,   // Scrypt        — Family-A §3 order
                     keyed_heavy     = 2 }   // RandomX       — Addendum-B order
```

Default `stateless_cheap`; Family-A lanes are unchanged and byte-identical. A `keyed_heavy`
lane additionally commits the block below (see `xmr_admission.hpp::LaneKeyedHeavy`), all
digest-committed so a lane cannot silently switch verify class or budget:

| keyed_heavy param | default | note |
|---|---|---|
| `r_max` | **2** | vs Family-A 4 (§B6) |
| `per_receipt_budget` | **768 B** | hard wire cap (§B6 FINDING) |
| `per_lane_budget` | `r_max × per_receipt_budget` = 1536 B/carrier | derived |
| `n_ctx` | 2 XMR bins ≈ 4 min | already a LaneParams field; bins are 120-s Monero blocks (§B5) |
| `seed_ref_policy` | `DerivedFromBin` (0 B) | OQ-X2 (§B5) |
| `index_retention_blocks` | **2112** | 2048 seed-epoch + 64 lag; dominates `n_ctx+2` (§B5) |

**Where each part lives (OQ-X3):** `pow_verify_class` and the committed budget/`n_ctx`/seed
params are **consensus** (`LaneParams`, digest). The per-peer relay throttle of §B3.1 (token
bucket on unverified carriers) is **non-consensus** (a W3 lane-relay parameter) — it must never
gate acceptance, only propagation.

---

## B2. The Family-B receipt envelope (`MoneroReceipt`)

Replaces the §3 `Receipt` layout for `keyed_heavy` lanes. Fields, wire sizes, and the exact
byte accounting are in `xmr_receipt.hpp`; the shape:

```
MoneroReceipt {
  hashing_blob     ~77 B      serialize(header) || tree_root(32) || varint(n_tx)
                              header = varint(major) varint(minor) varint(timestamp)
                                       prev_id[32] nonce[4 LE];  RandomX PoW lives here;
                                       prev_id -> bin(receipt) = height(prev_id)
  seed_ref         0 | 32 B   RandomX key ref: derived from bin (0 B, default) or
                              carried seed hash (32 B, Tari style) — OQ-X2
  coinbase_opening ~257–422 B Keccak-256 sponge opening of the miner_tx prefix at the
                              tx_extra boundary:
                                midstate[200]  resumable 1600-bit state after absorbing
                                               every full 136-B rate block BEFORE the opened
                                               region (compresses the ~40-B/payee vout list —
                                               a full coinbase is ~90 KB — unrevealed)
                                prefix_tail    < 136 B, the partial remainder
                                tx_extra       0x01 pubkey(33) + 0x02 nonce(6–16) +
                                               0x03 merge-mining tag(~36); the v37 commitment
                                               lives here
  tree_branch      ~129–193 B leaf-0 (miner_tx) O(log n) path to the blob's tree_root
                              (tree-hash.c); depth 4–6 for 10–60-tx blocks
  info_digest      32 B       §3 ref-side binding digest (payout identity, T_origin bits;
                              prev_own_share display-only per §4 round-2 #1)
}
typical 615 B  ·  worst realistic 756 B  ·  hard cap 768 B    (vs ≈ 250 B Family-A)
```

**The coinbase opening, precisely.** A Monero v2 coinbase tx hash is
`Keccak(H(prefix) || H(rct_base) || H(prunable))` with `H(prunable) = null_hash` for the
`RCTTypeNull` coinbase — so opening the commitment means opening `H(prefix)`, whose LAST field
is `tx_extra`. Keccak-256 as Monero uses it (`keccak.c`, original Keccak, `mdlen = 32`) has rate
`r = 136 B`, capacity `c = 64 B`, state `= 200 B`. The receipt carries the sponge state after
absorbing every complete 136-B block of the prefix bytes *preceding* the opened region, the
sub-block tail, and the `tx_extra` bytes in the clear; the verifier resumes, absorbs
`tail || tx_extra`, pads and squeezes to get `H(prefix)`. The bulk of the prefix — the output
list — never appears on the wire; it is absorbed into the 200-B midstate and is unforgeable
because any change to it changes `H(prefix)` → the tx hash → the tree root → the RandomX-signed
blob. This is exactly Tari `MoneroPowData`'s coinbase Keccak midstate. **[?] X0-gated:** the
midstate resume at the `extra` boundary is standard sponge behaviour but MUST be pinned by a KAT
against Monero's `keccak.c` before this ships (sibling leg `x0-feasibility`; scoping §7 X0).

---

## B3. Inverted admission order for `keyed_heavy` (THE W2 change)

§3 validates a receipt **PoW-first**:
`1 PoW → 2 R-1 pin → 3 bindings → 4 context → 5 dedup`. Correct only when the PoW hash is the
cheapest step. For `keyed_heavy` the RandomX hash is the most expensive step, so §3.1 of the
W2 spec, **for `keyed_heavy` lanes only**, is replaced by:

> **Per-receipt validation, `keyed_heavy` consensus order** (`xmr_admission.hpp::admit_receipt_keyed_heavy`):
>
> 0. **size cap** — `wire_size ≤ per_receipt_budget` (no crypto).
> 1. **dedup** — `receipt_id ∉` recent-event set (§5), where **`receipt_id = cheap_digest(hashing_blob)`, NOT the RandomX hash** (subtlety D below). *(~ns)*
> 2. **expiry / context** — `bin(receipt) = height(prev_id)` resolvable within the index horizon; `bin(receipt) ≤ bin(carrier)`; `bin(carrier) − bin(receipt) ≤ N_CTX`. *(~ns)*
> 3. **structural + binding** — resume the Keccak midstate over `tail‖tx_extra`, finalize `H(prefix)`, form the `RCTTypeNull` tx hash, walk `tree_branch`, require recomputed root == the blob's `tree_root`; parse the side-data commitment out of `tx_extra`; self-carriage (payout identity == carrier's) and `chain_id`. *(~µs, a few Keccak over <~1 KB)*
> 4. **R-1 target** — the **opened** `T_origin` (subtlety T below) == the consensus share difficulty pinned for `bin(receipt)`, and is non-zero. *(~ns, one 128-bit compare)*
> 5. **RandomX, LAST** — resolve the epoch seed for `bin`, `pow = rx_light_hash(seed, hashing_blob)`, require `pow ≤ T_origin` (Monero 128-bit `check_pow`). *(~10–15 ms — the only step that can cost real time)*
>
> Any failure ⇒ **receipt ignored, carrier stands** (the §3 miner-envelope altitude rule —
> invalid receipts never become a fork tool). On accept: insert `receipt_id` into the dedup
> store and perform the §4 push `push(miner, work(T_origin), flags|L0F_RECEIPT, bin(receipt))`.

This is p2pool's own order in `add_external_block`
(min-difficulty → expected difficulty → known mainchain parent `m_prevId` → seed lookup for
`m_txinGenHeight` → `get_pow_hash` → `check_pow`), with the RandomX call strictly last.

**Two load-bearing subtleties (both in `xmr_admission.hpp`):**

- **(D) The dedup key is NOT the PoW hash.** Family-A dedups on `header.hash`, which is its
  (free) PoW hash. Here the PoW hash is the expensive thing we are deferring, so dedup must key
  on `receipt_id = cheap_digest(hashing_blob)` — a plain digest, µs. This is sound: `prev_id`,
  `nonce`, and `tree_root` are all inside the blob and the whole coinbase (hence every
  commitment) is bound under `tree_root`, so distinct receipts have distinct blobs. **Deduping
  on the RandomX hash would defeat the entire inversion** — you would have to compute it to know
  whether to skip computing it.
- **(T) Structural (3) must precede R-1 (4).** `T_origin` has no header home (§B4); it is opened
  from `tx_extra` in step 3. The `T_origin` that gates the RandomX inequality in step 5 is that
  *opened, committed* value — never the relayed `info_digest` preimage — which closes the hole
  where a receipt advertises a favourable target in a preimage that does not match what the
  coinbase actually commits.

### B3.1 DoS budget (W3, NON-consensus)

An unauthenticated peer can force ~15 ms per bogus carrier ⇒ ~65 carriers/s saturate one
light-mode core. Mitigation (relay layer, never acceptance): a per-peer token bucket on
*unverified* carriers + ban on invalid PoW. p2pool does exactly this (bans on bad PoW; re-hashes
a failing share in forced light mode to flag *"UNSTABLE HARDWARE DETECTED"*). Because the order
above rejects replays/expiries/malformed receipts *before* RandomX, a peer can only burn a
verifier's RandomX budget with a receipt that already passed every cheap check — i.e. a nearly
valid one — which is the property the inversion buys.

---

## B4. `T_origin` from committed side data (no header home)

Bitcoin lanes read `T_origin` from `header.bits`. A Monero header carries no target. Therefore,
for `keyed_heavy` lanes:

- `T_origin` is a **128-bit Monero difficulty** (`difficulty_type`; `xmr_receipt.hpp::Difficulty`),
  not a compact "bits" target. `check_pow` semantics: `hash` passes at difficulty `d` iff the
  512-bit product `hash·d` has its high 256 bits zero (monero `check_hash_128`).
- `T_origin` is **committed in the v37 side data whose hash rides in the coinbase `tx_extra`**
  — the `0x03` merge-mining Merkle-tree leaf (p2pool commits `m_difficulty` in sidechain data →
  `m_sidechainId` → the MM tag; scoping OQ-X4 recommends the MM-tree leaf over the `0x02` nonce).
  It is *opened* in admission step 3 and *pinned* in step 4.
- **R-1 pinning is unchanged in meaning, only in source:** `T_origin` MUST equal the consensus
  share difficulty for `bin(receipt)`. What changes is *where the verifier reads it* (opened
  side data, not `header.bits`).
- The **per-worker extranonce** that makes each miner's template distinct sits inside the opened
  `tx_extra` (`0x02`, `EXTRA_NONCE_SIZE = 4`, grown to `EXTRA_NONCE_MAX_SIZE = 14`), not in a
  header nonce field — the 4-B header `nonce` is the RandomX search nonce.

---

## B5. Seed reference, epoch handling, and the index horizon

- **Bins are Monero mainchain blocks.** `bin(receipt) = height(prev_id)`; Monero targets 120-s
  blocks (`DIFFICULTY_TARGET_V2`), so `N_CTX = 2` ≈ 4 min of context — the direct analog of the
  Family-A origin-bin clock, on a finalized-height basis (§2 of the base doc).
- **RandomX seed / epoch.** The RandomX key is the Monero block hash at `seed_height(bin)`; it
  rotates every **2048 blocks** with a **64-block lag**. A receipt within `N_CTX = 2` bins can
  straddle an epoch boundary only when `bin mod 2048 ∈ {63, 64}`, so **two caches suffice**
  (current + previous), exactly as p2pool's `RandomX_Hasher` keeps two.
- **Seed-ref policy (OQ-X2).** `DerivedFromBin` (0 B on the wire, **default/recommended**): the
  verifier derives the seed from the committed index and *cannot disagree with it*.
  `CarriedSeedHash` (32 B, Tari style): the derived value MUST equal the carried one, else hard
  reject — the index wins, the wire is never trusted over it. Deriving is both cheaper and
  strictly safer, so the default is `DerivedFromBin`.
- **Index retention horizon — a distinct requirement.** Family-A needs the index back `N_CTX + 2`
  bins (the dedup horizon). `keyed_heavy` additionally needs it back far enough to resolve
  `seed_height(bin)`: `2048 + 64 = 2112` blocks. **The seed lag dominates**, so the committed
  `index_retention_blocks = 2112` (≈ 3.5 days of Monero blocks), not `N_CTX + 2`. This is the
  "mainchain index must reach ≥ 2112 blocks back" line of scoping §1.4.

---

## B6. Per-lane byte budget and `R_MAX` for the XMR lane

The Family-A budget row (§7) is *"receipt byte budget = R_MAX × 256 B"*. A `keyed_heavy` lane
overrides it with a digest-committed **per-lane** budget:

| quantity | value | basis |
|---|---|---|
| typical receipt | **615 B** | `RECEIPT_TYP` (blob 77 + seed 0 + opening 345 + branch 161 + info 32) — matches scoping "600–660 B [est]" |
| worst realistic receipt | **756 B** | `RECEIPT_MAX` (carried seed 32 + max opening 422 + depth-6 branch 193) |
| **per-receipt hard cap** | **768 B** | admits `RECEIPT_MAX` with ~12 B margin (see FINDING) |
| **`R_MAX_XMR`** | **2** | vs Family-A 4 |
| **per-lane budget** | **1536 B/carrier** | `R_MAX × 768` |

**FINDING (refines the scoping note).** The scoping "`R_MAX × ~700 B`" figure is a *typical*-case
size. The honest *worst* case — carried seed **and** a maximal Keccak prefix tail (135 B) **and**
a depth-6 tree branch — is **756 B**, which overshoots 700. A 700-B cap would reject legitimate
maximal receipts. The enforced per-receipt cap is therefore **768 B** (`3 × 256`). With the
default `DerivedFromBin` seed (0 B) the worst case is 724 B. This is `static_assert`-enforced in
`xmr_receipt.hpp` and exercised by `_compile_check.cpp` (615 B typical, 756 B max, 768 B cap).

**Why `R_MAX = 2` and not 4.** At `R_MAX = 4` the per-lane budget would be ~3 KB/carrier and the
RandomX join-replay cost scales with `1 + R_MAX`. `R_MAX = 2` halves both the wire budget
(1536 B, still above the Family-A "≤ ~1 KB/carrier" by design) and the worst-case verify rate
(`(1 + R_MAX)/share_interval` RandomX hashes/s) while leaving RDWR's anti-hoarding properties
intact (the `N_CTX` window, not `R_MAX`, bounds hoarding). Final value pending measurement (OQ-X2).

---

## B7. Whole-share pipeline delta (§8, for `keyed_heavy` lanes)

The §8 whole-share order is unchanged except that step 5 (`receipts[]`) uses the §B3 per-receipt
order instead of §3, dispatched on `pow_verify_class`
(`xmr_admission.hpp::verify_path_for`). Step 1 (the carrier's own header PoW) is itself a RandomX
verify on an XMR carrier — the same "carrier PoW before any receipt" rule (§2.4 item 1), and the
same cheap-pre-checks-first discipline applies to the carrier. Steps 2–4 (descriptor `valid()`,
share chaining, `message_data`) are family-agnostic, with one carry-over from the descriptor
leg: `PayoutDescriptor::valid()` gains a **prime-order-subgroup / torsion check** on Monero
payout points (scoping §16; p2pool `Wallet::torsion_check`) — that check lives in the descriptor
kinds leg, not in receipt admission, because the receipt binds identity via `info_digest`, not by
carrying the points.

---

## B8. Open questions (continues the base doc SF-OQ / scoping OQ-X numbering)

- **OQ-X2** (byte budget + seed ref) — *this addendum recommends* `R_MAX_XMR = 2`,
  `per_receipt_budget = 768 B`, `seed_ref_policy = DerivedFromBin`. Final `R_MAX`/budget pending
  a real Monero-block receipt-size distribution; open for operator ratification.
- **OQ-X3** (where each control lives) — *resolved here*: `pow_verify_class` + committed budget
  params are consensus (`LaneParams`, digest); the §B3.1 per-peer unverified-carrier token bucket
  is non-consensus (W3). Confirm at wiring.
- **X0 KAT (scoping §7)** — pin the Keccak-256 midstate resume at the `tx_extra` boundary against
  Monero `keccak.c` before this envelope ships (blocks §B2). Owned by sibling leg `x0-feasibility`.
- **SF-OQ4 (base doc)** — `info_digest` preimage minimalization applies unchanged to Family B;
  the Family-B preimage additionally must NOT be the authority for `T_origin` (subtlety T, §B3).
- **B-new-1** — the `receipt_id = cheap_digest(hashing_blob)` dedup key (subtlety D) should reuse
  the same digest primitive as the §5 store; confirm it is Keccak-256 (reuse the Monero hasher)
  vs SHA256d (reuse the Family-A store code) at wiring. Either is sound; picking the Monero hasher
  avoids a second hash dependency in the XMR node.

---

## B9. Cross-links

Base: `docs/c2pool-v37-share-format.md` §3/§4/§5/§7/§8. Scoping: `v37-monero-randomx-lane-scoping.md`
§1.4/§1.5/§2.4/§2.5/§3.2/§16, P-2, OQ-X2/X3. Sibling legs of this build: `monero-primitives`
(varint/blob decode, Keccak midstate, `tree_branch`), `randomx-vendor` (the `rx_check` light-verify
hook), `descriptor-kinds` (`XMR_STD`/`XMR_SUB` payout kinds + torsion check), `x0-feasibility`
(X0 KAT for the midstate opening), `license-manifest` (provenance for any ported source). Prior
higher-level doc: `v37/monero/c2pool-v37-monero-adaptation.md`. Precedents: SChernykh/p2pool
`side_chain.cpp` / `pool_block.h` / `block_template.cpp` / `pow_hash.cpp`; monero-project/monero
`cryptonote_format_utils.cpp` / `tree-hash.c` / `keccak.c` / `rx-slow-hash.c`; Tari `pow_data.rs`
(RFC-0132).
