# c2wallet-qt — Design Document

## 1. Goal & Non-Goals

### Goal

`c2wallet-qt` is a standalone, air-gapped Qt desktop wallet and transaction constructor for the frstrtr/c2pool ecosystem — the successor to the offline Python signer `tools/c2wallet/c2wallet.py`. It is the **key-holding, offline** side of a two-machine model: it imports keys, constructs and signs transactions, and self-verifies them, while a separate **online c2pool embedded daemon** performs script-verify / UTXO / policy validation and broadcast/injection. A Bitcoin-Core-like UI presents this over one wallet shell.

The wallet spans **two co-equal, first-class chain families that share almost nothing at the crypto layer**, and the architecture is built around that fact rather than treating one as a bolt-on:

- **Family A — Bitcoin-script (secp256k1 / hash160):** BTC, LTC, DOGE, DASH, DGB, BCH, NMC. ECDSA + Schnorr, Bitcoin script, base58check / bech32 / bech32m / CashAddr, BIP32/39/44 HD derivation, PSBT-like unsigned↔signed artifacts.
- **Family B — Monero / CryptoNote (Ed25519 / RingCT):** a first-class citizen per the operator's MONERO-FIRST beachhead directive, **not deferred**. Dual spend/view keypair, one-time stealth outputs, RingCT + CLSAG + key images, ring/decoy selection, 25-word Monero mnemonic (and optional polyseed), Monero base58, subaddresses and integrated addresses, and Monero's native cold-signing flow.

The two families are abstracted under one wallet/UI shell but are implemented as fully separate backends. They diverge at the curve (secp256k1 vs Ed25519), the seed scheme (BIP39 vs 25-word/polyseed), the address algebra (hash160 vs stealth one-time keys), and the keypair cardinality (one private key vs a spend+view pair). The family is resolved **before** any format parsing or address handling — it is a design invariant, not a runtime branch deep in the code.

The operator requirements the design must satisfy:

1. Import **any** key format for both families.
2. Construct and **spend every** script/output type, including exotic and historically-bugged ones (Family A) and RingCT spends (Family B).
3. Validate the unsigned/constructed transaction via the online c2pool embedded daemon **before** signing/broadcast.
4. An air-gapped security model with a network-incapable signing build.
5. **Cross-coin address conversion within Family A** (LTC↔DOGE and the wider secp256k1/hash160 set) with a hard money-misdirection guard (issue #961).

Baseline parity floor — **two** proven precedents the successor must strictly **extend, never regress**:

1. The DASH donation block **2518186** (1040 inputs → 4 outputs, P2PKH) signed by `c2wallet.py`.
2. The **LTC+DOGE donation** — a **bare-P2MS wrapped in P2SH** (P2SH-multisig) spend, the reference for the wrapped/nested script path (§4.1) and the cross-coin merged-payout algebra.

RFC6979 deterministic nonce, self-verify-before-emit, oversize refusal, and seed-never-persisted are non-negotiable inherited behaviours across both.

### Non-Goals

- **No online validation, broadcast, or key custody on a networked host.** The signer never opens a socket; c2pool never holds a key or signs.
- **Cross-coin address conversion does not cross the secp256k1↔Ed25519 boundary.** Requirement (5) is Family-A-only. Any attempt to convert a Bitcoin-family address to/from a Monero address is refused at the family layer.
- **BCH is in scope for construct/spend but excluded from cross-coin conversion** — CashAddr is a different encoding, not a prefix swap; the converter must detect and refuse it.
- **Monero N/M multisig (MMS) is in scope for v1** (locked 2026-09-12; delivered as the M4-X-MMS phase in §6, sequenced after single-sig RingCT); Bitcoin-family multisig (P2MS/P2SH) is fully in scope.
- Not a general online wallet, block explorer, or pool control panel — that is the existing `c2pool-qt` application, which is deliberately a separate, network-linked binary.

---

## 2. Architecture

### 2.1 The offline/online split

```
   OFFLINE — c2wallet-qt-signer (holds keys)          ONLINE — c2pool embedded daemon + companion (no keys)
   ─────────────────────────────────────────          ──────────────────────────────────────────────────────
                                       ◀── (1) UNSIGNED / constructed artifact ──   built from live UTXO / chain view
   import keys, derive, DISPLAY summary,
   operator CONFIRMS, sign, SELF-VERIFY
                (2) SIGNED artifact ──▶                                            re-validate (gate), then inject / broadcast
```

- **Keys live only inside the offline `c2wallet-qt-signer` build.** That binary is compiled network-incapable (§5). The seed/private keys never touch a networked or agent-controlled host, and never persist in plaintext.
- **c2pool is verify-only by construction.** Investigation confirmed there is no signing key class anywhere in the tree — no `CKey`, no ECDSA/Schnorr sign, no key-image generation. c2pool operates only on already-signed bytes and re-validates every artifact regardless of origin. It is the script-verify / UTXO / policy authority; it is never a signer.
- **Two artifacts cross the gap, both public data:** an unsigned/constructed artifact (online→offline) and a signed artifact (offline→online). Transport is file or QR — the same channel the donation ceremony proved.

### 2.2 The chain-family abstraction

The wallet shell is a thin, family-agnostic UI and orchestration layer over two backends that implement a common wallet interface but share no crypto code:

```
                    ┌─────────────────────────────────────────────┐
                    │  Qt Widgets shell (MainWindow + sidebar +    │
                    │  Page* screens, SettingsStore, artifact I/O) │
                    │  Bitcoin-Core-like UI, family-agnostic       │
                    └───────────────┬─────────────────────────────┘
                                    │  IChainFamily (import / scan / construct / sign / verify / export)
                    ┌───────────────┴───────────────┐
       ┌────────────▼────────────┐     ┌────────────▼─────────────────┐
       │  Family A backend        │     │  Family B backend             │
       │  secp256k1 / Bitcoin     │     │  Ed25519 / CryptoNote         │
       │  script                  │     │  (Monero)                     │
       └──────────────────────────┘     └───────────────────────────────┘
```

The `ImportedSecret` type is opaque, zeroizing, and **family-tagged**; requirement (5) conversion lives entirely inside the Family A backend and is refused at the family boundary as a type-level invariant.

### 2.3 Module layout

New sibling tree `ui/c2wallet-qt/`, sharing the toolchain with the shipped `ui/c2pool-qt/` app but linking a deliberately minimal, network-incapable set. It reuses c2pool-qt's shell **patterns** (MainWindow + sidebar + `Page*` idiom, `SettingsStore`) and links the node's **Qt-free leaf headers** directly, exactly as c2pool-qt already does via `C2POOL_NODE_SRC = ../../src`.

```
ui/c2wallet-qt/
  CMakeLists.txt            # Qt6::Core/Gui/Widgets ONLY — NO Network/WebEngine/WebChannel
  src/
    shell/                  # MainWindow, sidebar, Page* (Overview, Import, Construct,
                            #   Convert, Sign/Export, Validate, Settings), SettingsStore
    family/
      IChainFamily.hpp      # common backend interface
      bitcoin/              # Family A backend
        hdkeys/             # NEW: BIP39/32/44/49/84/86, WIF, raw-hex, keystore import
        sighash/            # legacy (reuse) + BIP143 + BIP341/342 (NEW)
        signer/             # NEW: CKey / ECDSA + Schnorr signing, self-verify
        construct/          # per-type scriptSig / witness assembly, cross-coin convert
      monero/               # Family B backend
        seed/               # NEW: 25-word mnemonic, polyseed, key/view import
        scan/               # output scanning (reuse xmr_derivation) + amount decrypt
        prover/             # NEW/PORT: CLSAG signer, Bulletproofs+ prover, key images
        addr/               # NEW: Monero base58, subaddress, integrated address
    artifact/               # PSBT-like container (A) + monero unsigned/signed_txset (B), QR codec
    secure/                 # SecureString, mlock, explicit_bzero, seccomp belt
```

### 2.4 Reuse vs new (cited from the reuse inventory)

**Link directly (leaf, Qt-safe — the seam was already carved out for exactly this by the #961 refactor):**

| Building block | c2pool source |
|---|---|
| Address encode/decode all Bitcoin-script types (P2PKH/P2SH/P2WPKH/P2WSH/P2TR/P2PK/bare-P2MS) | `src/core/address_utils.{hpp,cpp}`, `src/btclibs/{base58.h,bech32.h}` |
| Cross-coin conversion + #961 guard (`decide_payout_address`, `classify_address_for_coin`, `CoinAddressAcceptance`, `MergedChainAddr`) | `src/core/address_utils.hpp` |
| Per-coin address SSOT (version bytes / HRPs), explicitly "shared with c2pool-qt" | `src/impl/{btc,ltc,dash,dgb,bch}/**/address_encoding.hpp`, `src/impl/doge/coin/address_encoding.hpp` |
| BCH CashAddr codec (the non-convertible boundary) | `src/impl/bch/coin/cashaddr.hpp` |
| Legacy script interpreter + `SignatureHash` + `CScript` + opcode table (incl. `OP_CHECKMULTISIG`, `OP_CHECKSIGADD`), P2SH/P2MS eval | `src/impl/dash/coin/vendor/dashscript/{script,primitives}/*` — **`SigVersion::BASE` only** |
| Segwit-aware tx (de)serialization (`TxParams`, witness marker/flag, LTC MWEB) | `src/impl/bitcoin_family/coin/base_transaction.hpp` |
| `CPubKey` verify / recover / hash160 | `src/impl/dash/coin/vendor/dashscript/pubkey.{h,cpp}` |
| Hash primitives (sha256/512, ripemd160, hmac_sha512, scrypt) | `src/btclibs/crypto/*` |
| libsecp256k1 (system-linked; headers incl. `extrakeys`, `recovery`, `schnorrsig`) | `src/impl/dash/coin/vendor/dashscript/secp256k1/` |
| Monero curve engine: Ed25519 group/scalar ops, Keccak, stealth derivation, RCT ops, verifiers | `src/impl/xmr/coin/vendor/*`, `xmr_derivation.*`, `native/rct/xmr_rct_ops.*`, `xmr_rct_verify.*`, `xmr_bulletproofs_plus.*` |

**Build new (nothing in-tree signs; the interpreter is legacy-only; c2pool never spends XMR):**

- **Family A:** `CKey` / ECDSA signing (or keep `c2wallet.py`'s audited pure math as the signer core), **BIP143 (segwit v0) sighash + witness serialization**, **BIP341/342 taproot** (Schnorr signing, taptweak, tapleaf/branch, control block, tapscript eval), a **`hdkeys` module** (BIP39 with real checksum + multi-language wordlists, BIP32 CKD, xprv/xpub + SLIP-132, WIF decode, raw-hex, BIP38, descriptor import), and the **PSBT-like artifact**.
- **Family B:** **CLSAG signer** and **Bulletproofs+ prover** (port from monero-project BSD-3 onto the vendored `crypto-ops.c` / `xmr_rct_ops`), **key-image generation**, **Monero base58**, **25-word mnemonic (+CRC)**, **subaddress / integrated-address** derivation, output-scanning wallet state, and the `unsigned_txset` / `signed_txset` / outputs / key-image containers.

The critical seam: c2pool ported exactly the *verify* half of both families. c2wallet-qt is the **prover/signer** half. The correctness win is that both halves sit on the same vendored math, so the new prover code can be KAT-gated by constructing then verifying against the in-tree verifier.

---

## 3. Key-Import Design

The importer is a **two-layer dispatcher: crypto family first, then format.** The UI resolves family before it can even validate a string. Type spine:

```
ImportedSecret            (opaque, zeroizing, family-tagged)
 ├─ FamilyA_Secret        secp256k1 scalar(s) + compressed flag + optional HD context
 └─ FamilyB_Secret        {spend_priv, view_priv}  (+ view-only: {spend_pub, view_priv})
KeyCandidate = (family, privkey|none, pubkey, [address candidates per enabled coin/type])
```

**Fail-before-secret-entry law (inherited from `c2wallet.py` `sign-batch`):** validate the entire import form — files, paths, target coin — *before* accepting the secret. Every extra secret prompt is a chance to type it into the wrong window.

### 3.1 Family A formats

| Format | Map | Effort | Notes / validation |
|---|---|---|---|
| **BIP39 mnemonic (+passphrase)** | words → checksum-verify → PBKDF2-HMAC-SHA512(2048, "mnemonic"+passphrase) → BIP32 master → derive | LOW (port + extend) | Ship all languages (EN mandatory; JP needs NFKD + ideographic-space join). **Add the real BIP39 checksum** — baseline only counts words. Surface the passphrase silent-fork hazard (empty vs wrong both yield a valid but different wallet); show a first-address fingerprint. |
| **BIP32 xprv / xpub + path** | base58check decode → node; **xpub → watch-only** first-class | LOW–MED | Recognise xprv/xpub **and** SLIP-132 (yprv/zprv/Yprv/Zprv, per-coin analogues); a zpub hints P2WPKH intent. Refuse hardened derivation from an xpub with a clear reason. |
| **Derivation-path selection** | presets BIP44 (P2PKH) / BIP49 (P2SH-P2WPKH) / BIP84 (P2WPKH) / BIP86 (P2TR) + custom path + account/change/index ranges | LOW–MED | coin_type from SLIP-44; allow forcing (old p2pool keys used coin_type 0 and uncompressed keys — try compressed+uncompressed as baseline does). |
| **WIF** | base58check → strip per-coin version byte → 32-byte scalar; trailing `0x01` ⇒ compressed | TRIVIAL | Source version bytes from `address_encoding.hpp`, not re-hardcoded. Detect a mismatched version byte and offer in-family conversion, warning it is a distinct on-chain identity per coin. |
| **Raw hex privkey** | 64 hex → scalar; **range-check `1 ≤ k < N`** | TRIVIAL | New check (baseline never imports raw hex); reject 0 and ≥N. Default compressed, user-toggle; scan both address sets. |
| **BIP38 encrypted key** | scrypt (vendored) + EC-multiply/non-EC + AES-256 | LOW | Only new dep is AES. CPU-bound by design — show progress. |
| **Core descriptors (`listdescriptors`)** | parse `wpkh/tr/sh(wsh(multi(...)))` with `[fingerprint/path]` + `/*` | MED | **Recommended primary advanced path** — one descriptor expresses key + script type + derivation + range; maps directly onto the type system, reuses `address_utils`. |
| **Electrum / wallet.dat / generic JSON keystore** | — | MED–HIGH | **Defer full parse.** v1: import the xprv Electrum shows, or `dumpwallet`/`dumpprivkey` WIFs. |

**Address-candidate generation:** one derived secp256k1 privkey → pubkey (compressed **and** uncompressed) → per-type candidate scriptPubKeys: P2PK (both encodings), P2PKH, P2SH-P2WPKH, P2WPKH, P2TR key-path (x-only via `secp256k1_extrakeys`). P2SH/P2WSH/bare-P2MS are script-defined, supplied by the constructor.

### 3.2 Family B (Monero) formats — separate engine, none of §3.1 applies

Each maps to `(spend_priv, view_priv)` (+ derived `spend_pub`, `view_pub`):

- **25-word Monero mnemonic** (electrum-style, 1626-word list, 24 words + a CRC32 checksum word): decodes the private spend key; `view_priv = H_s(spend_priv)`. Multiple languages, each with its own autocomplete prefix length. **Build from scratch** (absent from tree); Keccak is reusable.
- **polyseed** (16-word, birthday + optional passphrase, Argon2): **build if adopted** — open decision.
- **Raw dual keys** — paste `spend_priv` + `view_priv` (32-byte hex each).
- **View-only import** — `spend_pub` + `view_priv` (+ primary address): scans/decrypts incoming outputs but **cannot sign**. This is the exact half that maps to the air-gap model (online = view-only, offline = full).
- **13-word MyMonero** variant — optional.
- **monerod `.keys` keystore** (ChaCha20 + slow-hash KDF): **defer**; v1 imports mnemonic/keys directly.

**Address candidates:** standard = base58(`netbyte ‖ spend_pub ‖ view_pub ‖ keccak_checksum[0:4]`); subaddresses (`m = H_s("SubAddr\0" ‖ view_priv ‖ major ‖ minor)`, `K_s^(i,j) = K_s + m·G`, `K_v^(i,j) = view_priv·K_s^(i,j)`, netbyte 42); integrated (standard + 8-byte payment ID, netbyte 19). Monero base58 + subaddress derivation are **new** (absent from the xmr lane).

### 3.3 Scan UX (Bitcoin-Core-like), air-gap-correct

One mnemonic → hundreds of addresses across {BIP44/49/84/86} × accounts × {external/change} × index range × {compressed/uncompressed}. Default scan: all four purposes, account 0, both chains, index 0–19, gap-limit 20; grouped by script type. **The offline signer can only enumerate candidate addresses — balances come from the online side:** the offline wallet exports its public address set (xpub or address list), the online c2pool node returns which are funded, and that funded set drives which paths get signed. The seed never leaves the offline box. Keep `find-key` parity (prove which path owns an address, both encodings tried) and a custom-path escape hatch for old/nonstandard keys.

### 3.4 Key GENERATION (new air-gapped wallets)

Import alone cannot create a fresh air-gapped wallet — the offline signer must also **generate** a new seed on the offline box. Source: the operator's `frstrtr/mnemonic_gen` (operator-owned; relicensed into c2pool AGPL on port).

- **Family A — new BIP39 mnemonic.** Generate a fresh 24-word (or 12/15/18/21-word) BIP39 mnemonic with a real checksum, then run it straight through the §3.1 derivation path. **HARD FLAG:** `mnemonic_gen` is self-labelled "educational / not for real funds" and uses a demo RNG; the port MUST replace it with a **vetted CSPRNG** (`getrandom(2)` / `BCryptGenRandom`) and compute the **real BIP39 checksum** — the demo RNG is never used for entropy that guards funds.
- **Family B — new Monero seed.** The analog: generate a fresh Monero 25-word mnemonic (and, per the seed-format lock, polyseed) from vetted CSPRNG entropy, feeding the §3.2 spend/view derivation.
- **Split / shuffle seed backup (port from `mnemonic_gen`).** Split a 24-word mnemonic into two 12-word shares (even/odd index positions) and apply the reversible secure shuffle (PBKDF2 → HMAC-DRBG Fisher-Yates over the wordlist, keyed by password + a 24-word salt mnemonic; `gen.py` / `ungen.py`). Round-trip (gen → ungen recovers the original 24 words from password + salt mnemonic) is a mandatory KAT. Optional **QR / printable annotated-image export** of the seed and shares for paper backup. **See the §7 risk flag** — this is custom cryptography, not SLIP-39, and needs independent review before it guards real seeds.

---

## 4. Construct + Spend Matrix

Two tracks. This is the money-correctness core of the whole wallet.

### 4.1 Track A — Bitcoin-script

Notation: `<sig>` = DER-ECDSA sig ‖ 1-byte sighash; `<schnorr>` = 64/65-byte BIP340 sig; `H160` = RIPEMD160(SHA256(pubkey)); `H256` = SHA256(script).

| Type | scriptPubKey | Spend (scriptSig / witness) | Sighash | The trap |
|---|---|---|---|---|
| **P2PK** | `<push 33\|65> <pubkey> OP_CHECKSIG` | scriptSig: `<sig>` (no pubkey — it is in the output) | legacy BASE | The output commits to exact pubkey bytes — an uncompressed-key output MUST be spent citing the 65-byte form. Try both encodings per index (baseline already does). |
| **P2PKH** | `OP_DUP OP_HASH160 <H160> OP_EQUALVERIFY OP_CHECKSIG` | scriptSig: `<sig> <pubkey>` | legacy BASE | **Parity path** (block 2518186). Wrong pubkey encoding → H160 mismatch. |
| **P2SH** | `OP_HASH160 <H160(redeemScript)> OP_EQUAL` | scriptSig: `<inner-satisfaction> <push redeemScript>` (redeemScript LAST) | legacy BASE over the **redeemScript** as scriptCode | Classic pitfall: signing over the P2SH SPK instead of the redeemScript; `SCRIPT_VERIFY_P2SH` re-executes the redeemScript. |
| **Bare P2MS** (the CHECKMULTISIG extra-pop bug) | `OP_m <pk1..pkn> OP_n OP_CHECKMULTISIG` | scriptSig: **`OP_0 <sig1>..<sigM>`** | legacy BASE | The leading `OP_0` is the off-by-one dummy the opcode over-pops. Under `SCRIPT_VERIFY_NULLDUMMY` it MUST be an **empty push**, not `OP_1`. Sigs MUST be in the **same relative order as the pubkeys** (CHECKMULTISIG scans top-down, no backtrack). Non-standard n≤3 relay limit is irrelevant — c2pool injects into its own template. |
| **P2SH-multisig** | P2SH over the §bare-P2MS redeemScript | `OP_0 <sig1>..<sigM> <push redeemScript>` | legacy over redeemScript | Same dummy + ordering rules. |
| **P2WPKH** | `OP_0 <H160(compressed pubkey)>` | witness: `<sig> <compressed pubkey>`; scriptSig empty | **BIP143** | **Compressed keys only** (`WITNESS_PUBKEYTYPE`). Legacy sighash here = no amount commitment = invalid + replay exposure. **NEW code.** |
| **P2WSH** | `OP_0 <SHA256(witnessScript)>` | witness: `<inner-satisfaction> <witnessScript>` | BIP143, scriptCode = witnessScript | Use SHA256 (not hash160) for the program. NEW. |
| **P2SH-P2WPKH / P2SH-P2WSH** | P2SH where redeemScript = the witness program (`OP_0 <20\|32>`) | scriptSig: one push (the program); witness carries `<sig> <pubkey>` / satisfaction | BIP143 | Sig data goes in the witness, not the scriptSig; forgetting the program push fails. NEW. |
| **P2TR key-path** | `OP_1 <32 tweaked key Q>`, `Q = P + int(H_tapTweak(P‖merkle_root))·G` | witness: single `<schnorr sig>` (64B for SIGHASH_DEFAULT, 65B with explicit byte) | **BIP341**, `SIGHASH_DEFAULT=0x00` | Must sign with the **tweaked** key `d' = d + tapTweak` (even-Y normalise both P and Q); commits to **all** spent outputs' amounts+SPKs via `sha_amounts`/`sha_scriptpubkeys` — the wallet must collect every prevout, not just the signed one. Needs secp256k1 `schnorrsig`+`extrakeys`. **All NEW.** |
| **P2TR script-path** | same `OP_1 <32 Q>` | witness: `<tapscript-stack> <tapscript leaf> <control block>` | **BIP342** tapscript | Control block = `(0xc0 \| parity(Q)) ‖ <32 internal P> ‖ <merkle path>`. Leaf sig is Schnorr over the **untweaked** leaf key (no taptweak). `tapleaf_hash` = tagged `TapLeaf`; `TapBranch` folds lexicographically-sorted pairs. Parity bit / sort order / tag are the traps. **All NEW.** |
| **Nonstandard ancestors** | CLTV/CSV timelocks, hashlocks | generic P2SH/P2WSH; interpreter has `OP_CHECKLOCKTIMEVERIFY`/`OP_CHECKSEQUENCEVERIFY` | as inner type | Allow raw-redeemScript entry. |
| **OP_RETURN** | `OP_RETURN <data>` | — unspendable | — | Build as output only, never a spend source. |

**Wrapped & nested scripts (first-class).** Wrapping is not a side case handled only by the P2SH/P2WSH table rows — it is a first-class capability spanning **construct + spend + manipulate**, because it is the exact pattern of the LTC+DOGE donation (a bare-P2MS wrapped in P2SH). The model is an **inner-script × wrapping-container** product: the wallet treats an arbitrary inner script as one axis and the container that wraps it as the other, and can build every cell of the product — so multisig-in-P2WSH, timelock-in-P2SH, and multisig-in-a-P2TR-tapleaf are all expressible from the same primitive.

**Wrapping containers (the outer shell — each wraps an arbitrary inner script):**

1. **P2SH(inner)** — `base58check(version ‖ hash160(redeemScript))`.
2. **P2WSH(inner)** — `bech32(SHA256(witnessScript))`.
3. **Nested P2SH-P2WSH(inner)** — `base58check(version ‖ hash160(OP_0 ‖ SHA256(witnessScript)))`.
4. **P2TR script-path(inner) — first-class taproot-script container.** The inner script is a **tapleaf**, and the container is a full **tap tree**: one taproot output can commit **multiple alternative spending scripts** (leaves), Merkle-folded via `TapBranch` (lexicographically-sorted pairs of tagged hashes) into a single merkle root. The address is the tweaked output key `Q = P + int(H_tapTweak(P ‖ merkle_root))·G`, bech32m-encoded (`OP_1 <32B Q>`). The internal key `P` is either a **NUMS point** ("provably no key-path", script-path-only) or a **real key** (so the same output offers a key-path OR any committed script-path). Spend of a chosen leaf = `<tapscript-stack> <tapleaf script> <control block>`, where the control block = `(0xc0 | parity(Q)) ‖ <32B internal key P> ‖ <merkle path to that leaf>`.

**Inner-script axis (the thing being wrapped — usable inside ANY container above):**

- **bare-P2MS multisig** (`OP_m <pks> OP_n OP_CHECKMULTISIG`) for legacy/segwit-v0 containers; its tapscript analog is the CHECKSIGADD form (see the trap below).
- **CLTV / CSV timelocks** (`OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY`).
- **Hashlocks / HTLC** (`OP_HASH160`/`OP_SHA256` + `OP_EQUALVERIFY`, timelock-branched).
- **Arbitrary raw scripts** — operator-entered redeemScript/witnessScript/tapleaf.

Short container × inner matrix (relay standardness vs inject-only; c2pool injects into its own template, so inject-only combos are fine there):

| Inner ↓ / Container → | P2SH | P2WSH | P2SH-P2WSH | P2TR script-path |
|---|---|---|---|---|
| multisig | standard (small n) | standard | standard | **CHECKSIGADD** (standard) |
| CLTV/CSV timelock | standard | standard | standard | standard leaf |
| hashlock / HTLC | standard | standard | standard | standard leaf |
| arbitrary raw | inject-only | inject-only | inject-only | inject-only |

- **Address CREATION from an arbitrary inner script.** For the base58/bech32 containers the wallet computes the receive address directly from the inner script (formulas above) without spending yet. For **P2TR script-path** it builds the tap tree from one or more inner leaves, folds the merkle root, tweaks the internal key, and emits the bech32m address. The operator can build the wrapped ADDRESS to receive into, save the inner script(s)/tap tree, and spend later.
- **SPEND a wrapped output.** P2SH → scriptSig = `<inner-satisfaction> <push redeemScript>` (redeemScript pushed **last**); sighash is legacy BASE over the **redeemScript as scriptCode**; `SCRIPT_VERIFY_P2SH` re-executes the redeemScript. P2WSH → witness = `<inner items> <witnessScript>`; **BIP143** sighash with `scriptCode = witnessScript` (SHA256, not hash160, for the program). Nested **P2SH-P2WSH** → scriptSig carries the single witness-program push (`OP_0 <32-byte SHA256(witnessScript)>`), and the witness stack carries the satisfaction. **P2TR script-path** → witness = `<tapscript-stack> <tapleaf script> <control block>`; **BIP342** tapscript sighash, each leaf signature a BIP340 Schnorr sig over the **untweaked** leaf key. When the inner script is **bare-P2MS** (legacy/segwit-v0 only), the inner satisfaction follows the CHECKMULTISIG rules: leading `OP_0` dummy as an **empty push** under `SCRIPT_VERIFY_NULLDUMMY`, and signatures in the **same relative order as the pubkeys**.
- **Taproot-multisig TRAP (money-correctness).** `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` are **DISABLED in tapscript (BIP342)** — a taproot script-path multisig MUST instead use **`OP_CHECKSIGADD`**: a k-of-n leaf is `<pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD ... <pkn> OP_CHECKSIGADD <k> OP_NUMEQUAL`, each participating signer supplying a BIP340 Schnorr sig and each **unused-signer slot filled with an empty-vector placeholder** (not omitted). This is a completely different assembly from the bare-P2MS `OP_0`-dummy CHECKMULTISIG path (which is legacy/segwit-v0 only). The reuse table already notes the interpreter carries `OP_CHECKSIGADD`.
- **MANIPULATE (multi-party partial-sign + combine) — across ALL containers.** A wrapped multisig input is signed cooperatively: each cosigner partial-signs independently against the shared inner script, and the wallet **combines** the collected partials into the final satisfaction. This applies to **every** wrapping container, not just bare-P2SH-multisig: the `OP_0 <sig1>..<sigM>` scriptSig (P2SH-multisig, the LTC+DOGE donation pattern), the equivalent witness stack (**P2WSH-multisig** and **P2SH-P2WSH-multisig**), and the **P2TR-tapscript CHECKSIGADD** witness (Schnorr partials slotted in signer order, empty-vector placeholders for absent signers). This is the PSBT-style combine on the A-track.
- **Reuse vs new.** P2SH/P2WSH address encode comes from `address_utils`, and the P2SH/P2WSH/tapscript re-execution is the vendored interpreter (P2SH/P2WSH already in-tree; taproot leaf eval and `OP_CHECKSIGADD` per the BIP342 additions of §4.1's taproot rows). The wrapping **assembly** — deriving each container address from one or more inner scripts (incl. tap-tree merkle folding + taptweak), and building/combining the layered scriptSig/witness/control-block across all containers — is new constructor code.

**Sighash flags:** `SIGHASH_ALL(1)` / `NONE(2)` / `SINGLE(3)`, each `| ANYONECANPAY(0x80)`; taproot adds `SIGHASH_DEFAULT(0x00)`. **The `SIGHASH_SINGLE` bug** (if `in_idx ≥ n_outputs`, legacy sighash returns the constant `0x00…01` digest) must be reproduced for correctness **and warned**. Default everywhere = `SIGHASH_ALL` (baseline). Preserve the self-verify-before-emit and 100 kB oversize refusal for **every** type, not just legacy P2PKH.

**Cross-coin address conversion (requirement 5).** Algebraic fact: every Family-A coin uses the same secp256k1 curve, the same `hash160` for P2PKH/P2WPKH, the same `SHA256(script)` for P2WSH, and the same x-only key for P2TR — so the **payload is byte-identical across coins**; conversion is purely a re-encoding under the target's version byte / HRP **iff the target supports that type**. This is the LTC↔DOGE merged-payout algebra.

Convertibility (SSOT = the per-coin `address_encoding.hpp` leaves):

| Coin | P2PKH ver | P2SH ver | segwit HRP | taproot |
|---|---|---|---|---|
| BTC | 0x00 | 0x05 | `bc` | yes |
| LTC | 0x30 | 0x32 (+legacy 0x05) | `ltc` | yes |
| DOGE | 0x1e | 0x16 | — | no |
| DASH | 0x4c | 0x10 | — | no |
| DGB | 0x1e | 0x3f | `dgb` | yes |
| BCH | 0x00 (legacy) | 0x05 (legacy) | **CashAddr, not bech32** | no |
| NMC | 0x34 (needs SSOT leaf) | 0x0d | — | no |

- **P2PKH / P2SH (base58 version-byte swap):** SAFE across BTC↔LTC↔DOGE↔DASH↔DGB↔NMC. Prefer LTC's modern P2SH byte (`0x32`) on re-encode.
- **P2WPKH / P2WSH (bech32 HRP swap):** SAFE only among BTC↔LTC↔DGB.
- **P2TR (bech32m HRP swap):** SAFE only among BTC↔LTC↔DGB (taproot-active).

**REFUSE (the #961 guard):** (a) **BCH is never a prefix swap** — CashAddr is a different encoding; transcode through the payload or refuse; BCH has no segwit/taproot equivalent for `bc1…`/`bc1p…`. (b) **Type absent on target** (segwit/taproot → DOGE/DASH/NMC/BCH). (c) **mainnet↔testnet** silent conversion. (d) **source is Foreign/Invalid** to its claimed source coin.

Conversion algorithm (direct lift of `classify_address_for_coin` + `CoinAddressAcceptance` + the `Own/Foreign/Reject` trichotomy of `decide_payout_address`): decode+classify under the source SSOT (must be `Own`), extract `{type, payload}`, capability-gate the target, re-encode under the target SSOT, then **mandatory round-trip proof** — decode the result under the target SSOT and assert it is `Own` and the payload matches. The UI displays **source payload = target payload (hex) side by side** before any convert is accepted; a wrong conversion is a fund misdirection, so a human confirms the hash160/program is unchanged. Gaps to fill: an **NMC SSOT leaf header** (Namecoin chainparams, no segwit) and a **BCH↔base58 transcode helper** on top of `cashaddr.hpp`.

#### 4.1.1 DASH special transaction: governance-proposal collateral builder

A specialized, first-class DASH-lane feature ported from the operator's `frstrtr/dash-proposal-collateral` (Python, MIT; relicensed into c2pool AGPL on port). It builds and signs the **1-DASH proof-of-burn collateral transaction** a Dash governance proposal requires, entirely offline. It is not a generic spend — it is a fixed OP_RETURN-burn template:

- **Compute the gobject collateral hash byte-exactly** (port `proto_hash.py`): `hashParent` (32 raw LE bytes) ‖ `revision` (int32 LE) ‖ `time` (int64 LE) ‖ `HexStr(vchData)` (compactsize + lowercase-hex ASCII) ‖ null `masternodeOutpoint` (32×00 ‖ `ffffffff`) ‖ dummy `uint8_t{}` ‖ `0xffffffff` ‖ empty `vchSig` (`00`), double-SHA256. Verified byte-exact against Dash Core `governance/common.cpp` `GetHash()` and proven against live mainnet objects.
- **Assemble the tx** (port `dash_collateral_tx.py`): output 0 = `1.00000000 DASH` → `OP_RETURN <collateral_hash>` (the hash in **internal/reversed** byte order, per `object.cpp` `IsCollateralValid()`); output 1 = change to the funding address. Coins selected largest-first; coinbase outputs younger than 101 confirmations skipped.
- **Funding-key scan with hard-abort on mismatch:** scan `m/44'/5'/0'/{0,1}/i` for the key whose P2PKH address **equals** the funding address (match double-checked through an independent base58 impl); **hard-abort** if no index matches, if any UTXO scriptPubKey is not P2PKH of the funding address, on wrong network, bad checksum, or `--expected-hash` mismatch.
- **Security model is already ours:** always-first dry-run summary, SIGHASH_ALL / RFC6979 / DER / low-S, per-signature self-verify before emit, typed `SPEND` confirmation, mnemonic via hidden input (never stored/logged), private-key zeroize. A direct fit for the air-gap model — the only stdout is public data (hash, summary, signed hex).
- **Port note:** re-implement the byte-exact logic in the C++ DASH modules with **KATs that treat the proven Python as the golden reference** (construct in C++ → compare to the Python reference vectors, which are themselves proven against mainnet).

#### 4.1.2 Message sign / verify

Port `sign_message.py`: sign an arbitrary message with a wallet key and verify a signature, in the Bitcoin/Dash signed-message format (Dash uses the legacy `DarkCoin Signed Message:\n` magic; double-SHA256 over `varstr(magic) ‖ varstr(message)`; 65-byte recoverable compact signature with the compressed-key header offset, low-S enforced). **Self-verify by public-key recovery** — the recovered pubkey must hash to the signing address before the signature is emitted, so a wrong key/derivation cannot produce a bad signature. Used e.g. for DashCentral proposal-ownership claims.

### 4.2 Track B — Monero

**Key model:** dual keypair `(k_s, k_v)`, `K_s=k_s·G`, `K_v=k_v·G` (standard `k_v=H_s(k_s)`). Standard/integrated/subaddress addresses per §3.2. Network bytes carried per-net (main/stage/test) and mismatch refused — the Monero analog of the #961 guard.

**Output scanning (reuse `xmr_derivation`):** for each tx pubkey `R`, `D = 8·k_v·R`; per output `i`, fast-reject via `derive_view_tag(D,i)`; if `derive_public_key(D,i,K_s) == P_i` the output is ours; one-time secret `x_i = H_s(D‖i) + k_s (mod l)` (needs `k_s` → full wallet only); amount decrypted via two Keccak calls + xor; key image `I_i = x_i·H_p(P_i)`. Subaddress scan uses a precomputed spend-key table. **View-only computes everything except the key image** — the reason cold-signing exists.

**Spend construction (the prover — the hard, must-build part):**

1. Input selection over owned unspent outputs.
2. **Decoy/ring selection** (ring size 16 = 15 decoys) via monerod's gamma distribution — **stays on the ONLINE side**; the unsigned artifact carries the frozen ring members (monero's `unsigned_txset` already does this).
3. **Pseudo-output + output Pedersen commitments** `C = x·G + a·H`, masks balanced so `Σ C_in(pseudo) − Σ C_out − fee·H = 0` (reuse generators G/H, sc/ge ops).
4. **Bulletproofs+ range proofs** over output amounts — **PORT the prover** (verifier only in-tree).
5. **CLSAG signatures** per input (proves knowledge of `x_i` and `I_i = x_i·H_p(P_i)` without revealing the real member) — **PORT** (absent entirely).
6. **Key images** — build (one line on vendored ops).
7. **Fee** = size · per-byte-rate · priority; base rate from the online node.
8. **tx_extra** (tx pubkey(s) `0x01`/`0x04`, encrypted payment-id nonce for integrated/subaddress).
9. Serialize to CryptoNote blob + tx_hash (reuse `xmr_blob`, keccak midstate).

Crypto sourcing: Ed25519 field/group, Keccak, H_s, H_p, Pedersen generators, multiexp = **reuse**; CLSAG signer + BP+ prover = **port from monero-project BSD-3 onto the vendored ops**; key-image + Monero base58 + mnemonic + subaddress = **new**; ring selection = **online**. Strong correctness harness the Bitcoin side never had: construct → verify with the in-tree `xmr_rct_verify` / `xmr_bulletproofs_plus` verifier → must pass, as a KAT.

**Multisig (MMS):** **in v1** (locked 2026-09-12) — delivered as the **M4-X-MMS** phase (§6), sequenced after single-sig RingCT (M4-X). It is a large, stateful, multi-round interactive protocol and a frequent bug source, so the key/CLSAG layer is kept general enough to carry the N/M multi-round message flow and partial signing.

---

## 5. Air-Gap Security Model

### 5.1 Threat model (both families)

| Adversary | Mitigation |
|---|---|
| Malicious online node / network attacker (sees & can tamper with artifacts) | Signed blob is self-authenticating; offline signer displays every output/amount/address for human confirm before signing; online node **re-validates consensus regardless of origin** — it trusts no signer. |
| Malware on the online host | Keys never exist online — no key to exfiltrate. Worst case is a DoS on the inject pool (bounded caps) or a tx the operator authorized. |
| Malware on the offline host | Signing build is **network-incapable** (§5.2); seed never persists plaintext (§5.3); reproducible + hash-pinned binary. |
| Operator error (wrong coin/address/amount/oversize, #961 misdirection) | Mandatory confirm screen; oversize refusal; cross-coin guard showing derived target address + coin. |
| Compromised transfer channel (QR cam, USB) | Both sides display a digest + human-readable summary; a swapped artifact changes the summary the operator compares. |

### 5.2 Network-incapable build — defense in depth

1. **Separate binary, separate target (PRIMARY).** `c2wallet-qt-signer` (offline, key-bearing) links **`Qt6::Core/Gui/Widgets` ONLY — no Qt Network, no WebEngine, no WebChannel, no libcurl, no boost::asio.** A socket call is a **link error**, not a runtime check. This is why c2wallet-qt must be a separate binary from `c2pool-qt`, which hard-requires QtWebEngine (Chromium + a network stack): you cannot embed Chromium and honestly claim network-incapable. The `c2wallet-qt-companion` (online, key-free) does QR/file marshalling and talks to c2pool — it **ships in v1** alongside the signer (decision 2, locked 2026-09-12).
2. **Compile-time no-net CI gate.** `nm c2wallet-qt-signer | grep -E 'connect|socket|bind|getaddrinfo|SSL_'` must be empty (benign libc aside) — a mechanical red-KAT, the binary-level analog of c2pool's reward-safety grep proof.
3. **Runtime seccomp belt.** On Linux the signer installs a seccomp filter killing the process on `socket(2)`/`connect(2)`, against a dependency that sneaks a socket in. Airplane-mode / no-NIC is the operational rule.

### 5.3 Key custody

- **Seed never persisted plaintext.** Ephemeral mode (default, = baseline): entered per-session into a masked, `mlock`-pinned buffer, zeroized immediately after derivation. Encrypted-store mode (opt-in): Argon2id KDF → XChaCha20-Poly1305 AEAD over the seed/xprv, passphrase never stored.
- **Memory hygiene:** all secrets in zeroizing containers (`explicit_bzero`/`memset_s`/`SecureZeroMemory`), `mlock`ed, RAII-wiped on every exit path including exceptions; core dumps disabled; no secret in argv/env/logs/window titles/recent-files/clipboard. Qt must do this explicitly (long-lived objects) where Python got it free from process teardown. Monero scalars are longer-lived during a multi-input sign — zeroize after each use.
- **Deterministic signing:** keep RFC6979 (removes the nonce-reuse key-leak class); BIP340 deterministic-nonce for taproot.
- **Self-verify before emit** (baseline law) — extend to **every** script type and to the Monero prover (run the in-tree RingCT/BP+ verifier + recompute key images offline before writing the signed artifact).

### 5.4 Transfer format & the c2pool validation seam

**Family A — two artifacts, both public:**

- **Unsigned/constructed (online→offline):** a **PSBT-like container** (raw hex superset so the proven path survives) carrying the unsigned tx bytes, per-input `{prevout, scriptPubKey, amount, derivation hint}`, coin id + network version bytes (so the signer selects legacy vs BIP143 vs BIP341 algebra), and optionally c2pool's pre-flight verdict.
- **Signed (offline→online):** exactly the format c2pool's loaders already consume — **one raw signed tx hex per line** (the `--pin-local-tx-hex` / `--embedded-tx-inject-hex` format, proven at block 2518186). No PSBT-finalization needed online; c2pool takes finished bytes.

**Transport:** file on removable media (proven), or multi-frame animated QR (sequence index + total + per-frame digest) for a diode gap; the 100 kB oversize ceiling bounds QR frame count. Both sides show `sha256d` digest + a human-readable render for cross-gap comparison.

**The validation seam.** Correction to the task premise: **there is no `POST /api/tx-inject/submit` route** — c2pool's HTTP surface is read-only + loopback-only, and its only POST is inert (503). The real, proven seam is **file-based**, which is better for the air-gap (a file is what crosses the gap anyway). The gate is `NodeCoinState::submit_inject` → `Mempool::add_inject`, cheapest-checks-first, with **named verdicts, no silent drops**: `ok`, `inject-oversize`, `inject-script-check-unarmed`, `inject-already-known`, `inject-already-confirmed`, `inject-unpriceable`, `inject-bip68-unsupported`, `inject-bad-txns-vout-range`. Consensus-exact `VerifyScript` runs under `--embedded-fold-checkscripts` (required armed); authoritative validation runs at template build and **drops** an invalid inject there — it is never mined; the #1218 tx-merkle-root cross-check keeps injection reward-neutral.

Contract (transport-agnostic; file today):

```
Request:  { "op": "validate" | "submit", "coin": "dash",
            "tx_hex": "<raw signed tx>", "flags": 0, "expiry_height": 0 }
Response: { "ok": true|false, "cause": "ok" | "inject-unpriceable" | ..., "txid": "<sha256d>" }
```

One small online-side add is recommended: a **`validate_inject` dry-run** (validate without admit — a `testmempoolaccept` analog) so the wallet can pre-flight *before* the operator signs (requirement 3). No off-host HTTP submit — file/QR is the seam; any HTTP is companion-local, loopback-only, armed-flag-gated. **Caveat:** the online interpreter is `SigVersion::BASE` (legacy) only, so online validation of segwit/taproot inputs needs the same BIP143/341/342 additions on the node side (or a Bitcoin-Core-parity verifier) — a cross-lane dependency to flag.

**Family B — Monero's native cold-signing flow (maps 1:1):** four public artifacts cross the gap — **outputs export** (online→offline: own outputs, no secrets), **key-image export** (offline→online: `{I_i, sig}`, public, lets the online side mark spent outputs and compute balance), **`unsigned_txset`** (online→offline: destinations + input choices + **frozen decoys/commitments** + fee + tx_extra + change), **`signed_txset`** (offline→online: fully-signed CryptoNote tx). Adopt monero's binary layouts verbatim for interop (a stock `monero-wallet-cli` could even be a fallback counterparty).

**Family B online contract (v37 XMR node = counterparty; local ledger task #191/#192; the correct GitHub series is `xmr(native)` #1500–#1612, integrated by #1612 — the brief's "#192 = Monero lane" is a mis-cite, #192 is an NMC storage PR):** the online node exposes (1) a **scan feed** (`get_blocks`/`get_o_indexes` equivalent) for the view-only wallet, (2) a **decoy / output-distribution service** (`get_output_distribution` + `get_outs`) for online ring selection, (3) a **dynamic fee** rate, (4) **relay** via levin `NOTIFY_NEW_TRANSACTIONS` after in-tree RingCT/BP+ verify, and (5) **validation feedback** (accept/reject + reason before relay). Honest limit (per `xmr_rct_verify.hpp`): a daemonless node cannot fully verify CLSAG/double-spend without the chain's spent-set, so the Monero online contract includes a **monerod-parity check** (#1583) as the authoritative leg — mirroring how the Bitcoin daemonless lane keeps `--coin-rpc` as guarded authority until cut. The wallet touches the v37 lane only as a relay/validate/scan client, never the sharechain/settlement code.

### 5.5 Money-path discipline

Offline signing moves no money (the blob is inert until armed online). **Arming the online c2pool to include/broadcast is the tap point** — every live submit (pin arm, inject arm, Monero relay) is a money-path → operator tap; the tx-injection feature is default-OFF at every milestone. The dry-run `validate` op is read-only and tap-free.

---

## 6. Phased Implementation Plan

Each phase is a shippable DRAFT PR delivered by **qt-steward** under the **Fable→Opus→Fable** review discipline (never one-shot), with A-track (Bitcoin-script) and X-track (Monero) interleaved. Any phase that can emit a spendable signature is money-path: caller-side lock trace, operator tap to merge, no subagent self-merge, no delegated force-push. The regression test for a fix folds **into** the fixing PR.

| Phase | Track | Deliverable | Depends on | Money-path gate |
|---|---|---|---|---|
| **M0** | shared | New `ui/c2wallet-qt/` tree; Widgets-only CMake; **network-incapable link-guard CI test** (the mechanical proof); MainWindow/sidebar shell reused from c2pool-qt. | — | Low — no keys yet. Gate = the binary provably links no network symbols. |
| **M1-A** | Bitcoin | `hdkeys`: port BIP39/32/44 + WIF/raw-hex, add BIP49/84/86 + xprv/xpub + SLIP-132 + real BIP39 checksum + BIP38 + **Core descriptors**; plus the now-in-scope keystore parsers — **Electrum full-file parser**, **`wallet.dat` (Berkeley DB) parser**, and **generic JSON keystore** (all v1 per the 2026-09-12 lock). Add **key GENERATION** (§3.4): new BIP39 mnemonic from a **vetted CSPRNG** (not the `mnemonic_gen` demo RNG) + real checksum, the **split/shuffle seed backup** (PBKDF2/HMAC-DRBG, gen→ungen round-trip KAT), and **QR/printable export**. | M0 | **Money-path (keys in memory)** → full F-O-F + tap. |
| **M1-X** | Monero | 25-word mnemonic (+CRC, wordlists), **polyseed (16-word, Argon2)** + **13-word MyMonero** import (alongside the 25-word), dual spend/view import, view-only import, Monero base58, subaddress/integrated derivation; plus **Monero seed GENERATION** (§3.4) — new 25-word + polyseed from vetted CSPRNG. | M0 | **Money-path** → full gate. |
| **M2-A** | Bitcoin | Wire `address_utils` + per-coin SSOT into a "Convert address" panel; detect-convertible / **WARN-or-refuse (#961)** UX with side-by-side payload display + round-trip proof; add the **NMC SSOT leaf** + BCH transcode helper; construct all output types (encode). | M1-A | Read-only derivation, but the **#961 path is money-relevant** → Fable review required. |
| **M2-X** | Monero | Output scanning via view key + amount decrypt; view-only "export outputs" artifact; balance/spent state. | M1-X | Read-only → lighter gate. |
| **M3-A** | Bitcoin | Legacy sighash (parity KAT for block 2518186 folded in **plus a KAT reproducing the LTC+DOGE P2MS-in-P2SH donation spend**), **BIP143** (P2WPKH/P2WSH/P2SH-wrapped), bare-P2MS incl. the CHECKMULTISIG extra-pop; **wrapped/nested construct + spend + multi-party combine** (P2SH / P2WSH / nested P2SH-P2WSH, single-party plus the partial-sign→combine wiring — §4.1); self-verify + oversize per type. | M2-A | **HIGH** money-path. |
| **M3-A-DASH** | Bitcoin (DASH) | DASH special-tx features (§4.1.1/§4.1.2, ported from `frstrtr/dash-proposal-collateral`): **governance-proposal collateral builder** (byte-exact gobject collateral hash, 1-DASH OP_RETURN burn + change, funding-key scan with hard-abort on mismatch) with a KAT against the proven Python reference; **message sign/verify** (Dash signed-message magic, recover-and-check self-verify). | M3-A | **HIGH** money-path (spends 1 DASH). |
| **M3-X** | Monero | Import outputs → compute key images → export key images; port/build the **CLSAG signer** on the vendored ops; KAT against in-tree verifier. | M2-X | **HIGH** money-path. |
| **M4-A** | Bitcoin | **BIP341/342** taproot key-path + script-path (schnorrsig/extrakeys, taptweak, control block, tapleaf/branch); multisig scriptWitness assembly. Includes the **P2TR script-path-as-wrapping-container** (§4.1): **multi-leaf tap trees**, and **taproot-multisig via `OP_CHECKSIGADD`** (not the disabled CHECKMULTISIG) — construct + spend + multi-party combine. (P2WSH / P2SH-P2WSH wrapping and their multisig combine land earlier in M3-A.) | M3-A | **HIGH** money-path. |
| **M4-X** | Monero | **Bulletproofs+ prover** port; full RingCT tx construction + serialization; offline self-verify (in-tree BP+/RCT verifier + key-image recompute) before emit — completes Monero's native cold-sign. | M3-X | **HIGH** money-path. |
| **M4-X-MMS** | Monero | **Monero multisig (MMS)** — now in v1 per the 2026-09-12 lock. The N/M multi-round MMS message flow: key-exchange rounds, per-round MMS message import/export, and partial (cooperative) signing over the RingCT prover. A large, stateful, interactive protocol; sequenced **after** single-sig RingCT (M4-X) is working. | M4-X | **HIGH** money-path (multi-party signing). |
| **M5** | both | Air-gap transfer + validation seam: PSBT-like container + QR (A), `unsigned_txset`/`signed_txset`/outputs/key-image containers (B); online c2pool `validate_inject` dry-run wiring; surface `InjectSubmitResult.cause` names in the UI; Monero relay contract. | M3/M4 both | **HIGH** (broadcast/inject arming). Dry-run validate is tap-free. |
| **M6** | both | Bitcoin-Core-like UI polish: wallet overview, coin-control, tx-builder screens, convert panel, sign/export flow — under one chain-family abstraction. | M5 | Low — no new crypto. |

Dependencies note: M5's Family-A online leg depends on the node-side BIP143/341/342 verifier work (§5.4 caveat); M5's Family-B online leg depends on the v37 XMR node exposing scan/decoy/fee/relay APIs.

Scope note: per the operator directive of 2026-09-12, v1 scope is deliberately **maximal** — the full keystore-format set (A), all Monero seed schemes, view-only/offline-full split, and Monero multisig all land in v1 rather than being deferred. This is a larger attack/format surface by design and correspondingly more KATs; the extra breadth is accepted in exchange for a single comprehensive v1 rather than a staged rollout.

Provenance note: the seed-generation/split-backup work (M1-A/M1-X) and the DASH special-tx work (M3-A-DASH) are **ports of two operator-owned repos** — `frstrtr/mnemonic_gen` and `frstrtr/dash-proposal-collateral`. Both are the operator's own and both are already offline-signer-shaped, fitting the air-gap model; both are **relicensed into c2pool's AGPL on port**.

---

## 7. Risks & Open Decisions

**Decisions locked 2026-09-12:** the operator has now locked **all 12** decisions (see below) — none remain open. The remaining six (2, 3, 9, 10, 11, 12) were each locked to the recommended option.

### Risks

- **The signer core is entirely new prover code on both tracks.** c2pool is verify-only; nothing in-tree signs, and the legacy interpreter is `SigVersion::BASE`. BIP143/341/342 sighash (A) and CLSAG + Bulletproofs+ prover (B) are the highest-risk, highest-value modules. Mitigation: KAT-gate every type (block-2518186 parity for legacy; construct→in-tree-verify for Monero and for segwit/taproot against a Core-parity verifier).
- **Sighash is where funds burn.** Each of BIP143 amount commitment, BIP341 all-prevouts commitment, the SIGHASH_SINGLE bug, and the CHECKMULTISIG NULLDUMMY/ordering rules is an independent money-loss vector. Per-scheme KATs are mandatory, not optional.
- **Cross-coin misdirection (#961).** A wrong conversion silently misdirects funds. Mitigation: reuse the hardened `decide_payout_address` / `classify_address_for_coin` engine verbatim, mandatory round-trip proof, side-by-side payload display, hard family partition.
- **Air-gap erosion.** A Qt binary can link a socket where the Python baseline could not. Mitigation: the three-layer network-incapable build with a CI link-guard as the mechanical proof.
- **Online validation blind spot.** The online node cannot fully validate segwit/taproot (A, legacy-only interpreter) or CLSAG/double-spend daemonlessly (B) — both require added verifier work or a parity authority (`--coin-rpc` for A's Core-parity path; monerod-parity #1583 for B).
- **Node-side dependencies** (BIP143/341/342 verifier; v37 XMR wallet-facing APIs) are outside this tree and must be sequenced with the respective lanes/stewards.
- **Custom seed split/shuffle is unreviewed cryptography (§3.4).** The `mnemonic_gen` port is **not** SLIP-39 Shamir — it is a bespoke 2-of-2 even/odd split with a PBKDF2/HMAC-DRBG reversible shuffle, and the source repo self-labels "educational, not for real funds." A 2-of-2 split means each recovered 12-word half **narrows the brute-force** of the other, so it is weaker than a threshold scheme. Mitigations: (a) generation entropy must come from a **vetted CSPRNG**, never the demo RNG; (b) the split/shuffle scheme needs an **independent security review before it guards real seeds**; (c) offer **SLIP-39 Shamir** as the standard, reviewed alternative alongside it.

### Open decisions for the operator

1. **Keystore formats (A):** **LOCKED 2026-09-12 = ALL IN v1** — Core descriptors + BIP38 + Electrum full-file parse + `wallet.dat` (Berkeley DB) parse + generic JSON keystore. The operator overrode the recommendation to defer Electrum full-file and `wallet.dat`; all five land in v1.
2. **Separate binary vs c2pool-qt mode:** **LOCKED 2026-09-12 = separate signer + online companion** — a **separate network-incapable binary** `c2wallet-qt-signer` (holds keys) PLUS a separate key-free `c2wallet-qt-companion` (online) that pulls data from c2pool and does QR/file marshalling. Both ship in v1 (c2pool-qt hard-requires Chromium/QtWebEngine, so it cannot be the signer).
3. **Packaging:** **LOCKED 2026-09-12 = new release.yml matrix job for all three OS now** — a **new release.yml matrix job** for `c2wallet-qt` producing a signed `.dmg` (macOS universal, same lipo pattern), NSIS/`windeployqt` `setup.exe`, and Linux AppImage/`linuxdeployqt`, all into the existing draft-release + SHA256SUMS shape (CI never publishes; reproducible + offline-verifiable). The current release pipeline builds coin nodes only — no Qt job exists to inherit, so the matrix job is added from scratch.
4. **Monero seed formats:** **LOCKED 2026-09-12 = ALL IN v1** — 25-word Electrum mnemonic (mandatory) + polyseed (16-word) + 13-word MyMonero.
5. **Monero view-only:** **LOCKED 2026-09-12 = IN v1** — the online view-only / offline full split ships in v1 (it *is* the air-gap flow).
6. **Monero multisig (MMS):** **LOCKED 2026-09-12 = IN v1** — the operator overrode the "defer to v2" recommendation; MMS ships in v1.
7. **RingCT prover strategy:** **LOCKED 2026-09-12 = Path A** — port the CLSAG signer + Bulletproofs+ prover onto the vendored `crypto-ops.c` / `xmr_rct_ops`; links only libsodium plus ported BSD-3 source; KAT-gated against the in-tree verifier; provably network-incapable. (Path B — linking monero-project `wallet2`/`libwallet` wholesale — was rejected: it pulls boost + the whole monero crypto tree and is harder to prove network-incapable.)
8. **Which Monero library to link:** **LOCKED 2026-09-12 = Path A libs** (follows decision 7) — links only libsodium (already required by the vendored ed25519 ops) plus the ported source files; no libwallet.
9. **Monero artifact format:** **LOCKED 2026-09-12 = verbatim monero layouts** — adopt monero's `unsigned_txset` / `signed_txset` / outputs / key-image layouts verbatim for interop (a stock `monero-wallet-cli` can serve as a fallback counterparty), not a c2pool-native container.
10. **Monero `.keys` interop:** **LOCKED 2026-09-12 = yes, both ways** — import AND export monero-wallet `.keys` (in addition to our own air-gap format).
11. **Integrated / long payment IDs:** **LOCKED 2026-09-12 = read + warn only** — never generate long/deprecated payment IDs.
12. **Ring size / consensus params source:** **LOCKED 2026-09-12 = live from the online node** — pull ring size / consensus params live (ring 16 now) so a consensus bump is survived without a rebuild, rather than hardcoding.
