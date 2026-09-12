# c2wallet-qt — Design Document

Standalone, air-gapped Qt desktop wallet and transaction constructor for the frstrtr/c2pool ecosystem. Successor to the offline Python signer `tools/c2wallet/c2wallet.py`. Bitcoin-Core-like UI on the key-holding, offline side; the online c2pool embedded daemon performs validation, splice, and broadcast/inject. This is a design; it authorizes no production code.

---

## 1. Goal & Non-Goals

### 1.1 Goal

A network-incapable desktop application that holds keys, imports any Bitcoin-script-family key format, constructs and signs spends of every script/output type (including exotic and historically-bugged ones), converts addresses across coins that share the same key/hash algebra, and hands unsigned/signed artifacts across an air gap to an online c2pool node for validation and broadcast. It is the offline half of a two-process system whose online half already exists (c2pool the validator/broadcaster). It must reach parity with `c2wallet.py` (which signed donation block 2518186) before extending beyond it.

Concrete goals, mapped to operator requirements:

1. **Import any key format** — BIP39 mnemonic (+ passphrase), BIP32 xprv/xpub with arbitrary derivation paths, BIP44/49/84/86 purpose presets, WIF (compressed/uncompressed, per-coin version byte), raw hex privkey, and encrypted keystore files.
2. **Construct and spend all script/output types** — uncompressed & compressed P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2SH-wrapped-segwit (both keyhash and scripthash), bare P2MS multisig including the `OP_CHECKMULTISIG` extra-pop dummy, and P2TR key-path and script-path — with correct sighash and scriptSig/witness assembly per type.
3. **Validate the constructed tx via the online c2pool daemon** (script-verify / UTXO / policy) before signing and before broadcast.
4. **An air-gapped security model** — the signing build is network-incapable by construction; keys never touch a networked or agent-controlled host; transfer is via public unsigned↔signed artifacts (file / QR / PSBT-like).
5. **Cross-coin address conversion** — re-encode the same hash160 / witness program / x-only key under a target coin's version byte or bech32 HRP when (and only when) the two coins share the same address algebra; warn or refuse when they do not (BCH CashAddr, or a type with no target equivalent). This is the merged-payout auto-conversion c2pool performed for LTC↔DOGE, closed against the pay-misdirection hole of issue #961.

### 1.2 Non-Goals (first wave)

- **Monero / CryptoNote.** Not secp256k1/hash160 script-based; a different signer and a different validation model entirely. Noted as a possible later, separate CryptoNote module — never a coin row in the Bitcoin-script registry.
- **Being a networked wallet.** UTXO discovery, balance display, fee estimation, mempool/policy probing, and broadcast live on the online side (c2pool, or a networked coordinator build). The signing build performs none of these and links no network stack.
- **Hot-wallet / always-on custody.** The default posture is amnesiac: secrets live only in locked memory for the duration of a signing ceremony. Encrypted-at-rest persistence is opt-in.
- **Zero-fee mempool relay.** The donation-consolidation class of tx does not relay (fee==0). The only correct network exit is the pin/own-template path (and, later, tx-inject). No "broadcast via mempool" affordance is offered for a zero-fee tx.

### 1.3 Coin scope (working default)

BTC, LTC, DOGE, DASH, DGB, BCH, NMC — one binary serves all via a shared coin registry. Two registry gaps must be filled (see §2.4): NMC has no `address_encoding.hpp` leaf header, and BCH CashAddr needs a standalone codec in the offline build.

---

## 2. Architecture

### 2.1 The offline/online split

The system is two processes that never share an address space and are joined only by hand-carried public artifacts.

```
┌─ OFFLINE ZONE (network-incapable) ──┐        ┌─ ONLINE ZONE (c2pool node / coordinator) ─┐
│  c2wallet-qt-sign                    │        │  c2pool embedded daemon + c2pool-qt        │
│   • key import / HD derivation       │        │   • UTXO discovery, balances, fee estimate │
│   • tx construction                  │        │   • validate: script-verify / UTXO / policy│
│   • sign + self-verify each input    │        │   • splice into own block template (pin)   │
│   • encrypted key store (opt-in)     │        │   • broadcast won block / (later) inject    │
└──────────────┬───────────────────────┘        └──────────────┬─────────────────────────────┘
               │  UNSIGNED artifact (c2psbt)  ───────────────────▶  validate-only, holds no keys
               │                              ◀───────────────────  advisory verdict (named cause)
               │  SIGNED artifact (raw hex)   ───────────────────▶  pin / inject / broadcast
        AIR GAP: removable file │ animated QR │ manual hex ; integrity checked by txid
```

The load-bearing invariant, confirmed in the c2pool tree: **c2pool never signs and never derives.** There is no `CKey`, no ECDSA/Schnorr signing glue, no HD derivation, no mnemonic anywhere in the C++ tree — c2pool is purely a verifier/splicer/broadcaster. The online node therefore has no write path to funds: it can only append a consensus-valid, fee-zero, non-collateral body tx that survives the merkle cross-check, or fail closed. The entire air-gap threat surface reduces to protecting the seed on the offline side and giving the operator a truthful view of what they are about to sign.

### 2.2 Where keys live

Keys exist only inside `c2wallet-qt-sign`, only in locked, non-dumpable, zeroized memory, only for the duration of a ceremony. Default = amnesiac (nothing persisted; re-import each time). Import channels are interactive masked entry, an externally-created encrypted keystore file, or a QR scanned *into* the offline box — never argv, never env, never a plaintext file the app writes, never a log. Deterministic RFC6979 signing means no RNG in the sign path and no nonce-reuse key-leak class.

### 2.3 Module layout

Two binaries share one crypto/coin core through CMake; they never share a process.

- **`ui/c2wallet-qt/`** — the offline signer. `Qt6::Core + Qt6::Gui + Qt6::Widgets` only, plus a small vendored QR encoder. **No `Qt6::Network`, no `Qt6::WebEngine*`, no `Qt6::WebChannel`, no `Qt6Keychain`.** A CI symbol-scan gate fails the build if any socket/TLS/DNS symbol resolves in the final link map.
- **`ui/c2pool-qt/`** (already a full multi-page node control panel) — gains the online-side "validate-and-broadcast/inject" seam. This is where requirement 3's network touchpoint lives, never in the signer.
- **Shared core** (`c2wallet-core`, a network-free static lib) — codecs, coin registry, HD/key layer, sighash engine, script/witness assembler, cross-coin conversion, artifact serialization. Both binaries link it; only the signer links the private-key half.

### 2.4 Reuse vs. new (grounded in the reuse inventory)

**Reuse in-tree, link/compile as-is** — all pure crypto/serialization, socket-free, safe for the network-incapable build:

| Need | Reuse |
|---|---|
| base58 / base58check (encode+decode) | `src/btclibs/base58.{h,cpp}` |
| bech32 + bech32m **decode** | `src/btclibs/bech32.h` |
| CScript container, all opcodes incl. `OP_CHECKMULTISIG` and BIP342 `OP_CHECKSIGADD`, `GetSigOpCount` | `src/btclibs/script/script.{h,cpp}` |
| hashes / HMAC-SHA512 (the BIP32/39 primitive) / RIPEMD160 / SHA256(d) | `src/btclibs/crypto/*`, `src/btclibs/hash.*`, `dashscript/crypto/*` |
| address algebra: `classify_script`, `address_to_hash160`, `hash160_to_merged_script`, `script_to_address`, `register_address_decoder` | `src/core/address_utils.{hpp,cpp}` |
| #961 cross-coin guard: `CoinAddressAcceptance`, `classify_address_for_coin`→{Own,Foreign,Invalid}, `MergedChainAddr`, `decide_payout_address`→{AcceptOwn,AcceptMerged,Reject} | `src/core/address_utils.hpp` |
| per-coin version-byte / HRP SSOT (hoisted expressly for "the standalone c2pool-qt payout validator") | `src/impl/<coin>/address_encoding.hpp` |
| coin/network params | `src/core/coin_params.hpp`, per-coin `params.hpp` |
| segwit-capable tx model (MutableTransaction with witness, marker/flag serialization) | `src/impl/btc/coin/transaction.{hpp,cpp}` |
| legacy script-verify + legacy sighash (self-check parity with the online node) | `dashscript/c2pool_scriptcheck.h` (`c2pool_dash_verify_input`, `c2pool_dash_legacy_sighash`, `c2pool_dash_hash160`) |
| CPubKey / CExtPubKey (public BIP32) | `dashscript/pubkey.{h,cpp}` |
| secure key memory (mlock allocator + zeroize) | `dashscript/support/{lockedpool.h, allocators/secure.h, cleanse.cpp}` — reuse verbatim |
| libsecp256k1 (link) | vendored at `dashscript/secp256k1/` (extrakeys/recovery/ellswift headers present) |
| Qt shell patterns to lift | `ui/c2pool-qt/src/{CoinProfiles,AddressValidator}.hpp` (Qt-Core-only address validator; profile registry) |
| Python parity target / independent second implementation | `tools/c2wallet/c2wallet.py` |

**Net-new (the real build cost) — port from Bitcoin Core / dashd where a signer already exists, honoring the standing no-workarounds rule; never hand-roll production bignum math:**

1. **Private-key/signing layer** — `CKey`-equivalent (ECDSA low-S RFC6979 + Schnorr BIP340), ported from Core `key.{h,cpp}`; pairs 1:1 with the already-vendored `CPubKey`, shares the same secp context, uses `secure_allocator`. Enable the `schnorrsig` (and confirm `extrakeys`) secp modules, which c2pool does not currently use.
2. **HD derivation** — `CExtKey`/`CExtPubKey` private CKD, BIP39 mnemonic + PBKDF2 + wordlists, BIP44/49/84/86 path parsing. Absent in C++ (only the Python signer has BIP32/39/44, and only path 44).
3. **Segwit-v0 (BIP143) + Taproot (BIP341/342) sighash and interpreter** — the vendored dashscript engine is `SigVersion::BASE` only (Dash has no segwit). This is the largest crypto gap. Port from Core; btclibs already anticipates it (`IsWitnessProgram`, `OP_CHECKSIGADD`).
4. **Key-import parsers** — WIF, raw hex, BIP38, Electrum JSON, Core descriptor JSON.
5. **Per-type scriptSig/witness assembly** (`ProduceSignature`-shape), incl. the CHECKMULTISIG dummy + pubkey-order rule, and tapscript control-block/merkle-tree construction.
6. **bech32m encode (GAP-1)** — `bech32.h` decode accepts bech32m but `encode_segwit` hardcodes the bech32 checksum constant (`polymod ^ 1`); a taproot/converted-taproot address currently encodes **invalid**. Add the BIP350 constant (`^ 0x2bc830a3` for witver ≥ 1) before the wallet encodes any v1 address.
7. **NMC address SSOT (GAP-2)** — add an `address_encoding.hpp` leaf (PUBKEY 0x34, P2SH 0x0d, HRP `nc`) so NMC participates in the acceptance/conversion machinery.
8. **CashAddr codec (GAP-3)** — a standalone BCH CashAddr encode/decode in the offline build (c2pool relies on a runtime-registered decoder; the network-incapable signer must carry its own). BCH also needs the SIGHASH_FORKID BIP143-shape sighash.
9. **HD coin_type (SLIP-44) + WIF-version table** — the C++ registry lacks both; the Python baseline carries them for four coins. Add alongside `coin_params`.
10. **Artifact format** — the c2psbt unsigned container and the raw-hex signed output (§5).

---

## 3. Key-Import Design

Every accepted format resolves to **one internal secret object**; the rest of the wallet consumes only that. Import produces keys — it never decides the address type. Type enumeration happens later in the derivation/scan step, which is what lets a single WIF spend as P2PK **and** P2PKH **and** P2WPKH.

```
ImportedSecret {
  kind:        SEED | XPRV | XPUB(watch-only) | WIF | RAWHEX | KEYSTORE
  origin_label:free text (UI only; never persisted with the secret)
  seed64 | ext_key(CExtKey) | ext_pub(CExtPubKey) | single_key(CKey+compressed) | keybag(vector<CKey>)
  coin_hint:   from WIF version / xprv magic / keystore field, if any
  net_hint:    MAINNET | TESTNET
}
```

### 3.1 Format-by-format

- **BIP39 mnemonic (+ passphrase).** NFKD-normalize; word count ∈ {12,15,18,21,24}; validate every word against the selected wordlist **and verify the checksum** (the baseline skips this — a mistyped word silently derives a wrong, empty wallet). Ship all official BIP39 wordlists as build-time resources, pinned by SHA256 KAT; auto-detect language, allow override. Seed = `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64)` on the in-tree HMAC. Passphrase entered twice with a match check; display a non-secret **seed fingerprint** (e.g. first 4 bytes of `hash160(account xpub)`) so the operator can confirm "same wallet as last time." Also **detect and warn** on an Electrum v2 seed (different checksum/KDF) rather than deriving garbage. *Effort: LOW.*
- **BIP32 xprv / xpub + paths.** Base58Check-decode the 78-byte payload; validate the version magic against a per-coin magic table (BTC `0488ADE4`/`0488B21E`; Ltub/Ltpv; dgub/dgpv; DASH uses BTC magics; **decode SLIP-132 y/z/Y/Z/v/u variants and record the implied script type as a hint, do not reject**). xprv→`CExtKey`; xpub→`CExtPubKey` (watch-only — can build/verify and produce an artifact to sign elsewhere, cannot sign; hardened children greyed out with the reason). Path UI: purpose presets 44'/49'/84'/86' plus 45'/48' multisig and a free `m/…` custom field with `'`/`h` hardened notation; account/change/index scan ranges. *Effort: LOW–MEDIUM.*
- **WIF.** `DecodeBase58Check`; first byte = version (per-coin table: BTC 0x80, LTC 0xB0, DOGE 0x9E, DASH 0xCC, DGB 0x80, NMC 0xB0, BCH 0x80; testnet 0xEF); trailing `0x01` ⇒ compressed. The compressed flag is authoritative on import (not a guess). Warn on coin mismatch against the preselected coin. *Effort: LOW.*
- **Raw hex privkey.** 64 hex (tolerate `0x`/whitespace/case); **range-check `1 ≤ k < n`** (the baseline never validates this). No compressed flag exists → ask (default compressed) and surface both address sets so a legacy uncompressed holder is not stranded. *Effort: TRIVIAL.*
- **Keystore files** — phased: phase-1 = **BIP38** (`6P…`, scrypt N=16384,r=8,p=8 + AES-256; non-EC-multiply mode `0142`), **Electrum wallet JSON** (route seed/xprv/imported-keys into the funnel), **Bitcoin Core descriptor JSON** (parse `wpkh([fp/84h/0h/0h]xprv/0/*)`, extract origin path + key). phase-2 = BIP38 EC-multiply (`0143`), raw `wallet.dat` BDB (recommend instead pointing users at `bitcoin-wallet dump`/`listdescriptors`), generic Ethereum-style JSON keystore. Every encrypted format prompts through the same secure-input widget as the seed.

### 3.2 Import → key → address candidates

```
secret ─derive→ CKey(+compressed)
        ├─ pubkey_compressed   → hash160 → P2PKH(c), P2WPKH, P2SH-P2WPKH, P2WSH(1-of-1)
        ├─ pubkey_uncompressed → hash160 → P2PKH(u), bare P2PK      (legacy; never dropped)
        └─ xonly = pub_c[1:33] → taproot tweak Q = P + int(TapTweak(x))·G → P2TR key-path
```

P2SH / P2WSH / bare-P2MS rows appear only when the user supplies (or the wallet constructs) the redeem/witness script; import's job there is to prove "this imported key is one of the N pubkeys in that script" and mark it signable. The historically-bugged forms are covered by *always* offering the uncompressed branch and never assuming compressed.

### 3.3 Derivation-scan UX

On SEED/xprv import, present a **scan matrix** (per purpose × account range × change ∈ {0,1} × index range × {compressed,uncompressed}), not a single guess. Default scan 0–19 (BIP44 gap-20), one-click extend, gap counter resets on a non-empty index. A first-class **"find address…"** verb (the baseline's `find-key`, generalized) takes a pasted target address and reports the exact derivation path or "not derivable within scanned range" — the money-critical "does this seed actually own this address" check. Because the signer is offline, the "has history / found" column is **empty until an artifact round-trips through the online node**; the UI must say "history unknown offline" and never imply an address is unused. Cross-coin (§4.2) is offered as "show the same keys as coin Y," guarded.

### 3.4 Import validation & memory hygiene

Sniff format by magic/prefix/length and report "recognized as X" **before** asking for secret material. Checksum everywhere (BIP39 word-checksum, Base58Check, bech32 polymod) with a specific failure reason. Range-check privkeys; validate pubkeys on-curve (`CPubKey::IsFullyValid`). Version/coin mismatch = warn, never silently proceed. **Self-consistency KAT at import time** (parity with the baseline's self-verify ethos): each imported key signs a throwaway digest and verifies it via the independent pubkey path before it is ever offered for a real spend; a key that cannot round-trip its own signature is rejected. Every secret is held in the vendored `LockedPool`/`secure_allocator` and `memory_cleanse`d on drop; secret-input widgets disable clipboard/undo/drag-drop and offer "reveal for N seconds" rather than persistent display.

---

## 4. Address / Script Construct + Spend Matrix

This is the money-correctness core. Legend: **BASE** = legacy sighash (reuse vendored `SignatureHash`, `SigVersion::BASE`), **V0** = BIP143 (new), **TR/TS** = BIP341/342 (new). Classification/address decode reuses `classify_script`; scriptSig/witness *assembly* is new per type.

| # | Type | scriptPubKey | Spend: scriptSig / witness | Sighash & scriptCode | Fatal naive errors |
|---|---|---|---|---|---|
| 1 | **P2PK** (65B uncompressed / 33B compressed) | `<pubkey> OP_CHECKSIG` | scriptSig `<sig‖hashtype>`; witness empty. Pubkey is in the output, not the scriptSig | BASE; scriptCode = the P2PK spk | compressed↔uncompressed are two different outputs — spend the exact form the UTXO used; missing trailing hashtype; high-S |
| 2 | **P2PKH** | `OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG` | scriptSig `<sig‖hashtype> <pubkey>`; witness empty | BASE; scriptCode = spk | wrong pubkey form (changes hash160→address); missing hashtype; high-S. **Fully covered by the baseline** |
| 3 | **P2SH** | `OP_HASH160 <h160(redeemScript)> OP_EQUAL` | scriptSig `<satisfier…> <redeemScript>` (redeemScript pushed LAST) | BASE; **scriptCode = redeemScript, NOT the P2SH spk** | signing over the P2SH spk; non-identical redeemScript re-serialization |
| 4 | **P2WPKH** (native v0) | `OP_0 <20B h160(compressed pubkey)>` | scriptSig **EMPTY**; witness `<sig‖hashtype> <compressed pubkey>` | **V0**; scriptCode = implied P2PKH of keyhash; **amount committed** | legacy sighash; **uncompressed pubkey forbidden in v0**; forgetting the amount; any scriptSig bytes |
| 5 | **P2WSH** (native v0) | `OP_0 <32B SHA256(witnessScript)>` (SHA256, not hash160) | scriptSig EMPTY; witness `<satisfier…> <witnessScript>` | V0; scriptCode = witnessScript; amount committed | using hash160 for the 32B program; legacy sighash |
| 6 | **P2SH-P2WPKH** (wrapped) | `OP_HASH160 <h160(0x0014<keyhash>)> OP_EQUAL` | scriptSig = push of the 22B redeemScript `0x0014<keyhash>`; witness `<sig‖hashtype> <compressed pubkey>` | V0; scriptCode = implied P2PKH; amount | sig in scriptSig; omitting the redeemScript push; legacy sighash |
| 7 | **P2SH-P2WSH** (wrapped) | `OP_HASH160 <h160(0x0020<sha256>)> OP_EQUAL` | scriptSig = push `0x0020<sha256>`; witness `<satisfier…> <witnessScript>` | V0; scriptCode = witnessScript; amount | as #6 |
| 8 | **Bare P2MS** (+ CHECKMULTISIG extra-pop) | `OP_m <pub1…pubn> OP_n OP_CHECKMULTISIG` | scriptSig `OP_0 <sig1>…<sigm>` — **leading `OP_0` is the mandatory dummy** consumed by the off-by-one | BASE (bare/P2SH) or V0 (P2WSH); scriptCode = the multisig script | omitting the dummy → underflow; a **non-empty** dummy → NULLDUMMY-invalid; sigs not in the same order as their pubkeys → fails with valid sigs; n sigs instead of m. **Same pattern is the redeem/witnessScript inside P2SH/P2WSH multisig; interpreter's extra-pop + NULLDUMMY reuse=YES** |
| 9 | **P2TR key-path** | `OP_1 <32B x-only Q>`, `Q = P + int(tagged("TapTweak", P‖merkle_root))·G` | scriptSig EMPTY; witness = single element: 64B Schnorr sig (SIGHASH_DEFAULT) or 65B (non-default hashtype appended) | **TR**; tagged `"TapSighash"`, commits to **all input amounts and all prevout spks**; Schnorr over the **tweaked** key with even-Y negation | signing the untweaked key; ECDSA instead of Schnorr; skipping even-Y normalization; conflating DEFAULT (0x00, 64B) with ALL (0x01, 65B) |
| 10 | **P2TR script-path** | `OP_1 <32B Q>` committing a script tree | witness `<tapscript inputs…> <leaf script> <control block>`; control block `= (0xc0‖y-parity) ‖ <32B internal key> ‖ <merkle path 32·k>`; leaf version 0xc0 | **TS** (BIP342); commits to tapleaf hash, key version, last CODESEPARATOR; sigs via `OP_CHECKSIG`/`OP_CHECKSIGADD` — **`OP_CHECKMULTISIG` is disabled in tapscript** | wrong leaf version; wrong control-block parity bit; wrong merkle-path (lexicographic sibling pairing); CHECKMULTISIG in tapscript |
| 11 | **Legacy ancestors** | bare P2PK/P2MS (rows 1,8); OP_RETURN/nulldata (construct-only, unspendable) | — | **SIGHASH_SINGLE bug**: if `in_idx ≥ n_outputs` the legacy digest is the constant `0x00…01` — to spend you must reproduce the bug, which the vendored `SignatureHash` does | uncompressed keys allowed pre-segwit (1,2,3,8) but **forbidden in any witness program** (block them on 4–10) |

**Sighash-type matrix (all rows):** `ALL 0x01` (default) · `NONE 0x02` · `SINGLE 0x03` · `| ANYONECANPAY 0x80`; taproot adds `DEFAULT 0x00` (≡ALL, 64B). Legacy coverage of ALL/NONE/SINGLE/ANYONECANPAY = reuse (vendored `SignatureHash` takes `nHashType`); witness coverage = new with the ported interpreter. **BCH** requires `SIGHASH_FORKID 0x40` **and a BIP143-shape digest for every input** (mandatory replay protection) despite BCH using legacy base58 — this is precisely why the baseline refuses BCH; it is new work (BIP143 shape + forkid), KAT-gated per coin.

**Discipline carried from the baseline (hard):** self-verify every signature with independent math before emit and abort on any mismatch; refuse oversize (the `MAX_TX_BYTES` / block-2517855 lesson — a 152 KB tx is consensus-invalid and takes the block down); RFC6979 determinism; low-S; try compressed and uncompressed; parse-all-before-one-seed-prompt in batch. **Refuse rather than fake:** the baseline refused segwit/BCH; the successor *implements* them with red-on-broken KATs and keeps "refuse if not KAT-proven for this coin+type."

---

## 4A. Cross-Coin Address Conversion (requirement 5)

All seven target coins are secp256k1 + `hash160 = RIPEMD160(SHA256(·))`, so the hash/program bytes are identical across coins — only the *encoding* differs. Per-coin params come from the in-tree SSOTs (cite, never re-type literals):

| Coin | P2PKH | P2SH | bech32 HRP | segwit | native format |
|---|---|---|---|---|---|
| BTC | 0x00 | 0x05 | `bc` | yes | base58 + bech32/m |
| LTC | 0x30 | 0x32 **+ legacy 0x05** | `ltc` | yes | base58 + bech32/m |
| DOGE | 0x1e | 0x16 | — | no | base58 only |
| DASH | 0x4c | 0x10 | — | no | base58 only |
| DGB | 0x1e | 0x3f | `dgb` | yes | base58 + bech32/m |
| NMC | 0x34 | 0x0d | `nc` (GAP-2) | aux | base58 |
| BCH | 0x00 | 0x05 | — | no | **CashAddr** (distinct) + legacy base58 |

**Convertibility (pure re-encode = swap version byte / HRP; hash/program preserved):**

- **P2PKH ↔ P2PKH — convertible across all seven** (incl. BCH-legacy base58). This is the LTC↔DOGE merged-payout case, exactly what `hash160_to_merged_script` + `decide_payout_address`→`AcceptMerged` already implement.
- **P2SH ↔ P2SH — convertible across all seven.** **Warn on the LTC/BTC 0x05 collision:** an LTC legacy-P2SH and a BTC P2SH are textually identical (`3…`); the encoding is safe but funds land on whichever chain the tx is broadcast to — surface it, do not silently treat them as "the same address."
- **P2WPKH / P2WSH (bech32 v0) ↔ only among {BTC, LTC, DGB}.** Swap HRP; witver+program identical. **Refuse to DOGE/DASH/NMC/BCH** (no segwit → no equivalent type).
- **P2TR (bech32m v1) ↔ only among coins with taproot active** (BTC, LTC, DGB-if-enabled). Gate on the target's witness-v1 support.

**Unsafe / impossible — refuse (tie to #961):**

- **BCH CashAddr** — same hash160 but a different encoding entirely; a version-byte/HRP swap cannot produce it. Needs the standalone CashAddr codec (GAP-3); base58↔cashaddr is a transcode, not a re-encode.
- **Segwit/taproot → non-segwit coin** — no equivalent output type. **Never down-convert** a P2WPKH to the P2PKH of the same key: it is a different address the recipient may not treat as theirs and it changes the expected txid.
- **P2SH-wrapped-segwit → non-segwit coin** — the base58 P2SH re-encodes, but its redeemScript is not a witness program there and degrades to an unspendable script. Refuse.
- **mainnet ↔ testnet** — never auto-convert across networks; acceptance sets are already network-scoped.

**Conversion algorithm (reusing c2pool):** (1) authenticate source with `classify_address_for_coin(src, SOURCE.acceptance) == Own`; extract `(type, hash/program)`. (2) check target type-support (base58 always; v0 only if `segwit_activation_version != 0` and HRP present; v1 only if taproot). (3) re-encode via `script_to_address(spk, target.hrp, target.p2pkh_ver, target.p2sh_ver)` (base58 = version swap; bech32 = HRP swap; program copied verbatim). (4) **round-trip guard:** decode the produced address and assert identical `(type, hash/program)`; refuse on any mismatch (BCH routes through the CashAddr codec). (5) the same acceptance-set gate that blocks a foreign payout gates conversion — `AcceptOwn`/`AcceptMerged`/`Reject`, the direct wallet analog of the stratum merged-payout auto-conversion, with the #961 misdirection hole closed.

---

## 5. Air-Gap Security Model + c2pool Validation Seam

### 5.1 Network-incapability (three layers, defence in depth)

1. **Separate binary** (`c2wallet-qt-sign`) — the primary, operator-reasonable guarantee ("I only ever run the *sign* binary on the airgapped box").
2. **Compile-time no-net** — links no Qt Network / sockets / HTTP / DNS. A CI symbol-scan (`nm`/link-map) gate fails the build if any of `socket`, `connect`, `getaddrinfo`, `SSL_*`, `Qt6::Network`, `WebEngine` resolves — the same discipline already used for the hidden-visibility dashscript `.so`.
3. **Runtime guard** — on start, abort if any socket can be opened; drop network capability where the OS allows (`unshare`/seccomp on Linux, sandbox on macOS). Advisory; the physically-airgapped machine remains the real boundary. This catches "I accidentally ran the sign build on my laptop."

This inherits and hardens the baseline's posture ("this script opens no sockets… 'send to a c2pool node' is deliberately a SEPARATE step").

### 5.2 Key custody (see also §2.2, §3.4)

Import offline, never persist plaintext, secrets in mlock'd/`DONTDUMP` pages zeroized after use (reuse `dashscript/support/cleanse`), core dumps disabled, RFC6979 deterministic signing. Opt-in encrypted-at-rest = Argon2id KDF → XChaCha20-Poly1305 / AES-256-GCM (same primitives as BIP38); default = amnesiac.

### 5.3 Threat model (summary)

Seed exfiltration over network (T1: no sockets), via disk/dump/clipboard (T2: never persisted, mlock+zeroize, output asserted secret-free), a tampered unsigned tx tricking the operator (T3: offline re-derivation + human confirm — see §5.5), a tampered signed blob in transit (T4: signature covers the tx, txid is the integrity check carried out-of-band), supply-chain (T5: reuse audited in-tree crypto, pin/vendor, keep the pure-Python `c2wallet.py` as an independent second implementation), cross-coin misdirection (T6/#961: display decoded hash160/program + target coin before signing), a lying online node (T7: it never signs, so it cannot induce a *theft*; it can only censor, mitigated by multiple broadcast paths + operator txid tracking; validity is advisory), evil-maid (T8: amnesiac default, hardware-token derivation a later extension).

### 5.4 What crosses the gap, and the format

**Unsigned artifact — a PSBT-superset ("c2psbt").** The baseline's bare unsigned-hex + single `--address` is too thin for the full matrix: BIP143/BIP341 sighash commit to input amounts and prevout scriptPubKeys, which a bare unsigned tx does not carry. The container carries — global: unsigned tx + coin/network id; **per-input: prevout (txid:vout), prevout scriptPubKey, amount (mandatory), redeemScript (P2SH), witnessScript (P2WSH), sighash type, derivation hint, and for P2TR the internal key / merkle root / leaf scripts**; per-output: scriptPubKey + amount + a "this is my change" derivation proof. BIP174 PSBT is the recommended base encoding.

**Signed artifact — raw signed hex, one tx per line** — byte-identical to what `--pin-local-tx-hex` reads today (multi-line = a split consolidation riding one template). This preserves the live seam with zero online-side change, and is already the right shape (`tx_bytes`) for the future tx-inject `submit`.

**Transport:** removable file (primary), **animated/chunked QR** (UR/BC-UR fountain codes — a 1000-input consolidation is ~150 KB and cannot fit one QR), manual hex (last resort, txid-checked).

### 5.5 Verification on each side (hard rules)

- **Offline, before signing:** independently re-parse the raw unsigned bytes, re-derive every output address + amount + total fee + the change-returns-to-me proof, and **show them**; refuse to sign if implied fee ≠ 0 unless explicitly allowed (the pin path requires fee==0); show the decoded hash160/witness-program per output so a cross-coin misencode is visible.
- **Offline, after signing:** self-verify every signature with independent math before emit; abort on any mismatch; refuse oversize; assert the emitted artifact contains no secret bytes before writing.
- **Online, on receipt:** re-hash → txid, operator confirms it equals the txid the offline box displayed, then run the validation gate below.

### 5.6 The validation seam — the exact contract (c2pool never signs)

**The live, mainnet-proven offline→online path is `--pin-local-tx-hex`, not an HTTP API.** (`tx-inject`/`submit_inject` are design-only, unimplemented — the forward-compatible successor.) The pin file is read at node start: one raw signed tx hex per line; all-or-nothing at load; refusals per line for odd hex, parse failure, `tx.type != 0` (special/extra_payload), empty vin/vout. Parked into `NodeCoinState`, re-gated on every template build, **exclusion-only** (a failing pin is excluded with a named cause, never costs a block, auto-retires once mined).

Two distinct validation surfaces the design must not conflate:

**(1) Pin-admission gate — `Mempool::pinned_tx_admissible()` → `PinnedTxGate`**, with the complete named-cause vocabulary the round-trip surfaces verbatim: `ok` · `tx-too-large` · `utxo-view-unset` · `input-missing-or-spent` · `immature-coinbase-input` · `fee-not-zero` · `tip-unknown` · `spends-mn-collateral`. Input/UTXO resolution uses the **embedded UTXO view first, `gettxout` via `--coin-rpc` second** (the off-tip crutch MEMORY tracks for the dashd-cut); fee==0 is **computed, never assumed**; an input neither source resolves is refused.

**(2) Consensus-exact script verify — `ScriptCheckFn` / `c2pool_dash_verify_input()`** — dashcore's own vendored VerifyScript + interpreter + secp256k1, **fail-closed** (returns 0 on any failure → exclude). Flags exposed today: P2SH, DERSIG, NULLDUMMY, CLTV, CSV.

**Requirement-3 pre-sign round-trip (proposed new method, forward-compatible with tx-inject):** a `validate_unsigned_tx` JSON-RPC method on the existing `c2pool-qt`/node web-server table, **reusing the exact same `pin_gate_verdict` value** so the pre-sign advisory can never drift from the template-time gate (the design law already stated in `embedded_gbt.hpp`). It runs, cheapest first: structural + size cap → input resolution → fee/zero-fee → MN-collateral → (if scriptSigs present) per-input `c2pool_dash_verify_input`. Response: `{ ok, at_height, per_input:[{nIn, ok, cause}], fee, cause }`. **Advisory only** — `ok` does not authorize spending; the operator's own review (§5.5) does; this keeps a lying node from inducing a bad signature. Package parent+child together or the child falsely reports `missing-inputs`.

**Handing the signed blob back:** (1) **pin → own block template** (primary for 0-fee/non-standard): `pin_append` respecting the block-size budget, won block broadcast **P2P-primary / `submitblock`-fallback** — how block 2518186 shipped. (2) **future tx-inject** p2p submit — the raw-hex artifact is already the right shape. Zero-fee txs do not relay, so the pin/inject path is the only correct exit — no mempool-broadcast affordance.

### 5.7 Seam gaps to surface

- **Segwit/taproot flags are absent from the DASH `c2pool_scriptcheck` enum** (Dash has no segwit). For BTC/LTC/DGB the online script-verify seam needs WITNESS/TAPROOT flags + BIP143/BIP341 sighash; verify each coin lane exposes a segwit-capable verify before promising online validation of P2WPKH/P2WSH/P2TR. Implement + KAT per coin; do not assume the DASH verifier covers it.
- **The `validate_unsigned_tx` method does not exist yet.** Recommendation: build it **and** keep an airgap-pure offline self-validation against a locally-linked copy of the same verifier + an operator-supplied UTXO dump; the online round-trip is the optional convenience for UTXO/spentness/policy the offline box cannot know.

---

## 6. Phased Implementation Plan

Each phase is one shippable **draft PR**, delivered by **qt-steward under the Fable→Opus→Fable workflow** (never one-shot). Any phase whose PR can emit a real signature or move funds is **money-path**: it ships flag/behaviour **default-OFF**, carries red-on-broken KATs, self-verifies every signature before emit, and merges only on an **operator tap**. No self-merge, no force-push delegation, no branch deletes. Reward/money-path PRs need the caller-side lock trace. Parallel phases run in isolated worktrees.

- **M0 — Scaffold + parity floor** *(money-path)*. `ui/c2wallet-qt/` CMake target (Widgets/Gui/Core only), secp256k1 hoisted out of `impl/dash/coin/vendor/` into a shared `third_party/secp256k1` with `schnorrsig`+`extrakeys` on (one copy for node and wallet), reuse-wire codecs + coin registry + secure-memory support, **network-incapability CI gate** (link-map symbol scan). Port `CKey`/`CExtKey` from Core. **Acceptance: reproduce the `c2wallet.py` baseline** — legacy P2PKH BIP44 signing of the donation-consolidation shape, self-verifying every input, block 2518186 as the golden. *Deps: none.*
- **M1 — Key import + HD** *(no signing; gate = BIP test vectors)*. BIP39 (+checksum, multi-wordlist, passphrase-fingerprint), BIP32/44/49/84/86 xprv + arbitrary paths, WIF, raw hex, phase-1 keystores; compressed **and** uncompressed; derivation-scan matrix + `find-address` verb; import-time self-KAT. *Deps: M0.*
- **M2 — Address construct / display + cross-coin conversion** *(money-relevant: pay-misdirection, #961/#182)*. All script types classified/displayed; the cross-coin engine reusing `address_acceptance()` — convert within one algebra, **refuse across**; fix bech32m encode (GAP-1), add NMC SSOT (GAP-2), add CashAddr codec (GAP-3). Gate = conversion KATs incl. LTC↔DOGE convertible + LTC↔BCH refused + the LTC/BTC 0x05 warn. *Deps: M0, M1.*
- **M3 — Legacy + segwit-v0 spend** *(money-path)*. Legacy sighash (reuse) + **BIP143** (new); P2PK (both key forms), P2PKH, P2SH, P2WPKH, P2WSH, P2SH-wrapped-segwit, bare P2MS incl. the CHECKMULTISIG extra-pop dummy + ordering; BCH forkid sighash. Gate = red/green sighash KATs vs known vectors + self-verify. *Deps: M1, M2.*
- **M4 — Taproot + multisig spend** *(money-path)*. **BIP341/342** key-path AND script-path (control block, merkle tree, tapscript `OP_CHECKSIGADD`), Schnorr signing (BIP340, tweaked key, even-Y); multisig finalization. Gate = taproot KATs; schnorr module proven. *Deps: M3.*
- **M5 — Air-gap transfer + c2pool validation seam** *(money-path; operator tap to inject)*. c2psbt unsigned artifact (file / animated QR / PSBT), raw-hex signed output matching `--pin-local-tx-hex`; online side (`c2pool-qt`) `validate_unsigned_tx` reusing `pin_gate_verdict` + broadcast/inject; offline self-validation against the linked verifier. **Requirement 3's home; the only network touchpoint — in c2pool-qt, never in c2wallet-qt.** Ties to tx-injection task #157. *Deps: M3 (M4 for taproot validation).*
- **M6 — Qt UI polish** *(no new money-path)*. Bitcoin-Core-like shell over M1–M5. *Deps: M1–M5.*

**Packaging** (a new coin-**agnostic** job — one wallet binary serves all coins, unlike the per-coin node matrix): offline-installable, self-contained bundles that pull nothing at install (Linux AppImage/`linuxdeployqt`, macOS `.dmg` via `macdeployqt` reusing the universal arm64+x86_64 pattern, Windows portable `.zip` via `windeployqt` + optional Inno installer). Reproducible builds with **published checksums and signatures** are first-class here (the trust model is "operator verifies the binary, then moves it to the airgap"), plus the network-incapability link-map gate in CI.

---

## 7. Risks & Open Decisions for the Operator

### 7.1 Risks

- **Segwit/taproot sighash is the largest net-new crypto surface** and the money-critical one; a BIP143/BIP341 error silently produces invalid or (worse) mis-committed signatures. Mitigation: port from Core, KAT red-on-broken per coin+type, refuse any coin+type not KAT-proven (the baseline's refuse-don't-fake discipline).
- **Cross-coin misdirection (#961)** — a wrong conversion misdirects funds. Mitigation: authenticate-source + type-support + round-trip guard + the reused acceptance-set gate; display decoded hash160/program before signing.
- **The `--coin-rpc` second source** in the online pin gate is the dashd-cut crutch MEMORY tracks; the wallet's UTXO discovery should prefer the embedded node's own view where available (c2pool-side concern, not the signer's).
- **BCH's mandatory forkid + CashAddr** is a distinct code path from every other coin; the baseline refuses BCH precisely here — the successor must implement and prove it, not fake it.
- **QtWebEngine on an air-gapped host would be exactly the wrong thing** (a ~150–400 MB Chromium attack surface); the separate-binary decision structurally prevents it.

### 7.2 Open decisions

1. **Separate binary vs. c2pool-qt mode** — recommendation: **separate binary** (`ui/c2wallet-qt/`), high confidence; c2pool-qt is network-first by construction (Network + WebEngine + WebChannel + keychain) and cannot also be a network-incapable signer. Confirm.
2. **Keystore formats for phase-1** — recommended: BIP38 (non-EC-multiply), Electrum JSON, Core descriptor JSON; phase-2: BIP38 EC-multiply, `wallet.dat` BDB (or point users at `bitcoin-wallet dump`), Ethereum-style JSON. Confirm the phase-1 set.
3. **Electrum-seed (non-BIP39)** — recommended: detect-and-warn in phase-1, full support phase-2. Confirm.
4. **Watch-only-from-xpub as a first-class phase-1 mode** (build tx + artifact, sign on a different seed-holding box) — high value for the air-gap story. Confirm in scope.
5. **Encrypted seed vault on the offline box vs. strict ephemeral-only** — recommended: ephemeral default, vault opt-in. Confirm.
6. **Build `validate_unsigned_tx` online method now, or ship offline-self-validation only** — recommended: both (offline-self-validation is the airgap-pure default; the online round-trip is the optional UTXO/policy convenience). Confirm.
7. **Transport artifact = BIP174 PSBT superset vs. an extended flat-hex** — recommended: PSBT-superset (the flat-hex path cannot carry the per-input amount/scripts BIP143/BIP341 require); keep the flat legacy-P2PKH hex path for parity with block 2518186. Confirm.
8. **NMC address SSOT** — must be added (currently a merged-mining backend with no `address_encoding.hpp`); confirm NMC stays in first-wave scope given that gap.
9. **Monero / CryptoNote** — confirmed **out of first wave**; noted as a later, separate signer + validation model, never a Bitcoin-script coin row.
10. **secp256k1 hoist** — moving the vendored copy from `impl/dash/coin/vendor/` to a shared location with taproot modules on touches the node build; confirm the node lane can consume the relocated copy (this is an M0 dependency).
