# Dash governance-proposal collateral tx builder (offline)

`dash_collateral_tx.py` builds and signs the **1 DASH proof-of-burn collateral
transaction** that a Dash governance proposal requires — on your own laptop,
without Dash Core wallet, without ever exposing the mnemonic.

**READ THIS WHOLE FILE BEFORE RUNNING. The transaction spends real funds and
irreversibly burns 1 DASH once broadcast.**

## What it does

1. Computes the governance-object **collateral hash** byte-exactly per the Dash
   Core sources (see "Correctness" below) from your gobject params
   (`parent-hash = 0`, `revision = 1`, creation `time`, and the bare-object
   `data-hex`).
2. Fetches the funding address' live UTXOs from an insight API (or reads them
   from a pasted JSON file for fully-offline use), rejects anything that does
   not pay the funding address, and skips coinbase outputs younger than
   101 confirmations.
3. Selects coins largest-first to cover `1 DASH + fee`, builds
   - output 0: `1.00000000 DASH` → `OP_RETURN <collateral hash>` (the burn)
   - output 1: change → the funding address (or `--change-address`)
4. Prints a full **dry-run summary** (always — before any key material is
   requested).
5. Only after the summary: reads the BIP39 mnemonic via hidden input, scans
   `m/44'/5'/0'/{0[,1]}/i` for the key whose P2PKH address **equals** the
   funding address, demands a typed `SPEND` confirmation, signs
   (SIGHASH_ALL, RFC 6979 deterministic, DER, low-S), self-verifies every
   signature and prints the signed raw tx hex — the only artifact.

## Security model

- The mnemonic and optional BIP39 passphrase are read with `getpass`:
  never on the command line, never echoed, never logged, never stored.
- **Hard abort** if no scanned derivation index produces exactly the expected
  funding address — a wrong path/index/passphrase can never silently sign
  with the wrong key. The match is double-checked through an independent
  base58 implementation.
- **Hard abort** if any UTXO's `scriptPubKey` is not P2PKH of the funding
  address, on insufficient mature funds, on a bad address checksum, on a
  wrong-network address, and on `--expected-hash` mismatch.
- Signatures are verified against the public key before the tx is emitted;
  non-low-S output is refused.
- Private key bytes are zeroized after use (best effort — CPython cannot
  guarantee no copy survives; see "Operational advice").
- The only stdout output is public data: collateral hash, summary, raw tx hex.

### Operational advice

- Run on a machine you trust, ideally offline: fetch UTXOs on any machine
  (`--fetch-utxos` needs the network, public data only), copy the JSON to the
  offline machine, run there with `--utxos utxos.json`, and carry only the
  signed hex (public) back for broadcast.
- Always run `--dry-run` first and read every line of the summary.
- Verify the printed collateral hash equals what
  `dash-cli gobject check <data-hex>` / your prepared object shows, or pass it
  as `--expected-hash` so the tool enforces it.

## Install

```
python3 -m venv venv && . venv/bin/activate
pip install bip_utils coincurve        # coincurve preferred; `ecdsa` works as fallback
```

Dependencies: `bip_utils` (BIP39/BIP44, Dash coin type 5'), `coincurve`
(libsecp256k1 bindings) or `ecdsa` (pure Python, RFC 6979 + canonical DER).
Everything else is stdlib.

## Usage

Step 0 — get your UTXOs (public data, any machine):

```
python3 dash_collateral_tx.py \
  --address XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u \
  --data-hex <GOBJECT_DATA_HEX> --time <GOBJECT_TIME> \
  --fetch-utxos --dry-run
```

Step 1 — dry-run (no mnemonic asked, nothing signed) and READ the summary:
inputs, the 1 DASH burn output, change, fee.

Step 2 — sign (offline machine, pasted UTXO JSON):

```
python3 dash_collateral_tx.py \
  --address XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u \
  --data-hex <GOBJECT_DATA_HEX> --time <GOBJECT_TIME> \
  --expected-hash <HASH_FROM_DRY_RUN> \
  --utxos utxos.json
```

You will be prompted for the mnemonic (hidden), then must type `SPEND`.

Step 3 — broadcast and submit:

```
dash-cli sendrawtransaction <signed hex>
# wait 6 confirmations (GOVERNANCE_FEE_CONFIRMATIONS), then:
dash-cli gobject submit 0 1 <time> <data-hex> <collateral-txid>
```

Useful options: `--change-address`, `--fee-rate` (duffs/kB, default 1000),
`--min-confirmations` (default 101 — the donation UTXOs are coinbase outputs),
`--scan-limit`/`--account`/`--scan-internal` (derivation scan width),
`--testnet` (coin type 1', `y…` addresses), `--insight-url` (API override).

## Correctness (Dash source cites)

Derived from dashpay/dash @ `728f5055836c6d29806412fc7223ac8fe05af991`:

- `src/governance/common.cpp:23-39` — `Governance::Object::GetHash()`:
  `hashParent` (32 raw bytes) ‖ `revision` (int32 LE) ‖ `time` (int64 LE) ‖
  `HexStr(vchData)` (compactsize + lowercase-hex ASCII) ‖ null
  `masternodeOutpoint` (32×00 + `ffffffff`) ‖ dummy `uint8_t{}` + `0xffffffff`
  ("to match old hashing") ‖ empty `vchSig` (`00`), double-SHA256.
- `src/governance/object.cpp:454-540` — `CGovernanceObject::IsCollateralValid()`:
  line 460 `nExpectedHash = GetHash()`; lines 488-489
  `findScript << OP_RETURN << ToByteVector(nExpectedHash)` (internal byte
  order, i.e. the reverse of the displayed hash); line 505 requires
  `nValue >= nMinFee` on exactly that script.
- `src/governance/object.h:30` — `GOVERNANCE_PROPOSAL_FEE_TX = 1 * COIN`;
  `:31` — `GOVERNANCE_FEE_CONFIRMATIONS = 6`.

Proven against mainnet (2026-08-19): the test suite recomputes the hashes of
three live governance objects bit-exactly, and the OP_RETURN byte order is
matched against the on-chain collateral tx
`b74be34896d8c48c4f059cb55763e4495857d29cbdbfec5710d1a5e5abd4ee64` of object
`5966468c…1129`. A dummy-key signed transaction round-trips through
`dash-cli decoderawtransaction` on Dash Core v22 (version 2, type 0,
`nulldata` + `pubkeyhash` outputs).

## Tests

```
pip install pytest && python3 -m pytest test_dash_collateral_tx.py -q
```

31 tests; all key material is the public BIP39 test mnemonic
(`abandon … about`). No real secret is used or needed anywhere.
