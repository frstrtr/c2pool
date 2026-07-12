# c2pool FAQ

Common questions from operators running `./c2pool`. See the
[README](../README.md) for the full option reference and `./c2pool --help`
for every flag.

---

## Merged mining

### How do I add merged coins? Do I implement them in code, or is there a command?

It's a **runtime command-line flag — no code changes**.

- **LTC + DOGE are built in.** They run as **embedded SPV** nodes (no coin
  daemon, no config). DOGE merged mining activates automatically — running
  `./c2pool` with no arguments already merge-mines LTC + DOGE.

- **Other aux chains** are added by running *their* daemon and passing
  `--merged`:

  ```bash
  ./c2pool --merged PEP:63:127.0.0.1:29377:rpcuser:rpcpass
  ```

  Format: `COIN:chain_id:host:port:rpcuser:rpcpass`. c2pool drives the aux
  daemon over its `createauxblock` / `submitauxblock` RPC. Repeat `--merged`
  for multiple chains.

| Coin  | chain_id | Backend                | Notes                              |
|-------|----------|------------------------|------------------------------------|
| DOGE  | 98       | **Embedded SPV**       | auto-configured, on by default     |
| PEP   | 63       | External daemon        | `--merged PEP:63:host:port:user:pass`   |
| BELLS | 16       | External daemon        | `--merged BELLS:16:host:port:user:pass` |
| LKY   | 8211     | External daemon        | `--merged LKY:8211:host:port:user:pass` |
| JKC   | 8224     | External daemon        | `--merged JKC:8224:host:port:user:pass` |
| SHIC  | 74       | External daemon        | `--merged SHIC:74:host:port:user:pass`  |

Only **LTC and DOGE** are daemonless (embedded SPV). Every other aux chain
needs its own full node running locally with AuxPoW RPC
(`createauxblock`/`submitauxblock`) enabled.

---

### Can I merge-mine DigiByte (DGB)? Is DigiByte "SPV" now?

**No — DGB cannot be merge-mined as a child of LTC, and it is not an embedded
SPV coin today.**

DigiByte does **not** support AuxPoW (auxiliary proof-of-work) and has **no
AuxPoW chain ID**. Unlike Dogecoin (chain_id 98) or Namecoin (chain_id 1),
which are child chains that inherit security from a parent's hashrate, DigiByte
secures its own chain directly through a **MultiAlgo** consensus: five
independent proof-of-work algorithms — **Scrypt, SHA-256d, Qubit, Skein, and
Odocrypt** — each mined directly on the DGB main chain with its own independent
difficulty adjustment. Because DGB is a primary chain with no aux-chain role, it
is **not** a valid `--merged` target. The `--merged` flag is only for true
AuxPoW coins (DOGE, PEP, BELLS, LKY, JKC, SHIC).

In c2pool, DGB-Scrypt is therefore handled as its **own parent chain** — a
standalone DGB-Scrypt P2Pool node running its own sharechain (Scrypt-only in
V36; the other four DGB algos are out of scope for now). That parent-chain
support is **in development** (`--net digibyte`), not yet in the stable LTC
release. Until it ships there is no LTC-side path to mine DGB through c2pool.

---

## Payouts & funds

### Where does it mine to when using SPV? How do I access the funds?

**c2pool holds no wallet and never custodies coins.** The embedded SPV nodes
are header-only — they validate the chain but store no keys. Block rewards are
paid **directly in the block's coinbase** to an address **you** control in your
own wallet (Litecoin Core, Dogecoin Core, etc.). There is nothing to "withdraw"
from c2pool — the coins land in your address the moment a block matures.

You set your payout address as your **stratum username** (the P2Pool
convention):

```
LcYourLitecoinAddress.worker1
```

**You normally supply just one address.** c2pool **auto-derives** the payout
address for every merged chain from that single primary address — LTC, DOGE and
the other Scrypt aux chains all share the same secp256k1 keys, so the same
`hash160` is re-encoded into each chain's address format automatically. Give
your LTC address and your DOGE reward is paid to the matching DOGE address with
no extra configuration.

**This auto-conversion is conditional on your address type:**

| Primary address type | Merged payout auto-derived? |
|----------------------|-----------------------------|
| P2PKH  (`L...`, legacy)      | ✅ yes |
| P2SH   (`M...` / `3...`)     | ✅ yes |
| P2WPKH (`ltc1q...`, segwit)  | ✅ yes |
| P2WSH  (`ltc1q...`, 32-byte) | ❌ no — supply merged addresses explicitly |
| P2TR   (`ltc1p...`, taproot) | ❌ no — supply merged addresses explicitly |

The 32-byte witness programs (P2WSH/P2TR) can't be reduced to a 20-byte
`hash160`, so for those you must name each chain's address yourself.

**To override or set addresses per chain explicitly**, use any of:

- **Slash + chain_id** (most explicit):
  `LTCADDR/98:DOGEADDR` — pays DOGE (chain_id 98) to `DOGEADDR`.
  Chain multiple: `LTCADDR/98:DOGEADDR/63:PEPADDR`.
- **Simple separator** (`,` `|` `;` or space): `LTCADDR,DOGEADDR` — first is
  the parent (LTC), second is the merged child.
- **Stratum method**: send `mining.set_merged_addresses`.

c2pool also **auto-corrects a swapped order** (if it detects the merged-chain
address first and the LTC address second) and, if you enter a DOGE address as
the primary, **reverse-derives** the LTC payout from the same key.

Worker names (`.worker1` or `_worker1`) are stripped from each address before
use.

### Which mode pays whom?

| Mode | CLI flag | Who gets paid |
|------|----------|---------------|
| **Integrated** (default) | *(none)* | All miners in the PPLNS window, by sharechain weight — paid to each miner's stratum-username address |
| **Solo** | `--solo` | Your connected miners, proportional to hashrate — paid to their addresses |
| **Custodial** | `--custodial --address ADDR` | **100% to the operator's `--address`**; miners are tracked off-chain via `/stratum_stats` |

In integrated and solo modes the miner's address appears **directly in the
coinbase** — the pool never holds the funds. Only `--custodial` routes
everything to the operator for off-chain accounting.

---

## Dashboard & explorer

### How do I add the dashboard? The docs don't have the integration files anymore.

**The dashboard is built in — there is nothing to install.** Whenever c2pool
runs (integrated, solo, or custodial mode), it serves the web dashboard and
REST API automatically:

```
http://localhost:8080/
```

Just open that URL in a browser. Change the port with `--web-port PORT`
(`web_port:` in YAML). The dashboard files live in `web-static/` and are
fully user-customizable — edit the HTML/JS/CSS there to restyle it.

**Optional lite block explorer** — a separate bundled Python app for browsing
recent blocks, decoded coinbase scripts, and THE commitment proofs:

```yaml
# in your config
explorer: true
explorer_url: "http://localhost:9090"
```

```bash
python3 explorer/explorer.py \
  --ltc-c2pool http://127.0.0.1:8080/api/explorer \
  --web-port 9090
```

Then browse `http://localhost:9090/`.

> **Note:** the README currently links `docs/DASHBOARD_INTEGRATION.md` for the
> full REST API reference, but that file is missing from the tree — tracked in
> [#677](https://github.com/frstrtr/c2pool/issues/677). The API endpoints
> themselves work and are listed in the README's API table; the dashboard is
> served automatically as described above.

---

## Ports (defaults)

| Port  | Purpose                          | Override         |
|-------|----------------------------------|------------------|
| 9326  | P2Pool sharechain (peer-to-peer) | `--p2pool-port`  |
| 9327  | Stratum mining                   | `-w PORT`        |
| 8080  | Web dashboard + REST API         | `--web-port`     |

On `--testnet`, P2P shifts to 19326 and stratum to 19327.
