# XMR lane — stratum front-end (leg: `stratum`)

The miner-facing **CryptoNote / xmrig "JSON stratum"** dialect for the V37
Monero/RandomX settlement lane (Family B). It speaks `login` / `job` / `submit`
to XMRig-class miners, hands accepted work to the rest of the lane through four
narrow seams, and shares **nothing** with the v36 Bitcoin stratum
(`mining.subscribe`/`notify`/`submit`) — it is a separate component, as the
scoping note requires (`v37-monero-randomx-lane-scoping.md` §5, row "Stratum").

This leg is the **skeleton + message schemas**. It is fresh, attribution-clean
AGPL-3.0 c2pool code that re-expresses p2pool's stratum PATTERNS (GPL-3.0,
combinable under AGPLv3 §13); see `PROVENANCE.md` for the line-by-line map and
what was deliberately dropped (all of p2pool's pool model).

## Files
| File | License | What |
|---|---|---|
| `xmr_stratum_messages.hpp` | AGPL-3.0 (fresh) | wire schemas: `LoginString`, `JobNotify`, `SubmitFields`/`ParsedSubmit`, `SubmitError`; fixed sizes; the 76-B blob / offset-39 contract; `ALGO="rx/0"` |
| `xmr_stratum.hpp` | AGPL-3.0 (fresh) | the four seams (`ITemplateSource`, `IPowVerifier`, `IShareSink`, `ITransport`), `XmrStratumSession` (4-deep job ring), `StratumDialect` (pure build/parse), `XmrStratumServer` |
| `xmr_stratum.cpp` | AGPL-3.0 (fresh) | skeleton logic: JSON build/parse, login/job/submit flow, nonce insertion, two-stage submit |
| `xmr_stratum_selftest.cpp` | AGPL-3.0 (fresh) | 53 KATs with fake seams (no socket, no engine) |
| `PROVENANCE.md`, `README.md` | docs | provenance map + this file |

## Build / verify (light, single invocation — no engine, no dataset)
```
g++ -std=c++20 -O1 -Wall -Wextra xmr_stratum.cpp xmr_stratum_selftest.cpp \
    -o /tmp/xmr_stratum_selftest && /tmp/xmr_stratum_selftest
# => "53 passed, 0 failed", exit 0   (verified 2026-09-05, clean under -Wall -Wextra)
```

## The wire dialect (byte-for-byte)
**Login request** (client → pool):
```json
{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"<addr>[+<diff>][.<worker>]","pass":"x","agent":"XMRig/6..","algo":["rx/0"]}}
```
**Login OK** (pool → client), with the nested first job:
```json
{"id":1,"jsonrpc":"2.0","result":{"id":"<rpcId hex>","job":{"blob":"<hex>","job_id":"<u32 hex>","target":"<hex>","algo":"rx/0","height":<h>,"seed_hash":"<32B hex>","next_seed_hash":"<32B hex>"},"extensions":["algo"],"status":"OK"}}
```
**Job push** (pool → client, new template):
```json
{"jsonrpc":"2.0","method":"job","params":{"blob":"<hex>","job_id":"<u32 hex>","target":"<hex>","algo":"rx/0","height":<h>,"seed_hash":"<hex>","next_seed_hash":"<hex>"}}
```
**Submit** (client → pool):
```json
{"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"<rpcId>","job_id":"<u32 hex>","nonce":"<8 hex, LE>","result":"<64 hex>"}}
```
**Submit OK / error:**
```json
{"id":2,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}
{"id":2,"jsonrpc":"2.0","error":{"message":"Low diff share"}}
```

### Load-bearing details
- **`blob` = the Monero hashing blob** `varint(major) varint(minor)
  varint(timestamp) prev_id[32] nonce[4] || tree_root[32] || varint(n_tx)`
  (~76 B; scoping §2.5). `prev_id` → `bin` for the v37 receipt. The template
  builder produces it and returns `nonce_offset`.
- **Header nonce at offset 39** — the 4 bytes the miner iterates; LE. For v16
  headers (major/minor 1 B each, 5-B timestamp varint, 32-B prev_id) that is
  `1+1+5+32 = 39`. Never hardcoded on the hot path: `TemplateJob::nonce_offset`
  carries it; `EXPECTED_NONCE_OFFSET_V16 = 39` is the sanity value.
- **Per-worker extra_nonce lives inside `miner_tx.extra`** (tag `0x02`,
  4 B, grown to ≤14 B; scoping §3.4). The **server** allocates a unique 32-bit
  extra_nonce per client/job (`get_next_extra_nonce`); the **template builder**
  bakes it into the miner_tx extra, so every client hashes a distinct blob and
  two workers never grind the identical template. `(template_id, extra_nonce,
  header nonce)` fully determines the blob — `SavedJob` remembers the first two
  so submit can rebuild it byte-identically.
- **`algo` is always `"rx/0"`** (Monero `rx_slow_hash`, no key-tweak variant).
- **`target`** is p2pool's compact encoding: 4-byte high word for large targets
  (low diff, `>= TARGET_4_BYTES_LIMIT`), full 8-byte LE otherwise.
- **PoW is recomputed, never trusted.** On submit the server rebuilds the blob,
  inserts the nonce, runs one RandomX **light** hash (256 MiB, ~10–15 ms;
  scoping §1.3), then: clears Monero mainchain target → real block
  (`submit_network_block`); clears the lane target → accepted share
  (`on_accepted_share`); else `"Low diff share"`.

## The four seams (who fills them)
| Seam | Filled by leg | Mirrors p2pool |
|---|---|---|
| `ITemplateSource` — per-extra_nonce blob, `rebuild_blob`, seed/next-seed, nonce_offset, targets | `template-builder`, `monerod-adapter` | `BlockTemplate::get_hashing_blob` |
| `IPowVerifier` — RandomX light hash + target check | `randomx-vendor` | `p2pool::calculate_hash` |
| `IShareSink` — accepted share → work-receipt; network block → monerod | v37 RDWR core, `monerod-adapter` | `submit_block_async` |
| `ITransport` — one framed JSON line per client | host / TCP layer | libuv `TCPServer` |

## Open questions (for the lane owner / integrator)
- **OQ-S1 — receipt hand-off shape.** `AcceptedShare` gives `IShareSink` the
  raw `address` (base58) + PoW hash + achieved target. Should the stratum layer
  decode base58 → `XMR_STD`/`XMR_SUB` payout target (descriptor-kinds leg) here,
  or leave that entirely to the sink? Current stance: leave it to the sink; the
  stratum layer holds strings, never descriptor bytes (matches the
  descriptor-kinds "payout-target bytes, never address strings" rule).
- **OQ-S2 — DoS budget.** An unauthenticated submit forces one ~15 ms light
  hash (scoping §2.4 item 2). Per-peer token bucket + ban-on-invalid-PoW belong
  behind `ITransport`/host; parameters TBD. Kept as a hook, not implemented.
- **OQ-S3 — force-light unstable-HW re-hash.** p2pool re-hashes a failing share
  in forced light mode to detect unstable hardware. `randomx_hash(...,
  force_light)` exposes the hook; the skeleton does not wire the second hash.
- **OQ-S4 — subaddress view-pub transport.** For `XMR_SUB` payouts p2pool
  carries the subaddress view pubkey in the share's MM-extra map (scoping
  §3.4). The stratum login only yields the address string; where the extra
  view-pub is supplied (login param vs. side channel) is unresolved.
- **OQ-S5 — target constant.** `TARGET_4_BYTES_LIMIT` (and `MAX_TARGET`,
  `AUTODIFF_START`) are pinned to p2pool `src/util.h` values (2^32 assumed);
  confirm the exact constants against upstream before landing.
- **OQ-S6 — CARROT fence.** `TemplateJob::monero_major_version` is carried so
  the lane can refuse to build/settle a coinbase for a post-CARROT major version
  (descriptor-kinds `xmr_precarrot_ok`, cap v16). The stratum layer does not
  itself gate on it — the template builder / descriptor path must.
