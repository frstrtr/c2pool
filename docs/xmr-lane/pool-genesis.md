# XMR lane: the pool genesis, derived from the chain, and how to verify it by hand

Status: **implemented** (RULES RATCHET slice R1, operator rulings 2026-10-03).
This is the LAST flag day before the mainnet genesis: the format below is what
attempt 10 and the mainnet pool run on; the later slices (R2 ballots, R3 the
tally and the RATCHET event) change no byte of it.

## 1. What a pool is named by

A pool has no name an operator can pick. It is named by a Monero block that
already exists and a short headline of the day:

```
pool_genesis = sha256d( "V37GEN"                    6 ASCII bytes
                     || block_hash(H)                32 bytes: the hash of the block at height H on the
                                                     pool's OWN Monero network (mainnet / testnet / stagenet)
                     || u8 len                       1 <= len <= 120
                     || headline[len] )              the headline bytes, exactly as given

pool_id      = sha256d( "V37PID" || u8 network || u32 chain_id (LE) || b32 pool_genesis )
network: 0 mainnet, 1 testnet, 2 stagenet, 3 regtest     chain_id: the lane's --lane-chain (default 0)
```

`sha256d(x) = sha256(sha256(x))`. Nothing else enters: not the node's rules
(they are an epoch, see [lane-rules.md](lane-rules.md)), not an operator key,
not a date.

Rules the node enforces at start (`--pool-genesis-from <H>:<hash64>:"<headline>"`):

* `H` must be at least `D_conf` (60) blocks deep: `tip - H >= 60`. A block
  that deep cannot be reorganised away on Monero (the lane's own finality
  boundary, [finality-boundary.md](finality-boundary.md)).
* The node reads the block header at height `H` from its own chain view (the
  embedded node's index under `--arm-order p2p-first`, monerod RPC otherwise)
  and requires `hash(H) == <hash64>`. Otherwise it refuses to start:
  `genesis: block <hash> is not height H on this chain` /
  `genesis: H is N deep, needs >= 60` / `genesis: this chain view does not
  hold height H`.
* The headline is printable ASCII (bytes 0x20..0x7E), 1 to 120 bytes, no
  leading or trailing space. It is hashed exactly as given: no case folding,
  no Unicode normalisation, no trimming. The node prints it as text AND as hex.
* The three inputs `(H, hash, headline)` are persisted in the settlement store
  (GenesisRec v2) and printed at every start:

```
genesis: H=3412000 hash=ab12...  headline="attempt 11: the last flag day" (hex 617474...)  pool_genesis=6c7d...  pool_id=61e7...
```

### The raw form

`--pool-genesis <hex64>` (a 32-byte value the operator chose) and the
per-network default (`sha256d("V37PG" || network)`) stay accepted on regtest,
and on testnet / stagenet with the warning `pool genesis given raw: not derived
from the chain, not verifiable by hand`. On mainnet both are REFUSED:
`mainnet: the pool genesis must be derived, use --pool-genesis-from`.

## 2. Where the pool_id appears

* In every lane coinbase, FIRST in the `0x02` extra-nonce payload, right after
  the 4-byte worker nonce, at the fixed offset `[4..49)`:

  ```
  "V37P" | 0x02 | b32 pool_id | u32 epoch_cur (LE) | u32 epoch_max (LE)      45 bytes
  ```

  A node of any epoch finds `(pool_id, epoch_cur)` there whatever later
  epochs put behind it. A block whose field carries another `pool_id` is
  another pool's block: an ordinary Monero block for this pool, never booked.
  (`epoch_cur` is the epoch the block was built under and must equal the
  epoch in force at its height; `epoch_max` is the builder's highest
  implemented epoch, a capability, never a vote.)
* In the relay HELLO, as its three inputs: the network byte, `chain_id` and
  the 32-byte `pool_genesis`. Two nodes with different genesis refuse each
  other at HELLO (`TAG_MISMATCH field=pool_genesis`).

## 3. Verify by hand

Take `H` and the headline from the node's `genesis:` start line (or the
dashboard). Read the block hash at `H` from ANY public Monero explorer (for
stagenet, e.g. the stagenet instance of xmrchain; for mainnet, any explorer)
and check it equals the `hash=` the node printed. Then:

```python
import hashlib, struct
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

H_hash   = bytes.fromhex("<the 64-hex block hash at height H, from the explorer>")
headline = b"<the headline exactly as the node printed it>"
network  = 2            # 0 mainnet, 1 testnet, 2 stagenet, 3 regtest
chain_id = 0            # the pool's --lane-chain (0 unless the operator says otherwise)

pool_genesis = sha256d(b"V37GEN" + H_hash + bytes([len(headline)]) + headline)
pool_id      = sha256d(b"V37PID" + bytes([network]) + struct.pack("<I", chain_id) + pool_genesis)
print("pool_genesis", pool_genesis.hex())
print("pool_id     ", pool_id.hex())
```

Compare `pool_id` with the 32 bytes at offset 5 of the `V37P` field in any
lane coinbase (the `0x02` payload bytes `[9..41)`: `V37P`, `02`, then the id)
and with the `pool_id=` in the start line. If the headline the node printed
has a byte you cannot type, use its hex: `headline = bytes.fromhex("...")`.

Worked example (the KAT's golden): block hash `101112...2f` (the bytes
0x10..0x2f), headline `attempt 11: the last flag day` (29 bytes), stagenet,
chain 0xABCD gives `pool_genesis = 6c7d98c6218459f422993479b05296eb53716c6970ab036f92ffc259e347854e`
and `pool_id = 61e75d6890eb0111b4ed796bae08dec0fcee62dfae767e8335336f04b06a72ed`
(`v37_xmr_pool_lineage_kat`, suite A).

## 4. No premine

On mainnet `owed_demo_amount = 0` and `settle_h_min = 0` are constitutional
(R-MIN (a), [lane-rules.md](lane-rules.md) sec. 4): the node refuses to start
with anything else, and a peer's HELLO carrying anything else is refused by
name (`R_MIN_VIOLATION field=owed_demo_amount ...`). So at the genesis the
owed ledger is EMPTY: `SUM finalW = 0`, and the first `owed_digest` is a
function of the epoch-1 rules alone -- `sha256d("V37Q" || "V37Y" epoch 1
rules_digest H_act 0 || "V37V" n 0)` -- until the first lane block credits
the first miner. The genesis creates no balance for anyone, and the
derivation above leaves the operator nothing to choose but a public block
and a sentence.

## 5. What changed on this flag day (for operators of earlier attempts)

* The per-rule `pool_tag` (`V37PT2`) and the 37-byte `V37P` v1 field at the
  end of the payload are gone; the 45-byte `V37P` v2 field is at the head.
  `rbind` (the share's payee binding) moved from `0x02[4..36)` to `[49..81)`.
* Old binaries refuse new pools and new binaries refuse old ones, by name:
  at HELLO as `TAG_MISMATCH field=version` (pool rules version 5, with the
  ratchet reason) and as `hello: rules length mismatch` (the HELLO rules frame
  now ends with the epoch trailer); on chain each sees the other's blocks as
  ordinary Monero blocks (no `V37P` v2 at `[4..49)` / an unknown version).
* The settlement store is schema 7 and holds a GenesisRec v2 bound to the
  `pool_id`. A store of another pool, a pre-R1 store, a raw genesis on
  mainnet or an epoch the build does not know refuses the open. Start the
  pool on a fresh `--data-dir`.
* Every pool restarts with a derived `--pool-genesis-from` (stagenet attempt
  11 rehearses it); mainnet can only start that way.
