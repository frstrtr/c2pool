# BIP-110 test miners

Standalone Stratum-v1 test miners for the BIP-110 (BLAKE2b, Sia-family PoW)
Bitcoin fork. They exist to drive **real pool-diff shares** into a c2pool
BIP-110 node so the M3 sharechain, PPLNS split, multi-miner convergence and the
majority-escape scenario can be tested with genuine work.

GPUs (and CPUs) **cannot win a block** against BLAKE2b ASICs at network
difficulty — that is expected and fine. They produce **shares** at pool
difficulty, which is exactly what these tools are for.

Neither tool touches the pool or c2pool source. Each mirrors the pool's PoW
fold in Python and **self-tests against live fork block 961640 before it ever
connects** — a wrong fold fails the self-test and aborts, so an accepted share
proves the miner did genuine, byte-correct BLAKE2b work.

## Files

| file | PoW backend | use |
|------|-------------|-----|
| `bip110_gpu_miner.py` | NVIDIA CUDA BLAKE2b (CuPy `RawModule`, JIT via the driver's nvrtc) | real GPUs — enough hashrate to cross share-diff |
| `bip110_miner.py`     | CPU (`hashlib.blake2b`), multi-process | reference / low-rate; the byte-correct Stratum plumbing the GPU miner reuses |

## The BIP-110 Stratum-v1 work format

Verified against the pool source (`src/impl/bip110/stratum/work_source.cpp`,
`pseudoheader.hpp`, `src/core/stratum_server.cpp`):

- **subscribe reply**: `[[[mining.set_difficulty,sid],[mining.notify,sid]], extranonce1(8 hex = 4 bytes), extranonce2_size=4]`. The miner sends extranonce2 as exactly 8 hex.
- **mining.notify** `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`:
  - `prevhash` = RAW wire hex of `prevblock_hidden` — **no** word-swab, **no** reversal. Used as-is.
  - `coinb1` = 44 bytes = `u32(0) || h2(32) || 8*0x00`; `h2` sits at `coinb1[4..36]`.
  - `coinb2` = `""` (empty). `merkle_branch` = `[]` — there is **no** SHA256d merkle fold.
  - `version` = `a0000000` (0xA0000000); version-rolling is **disabled** (do not negotiate).
  - `nbits` = block bits; the share target comes from `mining.set_difficulty` only.
  - `ntime` = 8 hex big-endian; **must be echoed unchanged** (ntime is committed into h1; rolling it desyncs h1→h2→root → reject).
- **mining.submit** `[user, job_id, extranonce2(8 hex), ntime(8 hex), nonce(8 hex)]`.

### The hash pipeline

Per-job, host-side (SHA256 fold — not on the GPU):
1. `pbh` (prevblock_hidden) arrives verbatim as the notify `prevhash` (32 B).
2. `root = BLAKE2b-256( coinb1(44) || extranonce1(4) || extranonce2(4) )` — 52-byte preimage; `coinb1` already carries `h2` at `[4..36]`. No merkle branch.

Per-nonce, the **only** on-device op:
3. `b2 = BLAKE2b-256( pbh(32) || nonce_LE(4) || 0*12 || root(32) )` — one single-block 80-byte BLAKE2b (t0=80, f0=all-ones, param word `IV[0] ^ 0x01010020`, 12 rounds). The 12 zero bytes are `nonce2 || time_offset || nonce3`, all zero for the served Sv1 shape. Display/block hash = `hex(b2)`; a share is found when big-endian `b2 <= target`.

## KAT (correctness gate)

Both miners pin live fork block **961640** and assert their fold reproduces its
canonical display hash before mining:

```
80B buf  = pbh || nonce || nonce2 || time_offset || nonce3 || root
BLAKE2b-256(80B) = 0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb
```

The GPU miner additionally runs the 80-byte KAT buffer **through the actual
`__device__` BLAKE2b core** and a mining-kernel round-trip (own-hash-as-target
must flag the nonce) at startup, and **aborts on any mismatch**.

```
python3 bip110_gpu_miner.py --selftest-only      # GPU core == canonical == CPU ref, then exit
python3 bip110_miner.py     --selftest-only      # CPU ref == canonical (+ fastpath equivalence)
```

## GPU setup (NVIDIA driver only — no CUDA toolkit needed)

CuPy JIT-compiles the kernel through the driver-provided nvrtc, so only the
NVIDIA driver is required on the host:

```
python3 -m venv gpuvenv
gpuvenv/bin/pip install cupy-cuda12x     # cupy-cuda11x for CUDA 11 drivers
```

## Run

Single GPU:

```
gpuvenv/bin/python bip110_gpu_miner.py \
  --host bip110.voidbind.com --port 9336 \
  --address <BIP110-ADDR> --worker rig-0 \
  --diff 2 --minutes 4320 --log /tmp/bip110_gpu_0.log
```

Multi-GPU = **one process per GPU** with a distinct payout `--address` each (so
PPLNS split + the concentration monitor have distinct payees to attribute). Use
`--device N` (or `CUDA_VISIBLE_DEVICES=N`). For a 3-GPU rig, e.g. the 3x3060 at
192.168.86.123:

```
for i in 0 1 2; do
  nohup gpuvenv/bin/python bip110_gpu_miner.py \
    --device $i \
    --host bip110.voidbind.com --port 9336 \
    --address <ADDR_$i> --worker rig3060-$i \
    --diff 2 --minutes 4320 --log /tmp/bip110_gpu_$i.log & 
done
```

### Notes

- `--diff` is the pool's real acceptance floor (a pinned `+N` suffix on the
  worker name). The live `set_difficulty` vardiff can be looser; the miner mines
  at `max(--diff, live)` so a share passes both the core "low difficulty" gate
  and the work-source gate.
- `--margin` submits shares this many × above the required difficulty (guards a
  vardiff up-creep between `set_difficulty` messages from borderline-rejecting an
  in-flight share).
- The 3060 is LHR, but LHR only throttles Ethash (memory-hard). BLAKE2b is
  compute-bound, so LHR does not apply.
- Generate **real** payout addresses before PPLNS-split economics matter — do
  not reuse the BIP-173 test-vector address for shares you care about.
