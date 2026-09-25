# XMR native node: pinned bootstrap snapshots

A c2pool v37 XMR native node starts above genesis from a **pinned snapshot**.
The snapshot has two parts:

1. The **format-2 trust anchor**, a `.inc` bundle compiled into the binary.
   It holds the block at height H_a, the difficulty and weight windows, and
   the output-set and spent-set MMR roots over blocks 1..H_a.
2. The **output-set snapshot** that the anchor commits to. This is a
   `ChainOutputSet::serialize()` file with every RingCT output and every spent
   key image up to H_a. It is too large to compile in, so it ships beside the
   release.

Each release pins both parts by sha256, for each network. Anyone with their
own synced monerod can mint both again and compare the result with the pins.
The pins are enforced in three places:

- `src/impl/xmr/native/anchor/xmr_anchor_pinned.hpp` holds the table the
  node enforces.
- `v37_xmr_pinned_snapshot_kat` checks that the table, the committed `.inc`
  files, the bytes compiled into the binary and this document all agree.
- The node itself checks the output-set file at boot, as described in
  [How the node uses the pin](#how-the-node-uses-the-pin).

The pins change no consensus rule. They only decide which bootstrap bytes a
node is willing to start from.

## Pinned values

### Stagenet

| | |
|---|---|
| Anchor height H_a | `2213803` |
| Anchor block id | `571f97ae8e7cd7816065c08260a3b65d0192b85d57e9961fa93e102629e6d3ee` |
| Anchor file | `src/impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc` |
| Anchor file sha256 | `7e39e1a206c4f18776f6f6d83b518fd7146cdd66eacd6d28752446168e88a4a5` |
| Anchor body sha256 (`#` lines removed) | `d5392fb467924afaad174e734d1a37a946c472bcfa9a6652dcc6fb011c055dba` |
| Anchor `digest` line | `1e8142fbb35873eaa09cb9ca2a4873981492148485219d0645d1a26e90ec8263` |
| rct_output_count | `10051944` |
| output_set_root | `ecd05c67cb7ee42af59177e99e5f073dedf3179ec722f1e9f9147ac4384a92ec` |
| spent_set_root | `a8776b6c0dc5316a0af18dcb247064eb3a287220a43b79c3d2ab2dd13cc33d81` |
| Output-set file | `xmr_stagenet_output_set.bin` |
| Output-set sha256 | `186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d` |
| Output-set size | `1170058729` bytes (1.1 GiB) |
| Download | `https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_stagenet_output_set.bin` (placeholder) |
| Minted | 2026-09-24 09:09Z, monerod 0.18.5.1, daemon tip 2214523 (anchor buried 720) |

### Mainnet

| | |
|---|---|
| Anchor height H_a | `3765865` |
| Anchor block id | `ff732eb5bd91e3d7a5188841a04af3146360ffa6f5acbc20ff93797f5351fe33` |
| Anchor file | `src/impl/xmr/native/anchor/xmr_chain_anchor_mainnet_f2.inc` |
| Anchor file sha256 | `616407ba7d2ab2d304532ba1a10aa174c945c28109436ab2eac7d255061782e2` |
| Anchor body sha256 (`#` lines removed) | `cd0169444efb2aab922a10630ed1ed361c2acbb9371487a368e03c95dd7ecb43` |
| Anchor `digest` line | `227b3cc3ea416a3f2a4464d18ea88db23084c3a60b53898f3e5d3aa0c2f5c8d3` |
| rct_output_count | `163820597` |
| output_set_root | `6a89a1111aaa59484bd56376977f47dffe5ecaf9acbc58022494eb44816f0ccf` |
| spent_set_root | `dc5063730476829c73344b34968f13468b9315fab2ff18cb1ea89b232a74bf5e` |
| Output-set file | `xmr_mainnet_output_set.bin` |
| Output-set sha256 | `506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d` |
| Output-set size | `18320778025` bytes (17.1 GiB) |
| Download | `https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_mainnet_output_set.bin` (placeholder) |
| Minted | 2026-09-23 06:06Z, monerod 0.18.5.1, daemon tip 3768428 (anchor buried 2563) |

The mainnet output set holds 163,820,597 RingCT outputs and 154,499,622 spent
key images, from a walk over blocks 0..3765865.

Testnet and regtest have no pin. A node on either network must pass
`--native-anchor`, or start from genesis.

## How the node uses the pin

- **`--native-output-set` without `--native-anchor`.** The node boots from
  the compiled-in pinned anchor for its network. At boot it logs:

  ```
  [pinned] booting from the compiled-in stagenet anchor: height 2213803 id 571f97ae... (anchor .inc sha256 7e39e1a2...); expected output-set sha256 186b23c3... (1170058729 bytes, xmr_stagenet_output_set.bin)
  ```

  It then checks the file's size and its whole-file sha256 against the pin,
  before it maps a single row. If either value differs, the node refuses to
  start:

  ```
  output-set snapshot '<path>' is not the pinned stagenet snapshot: expected sha256 186b23c3... (1170058729 bytes) for the compiled-in anchor at height 2213803 (block 571f97ae...), got <size or sha256>; refusing to start. ...
  ```

  After the sha256 check passes, the loader runs the existing check of the
  file's roots against the anchor.
- **With `--native-anchor <file>`.** The node uses that file, and only the
  root check applies because there is no pin to compare with. The root check
  binds the per-block leaf hashes that the file carries. It does not re-hash
  the output rows or the key-image rows, which is why the pinned path also
  hashes the whole file.
- **Neither flag.** The node boots from genesis, as before.
- **Cost of the sha256 pass.** The node reads the whole file once at every
  boot that seeds the output set.

## Download and verify

```sh
# stagenet
curl -LO https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_stagenet_output_set.bin
echo "186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d  xmr_stagenet_output_set.bin" | sha256sum -c -

# mainnet
curl -LO https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_mainnet_output_set.bin
echo "506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d  xmr_mainnet_output_set.bin" | sha256sum -c -

# the anchors compiled into this checkout
sha256sum src/impl/xmr/native/anchor/xmr_chain_anchor_*_f2.inc
```

Then start the node without `--native-anchor`:

```sh
c2pool-v37-xmr --network stagenet --xmr-template-source native --arm-order p2p-first \
  --native-seeds --native-output-set ./xmr_stagenet_output_set.bin ...
```

The node repeats the size and sha256 check, confirms the roots against the
compiled-in anchor, and runs gate 4. For gate 4 it fetches the block at H_a
from live peers and checks that the block hashes to the pinned id before it
serves anything.

## Reproduce it yourself

You need your own synced **unrestricted** monerod. The tool reads
`get_block`, `get_transactions` and `get_outs`, so monerod must not run with
`--restricted-rpc`, and must be synced past H_a. Use the
repo tool `tools/xmr-anchor-gen/xmr_anchor_gen.py`. It is read-only: it calls
only query RPCs and never submits or mines.

The pinned snapshots were minted with the tool's default walk flags: 8
threads, 100-block batches, 1000 transactions per `get_transactions` call and
5000 indices per `get_outs` call.

```sh
# stagenet (the pinned mint took about 36 min, peak RSS 1.5 GB)
python3 tools/xmr-anchor-gen/xmr_anchor_gen.py \
  --rpc http://127.0.0.1:38081 --net stagenet --height 2213803 \
  --output-set --output-set-out xmr_stagenet_output_set.bin \
  --out xmr_chain_anchor_stagenet_f2.inc

# mainnet (hours; the key-image dedupe table peaks at about 3 GB; the output
# needs about 18 GB of disk for the snapshot plus record files of similar
# size for the walk state)
python3 tools/xmr-anchor-gen/xmr_anchor_gen.py \
  --rpc http://127.0.0.1:18081 --net mainnet --height 3765865 \
  --output-set --output-set-out xmr_mainnet_output_set.bin \
  --out xmr_chain_anchor_mainnet_f2.inc
```

Notes on the tool:

- `--height` pins H_a. Without it, the tool picks `tip - 720`, which is a
  different anchor.
- If a walk is interrupted, re-run the same command with `--resume` added. The
  tool continues from its last checkpoint in `<output-set-out>.walkstate/`, and
  H_a comes from the checkpoint, so a resumed walk commits to the same block.
- `--threads` and `--batch-blocks` only change the fetch schedule. They do not
  change the bytes written.

### Compare your result with the pins

```sh
# 1. The output set must match byte for byte.
sha256sum xmr_stagenet_output_set.bin        # expect 186b23c3...0dcb7d
sha256sum xmr_mainnet_output_set.bin         # expect 506aa248...71390d

# 2. The anchor BODY must match byte for byte.
grep -v '^#' xmr_chain_anchor_stagenet_f2.inc | sha256sum   # expect d5392fb4...055dba
grep -v '^#' xmr_chain_anchor_mainnet_f2.inc  | sha256sum   # expect cd016944...7ecb43
grep '^digest' xmr_chain_anchor_*_f2.inc     # expect the digest lines above
```

**Why the anchor is compared by body.** The `#` lines at the top of an `.inc`
are provenance only: capture time, daemon tip and burial depth. The `digest`
line deliberately excludes them (see "THE DIGEST RULE" in
`src/impl/xmr/native/anchor/xmr_anchor_codec.hpp`). A re-mint made at a later
tip therefore has a different whole-file sha256, but the body and the
`digest` line are identical.

The whole-file sha256 of the committed `.inc` also covers its provenance
header, and that is the value pinned above. To reproduce the whole-file hash
too, three things must match the committed header:

- Pass `--stamp` with the committed `captured` time.
- Mint when your daemon tip equals the committed tip.
- Mint with monerod 0.18.5.1.

The committed headers record:

- stagenet: `2026-09-24 09:09Z`, tip 2214523
- mainnet: `2026-09-23 06:06Z`, tip 3768428

Two more checks confirm what the node will accept:

- Build `v37_xmr_pinned_snapshot_kat`. It checks the committed `.inc` files,
  the compiled-in bytes, the table in `xmr_anchor_pinned.hpp` and this
  document against each other.
- Boot a node with `--native-output-set <your file>` and without
  `--native-anchor`. The node refuses any file that is not the pinned one.

## Releasing a new pin

1. Mint both files from a synced monerod with the commands above, using a new
   `--height`.
2. Commit the new `.inc` as `src/impl/xmr/native/anchor/xmr_chain_anchor_<net>_f2.inc`.
3. Update these three places to the new height, id, both sha256 values and
   the size, then run `v37_xmr_pinned_snapshot_kat`:
   - the `PINNED_SNAPSHOT_<NET>` entry in `xmr_anchor_pinned.hpp`
   - the expected values in `v37_xmr_pinned_snapshot_kat.cpp`
   - this document
4. Attach the output-set file to the release under the documented file name.
