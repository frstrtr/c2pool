# Run a daemonless XMR node (c2pool-v37-xmr)

This guide takes you from a clean Linux account to a running
`c2pool-v37-xmr` node that joins a pool and serves work to your miners.
It covers stagenet today. Mainnet uses the same steps and is marked
"later" where it differs.

"Daemonless" means the node needs no monerod. It talks to the Monero
network over levin (the Monero P2P protocol), keeps its own verified chain
index, builds block templates itself and sends found blocks over levin. It
makes no monerod RPC call. It starts from a pinned snapshot instead of
genesis.

The node is an experimental prototype. Read [Known limits](#known-limits)
before you point real hashrate at it.

Commands marked `<!-- check -->` in the source of this file are run by
`scripts/xmr-run-a-node-check.sh`, so they stay correct.

## 1. What you need

- Linux x86_64. Tested on Ubuntu 26.04 (glibc 2.43). Ubuntu 24.04 uses the
  same package names.
- 4 CPU threads or more, 8 GB RAM for the build (4 GB is enough to run the
  node), 20 GB free disk for stagenet. Measured numbers are in
  [Resources](#resources).
- A shell account. You need `sudo` only for step 2.
- For stagenet: a stagenet payout address (`5...`), and from your pool's
  operator the pool genesis id and one or more relay peers
  (see [Join a pool](#6-join-a-pool)).

## 2. Install packages (admin, once)

<!-- check build -->
```sh
sudo apt-get update
sudo apt-get install -y --no-upgrade build-essential g++-13 git python3-venv libsecp256k1-dev curl openssl rsync
```

If `apt-get` says `Could not get lock /var/lib/dpkg/lock-frontend ... held by
... unattended-upgr`, the system is updating itself. Wait until that process
exits and run the command again.

- `g++-13`: the pinned compiler. The build profile uses GCC 13 even where
  the system default `g++` is newer (Ubuntu 26.04 ships GCC 15).
- `libsecp256k1-dev`: the one library that comes from the system.
- Boost is **not** needed from the system. Conan builds the pinned Boost
  (see [doc/build-unix.md](../../doc/build-unix.md)).

## 3. Build from a tag

Install Conan and CMake into a private venv (no system CMake needed):

<!-- check build -->
```sh
python3 -m venv ~/c2pool-tools
~/c2pool-tools/bin/pip install --quiet "conan>=2.0,<3" "cmake>=3.28"
export PATH="$HOME/c2pool-tools/bin:$PATH"
conan profile detect --force
```

Get the source and pick the ref to build. `REF` is a release tag. **No
release tag for the XMR node exists yet (not yet).** Until one does, use
the commit your pool operator names, and set it before the block below
(`REF=<that commit>`). `master` does not work yet: it does not have the
pinned snapshot boot. The ref must include it
(`docs/xmr-lane/PINNED-SNAPSHOTS.md` exists in it).

<!-- check build -->
```sh
: "${REF:?set REF first, e.g. REF=1a2b3c4 (the release tag or commit your pool operator names)}"
git clone --filter=blob:none https://github.com/frstrtr/c2pool.git ~/c2pool
cd ~/c2pool
git checkout "$REF"
```

Build. `JOBS` is the number of parallel compile jobs. Lower it on a small
machine.

<!-- check build -->
```sh
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
export CC=gcc-13 CXX=g++-13
JOBS=4
conan install . -pr:a=ci/conan/linux-gcc13.profile --build=missing \
  --output-folder=build -c tools.build:jobs=$JOBS
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON
cmake --build build --target c2pool-v37-xmr -j$JOBS
```

- The first `conan install` builds Boost and the other dependencies from
  source into `~/.conan2`. That is the slow step. Later builds reuse it.
- `-DXMR_BUILD_RANDOMX=ON` is required. Without RandomX the node cannot
  verify the proof of work of the blocks it receives.
- If `conan install` stalls downloading bzip2 sources, see the mirror fix in
  [doc/build-unix.md](../../doc/build-unix.md#conan-install-hangs--fails-downloading-from-sourcewareorg-bzip2).

Check the binary and its flags:

<!-- check -->
```sh
cd ~/c2pool
./build/src/c2pool/c2pool-v37-xmr --help | grep -- '--native-output-set'
```

## 4. The pinned snapshot

The node does not replay Monero from genesis. It starts from a pinned
snapshot with two parts:

1. **The anchor.** A block at height H_a with its difficulty and weight
   windows and the roots of the output set and spent set. It is compiled
   into the binary from
   `src/impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc`.
2. **The output-set file.** Every RingCT output and spent key image up to
   H_a. It is too big to compile in (stagenet 1.1 GiB, mainnet 17.1 GiB), so
   you obtain it separately and pass it with `--native-output-set`.

At boot the node hashes the whole file and refuses to start unless its size
and sha256 equal the pin in the binary. Then it checks the file's roots
against the anchor. Then it fetches the block at H_a from live peers and
checks that it hashes to the pinned id ("gate 4"). The pinned values and the
full procedure are in
[PINNED-SNAPSHOTS.md](PINNED-SNAPSHOTS.md). The stagenet pin:

| | |
|---|---|
| H_a | `2213803` |
| Anchor block id | `571f97ae8e7cd7816065c08260a3b65d0192b85d57e9961fa93e102629e6d3ee` |
| Output-set file | `xmr_stagenet_output_set.bin`, `1170058729` bytes |
| Output-set sha256 | `186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d` |

Check that the anchor in your checkout is the pinned one:

<!-- check -->
```sh
cd ~/c2pool
echo "7e39e1a206c4f18776f6f6d83b518fd7146cdd66eacd6d28752446168e88a4a5  src/impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc" | sha256sum -c -
```

### 4.1 Obtain the output-set file

There are three ways. Whichever you use, the node checks the sha256 at
every boot, so a wrong file cannot start it.

| Way | Status |
|---|---|
| Download the published file from the release | **not yet**: no release carries it. The URL in PINNED-SNAPSHOTS.md is a placeholder. |
| Mint it with your own monerod and the repo tool | available today |
| Copy it from someone who already has it | available today |

**Mint it yourself.** You need your own synced, unrestricted monerod (no
`--restricted-rpc`) past H_a. The tool is read-only. The stagenet mint took
about 36 minutes and 1.5 GB RAM.

```sh
cd ~/c2pool
mkdir -p ~/xmr-stagenet
python3 tools/xmr-anchor-gen/xmr_anchor_gen.py \
  --rpc http://127.0.0.1:38081 --net stagenet --height 2213803 \
  --output-set --output-set-out ~/xmr-stagenet/xmr_stagenet_output_set.bin \
  --out ~/xmr-stagenet/xmr_chain_anchor_stagenet_f2.inc
```

`--height 2213803` is required: without it the tool picks `tip - 720`, which
is a different anchor. If the walk stops, run the same command again with
`--resume` added.

**Copy it.** Any copy works. Set `SRC` to where the file is: a local path
(a disk, or a directory another user shared with you) or `<user>@<host>:<dir>`
for a copy over ssh from a pool member.

```sh
SRC=<user>@<host>:<dir>    # or a local directory
mkdir -p ~/xmr-stagenet
rsync --partial --progress "$SRC/xmr_stagenet_output_set.bin" ~/xmr-stagenet/
```

**Verify it** (the node repeats this check at boot):

```sh
cd ~/xmr-stagenet
echo "186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d  xmr_stagenet_output_set.bin" | sha256sum -c -
```

### 4.2 Check the pin against your own monerod

You do not have to trust the pin. With your own synced monerod:

1. Ask it for the block id at H_a. It must equal the pinned anchor block id:

   ```sh
   curl -s http://127.0.0.1:38081/json_rpc \
     -d '{"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":2213803}}' \
     | grep '"hash"'
   # expect "hash": "571f97ae8e7cd7816065c08260a3b65d0192b85d57e9961fa93e102629e6d3ee"
   ```

2. For a full check, mint the files yourself as in 4.1 and compare them with
   the pins. The output-set sha256 must match byte for byte, and so must the
   anchor body. See "Compare your result with the pins" in
   [PINNED-SNAPSHOTS.md](PINNED-SNAPSHOTS.md#compare-your-result-with-the-pins).
3. Point the node's levin peer at your monerod with
   `--native-connect 127.0.0.1:38080`. Gate 4 then fetches the anchor block from your own
   monerod and re-hashes it before the node serves anything.

## 5. Before you start

Make a data directory:

<!-- check -->
```sh
mkdir -p ~/xmr-stagenet/data
```

Set these values. Your pool operator gives you `POOL_GENESIS`,
`RELAY_PEER`, the fee model and the share difficulty. A new pool picks a
new random genesis id with `openssl rand -hex 32`.

```sh
ADDR=5...                       # your stagenet payout address
POOL_GENESIS=<64 hex digits>    # the pool's genesis id
RELAY_PEER=<host:port>          # a relay address of a node already in the pool
RELAY_LISTEN=0.0.0.0:<port>     # where this node accepts relay peers
LEVIN_PEER=<ip>:38080           # a monerod levin port you trust (yours if you have one)
STRATUM_BIND=0.0.0.0            # 127.0.0.1 if the miners run on this machine
STRATUM_PORT=3333
```

Open `STRATUM_PORT` to your miners and `RELAY_LISTEN` to the other pool
nodes. The node opens no levin listen port. It only dials out: to
`LEVIN_PEER`, and to other Monero peers it learns from it.

monerod accepts one connection per IP address by default
(`--max-connections-per-ip 1`). If another node on your IP address already
uses `LEVIN_PEER`, gate 4 fails with `no peer confirmed the anchor block`.
Then use a different `LEVIN_PEER`, or raise that limit on your monerod. If
you have no monerod, add `--native-seeds` to the command below to start from
the network's seed nodes. On a slow link also add
`--anchor-confirm-timeout-ms 180000`.

## 6. Join a pool

Start the node. Run it under `nohup`, `tmux` or a service manager so it
keeps running when you log out:

```sh
cd ~/xmr-stagenet
nohup ~/c2pool/build/src/c2pool/c2pool-v37-xmr --network stagenet \
  --coinbase v37 --xmr-template-source native --arm-order p2p-first \
  --native-connect "$LEVIN_PEER" \
  --native-output-set ~/xmr-stagenet/xmr_stagenet_output_set.bin \
  --native-snapshot-path ~/xmr-stagenet/data/native.snap \
  --data-dir ~/xmr-stagenet/data \
  --randomx --d-conf 10 --fee-model v1 --relay-bind rbind \
  --pool-genesis "$POOL_GENESIS" --relay-listen "$RELAY_LISTEN" --relay-peer "$RELAY_PEER" \
  --payout-address "$ADDR" --share-diff 10000 \
  --stratum-bind-host "$STRATUM_BIND" --stratum-port "$STRATUM_PORT" \
  --status-every 30 > ~/xmr-stagenet/node.log 2>&1 &
echo "node pid $!"
```

What the flags do:

| Flag | Meaning |
|---|---|
| `--network stagenet` | the Monero network (`mainnet` later, see [Mainnet](#mainnet-later)) |
| `--coinbase v37` | build the v37 settlement coinbase, which pays the pool's miners |
| `--xmr-template-source native` | the embedded node builds the template, not monerod |
| `--arm-order p2p-first` | the embedded node is the tip and sends found blocks over levin. No monerod RPC. |
| `--native-connect <ip:port>` | a levin peer to use. Repeat it for more peers. |
| `--native-seeds` | use the network's seed nodes instead of, or as well as, `--native-connect` |
| `--native-output-set <file>` | the output-set file. Without `--native-anchor` the node boots from the compiled-in pinned anchor. |
| `--native-snapshot-path <file>` | save the chain index here so a restart resumes (see [Restart](#9-restart-and-resume)) |
| `--data-dir <dir>` | the settlement store |
| `--randomx` | verify RandomX proof of work |
| `--d-conf 10` | settlement finality depth in blocks. Use the pool's value. |
| `--fee-model v1` | the pool fee model: one donation output in every pool block. Use the pool's value. |
| `--relay-bind rbind` | bind each share to its payee in the proof of work. Required with `--fee-model v1` and on mainnet. |
| `--pool-genesis <hex64>` | the pool's id. Nodes with a different id refuse each other. |
| `--relay-listen <host:port>` | accept relay connections from other pool nodes |
| `--relay-peer <host:port>` | dial a pool node. Repeat it for more peers. |
| `--payout-address <addr>` | this node's own payout address. The stratum port is served only when it is set. |
| `--share-diff <n>` | share difficulty for miners. Use the pool's value. 0 means network difficulty (solo). |
| `--stratum-bind-host <ip>`, `--stratum-port <p>` | where miners connect (default `127.0.0.1:3333`) |
| `--status-every <s>` | seconds between status blocks in the log |

When the relay link is up, the `relay:` status line shows `conns=1 ready=1
hello ok=1` for one peer.

Every node of one pool must use the same `--pool-genesis`, `--fee-model`,
`--relay-bind`, `--d-conf` and `--share-diff`. The relay compares the pool id
in its HELLO and refuses a peer from another pool. The `relay:` status line counts
those refusals as `tag_mismatch=`.

Optional fee flags (fee model `v1` only): `--node-owner-fee-pct <p>` with
`--node-owner-address <addr>` gives the node owner a share of jobs, and
`--give-author-pct <p>` donates a share to the author. Both default to 0.

## 7. Point a miner at it

Each miner logs in with its **own** payout address. That address is bound
into the shares it finds and is paid in the pool's blocks.

```sh
xmrig -o <node-ip>:3333 -u <your-XMR-address> -p <worker-name> -a rx/0 -k
```

To check the stratum without mining, send a login and read the job. Run
this in the shell where you set `ADDR` and `STRATUM_PORT` (section 5):

```sh
python3 - "$ADDR" 127.0.0.1 "$STRATUM_PORT" <<'EOF'
import json, socket, sys
addr, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.create_connection((host, port), timeout=30)
login = {"id": 1, "jsonrpc": "2.0", "method": "login",
         "params": {"login": addr, "pass": "x", "agent": "login-check", "algo": ["rx/0"]}}
s.sendall((json.dumps(login) + "\n").encode())
line = s.makefile().readline()
job = json.loads(line)["result"]["job"]
print("job height", job["height"], "target", job["target"], "job_id", job["job_id"])
EOF
```

The job height is the network tip plus one.

## 8. Read the status block

Every `--status-every` seconds the node prints a block of lines to its log.
The lines to watch:

| Line | What it tells you |
|---|---|
| `[pinned] output-set snapshot sha256 ... matches the pin` | the output-set file is the pinned one (printed once at boot) |
| `node: [GATE-4] anchor confirmed` | a live peer served the anchor block and it hashed to the pinned id |
| `node: [txpool] relay gate OPEN (index synced=1)` | the chain index reached the network tip. `synced=0` means it fell behind. |
| `status: hw=... cursor=... tip=...` | `tip` is the chain tip. `cursor` is how far settlement has booked the chain. `hw` is the highest block seen. After boot, `cursor` catches up to about `tip - d-conf`. |
| `status: ... template ... h=` | height of the template your miners get (tip + 1) |
| `status: ... stratum conn= logins= shares=` | miner connections and accepted shares |
| `suspend: lane_suspended=` | `no` is normal. `YES (job WITHDRAWN ...) causes=lag` means the cursor is too far behind the tip. This is expected during catch-up after boot. Miners get no job until it clears. |
| `hold: held_now=` | blocks the settlement is waiting for. It should return to 0. |
| `cold-boot-2: cursor=... owed_digest=...` | `owed_digest` is a digest of who is owed what at `cursor`. All honest nodes of a pool print the same value at the same cursor. |
| `relay: conns= ready= hello ok= rej=` | relay links to other pool nodes. `ready` should equal your peer count. |
| `native: ... verified_frontier=... peers=` | levin peers and the highest RandomX-verified block |
| `wire RPC to monerod: TOTAL=0` | monerod RPC calls made. It stays 0 in this setup. |

Alarms start with `cba-ALARM` and are counted in the `r6:` line
(`alarms=`) and the `minority:` line (`state=`, `alarms=`). One
`cba-ALARM ... SUSPENDED ... cause=lag` at boot is normal. Anything else, or
`minority: state=DIVERGED`, means this node disagrees with the pool: keep
the log and tell your pool operator.

A healthy node, some minutes after boot, shows `synced=1`, `cursor` within
`d-conf` of `tip`, `lane_suspended=no`, `held_now=0`, and a template at
`tip + 1`.

## 9. Restart and resume

Stop the node with `SIGINT` (Ctrl-C, or `kill -INT <pid>`). It saves the
chain index to `--native-snapshot-path` on a clean stop, and also every 300
seconds (`--native-snapshot-every`).

Wait until the log ends with `stopped. hw_height=...` and the process has
exited (`kill -0 <pid>` fails) before you start it again. The node writes the
snapshot during the stop; a new process started earlier reads an older
snapshot.

Restart it with the same command. It confirms the anchor again (gate 4),
then resumes from the saved index if the file matches the anchor. Otherwise
it boots from the anchor again. The settlement store in `--data-dir` keeps
the booked state. Do not delete `--data-dir` between restarts.

Keep downtime short. A restart after a long stop re-walks the gap from the
network and suspends the lane (`causes=lag`) until the cursor catches up.

## Resources

Measured on stagenet, Ubuntu 26.04, i5-14500T, one levin peer, 2026-09-25:

| | |
|---|---|
| Venv with Conan and CMake (pip, about 40 MB download) | 95-353 s on a 60-100 KB/s link |
| `git clone --filter=blob:none` | 93 s on the same link |
| Build: `conan install` from an empty `~/.conan2`, configure, compile `c2pool-v37-xmr` with `JOBS=6` | 148-177 s (Conan downloads prebuilt Boost and builds only gtest and zeromq) |
| Disk: `~/.conan2` + `~/c2pool` (with `build`) + venv | 171 MB + 107 MB + 80 MB |
| Disk: output-set file | 1.1 GiB (mainnet 17.1 GiB) |
| Disk: `--data-dir` after boot | 0.7 MB |
| Boot to `synced=1` and stratum listening | 36 s (3.4 s of that is the sha256 of the output set) |
| Boot to first stratum job | 282-287 s (catch-up of about 1,650 blocks behind the anchor) |
| Clean restart from `--native-snapshot-path` | stratum listening after 10 s; the lane was not suspended |
| Node memory | peak RssAnon 0.99 GB, VmHWM 1.18 GB |
| Levin traffic in the first 407 s (two levin peers) | 1.6 MB in, 0.11 MB out |

The output-set file is memory-mapped, so it also shows up in the page
cache. The catch-up time grows with the distance from H_a to the tip: about
720 blocks a day on stagenet. Mainnet needs more: plan for 20 GB of disk for
the output set. Mainnet node numbers are not measured yet.

## Known limits

- **Merge-mined coinbases.** Some blocks carry a merge-mining tag in the
  coinbase that the settlement parser does not accept yet. The log then
  shows `miner_tx prefix does not parse`. A fix is pending.
- **FCMP++ / Carrot is not supported.** The coming Monero hard fork changes
  the coinbase and the block header. This node does not follow it yet and
  will not follow the chain past the fork.
- **Block withholding.** A miner can submit shares and keep a found block to
  itself. The pool cannot detect this. The same is true of every pool.
- **Prototype.** The binary prints `EXPERIMENTAL prototype`. No release tag
  exists yet, and the output-set download is not published yet.
- **Mainnet** is refused unless you pass `--i-understand-mainnet`.

## Mainnet (later)

The steps are the same, with these changes:

- `--network mainnet --i-understand-mainnet`, and a mainnet address.
- The mainnet output set: `xmr_mainnet_output_set.bin`, 17.1 GiB, sha256
  `506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d`
  (H_a `3765865`). Mint it with `--net mainnet --height 3765865` and your
  monerod RPC on port 18081. The levin port is 18080.
- `--relay-bind rbind` is required for the relay on mainnet.
