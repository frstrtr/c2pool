# Run a daemonless XMR node (c2pool-v37-xmr)

This guide takes you from a clean Linux account to a running
`c2pool-v37-xmr` node that joins a pool and serves work to your miners.
It covers stagenet. On mainnet the node runs follow-only (see
[Mainnet](#11-mainnet)).

There are two ways to get the node: install the release package
(section 2, no compiler needed), or build it from source (section 3). The
pool pays miners by WRS / PPR (Work Receipt Settlement, pay per receipt):
every pool block pays the miners whose shares the pool has booked.

"Daemonless" means the node needs no monerod. It talks to the Monero
network over levin (the Monero P2P protocol), keeps its own verified chain
index, builds block templates itself and sends found blocks over levin. It
makes no monerod RPC call. It starts from a pinned snapshot instead of
genesis. The pool's nodes keep the Path B carrier chain of the shares they
book and relay to each other; every pool block pays the window of that
chain.

The node is an experimental prototype. Read [Known limits](#known-limits)
before you point real hashrate at it.

Commands marked `<!-- check -->` in the source of this file are run by
`scripts/xmr-run-a-node-check.sh`, so they stay correct.

## 1. What you need

- Linux x86_64. Tested on Ubuntu 24.04 (glibc 2.39) and Ubuntu 26.04
  (glibc 2.43). The release package needs the glibc named in its
  `GLIBC_FLOOR` file or newer, and libstdc++ from GCC 13 or newer
  (`BUILDINFO.txt` names both). Ubuntu 22.04 is too old.
- 4 CPU threads or more, 4 GB RAM to run the node (8 GB to build it), 20 GB
  free disk for stagenet. Measured numbers are in [Resources](#resources).
- A shell account. You need `sudo` only for a system-wide install or to
  install build packages.
- For stagenet: a stagenet payout address (`5...`), and from your pool's
  operator the pool identity and one or more relay peers
  (see [Join a pool](#6-join-a-pool)).
- The payout address must be a MAIN (standard) address: `4...` on mainnet,
  `5...` on stagenet. Subaddresses and integrated addresses are not
  supported as payees. The node refuses a subaddress for
  `--node-owner-address` and for `--payout-address` (with `--mine`) at
  start, and a miner's stratum login with one is refused and closed.

## 2. Install the release package

The package is `c2pool-xmr-<version>-linux-x86_64.tar.gz`, with a
`.sha256` file next to it. It holds the stripped binary (RandomX on,
libgcc linked in; it uses the system's libstdc++, which must come from
GCC 13 or newer, as on Ubuntu 24.04), the dashboard files, these docs, the
systemd unit and `install.sh`. It is built by
`scripts/xmr-node/build-release.sh`.

```sh
sha256sum -c c2pool-xmr-<version>-linux-x86_64.tar.gz.sha256
tar xzf c2pool-xmr-<version>-linux-x86_64.tar.gz
cd c2pool-xmr-<version>-linux-x86_64
./install.sh --user
```

As a normal user (install.sh --user) it installs into `~/.local/c2pool-xmr`
with data in `~/.c2pool-xmr`. Change these with the install.sh options
--prefix DIR and --data DIR. Run as root without --user and it installs into
`/opt/c2pool-xmr`, keeps data in `/var/lib/c2pool-xmr` and creates the
system user `c2pool-xmr`. Add --systemd to also install the unit
(a user unit or a system unit). The unit is written but not enabled or
started.

`install.sh` checks the package against `SHA256SUMS`, the glibc version,
RAM and free disk. It writes `node.env` into the data directory only if
there is none yet, and it never starts, stops or changes any other service.

Check the installed binary:

```sh
~/.local/c2pool-xmr/bin/c2pool-v37-xmr --version
```

It prints the build, the default network and the pinned snapshot heights.
Then go on with [The pinned snapshot](#4-the-pinned-snapshot).

## 3. Or build from source

For the full, tested walk-through on a fresh Ubuntu 24.04 (pinned Conan,
commit check, tests, hash comparison, packaging your own binary) see
[BUILD-FROM-SOURCE.md](BUILD-FROM-SOURCE.md). The short version follows.

### 3.1 Install packages (admin, once)

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

### 3.2 Build from a tag

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
the commit your pool operator names, or `master`, and set it before the
block below (`REF=<that commit>` or `REF=master`). `master` has the pinned
snapshot boot (c2pool #1777). Every node of one pool should run the same
commit.

To build the release package yourself instead, run
`scripts/xmr-node/build-release.sh` in the checkout after the venv and
packages above. It writes the tarball to `dist/`.

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

**Download it.** When a release carries the file, or your pool operator
publishes a download URL, fetch it straight into the data directory and
check it before the first start (`~/.c2pool-xmr` is the package's default
data directory; the source build below uses `~/xmr-stagenet`):

```sh
cd ~/.c2pool-xmr
curl -L -C - -o xmr_stagenet_output_set.bin "<URL from your pool operator or the release>"
echo "186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d  xmr_stagenet_output_set.bin" | sha256sum -c -
```

`sha256sum` must print `OK`. `-C -` resumes a broken download. The file is
1.1 GiB, so the check takes a few seconds.

**Mint it yourself.** The mint tool is in the source tree
(`tools/xmr-anchor-gen/`), not in the package. You need your own synced, unrestricted monerod (no
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

Set these values. Your pool operator gives you `POOL_IDENTITY` and
`RELAY_PEER`.

```sh
ADDR=5...                       # your stagenet payout address
POOL_IDENTITY='<H>:<64 hex digits>:<headline>'   # the pool identity
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

### 6.1 With the package

All launch flags live in `node.env` in the data directory, one flag per
line, each with a comment. Replace every `<placeholder>`: the pool identity
(`--pool-genesis-from`), the two public relay nodes (`--relay-peer`), your
relay port, and your MAIN payout address. `--give-author-pct 0.1` gives
0.1% of the weight of this node's jobs to the author; set it to 0 to opt
out. `--node-owner-fee-pct` with `--node-owner-address` is optional: the
node owner's weight share in this node's jobs. `--mine` stays commented
out. Relative paths in `node.env` are under the data directory.

Start it by hand:

```sh
cd ~/.c2pool-xmr
nohup ~/.local/c2pool-xmr/bin/run-node.sh ~/.c2pool-xmr/node.env > node.log 2>&1 &
```

or with the unit (after ./install.sh --user --systemd):

```sh
systemctl --user daemon-reload
systemctl --user start c2pool-xmr
journalctl --user -u c2pool-xmr -f
```

For a user unit that keeps running after you log out, an admin runs
`loginctl enable-linger <user>` once.

`run-node.sh` also starts `memguard.sh`. It watches `MemAvailable` and
stops the node cleanly (SIGINT) when it falls below `MEMGUARD_MIN_MB`
(1024 MB by default, set in `node.env`). The unit sets `OOMScoreAdjust=1000`
and a `MemoryMax=4G` hint.

The dashboard is at `http://127.0.0.1:8080/` (the `--web-host` and
`--web-port` lines). To see it from another machine, forward the port
over ssh rather than binding it to `0.0.0.0`.

### 6.2 By hand (source build)

Start the node. Run it under `nohup`, `tmux` or a service manager so it
keeps running when you log out:

```sh
cd ~/xmr-stagenet
nohup ~/c2pool/build/src/c2pool/c2pool-v37-xmr --network stagenet \
  --xmr-template-source native --arm-order p2p-first \
  --native-connect "$LEVIN_PEER" \
  --native-output-set ~/xmr-stagenet/xmr_stagenet_output_set.bin \
  --native-snapshot-path ~/xmr-stagenet/data/native.snap \
  --data-dir ~/xmr-stagenet/data --randomx \
  --pool-genesis-from "$POOL_IDENTITY" --relay-listen "$RELAY_LISTEN" --relay-peer "$RELAY_PEER" \
  --payout-address "$ADDR" --give-author-pct 0.1 \
  --web-port 8080 --web-host 127.0.0.1 --dashboard-dir ~/c2pool/web-static \
  --stratum-bind-host "$STRATUM_BIND" --stratum-port "$STRATUM_PORT" \
  --status-every 30 > ~/xmr-stagenet/node.log 2>&1 &
echo "node pid $!"
```

What the flags do:

| Flag | Meaning |
|---|---|
| `--network stagenet` | the Monero network (mainnet: [follow-only](#11-mainnet)) |
| `--xmr-template-source native` | the embedded node builds the template, not monerod |
| `--arm-order p2p-first` | the embedded node is the tip and sends found blocks over levin. No monerod RPC. |
| `--native-connect <ip:port>` | a levin peer to use. Repeat it for more peers. |
| `--native-seeds` | use the network's seed nodes instead of, or as well as, `--native-connect` |
| `--native-output-set <file>` | the output-set file. Without `--native-anchor` the node boots from the compiled-in pinned anchor. |
| `--native-snapshot-path <file>` | save the chain index here so a restart resumes (see [Restart](#9-restart-and-resume)) |
| `--data-dir <dir>` | the Path B store (`pathb_db`) |
| `--randomx` | verify RandomX proof of work (the pool node needs it) |
| `--pool-genesis-from <H>:<hash64>:"<headline>"` | the pool identity, derived (every network) |
| `--pool-genesis <hex64>:<H>` | a raw pool genesis with its height (regtest, testnet, stagenet) |
| `--pathb-launch` | the pool's first node: build templates with no Path B peer |
| `--relay-listen <host:port>` | accept relay connections from other pool nodes |
| `--relay-peer <host:port>` | dial a pool node. Repeat it for more peers. |
| `--no-relay-bootstrap` | do not dial the network's bootstrap peers (see [BOOTSTRAP-NODES.md](BOOTSTRAP-NODES.md)) |
| `--payout-address <addr>` | the payee of the in-process miner's jobs |
| `--stratum-bind-host <ip>`, `--stratum-port <p>` | where miners connect (default `127.0.0.1:3333`) |
| `--give-author-pct <p>` | the author's weight share in this node's jobs, in percent |
| `--node-owner-fee-pct <p>`, `--node-owner-address <addr>` | the node owner's weight share in this node's jobs, and its standard address |
| `--mine [threads]` | the in-process RandomX CPU miner on this node's jobs |
| `--web-port <p>`, `--web-host <ip>` | the dashboard (`http://<web-host>:<web-port>/`). Off unless `--web-port` is set. |
| `--dashboard-dir <dir>` | the dashboard files (`web-static/`). `run-node.sh` sets it for the package. |
| `--status-every <s>` | seconds between status blocks in the log |

When the relay link is up, the `relay:` status line shows `ready=1` and
`hello ok=1` for one peer.

Every node of one pool uses the same pool identity. The relay compares the
pool id in its HELLO and refuses a peer from another pool
(`TAG_MISMATCH field=pool_id`). The pool's rules are part of the identity.

The share difficulty is the pool's `d` (the `template` line). Miners get
jobs at `d`; `--stratum-min-diff-shift <s>` serves stratum shares at
`max(1, d >> s)`.

The author's share: `--give-author-pct <p>` gives p percent of the weight of
this node's jobs to the author; it defaults to 0.1 (`--give-author-pct 0` opts out).
The value rides in each share and every node splits the share's weight by
it, so it is never a separate output. The node owner's share
(`--node-owner-fee-pct`, `--node-owner-address`, a MAIN address) defaults
to 0.

## 7. Point a miner at it

Each miner logs in with its **own** payout address, a MAIN address (`4...`
on mainnet, `5...` on stagenet). That address is bound into the shares it
finds and is paid in the pool's blocks. Do not use a subaddress or an
integrated address. Point the miner at the node's `--stratum-port` (3333 in
`node.env`) on the address in `--stratum-bind-host`.

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
| `[GATE-4] anchor confirmed: height ...` | a live peer served the anchor block and it hashed to the pinned id |
| `status: up=... monero=<h> best pos=<n> id=... cum_work=... pending=... template=ok` | `monero` is the Monero tip, `best pos` the position of the best carrier, `pending` the receipts waiting for a carrier |
| `template <n>: tip=... x=... h=... d=... R=... n_tx=...` | a new template: the carrier tip it builds on, the Monero height `h`, the pool's `d`, the reward `R`, the transactions |
| `found h=... id=... landed=...` | a Monero block found on this node's job |
| `relay: peers in= out= ready= ... hello ok= rej= ...` | relay links to other pool nodes. `ready` should equal your peer count. |
| `stratum: conns= ... own receipts=` | miner connections and the shares this node booked |
| `txpool: gate= ... warm=` | the transaction pool gate and the warm latch after a restart |
| `follower: rows= recorded= events ...` | the Monero chain index |
| `wire RPC to monerod: TOTAL=0` | monerod RPC calls made. It stays 0 in this setup. |
| `run-node: <binary> <flags>` | printed once by `run-node.sh`: the exact command it started (package installs) |
| `memguard[<pid>]: watching, stop threshold ...` | memguard is running. `sending SIGINT (clean stop)` means the machine ran low on memory and memguard stopped the node. |

A healthy node, some minutes after boot, shows `template=ok`, a `template`
line at the Monero tip plus one, `ready` equal to its relay peers and
`TOTAL=0`.

## 9. Restart and resume

Stop the node with `SIGINT` (Ctrl-C, or `kill -INT <pid>`). It saves the
chain index to `--native-snapshot-path` on a clean stop, and also every 300
seconds (`--native-snapshot-every`), with the output-set overlay next to it
(`<snapshot>.outset`).

Wait until the log ends with `c2pool-v37-xmr: stopped` and the process has
exited (`kill -0 <pid>` fails) before you start it again.

Restart it with the same command. It confirms the anchor again (gate 4),
then resumes from the saved index when the index and its overlay match.
Otherwise it re-walks from the anchor. The Path B store in `--data-dir`
keeps the carrier chain. Do not delete `--data-dir` between restarts.

The follower keeps its Monero rows across a restart in the node's data
directory: `row_weights`, `row_weights_kept` (the rows within 720 blocks of the tip,
off the main chain too) and `row_weights_kept_blobs` (the blocks of the
kept rows off the main chain). A restarted node serves those blocks to the
pool's other nodes. `--alt-max-blocks <n>` sets how many alternative Monero
blocks it keeps (default 720, at least 1). A `row_weights_kept_blobs` that
does not decode is moved aside to `row_weights_kept_blobs.corrupt-<time>`
and the node starts without it.

## 10. Other modes

**Follow-only.** The node follows Monero and logs the template record of the
Monero tip for an empty window: no pool, no store, no job, no relay, no
monerod endpoint. Its start line reads
`c2pool-v37-xmr: FOLLOW-ONLY network=... pool=none stratum=off relay=off`.

```sh
~/c2pool/build/src/c2pool/c2pool-v37-xmr --network stagenet --follow-only \
  --native-connect "$LEVIN_PEER" \
  --native-output-set ~/xmr-stagenet/xmr_stagenet_output_set.bin \
  --native-snapshot-path ~/xmr-stagenet/follow.snap --randomx
```

**Solo (regtest).** A one-node pool without peers, monerod or anchor: the
chain starts at the locally assembled genesis block. Templates need
`--pathb-launch`; a found block counts as landed when the node's own index
accepts it (`landed=own-index`).

```sh
~/c2pool/build/src/c2pool/c2pool-v37-xmr --network regtest --native-solo \
  --arm-order p2p-first --xmr-template-source native --randomx \
  --pool-genesis-height 0 --pathb-launch --payout-address "$ADDR" \
  --data-dir ~/xmr-regtest --native-snapshot-path ~/xmr-regtest/chain.snap --mine 1
```

**The regtest K30 set.** `--pathb-regtest-k30 <L,GRACE,TIMEOUT>` sets the
regtest rig's K30 values; the pool identity's G follows from it. Any other
network refuses it: `REFUSED: --pathb-regtest-k30 is regtest only`.

## 11. Mainnet

On mainnet the node runs follow-only, behind `--i-understand-mainnet`:

```sh
~/c2pool/build/src/c2pool/c2pool-v37-xmr --network mainnet --i-understand-mainnet --follow-only \
  --native-connect <ip>:18080 --native-output-set ~/xmr-mainnet/xmr_mainnet_output_set.bin \
  --native-snapshot-path ~/xmr-mainnet/follow.snap --randomx
```

The mainnet output set: `xmr_mainnet_output_set.bin`, 17.1 GiB, sha256
`506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d` (H_a
`3765865`). Mint it with `--net mainnet --height 3765865` and your monerod
RPC on port 18081. The levin port is 18080.

Every other mainnet start is refused, before anything is written:

| Start | Line |
|---|---|
| without `--i-understand-mainnet` | `REFUSED: mainnet requires --i-understand-mainnet (prototype safety)` |
| without `--follow-only` | `REFUSED: mainnet requires --follow-only` |
| `--follow-only` with `--pathb-launch` | `REFUSED: mainnet refuses --pathb-launch` |
| `--follow-only` with a stratum, mining or relay flag | `REFUSED: mainnet refuses <flag>` |

<!-- check -->
```sh
cd ~/c2pool
out=$(./build/src/c2pool/c2pool-v37-xmr --network mainnet --i-understand-mainnet 2>&1 || true)
echo "$out" | grep -x 'REFUSED: mainnet requires --follow-only'
```

## Resources

Measured on stagenet, Ubuntu 26.04, i5-14500T, one levin peer, 2026-09-25:

| | |
|---|---|
| Venv with Conan and CMake (pip, about 40 MB download) | 95-353 s on a 60-100 KB/s link |
| `git clone --filter=blob:none` | 93 s on the same link |
| Build: `conan install` from an empty `~/.conan2`, configure, compile `c2pool-v37-xmr` with `JOBS=6` | 148-177 s (Conan downloads prebuilt Boost and builds only gtest and zeromq) |
| Disk: `~/.conan2` + `~/c2pool` (with `build`) + venv | 171 MB + 107 MB + 80 MB |
| Disk: output-set file | 1.1 GiB (mainnet 17.1 GiB) |
| Boot to the chain index synced | 36 s (3.4 s of that is the sha256 of the output set) |
| Node memory | peak RssAnon 0.99 GB, VmHWM 1.18 GB |
| Levin traffic in the first 407 s (two levin peers) | 1.6 MB in, 0.11 MB out |

The output-set file is memory-mapped, so it also shows up in the page
cache. Mainnet needs 20 GB of disk for the output set.

## Known limits

- **FCMP++ / Carrot is not supported.** The node does not follow the chain
  past that Monero hard fork.
- **Block withholding.** A miner can submit shares and keep a found block to
  itself. The pool cannot detect this. The same is true of every pool.
- **Prototype.** No release tag exists yet, and the output-set download is
  not published yet.
- **Payee addresses.** Only MAIN (standard) addresses are supported as
  payees: the node refuses the others at start and at the stratum login.
- **Mainnet** runs follow-only (see [Mainnet](#11-mainnet)).
