# c2pool — P2Pool rebirth in C++

[![CI](https://github.com/frstrtr/c2pool/actions/workflows/build.yml/badge.svg)](https://github.com/frstrtr/c2pool/actions/workflows/build.yml)
[![Claude for Open Source](https://img.shields.io/badge/Claude%20for%20Open%20Source-supported-D97757?logo=claude&logoColor=white)](https://claude.com/contact-sales/claude-for-oss)

C++ reimplementation of [forrestv/p2pool](https://github.com/p2pool/p2pool) targeting the **V36 share format**, with **per-coin binaries** for six parent chains and their merged-mining children: **Litecoin** (flagship — LTC + DOGE, PEP, BELLS, LKY, JKC, SHIC), **Bitcoin** (+ Namecoin), **DigiByte** (Scrypt), **Bitcoin Cash**, **Dash**, and **BIP-110** (the Bitcoin Knots BLAKE2b minority hard fork — embedded daemonless, experimental). See [Supported chains](#supported-chains) for the full matrix and status.

Bitcoin wiki: <https://en.bitcoin.it/wiki/P2Pool>

Original forum thread: <https://bitcointalk.org/index.php?topic=18313>

## Daemonless Dash

c2pool-dash builds valid Dash mainnet blocks from embedded coin-state. The
deterministic masternode list, LLMQ quorums, ChainLocks and the DIP-4 coinbase
are reconstructed inside c2pool. No Dash Core node is required on the serve path.
Blocks built this way have been accepted on Dash mainnet, including the pool
development-fee split. A bare `c2pool-dash --run` is daemonless: with no
`--coin-rpc` given, every embedded serving lever defaults ON
(`src/c2pool/main_dash.cpp` banner, "ALL embedded serving levers default ON
when NO dashd arm is given"; resolver in
`src/impl/dash/coin/good_citizen_defaults.hpp`). The public node
`dash.voidbind.com` runs this posture with no dashd on the host. A node started
with `--coin-rpc H:P` keeps dashd as the reward-safe fallback arm — the
operator's hotel deployment still runs dashd-attached — so both postures are
supported by the same binary. The remaining work is the daemonless-finalize item
below (retiring the `--coin-rpc` fallback entirely). See
[Per-binary launch reference](#per-binary-launch-reference) for the flags.

## Governance

Daemonless-Dash finalization has a funding proposal in Dash on-chain governance.
The c2pool-daemonless-finalize proposal is in its voting phase; masternode
operators can vote on it before the next superblock.

- DashCentral: https://www.dashcentral.org/p/c2pool-daemonless-finalize
- Governance object: fa758340f1bd2391d17bb43667f76c5d9070d737b68e018e42ed75b09c6ba631
- Vote from a masternode:

  ```
  dash-cli gobject vote-many fa758340f1bd2391d17bb43667f76c5d9070d737b68e018e42ed75b09c6ba631 funding yes
  ```

Funding requires net yes votes equal to 10 percent of enabled masternodes by the
next superblock.

## Daemonless BIP-110

c2pool-bip110 follows the BLAKE2b hard-fork chain over coin P2P with no bitcoind
on the serve path. It is an embedded SPV header-follower: below height 961640 it
validates SHA256d, and at/after the fork it validates the byte-exact BLAKE2b
proof-of-work of the 164-byte v2 header — a SHA256d block past the fork is
rejected, so the node tracks the BLAKE2b chain rather than the higher-work
canonical Bitcoin chain. A known-answer test reproduces the canonical hash of
live fork block 961640 (a block the fork network mined, not c2pool). This
fork-following node is on `master` and is running live: `bip110.voidbind.com` is
synced to the BLAKE2b fork tip.

The mining and reward-safe daemonless mempool-serving stack — Stratum-v1 work
source, block assembler, and fail-closed reward-safety cross-checks
(`coinbasevalue == subsidy + fees`, committed tx-merkle/txcount, refuse-to-serve
on mismatch, submit-side merkle re-verify), plus the 0.1% author-donation split —
is on `master` (merged via #1439). The live node at `bip110.voidbind.com` serves
the fork mempool and accepts Stratum miners at `stratum+tcp://bip110.voidbind.com:9336`,
behind a full coin-generic dashboard.

The value of this lane is strategic, not revenue: BIP-110 is a minority fork
whose coin is effectively unlisted (block reward ≈ 0 in fiat), and mining a demo
block requires renting BLAKE2b (Sia-algorithm) hashrate. The goal is to be a
working *decentralized* pool on a fresh fork — a P2Pool-style alternative to
centralized fork-mining gateways — not an earnings lane. This lane imports **zero
Dash consensus machinery**; it is Bitcoin-native.

`bip110.voidbind.com` is part of the **voidbind daemonless-standalone fleet** —
public pools that run with no coin daemon on the serve path:
`btc.voidbind.com`, `bch.voidbind.com`, `dgb.voidbind.com`, `dash.voidbind.com`,
and `bip110.voidbind.com`.

Mining (experimental, live): point a BLAKE2b (Sia-algorithm) miner at `stratum+tcp://bip110.voidbind.com:9336` with username `<BIP-110-address>.<worker>` and any password. Daemonless standalone node on the BLAKE2b fork; block reward is effectively zero today (coin unlisted) — a decentralized-pool proof, not a revenue venue.

## Supported chains

c2pool builds one binary per **parent chain** (`c2pool-<coin>`). Several parents also merge-mine **AuxPoW child chains** in the same coinbase.

| Parent chain | Algorithm | Merged-mining children | Status |
|---|---|---|---|
| **Litecoin** (LTC) | Scrypt | DOGE, PEP, BELLS, LKY, JKC, SHIC — external daemons | **Production** (V36; live LTC+DOGE blocks) — `c2pool-ltc` |
| **Bitcoin** (BTC) | SHA256d | Namecoin (NMC) | Live, daemonless (`c2pool-btc --coin-p2p-discover`; btc.voidbind.com); NMC embedded merged mining in development |
| **DigiByte** (DGB) | Scrypt¹ | DOGE (embedded, `-DAUX_DOGE`) | Live, daemonless (`c2pool-dgb --run --coin-p2p-discover`; dgb.voidbind.com) — mainnet only, no testnet mode |
| **Bitcoin Cash** (BCH) | SHA256d | — | Live, daemonless (`c2pool-bch --pool`; bch.voidbind.com) |
| **Dash** (DASH) | X11 | — | Live, daemonless (`c2pool-dash --run`; dash.voidbind.com); dashd-attached posture via `--coin-rpc` still supported |
| **BIP-110** (Knots BLAKE2b fork) | BLAKE2b² (SHA256d until height 961640) | — | **Experimental** (new fork; daemonless embedded; live on bip110.voidbind.com) — `c2pool-bip110 --run` |

"Live" means a public voidbind node runs that per-coin binary with no coin
daemon on the serve path. It is not a production-maturity claim: only the LTC
line has the crossing-soak record behind it. Each binary's real flag surface is
in [Per-binary launch reference](#per-binary-launch-reference).

¹ DigiByte is a MultiAlgo chain; c2pool runs its **Scrypt** algorithm as a standalone parent — it is **not** an AuxPoW child of Litecoin.

² BIP-110 is a minority Bitcoin hard fork (Bitcoin Knots): its proof-of-work switches SHA256d→BLAKE2b at block height 961640 with a one-off difficulty reset, and it uses a reduced block weight of 800000 WU (RDTS). It shares Bitcoin mainnet's network magic and port until the fork; fork peers advertise `NODE_BLAKE2B` (service bit 28).

## Status & Maturity — read this before evaluating

c2pool is a decentralized mining-pool codebase and the home of the **v37 research
line** (Roundabout / Work Receipts / MRR). This section states, plainly, what does
and does not yet exist, so the work can be judged on what it actually is.

**v37 is design- and prototype-stage. Do not run it in production.**

### What exists
- A **formally specified** settlement/lanes core: TLA⁺ specs, model-checked with
  TLC (green over the bounded configurations checked in). This is a proof over a
  *model*, not evidence at scale.
- **A v37 engine consumer tree implemented in C++** under `src/c2pool/v37/` — the
  Work Receipts / Roundabout settlement pipeline as a **reference/prototype engine
  behind CI, not a production node.** Merged behind CI: the W1 O1 executor and W2
  receipt ingestion (admission-first, carrier-position credit — PR #1483), the W4
  prerequisites (identity view + read-at-version ring — PR #1485), W4 per-lane
  settlement (OWED-ledger fold + O2 cut + O5.5 — PR #1486), W5 coinbase assembly
  (oldest-owed-first K_fair + h_min carry + §13 root — PR #1487), and W3 carrier
  relay over the v36 p2p (wire extension + R_MAX — PR #1484). W6 persistence /
  restart-recovery is a **reviewed draft, not landed** (PR #1506).
- An isolated **"Family B: XMR lane"** (Monero / RandomX) under `src/impl/xmr/`,
  which does **not** touch the v37 consensus digest. Merged: the lane foundation
  (scaffold + vendored RandomX + X0 — PR #1500), buildable KAT-tested primitives
  (RandomX CI-gated — PR #1502), the monerod adapter + descriptor-finalize + receipt
  envelope (PR #1503), and stratum + FCMP-fenced coinbase-settlement + carrier wire
  (PR #1507). Goldens, real-RandomX verify, and the end-to-end KAT are **in progress
  (draft, not merged)**; a live stagenet run is **not started**.
- **Reference prototypes** under `proto/` (TLA⁺, MRR refimpl + goldens, the M4 sync
  feasibility harness, testbeds) and the v37 design-track spec/headers under
  `src/sharechain/v37/`. These are for study and reproduction, not deployment.
- The production multi-coin pool code (v36 line) that c2pool actually runs.

### What does NOT yet exist — the honest gaps
- **Not wired into a live node.** The v37 engine exists as a **reference/prototype
  behind CI**; it is **not** connected to a live production node lifecycle for
  settlement. The F1 finalize-driver obligation is **dormant** — no production
  finalize caller is wired — so nothing settles on a live network today.
- **No public v37 testnet.** There is no running v37 network; the engine and lanes
  exercise **simnet / loopback only**. The runnable v37 artifacts are the engine
  tree and the prototypes above.
- **No performance benchmark.** The only performance artifact is a Python
  *feasibility* harness (M4). There is **no benchmark of the real engine**;
  throughput, latency, and scaling claims are **unproven** until one exists.
- **XMR lane is pre-stagenet.** Its RandomX verify runs **CI-gated in light mode**;
  there is no run against a live `monerod`-stagenet + real miner yet, and the XMR
  PayoutDescriptor kind-bytes are staged/reserved pending a canon ruling, not
  activated.
- **No token, no production deployments.** There is no v37 token, and nothing v37 is
  deployed in production.
- **Formal ≠ empirical.** Model-checking bounds behavior over small configurations;
  it does **not** substitute for a benchmark or a live network.

### v36 consensus note
- In July 2026 the LTC v36 line hit a consensus incident: specific **false-activation
  modes** of the AutoRatchet (an automatic protocol-upgrade latch) could trip on
  absence-as-assent and flap without hysteresis, desynchronizing the share chain.
  Those specific modes were caught and are now **guarded by regression tests** — see
  commit `a7e5b29b8` (LTC ratchet mode-2 false-activation guard, PR #930) and its C5
  regression KATs. A deeper redesign — deterministic ancestry-depth activation with
  hysteresis and chain self-heal, to close the whole *class* rather than the known
  modes — is **in progress on the design track and not yet landed. We do not claim
  the class is fully closed.**
- **Donation script (legacy key, disclosed):** the v36 donation output currently
  uses a P2SH script that **inherits a legacy p2pool donation key** from the
  upstream codebase. This is **not an endorsement by, or involvement of, any third
  party** — it is inherited code. It is scheduled for replacement with a
  **c2pool-only script in v37**. v36 blocks already produced with the inherited
  script are immutable consensus history and cannot be retroactively changed; the
  clean script becomes the default at the v37 boundary.

### v36 ratchet complete — the last generation shared with Python p2pool
- **The LTC line has ratcheted to V36.** As of August 2026 the live Litecoin
  sharechain signals **100% V36** across the sampling window, and c2pool nodes
  produce and validate **V36 PPLNS** shares on the shared LTC+DOGE chain alongside
  the remaining Python `p2pool` v36 nodes. V36 is now the operating generation, not
  a transition target.
- **V36 is the end of the line for the Python implementation.** The Python `p2pool`
  is maintained only for the V36 sharechain it already interoperates with; no
  further Python protocol development is planned. V36 is the **final share format
  shared between the Python codebase and c2pool (C++).**
- **v37 is C++ only.** The next generation — **Work Receipts** and the **MRR
  Roundabout** settlement/lanes core — is being built exclusively in c2pool. There
  is no Python v37, and the v37 sharechain does not interoperate with Python
  `p2pool`. v37 remains design- and prototype-stage per the notes above and must not
  be run in production.

### CI / repo state
- The v37 research line is merged to `master` (PR #809, "V37 dev"), and the v37
  engine consumer tree (`src/c2pool/v37/`, W1–W5) and the isolated XMR Family-B lane
  (`src/impl/xmr/`) now build behind CI on both build legs. **Current master CI is
  green across the required per-coin gates and the coin matrix** (DASH / LTC / BCH /
  DGB / DOGE); the RandomX-dependent XMR checks run CI-gated in light mode, and the
  CodeQL security scan is a non-gating job.

### Provenance
c2pool builds on ideas from p2pool but is an **independent codebase**. No outside
party is represented as endorsing, maintaining, or being involved in c2pool.

---

## Credits

c2pool is an independent C++ implementation of the P2Pool sharechain concept originally created by Forrest Voight (forrestv, <https://github.com/forrestv/p2pool>).

Development is supported by Anthropic's [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) program (2026). The design, the consensus rules, and responsibility for every byte shipped remain with the maintainers.

> **First merged-mined DOGE block:** [#6135703](https://blockchair.com/dogecoin/block/f84500c25a4cce2a08887f29763726bd5ecec7b66fed65a88b181fb0b0ab2383) (2026-03-23) — decentralized LTC+DOGE merged mining via P2Pool V36, cross-validated with c2pool on shared share chain
>
> **First daemonless DOGE block:** (2026-03-27) — DOGE block accepted on testnet4alpha via embedded SPV P2P, no dogecoind RPC needed
>
> **Daemonless DASH chain state at the live tip** (2026-07-29) — an embedded DASH node started from an empty data dir reached mainnet tip #2513008 in about four minutes with no `dashd` in the path: 16 MB of headers, 57 tip advances, and the full masternode set (8,620 deltas over 59 `mnlistdiff` messages) acquired entirely over coin P2P rather than from `protx list`. Chain-state acquisition only — this is not a block found daemonlessly on DASH.
>
> **First V36 Twin Block:** LTC [#3085349](https://blockchair.com/litecoin/block/3085349) + DOGE [#6154761](https://blockchair.com/dogecoin/block/6154761) (2026-04-05) — simultaneous LTC+DOGE block found by v36-signalling nodes running p2pool v36 producing V35 shares with `desired_version=36`; detected and displayed by c2pool's embedded block scanner
>
> **Sharechain Transparency Explorer** (2026-04-07) — defragmenter-style sharechain visualization with interactive PPLNS treemaps, animated hover effects, per-miner LTC+DOGE payout breakdown, V36 upgrade pressure for V35 miners
> 
> **Recent Bitcoin Block Mined by P2pool** (2026-06-27 05:34:44 UTC) BTC [#955609](https://blockchair.com/bitcoin/block/955609)
> 
> **Recent Bitcoin Block Mined by P2pool** (2025-03-07 06:08:22 UTC) BTC [#886688](https://blockchair.com/bitcoin/block/886688)
>
> **First DASH block, c2pool** (2026-07-20 01:15:15 UTC) DASH [#2507753](https://blockchair.com/dash/block/2507753) — a solo X11 block. The DIP4 coinbase pays the masternode the network requires at that height, and dashd accepted it. The payee is checked against the template before the block is broadcast; work built on a stale template is discarded, not mined.
>
> **DASH block at a full-payment height** (2026-07-20 23:25:32 UTC) DASH [#2508254](https://blockchair.com/dash/block/2508254) — six transactions, three consensus-mandated payments in the coinbase. The full payee set was assembled and verified against the template before submission, and dashd accepted the block. The demanding case takes the same path as the trivial one.

---

## Tested platforms

| OS | Version | Compiler | Boost | Arch | Status |
|----|---------|----------|-------|------|--------|
| Ubuntu | 24.04.4 LTS | GCC 13.3 | 1.90 (Conan) | x86_64 | Working |
| macOS | 26.3.1 (Tahoe) | Apple Clang 21.0 | 1.90 (Homebrew) | x86_64 Intel | Working |
| macOS | 26.3.1 (Tahoe) | Apple Clang 21.0 | 1.90 (Homebrew) | arm64 (M-series) | Working |
| Windows | 11 (26100) | MSVC 2022 | 1.90 (Conan) | x86_64 | Working |

---

## Download

Pre-built binaries are available on the [Releases page](https://github.com/frstrtr/c2pool/releases). The current release line is **v0.2.x** (V36). Packages are built **per parent chain** and named `c2pool-<coin>-<version>-<platform>` (`ltc`, `btc`, `dgb`, `dash`, `bch`, `bip110` — the coin matrix in `.github/workflows/release.yml`).

| Platform | Package | Notes |
|----------|---------|-------|
| Linux x86_64 | `.tar.gz` | Extract and run `./start.sh` |
| macOS (universal) | `.dmg` or `.zip` | Single universal arm64 + x86_64 build (lipo-merged); bundled dylibs, no Homebrew needed |
| Windows x86_64 | `.zip` or `setup.exe` | Installer bundles VC++ Runtime + firewall rules |

### Verify downloads

Each release includes a `SHA256SUMS` file. Verify after downloading:

```bash
# Linux / macOS
sha256sum -c SHA256SUMS

# Windows (PowerShell)
Get-FileHash c2pool-*-setup.exe -Algorithm SHA256
# Compare with the hash in SHA256SUMS
```

### Reproducible builds

All release binaries are built from the tagged git commit. To verify a binary matches the source:

1. Check the git tag: `git log v0.2.0 --oneline -1`
2. Build from that tag following the platform-specific guide
3. Compare the SHA256 of your binary with the release `SHA256SUMS`

> Exact binary reproducibility depends on compiler version and build environment.
> The `SHA256SUMS` file in each release documents the official build output.

---

## Quick start

**Linux (Ubuntu 24.04)**
```bash
sudo apt-get install -y g++ cmake make libleveldb-dev libsecp256k1-dev python3-pip
pip install "conan>=2.0,<3.0" --break-system-packages
export PATH="$PATH:$HOME/.local/bin"   # so `conan` is on PATH (add to ~/.bashrc to persist)
conan profile detect --force

git clone https://github.com/frstrtr/c2pool.git
cd c2pool && mkdir build && cd build
conan install .. --build=missing --output-folder=. --settings=build_type=Debug
cmake .. --preset conan-debug
cmake --build . --target c2pool -j$(nproc)
./src/c2pool/c2pool
```

**Linux (Ubuntu 26.04 LTS)** — *theoretical: CI builds on 24.04, so the 26.04 path below is documented from known toolchain deltas, not yet exercised in the CI matrix. Report any gotcha via an issue.*

The 24.04 steps above apply unchanged; the build is Conan-managed, so it is largely toolchain-version agnostic. Expect only these deltas on 26.04:
- **Newer default compiler.** 26.04 LTS ships a newer default GCC (15.x) / libstdc++. No action needed — `conan profile detect --force` picks up the system toolchain, and `conan install --build=missing` builds the C++ dependencies (Boost 1.90, etc.) against it. If the newer compiler turns a dependency warning into an error, `--build=missing` already rebuilds that dependency from source with your toolchain.
- **Externally-managed pip (PEP 668).** As on 24.04, install Conan with `pip install "conan>=2.0,<3.0" --break-system-packages`, or prefer an isolated `pipx install "conan>=2.0,<3.0"` (`sudo apt-get install -y pipx`) so the tool does not touch the system Python. (Conan is c2pool's **C++** dependency manager — a pip-distributed tool — and is unrelated to any Python component of a pool.)
- **apt package names are unchanged**: `g++ cmake make libleveldb-dev libsecp256k1-dev python3-pip`.

Everything else — `conan install` → `cmake --preset conan-debug` → `cmake --build` — is identical to 24.04.

**macOS (Intel & Apple Silicon)**
```bash
xcode-select --install
brew install cmake boost leveldb secp256k1 nlohmann-json yaml-cpp

git clone https://github.com/frstrtr/c2pool.git
cd c2pool && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target c2pool -j$(sysctl -n hw.ncpu)
./src/c2pool/c2pool
```

**Windows (setup.exe or build from source)**

Download `c2pool-ltc-VERSION-windows-x86_64-setup.exe` from [Releases](https://github.com/frstrtr/c2pool/releases) and run the installer. Or build from source — see [doc/build-windows.md](doc/build-windows.md).

That's it. No litecoind, no dogecoind, no config file. The node starts in
**integrated P2P pool mode** with embedded LTC and DOGE SPV nodes, connects
to p2pool sharechain peers via hardcoded bootstrap hosts, and waits for
shares before opening stratum to miners.

Miners connect to stratum and set their LTC payout address as the username
(p2pool convention). No `--address` flag needed.

Full step-by-step guides: [Linux](doc/build-unix.md) | [macOS](doc/build-macos.md) | [Windows](doc/build-windows.md)

Common operator questions (merged coins, payouts, dashboard): [docs/FAQ.md](docs/FAQ.md)

---

## Operating modes

> The **Operating modes**, **Defaults**, **Peer discovery**, **Merged mining**,
> **Ports** and **Configuration reference** sections below describe the LTC
> binary (`c2pool-ltc`, dev alias `c2pool`, `src/c2pool/main_ltc.cpp`). The
> other per-coin binaries have their own, smaller flag surfaces — see
> [Per-binary launch reference](#per-binary-launch-reference).

c2pool has four operating modes. The default is a full P2P pool — no flags required.

| Mode | CLI flag | P2P sharechain | Coinbase payouts | Use case |
|------|----------|:-:|---|---|
| **Integrated** | *(default)* | yes | PPLNS from sharechain | Decentralized pool node |
| **Solo** | `--solo` | no | Proportional by miner hashrate | Private pool for own ASICs |
| **Custodial** | `--custodial` | no | 100% to `--address` | Hosted pool, off-chain accounting |
| **Sharechain** | `--sharechain` | yes | *(no mining)* | P2P relay node only |

Legacy `--standalone` mode (minimal stratum + RPC daemon, no embedded SPV) is available for backwards compatibility.

### DASH daemonless masternode-set checkpoint — trust anchor

**If you run DASH without a dashd arm (a bare `--run` is daemonless by default),
you are trusting the c2pool release build for one specific piece of data. This
section says exactly which, and why.**

To build a DASH block, c2pool must know which masternode is next in the DIP-3
payment queue. Paying the wrong one produces a coinbase the network rejects
(`bad-cb-payee`) — a mined block thrown away. Ranking the queue needs each
masternode's `scriptPayout` and `nLastPaidHeight`, and **neither is available
from the DASH P2P network**: the Simplified MN List (`mnlistdiff`) omits both,
and neither is committed in `merkleRootMNList`, so there is no header
commitment to check them against.

So c2pool ships a **release-pinned masternode set** — a trust anchor of the
same class as Bitcoin Core's `assumeutxo` — and replays blocks forward from it
to the current tip.

**What the node verifies for itself, with no trust:**

- **chain position** — the anchor names a block hash, and is rejected unless
  c2pool's own X11-PoW + DGW-validated header chain holds exactly that hash at
  exactly that height;
- **integrity** — a SHA-256 digest over the anchor's contents (an integrity
  check on the file, *not* a signature: whoever can change the source can
  recompute the digest — it catches accidents, not malice);
- **forward consistency** — every block replayed from the anchor re-derives
  the projected payee and compares it against that block's real coinbase, so a
  wrong anchor is falsified within a few blocks.

**What you are trusting:** the membership and payout state of the masternode
set *at the anchor height*. Nothing available to the node can prove it.

A fully trustless alternative exists — replaying every block from DIP-3
activation (~1.5M blocks) — and is **planned as a later opt-in verify-mode**.
It is not implemented today.

**Fail-closed by design.** If the anchor is missing, corrupt, for the wrong
network, in the wrong chain position, further behind the tip than
`--embedded-mn-bridge-max` (default 20000 blocks, ≈34 days), or contradicted
by a replayed block, c2pool logs the refusal at `ERROR` and **refuses to serve
embedded DASH templates**. It falls back to a configured dashd, or serves
nothing. It never guesses a masternode payee.

Running DASH with a dashd RPC configured does **not** use the anchor at all —
`protx list registered true` is authoritative and is used instead.

Both the anchor and the RPC seed carry the **registered** masternode set, not
the valid one: `protx list valid` filters PoSe-banned masternodes out entirely,
which makes "banned" and "does not exist" the same observation. Because the
replay's only insertion path is `ProRegTx`, a `ProUpServTx` that later revives
such a masternode would have no entry to revive, and it could never re-enter the
DIP-3 payment queue — leaving every later payee projection one queue slot ahead
of the chain's. Carrying banned masternodes as **present but ineligible**
(eligibility is derived from `poseBanHeight`) keeps the revive path working.

Details, provenance of the shipped anchor, and the release-time re-pinning
procedure: [`src/impl/dash/coin/checkpoints/README.md`](src/impl/dash/coin/checkpoints/README.md).

### Startup examples

```bash
# Default: full P2P pool, embedded SPV, wait for peers
./c2pool

# Same, with explicit address for node-owner fee
./c2pool --address YOUR_LTC_ADDRESS --fee 1

# Solo pool for own miners (no sharechain, proportional payouts)
./c2pool --solo

# Custodial pool (all coinbase to operator, stratum for accounting)
./c2pool --custodial --address YOUR_LTC_ADDRESS

# With external LTC daemon instead of embedded SPV
./c2pool --no-embedded-ltc \
  --coind-address 127.0.0.1 --coind-rpc-port 9332 \
  --rpcuser user --rpcpassword pass

# Testnet
./c2pool --testnet

# With config file
./c2pool --config config/c2pool_mainnet.yaml

# Full option reference
./c2pool --help
```

### Feature matrix

| Feature | Integrated | Solo | Custodial | Sharechain |
|---------|:---:|:---:|:---:|:---:|
| Embedded LTC SPV | on | on | on | -- |
| Embedded DOGE SPV | on | on | on | -- |
| Stratum server | yes | yes | yes | -- |
| VARDIFF | yes | yes | yes | -- |
| P2P share exchange | yes | -- | -- | yes |
| PPLNS payouts | yes | -- | -- | -- |
| Proportional payouts | -- | yes | -- | -- |
| Single-address coinbase | -- | -- | yes | -- |
| Merged mining (DOGE etc.) | yes | yes | yes | -- |
| Web dashboard + REST API | yes | yes | yes | -- |
| Per-worker accounting | yes | yes | yes | -- |
| `--address` required | no | no | **yes** | no |
| `--fee` supported | yes | yes | -- | -- |
| Redistribute modes | yes | -- | -- | -- |
| ShareTracker / LevelDB | yes | -- | -- | yes |
| Think loop / monitoring | yes | -- | -- | -- |

### Payout model by mode

| Mode | Who gets paid | How amounts are calculated |
|------|---------------|---------------------------|
| **Integrated** | All miners in PPLNS window | Share weight from sharechain (decentralized consensus) |
| **Solo** | Connected stratum miners | Proportional to real-time hashrate from RateMonitor |
| **Custodial** | Node operator only | 100% of block reward to `--address`; miners tracked in `/stratum_stats` |

In **integrated** and **solo** modes, miners set their payout address as
their stratum username (e.g., `LcAddress.worker1`). The address appears
directly in coinbase outputs. `--address` is optional — it serves as the
node operator's fee destination and fallback when no miners are connected.

In **custodial** mode, miner stratum usernames are used for accounting only
and never appear in coinbase outputs. The backoffice polls `/stratum_stats`
for per-worker hashrate, accepted shares, and connection time.

---

## Defaults

Running `c2pool` with no arguments is equivalent to:

```
--integrated --embedded-ltc --embedded-doge --wait-for-peers
--header-checkpoint 3088000:4a7fc8d4...
--doge-header-checkpoint 6160000:51efd04d...
```

| Setting | Default | Override |
|---------|---------|----------|
| Operating mode | Integrated P2P pool | `--solo`, `--custodial`, `--sharechain`, `--standalone` |
| LTC backend | Embedded SPV (DNS seeds) | `--no-embedded-ltc` (requires RPC daemon) |
| DOGE backend | Embedded SPV | `--no-embedded-doge` (disables merged mining) |
| LTC bootstrap | Block 3,088,000 | `--header-checkpoint HEIGHT:HASH` |
| DOGE bootstrap | Block 6,160,000 | `--doge-header-checkpoint HEIGHT:HASH` |
| Startup mode | Wait for peers (persist=true) | `--genesis` or `--startup-mode auto` |
| Coin daemon | Not required | `--coind-address` / `--coind-rpc-port` |
| `--address` | Optional (miners use stratum username) | Required only for `--custodial` |
| `--fee` | 0% | `-f 1` (1% to `--address`) |
| Stratum port | 9327 | `-w PORT` |
| P2P port | 9326 | `--p2pool-port PORT` |
| Web port | 8080 | `--web-port PORT` |
| Data directory | `~/.c2pool` (`%APPDATA%\c2pool` on Windows) | `--data-dir PATH` |

> **Running two instances on one host?** Give each its own `--data-dir`.
> All per-instance on-disk state — the sharechain LevelDB, address store,
> whitelist, logs, ratchet, and found-blocks db — is rooted there, so
> co-located instances never contend the same LevelDB `LOCK`. Leaving it
> unset keeps the historical `~/.c2pool` path, byte-for-byte unchanged.

### Testnet overrides

On `--testnet`, mainnet SPV checkpoints are automatically cleared (testnet
uses a different chain). Ports shift to testnet defaults (P2P 19326,
stratum 19327).

---

## Peer discovery and sharechain bootstrap

The sharechain P2P layer discovers peers from multiple sources:

| Source | Config | Priority |
|--------|--------|----------|
| CLI seed nodes | `-n HOST:PORT` (repeatable) | Highest |
| YAML config | `seed_nodes:` list | Appended to CLI |
| `~/.c2pool/ltc/pool.yaml` | `bootstrap_addrs:` (auto-generated, persists learned peers) | Medium |
| Hardcoded bootstrap hosts | `ml.toom.im`, `usa.p2p-spb.xyz`, + 9 IPs | Fallback |

With `startup_mode: wait` (default), the node waits until peers deliver
shares before opening stratum. This matches p2pool's `PERSIST=True` behavior.

| Startup mode | CLI flag | Behavior |
|-------------|----------|----------|
| **wait** (default) | `--wait-for-peers` | Wait for peers to deliver shares, then mine |
| genesis | `--genesis` | Create first share immediately (new chain) |
| auto | `--startup-mode auto` | Wait 60s for peers, then genesis |

---

## Merged mining

LTC and DOGE have built-in embedded SPV nodes (enabled by default).
Other chains need their daemon running externally.

| Coin | chain_id | Backend | `--merged` example |
|------|----------|---------|---------------------|
| DOGE | 98 | **Embedded SPV** | auto-configured |
| PEP | 63 | External | `PEP:63:127.0.0.1:29377:user:pass` |
| BELLS | 16 | External | `BELLS:16:127.0.0.1:19918:user:pass` |
| LKY | 8211 | External | `LKY:8211:127.0.0.1:9916:user:pass` |
| JKC | 8224 | External | `JKC:8224:127.0.0.1:9770:user:pass` |
| SHIC | 74 | External | `SHIC:74:127.0.0.1:33863:user:pass` |
| DINGO | 98 | External | Cannot run with DOGE (same chain_id) |

DOGE merged mining activates automatically when `--embedded-doge` is on (default).
External daemons use `createauxblock`/`submitauxblock` RPC.

**DigiByte Scrypt** is its own parent chain with its own binary and sharechain:
`c2pool-dgb` (`src/c2pool/main_dgb.cpp`, sharechain port 5024). It is not
selected through the LTC binary — `--net digibyte` on `c2pool-ltc` is the LTC
binary's legacy chain selector (`--net CHAIN`, `main_ltc.cpp` usage text), not
the DGB pool. See [c2pool-dgb](#c2pool-dgb--digibyte-scrypt) below.

---

## Ports

| Port | Purpose |
|------|---------|
| 9326 | P2Pool sharechain (peer-to-peer) |
| 9327 | Stratum mining |
| 8080 | Web dashboard + REST API |

---

## Configuration

### Settings file (TOML) — all binaries

Every node binary resolves its launch configuration in three layers
(`src/core/settings_cli.hpp`): **compiled defaults (L0) < settings file (L1) <
command line (L2)**. The CLI always wins, even over a money-class key that the
file has acknowledged. The catalog of every key and its per-binary CLI spelling
is `src/core/param_catalog.inc`.

| Flag | Binaries | Behaviour |
|------|----------|-----------|
| `--settings PATH` | ltc, dash, btc, dgb, bch | Explicit settings-file path. The file **must exist** — a typo is fatal (exit 78), it never falls through silently. Omitted: `<data-dir>/c2pool.toml` is loaded if present, else the run is pure compiled+CLI. (`settings_cli.hpp` `resolve_settings_path`) |
| `--dump-resolved-config` | ltc, dash, btc, dgb, bch | Print the fully resolved config with the source of every key (compiled / file / CLI) between `=== RESOLVED CONFIG BEGIN ===` / `END` markers, then exit 0 **without starting the node**. Works with no coin endpoint configured. |
| `--ack-money-settings` | ltc, dash, btc, dgb, bch | Compute and print the money-ack hash for the resolved settings file, then exit. Requires a settings file (`--settings PATH` or the data-dir default); exit 78 otherwise. |
| `--data-dir PATH` | ltc, dash, btc, dgb, bch | Root all per-instance state (sharechain LevelDB, addr store, logs, …) under `PATH` (default `~/.c2pool`). Handled before the settings probe, so the default `c2pool.toml` is looked up under the final data dir. Requires a non-empty, non-flag argument (exit 1 otherwise). |

**Money gate.** A settings file can never silently arm a money-class key
(`MONEY_*` rows in the catalog: fees, donation, payout addresses, network
identity, `embedded.null_arm`, …). A file that sets such a key without a
matching `[gate].money_ack_hash` is refused and the node exits 78 (`EX_CONFIG`)
before anything starts (`src/core/settings_file.hpp`). Run
`--ack-money-settings` to obtain the hash for the file as it stands, put it in
`[gate].money_ack_hash`, and the file is accepted; any later edit to a money key
invalidates the hash.

`c2pool-bip110` does not take `--settings` / `--data-dir` / `--dump-resolved-config`
(no `BIN_BIP110` alias for those rows in `param_catalog.inc`); its money
defaults are seeded from the catalog and overridden only by CLI flags
(`main_bip110.cpp` `main()`).

### Legacy YAML config (`--config`, LTC only, deprecated)

`--config FILE` loads a YAML overlay on the LTC binary only. It is catalogued as
`meta.config_yaml` — "DEPRECATED legacy YAML config overlay"
(`param_catalog.inc`) — and is kept this release for byte-identical behaviour of
existing YAML deployments. If both a `--config` YAML and a TOML settings file
resolve, the **TOML is skipped with a loud warning and the YAML wins** for this
release (`main_ltc.cpp`, M0b wiring block). Migrate to the TOML settings file;
the YAML path will be removed.

```bash
# Legacy (LTC only, deprecated)
./c2pool --config config/c2pool_mainnet.yaml
```

See [config/c2pool_mainnet.yaml](config/c2pool_mainnet.yaml) (mainnet) and
[config/c2pool_testnet.yaml](config/c2pool_testnet.yaml) (testnet) for the
legacy YAML key set.

### Configuration reference (LTC binary)

| CLI flag | YAML key | Default | Description |
|----------|----------|---------|-------------|
| `--integrated` | `integrated` | **true** | Full P2P pool mode |
| `--solo` | `solo` | false | Solo pool (no sharechain) |
| `--custodial` | `custodial` | false | Custodial pool (single-address coinbase) |
| `--sharechain` | `sharechain` | false | P2P node only (no mining) |
| `--standalone` | -- | false | Legacy solo (RPC daemon, no embedded SPV) |
| `--embedded-ltc` | `embedded_ltc` | **true** | Embedded LTC SPV node |
| `--no-embedded-ltc` | | | Disable embedded LTC, use RPC daemon |
| `--embedded-doge` | `embedded_doge` | **true** | Embedded DOGE SPV for merged mining |
| `--no-embedded-doge` | | | Disable embedded DOGE |
| `--net` | -- | litecoin | LTC-binary chain selector (`--net CHAIN`; alias `--blockchain`). Not the way to run DGB/BTC/BCH/DASH pools — those are separate binaries |
| `--testnet` | `testnet` | false | Enable testnet mode |
| `--settings FILE` | -- | `<data-dir>/c2pool.toml` | TOML settings file (all binaries; see above) |
| `--dump-resolved-config` | -- | -- | Print resolved config with sources, exit 0 |
| `--ack-money-settings` | -- | -- | Print the money-ack hash for the settings file, exit |
| `--config FILE` | -- | -- | **Deprecated** legacy YAML overlay (LTC only); takes precedence over TOML this release |
| `--address` | `solo_address` | -- | Node operator payout address (optional) |
| `--give-author` | `donation_percentage` | 0.1 | Developer fee % (p2pool default: 0.5%) |
| `-f` / `--fee` | `node_owner_fee` | 0 | Node owner fee % |
| `--node-owner-address` | `node_owner_address` | -- | Node owner payout address |
| `--redistribute` | `redistribute` | pplns | Mode: pplns/fee/boost/donate |
| `-n HOST:PORT` | `seed_nodes` | -- | Sharechain seed peer (repeatable) |
| `--startup-mode` | `startup_mode` | **wait** | Bootstrap: `wait`, `genesis`, `auto` |
| `--genesis` | | | Shortcut for `--startup-mode genesis` |
| `--wait-for-peers` | | | Shortcut for `--startup-mode wait` |
| `--header-checkpoint` | `header_checkpoint` | mainnet default | LTC SPV starting point (`HEIGHT:HASH`) |
| `--doge-header-checkpoint` | `doge_header_checkpoint` | mainnet default | DOGE SPV starting point |
| `--p2pool-port` | `port` | 9326 | P2P sharechain port |
| `-w` / `--worker-port` | `stratum_port` | 9327 | Stratum mining port |
| `--web-port` | `web_port` | 8080 | HTTP API / dashboard port |
| `--http-host` | `http_host` | 0.0.0.0 | HTTP bind address |
| `--coind-address` | `ltc_rpc_host` | 127.0.0.1 | Coin daemon RPC host |
| `--coind-rpc-port` | `ltc_rpc_port` | auto | Coin daemon RPC port |
| `--rpcuser` | `ltc_rpc_user` | -- | RPC username |
| `--rpcpassword` | `ltc_rpc_password` | -- | RPC password |
| `--max-conns` | -- | 8 | Target outbound P2P peers |
| `--stratum-min-diff` | `min_difficulty` | 0.0005 | Vardiff floor |
| `--stratum-max-diff` | `max_difficulty` | 65536 | Vardiff ceiling |
| `--stratum-target-time` | `target_time` | 3.0 | Seconds between pseudoshares |
| `--no-vardiff` | `vardiff_enabled` | true | Disable auto-difficulty |
| `--max-coinbase-outputs` | `max_coinbase_outputs` | 4000 | Max coinbase outputs |
| `--network-id` | `network_id` | 0 | Private chain identifier (hex) |
| `--log-level` | `log_level` | trace | trace/debug/info/warning/error |
| `--log-file` | `log_file` | debug.log | Log filename |
| `--log-rotation-mb` | `log_rotation_size_mb` | 100 | Log rotation threshold (MB) |
| `--log-max-mb` | `log_max_total_mb` | 1000 | Total size cap across all rotated log files (MB) |
| `--p2p-max-peers` | `p2p_max_peers` | 30 | Max total P2P peers |
| `--ban-duration` | `ban_duration` | 300 | P2P ban duration (seconds) |
| `--rss-limit-mb` | `rss_limit_mb` | 4000 | RSS memory abort limit (MB) |
| `--cors-origin` | `cors_origin` | -- | CORS Allow-Origin header |
| `--payout-window` | `payout_window_seconds` | 86400 | PPLNS window (seconds) |
| `--storage-save-interval` | `storage_save_interval` | 300 | Sharechain save interval |
| `--dashboard-dir` | `dashboard_dir` | web-static | Static dashboard directory |
| `--analytics-id` | `analytics_id` | -- | Google Analytics measurement ID (e.g. `G-XXXXXXXXXX`); injected into dashboard HTML `</head>` |
| -- | `address_explorer_prefix` | Blockchair | Custom address explorer URL prefix |
| -- | `block_explorer_prefix` | Blockchair | Custom block explorer URL prefix |
| -- | `tx_explorer_prefix` | Blockchair | Custom tx explorer URL prefix |
| -- | `explorer` | false | Enable lite block explorer (stores recent blocks + REST API) |
| -- | `explorer_url` | -- | Explorer URL injected into dashboard nav (e.g. `http://localhost:9090`) |
| -- | `explorer_depth_ltc` | 288 | LTC blocks to keep in explorer store |
| -- | `explorer_depth_doge` | 1440 | DOGE blocks to keep in explorer store |
| `--coinbase-text` | `coinbase_text` | see below | Custom coinbase scriptSig text |
| `--message-blob-hex` | -- | -- | V36 authority message blob |
| `--doge-testnet4alpha` | `doge_testnet4alpha` | false | Use DOGE testnet4alpha |

---

## Per-binary launch reference

Each parent chain ships as its own binary with its own hand-written argv parser.
The tables below are transcribed from those parsers on `master` — the `--help`
text of some binaries lags the parser, so the parser is the source of truth
cited here (`src/c2pool/main_<coin>.cpp`; canonical key names in
`src/core/param_catalog.inc`). The `--settings` / `--dump-resolved-config` /
`--ack-money-settings` / `--data-dir` control-plane flags are described once
under [Settings file (TOML)](#settings-file-toml--all-binaries) and only
listed here.

Common conventions:

- `[HOST:]PORT` — a bare port binds `0.0.0.0`; `HOST:PORT` binds one interface.
- Stratum and the web dashboard are **off unless bound** on `btc`, `dgb`, `bch`
  and `dash` (`--stratum` / `--http`; DASH's dashboard is the exception and is
  on at 8080 by default). `bip110` binds Stratum on 9336 by default.
- Unknown flags: `dash`, `btc`, `dgb`, `bch` reject them with a non-zero exit;
  `bip110` **silently ignores** them (its parse loop has no trailing `else`).
- Coin-daemon RPC credentials are never taken on argv: every `--coin-rpc-auth`
  / `--rpc-conf` points at a `bitcoin.conf`-style file.

### Default ports by binary

| Binary | Sharechain P2P | Stratum | Web dashboard | Coin P2P (embedded) |
|--------|---------------:|--------:|--------------:|--------------------:|
| `c2pool-ltc` | 9326 (`--p2pool-port`) | 9327 (`-w`) | 8080 (`--web-port`) | embedded LTC + DOGE SPV (DNS seeds) |
| `c2pool-btc` | 9333 (`--sharechain-port`) | off (`--stratum`) | off (`--http`) | 8333 (`--coin-p2p-discover`) |
| `c2pool-dgb` | 5024 (`--sharechain-port`) | off (`--stratum`) | off (`--http`) | 12024 (`--coin-p2p-discover` / `--coin-daemon`) |
| `c2pool-bch` | 9349 (fixed) | off (`--stratum`) | off (`--http`) | 8333 (`--peer`, or seed ladder when `--peer` port is 0) |
| `c2pool-dash` | 8999 mainnet / 18999 testnet (`--listen`) | off (`--stratum`) | 8080 (`--web-port`; 0 disables) | 9999 (`--coin-p2p-connect` / `--coin-p2p-discover`) |
| `c2pool-bip110` | 9337 (`--bip110-sharechain` to enable) | 9336 (`--no-stratum` to disable) | off (`--http`) | 8333 (`--peer` / `--coin-p2p-discover`) |

Sources: `src/impl/{btc,dgb,bch,dash}/config_pool.hpp` `P2P_PORT`;
`src/impl/bip110/params.hpp` `SHARECHAIN_P2P_PORT` / `SHARECHAIN_WORKER_PORT` /
`COIN_P2P_PORT`; each `main_<coin>.cpp` local-variable defaults.

### c2pool-dash — Dash (X11)

Source: `src/c2pool/main_dash.cpp` — `print_banner()` (usage text) and the
`main()` parse loop. Unknown argument → `unknown argument: …`, exit 1.

```bash
# Daemonless public pool (the dash.voidbind.com posture, no dashd on the host)
./c2pool-dash --run --data-dir /var/lib/c2pool/dash \
  --coin-p2p-discover --coin-p2p-peers 8 \
  --listen 0.0.0.0:8999 --addnode <sharechain-peer>:8999 \
  --stratum 0.0.0.0:7903 --web-host 127.0.0.1 --web-port 8082 \
  --dashboard-dir /opt/c2pool/web-static \
  --node-owner-address <your-DASH-address>

# dashd-attached (reward-safe fallback arm kept; creds read from dash.conf)
./c2pool-dash --run --coin-rpc 127.0.0.1:9998 --coin-rpc-auth ~/.dashcore/dash.conf \
  --stratum 3335
```

A bare `--run` **with no `--coin-rpc`** is the daemonless posture: every
embedded serving lever below defaults ON ("ALL embedded serving levers default
ON when NO dashd arm is given", banner text; resolver
`src/impl/dash/coin/good_citizen_defaults.hpp`). With `--coin-rpc` given, the
node is dashd-attached and the `--embedded-*` levers default OFF unless named.
Only the daemonless trust anchor applies to a daemonless node — see
[DASH daemonless masternode-set checkpoint](#dash-daemonless-masternode-set-checkpoint--trust-anchor).

**Modes and control plane**

| Flag | Meaning |
|------|---------|
| `--run` | Stand up the node (sharechain peer, coin feed, Stratum, web). Without it the binary runs the self-test and exits. |
| `--selftest` | Accepted explicitly; same as the default path. |
| `--version` / `--help` | Print and exit. |
| `--data-dir PATH`, `--settings PATH`, `--dump-resolved-config`, `--ack-money-settings` | Control plane, see [Settings file](#settings-file-toml--all-binaries). |
| `--testnet` / `--regtest` | Both set the testnet flag (the parser treats them identically). Sharechain port becomes 18999. |
| `--mine-block [--payout-pubkey-hash HEX] [--max-nonce N]` | One-shot CPU miner harness. |
| `--submit-block HEX` / `--submit-block-file PATH` | Drive one real `submitblock` through the dashd arm, then exit. |
| `--replay-utxo-db PATH [--replay-utxo-hash] [--replay-utxo-expect HEX]` | Standalone UTXO-fold utility; runs and exits, never serves. |
| `--dump-mn-checkpoint H FILE` | Write the self-derived masternode set at height H as a checkpoint `.inc`; two arguments. |

**Coin daemon arm (optional)**

| Flag | Default | Meaning |
|------|---------|---------|
| `--coin-rpc H:P` (alias `--coin-daemon`) | none = daemonless | dashd RPC endpoint. Endpoint only, no secret. |
| `--coin-rpc-auth PATH` | `~/.dashcore/dash.conf` | `dash.conf` with `rpcuser`/`rpcpassword`. |
| `--coin-zmq-hashblock tcp://H:P` | off | Subscribe to dashd ZMQ `hashblock` for instant tip refresh on the fallback arm (needs `zmqpubhashblock` in dashd). |
| `--embedded-oracle-shadow`, `--oracle-graduation-blocks N` (5000), `--oracle-class-coverage K` (20) | off | Observe-only per-block dashd cross-check + graduation ledger. Needs the RPC arm. |
| `--embedded-shadow-compare` | off | Observe-only served-template vs `getblocktemplate` diff on a worker thread. No-op without dashd. |
| `--embedded-no-dashd-mn-seed` [`--embedded-fold-only-proof`] | off | Cut the `protx list` payee seed while keeping dashd for observation (cut rehearsal); the second flag also leaves the checkpoint bridge unarmed. |

**Sharechain and coin P2P**

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen [HOST:]PORT` | `0.0.0.0:8999` | Sharechain (pool P2P) bind. |
| `--addnode H:P` (repeatable) | — | Persistent outbound sharechain peers. |
| `--connect H:P` (repeatable) | — | Connect-only sharechain peers. |
| `--no-p2p-relay` | off | Suppress the embedded won-block P2P relay (isolates the RPC submit arm). |
| `--coin-p2p-connect H:P` (repeatable) | — | Pin explicit DASH coin-network peers (port 9999). |
| `--coin-p2p-discover` | off | Seed-based (dnsseed.dash.org + fixed), scored, group-diverse coin-peer discovery — the network-standalone arm. Pinned peers are kept alongside. |
| `--coin-p2p-peers N` | 8 (cap 16) | Concurrent coin-network peers held. An evidence knob: `qfcommit`/`clsig` are announced once, so more peers = lower miss probability. |
| `--coin-p2p-magic HEX` | mainnet `bf0c6bbd` | Wire-magic override (testnet `cee2caff`, regtest `fcc1b7dc`). |
| `--embedded-fresh-datum-race[=false]`, `--embedded-fresh-datum-race-k N` (2) | off (`fresh_datum_race.hpp`: `static bool f = false`; the catalog help string says "default ON" — the code is authoritative) | Race the freshest `getmnlistd` to K distinct netgroups; fold the first self-checked reply. |
| `--embedded-getmnlistd-tracker[=false]` | off (`getmnlistd_tracker.hpp`: `static bool f = false`; same catalog/code mismatch) | Fixed 10 s per-slot re-ask tracker for the MnListDiff class. |
| `--embedded-asn-diversity[=false]` | off | Require the racing set to span ≥2 ASNs. |
| `--embedded-peer-latency-score[=false]` | off | Latency tie-breaker inside the eligible peer set. |
| `--embedded-proactive-rotate` | off | Low-rate proactive coin-peer rotation (default is stall-only). |

**Embedded serving levers** (all daemonless-default ON, `=false` opts out;
dashd-attached default OFF)

| Flag | Meaning |
|------|---------|
| `--embedded-mainnet[=false]` | The arm gate: serve embedded templates on mainnet and arm the coin-state feed. `=false` on a mainnet node serves only the dashd fallback. |
| `--embedded-utxo[=false]` | Embedded UTXO / fee lane. |
| `--embedded-null-arm[=false]` | Optimistic null quorum commitment at fresh window-open slots, freshness-gated (#127). |
| `--embedded-superblock[=false]` | Daemonless superblock payee sourcing via govsync. |
| `--embedded-govsync` | Observe-only governance store (inv 17/18 pull). Does not arm serving by itself. |
| `--embedded-serve-mempool-txs[=false]` | Serve fee-carrying templates from the embedded mempool. |
| `--embedded-tx-serve-own-set[=false]` | Serve-time self-validation referee. |
| `--embedded-mempool-ingest[=false]` | Coin-P2P `MSG_TX` pull (fills the mempool). |
| `--embedded-ingest-isdlock[=false]` | `MSG_ISDLOCK` feed (InstantSend conflict locks, BLS-gated). |
| `--embedded-ingest-dstx[=false]` | CoinJoin DSTX lane. |
| `--embedded-include-mn-special-txs[=false]` | DIP special-tx superset (types 1–4). |
| `--embedded-accrue-asset-locks[=false]` / `--embedded-accrue-asset-unlocks[=false]` | Type-8 / type-9 asset-lock/unlock fold. |
| `--embedded-utxo-immature-serve-empty` | Serve coinbase-only until the UTXO view is mature. |
| `--embedded-creditpool-publish-at-serve-tip` | Publish the derived credit pool at the serve tip (money path, default OFF). |
| `--embedded-mined-commitment-index` | Arm the mined-commitment store on live tips. |
| `--embedded-mn-bridge-max N` | Max blocks the pinned masternode anchor may lag the tip before the bridge refuses it as stale (default 20000, `mn_checkpoint_lane.hpp`). |
| `--embedded-mn-bridge-no-cursor` | Replay the whole window from the anchor on every start instead of resuming the saved cursor. |
| `--embedded-fold-live PATH` + `--embedded-fold-live-expect HASH`, `--embedded-fold-checkscripts` | Wire a full-history UTXO fold store as the live input-pricing view (store hash must match); consensus-exact input-script check. |
| `--embedded-utxo-fold-fees DBPATH` + `--embedded-utxo-fold-expect HEX` | Graduated fold fee pricing; both required together. |
| `--bestcl-policy freshness\|consensus-exact` | How the bestCL gate decides (default `freshness`). |
| `--serve-staleness-sentinel[=off]` | Report-only served-height staleness detector, ON by default; `=off`/`=0`/`=false` disables. |
| `--serve-gate-state-file PATH` | Cross-restart serve-gate accounting (soak convenience). |
| `--regtest-force-won-block` | Regtest-only: drive one won block through the dual-path dispatch. |

**Transactions, replay, checkpoints**

| Flag | Meaning |
|------|---------|
| `--embedded-tx-inject`, `--embedded-tx-inject-hex FILE` | Opt-in miner/user tx injection (#157), default OFF. |
| `--pin-local-tx-hex FILE`, `--pin-splice-xcheck-arm`, `--pin-splice-block-budget` | Pin a zero-fee self-mined tx (e.g. donation consolidation) into served templates; splice policy knobs default OFF. |
| `--replay-bulk`, `--replay-bulk-capture DIR`, `--replay-bulk-start H` | Full-history bulk block-fetch lane from DIP3 (1028160); capture caches bodies. |
| `--replay-fold-prestate FILE`, `--replay-fold-quorums`, `--replay-fold-qsnapshot FILE`, `--replay-fold-worklists FILE` | Anchor-seeded DML fold driven by the bulk lane, with derived quorum member sets. |
| `--replay-mnlist-seed-height H --replay-mnlist-seed-source getmnlistdiff --replay-mnlist-seed-file FILE` | Optional V20 `getmnlistdiff` seed instead of deriving from DIP3 (implies `--replay-bulk`). |
| `--replay-mined-commitment-index` | Mined-commitment store fed from replay. |

**Web, money, misc**

| Flag | Default | Meaning |
|------|---------|---------|
| `--stratum [HOST:]PORT` | off | Miner-facing Stratum listener. |
| `--web-port PORT` (alias `--http-port`) | 8080 | Dashboard + JSON API; `0` disables. If it collides with the Stratum port it moves to stratum+1. |
| `--web-host ADDR` | `0.0.0.0` | Dashboard bind interface. |
| `--dashboard-dir PATH` | `web-static` | Static dashboard root. |
| `--external-ip ADDR` (aliases `--stratum-advertise`, `--public-host`) | auto-detect | Miner-facing host shown in the dashboard Stratum URL (NAT). |
| `--explorer` / `--no-explorer` | on | Loopback-only `/api/explorer` surface + raw-block retention. |
| `--give-author PCT` (alias `--dev-donation`) | 0.1 | Author donation percent. |
| `-f` / `--fee PCT` | 0 | Node-owner fee percent. |
| `--node-owner-address ADDR` | — | Fee destination. |
| `--redistribute pplns\|fee\|boost\|donate` | `pplns` | Unnamed-share redistribution. |
| `--coinbase-text TEXT` | `/P2Pool-DASH/c2pool/` | Coinbase scriptSig text, max 64 bytes (see [Coinbase structure](#coinbase-structure)). |
| `--message-blob-hex HEX` (alias `--transition-message`) | — | Encrypted authority message blob. |

### c2pool-btc — Bitcoin (SHA256d)

Source: `src/c2pool/main_btc.cpp` — `print_usage()` and the `main()` parse
loop. Unknown argument → `unknown arg: …` + usage, exit 1. There is **no
`--version`** flag on this binary. A coin source is mandatory: without
`--bitcoind` **or** `--coin-p2p-discover` the binary prints usage and exits 1.

```bash
# Daemonless public pool (btc.voidbind.com posture)
./c2pool-btc --data-dir /var/lib/c2pool/btc --coin-p2p-discover \
  --http 127.0.0.1:8083 --stratum 0.0.0.0:9334 \
  --fee 0.1 --node-owner-address <your-BTC-address> --give-author 0

# Against a local bitcoind P2P port, with the submitblock RPC backup
./c2pool-btc --bitcoind 127.0.0.1:8333 --coin-rpc 127.0.0.1:8332 \
  --coin-rpc-auth ~/.bitcoin/bitcoin.conf --stratum 9332
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-h` / `--help` | | Usage and exit 0. |
| `--data-dir PATH`, `--settings PATH`, `--dump-resolved-config`, `--ack-money-settings` | | Control plane, see [Settings file](#settings-file-toml--all-binaries). `--dump-resolved-config` runs before the mandatory-coin-source check, so it works with no endpoint. |
| `--testnet` / `--testnet4` / `--regtest` | mainnet | Chain selection (testnet4 also sets the testnet flag). |
| `--bitcoind HOST:PORT` | — | bitcoind **P2P** endpoint (8333 / 18333 / 48333 testnet4 / 18443 regtest). Required unless `--coin-p2p-discover`. |
| `--coin-p2p-discover` | off | BTC-isolated scored, group-diverse coin-peer discovery (DNS + fixed + HTTP seeds); streams headers with no bitcoind. |
| `--p2pool HOST:PORT` | — | Single BTC p2pool peer; folds into `--sharechain-addnode` as an exclusive target. |
| `--sharechain-addnode HOST:PORT` (repeatable) | — | Explicit sharechain peers. When given, the public seed list is **not** dialed and the saved addr book is reset. |
| `--sharechain-port P` | 9333 | Sharechain listener port (second instance on one host). |
| `--network-id HEX` (≤8 bytes), `--prefix HEX` | public BTC | Private sharechain identifier / prefix — two independent constants. Setting `--network-id` alone also suppresses the public seed list. |
| `--stratum [HOST:]PORT` | off | Stratum listener. |
| `--http [HOST:]PORT` | off | Operator dashboard (`web-static` relative to the working directory; parser only — not in the `--help` text). |
| `--coin-rpc HOST:PORT` | — | `submitblock` RPC backup endpoint (no secret on argv). |
| `--coin-rpc-auth PATH` | `~/.bitcoin/bitcoin.conf` | `rpcuser`/`rpcpassword` file for the backup. Omit both to run daemonless. |
| `--merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]` (repeatable) | — | Embedded merged-mined aux chain (NMC under BTC). |
| `-f` / `--fee PCT` | 0 | Node-owner fee as a committed payout-identity substitution (not a separate output). Requires `--node-owner-address`. |
| `--node-owner-address ADDR` | — | Fee destination (P2PKH/P2SH/P2WPKH). Undecodable → fee disabled. |
| `--give-author PCT` (alias `--dev-donation`) | compiled-in `donation_u16 = 50` (the usage text labels it 0.5%) | Donation **amount** only; `0` allowed (dust-marker output still emitted). The donation script is never changed. |

### c2pool-dgb — DigiByte (Scrypt)

Source: `src/c2pool/main_dgb.cpp` — `print_banner()` and the `main()` parse
loop. Unknown argument → `unknown argument: …`, exit 1. **Mainnet only**: there
is no `--testnet` flag and `make_coin_params(/*testnet=*/false)` is hardwired;
a settings file that sets `network.testnet` is refused. The DGB parser has no
`--fee` / `--give-author` (the catalog's `money.give_author_pct` and
`money.node_owner_fee_pct` rows exclude DGB); operator payout goes through
`--redistribute` + `--node-owner-address`.

```bash
# Daemonless public pool (dgb.voidbind.com posture)
./c2pool-dgb --run --coin-p2p-discover --data-dir /var/lib/c2pool/dgb \
  --http 127.0.0.1:8084 --stratum 0.0.0.0:9434 \
  --sharechain-port 5024 --sharechain-addnode 92.53.224.27:5024
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--version` / `--help` | | Print and exit. |
| `--data-dir PATH`, `--settings PATH`, `--dump-resolved-config`, `--ack-money-settings` | | Control plane, see [Settings file](#settings-file-toml--all-binaries). |
| `--run` | | Stand up the run-loop (io_context + sharechain peer + Stratum). Without it (or with `--selftest`) the binary runs the self-test and exits. |
| `--stratum [HOST:]PORT` | off | Stratum listener. |
| `--http [HOST:]PORT` | off | Dashboard + stats persistence (`web-static` relative to the working directory). |
| `--sharechain-port P` | 5024 | Sharechain listener port. |
| `--sharechain-addnode HOST:PORT` (repeatable) | public defaults | Pin sharechain peers; suppresses the default bootstrap list. `92.53.224.27:5024` is the live public DGB sharechain seed named in the source. |
| `--coin-p2p-discover` | off | DGB-isolated scored, diverse coin-peer discovery — daemonless. |
| `--coin-daemon HOST:PORT` | — | Explicit embedded coin-P2P producer target (a `digibyted` P2P port). |
| `--coin-magic HEX`, `--coin-genesis HASH` | mainnet | Wire-magic / genesis overrides (regtest). |
| `--coin-rpc HOST:PORT`, `--coin-rpc-auth PATH` | — | External `digibyted` `submitblock` arm; creds stay in `digibyte.conf`. |
| `--regtest`, `--regtest-force-won-share` | off | Regtest marker; forced won share is refused unless `--regtest` **and** `--coin-daemon` are both given. |
| `--no-p2p-relay` | off | Suppress the embedded won-block relay (isolates the RPC arm). |
| `--dev-relax-algo-softforks` | off | Dev-only: relax the algo-softfork readiness gate for an isolated tuned testnet; ignored on mainnet. |
| `--redistribute SPEC` | `pplns` | `pplns\|fee\|boost\|donate` or hybrid `boost:70,donate:20`. |
| `--node-owner-address ADDR` | — | Operator payout identity for the `fee` arm. |
| `--merged SYMBOL:CHAIN_ID[:HOST:PORT:USER:PASS[:P2P_PORT]]` (repeatable) | — | Embedded DOGE aux backend (`-DAUX_DOGE` build; DOGE chain_id 98, P2P 22556). |
| `--doge-p2p-address HOST`, `--doge-p2p-port PORT`, `--embedded-doge` | — | DOGE peer overrides; `--embedded-doge` forces the embedded path. |
| `--embedded-serve-mempool-txs[=true\|=false]` | posture default | Arm / opt out of the embedded UTXO fee-proof lane. CLI wins over the settings file. |

### c2pool-bch — Bitcoin Cash (SHA256d)

Source: `src/c2pool/main_bch.cpp` — `print_banner()` and the `main()` parse
loop. Unknown argument → `unknown argument: …`, exit 1. The pool mode is
`--pool`; the other modes are harnesses.

```bash
# Daemonless public pool (bch.voidbind.com posture): --peer with port 0 means
# "no explicit BCHN peer" and turns on the DNS/fixed/HTTP seed ladder
./c2pool-bch --pool --peer 0.0.0.0:0 --data-dir /var/lib/c2pool/bch \
  --http 127.0.0.1:8085 --stratum 0.0.0.0:9534 \
  --sharechain-addnode 92.53.224.27:9349
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--version` / `--help` | | Print and exit (help prints the banner after the settings probe). |
| `--data-dir PATH`, `--settings PATH`, `--dump-resolved-config`, `--ack-money-settings` | | Control plane, see [Settings file](#settings-file-toml--all-binaries). |
| `--pool` | | Pool run-loop: embedded daemon + sharechain + Stratum. |
| `--selftest` | default | ABLA budget self-test, exit. |
| `--ibd [--near-tip] [--auto-kick]`, `--with-peer-verify`, `--max-seconds N` (600) | | Headers-first IBD / peer-verify harnesses against one BCHN peer. |
| `--leg-c-capture [--rpc-conf PATH]`, `--leg-c-capture-p2p [--p2p-port N]` (18444) | | Regtest capture harnesses; `--rpc-conf` defaults to `~/bch-regtest/bitcoin.conf` here. **`--p2p-port` is the leg-C BCHN regtest port, not the sharechain port** (the catalog maps it to `sharechain.listen`; the parser does not). |
| `--peer HOST[:PORT]` | `192.168.86.110:8333` (a developer-host default — always supply your own) | BCHN coin-P2P peer. Port `0` = no explicit peer → SeedTier discovery ladder (`src/impl/bch/coin/embedded_daemon.hpp` `maybe_start_p2p`). |
| `--testnet` / `--testnet4` / `--regtest` | mainnet | Chain selection; also moves the default peer port (18333 / 28333 / 18444). |
| `--anchor N` | 0 | Cold-start ABLA floor anchor height. |
| `--stratum [HOST:]PORT` | off | Stratum listener. |
| `--http [HOST:]PORT` | off | Dashboard. |
| `--rpc-conf PATH` | — | BCHN `bitcoin.conf` for the external-RPC fallback (`rpcuser`/`rpcpassword`; endpoint is `127.0.0.1:<rpcport>`). |
| `--sharechain-addnode HOST:PORT` (repeatable) | public defaults | Pin sharechain peers (`92.53.224.27:9349` is the live public BCH sharechain seed named in the source). |

No money flags on this binary: BCH has no `--fee` / `--give-author` /
`--node-owner-address` in the parser (the catalog rows exclude `C_BCH`).

### c2pool-bip110 — Bitcoin Knots BLAKE2b fork

Source: `src/c2pool/main_bip110.cpp` — `print_banner()` and the `main()` parse
loop. **Unknown flags are ignored silently** (no trailing `else`), and the
binary takes no `--data-dir` / `--settings` / `--dashboard-dir`: the dashboard
is served from `web-static` relative to the working directory
(`web_server->set_dashboard_dir("web-static")` in `run_embedded`), so deploy a
`web-static` copy next to the binary and start it from that directory.

```bash
# Public fork pool (bip110.voidbind.com posture)
cd /opt/c2pool-bip110 && ./c2pool-bip110 --run --coin-p2p-discover \
  --coin-externalip <your-public-ip> --fork-checkpoint \
  --http 127.0.0.1:8086 --stratum 9336 --serve-mempool-txs \
  --give-author 0.1 --fee 0 --node-owner-address <your-BTC-address> \
  --bip110-sharechain --explorer
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--version`, `-h` / `--help` | | Print and exit. |
| `--run` | | Embedded daemonless BLAKE2b fork follower + Stratum. Without it (or with `--selftest`) the KAT self-test runs and exits. If neither `--coin-p2p-discover` nor `--peer` is given, discovery is switched on automatically. |
| `--coin-p2p-discover` | auto with `--run` | Discover `NODE_BLAKE2B` fork peers (DNS + fixed seeds). |
| `--peer IP[:PORT]` (repeatable) | port 8333 | Explicit fork peer. |
| `--coin-externalip IP` | peer-echo auto | Operator-pinned reachable IP for self-advertisement (bare IP; port 8333 substituted). |
| `--fork-checkpoint` | off | Seed the Knots 961640 checkpoint for a fast proof. |
| `--http [HOST:]PORT` | off | Shared coin-generic dashboard (`/`, `/node_info`, `/api/node_topology`, `/broadcaster_status`). |
| `--stratum [HOST:]PORT` / `--no-stratum` | `0.0.0.0:9336` on | Stratum listener; `--no-stratum` disables. |
| `--serve-mempool-txs` / `--no-serve-mempool-txs` | on | Include real network txs in served templates (M3 good-citizen); the `--no-` form is the coinbase-only escape hatch. |
| `--bip110-sharechain` | off | Arm the M3 sharechain mint on `:9337` and dial the federation sharechain. First outbound is irreversible (params-freeze checkpoint). Absent → M2 header-follower only. |
| `--sharechain-addnode HOST:PORT` (repeatable) | beacon list | Override the default sharechain bootstrap beacons. |
| `--explorer` / `--no-explorer` | on | Loopback-only `/api/explorer` + raw-block retention. |
| `--node-owner-address ADDR` (alias `--donation`) | — | Node-owner fee destination and subsidy fallback when a miner's username has no resolvable address. |
| `--give-author PCT` (alias `--dev-donation`) | 0.1 (catalog `money.give_author_pct`) | Author donation percent. |
| `-f` / `--fee PCT` | 0 | Node-owner fee percent. |

---

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `/local_stats` | Local node statistics (peers, hashrates, shares) |
| `/global_stats` | Pool-wide statistics |
| `/current_payouts` | Current PPLNS payout distribution |
| `/recent_blocks` | Recently found blocks |
| `/connected_miners` | Connected stratum workers |
| `/stratum_stats` | Per-worker stratum statistics (hashrate, difficulty, accepted/rejected) |
| `/sharechain/stats` | Share chain state |
| `/miner_thresholds` | Minimum viable hashrate, dust range |
| `/merged_stats` | Merged mining block statistics |
| `/current_merged_payouts` | Current merged mining payouts |
| `/recent_merged_blocks` | Recent merged-mined blocks |
| `/broadcaster_status` | Parent chain broadcaster status |
| `/api/explorer/getblockchaininfo` | Chain info (loopback-only, requires `explorer: true`) |
| `/api/explorer/getblockhash` | Block hash by height (loopback-only) |
| `/api/explorer/getblock` | Full block JSON by hash or height (loopback-only) |

See [docs/DASHBOARD_INTEGRATION.md](docs/DASHBOARD_INTEGRATION.md) for the
complete REST API reference and dashboard/explorer integration guide (and
[docs/FAQ.md](docs/FAQ.md) for common questions).

**Web dashboard** — served from `web-static/` by default:

```bash
xdg-open http://localhost:8080/
```

**Lite block explorer** — bundled Python app in `explorer/` for browsing recent blocks:

```yaml
# Enable in config to store blocks + serve REST API
explorer: true
explorer_url: "http://localhost:9090"
```

```bash
# Run the explorer UI against c2pool's API
python3 explorer/explorer.py --ltc-c2pool http://127.0.0.1:8080/api/explorer --web-port 9090
```

The explorer shows block details, decoded coinbase scripts, THE commitment proofs for c2pool-found blocks, and links to Blockchair for transactions/addresses outside the stored range.

**Customization** — both the dashboard (`web-static/`) and the explorer (`explorer/explorer.py`)
are user-customizable components. Edit HTML/JS/CSS in `web-static/` or modify
`explorer/explorer.py` to change the design, add features, or integrate with your
own infrastructure. Block explorer links default to Blockchair but can be overridden
per-node via YAML config:

```yaml
address_explorer_prefix: "https://your-explorer.example.com/address/"
block_explorer_prefix: "https://your-explorer.example.com/block/"
tx_explorer_prefix: "https://your-explorer.example.com/tx/"
```

---

## Coinbase structure

Every block found by c2pool embeds structured data in the coinbase scriptSig:

```
[4]  BIP34 block height (consensus)
[44] AuxPoW merged mining commitment (when active)
[N]  Operator text (--coinbase-text, see per-lane defaults below)
[32] THE state root (sharechain state commitment)
[M]  THE metadata (pool analytics, fills remaining space)
     Total: 100 bytes (Bitcoin consensus limit)
```

The THE state root commits the sharechain state at block-find time (PPLNS
distribution, chain height, difficulty). Any node can verify a found block's
payouts match the committed state root.

### Operator text defaults

`--coinbase-text` is capped at 64 bytes (20 when merged mining is active, since
the AuxPoW commitment shares the same 100-byte budget).

| Lane | Default operator text |
|------|-----------------------|
| LTC (`c2pool`) | `/c2pool/` |
| DASH (`c2pool-dash`) mainnet | `/P2Pool-DASH/c2pool/` |
| DASH (`c2pool-dash`) testnet / regtest | `/P2Pool-tDASH/c2pool/` |

The DASH default embeds the canonical p2pool marker (`COINBASEEXT` from the
p2pool-dash oracle `networks/dash.py`) because block explorers attribute blocks
to a pool by coinbase text — [chainz.cryptoid.info](https://chainz.cryptoid.info/dash/extraction.dws?30.htm)
lists the pool as `P2Pool-DASH` and does not know the string `c2pool`. The
`c2pool/` suffix records which implementation mined the block. The coinbase text
is not consensus-bearing (peers never re-derive it), so overriding it cannot
orphan a share — but an override that drops `/P2Pool-DASH/` makes your blocks
unattributable on explorers.

DASH sources this default from its coin SSOT (`src/impl/dash/config_pool.hpp`);
the same pattern is available for the other lanes but is not yet wired there.

---

## Authority message blobs (V36)

```bash
# Create transition signal (authority key holder)
python3 util/create_transition_message.py create \
    --privkey <64-hex> \
    --from 36 --to 37 --msg "Upgrade to V37" --urgency recommended

# Pass blob at startup (node operator)
./c2pool --message-blob-hex 01a2b3c4...
```

See [util/README.md](util/README.md) for full documentation.

---

## Private sharechains

```bash
# Start a private chain
./c2pool --network-id DEADBEEF12345678

# Join the same chain
./c2pool --network-id DEADBEEF12345678 -n OPERATOR_IP:9326
```

The `--network-id` overrides the IDENTIFIER hashed into every share's
verification hash. Nodes without the correct ID cannot forge valid shares.
See [above](#configuration-reference) for details.

---

## Build targets

| Target | Description |
|--------|-------------|
| `c2pool-ltc` | Primary binary — release packages ship this per-coin name (`c2pool` is the dev-build alias) |
| `c2pool-btc` | Bitcoin parent (`src/c2pool/main_btc.cpp`) |
| `c2pool-dgb` | DigiByte Scrypt parent (`src/c2pool/main_dgb.cpp`; `-DAUX_DOGE` for embedded DOGE) |
| `c2pool-bch` | Bitcoin Cash parent (`src/c2pool/main_bch.cpp`) |
| `c2pool-dash` | Dash parent (`src/c2pool/main_dash.cpp`) |
| `c2pool-bip110` | BIP-110 BLAKE2b fork (`src/c2pool/main_bip110.cpp`) |
| `test_hardening` | Softfork gate + reply-matcher regression tests |
| `test_share_messages` | V36 authority message decrypt/verify tests |
| `test_coin_broadcaster` | Coin peer-manager and broadcaster tests |

```bash
cd build && ctest --output-on-failure -j$(nproc)
```

---

## Status

| Area | Status |
|---|---|
| V36 share format (LTC parent chain) | Released (v0.2.0); prod cutover gated on crossing soak |
| V36 share format (DGB Scrypt parent chain) | Running — `c2pool-dgb` daemonless public node (dgb.voidbind.com), joined to the live DGB sharechain via `--sharechain-addnode` |
| Daemonless per-coin nodes (BTC, BCH, DASH) | Running — public voidbind nodes with no coin daemon on the serve path |
| Merged mining (DOGE, PEP, BELLS, LKY, JKC, SHIC) | Working |
| Embedded LTC SPV node | Working |
| Embedded DOGE SPV node | Working |
| Embedded BIP-110 daemonless pool (BLAKE2b fork) | Experimental (live on bip110.voidbind.com; fork-follow + Stratum mining + reward-safe mempool-serving on `master` #1439) |
| Coin daemon RPC/P2P | Hardened |
| Stratum mining server | Working |
| VARDIFF | Working |
| Payout / PPLNS | Working |
| Authority message blobs (V36) | Working |
| Solo / Custodial modes | Working |
| Test suite | 1,875 test cases across 194 suites |

> **Need a pool running today?**
> [frstrtr/p2pool-merged-v36](https://github.com/frstrtr/p2pool-merged-v36) — production Python V36 pool (LTC + DGB + DOGE, Docker, dashboard).

---

## Community

- Telegram: <https://t.me/c2pooldev>
- Discord: <https://discord.gg/yb6ujsPRsv>

---

## V37 development

- **V37 Purple Paper** (Work Receipts design): https://frstrtr.github.io/c2pool/purple-paper.html
- Dev chat (Telegram): https://t.me/c2pooldev
- V37 dev-branch primitives (diff): https://github.com/frstrtr/c2pool/compare/master...v37-dev

---

## License

- **c2pool daemon** (this repository): [AGPL-3.0-or-later](LICENSE). Network use triggers the AGPL source-provision obligation.
- **c2pool-core-engine** (extracted primitive layer): Apache-2.0, in the separate [c2pool-core-engine](https://github.com/frstrtr/c2pool-core-engine) repository.
- **Bundled `src/btclibs/` and third-party crypto**: retain their original MIT licenses (notices preserved in-file).
- **V37 Purple Paper** (frstrtr.github.io/c2pool): MIT License (as with the Bitcoin whitepaper). The remaining site articles are © technocore.one, all rights reserved.

### Install guides
- [Ubuntu / Debian / Linux](doc/build-unix.md)
- [macOS (Intel & Apple Silicon)](doc/build-macos.md)
- [Windows](doc/build-windows.md)

See [deploy/DEPLOY.md](deploy/DEPLOY.md) for HiveOS/MinerStat/RaveOS setup.

<!-- safe-cosmetic auto-merge dry-run 2026-06-06 -->
