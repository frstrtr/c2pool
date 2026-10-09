# c2pool threat model (for the OSS Scanner)

## What c2pool is

c2pool is a C++ reimplementation of P2Pool: a decentralized proof-of-work mining
pool. Every node keeps a "sharechain" (a side chain of miner shares) in consensus
with its peers, pays miners directly in the coinbase of each block it finds, and
can run without a local coin daemon by speaking the coin's own P2P protocol.
There is one binary per parent chain (`c2pool-ltc`, `-btc`, `-dgb`, `-bch`,
`-dash`, `-bip110`; `c2pool` is the LTC build) and an experimental Monero lane
(`c2pool-v37-*`).

Operators run nodes on public hosts. Real money flows through them: a bug can
redirect block rewards, forge or erase miners' credit, split the sharechain, or
make a node build blocks the coin network rejects.

## Where untrusted input enters (all remote, unauthenticated)

In priority order:

1. **Sharechain P2P** (pool-to-pool; LTC 9326, BTC 9333, DGB 5024, BCH 9349,
   DASH 8999 / 8998 for v36, BIP110 9337; bound to all interfaces). Any host can
   connect.
   - Framing: `src/core/socket.cpp`, `src/core/packet.hpp`, `src/core/message*.hpp`.
   - Messages, handlers, version handshake, misbehaviour scoring:
     `src/impl/<coin>/{messages.hpp,protocol_*.cpp,node.cpp,peer.hpp}`,
     `src/impl/bip110/pool/`, `src/pool/`.
   - Share parsing and validation (the consensus core):
     `src/impl/<coin>/share*.hpp`, `share_check.hpp`, `share_tracker.hpp`,
     `src/sharechain/`, `src/c2pool/p2p_share_tracker.cpp`,
     `src/c2pool/bridge/`.
2. **Stratum** (miner-facing; LTC 9327, BIP110 9336, opt-in elsewhere; all
   interfaces). Newline-delimited JSON-RPC from anyone; the username is the
   payout address. `src/core/stratum_server.cpp`, `src/core/stratum_types.hpp`,
   `src/core/address_validator.cpp`, `src/core/address_utils.cpp`,
   `src/impl/*/stratum/`, `src/c2pool/hashrate/`, `src/c2pool/difficulty/`.
   Monero: `src/impl/xmr/stratum/`, `src/c2pool/v37/xmr/xmr_stratum_listener.hpp`.
3. **HTTP / JSON API** (port 8080 for LTC and DASH, opt-in elsewhere; all
   interfaces). Boost.Beast. `src/core/http_session.cpp` (routing, static
   files), `src/core/web_server.cpp` (REST and JSON-RPC handlers). Public routes
   are read-only stats plus the JSON-RPC methods. Routes under `/api/admin/`,
   `/api/config`, `/api/explorer/` and `/api/tx-inject` are meant for the local
   operator only and are gated on a loopback peer address and, for config apply
   and tx-inject, a control token.
4. **Coin-network P2P** (outbound connections to arbitrary coin peers; BIP110
   also listens on 8333). Headers, blocks, transactions, compact blocks,
   addr/addrv2, and Dash's mnlistdiff, qrinfo, qfcommit, clsig, isdlock,
   governance and spork messages; DOGE/NMC AuxPoW.
   `src/impl/bitcoin_family/coin/`, `src/impl/<coin>/coin/`,
   `src/impl/dash/coin/` (including `vendor/`), `src/impl/doge/coin/`,
   `src/impl/nmc/coin/`, `src/c2pool/merged/`, `src/core/coin_addrman.hpp`.
5. **Monero lane**: levin/epee P2P client (`src/impl/xmr/native/p2p/`), block and
   transaction parsing (`src/impl/xmr/native/consensus/`,
   `src/impl/xmr/native/txpool/`, `src/impl/xmr/native/rct/`), and the v37
   carrier relay wire, off by default (`src/c2pool/v37/`, `src/impl/xmr/wire/`,
   `src/impl/xmr/pathb/`).

All of the above share the serializers in `src/core/pack.hpp`,
`src/core/pack_types.hpp`, `src/core/legacy/`, and the Bitcoin Core-derived
`src/btclibs/` (`serialize.h`, `streams.h`, `script/`, `base58`, `bech32`).
Bugs there are in scope wherever a remote input can reach them.

## Trusted inputs (lower priority)

- The coin daemon's JSON-RPC responses (`src/impl/*/coin/rpc.cpp`): the daemon is
  the operator's own, normally on 127.0.0.1 with credentials. The same goes for
  monerod RPC/ZMQ and the dashd ZMQ `hashblock` feed.
- Command-line flags, YAML config (`config/`, `src/core/settings*.cpp`) and
  on-disk state (LevelDB sharechain store, peer lists, snapshots). These are
  written by the operator or by the node itself.

A bug that needs one of these to be malicious is still worth reporting, at a
lower severity (see below).

## Severity

**Critical**
- Remote code execution.
- Stealing or redirecting payouts: changing coinbase outputs, forging PPLNS
  weight, or crediting one miner's work to another address.
- Getting a share accepted without the proof of work it claims, or otherwise
  breaking sharechain consensus so that honest c2pool nodes diverge from each
  other or from the reference p2pool rules.
- One remote message that crashes or wedges every node that relays it
  (network-wide kill).
- Making a node build or broadcast blocks that the coin network rejects (lost
  block rewards), when an outside party can trigger it.

**High**
- Memory corruption reachable from a remote input (out-of-bounds read/write,
  use-after-free, integer overflow into an allocation) without a demonstrated
  path to code execution.
- A remote crash or hang of a single node from one connection.
- Getting past the loopback-only or control-token gates on the operator routes.
- Bypassing peer bans or misbehaviour scoring in a way that enables the above.

**Medium**
- Resource exhaustion (memory, CPU, file descriptors, disk) that needs sustained
  traffic from one host.
- Leaking operator data (logs, internal addresses, configuration) over a public
  route.

**Low**
- Anything that needs a malicious coin daemon, config file or local file, or
  local access to the host.
- Hardening gaps with no demonstrated impact.

## Out of scope

- Not production code: `prototypes/`, `proto/`, `test/`, `tests/`, every
  `*/test/` directory, `*_kat.cpp` and `test_*.cpp` sources, `tools/`,
  `scripts/`, `utils/`, `util/`, `ci/`, `contrib/`, `deploy/`, `installer/`,
  `cmake/`, `doc/`, `docs/`, `ui/` (Qt apps), `explorer/` (separate Python app),
  `p2pool-dash/`, `src/impl/todo`, `src/btclibs/removed`,
  `src/c2pool/c2pool_temp.cpp`.
- Bugs inside dependencies (Boost, nlohmann_json, yaml-cpp, LevelDB, ZeroMQ,
  secp256k1) or vendored upstream code (RandomX, Monero crypto, Dash Core
  shims, d3/highcharts) unless c2pool calls them in a way that makes the bug
  reachable. Report the misuse, not the library.
- Dash BLS: the default build compiles a fail-closed stub
  (`C2POOL_DASH_BLS=OFF`). The binary refuses BLS-relying configurations and
  says so. That is intended, not a finding.
- Missing TLS or authentication on the sharechain P2P and Stratum ports. Both
  are open by design, as in P2Pool.

## How to exercise it

- The image builds into `/src/build`. The pool daemons are in
  `/src/build/src/c2pool/`; the test and KAT executables sit under
  `/src/build`, mirroring the source tree. `ctest --test-dir /src/build -N`
  lists them.
- The KATs make good drivers: they feed known byte strings through the same
  parsers the network paths use. There are fuzz-style harnesses for the Monero
  levin codec and blob reader (`xmr_levin_fuzz_kat`,
  `xmr_native_blob_reader_fuzz_kat`).
- The scan has no network, so a node cannot reach real peers. Its listeners
  still bind, so sharechain P2P, Stratum and HTTP can be driven from a local
  client on 127.0.0.1. Each binary's `--help` lists ports, `--testnet`, and the
  flags that skip the coin daemon.
- The Python scripts in `test/` (e.g. `simple_stratum_test.py`) show how a miner
  talks to the Stratum port.

## Reports

- One report per root cause. Group every input that reaches the same faulty
  check or parser into one report.
- Include a reproducer that runs offline in this image: preferably a small C++
  test against the affected header, or a Python script that sends bytes to a
  local node.
- Propose a minimal patch that fixes the root cause. Do not refactor around it.
- For consensus findings, say which rule the share or block breaks and how the
  reference p2pool (Python) or the coin's own node behaves on the same input.
