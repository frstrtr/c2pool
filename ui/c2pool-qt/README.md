# c2pool Qt Control Panel

Desktop control panel for c2pool. First-pass toward full finalization —
the qt-steward owns deeper controls; this cut makes the launcher
coin-generic and reward-safe.

Implemented:

- Qt Widgets app shell
- Sidebar navigation
- Overview page
- Mining page
- Logs page
- Basic node/miner monitoring refresh loop
- Log export action (calls /logs/export endpoint)
- **Coin-generic launch** (profile-driven, `src/CoinProfiles.hpp`):
  litecoin, bitcoin, dogecoin, dash, digibyte, bitcoincash
- **Reward-safe launch defaults** (see below)

## Coins & launch CLIs

c2pool ships two launch CLIs; the chain profile records which one each coin
uses, plus its binary, daemon, algo and default RPC ports:

| Coin | Binary | Daemon | Algo | Launch CLI |
|------|--------|--------|------|------------|
| litecoin | `c2pool` | litecoind | Scrypt | unified `--net litecoin` |
| bitcoin | `c2pool` | bitcoind | SHA-256d | unified `--net bitcoin` |
| dogecoin | `c2pool` | dogecoind | Scrypt (AuxPoW) | unified `--net dogecoin` |
| dash | `c2pool-dash` | dashd | X11 | per-coin `--run` (daemonless; masternode-payee) |
| digibyte | `c2pool-dgb` | digibyted | Scrypt | per-coin `--run` (experimental) |
| bitcoincash | `c2pool-bch` | bitcoind (BCHN) | SHA-256d | per-coin `--pool` (experimental) |

Adding a coin is a row in `CoinProfiles.hpp`, not a scattered code edit —
mirroring the coin-generic web dashboard/explorer.

## ★ Reward safety

The panel only assembles argv — the node's own good-citizen defaults own the
reward decision. The default DASH launch is a bare `--run` (**daemonless** cut
mode): with no dashd arm the node keeps its serving levers ON (embedded-mainnet
included), so the panel does not emit `--embedded-mainnet` there. Attaching an
external dashd (`--coin-rpc HOST:PORT` + `--coin-rpc-auth PATH`; the rpcpassword
is read from the coin's .conf and never placed on argv) is an explicit opt-in
("Attach external dashd"). The embedded coin-network knobs
(`--coin-p2p-connect` / `--embedded-mainnet`) are **default OFF** — emitted only
from the explicit "Advanced / embedded" controls (transport pinning / explicit
gate-lift). The author donation is left to the binary default (0.1% / BTC 0.5%)
unless explicitly overridden, and `--give-author 0` is never emitted silently.

The invariant is unit-tested Qt-free in `test/test_reward_safe_launch.cpp`
(the default DASH command is a bare `--run` and omits the dashd/embedded arms);
build tests with `-DC2POOL_QT_BUILD_TESTS=ON` and run via `ctest`.

## TODO (qt-steward)

- Deeper per-coin controls for the DGB/BCH run-loops (ZMQ, anchors,
  sharechain isolation, etc.)
- Address-flavour validation per coin
- Wiring the per-coin binaries' full flag surface

## Build

```bash
cmake -S ui/c2pool-qt -B build-qt
cmake --build build-qt -j4
```

Requires Qt6 (Widgets, Network, WebEngineCore/Widgets, WebChannel).

## Run

```bash
./build-qt/c2pool-qt
```

Default API base URL in the app:

- http://127.0.0.1:8080 (separate port to avoid stratum conflict)

Important:

- Point this URL to the c2pool web/API endpoint.
- Do not point it to coin daemon RPC ports (for example litecoind RPC on 19332), which are not c2pool panel endpoints.

Use the top bar to change base URL and refresh pages.

## Current status

First-pass finalization: coin-generic + reward-safe launch land here; data
mapping, UI polish, and deeper per-coin controls continue incrementally
(qt-steward).
