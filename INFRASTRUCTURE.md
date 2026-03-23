# Testnet Infrastructure — LTC + DOGE Merged Mining

## Coin Daemons

| IP | Coin | RPC Port | P2P Port | User | Password |
|----|------|----------|----------|------|----------|
| 192.168.86.26 | litecoind testnet | 19332 | 19335 | litecoinrpc | litecoinrpc_mainnet_2026 |
| 192.168.86.27 | dogecoind testnet4alpha | 44555 | 44556 | dogecoinrpc | testpass |

DOGE uses non-default ports: `-rpcport=44555 -port=44556`
litecoin-cli on .26: `/home/user0/.local/bin/litecoin-cli -testnet`
Generate bech32 address: `/home/user0/.local/bin/litecoin-cli -testnet getnewaddress '' bech32`

## Pool Nodes

| IP | Software | Branch | Payout Address | Type | P2P | Stratum |
|----|----------|--------|---------------|------|-----|---------|
| 192.168.86.29 | p2pool (PyPy2) | `c2pool-debug` | `tltc1q7k2fc2mpmnqram3et5vt3y7a4wl44597wc7h93` | P2WPKH | 19338 | 19327 |
| 192.168.86.31 | p2pool (PyPy2) | `c2pool-debug` | `QcUvq1EV2LtAhiMGWerMDzN7HYJbqLzhx4` | P2SH | 19338 | 19327 |
| 192.168.86.191 | c2pool (C++) | `master` | `QcUvq1EV2LtAhiMGWerMDzN7HYJbqLzhx4` | P2SH | 19338 | 19327 |

p2pool repo: `github.com/frstrtr/p2pool-merged-v36`, branch `c2pool-debug`
p2pool code on nodes: `~/p2pool-merged/`
PyPy2 path: `~/pypy2.7-v7.3.20-linux64/bin/pypy`
c2pool repo: `github.com/frstrtr/c2pool`, branch `master`

## Physical Miners (AntRouter R1-LTC, ~1.3 MH/s Scrypt each)

| Miner IP | Name | Pool | Stratum User |
|----------|------|------|-------------|
| 192.168.86.37 | charlie/r1a | p2pool .29:19327 | mg1jpD5KPyXjMhP347ZTR9mN16DtVSzd2R |
| 192.168.86.38 | alfa/r1b | p2pool .31:19327 | myT1aT2PpJs9JFDKJ31og7aYb6RBesXX9D |
| 192.168.86.39 | bravo/r1c | c2pool .191:19327 | myEDJdUu5XvVT4HNrM4jrUNsGDdNjFnHca |

## mm-adapter (on .29 and .31)

Uses `getblocktemplate` (NOT `createauxblock`). P2Pool builds its own
coinbase with PPLNS multi-address payouts. `payout.address` in config
is a legacy field, not used for block building.

- Listens: `0.0.0.0:44556`, proxies to `192.168.86.27:44555`
- Config: `~/mm-adapter/config.yaml`
- Screen session: `mm-adapter`
- Logs: `/tmp/mm-adapter-29.log`, `/tmp/mm-adapter-31.log`

### mm-adapter config (.29)
```yaml
server:
  host: "0.0.0.0"
  port: 44556
  rpc_user: "dogecoinrpc"
  rpc_password: "testpass"
upstream:
  host: "192.168.86.27"
  port: 44555
  rpc_user: "dogecoinrpc"
  rpc_password: "testpass"
  timeout: 30
chain:
  name: "dogecoin_testnet4alpha"
  chain_id: 98
  network_magic: "fcc1b7dc"
payout:
  address: "nmkmeRtJu3wzg8THQYpnaUpTUtqKP15zRB"
coinbase_text: "c2pool-testnet"
logging:
  level: "DEBUG"
```

### mm-adapter config (.31)
Same as .29 except `payout.address: "noBEfr9wTGgs94CdGVXGYwsQghEwBsXw4K"`

### Start mm-adapter
```bash
ssh <IP> 'screen -dmS mm-adapter bash -c "cd ~/mm-adapter && python3 adapter.py --config config.yaml 2>&1 | tee /tmp/mm-adapter-<N>.log"'
```

## p2pool Start Commands

### .29 (P2WPKH bech32 address)
```bash
ssh 192.168.86.29 'find ~/p2pool-merged -name "*.pyc" -delete; screen -dmS p2pool bash -c "cd ~/p2pool-merged && export PATH=~/pypy2.7-v7.3.20-linux64/bin:\$PATH && exec pypy run_p2pool.py --net litecoin --testnet --bitcoind-address 192.168.86.26 --bitcoind-rpc-port 19332 --bitcoind-p2p-port 19335 --merged-coind-address 127.0.0.1 --merged-coind-rpc-port 44556 --merged-coind-rpc-user dogecoinrpc --merged-coind-rpc-password testpass --merged-coind-p2p-address 192.168.86.27 --merged-coind-p2p-port 44557 -a tltc1q7k2fc2mpmnqram3et5vt3y7a4wl44597wc7h93 --give-author 0 -f 0 --disable-upnp --max-conns 20 -n 192.168.86.191:19338 -n 192.168.86.31:19338 --no-console litecoinrpc litecoinrpc_mainnet_2026 2>&1 | tee ~/p2pool_testnet29_stdout.log"'
```

### .31 (P2SH address)
```bash
ssh 192.168.86.31 'find ~/p2pool-merged -name "*.pyc" -delete; screen -dmS p2pool bash -c "cd ~/p2pool-merged && export PATH=~/pypy2.7-v7.3.20-linux64/bin:\$PATH && exec pypy run_p2pool.py --net litecoin --testnet --bitcoind-address 192.168.86.26 --bitcoind-rpc-port 19332 --bitcoind-p2p-port 19335 --merged-coind-address 127.0.0.1 --merged-coind-rpc-port 44556 --merged-coind-rpc-user dogecoinrpc --merged-coind-rpc-password testpass --merged-coind-p2p-address 192.168.86.27 --merged-coind-p2p-port 44557 -a QcUvq1EV2LtAhiMGWerMDzN7HYJbqLzhx4 --give-author 0 -f 0 --disable-upnp --max-conns 20 -n 192.168.86.191:19338 -n 192.168.86.29:19338 --no-console litecoinrpc litecoinrpc_mainnet_2026 2>&1 | tee ~/p2pool_testnet31_stdout.log"'
```

## c2pool Start Command

```bash
nohup /home/user0/Github/c2pool/build/src/c2pool/c2pool \
  --integrated --net litecoin --testnet \
  --bitcoind-address 192.168.86.26 --bitcoind-rpc-port 19332 --bitcoind-p2p-port 19335 \
  --rpcuser litecoinrpc --rpcpassword litecoinrpc_mainnet_2026 \
  --merged DOGE:98:192.168.86.27:44555:dogecoinrpc:testpass \
  --merged-coind-p2p-address 192.168.86.27 --merged-coind-p2p-port 44556 \
  --address QcUvq1EV2LtAhiMGWerMDzN7HYJbqLzhx4 \
  --give-author 0 --fee 0 --disable-upnp --max-conns 0 \
  --worker-port 19327 --p2pool-port 19338 --web-port 18080 \
  > /tmp/c2pool_run.log 2>&1 &
```

NOTE: c2pool uses `--address` (not `-a`), `--fee` (not `-f`),
`--rpcuser`/`--rpcpassword` (not positional args).
c2pool talks DIRECTLY to DOGE daemon RPC — no mm-adapter.

## Flush Procedures

### p2pool (on .29 or .31)
```bash
ssh <IP> "killall -9 pypy; rm -f ~/p2pool-merged/data/litecoin_testnet/shares.*; rm -rf ~/p2pool-merged/data/litecoin_testnet/graph_db; find ~/p2pool-merged -name '*.pyc' -delete"
```
Data dir is `litecoin_testnet/` (NOT `litecoin/`).
`shares.*` alone is NOT enough — `graph_db` also has share data.
**PRESERVE `v36_ratchet.json`** — without it, V35->V36 transition takes ~1 hour.

### c2pool
```bash
pkill -9 -f "c2pool/c2pool"; rm -rf ~/.c2pool/litecoin_testnet/sharechain_leveldb
```

### Full flush all
```bash
# 1. Kill everything
ssh 192.168.86.29 "killall -9 pypy"
ssh 192.168.86.31 "killall -9 pypy"
pkill -9 -f "c2pool/c2pool"

# 2. Flush sharechains (preserve ratchet)
ssh 192.168.86.29 "rm -f ~/p2pool-merged/data/litecoin_testnet/shares.*; rm -rf ~/p2pool-merged/data/litecoin_testnet/graph_db; find ~/p2pool-merged -name '*.pyc' -delete"
ssh 192.168.86.31 "rm -f ~/p2pool-merged/data/litecoin_testnet/shares.*; rm -rf ~/p2pool-merged/data/litecoin_testnet/graph_db; find ~/p2pool-merged -name '*.pyc' -delete"
rm -rf ~/.c2pool/litecoin_testnet/sharechain_leveldb

# 3. Restart in order: mm-adapters (if needed) -> p2pool -> c2pool
```

## V36 Ratchet

File: `~/p2pool-merged/data/litecoin_testnet/v36_ratchet.json`
Current state: `{"state":"confirmed","confirm_count":800}`
Pre-seed for fresh chain: `echo '{"state":"confirmed","confirm_count":800}' > data/litecoin_testnet/v36_ratchet.json`

## Logs

| What | Where | Notes |
|------|-------|-------|
| p2pool .29 stdout | `~/p2pool_testnet29_stdout.log` (on .29) | tee buffers |
| p2pool .29 real-time | `~/p2pool-merged/data/litecoin_testnet/log` (on .29) | unbuffered |
| p2pool .31 stdout | `~/p2pool_testnet31_stdout.log` (on .31) | tee buffers |
| p2pool .31 real-time | `~/p2pool-merged/data/litecoin_testnet/log` (on .31) | unbuffered |
| mm-adapter .29 | `/tmp/mm-adapter-29.log` (on .29) | |
| mm-adapter .31 | `/tmp/mm-adapter-31.log` (on .31) | |
| c2pool | `/tmp/c2pool_*.log` + `~/.c2pool/debug.log` (local) | |

Attach to screen: `ssh <IP> "screen -r p2pool"` (detach: Ctrl-A D)

## p2pool Debug Branch

Repo: `github.com/frstrtr/p2pool-merged-v36`, branch: `c2pool-debug`

Modifications:
1. **No-ban mode** (`p2p.py`): disconnect only, no ban
2. **Cross-impl diagnostics** (`data.py`): GENTX field dumps, ref_hash comparison
3. **DOGE payout fixes** (`web.py`, `work.py`): raw script key handling
4. **Network config** (`litecoin_testnet.py`): PERSIST and BOOTSTRAP configurable

Update nodes from local:
```bash
cd ~/Github/p2pool-merged-v36 && git checkout c2pool-debug && git push origin c2pool-debug
ssh 192.168.86.29 "cd ~/p2pool-merged && git fetch origin && git checkout c2pool-debug && git pull origin c2pool-debug && find . -name '*.pyc' -delete"
ssh 192.168.86.31 "cd ~/p2pool-merged && git fetch origin && git checkout c2pool-debug && git pull origin c2pool-debug && find . -name '*.pyc' -delete"
```

## SSH Access

All nodes accessible via `ssh user0@192.168.86.<N>` with key auth.
Use `-o StrictHostKeyChecking=no` for scripted access.
Some commands need `-tt` flag for pseudo-terminal allocation.
`killall -9 pypy` is the reliable way to kill p2pool (not `pkill -f run_p2pool`).
