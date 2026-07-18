# DASH Deployment Guide — c2pool v0.2.3

Operator handbook for running c2pool as a DASH stratum endpoint at a professional
mining site. Applies to v0.2.3 on Ubuntu-class Linux x86_64.

## 1. What v0.2.3 is (and is not)

v0.2.3 provides functional DASH stratum mining with **solo-mode payouts**:

- Miners connect over stratum and receive real DASH work (X11).
- When a block is found, the coinbase pays the **finding miner's address directly**.
  Winner takes the block. There is no share-based smoothing in this release.
- Pooled PPLNS payout smoothing arrives in **v0.2.4** (sharechain mint campaign).
  Same binary family, drop-in upgrade — deploy v0.2.3 now, upgrade in place later.

Treat v0.2.3 as: "solo mining with pool-grade infrastructure." Every rig you point
at it is mining for its own payout address.

## 2. Prerequisites

- A fully **synced dashd** (mainnet) on a host the c2pool node can reach.
- RPC credentials in `dash.conf` — **never on the command line** (argv is visible
  in `ps`; config files are not).
- Ubuntu-class Linux, x86_64.

Minimal `dash.conf`:

```ini
server=1
rpcuser=<user>
rpcpassword=<long-random-secret>
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

Confirm sync before proceeding:

```bash
dash-cli getblockchaininfo | grep -E '"blocks"|"headers"|"verificationprogress"'
```

`blocks` must equal `headers` and `verificationprogress` must be ~1.0.

## 3. Install and run

Fetch and unpack the release tarball:

```bash
wget https://github.com/frstrtr/c2pool/releases/download/v0.2.3/c2pool-dash-0.2.3-linux-x86_64.tar.gz
tar xzf c2pool-dash-0.2.3-linux-x86_64.tar.gz
```

Run against your dashd, with stratum on your chosen port:

```bash
./c2pool-dash --run \
  --coin-rpc 127.0.0.1:9998 \
  --coin-rpc-auth /home/dash/.dashcore/dash.conf \
  --stratum 3335
```

- `--coin-rpc H:P` — the dashd RPC endpoint.
- `--coin-rpc-auth PATH` — path to `dash.conf`; c2pool reads the RPC credentials
  from it (credentials never appear on argv).
- `--stratum [HOST:]PORT` — bind the miner-facing stratum listener (e.g.
  `--stratum 3335` or `--stratum 127.0.0.1:3335`); omit to disable.
- `--testnet` — testnet variant, for staging.

Healthy startup looks like:

- `...CoindRPC connected!` (dashd reachable, credentials accepted)
- `StratumServer started on 0.0.0.0:3335`
- `[run] external-daemon submit arm ARMED` (won blocks will reach dashd via
  submitblock)
- DASH-tagged log lines showing new templates as the chain advances

If you do not see all of these within a few seconds, stop and see §6.

### Pointing miners

On each rig / firmware pool slot:

```
URL:    stratum+tcp://<node-ip>:3335
Worker: <miner's DASH payout address>
Pass:   x
```

The **worker name is the payout address**. In solo mode this is where the block
reward goes if that rig finds the block. Double-check addresses — a typo pays
someone else or burns the reward.

## 4. Per-node capacity and clustering

Each node enforces a **strict stratum connection cap** — default **100**,
tunable with `--max-stratum-connections`. Connections beyond the cap are refused,
not queued.

Size the cluster for M rigs with per-node cap S_max:

```
N = max(2, ceil(M / (0.7 × S_max)))
```

Then bump N until:

```
(N − 1) × S_max ≥ M
```

so the site survives any single node failure at full rig count. The 0.7 factor
keeps steady-state headroom for reconnect storms after a network blip.

Example: M = 250 rigs, S_max = 100 → ceil(250/70) = 4 nodes; check (4−1)×100 =
300 ≥ 250 — OK. Deploy 4.

### Rig failover

Use the firmware's pool-slot list on every rig:

1. **Slot 1:** the rig's home node
2. **Slot 2:** a designated neighbor node
3. **Slot 3:** a third node (or a spare)

Distribute home-node assignments evenly. With the sizing rule above, any single
node can die and every rig still finds a slot.

## 5. Verifying it works

After pointing a miner, confirm in order:

1. **Job delivery:** the miner receives a job within seconds of
   `mining.authorize`. Firmware dashboard shows an active job; node log shows the
   subscribe/authorize and a job push.
2. **Sane difficulty:** X11 difficulty is in a plausible range for the rig's
   hashrate. If you see huge scrypt-scale numbers, something is misconfigured —
   that was a pre-0.2.3 symptom, not normal DASH behavior.
3. **Shares accepted:** accepted-share counter climbs on both the miner and the
   node log. Steady rejects mean a config problem, not luck.
4. **A found block:** the node log records the block submission (block hash and
   the winning payout address). Confirm on-chain: the coinbase of that block pays
   the finding rig's worker address. Check with any DASH explorer or:

```bash
dash-cli getblock <blockhash> 2 | grep -A5 '"vout"'
```

The reward matures after the standard coinbase maturity window before it is
spendable.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Miner connects, authorizes, but **never receives work** | v0.2.2 defect | Upgrade to v0.2.3. This is the defining pre-0.2.3 failure. |
| Absurd (scrypt-scale) difficulty on an X11 rig | Pre-0.2.3 difficulty handling | Upgrade to v0.2.3. |
| `CoindRPC` errors / no new templates | dashd down, unsynced, or stale RPC creds | Check `dash-cli getblockchaininfo`; verify `dash.conf` creds; restart dashd, then c2pool. |
| Rigs cannot connect at all | Port not open / firewall | `ss -ltn \| grep 3335`; open the stratum port on the host and site firewall. |
| New rigs refused, existing ones fine | Connection cap reached | Check connection count in the log; raise `--max-stratum-connections` or add a node per §4. |
| Shares rejected in bulk | Wrong coin/algo or wrong port on the rig | Confirm the rig is set to X11/DASH and the URL/port match the node. |

When in doubt: node log first, then dashd log, then the rig's firmware log.

## 7. Upgrade path: v0.2.4

v0.2.4 adds **sharechain PPLNS credit on the live legacy network** — shares earn
proportional payouts instead of winner-takes-block. It is a drop-in upgrade:

- Same binary invocation, same config, same stratum port.
- Rig-side configuration unchanged (worker = payout address carries over).
- Replace the binary, restart the node, done.

Sites running v0.2.3 today upgrade in place with no rig-side changes.
