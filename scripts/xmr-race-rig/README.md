# xmr-race-rig: race-heavy 3-node regtest + settlement-divergence classifier

REGTEST ONLY. Three `monerod --regtest --fixed-difficulty 1` wired only to each other (exclusive nodes on
127.0.0.1) and three `c2pool-v37-xmr` nodes (native template, `--arm-order p2p-first`, relay ON, D_conf 10,
flip 0 as built). Each node gets a paced stratum miner (`burst.py`, one nonce every LO..HI s). At
difficulty 1 every nonce is a block, so the three miners produce same-height races, depth-1/2 native
reorgs and one-tick flip-flops (X -> Y -> X) all the time: the shapes a live pool sees rarely, many times per
run. Nothing here mines, submits or broadcasts on mainnet or stagenet.

## Files

| file | what |
| --- | --- |
| `common.sh` | paths + ports (env-overridable: `RIG`, `MDIR`, `MON_BASE`, `PRX_BASE`, `STR_BASE`, `REL_BASE`, `SRC_IP_BASE`) |
| `gen_chain.sh` | builds the chain template once (`$RIG/tmpl/mdata1`, GEN=120 blocks) |
| `run.sh` | one run: monerods, RPC proxies, nodes A/B/C, miners until `FOUND_WANT` lane blocks, bury, classify |
| `runq.sh PREFIX N BIN` | N runs of BIN, then `table.py` over them |
| `race_classify.py` | the analyzer (below) |
| `table.py` | one row per run from `runs-*/classify.json` + totals |
| `burst.py`, `rpcproxy.py`, `dump_coinbases.py` | paced miner, per-method monerod RPC counter, final-chain coinbase dump |
| `stop.sh` | stops this rig's processes only (recorded PIDs + patterns that contain `$RIG`) |

## Run

```sh
export RIG=$HOME/v37/v37-racediv-rig MDIR=$HOME/v37/ic-verify/monero   # defaults
scripts/xmr-race-rig/gen_chain.sh                                      # once
scripts/xmr-race-rig/runq.sh base 6 /path/to/c2pool-v37-xmr            # 6 runs -> $RIG/runs-base-1..6
python3 scripts/xmr-race-rig/table.py $RIG/runs-base-*
```

Knobs (env): `FOUND_WANT` (45 lane blocks), `DUR_CAP` (300 s), `LO`/`HI` (2/4 s per miner), `BURY` (14),
`DCONF` (10), `SHAREDIFF` (8). A run takes about 4 minutes and ~3 GB RSS in total.

## race_classify.py

Input: the node stdout logs (and optionally the monerod logs and `dump_coinbases.py` output). Either a
directory (`node<X>.log`, `monerod<i>.log`, `coinbases.txt`) or explicit files, which is how the capstone
measurement uses it on real hosts:

```sh
race_classify.py --node vm905=/logs/vm905.log --node ws=/logs/ws.log --node sg=/logs/sg.log --d-conf 10 --json out.json
```

For every shared finalize cursor it compares `cba-digest ... owed_digest=`; for every height every node's
cursor has passed it compares the `FINALIZED <bid> h=` block. Each divergence is labelled:

* **(a) EXPECTED**: some node saw a reorg covering that height at depth >= D_conf (native view: the
  `reorg-in: ... (depth d)` re-delivery, or the tip at an `ORPHANED` disposition; monerod view: `REORGANIZE on
  height` lines). The finality boundary was crossed; the report says whether that node's D2 alarm fired
  (`cba-ALARM MINORITY-*`, a CONVERGING/DIVERGED state, or non-zero minority alarm counters).
* **(b) BUG**: every reorg covering the height was shallower than D_conf, yet the nodes finalized
  different blocks (or their digests differ with equal finalized sets).

Each divergent height is printed with the evidence lines (node:line: booking / ORPHANED / re-delivery /
FINALIZED) and a `SUMMARY {json}` line. Exit status 2 if any class-(b) divergence exists, 0 otherwise.
The depth taken from an `ORPHANED` line without a matching re-delivery is an upper bound (tip - h + 1).
`stale_pending_rebooked` counts the RACE-DIVERGE retirements (a one-tick flip-flop re-booked, see
`v37_xmr_race_rebook_kat`).
