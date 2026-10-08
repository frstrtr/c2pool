# C5 live proof — pushing a block to a real monerod

`xmr_c5_regtest_push.cpp` puts one found block on the wire through the real
`LevinBlockRelay` and the real C1a codec, and lets a real monerod judge it. The
KAT checks our 2008 frame against our own decoder; this checks it against the
only decoder whose opinion counts.

CI builds it and runs nothing: it needs a daemon, and CI must not depend on one.
It registers no ctest test, so the #1539 Not-Run rule does not apply — but it is
in both `build.yml` `--target` lists, so it cannot bit-rot unnoticed.

## The rig

Two isolated regtest daemons on loopback, each with its own data dir and ports,
peered only with each other. `fakechain` has no seed nodes and `--no-igd` is
set, so neither dials anything else.

A single daemon is not enough, and the reason is worth writing down: with
`--offline` monerod never binds its P2P listener at all, and *without*
`--offline` a daemon with zero peers never declares itself synchronized, so it
refuses both mining RPCs and relayed blocks. Two daemons that handshake each
other are synchronized within seconds, and the second node also gives the proof
its most interesting half — the block we push to one daemon has to reach the
other by Monero's own relay.

```bash
M=<path>/monerod            # v0.18.5.1

common="--regtest --fixed-difficulty 1 --no-igd --hide-my-port --non-interactive \
        --no-zmq --disable-rpc-ban --keep-fakechain --detach"

$M $common --data-dir ~/c5-regtest/data   --log-file ~/c5-regtest/logs/monerod.log \
   --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18189 \
   --p2p-bind-ip 127.0.0.1 --p2p-bind-port 18188 \
   --add-exclusive-node 127.0.0.1:18288 --pidfile ~/c5-regtest/monerod.pid

$M $common --data-dir ~/c5-regtest-b/data --log-file ~/c5-regtest-b/logs/monerod.log \
   --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18289 \
   --p2p-bind-ip 127.0.0.1 --p2p-bind-port 18288 \
   --add-exclusive-node 127.0.0.1:18188 --pidfile ~/c5-regtest-b/monerod.pid
```

`--no-zmq` on both: the ZMQ RPC port has no per-instance default, and the second
daemon dies on the collision.

Wait for `get_info` to report `"synchronized": true` on both, then mine a few
blocks on node A with `generateblocks` (any mainnet-format address; fakechain
uses the mainnet prefix).

## The push

Take a template from node A, take node B's sync data, and push the block to
node B:

```bash
BLOB=$(curl -s http://127.0.0.1:18189/json_rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_block_template",
       "params":{"wallet_address":"<addr>","reserve_size":0}}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["blocktemplate_blob"])')

# get_info on 18289 gives height / top_block_hash / cumulative_difficulty;
# hard_fork_info gives the version.
C5_SRC_IP=127.0.0.2 ./xmr_c5_regtest_push 127.0.0.1 18288 \
    <height> <top_block_hash> <cumulative_difficulty> <hf_version> "$BLOB" 7
```

`C5_SRC_IP` matters: monerod allows one connection per remote IP, and in this
rig node A already holds 127.0.0.1's slot on node B. Binding the source to
another loopback address arrives as a distinct peer.

At `--fixed-difficulty 1` every nonce clears the target, so no RandomX hashing
is needed to produce a valid block — which is exactly why the relay's gate is an
injected closure: the tool passes `pow_attestation(id)` for the block it built.

## The run this component was landed on

monerod 0.18.5.1-release, regtest, two nodes at height 11, block pushed to node
B (18288) from 127.0.0.2:

```
[live] block id aa6a3fa30d170b2b41ba6663aa29c74a10c5f266c24cda6177cdaf50fd229e98 at height 11, 0 txs, nonce 7
[live] <- command 1001 (HANDSHAKE), 262 bytes, class Response
[live] HANDSHAKED
[live] writing 217 bytes, command 2008
[relay:info] relay: block aa6a3fa3... h=11 peers=1 daemon=none first=p2p
[live] verdict: peers=1 reached=1 why=''
```

monerod's own log, node B:

```
[127.0.0.2:40747 INC] 184 bytes received for category command-2008 initiated by peer
[127.0.0.2:40747 INC] Received NOTIFY_NEW_FLUFFY_BLOCK <aa6a3fa3...> (height 12, 0 txes)
+++++ BLOCK SUCCESSFULLY ADDED
```

Both daemons then reported height 12, and `get_block_header_by_height(11)` on
BOTH returned id `aa6a3fa3...`, nonce 7 — node B accepted our block and relayed
it to node A over Monero's own P2P. The daemon arm was not configured
(`daemon=none`): this block reached the Monero network over levin alone, which
is the daemonless claim C5 exists to make.

## Still owed

The block above carries no transactions, so it does not exercise the
self-contained body path against a real daemon. Proving that needs a regtest
wallet putting transactions in the pool first, and it is the natural first step
of the C6 regtest harness rather than of this tool.
