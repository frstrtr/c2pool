# M0 — the assembly, and the run that judges it

`node/` is where the thirteen wave-0/wave-1 components stop being a library and
start being a node: it constructs them, gives them the threads their own banners
ask for, seeds the index, decides when to ask a peer for a chain, and prints
enough about all of it that "connected and receiving nothing" is a pair of
numbers rather than a debugging session.

| file | what |
|---|---|
| `xmr_worker_loops.hpp` | the threads — `WorkerLoop` (one thread, one bounded queue, a blocking `call()` for the control path), `VerifyInbound` and `TxSinkLoop` (the enqueue-and-return adapters between the io thread and the components), and `ThreadWitnessPowSource` (the io-thread fence, as a counter) |
| `xmr_chain_boot.hpp` | where history starts: the anchor path, the genesis path, and the pre-boot serving answers that keep a peer from closing us before the trust root lands |
| `xmr_sync_driver.hpp` | the half of chain sync no component owns — who to ask, when, and what else |
| `xmr_monerod_http.hpp` | the parity/backup arm's transport, and nothing else's |
| `xmr_native_node.hpp` | `NativeNode`: the wiring, the two networks, the status surface |
| `tools/xmr_native_node_main.cpp` | `xmr_native_node`, the entrypoint: follow / probe / parity |

The KAT is `test/xmr_native_node_kat.cpp` (`ctest -R xmr_native_node_kat`): the
queues, the deferred txpool verdict, the RandomX witness, the genesis
derivation against monerod's own numbers, the pre-boot advertisement, the sync
schedule, and one regression that is a real defect this assembly found (below).

## What this layer adds that no component did

1. **The threads.** Three component banners demand a thread that none of them
   creates. C1c calls `IChainIndexInbound` and `IRelayedTxSink` from the io
   thread and says "enqueue-and-return"; C2c says "one owner (the verify
   thread) mutates" and runs a ~10–15 ms RandomX evaluation inside
   `offer_block`; C3 says its caller "must not be the io thread once the heavy
   leg is on". So: io thread for sockets and codec, verify thread for consensus
   and RandomX, pool thread for transaction decode and range proofs.
2. **The first question.** Nothing in the tree sends the first
   `NOTIFY_REQUEST_CHAIN`, and nothing seeds row zero. Without both, a node sits
   handshaked, liveness-green and empty forever.
3. **The two networks.** A Monero node needs two answers to "which network":
   the WIRE identity (network id, genesis id, default port — `levin::XmrNet`)
   and the CONSENSUS rules (the hard-fork table — `native::XmrNet`). regtest is
   the case that proves they are different facts: monerod's fakechain carries
   the MAINNET network id and serves the MAINNET genesis block at height 0,
   while running a hard-fork table that starts at v16 from height 1.
4. **The admissions.** The status line reports the RandomX witness, the queue
   depths, the peers that are handshaked but silent, and the RPC call count
   beside the block count.

## The io-thread fence is a number, not a promise

`ThreadWitnessPowSource` wraps the PoW source, records the thread every RandomX
evaluation actually ran on, and counts the ones that ran on a thread the node
declared forbidden (the io threads). The node prints it and the KAT asserts the
counter itself works — a witness that could not catch a forbidden call would be
worth nothing:

```
randomx        : mode=1 hashes=24 prefetches=1 rekeys=1 verified=24 failed=0 foreign=0 threads=128870032328384
threads        : io=128870015542976 verify=128870032328384
```

## The M0 run (regtest, 2026-09-11)

Two isolated `monerod 0.18.5.1 --regtest --fixed-difficulty 1` daemons on
loopback, own data dirs and own ports, peered only with each other — the rig
from `relay/tools/README.md`, with one addition. Give the two daemons
**different loopback addresses** (A on 127.0.0.1, B on 127.0.0.2): monerod does
not source-bind its outbound connections to its p2p bind address, so on a single
loopback address the two daemons' mutual links occupy each other's
one-connection-per-remote-IP slot and a third participant is refused with
`CONNECTION FROM 127.0.0.1 REFUSED, too many connections from the same address`
before it can say hello. The native node dials from a third address
(`--p2p-bind-ip 127.0.0.3`, which is `XmrPeerPool::Config::bind_ip`).

```bash
M=<path>/monerod
common="--regtest --fixed-difficulty 1 --no-igd --hide-my-port --non-interactive \
        --no-zmq --disable-rpc-ban --keep-fakechain --detach"

$M $common --data-dir ~/xmr-m0-rig/A --log-file ~/xmr-m0-rig/A/logs/monerod.log \
   --rpc-bind-ip 127.0.0.1 --rpc-bind-port 41189 \
   --p2p-bind-ip 127.0.0.1 --p2p-bind-port 41188 --add-exclusive-node 127.0.0.2:41288
$M $common --data-dir ~/xmr-m0-rig/B --log-file ~/xmr-m0-rig/B/logs/monerod.log \
   --rpc-bind-ip 127.0.0.2 --rpc-bind-port 41289 \
   --p2p-bind-ip 127.0.0.2 --p2p-bind-port 41288 --add-exclusive-node 127.0.0.1:41188

xmr_native_node --net regtest --connect 127.0.0.1:41188 --p2p-bind-ip 127.0.0.3 \
                --monerod-rpc 127.0.0.1:41189 --commit "$(git rev-parse HEAD)" \
                --follow-to 24 --run-seconds 200
```

`--fixed-difficulty 1` is monerod's own fakechain knob and needs no mirror on
our side: the genesis timestamp is 0, so for any chain shorter than the 735-row
window our `next_difficulty` computes 1 as well — and the parity oracle compares
the two at every sampled height rather than taking it on trust.

What the node did:

```
[node] net=regtest wire-net=0 consensus-net=regtest boot=genesis peers=1 parity=1 probe=0
[tip] height=1  id=1705bccea704... prev=418015bb9ae9... difficulty=1 cumdiff=2  timestamp=1789089762 reward=35184338534400 weight=85
...
[tip] height=24 id=d09d52593... prev=c97790ea09c0... difficulty=1 cumdiff=25 timestamp=1789091255 reward=35182795064383 weight=85
[XMR-PARITY] seam=TIP h=21 verdict=CLEAN classes=Steady+EpochEdge compared=9/9 note="9 field(s) equal [P-TIP first=native]"
[XMR-PARITY] seam=TIP h=22 verdict=CLEAN ...
[XMR-PARITY] seam=TIP h=23 verdict=CLEAN ...
[XMR-PARITY] seam=TIP h=24 verdict=CLEAN ...

=== summary ===
tip            : height=24 verified_frontier=24 rows=25 synced=1 alt=0 orphans=0 reorgs=0
boot           : genesis booted=1 inspected=1 refusals=0 dropped=0 (genesis row seeded from the levin-delivered blob)
chain-entry    : start=0 total=21 ids=21 first=418015bb9ae9... last=66979fcc5a85... first_block=1/129 bytes
peers          : handshaked=1 total=1 netgroups=1 silent=0 handshakes=1 dials=2/0 last_close= ()
levin in       : blocks=4 chain_entries=1 objects=2 txs=0 frames=7 dos_drops=0
randomx        : mode=1 hashes=24 prefetches=1 rekeys=1 verified=24 failed=0 foreign=0
monerod rpc    : calls=10 (parity/bootstrap only; never on the tip-follow path)
parity         : clean=5 fail=0 served_mismatch=0 void=0
M0-VERDICT: PASS heights=24 parity_clean=5 parity_fail=0 randomx_foreign=0
```

Read the two halves of that:

* **Heights 1–20 were BACKFILLED over levin.** One `NOTIFY_REQUEST_CHAIN` from a
  genesis-terminated locator, one `RESPONSE_CHAIN_ENTRY` with 21 ids, and the
  index's own `NOTIFY_REQUEST_GET_OBJECTS` for what it lacked (`objects=2`
  frames after C1c's ≤100-id chunking).
* **Heights 21–24 were FOLLOWED LIVE.** Four blocks mined on the daemon,
  `blocks=4` inbound `NOTIFY_NEW_FLUFFY_BLOCK` pushes, `chain_requests` flat at
  1 — the driver went quiet and the height kept moving, which is the observable
  difference between catching up and following.
* **P-TIP was CLEAN at every sampled height**, comparing all nine fields
  (`id`, `prev_id`, `cumulative_difficulty`, `difficulty`, `timestamp`,
  `reward`, `block_weight`, `long_term_weight`, `major_version`) against
  monerod's own `get_info` + `get_last_block_header`. The oracle coalesces a
  BURST of tips to its newest by design, so the twenty backfilled heights
  produced one sample between them; the four live heights produced one each.
* **`monerod rpc calls=10` is exactly two per parity sample.** Nothing on the
  tip-follow path made an RPC: `--probe-only` and `--no-parity` runs report
  `calls=0` while the index still follows.

## The live stagenet probe (read-only)

Against the synced-and-syncing stagenet daemon on `192.168.86.44:38080`, one
connection, one question, no blocks fetched:

```
xmr_native_node --net stagenet --connect 192.168.86.44:38080 --probe-only --no-parity

chain-entry : start=0 total=1067456 ids=10000 first=76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb
              last=ef2163d4a1bb0561ef53def8367caec3ab4b7feaa1aeeab1cbc47b354fba3b9d first_block=1/317 bytes
peers       : handshaked=1 total=1 handshakes=1 dials=2/0
levin in    : blocks=0 chain_entries=1 objects=0 txs=0 frames=1
monerod rpc : calls=0
```

`total_height` is the daemon's own count and it moved between two probes twenty
minutes apart (997 377 → 1 067 456): .44 is mid-sync, which is exactly the state
this probe had to be safe against.

`--probe-only` also pins the DIAL PLAN to the peers it was given. The pool
learns addresses from the handshake peerlist and refills toward its target, so
the first version of this probe opened a connection to a public stagenet node it
had just learned from the daemon it was probing. A read-only probe dials what it
was told to dial and nothing else.

`ids[0]` is `STAGENET_GENESIS`, which is the daemon's own proof that it accepted
our network id, our handshake and our locator terminus. `--probe-only` sends
exactly one `NOTIFY_REQUEST_CHAIN` and never a `GET_OBJECTS`: a chain entry
costs the daemon a walk of its id index, a block span costs it disk and
bandwidth it is using to sync.

One observation worth recording: the probe's `first_block` (317 bytes) did NOT
parse as the stagenet genesis block, and the boot refused it rather than
believing it — `refusals=1`, and the object-request path is what actually seeds
a node. The opportunistic use of `first_block` is best effort by design; what
the field really carries on that daemon version is an open question, not a
dependency.

## The defects this assembly found

Both were invisible to every component KAT, because both are about what happens
when the parts are wired to each other and to a real daemon.

1. **A parked block was never revisited when its parent connected.** `C2c`'s
   branch path resolves descendants; the fast path (a block that extends the
   tip) did not. monerod sends its top block to any peer it sees as behind, so
   the first block a cold node receives is normally one it cannot connect yet —
   this is every cold start, not a corner case. The live symptom was a node that
   backfilled to height 8, sat there, and let four already-delivered blocks rot
   in the alt pool while its peer climbed, with no error anywhere because
   nothing had failed. Fixed in `chain/xmr_chain_index.hpp` by draining the
   tip's parked children as ordinary EXTENDS (going through the fork-choice
   switch would announce a Reorg of depth 0 for what is simply the next block),
   and pinned by `test_out_of_order_push_connects()` — which fails 2 checks on
   the code as it stood.
2. **The first chain request waited out the boot fetch's timeout.** The sync
   driver kept one in-flight flag for two different questions, so the chain
   request went out a full `chain_request_timeout_ms` (20 s) after the trust
   root had landed. Twenty seconds of "connected, synced=0, nothing happening"
   on every cold start — the exact shape of failure this layer exists to make
   unmisreadable. Fixed in `xmr_sync_driver.hpp`, pinned in the KAT.

A third thing worth knowing rather than fixing here: `ChainIndex::refetch_wanted()`
is a STANDING want list — it is not cleared when a block arrives. A driver that
asked for all of it every tick asked twice a second forever (observed: 361
`RESPONSE_GET_OBJECTS` frames for a 12-block backfill, every one of them an
answer to a question already answered). The driver now rate-limits per id and
skips ids the index already has. Whether the index should prune the list is a
C2c question; that the SCHEDULE must not be a busy loop is this file's.

## Wired, and deliberately not driven

* **C5 `LevinBlockRelay`** is constructed and its 2009 responder is armed, but
  nothing in M0 calls `relay()`: a found block comes from the stratum /
  settlement path, which is M3.
* **C4's arms** are constructed, readable and reported in the status line
  (`tmpl=native`), but the option-B settlement provider is not rebound through
  them yet: that is M2.
* **C3's txpool** is fed from levin and selectable, and its chain-event
  subscription (mined-id drop, key-image eviction, rollback re-admission) is
  wired; proving per-transaction equality against monerod's own pool is M1.
* **Anchor boot** (`--boot anchor`) is wired and is the production path, but M0
  ran on the genesis path because a fresh regtest chain is younger than the
  anchor format can describe (`generate_anchor` refuses any height below the
  100 000-block long-term weight window). The embedded stagenet bundle is not
  exercised live here.

Each of those is wired to its seam and left unexercised ON PURPOSE, so the
milestone that owns it has something to prove rather than something to discover.

## Owed operator calls

* **R-ARMORDER — the found-block arm order.** `contracts/relay.hpp` defaults
  `ArmOrder::DaemonFirst` (the plan's M0–M4 posture: monerod validates for free
  before our P2P identity is behind the block), while C5's own
  `self_contained_policy()` defaults to `Parallel` with the P2P arm first (the
  daemonless posture the track exists to reach). The node currently takes
  `DaemonFirst` as its default and exposes `--relay-order`; which one a
  PRODUCTION pool ships with is an operator ruling, and it is the last knob
  before M3 can claim a daemonless find.
* **P-TIP soak scope.** M0's exit criterion in the plan is a 48–72 h P-TIP run
  with ≥1 EpochEdge and zero field diffs over ≥2200 blocks. This run is a SHORT
  proof (24 heights, 5 samples, 22 s of wall clock); the sustained soak needs a
  host, a network and a window, and the graduation ledger says so itself
  (`state: Observing`, `window: 22 s observed, need 60 s` at the regtest
  policy). Which network it runs against (stagenet from a host that is not
  .44's syncing daemon) and for how long is the operator's call.
