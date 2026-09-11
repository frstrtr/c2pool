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
  wired. Proving per-transaction equality against monerod's own pool is M1, and
  the M1 section below is where that happened -- including the wiring gap M0
  left behind it.
* **Anchor boot** (`--boot anchor`) is wired and is the production path, but M0
  ran on the genesis path because a fresh regtest chain is younger than the
  anchor format can describe (`generate_anchor` refuses any height below the
  100 000-block long-term weight window). The embedded stagenet bundle is not
  exercised live here.

Each of those is wired to its seam and left unexercised ON PURPOSE, so the
milestone that owns it has something to prove rather than something to discover.

## M1 — the transaction pool, per transaction, against monerod

M0 proved the node follows a tip. M1 proves the thing a template is actually
built out of: that for every transaction in both pools, `{id, weight, fee,
blob_size}` is the same number on both sides — with our side computed by C3
from bytes that arrived over levin `NOTIFY_NEW_TRANSACTIONS`, and monerod's
side the daemon's own answer to `get_transaction_pool`. Nothing in our number
came from the daemon.

### What M1 added

| what | where |
|---|---|
| the **P-POOL seam** — per-transaction comparison, set differences as measurements, and the cumulative coverage claim | `parity/xmr_txpool_parity.hpp` |
| `ProbeKind::Pool` and the frozen `POOL_FIELDS` table, comparator version **1 → 2** | `contracts/parity.hpp`, `parity/xmr_parity_types.hpp` |
| `RelayedTxPool::facts()` — the whole pool as four numbers per entry, under one lock | `txpool/xmr_relayed_txpool.*` |
| `NativeNode::txpool_parity_sample()` and the harness injection port `inject_relayed()` | `node/xmr_native_node.hpp` |
| `publish_tx_gate_()` — **the defect below** | `node/xmr_native_node.hpp` |
| `--txpool-parity`, `--inject-dir`, the M1 gate flags and the `M1-VERDICT` line | `node/tools/xmr_native_node_main.cpp` |
| the offline replay KAT and its captured daemon response | `test/xmr_txpool_parity_kat.cpp`, `test/xmr_txpool_parity_golden.hpp` |

### The defect M1 found

**C3's relay gate was never opened.** `RelayedTxPool` refuses every transaction
with `NotSynced` until somebody tells it the index reached the tip — monerod's
`is_synchronized()` rule, fail-closed so that a node catching up cannot build a
template on a pool it could not have populated correctly. M0 wired C2 → C3 for
BLOCK events and left this seam open: nothing in the tree called
`set_synced()`, so the gate stayed shut for the life of the process and the
pool refused every transaction that ever reached it.

It is invisible from every angle M0 looked from. The tip follows. The peer is
healthy. The status line's `txs=` counts frames coming IN, and they do. The only
symptom is a pool that stays empty, which on a quiet chain is also what success
looks like. M1 is the first milestone that asks the pool what it HOLDS, which is
why M1 is where it surfaced. Fixed by `publish_tx_gate_()`, published from the
verify thread (which owns the sync state) to the pool thread (which owns the
gate) on a change only; the status line now carries `txpool: gate=` beside the
counts, so the shut-gate state can never again look like a quiet chain.

### The run (regtest, 2026-09-11)

Two isolated `monerod 0.18.5.1 --regtest --fixed-difficulty 1` daemons on
loopback with their own data dirs and ports (42188/42189 and 42288/42289), the
node dialling from a third loopback address, and a `monero-wallet-rpc` against
the first daemon as the transaction SOURCE — real wallet transactions, signed
and relayed the ordinary way, never handed to the node directly.

```bash
xmr_native_node --net regtest --connect 127.0.0.1:42188 --p2p-bind-ip 127.0.0.3 \
                --monerod-rpc 127.0.0.1:42189 --force-synced \
                --txpool-parity --txpool-parity-every 1000 \
                --m1-min-txs 50 --m1-require-mined-eviction --run-seconds 600
```

```
=== M1: txpool parity (P-POOL) ===
samples        : judged=582 unjudged=14 aligned=471 no-samples=452 (polls=596)
transactions   : distinct_compared=67 daemon_ids_seen=67 never_compared=0 | pool_max ours=26 theirs=26
per-tx verdicts: clean=1368 fail=0 served_mismatch=0 void=0
fields         : compared=4104 equal=4104 differed=0 absent=0
evictions      : mined=67 key_image_conflict=0
txpool         : count=0 bytes=0 accepted=67 duplicates=0 rejected=0 evicted(age=0 cap=0)
dos            : frames_in=45 dropped=4
M1-VERDICT: PASS txs_compared=67 all_equal=1 fields=4104/4104 mined_evictions=67 never_compared=0
M0-VERDICT: PASS heights=171 parity_clean=9 parity_fail=0 randomx_foreign=0
```

Read the numbers that matter:

* **67 distinct transactions, 4104 field comparisons, 0 differences and 0
  absences.** Three fields per transaction per sample, 1368 per-transaction
  CLEAN verdicts across 582 judged samples.
* **`never_compared=0`.** This is the line that stops the seam being vacuous.
  The intersection is what gets judged and the set differences are measurements,
  so a probe could report "all clean" over an intersection that was always
  empty. The tally therefore remembers every id the DAEMON's pool ever held and
  every id actually compared; `never_compared` is the difference, and it is a
  gate. Every transaction the daemon ever pooled was compared, field by field.
* **`aligned=471`.** Samples where the two pools held the same SET of ids, not
  merely agreeing about their overlap.
* **`no-samples=452` is not a pass and is not counted as one.** Most of a run is
  two empty pools between blocks; those samples are judged, contribute nothing,
  and are reported separately so nobody can read them as agreement.
* **`mined=67`.** Every transaction left the native pool because the block that
  mined it connected — four `[M1-EVICT]` lines, one per block, each naming what
  left and matching the pool's own `evicted_mined` counter. A counter with no id
  behind it names nothing; an id that vanished with no counter behind it could
  have gone for size or age. The proof needs both and has both.
* **`dos: frames_in=45 dropped=4`.** The C1 token buckets fired during the run,
  on a daemon re-relaying transactions we already held, and the drops cost the
  parity claim nothing: all 67 ids were still compared. The buckets held.

### The key-image conflict, on purpose

A mined eviction is easy to observe because the chain produces one every block.
A KEY-IMAGE-CONFLICT eviction — an entry dropped because a block spent its key
image inside a DIFFERENT transaction — needs a double spend, and a daemon will
not make one for you. So M1 builds one, out of a transaction a real wallet
really signed:

1. the wallet builds a transaction with `do_not_relay`, so the daemon never
   hears about it;
2. the harness is handed its blob as `<inject-dir>/x.twin` and injects the
   **key-image twin** — the same bytes with one byte of `tx_extra` flipped,
   which leaves every key image, every commitment and the range proof untouched
   while changing the id. The flip is done with C3's own decoder, because only a
   parse knows where `tx_extra` begins. The twin is admitted; now OUR pool holds
   the twin and the daemon's pool holds nothing;
3. the ORIGINAL is handed to the daemon with `send_raw_transaction`, which
   relays it to us over levin. C3 refuses it as a `KeyImageConflict` with
   `drop_offense=0` — first-seen-wins, exactly as monerod's
   `have_tx_keyimges_as_spent` keeps the first and marks the second a no-drop
   double spend;
4. the daemon mines a block containing the ORIGINAL. Our pool holds the twin,
   whose id is nowhere in that block — so it leaves by KEY IMAGE, and the pool
   accounts for it as `evicted_conflict`, not as mined.

The run, at heights 174 → 175:

```
[M1-INJECT] conflict.twin: injecting the KEY-IMAGE TWIN of the blob
            (one tx_extra byte flipped; same key images, new id)
[M1-INJECT] conflict.twin bytes=2166 verdict=Accepted drop_offense=0
            id=33a99d6b796fad97776b75697fbec1982a313da3b59a6ca0929e7eb6bd37c8b1
[M1-EVICT]  h=174->175 left_pool=1 mined=0 conflict=1 ids=33a99d6b796fad97

evictions   : mined=0 key_image_conflict=1
conflicts   : rejected_key_image=1 (of which injected=0) | injected=1 accepted=1
scope       : SCENARIO run -- parity coverage is NOT claimed (--m1-min-txs 0);
              the verdict rests on the required eviction(s)
M1-VERDICT: PASS conflict_evictions=1 never_compared=1
```

The daemon's original was `51595e6c…`, which never appears in our pool. Read the
three lines that make it a proof rather than a story:

* `rejected_key_image=1 (of which injected=0)` — the refusal happened to a
  transaction that arrived over LEVIN, not to one the harness handed in. That is
  first-seen-wins working against the network, and it is broken out of the
  general `rejected` counter precisely so it can be pointed at.
* `mined=0 conflict=1` — the twin did not leave because it was mined. Its id is
  nowhere in block 175. It left because that block spent its key image inside a
  transaction we never held.
* `left_pool=1` beside `conflict=1` — the set difference and the pool's own
  accounting agree about the same single entry.

That window is a DELIBERATE divergence: for the length of it the daemon holds an
id we will never hold. The run declares exactly that in its own arguments,
`--m1-allow-uncompared 1`, and `--m1-min-txs 0` makes it a SCENARIO run: parity
coverage is not claimed at all, the verdict rests on `no_disagreement()` plus the
eviction the run explicitly required, and a scenario that required no eviction
FAILS rather than passing for free. Every parity run passes zero allowance.

### Coverage, and what this run is not

The plan's M1 exit criterion is 100 % per-transaction equality over **≥10 000**
relayed transactions on stagenet, plus a ≥720-block
`already_generated_coins` / `median_weight` streak. This is the REGTEST proof of
the same claim at two orders of magnitude less volume: the mechanism, the
comparator, the coverage gate and both evictions, on a chain we control end to
end. The volume and the streak need stagenet, a host and days, and that is an
operator call about where the soak runs — the same call M0's P-TIP soak is
waiting on.

What runs in CI is the OFFLINE REPLAY: a real daemon's `get_transaction_pool`
answer is checked in, the KAT feeds each entry's `tx_blob` into a real
`RelayedTxPool` through `IRelayedTxSink`, and the same `compare_txpools` judges
the two sides. Every native number is recomputed at test time from the
transaction bytes; every monerod number is one the daemon printed. Perturb a
weight, a fee or a size and the KAT fails, which is the point.

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
