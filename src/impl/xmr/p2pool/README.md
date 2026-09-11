# P2Pool sidechain observer — strictly read-only

A client for **somebody else's network**. P2Pool (SChernykh/p2pool) is a
decentralised Monero pool whose miners share a PPLNS window carried on its own
peer-to-peer sidechain: a small binary protocol over TCP, unrelated to Monero's
levin and unrelated to c2pool's own share chain. This tree connects to it,
parses what it says, and does nothing else.

It exists because P2Pool is the only large, live, adversarial instance of the
problem c2pool's XMR lane is solving, and the cheapest way to learn how that
problem actually behaves is to watch the thing that already works — how often
two miners land on the same height, how wide that window is, how the share set
moves, how a template tracks the Monero tip.

---

## Read-only is a shape, not a flag

The protocol has twelve message ids. Seven of them publish or announce:
`BLOCK_RESPONSE`, `BLOCK_BROADCAST`, `BLOCK_BROADCAST_COMPACT`,
`MONERO_BLOCK_BROADCAST`, `AUX_JOB_DONATION`, `BLOCK_NOTIFY`, and `LISTEN_PORT`.

**This tree can encode none of them.** `p2pool_wire.hpp` declares

```cpp
enum class ControlMessage : std::uint8_t {
    HandshakeChallenge, HandshakeSolution, BlockRequest, PeerListRequest
};
```

and one `encode()` that is total over that enum. There is no `PoolBlock`
serialiser anywhere under `p2pool/` — `p2pool_block.hpp` declares `deserialize`
and nothing that writes — and no `bind()`, so there is no inbound path either.
"Can this observer publish?" is answered by reading one enum declaration.

The KAT pins the emitted message-id set at `{0, 1, 3, 6}`, so adding a fifth
encoder is a test failure rather than a review oversight. The live tool prints
the same thing as a per-message byte ledger from the run itself.

`LISTEN_PORT` is the interesting omission. Sending it is what puts an address
into every peer's list and onward into the network's own directory — a write to
P2Pool's peer state, even though it is not a write to its sidechain. Not sending
it has a documented cost, straight out of upstream: `P2PClient::is_good()`
requires a listen port and `on_broadcast()` skips peers that are not good, so a
node that never announces one is **never sent block broadcasts**.

So the observer **pulls**. It polls each peer's tip with `BLOCK_REQUEST` — a
33-byte GET whose answer is the only thing that moves — and walks parents
backwards to fill the ancestry.

### The five-second rule

Pulling has one timing constraint, and it has to be right:

* a peer disconnects a handshaken connection that has sent nothing for **300 s**;
* a peer *bans* a connection that has not broadcast a block in **900 s**, but
  only when `cur_time >= max(last_sidechain_update, last_block_request) + 10`.
  A peer that is requesting blocks reads as **syncing**, not silent, and is
  exempt.

`tip_poll_ms` is therefore 5000. A thirty-second poll would look harmless in
review, work for a quarter of an hour, and then get the observer banned by every
peer at once.

---

## Layout

| file | what it is |
|---|---|
| `p2pool_consensus.hpp` | the three sidechain consensus ids, ports, DNS seeds, chain parameters |
| `p2pool_wire.hpp` | message ids, frame splitting, the four-value write surface, peer-list decode |
| `p2pool_handshake.hpp` | challenge/solution keccak and the dial-side proof of work |
| `p2pool_block.hpp` | the `PoolBlock` parse: Monero template + sidechain record + share set |
| `p2pool_read_model.hpp` | the accumulator: tip, difficulty, cadence, same-height contests |
| `p2pool_observer.hpp` | sessions and the poll loop, in three drivable phases |
| `p2pool_multiwatch.hpp` | three observers through **one** `poll()`, plus the terminal |
| `p2pool_tui.hpp` | the frame: a pure function from three read models to text |
| `tools/p2pool_observer_main.cpp` | the live single-chain harness |
| `tools/p2pool_monitor_main.cpp` | the live all-in-one monitor: fullscreen TUI and `--snapshot` |
| `test/p2pool_parse_kat.cpp` | the parser KAT, over two real captured frames |
| `test/p2pool_monitor_kat.cpp` | the render KAT: a golden frame and the emit-set pin |
| `test/p2pool_monitor_golden.inc` | that golden frame, one C string per line — readable as a picture |
| `test/gen_p2pool_golden.py` | independent Python reading that generates the golden's expected values |

Everything is header-only STL over two things the repository already has:
`xmr_coin` (the vendored Monero keccak and tree hash) and the native lane's
consensus headers. The TUI adds nothing to that: ANSI escapes and POSIX
`termios`, no ncurses, no boost, no asio, no threads.

---

## What is reused from M3, and why that matters

A P2Pool sidechain block is a **complete, valid Monero block blob** with
P2Pool's own record welded onto the end:

```
+---------------------------------------------+------------------------+
|            Monero block template            |     side-chain data    |
| ... NONCE ... EXTRA_NONCE ... MM_ROOT ...    | parent, uncles, height,|
|                                             | difficulty, proof, ... |
+---------------------------------------------+------------------------+
```

So the observer does not re-implement Monero. It finds the boundary and hands
bytes `[0, sidechain_offset)` to `native/consensus/xmr_block_parse.hpp` and
`xmr_block_id.hpp` — the same coinbase parse, the same tree hash, the same
length-prefixed block id the native node runs against monerod. Every read goes
through Wave 0's bounds-checked `BlobReader`, because these bytes come from an
unauthenticated peer on a public network.

The two readings are cross-checked against each other at runtime: a disagreement
on timestamp, prev_id or nonce is reported loudly rather than absorbed.

### The sidechain id

```
sidechain_id = keccak256( block bytes with NONCE, EXTRA_NONCE and the
                          merge-mining ROOT zeroed  ||  consensus_id )
```

The three zeroed windows are what a miner grinds, so the id is stable while a
template is being mined; the consensus id at the end binds the block to one
sidechain. Recomputing it is both an integrity check on the parse (every offset
must be right) and an authentication of the chain the peer claims to be on. For
a `BLOCK_RESPONSE` the observer recomputes it and flags it verified; for a
pruned or compact broadcast it records the id from the wire and flags it
**unverified**, because rebuilding the elided outputs needs the PPLNS window
this observer deliberately does not keep.

---

## Two defects this found by being run

**1. P2Pool's hash order is not byte order.** Upstream's `struct hash`
(`src/common.h`) compares 32-byte ids as four little-endian words, most
significant first — and the merge-mining extra list is emitted from a
`std::map<hash, ...>`, so it arrives in *that* order. The first cut used
`std::array`'s lexicographic `operator<` for the "ids must increase" check and
rejected a steady trickle of perfectly legal live blocks. The counter-example is
mini block `f11e43b5…ea31fb` at sidechain height 14757139, whose two chain ids

```
40b20e14c59edc3257b171b0f37627018e9245edd52a690bf6d9e621a098b96a
01f0cf665bd4cd31cbb2b2470236389c483522b350335e10a4a5dca34cb85990
```

descend lexicographically and ascend in P2Pool's order. It is golden B in the
KAT; reverting the comparator makes the KAT fail with the same
`BadSidechain` the live run produced.

**2. Backfill was poisoning the cadence.** A pulling observer fetches the tip
and then walks parents, so most heights in the model were *received* seconds
apart even though they were *mined* ten seconds apart. Averaging over all of
them reported **4.4 s/height** on a chain that targets 10 — a number that looks
like a finding and is an artefact of our own fetch rate. Cadence is now measured
only over the **live window**: heights strictly above the frontier (the tip that
already existed when the run started), which cannot have been backfilled.

---

## Running it

```
xmr_p2pool_observer --chain mini --seconds 400 --peers 5 \
    --monero-prev 3760079:4a051a76…19dd0 \
    --capture-golden A.bin --capture-mm B.bin --dump-failed ./failed
```

`--monero-prev H:HASH` is the external anchor: every sidechain block templated
on Monero height `H+1` carries the id of `H` as its `prev_id`, so supplying that
pair from any independent Monero source turns "we parsed some bytes" into "we
parsed the chain everyone else sees". A mismatch fails the run.

CI **builds** this binary so it cannot bit-rot and **never runs** it, because
running it dials a public network. It registers no ctest test, so the #1539
Not-Run rule does not apply to it. What CI runs is `xmr_p2pool_parse_kat`,
which is offline: both goldens are embedded in the header.

---

## All three sidechains at once

`xmr_p2pool_monitor` watches **main, mini and nano together** in one read-only
process, on one screen.

```
xmr_p2pool_monitor                          fullscreen, all three chains
xmr_p2pool_monitor --chains mini,nano       two of them
xmr_p2pool_monitor --snapshot --seconds 90  one plain-text frame to stdout
```

### One `poll()`, three chains, no threads

An `Observer` **is** one sidechain — one consensus id, one peer set, one read
model, one byte ledger — and that shape is not changed to make three of them
fit. What cannot be had three times is the event loop: three `::poll()` calls in
sequence means each blocks the other two for its timeout, and the five-second
tip-poll rule above starts to slip. Threads would fix the stall and bring a
mutex around every read model for three sockets' worth of traffic.

So the observer's loop was split into the three phases it already contained, and
the monitor drives all three chains through **one** `poll()`:

```
for each chain:  begin_tick()                        dial, reap
for each chain:  begins[i] = pfds.size(); collect()  append its sockets
append the tty                                       a keypress wakes the loop
::poll(pfds, timeout)                                the only blocking call
for each chain:  dispatch(pfds + begins[i], n_i)     its own slice, only
```

**The range is the tag.** A chain's sockets occupy a contiguous slice of the
shared array, so there is no per-fd chain map to build, look up or leave stale,
and a chain cannot be handed another chain's `revents` — it is handed a pointer
and a length. `run()` is written in terms of the same three calls, so the
single-chain harness and the monitor cannot drift apart.

Per-connection timers needed nothing: `next_tip_poll_ms_` already lives inside
`PeerSession`, so the "< 10 s" rule holds independently on every socket of every
chain.

One thing did have to change. The observer never re-dials an endpoint, which is
right for a 300-second harness and wrong for a monitor left running for hours:
every peer that ever hung up would be excluded permanently, the dial queue would
drain, and a panel would go quiet while the chain was fine. `redial_after_ms`
(0 = never, the harness default) and an idle-chain reseed fix that, and the
queue is capped so gossip cannot grow it without bound overnight.

### The TUI has no dependencies

ANSI escapes and POSIX `termios`: raw mode is four flags, the alternate screen
and the cursor are two escapes each, the size is `TIOCGWINSZ`, `SIGWINCH` sets a
flag. No ncurses, no boost, no asio, no threads.

The restore path is installed three ways over, because a monitor that dies in
raw mode leaves someone with a shell that does not echo: the loop exits on a
quit flag set by `SIGINT`/`SIGTERM`, the `TerminalUi` destructor restores, and an
`atexit` hook restores whatever the exit path was.

Everything drawn is printable ASCII — the pulse ramp is `_.-=+*#`, the bars are
`#`/`-`. The moment a frame holds a multi-byte character, `size()` stops being
the column count and every alignment becomes a guess.

### The frame is a pure function, so it is pinned

`p2pool_tui.hpp` is deliberately POSIX-free: no socket, no terminal, no clock.
Ages and uptime are resolved at one instant handed in by the caller. That is
what lets `xmr_p2pool_monitor_kat` fill three read models with fixed synthetic
observations at fixed timestamps and compare the **whole frame** against
`p2pool_monitor_golden.inc`, byte for byte, on every machine and forever. A
dashboard is the easiest place in a codebase to hide a wrong number, because the
only thing that would catch it is somebody looking at it.

Colour is additive and nothing else: `strip_ansi(render(color))` equals
`render(plain)` line for line, which the KAT asserts — so `--snapshot` is the
same renderer with the escapes off, not a second one that could disagree with
the screen. The KAT also re-asserts the emitted id set `{0, 1, 3, 6}` for this
second binary, and the footer of every frame prints that set **as computed from
the encoder**, so a fifth encoder would start announcing itself on screen in the
same breath as it failed the test.

The panels inherit the read model's refusals rather than softening them for
looks: below two live samples the cadence line says `warming` instead of
printing a number, the pulse shows the individual gaps because a mean hides the
difference between a steady beat and a stall between bursts, and `monero tpl` is
labelled a template height — deciding that a sidechain block cleared Monero's
target needs a Monero PoW target this observer does not hold.

### What the live runs found

**A whole sidechain went dark, and the panel is how it was caught.** On the
second live run the main chain reported `DARK — 0 up / 0 sock / 0 known / 0
queued / 0 B sent` for four minutes while mini and nano were fine. That is a
real bug with three parts, all now fixed:

* both of main's DNS seeds failed inside `start()` in the first second of the
  run — and `fail()` only logged when the session had already left
  `State::Closed`, which a session that never connected never does, so the
  failure was **silent**. It logs now;
* the failed dial then took the full five-minute cool-off, the same as a peer
  that had talked and hung up. A dial that never reached a socket is a different
  fact and now earns a 15-second retry instead;
* with no peer connected there is no peer-list gossip, so the seeds were the
  only way back and the chain could not recover on its own. `reseed()` now
  clears the cool-off on the seed endpoints of a chain that has nothing, and the
  monitor reseeds a dark chain every 20 seconds.

Two display defects too, both invisible until three real chains were on screen:
the final snapshot was taken *after* the sockets were closed and so reported
`4 up / 0 sockets`, and the `net` line overflowed 100 columns once peer counts
reached three digits, truncating `bcast` mid-word. Both fixed; the golden frame
pins the layout that replaced them.

The first of those is the argument for the dashboard existing at all: `DARK` next
to `0 queued` said, on sight, that the chain had nothing left to dial — which is
a different failure from "peers are refusing us", and the two look identical in
a log.

CI **builds** the monitor and never runs it — it dials three public networks and
the fullscreen mode wants a tty — and it registers no ctest test either. What CI
runs is the render KAT, which is offline.

---

## Scope fence

Everything lives under `src/impl/xmr/p2pool/`. This tree observes a foreign
network. It is not part of the v37 share-chain record, it activates no
consensus, and it touches nothing under `src/sharechain/`.
