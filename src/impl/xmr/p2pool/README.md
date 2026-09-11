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
| `p2pool_observer.hpp` | sessions and the poll loop |
| `tools/p2pool_observer_main.cpp` | the live harness |
| `test/p2pool_parse_kat.cpp` | the KAT, over two real captured frames |
| `test/gen_p2pool_golden.py` | independent Python reading that generates the golden's expected values |

Everything is header-only STL over two things the repository already has:
`xmr_coin` (the vendored Monero keccak and tree hash) and the native lane's
consensus headers.

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

## Scope fence

Everything lives under `src/impl/xmr/p2pool/`. This tree observes a foreign
network. It is not part of the v37 share-chain record, it activates no
consensus, and it touches nothing under `src/sharechain/`.
