# Native-minimal Monero embedded node — Waves 0 and 1

This tree is the pool-scoped Monero node c2pool speaks the Monero P2P protocol
with directly, rather than linking monerod's libraries. monerod is not removed:
it stays as a bootstrap oracle, a fallback submit arm and a parity judge, and it
is demoted to optional only after the parity oracle has graduated the native
node against it.

**Scope fence.** Everything lives under `src/impl/xmr/`. This node is a WORK
SOURCE for the pool — it tells the template what to build on and it pushes a
found block — and it is **not** part of the v37 share-chain record. Nothing here
activates v37 consensus and nothing here touches `src/sharechain/v37`.

## What is here

| directory | what |
|---|---|
| `contracts/` | the pinned interfaces every later component builds against, header-only (Wave 0) |
| `contracts/fakes/` | a compiling fake per interface, so wave-1 components can be written and tested before their dependencies exist (Wave 0) |
| `consensus/` | the shared primitives, plus the C2a consensus rules: block parse and identity, weights, reward, difficulty, timestamps, hard-fork policy |
| `chain/` | Wave 1 / C2a: the consensus state, the wire-to-state evaluation seam, and the real `IChainView` |
| `test/` | the KATs |

### contracts/

| file | surfaces |
|---|---|
| `types.hpp` | `PeerRef`, `TxBlobEntry`, `BlockEntry`, `ChainEntry`, `PeerSyncData`, `PeerFault`, `TemplateInputs`, `BlockTxEvent`, `SyncState`, the 128-bit helpers |
| `chain_index.hpp` | `IChainIndexInbound` (wire → index), `IChainView` (index → consumers) |
| `fetcher.hpp` | `IChainFetcher` (index → wire), and the ≤100-id request cap |
| `serving.hpp` | `IChainServing`, the io-thread read side that keeps peers from dropping us |
| `anchor.hpp` | `AnchorBundle`, the exact window sizes, `AnchorStatus` + `anchor_self_check`, and the pinned `load_anchor` signature |
| `txpool.hpp` | `AdmissionEvidence`, `TxpoolSelectPolicy`, `TxRelayVerdict`, `IRelayedTxSink`, `ITxpoolSnapshot`, `ITxSource`, `ITxBlobSource` |
| `broadcast.hpp` | `IBroadcastPort` |
| `miner_data.hpp` | `IMinerDataSource`, `MinerDataReadiness`, `MinerDataEpoch` — the one seam the template provider is rebound through |
| `relay.hpp` | `ArmOrder`, `RelayPolicy`, `BlockRelayRequest`, `BlockRelayVerdict`, `IBlockRelay` |
| `parity.hpp` | `ParitySample`, `GraduationState`, `ParityCoverage`, `IParityOracle` |

The family is header-only, STL plus the existing lane value types from
`src/impl/xmr/node/xmr_node_types.hpp`, and free of transport, crypto and
threading dependencies. That is what makes it a collision fence for the parallel
implementation waves. Changing a signature here after Wave 0 is a
contract-amendment commit touching only `contracts/` and the affected fakes.

Seven things are worth calling out because they were changed during review, and
each of them was a real defect rather than a preference:

* **`TxRelayVerdict` and `BlockRelayVerdict`.** Both used to be called
  `RelayVerdict`. They are unrelated shapes with unrelated consumers, and
  sharing the name made the transaction-relay and block-relay headers
  unincludable in one translation unit.
* **`AdmissionEvidence` is a bitmask, not a tier.** The four kinds of evidence a
  pool can have about a relayed transaction — structural, our own fee-policy
  replica, non-input consensus, and an armed daemon having accepted it — are
  orthogonal. A scalar ladder could not express "daemon-confirmed, fee replica
  has not run", which is the ordinary state of every transaction while a daemon
  is armed.
* **Hints are named as hints.** `ChainEntry::cumulative_difficulty_hint`,
  `ChainEntry::weights_claimed_hint` and `BlockEntry::block_weight_claimed_hint`
  are the peer's claims. They are recomputed and never trusted; the names say so
  at every call site.
* **`BlockTxEvent::tx_blobs` is best effort.** On a rollback the index returns
  what bodies it still has, which under pruned sync may be none, so the event
  carries `tx_blobs_complete` and the txpool must treat a missing body as gone.
* **`TxpoolSelectPolicy` replaces the deleted tier.** Making evidence a bitmask
  removed the `tier >= min_tier` term from the plan's `selectable_backlog()`
  predicate and left nothing in its place, so the pool that implements the
  filter and the assembler that consumes it would each have invented one. The
  policy is now a pinned struct, with an explicit-policy overload — comparing
  two arms is only meaningful when both selected under the same rule.
* **`IParityOracle` carries the artefact, not a tag.** `on_serve` takes the
  `node::MinerData` that was actually served alongside its epoch, and `on_submit`
  takes the whole `BlockRelayVerdict`. With only an epoch the oracle has to
  re-pull from the served arm, which differs whenever the backlog moved in
  between, and `ServedMismatch` — the one verdict that catches us serving
  something neither arm would produce — becomes unprovable. Without
  `daemon_armed` a daemon *rejecting* our block is indistinguishable from there
  being no daemon arm, which is a void sample rather than a failure.
* **`AnchorBundle` is pinned in Wave 0.** The wave-1 table hands the anchor
  generator to one workflow and anchor boot to another. It is the node's trust
  root, so two independently invented layouts would not merely fail to compile —
  they would disagree about what is trusted.

There is one namespace root, `c2pool::xmr::native`, with aliases to the two
neighbouring roots (`node::` for the existing lane value types, `submit::` for
the live-submit surface). Nothing here re-opens either.

### consensus/

| file | what, and why it is Wave 0 rather than any one component's |
|---|---|
| `xmr_blob_reader.hpp` | the bounds-checked read counterpart to `xmr_blob.hpp`'s `BlobWriter`. Nothing on master could read a CryptoNote blob back; three wave-1 components each needed one. Poisoning reader, monerod-exact varint rules, depth cap of 8, counted containers refused against the bytes actually present. |
| `xmr_tx_weight.hpp` | consensus transaction weight, from a full blob **and** from a pruned one. The pruned path matters because chain sync is pruned by pinned decision D-4: the node never sees the prunable bytes and must reconstruct their length from structure. This is the most consensus-fatal function in the node. |
| `xmr_hf_table.hpp` | the vendored hard-fork table, the version-dependent rules, and the CARROT / FCMP++ fence that reports anything above v16 rather than guessing at it. Two of the rules are **bands, not scalars**: Monero allows a new ring size or proof system at one fork and only requires it at the next, so `hf_ring_size_allowed()` and `hf_rct_type_allowed()` are the admission tests and the scalars say only what a freshly built transaction should use. Every threshold cites the `cryptonote_config.h` constant behind it and is pinned in the KAT against what a synced stagenet daemon actually reports over each activation band. |
| `xmr_epoch.hpp` | the RandomX seed epoch, re-exported from `coin/xmr_seedheight.hpp` (which is the single source of the 2048/64 constants) plus the seed-pair scheduling rule. |

### p2p/ — Wave 1, component C1a: the levin codec

Pure codec for the Monero P2P wire. No socket, no thread, no connection state:
the transport (C1b) and the peer pool (C1c) are separate components that build
on these three headers.

| file | what |
|---|---|
| `levin_codec.hpp` | the 33-byte levin bucket header, the command ids, the frame classification rules, and the inbound per-command size caps (R-CAPS) |
| `epee_storage.hpp` | the epee portable-storage encoder and a bounded decoder: the size-mark varint, the type tags, sections and arrays |
| `levin_messages.hpp` | the typed messages — 1001/1002/1003/1007 and 2001–2010 — decoding into the W0 contract types (`BlockEntry`, `ChainEntry`, `TxBlobEntry`, `PeerSyncData`) so C2 and C3 need no second conversion |

Five things about the epee format were read out of monerod's source rather than
inferred, and each is a place an independently written codec would have been
wrong on the wire:

* **Sections are emitted in sorted key order.** `epee::serialization::section`
  holds a `std::map<std::string, storage_entry>`, so monerod writes entries
  lexicographically, not in the order the KV map declares them. An encoder that
  preserved declaration order would produce frames a daemon still parses — and
  would never be byte-identical to a capture, which is exactly what the C6
  parity rig exists to compare.
* **`KV_SERIALIZE_OPT` omits the field at its default.** `rpc_port` at zero,
  `pruned` at false, `dandelionpp_fluff` at true and `prune` at false are simply
  absent from the frame. The omission is the format, not an optimisation.
* **Empty containers are not written at all**, and the loader's failure to find
  one is discarded (`KV_SERIALIZE` ignores its return value), so an absent
  container means empty at both ends rather than a parse error at either.
* **`cumulative_difficulty_top64` is unconditional on store.** monerod branches
  on `is_store` and only makes the field optional when loading, so a frame that
  omits it was written by neither monerod nor us.
* **The size-mark varint is not the CryptoNote LEB128 varint** used inside block
  and transaction blobs. Two varints, two codecs; the other one lives in
  `consensus/xmr_blob_reader.hpp` and the two are never mixed.

The decoder mirrors epee's bounds exactly — array counts refused against the
bytes actually remaining, duplicate keys rejected, a bool byte above 1 rejected
— and then tightens them: recursion depth 8 instead of 100, plus hard ceilings
on entries, objects, strings and array elements. Where epee truncates an integer
that does not fit the requested width, this decoder refuses it: an honest peer
writes the declared width, so the only sender that trips it is one trying to
make our number differ from the one it sent.

What is NOT proven here is byte parity against a real captured monerod frame.
That is hardest-unknown U5, it needs a daemon, and it belongs to the C6 parity
rig. The goldens below are derived from the serialization rules instead, which
checks the encoder rather than photographing it.

### test/

| target | what it proves |
|---|---|
| `xmr_native_contracts_kat` | every contract and fake compiles together; the fakes satisfy the interfaces; the pinned semantics hold; the hard-fork table and seed-epoch rules hold at their edges |
| `xmr_native_tx_weight_kat` | the weight golden over real stagenet transactions |
| `xmr_native_blob_reader_fuzz_kat` | reader unit rules plus a deterministic fuzz pass, over random input and over mutations of the real transaction corpus |
| `xmr_levin_codec_kat` | the bucket header byte layout, the frame classification table (including the noise and fragment cases), and the cap table |
| `xmr_epee_storage_kat` | the varint at every size-mark boundary, the type-tag matrix, sorted key order, and every decoder bound |
| `xmr_levin_messages_kat` | goldens for the handshake, the chain request and the address encoding, plus a round trip of every message and both shapes of `block_complete_entry` |
| `xmr_levin_fuzz_kat` | the bounded deterministic fuzz pass; `--dump-corpus <dir>` exports the seeds for an external libFuzzer run |
| `xmr_native_block_id_kat` | block identity against monerod over whole captured blocks, with the negative controls (flipped bytes, truncation, trailing bytes, the length prefix) |
| `xmr_native_consensus_state_kat` | 600 stagenet heights replayed through the windows — difficulty, long-term weight, reward, emission — plus rollback exactness, `connect()` on real blobs, the R-HFFUSE policy and the 128-bit arithmetic against boost |

The fuzz KAT's load-bearing assertion is that **canonical re-encoding is
idempotent**: any buffer that decodes must re-encode and re-decode to the same
value tree, and the second encoding must be a fixed point. That makes the
encoder and the decoder each other's oracle, and it is what catches a sort-order
or size-mark bug that a round trip through our own encoder alone would hide.

## The tx-weight golden

`test/xmr_tx_weight_golden.hpp` is generated from a live stagenet daemon
(`test/gen_tx_weight_golden.py` regenerates it). It carries the transactions of
177 real blocks: 249 non-coinbase transactions across CLSAG and bulletproof-plus
shapes, ring sizes 11 and 16, one to forty-two inputs, one to six outputs, plus
each block's coinbase.

The one number in that file this repository does not compute is
`GoldenBlock::block_weight`, which comes from the daemon's own block header.
Since a block's weight is its coinbase weight plus the weight of every
transaction in it, that single number pins the per-transaction weights — exactly,
for the blocks carrying a single transaction, and as a sum for the rest. Without
it the golden would only prove that the code agrees with itself.

## Wave 1 / C2a — the consensus state

C2a is the arithmetic of following the Monero chain: what a block weighs, what
it pays, what difficulty it had to meet, what its id is, and what the five
windows look like afterwards. It is deliberately NOT the index — no fork choice,
no alt branches, no peers, no storage, which are C2c's — and that line is what
makes every rule in it testable against monerod without a network.

### consensus/ (C2a additions)

| file | what |
|---|---|
| `xmr_block_parse.hpp` | the block blob parser. Slices the header rather than re-serializing it (a re-serializer that drifted by one byte would silently change every block id), parses the coinbase through the Wave 0 transaction parser, and re-reads the two coinbase fields that parser discards: the txin_gen height and the output sum. |
| `xmr_block_id.hpp` | coinbase hash, transaction tree root, hashing blob and block id, over the keccak and tree-hash already in `xmr_coin`. The id is keccak of the **length-prefixed** hashing blob; the PoW input is the bare one. |
| `xmr_median.hpp` | monerod's median, `get_mid` included, and a rolling window that answers a 100 000-entry median in O(distinct) and rolls **backwards** exactly — which the reorg path needs and monerod's own median heap cannot do. |
| `xmr_weight.hpp` | block weight from (possibly pruned) bodies, the long-term weight recursion including the HF15 2021-scaling floor of `ltemw * 10 / 17`, the two medians and the effective median that sets the penalty knee. |
| `xmr_reward.hpp` | the emission curve, the tail, the weight penalty in 128-bit arithmetic (both the `__int128` and the 32-bit-limb spellings, cross-checked), already-generated-coins with monerod's saturation, and the coinbase-amount rule including the v2..v12 partial-claim path that changes what the emission grows by. |
| `xmr_difficulty.hpp` | the R-U128 adapter over the vendored `difficulty.cpp`, plus the 735-row window. The window is 735 and not 720 because `next_difficulty` drops the newest 15 rows itself; the KAT pins that against 600 heights and shows 720 and 721 reproducing none of them. |
| `xmr_timestamp.hpp` | the 60-block timestamp median, the future-time limit (local, soft) and the below-median rule (consensus, hard). |
| `xmr_hf_policy.hpp` | **R-HFFUSE**, the unknown-fork ruling Wave 0 left open. |

### R-HFFUSE: code-rolling, not fail-closed

The plan's original R-HF was: meet a fork we do not implement, halt the native
path, fall back to an armed daemon. That is safe and useless — it turns every
Monero hard fork into a total outage on a schedule we do not control, and it
pays for the safety of the arm that needed it (block PRODUCTION) with the arm
that needed none (chain FOLLOWING).

The ruling splits them. At a fork above `MAX_IMPLEMENTED_HF_VERSION` the node
KEEPS FOLLOWING, with rule lookups rolled forward to the newest version it
implements, and a latching fuse withdraws exactly the two capabilities that can
emit something the network judges:

| capability | known fork | rolled fork |
|---|---|---|
| follow the chain | yes | yes (fail-open) |
| serve / relay blocks | yes | yes |
| admit transactions | yes | **no** (fail-closed) |
| build a template | yes | **no** (fail-closed) |

A version BELOW what the table requires at a height stays a hard reject: that is
not an unknown fork, it is a block from a fork the network already left.
`top_version` follows the CHAIN at a rolled fork rather than advertising a stale
version, because a stale advertisement is what actually gets a node dropped.

### chain/

| file | what |
|---|---|
| `xmr_consensus_state.hpp` | the five windows, `connect()` (version, timestamp, weight, reward, coinbase, emission, difficulty) and an exactly reversible `disconnect()`. Every connect returns an undo record carrying what fell out of each window, so a reorg is a rollback rather than a re-derivation. |
| `xmr_block_eval.hpp` | the wire-to-state seam: parse, identify, then **authenticate every transaction body against the id the block commits to** before its weight is allowed to touch a median. This is what makes pruned sync safe. |
| `xmr_chain_view.hpp` | `ChainStateView`, the real `IChainView`: tip, template inputs, lookups by id and height, confirmation depth, seed anchors across epoch boundaries, the event streams, own-block submission. |

### The C2a golden

`test/xmr_c2a_golden.hpp` (regenerate with `test/gen_c2a_golden.py`) carries 600
consecutive stagenet heights with the numbers monerod computed for them —
difficulty, long-term weight, reward — the 100 000-entry long-term weight window
that precedes them, ten whole block blobs with the daemon's ids, and
already-generated-coins from `get_coinbase_tx_sum` at both ends of the run.
Nothing in that file is computed by this repository, which is what lets the
replay fail rather than agree with itself.

It earned that on the first run: every window value matched and all ten block
ids were wrong, because the id is keccak over the **length-prefixed** hashing
blob and the first cut hashed the bare one.

## Not here yet

The rest of the components: the levin P2P client (C1), the anchor loader and
RandomX verify (C2b), the index and fork choice (C2c), the relayed txpool (C3),
the template source (C4), the block relay (C5) and the parity oracle (C6). Each
is authored against the contracts here.
