# Native-minimal Monero embedded node — Wave 0

This tree is the pool-scoped Monero node c2pool speaks the Monero P2P protocol
with directly, rather than linking monerod's libraries. monerod is not removed:
it stays as a bootstrap oracle, a fallback submit arm and a parity judge, and it
is demoted to optional only after the parity oracle has graduated the native
node against it.

**Scope fence.** Everything lives under `src/impl/xmr/`. This node is a WORK
SOURCE for the pool — it tells the template what to build on and it pushes a
found block — and it is **not** part of the v37 share-chain record. Nothing here
activates v37 consensus and nothing here touches `src/sharechain/v37`.

## What Wave 0 contains

| directory | what |
|---|---|
| `contracts/` | the pinned interfaces every later component builds against, header-only |
| `contracts/fakes/` | a compiling fake per interface, so wave-1 components can be written and tested before their dependencies exist |
| `consensus/` | the four shared primitives that would otherwise have been implemented three times |
| `test/` | the three Wave 0 KATs |

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

### test/

| target | what it proves |
|---|---|
| `xmr_native_contracts_kat` | every contract and fake compiles together; the fakes satisfy the interfaces; the pinned semantics hold; the hard-fork table and seed-epoch rules hold at their edges |
| `xmr_native_tx_weight_kat` | the weight golden over real stagenet transactions |
| `xmr_native_blob_reader_fuzz_kat` | reader unit rules plus a deterministic fuzz pass, over random input and over mutations of the real transaction corpus |

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

## Not in Wave 0

The components themselves: the levin P2P client, the chain-state index, the
relayed txpool, the template source, the block relay and the parity oracle. Each
is a later wave, authored against the fakes here.
