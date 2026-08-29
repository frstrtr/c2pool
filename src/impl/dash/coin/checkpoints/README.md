<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# DASH masternode-set checkpoints — the daemonless trust anchor

**Short version: the files in this directory are data your c2pool release
*asserts* is true. A node that cold-starts from one is trusting the release
build. That is a deliberate trade, and this page is where the cost is
written down.**

---

## Why a trust anchor exists at all

To build a DASH block template, c2pool must know which masternode is next in
the DIP-3 payment queue. Getting that wrong produces a coinbase the network
rejects (`bad-cb-payee`) — a mined block thrown away.

Ranking the queue needs, per masternode, `scriptPayout` and
`nLastPaidHeight` (plus `registeredHeight` / PoSe heights as tiebreakers).

Those fields are not obtainable from the P2P network:

* the Simplified MN List (DIP-0004 `mnlistdiff`), which is the only
  masternode data the P2P protocol carries, **omits `scriptPayout` and
  `nLastPaidHeight` entirely**;
* neither field is committed in `merkleRootMNList`, so even if a peer
  volunteered them there would be no header commitment to check them against.

So there are exactly three ways to obtain a payout-bearing masternode set:

| source | trust | cost |
|---|---|---|
| dashd RPC `protx list registered true` | trust your own dashd | requires running dashd — the thing daemonless mode removes |
| replay every block from DIP-3 activation | **none** | ~1.5M block bodies downloaded and replayed |
| **pinned checkpoint + forward replay** | trust the release build for the set at one height | seconds to minutes |

This directory implements the third. The second remains available as a later
opt-in verify-mode; it is **not** built yet.

## What is trusted, and what is not

Verified locally, no trust required:

* **Chain position.** The checkpoint names a `blockhash`. It is rejected
  unless our own X11-PoW + DGW-validated header chain holds exactly that hash
  at exactly that height. An anchor minted on another chain or fork is
  refused.
* **Integrity.** A SHA-256 `digest` line commits every other line. A
  truncated, hand-edited, or half-merged checkpoint is refused.
  *This is an integrity check on the file, not a signature.* Anyone able to
  change the source can recompute the digest. It catches accidents, not
  malice.
* **Forward consistency.** Every block replayed from the anchor to the
  current tip re-derives the projected payee and compares it against that
  block's real coinbase. A wrong anchor desyncs within a few blocks and the
  bridge fails closed permanently — it never publishes, so a wrong anchor
  cannot reach a template.

Trusted, and not checkable by any means available to the node:

* **The membership and per-masternode payout state of the set at the
  anchor height.** Nothing on the DASH P2P network can prove it.

## The anchor is the REGISTERED set, not the valid set

An anchor is generated with `protx list registered true <height>`, which
includes PoSe-banned masternodes, each carrying its `poseBanHeight`. The
runtime derives eligibility (`MNState::isValid`) as `poseBanHeight == 0`, so a
banned masternode is **present but ineligible** — never absent.

This is load-bearing, not tidiness. `protx list valid` filters banned
masternodes out, and in a valid-filtered anchor "PoSe-banned at the anchor
height" and "does not exist" are the *same observation*: absence. The forward
replay has exactly one insertion path (`ProRegTx`), and a masternode that
registered years ago will never emit another one. So when the chain **revives**
such a masternode with a `ProUpServTx` inside the replay window, the bridge
finds no entry, drops the revive as an unknown masternode, and that masternode
can never re-enter the DIP-3 payment queue. Our queue head becomes permanently
the *next* entry — every later payee projection is one slot ahead of dashd's,
which is a served `bad-cb-payee`.

Measured on mainnet: proTx `7afbd798…` was PoSe-banned at height 2511957 and
revived by a `ProUpServTx` in block 2513357. It is absent from a `valid`-based
2513000 anchor. At height 2515416 dashd's payee queue head *is* `7afbd798…`,
and a valid-filtered anchor cannot contain it.

`count` therefore counts REGISTERED masternodes. The number comparable to
`protx list valid <height>` is the runtime's `eligible_size()`, which the
generator and `verify` both print alongside the count.

## Fail-closed behaviour

There is no degraded mode. If any of the following holds, the embedded arm
refuses to serve templates and logs at `ERROR`:

* the checkpoint is **unpinned** (a release built without an anchor);
* the payload fails to parse — bad magic, unknown key, wrong network, count
  mismatch, duplicate proTxHash or collateral, missing `scriptPayout`, any
  unparseable field;
* the **digest** does not match the contents;
* the **chain position** disagrees with our header chain;
* the anchor is **more than `--embedded-mn-bridge-max` blocks behind the
  tip** (default 20000, ≈34 days) — a stale anchor is refused rather than
  ground through;
* the forward replay hits a **gap** or a **payee desync**.

In every one of those cases templates keep routing to the dashd fallback arm
if one is configured, and to nothing at all if one is not. No masternode
payee is ever guessed.

## Pinning / re-pinning (release step)

**A stale anchor that nobody notices is the failure mode.** Re-pin as part of
cutting a release:

```sh
tools/dash/gen_mn_checkpoint.py pin --network mainnet \
    --rpc-url http://127.0.0.1:9998 --rpc-user USER --rpc-password PASS
```

`pin` prints a **WARNING** if the produced anchor carries zero PoSe-banned
masternodes: on mainnet that is the fingerprint of a `valid`-filtered capture,
and such an anchor can never reinstate a revived masternode.

This overwrites `dash_mn_checkpoint_mainnet.inc` in place and prints a
provenance block. **Paste that block into the release notes** — the anchor's
height, block hash, masternode count and digest belong where a user can read
them without building the source.

The generator:

* brackets `protx list valid true <height>` with `getblockcount` before and
  after and refetches if the tip moved, so the set is labelled with the exact
  height it is current at (a mislabelled height seeds the payment cursor
  wrong, which is a served `bad-cb-payee`);
* refuses to pin if `getblockchaininfo.chain` disagrees with `--network`;
* converts `payoutAddress` to `scriptPayout` once, at release time, where a
  bad address is a visible failure rather than a silent runtime degradation
  (this applies to PoSe-banned entries too — they need a payout script for the
  block after their revive);
* sorts by `proTxHash` so re-pin diffs are readable and two pins of the same
  set produce identical bytes.

To re-validate a checkpoint already in the tree (do this after any rebase
that touched one, and in the release checklist):

```sh
tools/dash/gen_mn_checkpoint.py verify \
    src/impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc
```

An offline capture works too, for pinning from a machine that cannot reach a
dashd:

```sh
dash-cli protx list registered true 2510000 > protx.json   # on the dashd box
tools/dash/gen_mn_checkpoint.py pin --network mainnet \
    --protx-json protx.json --height 2510000 --blockhash <hash of 2510000>
```

## File format

Authoritative specification: the header comment of
[`../mn_checkpoint.hpp`](../mn_checkpoint.hpp).

Summary — ASCII, LF-separated, `#` comments ignored:

```
c2pool-dash-mn-checkpoint/1
network   mainnet
height    2510000
blockhash <64 hex>
source    <provenance, free text>
generated <ISO-8601 UTC>
count     4123
digest    <64 hex>            # SHA-256 over every other non-comment line
mn <proTxHash> <collateralHash> <collateralIndex> <type> <version> \
   <registeredHeight> <lastPaidHeight> <poseRevivedHeight> <poseBanHeight> \
   <consecutivePayments> <revocationReason> <operatorReward> \
   <scriptPayout> <scriptOperatorPayout|-> <keyIDOwner|-> <keyIDVoting|-> \
   <pubKeyOperator|->
```

The `.inc` files are the same text wrapped as adjacent C++ string literals so
the anchor is compiled into the binary — a daemonless cold start must not
depend on a file the operator could lose, swap, or forget to install.

## Current state of this directory

| file | state |
|---|---|
| `dash_mn_checkpoint_mainnet.inc` | **PINNED** at height 2513000 — 2974 registered masternodes (2068 payee-eligible, 906 PoSe-banned) |
| `dash_mn_checkpoint_testnet.inc` | **UNPINNED** — no anchor; daemonless DASH testnet fails closed |

Pinning requires RPC access to a synced dashd on the corresponding network,
which is a release-time step, not a build-time one. Until then the mechanism
is present and refuses to serve, which is the intended safe default.

The mainnet anchor's 2068 payee-eligible records are byte-identical to the
previous `valid`-based pin at the same height; the re-pin is purely additive
(the 906 present-but-ineligible records) and does not move a single eligible
masternode's payout state.

The format, the parser, the bridge and the fail-closed paths are exercised
against **real captured testnet data** —
`test/dash_mn_checkpoint_testnet_1519543.inc` (produced by this directory's
generator from a real `protx list valid true 1519543`) replayed over the real
accepted blocks 1519544–1519546 — in `test/test_dash_mn_checkpoint.cpp`. That
fixture is a 6-masternode KAT subset and is **not** a shippable anchor.
