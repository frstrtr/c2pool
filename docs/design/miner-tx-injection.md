# Miner / user tx-injection over the c2pool sharechain p2p (post-cut, SV2-like)

Status: **M1 + M2 IMPLEMENTED (DASH, `--embedded-tx-inject`, default OFF); M3
staged.** M2 adds the `tx_inject` sharechain-p2p subtype (Legacy + Actual),
routing a peer's tx through the SAME `submit_inject` gate, first-see fan-out
(txid-deduped), a per-peer DoS guard, and the unknown-command-is-a-warning
wire-compat property. This is a **post-cut (Tier-3)** feature, not a `--coin-rpc` (dashd)
cut blocker. It is sequenced strictly **after** the daemonless block-template
self-derive close (#154) and the full-mempool serving canary (#132). Nothing
here touches the coinbase, the reward split, or the masternode-payee queue.

M1 (this PR) lands the runtime: the inject pool, the validation gate, the
priority class, the DoS caps, the local submit path, and — see §9/§10 below —
the isolated-signer SEAM and the design for sandboxed tx-blob construction. The
`tx-inject` p2p transport (§4.2) and its first-see fan-out (§4.5) are M2;
per-peer token buckets / capability advertisement (§4.6) and the full sandboxed
signer are M3. §11 is the exact per-milestone code map.

Scope: DASH first, but the transport (`tx-inject` p2p subtype) and the
validation gate are coin-agnostic and reuse existing core/ infrastructure.

---

## 1. Summary

Let a miner or a user hand c2pool a raw, consensus-valid transaction and have it
land in the block c2pool mines — transported over c2pool's **own** sharechain
p2p messaging layer, fanned out to every node, and included by whichever node
wins the block. Three categories of transaction are the target:

- **(a) runtime 0-fee txs** — a transaction paying no fee at all.
- **(b) node/miner-prioritized txs** — a transaction forced past the local
  fee-rate inclusion threshold regardless of its fee rate.
- **(c) non-standard txs** — a transaction the *public dashd mempool* refuses to
  relay by standardness policy, but which is fully consensus-valid.

This is the decentralized analog of Stratum V2 **job declaration** (the miner
declares the work / the transaction set it wants to mine). SV2 centralizes that
declaration at a Job Declarator server; c2pool declares it over the sharechain
p2p mesh instead, so no coordinator is introduced.

The single gate on an injection is **consensus-validity** (never build an
invalid block) plus the **existing tx-merkle-root reward-safety cross-check**
that already guards every served template. The coinbase and reward path are
untouched.

---

## 2. Motivation

### 2.1 Miner sovereignty — standardness is not consensus

dashd rejects non-standard and 0-fee transactions at the **mempool relay-policy**
layer (`AcceptToMemoryPool` standardness + min-relay-fee checks), **not** at the
consensus layer (`CheckBlock` / `ConnectBlock`). A block that contains a
consensus-valid non-standard or 0-fee transaction is a **fully valid block** —
dashd will accept it on receipt and build on it. Standardness exists to protect
the *public relay network* from resource abuse and to keep a predictable
mempool; it is a policy of nodes-relaying-to-each-other, not a rule of what a
block may contain.

A miner has always been free to include any consensus-valid transaction in the
block they find, fee or standardness notwithstanding — this is intrinsic to what
it means to be the party that assembles the block. Bitcoin Core and dashd both
expose exactly this via `prioritisetransaction` (force fee-rate priority) and
via direct block-template manipulation. c2pool mines the block, so c2pool's
miners hold that same sovereignty. Surfacing it is **not a rules bypass** — it
is giving the block's actual producers the inclusion control that centralized
pools reserve for themselves.

### 2.2 User-friendliness

Users occasionally need a transaction the public mempool will not carry:

- a 0-fee sweep or consolidation the user is willing to wait on;
- a CPFP/child that a policy-limit mempool drops;
- a data-carrying or multisig shape that trips a standardness flag but is
  perfectly valid in a block;
- a stuck transaction they want mined directly rather than re-broadcast.

Today the only escape hatch is to run your own miner or trust a centralized pool
to honor a manual request. c2pool can offer it as a first-class, opt-in,
decentralized submit path.

### 2.3 The SV2 analogy, decentralized

Stratum V2's Job Declaration Protocol lets a miner declare the transaction set
of the job it wants, decoupling block content from the pool operator. Its
weakness is that declaration still flows through a Job Declarator endpoint. The
c2pool sharechain is already a broadcast mesh with a working tx-advertisement
sublayer (`have_tx` / `losing_tx` / `remember_tx` / `forget_tx`, see
`src/core/tx_advertiser.hpp`). Adding an authenticated **tx-inject** submit
message reuses that mesh to achieve SV2-style job declaration with **no**
declarator, no operator, and no new trust root.

---

## 3. Non-goals

- **Not** a change to the coinbase, reward split, PPLNS accounting, donation
  output, or masternode-payee queue. Injected txs are ordinary block body txs;
  the coinbase is computed exactly as today.
- **Not** a relaxation of any **consensus** check. Injected txs are consensus-
  validated with the same rigor as any other template tx; an injection that
  would make the block invalid is rejected, full stop.
- **Not** a dashd-cut blocker. This rides on top of a completed daemonless cut
  (#154) and full serving (#132); it is not on the critical path to removing
  `--coin-rpc`.
- **Not** a public mempool. c2pool does not become a general-purpose relay; the
  inject path is opt-in, rate-limited, and scoped to the local pool's own block
  assembly, not to re-broadcasting for the network at large.
- **Not** a fee-market change. Injected txs occupy a separate priority class;
  they do not reorder or evict the fee-sorted body except by the explicit,
  bounded reservation described in §4.4.

---

## 4. Design

### 4.1 Where injection sits in the pipeline

c2pool already assembles the block body from its served/derived mempool view and
already runs a **tx-merkle-root cross-check** on the assembled template as a
reward-safety guard. Injection adds one bounded, opt-in stage between "candidate
body assembled" and "template frozen for mining":

```
served/derived mempool  ─┐
                         ├─> candidate body (fee-sorted)
inject pool (this doc)  ─┘        │
                                  ├─> [inject merge: priority class, §4.4]
                                  ├─> [consensus-validate whole body, §4.3]
                                  ├─> [tx-merkle-root reward-safety cross-check]
                                  └─> frozen template → mine → won-block broadcast
```

The inject pool is a small, capped, per-node set of accepted injected txs. It is
populated from two sources: a local operator/miner submit (RPC/CLI/HTTP), and
the p2p `tx-inject` message described next.

### 4.2 Transport: the `tx-inject` p2p message subtype

A new sharechain message subtype `tx-inject`, declared with the existing
`BEGIN_MESSAGE(tx_inject)` / `MESSAGE_FIELDS(...)` macro machinery in
`src/core/message_macro.hpp` and dispatched by the 12-byte-command
`MessageHandler` in `src/core/message.hpp` — i.e. exactly the mechanism that
carries `shares`, `have_tx`, and `remember_tx` today. It is not a new socket, a
new port, or a new protocol; it is one more command on the live mesh.

Wire-format sketch (fields, in pack order; VarInt = the codebase's existing
CompactSize):

| field            | type            | meaning                                                    |
|------------------|-----------------|------------------------------------------------------------|
| `version`        | VarInt          | inject-message schema version (start at 1)                 |
| `flags`          | uint32          | bit0 = zero-fee-intent, bit1 = non-standard-intent, bit2 = priority-request |
| `expiry_height`  | int32           | last coin-block height at which inclusion is still desired (drop after) |
| `tx_bytes`       | var-bytes       | the full raw serialized transaction                        |
| `submitter_hint` | var-bytes (opt) | optional pubkey/share-address for local rate-accounting; NOT a reward key |

Notes:

- `tx_bytes` is the raw tx exactly as it will appear in the block — c2pool never
  rewrites it, so `submitter_hint` cannot influence funds; it is only a local
  DoS-accounting label.
- No signature over the message is *required* for consensus (the tx carries its
  own scriptSigs); an optional detached submitter signature MAY be added later
  purely for rate-limit fairness (Open question §8).
- The message id for de-dup and gossip is `sha256d(tx_bytes)` = the txid,
  reusing the same known-tx keying that `have_tx`/`remember_tx` already use, so
  the eviction cache in `src/core/known_txs_eviction.hpp` covers it for free.

### 4.3 Validation gate — the *only* gate

On receipt (whether from local submit or a peer `tx-inject`), before an injected
tx is admitted to the inject pool, it must pass — in order, cheapest first:

1. **Size / structural sanity** — within `MAX_INJECT_TX_WEIGHT`; deserializes;
   txid not already in the inject pool or in the current body.
2. **Consensus validity in the context of the candidate template** — inputs
   exist and are unspent against the template's UTXO view (including any earlier
   injected parents), scripts verify, no double-spend against the fee-sorted
   body, respects all consensus rules c2pool already enforces when it validates
   a served template (BIP68/112/113, sigops, weight, DIP-specific rules). This
   is the **same** consensus path the daemonless serve/derive already runs; the
   inject gate calls it, it does not fork it.
3. **Whole-body re-validation after merge** — once merged into the priority
   class and the body is finalized, the assembled block body is validated as a
   unit and the **existing tx-merkle-root reward-safety cross-check** is run
   unchanged. If either fails, the injected tx (or the smallest offending
   subset) is dropped and the body reverts to its pre-inject fee-sorted form.

Standardness is deliberately **not** a gate here — that is the entire point of
category (c). Consensus-validity is necessary and sufficient for a tx to be
legal in a block, and the tx-merkle-root cross-check guarantees the served/mined
template still matches what the reward accounting expects.

### 4.4 Priority class (separate from fee-sorting)

Injected txs are not thrown into the fee comparator, where a 0-fee tx would sort
to the bottom and never be picked. Instead they form a **priority class** with a
bounded reservation:

- A configurable cap `INJECT_MAX_BLOCK_FRACTION` (e.g. default 1%–2% of block
  weight, operator-tunable, 0 = feature off) reserves space that injected txs
  may occupy *ahead of* the fee-sorted tail.
- Within the reservation, injected txs are ordered by (explicit priority-request
  flag, then submit time), never by fee. Dependencies (parent-before-child) are
  topologically respected.
- If injected txs do not fill the reservation, the space returns to the normal
  fee-sorted body — the reservation is a ceiling, not a floor, so a block is
  never padded or starved of paying txs beyond the cap.
- Because the coinbase's fee total is computed from the *actual* final body, a
  0-fee injected tx simply contributes 0 to fees; the reward math needs no
  special case and the tx-merkle cross-check still ties out.

### 4.5 Fan-out — reuse the won-block broadcast mesh

Two distinct propagation needs, both served by existing machinery:

1. **Pre-win fan-out of the injected tx** so *every* node's candidate body can
   include it (so it lands regardless of who wins). This reuses the sharechain
   gossip path that already forwards `remember_tx` / `have_tx` across the mesh —
   `tx-inject` is forwarded on first-see (keyed by txid, de-duped by the
   known-txs eviction cache) with a small hop/TTL and per-peer rate budget.
2. **Post-win block propagation** is unchanged: the won block reaches the network
   via `src/core/block_broadcast.hpp` (P2P relay PRIMARY, `submitblock` RPC
   FALLBACK). Injected txs are already inside the block body by then, so nothing
   new is needed on the win path — the injected tx rides the block out exactly
   like any other body tx.

This is the key reuse: **construct-and-broadcast-arbitrary-tx is already proven**
(see §6), and mesh tx-forwarding already exists; this feature is the thin
**submit + validate-gate + priority-merge** layer that ties them together.

### 4.6 Guards / DoS

- **Opt-in at every hop.** A node runs the inject acceptor only if the operator
  enables it (`--tx-inject-accept`), and advertises the capability so peers do
  not waste bandwidth sending `tx-inject` to a node that will drop it.
- **Size caps.** `MAX_INJECT_TX_WEIGHT`, `INJECT_POOL_MAX_ENTRIES`,
  `INJECT_MAX_BLOCK_FRACTION` all bounded and configurable.
- **Rate limiting.** Per-peer and per-`submitter_hint` token buckets; a peer
  that floods `tx-inject` is throttled and can be scored down on the existing
  peer-misbehavior path. Consensus-invalid injects are penalized harder
  (they cost a full validation), matching how bogus shares are treated.
- **De-dup / eviction.** Keyed by txid through the existing known-txs eviction
  cache; an inject already in a recent block or the current body is dropped.
- **Expiry.** `expiry_height` bounds how long a node keeps re-offering an
  inject; expired entries are evicted without further gossip.
- **No amplification.** `tx-inject` is forwarded on first-see only, with TTL, so
  it cannot loop the mesh. A node never re-derives or re-signs the tx; it
  forwards the bytes verbatim or drops them.
- **Reward isolation.** The acceptor has no write path to the coinbase, the
  reward split, or the payee queue — it can only add a consensus-valid body tx
  that survives the merkle-root cross-check, or fail closed.

---

## 5. Reward-safety analysis

The reward path is provably untouched:

1. **Coinbase unchanged.** Injected txs are ordinary body txs. The coinbase
   output set (subsidy + fees + masternode/donation splits) is computed from the
   *final* body's fee total. A 0-fee inject adds 0 fees; a fee-paying inject adds
   its fee — either way the coinbase is derived from the real body, as today.
2. **The tx-merkle-root cross-check is the backstop.** c2pool already cross-
   checks the assembled template's tx-merkle-root as a reward-safety guard
   (memory: tx-merkle mismatch is a fee-unknown / reward-safety signal). The
   inject stage runs *before* that check and the check runs **unchanged** on the
   final body. Any body the inject stage produces that would desync the reward
   accounting fails the cross-check and is reverted. Injection cannot ship a body
   the reward path has not blessed.
3. **No new trust root.** Unlike the near-tip anchor reseed question, injection
   introduces no new authority over MN lists, quorums, or credit-pool state. It
   only adds consensus-valid body txs. The masternode-payee derivation and every
   DIP-specific reward rule run on exactly the same inputs.
4. **Fail-closed.** Every failure mode (invalid tx, cross-check mismatch, over-
   cap) reverts to the pre-inject fee-sorted body, which is the status-quo
   block. The worst case of the feature is "no injection happened."

Conclusion: injection is a **reward-neutral** feature by construction. It can
change *which consensus-valid txs* are in the block; it cannot change *who gets
paid what*.

---

## 6. Proof-of-capability — the daemonless donation precedent

The hard part of this feature — construct, sign, and broadcast a bespoke,
non-trivial transaction with **no daemon in the loop** — is **already done and
proven on mainnet**.

At DASH block **2518186**, c2pool built, signed, and broadcast the annual
donation transaction fully daemonlessly:

- **0.90491416 DASH** aggregated from **1040 PPLNS dust inputs** into **one**
  transaction with **4 split outputs**, all confirmed on-chain.
- The tx was assembled, its inputs signed, and it was relayed by c2pool's own
  code path — not handed to a `dashd` wallet.

That established, in production, the exact primitives this feature depends on:
arbitrary-tx construction, signing, and daemonless broadcast onto the DASH
network. Miner/user tx-injection **does not** need to re-solve any of that. It
adds three well-scoped pieces on top of proven primitives:

1. a p2p **submit transport** (`tx-inject`, §4.2) — new,
2. a **validation gate** (§4.3) — a *call into* the existing consensus/serve
   validation, not new consensus code,
3. a **priority-merge + mesh fan-out** (§4.4–4.5) — reusing the existing
   tx-forward and won-block broadcast paths.

The risky capability is retired; what remains is transport-and-glue.

---

## 7. Milestones

- **M0 — this design + operator sign-off.** Confirm scope, caps, and that it is
  post-cut (after #154, #132). No code.
- **M1 — inject pool + local submit path.** A capped, in-memory inject pool and a
  local RPC/CLI/HTTP submit that runs the full validation gate (§4.3) and the
  priority-merge (§4.4). No p2p yet; single-node. Reward cross-check proven to
  still tie out with a 0-fee and a non-standard tx in the body (red-KAT).
- **M2 — `tx-inject` p2p subtype + first-see fan-out.** Declare the message,
  wire it into the handler table, forward on first-see with TTL and the known-tx
  eviction keying. Two-node soak: an inject submitted to node A lands in a block
  mined by node B.
- **M3 — guards + rate limiting + opt-in advertisement.** Token buckets,
  capability advertisement, misbehavior scoring, size caps hardened. Adversarial
  soak (flood, invalid-inject flood, oversize) shows bounded resource use.
- **M4 — mainnet opt-in canary.** One operator node enables `--tx-inject-accept`
  with a conservative `INJECT_MAX_BLOCK_FRACTION`; verify a real 0-fee /
  non-standard user tx is mined and the reward accounting is unaffected across a
  soak window.

Each code milestone ships as a PR with a red-KAT on the reward-safety cross-check
per repo convention for anything near the reward path.

---

## 8. Open questions

1. **Submitter authentication for fairness.** Do we require a detached submitter
   signature (or a small share-backed proof-of-work / stake) on `tx-inject` to
   make per-submitter rate-limiting Sybil-resistant, or is per-peer rate-limiting
   plus the consensus-cost penalty enough? (Consensus does not need it; fairness
   might.)
2. **Reservation policy.** Fixed `INJECT_MAX_BLOCK_FRACTION`, or a dynamic cap
   that scales with how full the fee-sorted body is (only reserve space when
   there is slack)? The latter avoids ever displacing a paying tx.
3. **Cross-coin scope.** Ship DASH-only first, or land the coin-agnostic
   transport in core/ immediately and gate per-coin acceptance? The transport is
   coin-agnostic; the validation gate calls per-coin consensus.
4. **Interaction with full-mempool serving (#132).** Once c2pool serves the full
   mempool, should injected txs be surfaced back into the served view (so they
   propagate to the public network too), or kept strictly block-local? Block-
   local is the safer default; surfacing them turns c2pool into a limited relay.
5. **Priority signaling to miners.** Should a miner's own stratum session be able
   to pin an inject to *its* work specifically (SV2-declaration-parity), versus
   the pool-wide fan-out default?
6. **Expiry vs. persistence.** Should injects survive a node restart (persisted
   inject pool) or be intentionally ephemeral? Ephemeral is simpler and limits
   liability; persistence is friendlier to a user who submitted and went away.

---

## 9. Embedded-daemon tx-blob construction + isolated signing modules

The proof-of-capability in §6 (the daemonless donation at block 2518186)
established that c2pool can construct, sign, and broadcast an arbitrary tx with
no daemon in the loop. tx-injection generalises that: a miner or user must be
able to build a raw, consensus-valid transaction — including the non-standard
and 0-fee shapes a public mempool refuses — and hand it to c2pool for inclusion.
This section specifies **where the signing happens** and the **module boundary**
that keeps private keys out of the injection runtime.

### 9.1 The runtime accepts an ALREADY-SIGNED blob (the SEAM)

The injection runtime — `Mempool::add_inject`, the inject pool, the p2p
`tx-inject` transport, the fan-out — operates **exclusively on fully-serialized,
already-signed transaction bytes**. It never sees a private key, never
constructs a scriptSig, and never re-serializes or mutates the tx: `tx_bytes` is
the exact bytes that will appear in the block, and `sha256d(tx_bytes)` is the
txid used for dedup/gossip. This is the **isolated-signer SEAM**:

```
   ┌─────────────────────────┐        signed raw tx bytes        ┌──────────────────────┐
   │  tx-blob construction +  │  ───────────────────────────────▶ │  injection runtime    │
   │  signing (isolated,      │      (opaque, never mutated)      │  (add_inject, pool,   │
   │  key-bearing)            │                                   │   p2p, fan-out)       │
   └─────────────────────────┘                                   └──────────────────────┘
        holds keys                                                    holds NO keys
```

Consequences of the seam:

- **The runtime is key-free.** A compromise of the injection path (a malicious
  peer flooding `tx-inject`, a bug in the pool) cannot reach signing material —
  there is none on that side of the seam.
- **The signer is swappable.** Any external tool that emits a signed raw tx —
  a dashd `createrawtransaction`+`signrawtransactionwithkey`, a hardware wallet,
  the c2wallet PIN-TX offline signer already used for the donation lane, or the
  sandboxed builder of §10 — satisfies the seam. The runtime is indifferent to
  which produced the bytes.
- **Validity is re-checked regardless of origin.** Because the runtime trusts no
  signer, every injected blob passes the SAME consensus gate as any mempool tx
  (script-verify, topology, double-spend, finality, sigops, maturity) at
  template build — a mis-signed or malicious blob is dropped, never served.

### 9.2 M1 seam implementation (this PR)

M1 wires the seam at two entry points, both taking already-signed bytes:

- **`--embedded-tx-inject-hex FILE`** — a local operator/miner submit: one raw
  signed tx hex per line (classic type-0, all-or-nothing at load, mirroring the
  proven `--pin-local-tx-hex` loader). Each line is deserialized and handed to
  `NodeCoinState::submit_inject`, which runs the gate and reports a named verdict.
- **`NodeCoinState::submit_inject(tx, flags, expiry_height)`** — the in-process
  API the file loader (M1) and the p2p handler (M2) both call. It takes a
  deserialized `MutableTransaction` whose scriptSigs are already populated; it
  never signs.

A minimal build/sign helper for producing the blob is intentionally **out of the
runtime**: for M1 the operator uses the existing offline path (c2wallet PIN-TX
procedure / dashd `signrawtransactionwithkey`) — the same tooling that signed the
2518186 donation — and drops the resulting hex into the file. This keeps PR-1
key-free while delivering an end-to-end submit path.

### 9.3 Reward isolation restated for the seam

The signer produces `tx_bytes`; the runtime places those bytes **only** into the
block body (tx-merkle / fee-total). Neither side writes the coinbase, subsidy,
PPLNS, donation, payee queue, or `give_author`. The `submitter_hint` (§4.2), when
it arrives on the wire in M2, is a **local DoS-accounting label only** — it is
never a reward key and never influences funds, because the runtime never
rewrites the tx to pay it.

## 10. Sandboxed tx-blob construction (staged to M3)

M1 ships the SEAM; the **full sandboxed signer** — a self-contained builder that
constructs and signs the blob inside an isolation boundary — is staged. Its
design:

- **A separate process / module** with the sole capability of turning a
  (inputs, outputs, keys) request into signed raw tx bytes. It links the
  consensus-exact script/sighash primitives already vendored for c2pool
  (`dash_scriptcheck.so` / the c2pool_dash_* legacy-sighash + secp256k1 path the
  M1 KATs sign against), so a blob it produces verifies under the very
  interpreter the runtime re-checks it with.
- **No network, no mempool, no sharechain access.** The sandbox cannot see peers
  or the pool; it emits bytes on a single pipe. This bounds the blast radius of a
  signing bug to the blob itself.
- **Immature-coinbase + maturity filtering at build** (the lesson from the PIN
  consolidation lane): the builder refuses to spend an immature coinbase input,
  so a blob never fails maturity at template build.
- **All-or-nothing, offline-first**: the builder is usable fully offline (the
  donation precedent), so a user can construct a 0-fee sweep / non-standard tx
  without exposing keys to any online component.

The sandbox is **not** required for the runtime to function — the seam (§9.1)
means any signer suffices — so it is correctly deferred without blocking M1.

## 11. Per-milestone code map (implementation reality)

| Milestone | Component | Where |
|-----------|-----------|-------|
| **M1 (this PR)** | inject pool (cap/expiry/dedup, DoS) | `src/impl/dash/coin/tx_inject_pool.hpp` |
| M1 | priority delta + gate + `add_inject` | `src/impl/dash/coin/mempool.hpp` (`INJECT_FEE_DELTA`, `InjectGate`, `add_inject`, `kMaxInjectTxBytes`) |
| M1 | intra-template double-spend guard (`consumed`) | `src/impl/dash/coin/mempool.hpp` `get_sorted_txs_with_fees` |
| M1 | submit gate + reconcile + node ownership | `src/impl/dash/coin/node_coin_state.hpp` (`submit_inject`, `set_tx_inject_enabled`, `m_inject_pool`) |
| M1 | flag + local submit (SEAM entry) + catalog | `src/c2pool/main_dash.cpp` (`--embedded-tx-inject`, `--embedded-tx-inject-hex`), `src/core/param_catalog.inc` |
| M1 | KATs (priority, reward-safety, double-spend, bad-script, missing-input, oversize, seam-unarmed, DoS, never-defaulted) | `test/test_dash_tx_inject.cpp` (in `test_dash_mempool`) |
| **M2 (implemented)** | `tx_inject` p2p subtype + handler wiring | `src/impl/dash/messages.hpp`, `node.hpp` handler tables (`ADD_HANDLER(tx_inject)` Legacy+Actual), `protocol_actual.cpp` / `protocol_legacy.cpp` |
| M2 (implemented) | relay policy (flag short-circuit, per-peer dedup + rate guard, node-level seen set, first-see fan-out) | `src/impl/dash/tx_inject_relay.hpp` (`ingest_peer_inject`), `src/impl/dash/peer.hpp` (`m_inject_guard`) |
| M2 (implemented) | submit sink seam (routes the peer path through the armed `NodeCoinState::submit_inject`) | `node.hpp` (`set_tx_inject_sink` / `handle_peer_tx_inject` / `relay_tx_inject`), `src/c2pool/main_dash.cpp` (wired next to the arm) |
| M2 (implemented) | first-see fan-out + `register_template_txs` ride | `relay_tx_inject` (fan-out); an accepted inject is an ordinary body tx, so it rides `register_template_txs` unchanged (KAT-proven) |
| M2 (staged) | continuous re-submission per tip | block-connect wiring of `reconcile_inject_pool` (lazy reconcile inside `submit_inject` suffices for M2) |
| **M3** | per-peer token buckets, misbehaviour score, capability advertisement | coin_peer_manager / handler |
| M3 | `submitter_hint` rate-accounting | inject pool |
| M3 | full sandboxed signer (§10) | new isolated build/sign module |

### Reward-safety proof obligation (every milestone)

`git diff master --stat -- src/impl/dash/coinbase_builder.hpp src/core/coinbase_builder.hpp src/impl/dash/coin/gentx_coinbase.hpp src/impl/dash/coin/subsidy.hpp src/impl/dash/pplns.hpp src/core/donation.hpp`
must be **empty**, and `grep -n "give_author\|donation\|payee\|m_payment_amount\|subsidy"` over the injection files must be **empty**. An injected tx enters ONLY the block body; the coinbase is `subsidy + Σ base-fees` exactly, and the priority delta is scoring-only (`total_fees` reads base `fee`).
