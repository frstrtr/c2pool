# DASH Coordinated v36-Universal Migration Plan

Owner: dash-consensus-pay-replay (DASH lane)
Oracle baseline: frstrtr/p2pool-dash @9a0a609 — share VERSION=16 / VOTING=16.
Transition: **16 -> 36** (NOT 35->36; DASH is older-than-v35).
Status: staged, executes only AFTER block-viable gate (below) is satisfied.

## Why DASH is coordinated, not ratcheted

DGB/BTC/LTC run a **slow 1-by-1 RATCHET** (dual v35+v36 pool, organic miner
opt-in, 5 acceptance checks) because their pools carry unknown third-party
miners whose upgrade cadence cannot be scheduled. The DASH friendly-p2pool
node set is **enumerable and operator-coordinated**, so DASH can run a short
dual-stack window followed by a **coordinated cutover** — a scheduled flag
moment, not an open-ended adoption ratchet. This is the "WITHOUT a slow
ratchet" directive (operator 2026-06-18).

## Block-viable gate (HARD precondition — do not start migration until ALL true)

1. PR #465 broadcaster_full keystone MERGED — won-block dual-arm relay
   (embedded P2P fan-out AND dashd `submitblock` fallback) on master.
2. PR #438 G3a POPULATED regtest block proven (diverse tx types, not
   coinbase-only) via the c2pool-dash submitblock arm.
3. dashd RPC fallback retained on EVERY node — never removed.

## Isolation invariant (3-bucket rule — preserved through migration)

- Bucket 1 (ISOLATION PRIMITIVE): per-coin/per-instance PREFIX + IDENTIFIER
  stay distinct. The migration NEVER touches the DASH sharechain/peer
  namespace. v37 unifies code, not namespaces.
- Bucket 2 (v36-NATIVE SHARED): donation P2SH (FLAG6 1-of-2), share-version
  semantics — already standardized toward the v37 shape; carried as-is.
- Bucket 3 (PRE-V36 COMPAT): the v16 accept-floor + old donation script are
  kept TEMPORARY for the dual-stack window, dropped at cutover+grace.

## Sequence

### Phase M0 — Enumerate + pin (T-0)
- Roster every friendly DASH p2pool node + operator contact.
- Pin each node's current build SHA and confirm dashd RPC reachable.
- Publish target master SHA (= the merge SHA carrying #465 + #438).

### Phase M1 — Dual-stack window (T0 .. T0+72h)
- Each node runs v36-capable c2pool-dash that ACCEPTS both v16 and v36
  shares (accept-floor = v16; mint-gate weighting = work-weighted 60%,
  oracle-conform per the AutoRatchet mint-gate verdict).
- Won blocks relay via BOTH arms (embedded P2P + dashd submitblock).
- No node yet MINTS v36; the window only proves cross-version share
  acceptance + block relay on the real friendly net.

### Phase M2 — Coordinated cutover (scheduled T1)
- At the agreed flag moment all friendly nodes flip mint-version to v36
  simultaneously (coordinated, not ratcheted). Accept-floor stays v16 for
  the grace window so any straggler share is still counted, not orphaned.

### Phase M3 — Grace + compat drop (T1+grace)
- After a clean grace window with zero v16 mints observed, raise the
  accept-floor to v36 and drop the Bucket-3 v16 compat (donation script,
  old accept-floor). Bucket-1 PREFIX/IDENTIFIER untouched.

## 5 acceptance checks (gate each phase boundary; mirror of DGB G2 ratchet)

1. **Cross-version accept** — a v16 share and a v36 share from peers are
   both accepted and weighted correctly (no orphan, no double-count).
2. **Mint-gate weighting** — version-transition gate fires at work-weighted
   60% successor threshold, exact-rational (PROVEN conformant 06-24).
3. **Won-block reaches network** — a minted block is confirmed accepted by
   dashd via BOTH the embedded P2P arm and the submitblock fallback arm.
4. **Payout parity** — PPLNS payout (incl. nonzero sub-dust, drop only
   exactly-zero) byte-matches the oracle (dust-conform #154, merged).
5. **Namespace isolation** — DASH PREFIX/IDENTIFIER unchanged across the
   cutover; no cross-coin/instance share leakage.

## Rollback

Any phase failing a check: revert the node's mint-version to v16 (accept
-floor never moved past v16 until M3, so rollback is loss-free). dashd RPC
fallback guarantees block submission survives an embedded-P2P regression.

## Open coordination items (for operator/decisions@)

- Confirm friendly-node roster + cutover flag time (M0/M2 are operator-owned).
- Confirm grace-window length before Bucket-3 compat drop (M3).
