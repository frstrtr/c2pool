# What the second node needs to come up (technical section)

## Why the old invitation is wrong on substance, not just timing

The prior package said "build commit 2c9f2be0 and join." A fresh deployment today cannot
reach a served masternode set on the cold path. The embedded daemonless MN-set bridge
starts from the compiled-in anchor (height 2522504) and replays forward, cross-checking
each block's projected payee against the real coinbase. On an empty datadir it has no
persisted cursor and no local masternode-diff store, so it falls back to network
on-demand list probes with a small flat budget. Across the current anchor-to-tip window
that budget is exhausted before the replay completes, the bridge fails closed, and the
node never arms have_mn. This is a structural block at the current window size, not an
occasional failure. The running canary avoids it only because it holds a persisted cursor
that already sits past the divergence and a diff store that answers ban-state queries
locally at zero network cost.

## The serve-versus-peer question is resolved: the second node must serve

R5 governance completeness is already satisfied by ordinary network peers. The canary holds
gov_complete=1 with ten network governance peers, and the superblock serve-gate reuses the
same completeness predicate with no stricter peer floor and no requirement for our own
nodes. the second node is therefore not needed for R5 at all.

That narrows the second node to its D1 and D6 roles: providing hashrate, and cross-node PPLNS payout
with rebroadcast. Both require its node to build templates for its own miners, so have_mn is
genuinely required. The question is not whether it must serve but how to give it a working
serve, which the options below address.

## Options to make the second node reach have_mn (if serving is required)

### Option A: ship a ready post-divergence cursor plus diff store

Give the node a persisted bridge cursor that already sits past the divergence, together
with the masternode-diff store that answers ban-state queries locally, placed in its
datadir before first start, on the same binary the anchor belongs to (2522504, i.e.
2c9f2be0).

- Pro: no code change, no build gate, deliverable today. The node resumes past the
  divergence exactly as the canary does.
- Con: the cursor descends from a specific compiled anchor and is validated against the
  node's own header chain, so it must match the binary. The cursor is frozen at its
  publish height and the resume gap grows over time, so this is a point-in-time seed that
  ages. A later unplanned cold restart, if the diff store no longer covers the widened
  window, hits the same wall. Handing a multi-file state blob to an external operator is
  brittle: exact paths, version match, and integrity all have to be right, and the blob
  encodes this pool's state.
- External feasibility: moderate. It is a data blob plus precise placement instructions.
  Workable, but fragile and needs re-issuing as it ages.

### Option B: ship a fixed binary

Build c2pool-dash with the ban-state probe budget scaled to the replay window, or with the
compiled masternode-set anchor re-pinned closer to the tip (self-derived dump via
tools/dash/gen_mn_checkpoint.py), and give the second node that binary.

- Pro: fixes the root cause. A fresh cold start succeeds with no seed blob, and the fix
  also covers unplanned cold restarts on any node, including the canary. This is the
  durable, general answer.
- Con: requires a code change, a build, and review. A re-pinned anchor changes the trust
  root, so existing persisted cursors are discarded and replaced by a short cold replay
  from the fresher anchor. Deploying it to the canary is a binary change rather than a
  flag, which is a larger operation than arming. Gated on the fix landing.
- External feasibility: high once built. Hand over a single binary and standard flags,
  which is the cleanest package for an external operator. Blocked only on the fix landing.

### Option C: launch via the full replay-fold self-derive path

Run the node with the full replay-fold (the bulk genesis-to-tip fold), which folds every
block contiguously and derives ban and revive state directly from each block's ProUpServTx
and ProUpRevTx. It does not use the checkpoint bridge and is immune to the ban-state probe
budget entirely.

- Pro: architecturally correct self-derivation, with no seed blob and no anchor dependency
  for the payee set. Immune to the wall.
- Con: roughly 9 to 11 hours to fold genesis to tip, heavier resource use for bulk block
  fetch, and it needs the exact fold-builder invocation, which is still build-gated and
  unconfirmed on our side. Overkill if the second node only needs to provide hashrate or peer
  redundancy.
- External feasibility: low right now. We do not yet have a confirmed known-good fold
  launch to hand out. Not appropriate for an external operator until we run it ourselves.

## Recommendation

the second node must serve, so a working have_mn is genuinely required. Option A is the only package
deliverable today, as a point-in-time seed, with an explicit note that it ages and that
Option B is the durable fix. Option B is the right general answer and should be pursued in
parallel so the next node, and the canary itself, no longer depends on a hand-issued seed.
Option C is not externally deliverable until we have a confirmed fold launch of our own.
