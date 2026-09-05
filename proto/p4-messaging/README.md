# V37 P4 — perishable-receipt messaging prototype

Deterministic reference core + golden harness for the V37 perishable-receipt /
TTL-messaging primitive (design: `docs/c2pool-v37-ttl-messaging.md`,
`c2pool-v37-miner-messages.md`, receipt primitive `c2pool-v37-work-receipts.md`).
Prototyping only — NO consensus code. Runnable code target = `frstrtr/c2pool`
`v37-dev` branch; prose/findings = `frstrtr/the`.

## Slice 1 — perishable-receipt admission core (GREEN)

`harness/perishable_receipt.py` — reference core: HMAC-derived signing identity
(miner-messages §3.2/A-1), per-epoch difficulty anchor, TTL freshness window,
signed anti-grief, ephemeral domain-scoped standing accumulator.

`harness/run_p4.py` — 12 invariants, deterministic (no RNG/clock; epoch = integer
L0 bin clock, keys/targets from fixed seeds). Golden digest pinned in
`golden/p4-slice1.sha256`.

    cd harness && python3 run_p4.py     # 12/12 PASS, sha256 61ea15ed…

Invariants:
- P4-1 perishable / current-difficulty: fresh admits; cheap PAST-epoch precompute
  and FUTURE-epoch receipts rejected.
- P4-2 TTL boundary: epoch − now == TTL fresh (inclusive); TTL+1 dead.
- P4-3 signed / anti-grief: forged sig ignored; cannot mint standing under a
  victim's signing_id.
- P4-4 standing: ephemeral (window-GC), domain-scoped, sybil-TAXED linearly
  (splitting standing S into N ids yields Σ = S, no superlinear gain).

Signatures are modelled as HMAC-SHA256 keyed bindings — carries the same
anti-forge / anti-grief invariant under test; the secp256k1/ed25519 curve leg is
proven separately (M4 t18 identity harness) and out of scope for freshness/standing.

## Slice 2 — TTL-as-decayed-work (GREEN)

`harness/perishable_ttl_work.py` — carriage right derived from the ROUNDABOUT LANE
decayed-weight accumulator: `ttl_shares = clamp(floor(decayed_weight/TTL_WORK_UNIT),
0, TTL_SHARES_MAX)`. Binds to the PINNED canonical decay-table base
(`refimpl/golden/decay_table_canonical_v1.json`) via `mrr_ref.Lane` — same base as the
settlement golden, not a slice-local table. REQUIRES-NOT-BURNS: `admit()` gates on
>= 1 ttl_share of live decayed work but consumes NOTHING; perishability is emergent
from decay (no explicit spend/burn op, so no double-spend ledger needed).

`harness/run_p4_slice2.py` — 9 invariants, deterministic. Golden digest pinned in
`golden/p4-slice2.sha256`.

    cd harness && python3 run_p4_slice2.py    # 9/9 PASS, sha256 8839b966…

Invariants: P4-5 exact clamp derivation; P4-6 requires-not-burns (accumulator
unchanged by admit); P4-7 decay-coupling (no new work ⇒ ttl_shares monotone
non-increasing across an epoch ⇒ perishes to 0); P4-8 threshold gate (dw<UNIT
rejected); P4-9 sybil-tax (floor is sub-additive ⇒ splitting work across ids cannot
gain shares); P4-10 determinism.

## Next slices (queued)
- Slice 3: share-carriage envelope (ENVELOPE_MINER 0x02, limits 3msg/220B/512B,
  invalid⇒message-ignored/share-stands) + cross-sharechain semantics (§7).
- GLM adversarial pass (precompute/backdate/cross-domain arbitrage) when the slot frees.
