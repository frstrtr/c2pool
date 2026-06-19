# BCH M5 — live sync-to-tip soak evidence (VM300 bchn-bch, read-only)

Pins the LIVE on-wire IBD behavior of the PR #208 HeaderChain back-off locator
side-by-side with the deterministic predictions in `header_sync_progress_test.cpp`
(inv. 6/7/8). The simulation proves convergence + false_evict==0 + bounded
reissue abstractly; this is the same property observed on the live wire.

## Harness
- Binary: `c2pool-bch --ibd --near-tip --peer 192.168.86.110:8333 --max-seconds N`
- Peer: VM300 `bchn-bch` (.110:8333), mainnet, READ-ONLY (P2P header/block pull
  only; no qm/control op, no RPC — start_ibd_near_tip skips init_rpc()).
- Mode: --near-tip seeds the header origin at the operator-approved BCHN anchor
  {height=955700} so the sync covers anchor -> peer tip and the ABLA feed folds
  REAL serialized block sizes within one harness window.
- Continuation locator: HeaderChain back-off (bind_locator_provider ->
  m_chain.get_locator()), i.e. the PR #208 fix under live load.

## Run — post-merge binary @ master bcfd21c7 (2026-06-19)
```
[ibd] init checkpoint=955700, deadline=50s
[ibd] handshake up; getheaders kicked from height 955700
[ibd] t=5s  synced=955700 peer_tip=955992 in_flight=0  reissue=0 false_evict=0 abla_cursor=955700 abla_budget=32000000
[ibd] t=10s synced=955992 peer_tip=955992 in_flight=16 reissue=0 false_evict=0 abla_cursor=955839 abla_budget=32000000
[ibd] t=15s synced=955992 peer_tip=955992 in_flight=0  reissue=0 false_evict=0 abla_cursor=955992 abla_budget=32000000
[ibd] SYNCED — final synced=955992 (init checkpoint=955700, advanced=yes) false_evict=0 reissue=0 abla_cursor=955992 abla_budget=32000000
```
Reproduced identically on the pre-merge bch/m5-ibd-robust-locator binary (08:05).

## Live numbers vs simulation predictions
| property            | sim (inv.6, header_sync_progress_test) | LIVE vs VM300 |
|---------------------|----------------------------------------|---------------|
| converged to tip    | yes (synced == peer_tip)               | yes (955992)  |
| false_evict (redundant re-walk) | 0 (anchored at exact ancestor) | 0     |
| reissue (ContinueSync getheaders) | bounded = gap/CAP        | 0 (gap 292 < one batch) |
| stall               | no (inv.7 stalls ONLY w/o provider)    | no            |

Live cursor advanced 955700 -> 955992 (+292). ABLA cursor tracked the same span
(955700 -> 955839 -> 955992) as full block bodies backfilled through the bounded
download window — full_block -> AblaBlockFeed -> AblaTracker live on real network
data. Budget held at the 32MB floor (live tip below the ABLA growth threshold,
as designed; growth path separately proven in abla_growth_soak_test).

## Scope
src/impl/bch/test only. impl_bch unregistered for this doc (evidence artifact).
p2pool-merged-v36 surface: NONE (local SPV header state + ABLA budget only).
VM300 untouched beyond a read-only P2P peer session.
