# M5 ABLA live full-block feed — VM300 read-only proof (2026-06-20)

Closes the in-flight M5 leg: embedded BCHN daemon / full-block layer feeding
`AblaTracker::record_block_size` from VM300 `bchn-bch` (192.168.86.110:8333,
read-only). Proves the production path `full_block -> AblaBlockFeed ->
AblaTracker -> template builder` advances the ABLA cursor on REAL mainnet data,
not merely the cold-start anchor.

## Harness
    c2pool-bch --ibd --near-tip --auto-kick --peer 192.168.86.110:8333 --max-seconds 90

Binary built off origin/master @67f89af9e. Peer = Bitcoin Cash Node 29.0.0
(EB32.0), mainnet start_height=956052.

## Result (PASS)
- handshake up; AUTO getheaders self-started from 956052 (no manual kick; #240)
- headers synced 955700 (cold-start anchor) -> 956052 (peer tip), advanced=yes
- full-block download: in_flight 16 -> 0, false_evict=0, reissue=0 (clean)
- ABLA cursor advanced via the live feed:
    t=5s  abla_cursor=955840
    t=10s abla_cursor=956020
    t=15s abla_cursor=956052  (== peer tip)
  abla_budget held at 32000000 (32 MB floor — near-tip blocks below ABLA
  raise threshold; never-undercut invariant holds).

## Conformance / isolation
p2pool-merged-v36 surface: NONE (ABLA + SPV header state carry no share /
coinbase / PPLNS bytes). src/impl/bch/ only; VM300 strictly read-only.
