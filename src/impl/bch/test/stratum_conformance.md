# BCH stratum conformance vs p2poolBCH @6603b79 (M5 sweep — final leg)

Verdict: CONFORMANT. Zero code change required; zero p2pool-v36 surface.

## Architecture
The stratum server is coin-AGNOSTIC and lives in `src/core/stratum_server.{hpp,cpp}`
+ `src/core/stratum_work_source.hpp`. Per-coin modules contribute ONLY
`rpc::WorkData` (`src/impl/bch/coin/rpc_data.hpp`) via `getwork()`
(`src/impl/bch/coin/template_builder.hpp`). The notify wire-shape is therefore
fixed by core, identical across btc/bch/ltc/dgb/dash.

## Field-mapping parity (BCH getwork m_data  ->  p2poolBCH data.py / stratum.py)
  version           -> work['version']                  (BCH: floor 4, no BIP9 vbits)
  previousblockhash -> int(work['previousblockhash'],16) -> notify prevhash via _swap4
  bits              -> FloatingInteger(work['bits'][::-1]) (8-char lowercase hex, bchn GBT)
  curtime           -> work['curtime'] (==time)          -> notify ntime BE-hex
  coinbasevalue     -> work['coinbasevalue']  (subsidy)
  transactions      -> unpacked_transactions / txhashes  (CTOR-sorted, CashTokens transparent)
  coinbaseflags     -> work['coinbaseflags']  (empty; coinbase commitment built M3 s19)

## Notify params (core stratum, == p2poolBCH stratum.py _send_work):
  [jobid, prevhash(swap4), coinb1, coinb2, merkle_branch[], version_hex,
   nbits_hex, ntime_hex, clean_jobs]  -- BE-hex default (LE is operator env toggle).

## BCH-specific divergences confirmed NON-impacting on stratum wire:
  - No SegWit  -> no witness commitment in coinb2 (share fmt: SegWit disabled, slice H).
  - ASERT DAA  -> only affects `bits` VALUE, not encoding (8-char hex unchanged).
  - ABLA       -> only affects `sizelimit`/budget, not any notify field.
  - ASICBoost (version-rolling mask 0x1fffe000), vardiff, FR-1.15 firmware
    env-toggles (FIXED_INITIAL_DIFF, NO_SUBMIT_RATCHET, IDLE_DOWNSHIFT) are all
    coin-agnostic operator runtime tuning in core -- not BCH module surface.

## M5 conformance sweep status: COMPLETE
  share-emit (sF) + merkle-accept (sG) + share-serialization/SegWit-off (sH)
  + PPLNS (verified no-diff) + stratum (this) all CONFORMANT vs p2poolBCH @6603b79.
