# src/core re-certification: PPLNS precompute pacing (#1556)

Origin fix: PR #1556 "ltc(web): pace PPLNS precompute walk under the boot
io_context watchdog", merge commit 679a584e, merged 2026-09-10T15:34:29Z.

## Why this needs a src/core re-certification
#1556 landed titled `ltc(web)` and touched a shared file,
`src/core/web_server.cpp` (`MiningInterface::start_pplns_precompute`,
line 3130; +18/-2). Under the per-coin isolation invariant, any edit to
`src/core/**` is EXCEPTIONAL and must carry (a) an explicit justification
for living in core rather than a per-coin seam and (b) an explicit
LTC/DOGE preservation verification with all four coin smokes green.
#1556 did not carry that record. This document closes that audit gap
retroactively; it adds no code change of its own.

## Justification for the core location
`start_pplns_precompute()` is a member of the shared `MiningInterface`
in `src/core/web_server.cpp`. The precompute walk, its lock discipline,
and the boot io_context watchdog it was starving all live in core; there
is no per-coin override seam for this entrypoint. The fix therefore had
to be confined WITHIN the core entrypoint rather than duplicated per
coin. The pacing is scoped to the precompute thread body only and does
not touch `refresh_work()` or the dashboard readiness gate.

## LTC/DOGE + cross-coin preservation verification
The change is LTC-scoped by construction, not by a runtime coin branch:
the only LIVE caller of `start_pplns_precompute()` is
`src/c2pool/main_ltc.cpp:4349`. The would-be BTC and DASH call sites
(`main_btc.cpp:2800`, `main_dash.cpp:2012`) are COMMENTS, so BTC and DASH
never enter the paced path and their boot is byte-for-byte unaffected.
DGB likewise has no live caller. DOGE has no separate main entrypoint --
it rides the LTC merged-mining path through `main_ltc.cpp`, so DOGE
inherits exactly the LTC behavior.

Preservation claim, per coin:
- LTC: behavior CHANGED intentionally (30s boot-settle + 250ms burst
  budget then 50ms yield); this is the fix. Runtime payout/share
  semantics unchanged -- only walk pacing.
- DOGE: rides LTC; same paced path; merged-mining aux semantics
  unchanged.
- DGB / BTC / DASH: no live caller -> zero behavioral change.

## Four-coin smoke evidence (required to clear the exceptional bar)
Runners under tests/gates/:
- LTC : ltc_g3a_regtest_block_production.sh
- DOGE: doge_aux_smoke.sh
- DGB : dgb_embedded_standalone_smoke.sh
- DASH: g3a_regtest_block_production.sh (dash regtest arm)

Results are attached to the PR thread once green; the PR stays draft
until all four pass on Linux x86_64.
