# DASH dashboard plan (web_server / JSON API layer)

Owner: dashboard-steward. Charter: a dashboard must never lie about prod health
— and must never serve a tenant *wrong instructions*. Progress is logged here so
it is visible without anyone asking.

## Live context
- Hotel DASH node LIVE on PPLNS, real tenant watching (109.161.57.3:8080).
- Gauge truth caveat: build on #877 (pool_hash_rate / min_difficulty un-fudge)
  and cross-check any new card against an oracle node, not our own JSON.

## P4 — cross-coin dashboard correctness (coin-specific strings data-driven)

Trigger: 2026-07-26 integrator HIGH — the DASH node served the LTC dashboard
essentially unmodified: LTC+DOGE **merged-mining worker-username** instructions
(`<ADDR>,<DOGE_ADDR>.WORKER`) on a standalone DASH pool with no merged child, plus
LTC branding/explorer links throughout. Wrong instructions actively mislead a
paying tenant.

### (a) Minimal — data-drive coin strings  [IN PROGRESS: branch dash/coin-topology-username-honesty]
- [x] Backend: `rest_web_currency_info()` emits merged-mining **topology**
      (`merged_child_symbol`) — `"DOGE"` for LTC parent, ABSENT for standalone
      coins (DASH/BTC/DGB). currency_info already carried per-coin symbol/name/
      explorer prefixes (incl. DASH), so only topology was missing.
- [x] Frontend: the Username connection-instruction line is now topology-driven —
      merged parent → `PARENT_ADDR,CHILD_ADDR.WORKER`; standalone → `PARENT_ADDR.WORKER`.
      DASH now renders `<DASH_ADDR>.WORKER`; the merged child span is hidden.
- [x] Honesty KAT (test_web_honesty_regression): DASH advertises no merged child
      and DASH (not litecoin) explorer branding; LTC advertises DOGE. Not
      `#ifdef`-guarded (issue #895) — the test actually executes.
- [ ] Follow-up within (a): route the found-block miner/block explorer links
      (still hardcoded blockchair litecoin/dogecoin at web-static/dashboard.html
      ~3887/3918/4033/6401) through `currency_info.*_explorer_url_prefix`.

### (b) Structural — one template, every lane renders its own coin  [FOLLOW-UP]
- Canvas block labels ("LTC BLOCK"), page title/branding sweep (7x "Ltc",
  6x "LtcBlock", 5x "litecoin"), and full coin-profile parameterization so
  LTC/DOGE, DASH, DGB, BCH, BTC each render correctly from one source.

## Watchlist
- PR #879 (draft) `/p2p_stats`: tip lag + timestamp-saturation fraction are the
  HONEST sharechain-health signals; under saturation pool_hash_rate is a
  difficulty-history gauge, not a hashrate gauge. Surface once merged.
  (bg: p2pool-dash/PPLNS_TIMESTAMP_CLIP_SATURATION.md)

## Non-issues (do not "fix")
- `record_merged_share_difficulty` absent on DASH is CORRECT — standalone parent,
  no merged child. That absence is exactly what (a) makes the dashboard honest about.
