# Dash ↔ Explorer module §5 endpoint conformance audit

Reference: `frstrtr/the/docs/c2pool-sharechain-explorer-module-task.md` §5.
Audited against `multipow-v2-dash` @ `991b59ba` on 2026-04-22.

All six contract endpoints are reachable and return HTTP 200. Response
shape matches the spec for the critical share fields (the ones the grid
renderer requires). Four endpoints have minor gaps on optional
fields — listed below. Renderer tolerates their absence in testing,
so these are P1 follow-ups, not Pass-C blockers.

## 5.1 `/sharechain/window`

**Present:** best_hash, chain_length, fee_hash160, my_address, pplns,
pplns_current, shares, total, window_size.

**Share fields (ALL 11 required):** `H V a b dv h m p s t v` ✓ (exact match).

**Missing optional top-level fields:**
- `heads` — short hashes of chain heads (used for the "Verified Heads" row).
- `blocks` — short hashes of block-solution shares on the parent chain.
- `doge_blocks` — N/A for Dash (no merged mining); return `[]` to match spec.

## 5.2 `/sharechain/tip`

**Present:** hash, height.
**Missing:** `total` (informational but called out in §5.2 contract).

## 5.3 `/sharechain/delta?since=<short-hash>`

**Present:** blocks, chain_length, count, heads, pplns, shares, tip, window_size.
**Missing:** `doge_blocks` — return `[]` for Dash.
**Note:** `fork_switch: true` fallback (§5.3 rule 2) not audited — only
fires when `since` is outside the window. Worth adding a targeted test.

## 5.4 `/sharechain/stream`

**Verified:** `data: {"connected":true}\n\n` on connect ✓.
Debounce + dedup behaviour not exercised in this audit; has been
validated in prior sessions (see project memory
`project_next_session_socket_debug.md`).

## 5.5 `/sharechain/stats`

**Present:** chain_height, fork_count, total_shares, verified_count.
**Missing:** `head_count`.

## 5.6 `/web/share/<full-hash>`

**Full match:** block, children, far_parent, is_block_solution,
is_doge_block, local, parent, share_data, type_name, version ✓.
share_data keys: absheight, abswork, desired_version, difficulty,
donation, max_target, min_difficulty, nonce, payment_amount,
payout_address, stale_info, subsidy, target, timestamp ✓.
local keys: peer_first_received_from, time_first_seen, verified ✓.

## Summary of server-side TODOs

Small C++ patches against `src/impl/dash/main_dash.cpp` before the
Dash → master merge:

1. `/sharechain/window` — add `heads[]`, `blocks[]`, `doge_blocks[]`
   (the last always empty).
2. `/sharechain/tip` — add `total` (cheap: same value as chain_length
   returned elsewhere).
3. `/sharechain/delta` — add `doge_blocks: []`.
4. `/sharechain/stats` — add `head_count` (cheap: `heads.size()`).

Each is 1–3 lines. Grouped into a single "Dash: /sharechain/* §5
conformance" commit is the cleanest merge target. Not blocking the
Dash descriptor or bundle wiring.
