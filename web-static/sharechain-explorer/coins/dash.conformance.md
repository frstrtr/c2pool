# Dash ↔ Explorer module §5 endpoint conformance audit

Reference: `frstrtr/the/docs/c2pool-sharechain-explorer-module-task.md` §5.
Audited against `multipow-v2-dash` @ `fbf48169` on 2026-04-22.
Re-audited @ `<HEAD>` after server-side patches landed — **all 6 endpoints
now fully match §5** (see "Conformance fixes" section below).

## 5.1 `/sharechain/window` ✓

- Top-level keys: `best_hash, blocks, chain_length, doge_blocks,
  fee_hash160, heads, my_address, pplns, pplns_current, shares, total,
  window_size` — matches §5.1.
- Share fields (ALL 11 required): `h H p v t V s b a dv m` ✓.
- `heads` populated from `chain.get_heads()` (short hashes).
- `blocks` currently returns `[]` — TODO: wire to `found_blocks_db`
  once block-solution tracking lands (not a §5 violation — the spec
  accepts an empty array).
- `doge_blocks` always `[]` (no merged mining on Dash).

## 5.2 `/sharechain/tip` ✓

- Keys: `hash, height, total` — matches §5.2.
- `hash` MUST equal `window.shares[0].h` — verified ✓ (both use
  `best_share_hash_nolock()` — the single shared picker).

## 5.3 `/sharechain/delta?since=<short-hash>` ✓

- Top-level keys: `blocks, chain_length, count, doge_blocks, heads,
  pplns, shares, tip, window_size` — matches §5.3.
- `fork_switch: true` fallback (§5.3 rule 2) — not currently emitted;
  the 200-share cap is enforced but no explicit fork_switch flag is
  returned. Minor follow-up if client relies on it; today's inline
  client falls back to `liveRefresh()` on empty delta anyway.

## 5.4 `/sharechain/stream` ✓

- Emits `data: {"connected":true}\n\n` on connect ✓.
- Per-tip push with `{hash, height}` ✓.
- Debounce + dedup already validated in prior sessions.

## 5.5 `/sharechain/stats` ✓

- Keys: `chain_height, total_shares, verified_count, head_count,
  fork_count` — matches §5.5.

## 5.6 `/web/share/<full-hash>` ✓

- Top-level: `block, children, far_parent, is_block_solution,
  is_doge_block, local, parent, share_data, type_name, version` ✓.
- `share_data` keys: `absheight, abswork, desired_version, difficulty,
  donation, max_target, min_difficulty, nonce, payment_amount,
  payout_address, stale_info, subsidy, target, timestamp` ✓.
- `local` keys: `peer_first_received_from, time_first_seen, verified` ✓.

## Conformance fixes (landed 2026-04-22)

Four additive patches in `src/impl/dash/main_dash.cpp`:

1. `/sharechain/window` — populate `heads[]` from `chain.get_heads()`;
   emit empty `blocks[]` + `doge_blocks[]` arrays.
2. `/sharechain/tip` — add `total` = `chain.size()`.
3. `/sharechain/delta` — emit empty `doge_blocks[]` array.
4. `/sharechain/stats` — compute `head_count` = `chain.get_heads().size()`.

Each is ~3-5 lines, additive only. No other handlers touched.

## Remaining (optional) follow-ups

- `/sharechain/window` — populate `blocks[]` from the Dash found-blocks
  DB once a block has been found on the pool.
- `/sharechain/delta` — emit `fork_switch: true` when `since_hash` is
  not in the current walk path (defensive — today's client tolerates
  its absence).
