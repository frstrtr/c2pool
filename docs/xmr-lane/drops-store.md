# XMR lane: the raindrop set of a lane block and the servable store

How a lane block's raindrops (DROPS, sub-threshold credit) are chosen, kept and
fetched, and how much memory and disk that takes. Code: `xmr_relay_node.hpp`
(the servable store), `xmr_drops_wiring.hpp` (the harvest and the range),
`main_v37_xmr.cpp` (`drops_compose_lane`, `wire_cache_prune`),
`xmr_o2_finalize_connect.hpp` (`is_undecided`). KATs:
`v37_xmr_drops_retain_kat` (R1-R12), `v37_xmr_relay_repair_hold_kat` (K1/K1b, A1-A3),
`v37_xmr_drops_set_kat`, `v37_xmr_drops_harden_kat`.

## 1. The range and the set

The raindrops of lane block `h` are those of the bins
`[prev_lane(h) - D_conf, h - D_conf)` (`range_with`), where `prev_lane(h)` is the
canonical lane block below `h`. With `D_conf = 60` (the floor off regtest, and
mainnet's value) the youngest raindrop of a range is about 2 hours old when the
block is found, and the oldest is older by the time between the two lane
blocks.

The winner pins the raindrop ids it composed from and carries them on
`FB_BLOCK_WON` v0x03 (at most 16384 ids, the smallest). Every node, the winner
too, composes the block from exactly that set. A member a node does not hold
is fetched by id; until it arrives the booking HOLDs.

Each node keeps two stores:

- the **harvest** (`ChainOrderedHarvest`): id, payee, bin and normalised hash
  per raindrop, about 150 B each, pruned 64 bins below the newest booked range;
- the **servable store** (the relay): the raw receipt bytes, about 1 KB each in
  memory and 870 B on disk. Only this store answers a fetch.

## 2. The incident (stagenet attempt 6, 2026-10-02)

Node A found `h = 2220425` (range `[2220334, 2220365)`) and pinned 16384 ids
from its harvest. The servable store was bounded by a count of 65536 raindrops:
about 73 minutes at the measured 15.0 raindrops/s. The members were 112-160
minutes old, so every store had evicted them, A's included (`drops-sync: ...
raindrops_held=0`, `fetchreq_rx=1476 served=0`). B and C were missing 6 and 4
members (flood loss; B also restarted and rebuilt its harvest from its store,
then missed all 16384). After 600 retries (about 50 minutes)
`booking_stall_timeout` refused the block on B and C into node-local liability
while A booked it: an owed-ledger split at the block's FINALIZE. With
`D_conf = 10` the ranges were 20-70 minutes old, inside the store, which hid
the defect.

## 3. The fix (node-local; no lane rule, range, set rule or wire frame changed)

**L3, HOLD.** "pinned raindrop(s) not held" and "drops set ... not carried yet"
are undecided outcomes, like a relay repair in flight. Past the retry bound the
block is HELD (it keeps the R4 gate and keeps fetching) and books when the data
arrives; it is refused only on a decided reason. A withholding winner costs
liveness, loudly, never an honest split. (A decidable fallback needs the set
digest on chain: v37.1.)

**L2, pin what you can serve, and keep it.** (a) The winner pins
`harvest ∩ servable store` (`drops_pin_servable`): ids its store already
evicted are skipped and counted (`drops-ALARM set-unservable`). The set is the
winner's bounded choice already; receivers accept any valid set. (b) Every
pinned set is retained (`drops_pin_retain`) until the block is decided on this
node: the winner retains at compose, a receiver when it admits the carried set,
and a restarted node re-pins its journalled sets before it reloads the store.
Eviction skips retained raindrops. The set is released (`drops_pin_release`)
when `wire_cache` forgets the block (the finalize cursor passed `h + D_conf`, or
the byte cap evicted it).

**L1, size the store by what this node still has to book.** The store is
bounded by a floor and a byte budget, not by a count:

- the floor is `frontier_of(F) - 64`, where `F` is the newest lane block below
  this node's finalize cursor (`set_drops_floor_bin`, pushed on each finalize
  step). Every block this node may still compose, pending or not found yet, has
  its range at or above it. Raindrops below the floor are evicted even under
  budget. Before the first finalize step the old window (`--drops-retain-bins`,
  512 bins below the tip) applies;
- the budget is `--drops-store-bytes` (default 536870912 = 512 MiB; raw receipt
  plus about 160 B of index per raindrop). Measured RSS is about 1.15 KB per
  raindrop, so a full budget costs about 600 MiB of memory. Over it the oldest unretained bins
  are evicted and counted (`overflow_bins`, `relay: drops-ALARM store over
  budget`). Because the winner pins only what it can serve, an overflow costs
  raindrop credit in that block, never a split.

The store is persisted as per-bin segments `<settle_db>/lane<N>.drops.d/<bin>.seg`:
new raindrops of a bin are appended (one fsync per changed bin), a bin that lost
raindrops to an eviction is rewritten (tmp + fsync + rename), an evicted bin is
unlinked. Each record carries its own checksum: a torn tail ends that segment
only. At boot the segments are read newest bin first while they fit the budget;
older bins keep only their pinned raindrops. The old whole-store file
`lane<N>.drops` (rewritten whole on every change: 56 MB every ~2.4 s, about
23 MB/s, on every attempt-6 host; and ignored whole at boot when it held more
than the count) is read once when no segment exists and renamed
`lane<N>.drops.migrated` after the first segment write.

A backfill inventory that reaches the frame bound (16384 ids) over more than one
bin is paged: one inventory per bin, each fetched on its own (a 31-bin range
holds about 44k ids at 15 raindrops/s). One bin over the bound is paged by
cursor (section 6).

## 4. Memory and disk

The window the floor holds is about `T_lane + 2 h (D_conf) + 2.1 h (64 bins)`,
where `T_lane` is the time since the newest finalized lane block. At 15
raindrops/s (stagenet attempt 6; on mainnet the rate is
pool hashrate / drops floor difficulty, a lane-rules choice that keeps it in
the same range):

| lane blocks every | window | raindrops | servable store (RAM) | segments (disk) | harvest (RAM) |
|---|---|---|---|---|---|
| 45 min (stagenet attempt 6) | ~5 h | 270k | 270 MB | 235 MB | 40 MB |
| 6 h | ~10 h | 540k | 512 MiB budget (just over it: overflow) | 470 MB | 80 MB |
| 24 h | ~28 h | 1.5M | 512 MiB budget: overflow | ~460 MB (the budget) | 225 MB |

Before this change: 65536 raindrops, 64 MB RAM, 56 MB disk, about 73 minutes of
history. Raise `--drops-store-bytes` for a pool whose lane blocks are hours
apart, or accept the overflow (it is loud, and economic only). A pool with lane
blocks days apart needs a disk-backed store (not built yet).

## 5. Status line and alarms

- `drops-retain: store=N bytes=B budget=B bins=[lo,hi] floor=F pins=P retained=R
  | evict floor_bins=.. overflow_bins=.. kept_pinned=.. | set_unservable_skipped=..
  | seg appends=.. rewrites=.. unlinks=.. torn=.. load_over_budget=.. | inv_paged=..
  | set_unservable=..` (every status tick);
- `drops-ALARM set-unservable: h=.. range=[..) N harvested raindrop(s) are not in
  the relay store` (the winner's own composition skipped evicted ids);
- `relay: drops-ALARM store over budget` (at most once a minute);
- `drops-store: raindrop store <path>(.d) restored=N bytes=B budget=B retained=R`
  (boot);
- `drops-backfill: ... | pages tx=.. served=.. rx=.. gaveup=.. | refused=..
  refused_held=.. budget_setaside=..` (section 6); `drops: ... | mint drops=..
  below_floor=.. stale=..` (raindrops refused on a stale job).

What to check on a running pool: on the winner `drops-sync: ... raindrops_held=N`
equals the pinned count; `drops-backfill: ... served>0` on the winner after a
receiver's fetch; `pin_slow_asks` does not grow; `drops-retain: store=` exceeds
65536 on a pool past 73 minutes of history and its `floor=` tracks the finalize
cursor.

## 6. The re-ask storm (stagenet attempt 7, 2026-10-02) and paging within a bin

Node A held B's lane block 2220689 (HOLD, `finality-boundary.md`): its finalize
cursor stopped, the booking-point gate froze its template at h=2220689, and its
miners kept hashing that job for hours: about 130k raindrops in ONE bin. B's
link to A was reset every ~3 s (the share strikes of `coinbase-recompute.md`
section "Share verdict and lane-prefix skew"), and every HELLO pulled A's
inventory of the last 64 bins: the 16384 smallest ids of bin 2220689, fetched
at once outside the ask budget, overflowing B's verify queue or expired by the
index horizon, never admitted, never counted as held, asked again at the next
HELLO. The per-peer ask counter was keyed by the connection and erased at every
disconnect, so the 8-ask set-aside fired once in three hours. B asked 3.75M ids;
A served 3.58M. B's own next block then held on "drops backfill ... incomplete
(2/2 peer(s) unconfirmed, 0 raindrop(s) missing)": the page of a dead bin can
never be confirmed. The fix (relay wire only, Family B; no consensus byte):

- **C1, one bin is paged by cursor.** `FB_GETDROPS [bin, bin+1)` carrying the
  same id twice means "your inventory of this bin, ids above this one"
  (`encode_getdrops_page`); the answer is a `FB_DROPINV [bin, bin+1)` page. A
  plain fetch never repeats an id, so the form is unambiguous; an old server
  serves it as a fetch of that one id, and the asker keeps its unpaged page
  after `drops_inv_page_max_asks` (3) unanswered pages (`gaveup`). A sync of one
  bin is complete only when every page is held (base: complete at 16384).
- **C2, an id this node cannot admit counts as held.** A fetched or flooded
  raindrop dropped before admission (beyond the index horizon, structurally bad,
  refused by the share verdict, its context unknown past the patience, not a
  raindrop at all, or asked 10 minutes ago and never admitted) enters a bounded
  set (`drops_refused_max`, 262144); the backfill counts it as held, so the
  peer's inventory is confirmed and the id is not asked again. "Complete" means
  "holds every raindrop it would admit". A queue overflow is NOT a refusal (the
  id may be admitted on a re-ask).
- **C3, the ask budget is per node.** Inventories are keyed by the peer's HELLO
  node nonce, kept across a disconnect (aged out after 10 minutes untouched);
  the fetch-at-once of a HELLO inventory goes through the same budget. After
  `drops_fetch_max_asks` (8) asks in all the peer is set aside for that range
  (`budget_setaside`). The HELLO inventory skips bins below the index horizon.
- **C4, no raindrop on a stale job.** The minter refuses a raindrop whose job
  height the chain tip has passed by more than 2 heights (`stale=`): one job late
  is honest work, a frozen template is not.

KATs: `v37_xmr_drops_retain_kat` R9 (20,000 raindrops of one bin), R10 (an
inadmissible id is not re-asked across forced reconnects), R11 (set aside after
8 asks in all across reconnects), R12 (the stale-job rule and its wiring).
