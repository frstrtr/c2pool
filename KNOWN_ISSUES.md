# Known Issues

Tracking known bugs, their root causes, and fix status. Issues are removed
once verified fixed in a tagged release.

---

## FIXED: Tracker data race — OOM crash (10 GB memory spike)

**Status**: Fixed in `c29efcac` + next commit  
**Severity**: Critical (production crash)  
**Affected**: All versions before fix  
**Symptoms**: Process killed by OOM killer after sudden RSS spike (1.4 GB → 11.3 GB in ~2 minutes). No crash log written (SIGKILL is uncatchable).

### Root Cause

A data race between the IO thread and the compute thread accessing the
share tracker without proper synchronization.

**The race condition:**

1. `cache_pplns_at_tip()` runs every 2 seconds on the IO thread. It calls
   the PPLNS function which walks 8,640 shares following chain pointers.

2. `clean_tracker()` runs on the compute thread holding `m_tracker_mutex`
   exclusively. It removes stale shares, deleting their chain entries.

3. The PPLNS function lambda (and other callbacks like `ref_hash_fn`,
   `sharechain_window_fn`) accessed the tracker **without any lock**.

4. When both ran concurrently: the PPLNS walk followed a pointer to a
   deleted share → use-after-free → corrupted chain traversal → massive
   allocation in a runaway loop → 10+ GB RSS → kernel OOM kill.

**Why the watchdog didn't help**: The OOM killer sends SIGKILL, which
cannot be caught by any signal handler. The external watchdog thread
was also killed instantly. The RSS limit check (4 GB) runs every 10
seconds — the spike from 1.4 GB to 11.3 GB happened faster.

### Fix

All IO-thread callbacks that access the share tracker now acquire
`shared_lock(tracker_mutex, try_to_lock)` before reading. If the
compute thread holds the exclusive lock (during think/clean), the
IO callback returns empty and retries on the next cycle.

**Synchronization contract** (from `node.hpp`):
```
Compute thread: unique_lock(m_tracker_mutex)     — exclusive, blocking
IO thread reads: shared_lock(try_to_lock)        — non-blocking, skip if busy
IO thread writes: unique_lock(try_to_lock)       — non-blocking, queue if busy
```

### Safety Layers

Even with the data race fixed, three safety layers protect against future
memory issues:

1. **External watchdog thread** — detects event loop freeze >30s, dumps
   heartbeat diagnostics, writes crash log, aborts for core dump.

2. **RSS memory limit** — external watchdog checks RSS every 10s. If it
   exceeds `rss_limit_mb` (default 4 GB), aborts cleanly before the
   kernel OOM killer sends uncatchable SIGKILL.

3. **UTXO prune batching** — `prune_undo()` and `prune_raw_blocks()` skip
   the already-pruned height range on startup and batch to 500 records
   per call, preventing event loop freezes from million-iteration loops.

---

## FIXED: UTXO prune startup freeze

**Status**: Fixed in `2ce272db`  
**Severity**: High (node freeze on every restart)  
**Symptoms**: Node freezes for >30 seconds on startup, then killed by
external watchdog or becomes unresponsive.

### Root Cause

`m_oldest_undo_height` initialized to 0. On restart, `prune_undo()` tried
to loop from height 0 to `tip_height - keep_depth`. For DOGE at chain
height ~6.16M, this was 6,161,704 LevelDB delete attempts — synchronously
on the event loop thread.

### Fix

Skip the already-pruned range on first call (`m_oldest_undo_height = prune_below`).
Batch all prune operations to max 500 records per call.

---

## FIXED: Memory leaks (gradual growth)

**Status**: Fixed in `c29efcac`  
**Severity**: Medium (gradual RSS growth over hours)

| Leak | Location | Fix |
|------|----------|-----|
| `m_pplns_per_tip` | `web_server.cpp` | Evict at 200 entries |
| `m_rate_buckets` | `web_server.cpp` | Cleanup IPs idle >1 hour |
| `m_pplns_precompute_thread` | `web_server.cpp` | Atomic flag guard (was re-spawning after detach) |

---

## Monitoring: RSS growth pattern

For tracking memory health on production nodes, monitor the RSS value
in the stat line (logged every 30 seconds):

```
Shares: 20771 ... [heads=5 v_heads=5 rss=1441MB]
```

Normal steady-state RSS:
- **LTC only**: ~400-600 MB
- **LTC + DOGE merged mining**: ~800-1500 MB
- **Concern threshold**: >2500 MB (investigate)
- **Hard limit**: `rss_limit_mb` in config (default 4000 MB)

If RSS grows continuously without stabilizing, file an issue with the
RSS growth rate and log excerpts from around the growth period.

---

## Platform Notes

### Windows: DLL placement
The portable ZIP requires `libsecp256k1-6.dll` next to `c2pool.exe`
(Windows only searches the exe directory). The Inno Setup installer
handles this automatically.

### macOS: Gatekeeper quarantine
First run may be blocked. Fix: `xattr -dr com.apple.quarantine c2pool`

### macOS arm64 cross-compile
Homebrew's secp256k1 is native-only. Cross-compile from source into
a persistent directory (not `/tmp/`). See `doc/build-macos.md`.
