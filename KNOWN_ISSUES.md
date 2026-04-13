# Known Issues

Open issues and limitations in the current release. Fixed issues are
documented in the [postmortem archive](https://github.com/frstrtr/the/tree/master/docs).

---

## Remaining IO-thread tracker callbacks without shared_lock

**Severity**: Medium  
**Risk**: Data race under specific timing (same class as the OOM crash)

The three hottest callbacks (`pplns_fn`, `ref_hash_fn`, `sharechain_window_fn`)
now hold `shared_lock(try_to_lock)` before accessing the tracker. However,
several less-frequently-called callbacks still access the tracker without the
lock. These are lower risk (called on-demand, not on timers) but are the same
class of bug:

- `sharechain_stats_fn` — called by `/sharechain/stats` HTTP endpoint
- `sharechain_delta_fn` — called by `/sharechain/delta` HTTP endpoint
- `share_lookup_fn` — called by `/sharechain/share/:hash` HTTP endpoint
- `protocol_messages_fn` — called by `/protocol_messages` HTTP endpoint
- `m_on_block_found` callback — fires when a share solves a block
- `m_on_merged_block_check` callback — fires on merged mining block check

These should be audited and guarded with `shared_lock(try_to_lock)` as well.

---

## `m_found_blocks` grows without bound

**Severity**: Low (very slow growth)  
**Location**: `web_server.hpp:1065`

The found blocks vector appends every block found and is never pruned.
Growth rate is extremely slow (~1 entry per days/weeks depending on pool
hashrate), so this is not a practical concern for current deployments.
Should be capped at ~1000 entries for long-running nodes.

---

## RSS steady-state growth not fully characterized

**Severity**: Low (monitoring)

Normal steady-state RSS for LTC + DOGE merged mining is 800-1500 MB.
The RSS watchdog aborts at `rss_limit_mb` (default 4000 MB). Whether
RSS stabilizes or grows slowly over multi-day runs is not yet confirmed
after all fixes. Monitor the stat line:

```
Shares: 20771 ... [heads=5 v_heads=5 rss=1441MB]
```

Report RSS growth patterns to help characterize the baseline.

---

## Platform Limitations

### Windows: sleep kills the process

If the Windows PC goes to sleep, all TCP connections die and the event
loop stops progressing. The process remains alive but non-functional
after wake. Workaround: disable sleep on mining machines, or restart
c2pool after wake.

### Windows: DLL placement for portable ZIP

The portable ZIP requires `libsecp256k1-6.dll` next to `c2pool.exe`.
Windows only searches the exe's directory for DLLs, not subdirectories.
The Inno Setup installer handles this automatically.

### macOS: Gatekeeper quarantine

First run may be blocked by macOS Gatekeeper. Fix:
```bash
xattr -dr com.apple.quarantine ~/c2pool
```

### macOS arm64 cross-compile

Homebrew's secp256k1 is native-only (x86_64 on Intel Macs). To build
an arm64 binary, cross-compile secp256k1 from source into a persistent
directory (not `/tmp/` which gets cleaned). See `doc/build-macos.md`.
