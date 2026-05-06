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

## SIGSEGV during sharechain pruning (drop_tails iterator/race) — open

**Severity**: Medium  
**First reported**: 2026-05-06 (krizis, pre-v0.1.2-alpha binary)  
**Risk**: Process crash; auto-restarts cover it but state momentarily lost.

Reported crash signature on a long-running pre-v0.1.2-alpha node:

```
[drop-tails-QUALIFY] tail=e1add697515ef9f1 min_height=17521 threshold=17290 n_heads=5 chain_size=18705
[drop-tails-PRE] iter=0 drop_idx=0/1 aftertail=65ba9088c660768a chain_size=18705
[drop-tails-PRE] iter=1 drop_idx=0/1 aftertail=b3ff057b0c294850 chain_size=18704
=== CRASH (signal 11) ===
./c2pool(+0x47919) ...
/lib/x86_64-linux-gnu/libc.so.6(+0x45330) ...
```

SIGSEGV inside `drop_tails` on the second pruning iteration of a large
sharechain (18,705 entries, 5 disconnected heads). **Not** the same class
as v0.1.2-alpha's Bug 9 fix (wire-side `vector::resize` / `Packet::read`
length_error) or Bug 3 fix (Factory async-lambda UAF on disconnect-reconnect)
— the crash site is in sharechain mutation, not network IO.

The most plausible cause is the residual tracker-race class above: an HTTP
request walking the chain (e.g. `/sharechain/share/:hash` via
`share_lookup_fn`) racing with `drop_tails` mutating the chain mid-iteration.
The reporter's binary was discarded before symbols could be resolved, so the
exact fault address is undetermined; symptoms are consistent with this class.

**Status**: open. Triggered repro requires a long-running node + heavy
HTTP traffic on `/sharechain/*` endpoints during pruning.

**Mitigation today**: enable `Restart=always` in the systemd unit so the
auto-restart absorbs the crash; rely on persistent sharechain on disk to
resume cleanly. v0.1.1-alpha's external watchdog thread + `LimitCORE=infinity`
will also capture a core dump for future analysis if it recurs on a
v0.1.2-alpha+ binary (where addr2line will resolve symbols against a
distributed binary's BuildID).

**Fix path**: extend the `shared_lock(try_to_lock)` guard to the remaining
HTTP callbacks listed above. Tracked in the tracker-callbacks audit item
that v0.1.1-alpha started.

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

Homebrew's secp256k1 is native-only (x86_64 on Intel Macs / arm64 on
Apple Silicon). The official macOS distribution since v0.1.2-alpha is
a single Universal DMG built by combining per-arch binaries (one
built on each Mac) via `lipo -create` — see
`installer/macos/create-universal-dmg.sh`. If you need to cross-compile
a single-arch binary on a single Mac, see the cross-compile section in
`doc/build-macos.md`.
