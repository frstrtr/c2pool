# Known Issues

Open issues and limitations in the current release. Fixed issues are
documented in the [postmortem archive](https://github.com/frstrtr/the/tree/master/docs).

---

## DASH daemonless masternode set is seeded from a TRUST ANCHOR

**Severity**: Medium (security-model disclosure, not a defect)
**Affects**: DASH daemonless run (bare `--run`, no dashd RPC — the default posture)

c2pool cannot derive the payout-bearing DASH masternode set from the P2P
network: the Simplified MN List omits `scriptPayout` and `nLastPaidHeight`,
and neither is committed in `merkleRootMNList`. Daemonless DASH therefore
cold-starts from a **release-pinned masternode set compiled into the binary**
and replays blocks forward from it.

**You are trusting the release build** for the set contents at the anchor
height. The node does independently verify the anchor's chain position against
its own PoW-validated header chain, its SHA-256 integrity digest, and every
replayed block's coinbase against the projected payee. That last check proves
the payout state of every masternode paid inside the replayed window, and a
wrong entry there fails the bridge closed. A wrong `scriptPayout` or
`nLastPaidHeight` of a masternode NOT yet paid in the window surfaces only at
its first payment: our block then carries the wrong payee, the network rejects
it (`bad-cb-payee`) and that block's reward is lost. Nothing is paid to a wrong
address, because every node checks the payee. Nothing available to the node can
prove the set itself; anyone with a synced dashd can reproduce it (README,
"Verifying the anchor yourself").

A fully trustless DIP-3-height replay (~1.5M block bodies) is planned as a
later **opt-in verify-mode**; it is not implemented.

Two further limitations today:

- **The mainnet anchor is pinned at h=2,563,800; the testnet anchor is
  UNPINNED.** Pinning is a release-time step (see
  `src/impl/dash/coin/checkpoints/README.md`). Without a pinned anchor,
  daemonless DASH testnet **fails closed**: it logs at `ERROR` and refuses to
  serve embedded templates rather than guessing a payee.
- **A stale anchor is refused, not worked around.** The bridge refuses to
  start more than `--embedded-mn-bridge-max` blocks behind the tip (default
  40000, ≈69 days). The distance is measured from where the bridge starts: the
  anchor on a cold start (empty data directory), the persisted cursor when a
  node resumes. A running node persists its cursor as it follows the chain, so
  the limit bites only on a cold start or after a stop longer than the limit:
  with the h=2,563,800 anchor, a cold start is refused once the tip passes
  2,603,800 (2,583,800 under the earlier 20000 default). A release cut long
  ago will not
  daemonlessly cold-start DASH without a fresher build, a larger
  `--embedded-mn-bridge-max`, or `--coin-rpc-*`.

Background: README section "DASH daemonless masternode-set checkpoint — trust
anchor" and `src/impl/dash/coin/checkpoints/README.md`.

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
