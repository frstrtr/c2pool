# QT Control Panel Design And Plan

## 1. Purpose

Build a desktop control panel for c2pool in a Bitcoin-Qt style with:

- live monitoring dashboard
- message center (signals, warnings, errors, future BBS)
- logs viewer
- settings editor
- network monitor
- RPC console
- anti-abuse controls (ban/poolhopper mitigation)

This document defines first implementation scope, architecture, API contracts, and milestones.

## 2. Product Goals

- Provide a single operator UI for day-to-day pool operations.
- Keep daemon logic in c2pool process; UI is controller/monitor only.
- Preserve existing REST/API behavior from Python dashboard where practical.
- Make unsafe operations explicit and localhost-only by default.

## 3. Non-Goals (v1)

- Wallet operations and key management.
- Distributed multi-user admin auth.
- Full replacement of all legacy debug endpoints.
- Embedded browser-based UI in v1.

## 4. UI Model (Bitcoin-Qt style)

Main window layout:

- left navigation sidebar
- top status strip
- central page stack
- bottom event/status bar

Pages (v1):

1. Overview
2. Mining
3. Payouts
4. Network
5. Message Center
6. Logs
7. Settings
8. RPC Console
9. Security/Abuse Controls

## 5. Monitoring Surface (from Python web endpoints)

Source reference: ref/p2pool/web.py

### 5.1 Overview

- /global_stats
- /local_stats
- /rate
- /difficulty
- /uptime
- /version_signaling
- /v36_status

### 5.2 Mining And Worker Monitoring

- /stratum_stats
- /stratum_security
- /ban_stats
- /connected_miners
- /miner_stats/<address>
- /stale_rates

Critical worker fields to expose in UI:

- merged_auto_converted
- merged_redistributed
- merged_reverse_converted

### 5.3 Payout Monitoring

- /current_payouts
- /current_merged_payouts
- /miner_payouts
- /merged_miner_payouts
- /fee
- /payout_addr
- /payout_addrs

### 5.4 Chain/Share Monitoring

- /best_share
- /recent_blocks
- /recent_merged_blocks
- /all_merged_blocks
- /discovered_merged_blocks
- /tracker_debug

### 5.5 Network Monitoring

- /peer_list
- /peer_versions
- /peer_addresses
- /peer_txpool_sizes
- /pings
- /network_difficulty
- /node_info
- /luck_stats
- /broadcaster_status
- /merged_broadcaster_status

### 5.6 Graph/History Data

- /web/graph_data/<source>/<view>
- /web/log

### 5.7 Message Center Monitoring

- /msg/config
- /msg/recent
- /msg/alerts
- /msg/announcements
- /msg/status
- /msg/chat (future BBS feed)
- /msg/stats
- /msg/bans
- /msg/diag

Message Center categories in UI:

- Signals (transition and protocol signaling)
- Warnings
- Errors/Critical alerts
- Operator announcements
- Chat/BBS stream (future, optional tab)

## 6. Control Surface (Operator Actions)

### 6.1 Actions We Already Have Endpoint Support For

- message moderation:
  - POST /msg/ban
  - POST /msg/unban
- authority/transition blob load:
  - POST /msg/load_blob

### 6.2 Anti-Abuse Controls (Poolhoppers / Attacks)

Controls to expose in the Qt Security page:

- Ban by address/signing_id/keyword/type (existing /msg/ban)
- Unban actions (existing /msg/unban)
- Ban list live table with reason and timestamps (from /msg/bans)
- Stratum security and ban telemetry widgets (from /stratum_security and /ban_stats)
- Connected miner risk view (from /stratum_stats and /connected_miners)

Controls to add or confirm server support for:

- Mark miner as high-risk poolhopper and apply configurable policy
- Policy selector for suspicious miners:
  - reject work
  - allow but redistribute shares
  - allow with stricter vardiff/rate limits
- Auto-action thresholds (rapid reconnect pattern, burst reject ratio, IP/worker churn)
- Safety mode toggle: "redistribute suspicious miners" with explicit audit logging

### 6.3 Actions To Add/Confirm For Qt Runtime Control

- daemon lifecycle:
  - start
  - stop
  - restart
- config apply with validation and rollback
- controlled log level change
- safe RPC command execution (allowlist)
- optional peer management actions in future revision

## 7. Technical Architecture

## 7.1 Process Boundary

- c2pool daemon remains separate process.
- Qt app communicates over localhost HTTP JSON endpoints.
- No direct consensus logic in GUI.

## 7.2 Qt Stack

- Qt 6 Widgets (preferred for Bitcoin-Qt style)
- QNetworkAccessManager for REST polling
- optional QWebSocket for push updates (phase 2)
- QProcess for daemon lifecycle control
- QSettings for UI preferences only

## 7.3 App Modules

- ApiClient: typed requests, retries, timeout handling
- PollScheduler: endpoint polling cadence and backoff
- AppStateStore: normalized in-memory state
- ProcessController: start/stop/restart daemon
- ConfigController: load/validate/apply settings
- LogController: tail/filter/export log events
- ConsoleController: command history and safe dispatch
- MessageController: signals/alerts/chat stream + moderation actions
- AbuseController: risk scoring, ban workflow, redistribution policy controls

## 8. Polling And Refresh Plan

- Fast (1-2s): stratum stats, hashrate, top strip health
- Medium (5s): peer list, payouts, stale rates
- Slow (15-30s): luck stats, version signaling, tracker debug summary
- Message Center (2-5s): recent/alerts/status/stats/bans

Backoff behavior:

- endpoint error -> exponential backoff up to 30s
- UI marks stale data age explicitly

## 9. Security Model

- UI expects daemon endpoints bound to localhost by default.
- Mutating actions require explicit confirm dialog.
- RPC console defaults to read-only allowlist category in v1.
- Message moderation and blob loading remain localhost-only.
- Never store wallet secrets in UI config.

## 10. Mining-First MVP Plan

Implementation priority is changed to: "start mining operations reliably first, then expand operator features".

### MVP-0: Bootstrap (2-3 days)

- Qt shell (Widgets), sidebar, status strip, page routing
- API client with retry/backoff + endpoint health badges
- Daemon process controls: start/stop/restart and state indicator

### MVP-1: Start Mining Core (1 week) [PRIMARY GOAL]

- Mining page first:
  - /stratum_stats
  - /connected_miners
  - /miner_stats/<address>
  - /stratum_security
  - /ban_stats
- Overview essentials:
  - /global_stats
  - /local_stats
  - /uptime
- Minimal Logs page:
  - live tail + severity filter + search
- Quick actions required for operations:
  - temporary ban/unban for abusive clients
  - emergency DDoS shield toggle (if backend supports)

Exit criteria for MVP-1:

- Operator can start/monitor mining from panel only
- Operator can see accepted/rejected shares and miner connectivity in real time
- Operator can apply emergency abuse action in under 10 seconds

### MVP-2: Stability And Safety (4-6 days)

- Security/Abuse page with score table and policy toggles
- DDoS telemetry widgets and mitigation level control
- Action audit journal visible in UI
- Safe defaults + rollback timer for emergency controls

### Phase 3: Economics And Operator Tools (1 week)

- Payouts page (/current_payouts, /current_merged_payouts, /fee)
- Message Center full view (/msg/recent, /msg/alerts, /msg/status, /msg/stats)
- Settings editor (validated apply)

### Phase 4: Advanced Ops (1 week)

- RPC console (allowlist mode)
- Network deep-dive views (peer list detail, pings, broadcaster status)
- Message moderation extras (load_blob workflow, BBS/chat preview)

### Phase 5: Release Candidate (3-5 days)

- Stabilization and bugfixes
- Packaging scripts and launch docs
- Regression checklist and smoke tests

## 11. Test Plan

- Unit tests:
  - endpoint parsing models
  - error/backoff logic
  - settings validation rules
- Integration tests:
  - mocked API responses for all pages
  - process controller start/stop/restart
- MVP mining flow test:
  - launch daemon from panel
  - verify /stratum_stats and /connected_miners update continuously
  - execute temp ban and verify effect in ban stats
- E2E smoke test:
  - start daemon
  - verify all page data load
  - perform one safe control action
  - confirm UI and daemon remain healthy

## 12. Open Decisions

1. Qt Widgets only or limited QML for charts?
2. Keep polling-only in v1 or add push channel early?
3. Which settings are editable in UI vs read-only in v1?
4. Is RPC console enabled by default or hidden behind advanced mode?
5. Which anti-poolhopper policy is default: reject, redistribute, or limited-allow?
6. Should abuse actions be manual-only in v1, or allow guarded auto-actions?

## 13. Abuse Scoring Specification (v1)

This section defines a concrete scoring model for poolhopper and abuse mitigation
that the Qt Security page can control and visualize.

### 13.1 Signals

- reconnect_burst_1m: connection opens in last 60s
- worker_churn_5m: distinct worker names seen for same base address in 5m
- reject_ratio_5m: rejected/(accepted+rejected) over 5m
- low_quality_shares_5m: stale + doa share ratio over 5m
- ip_fanout_10m: unique base addresses per source IP in 10m
- difficulty_flip_rate_5m: vardiff oscillation count in 5m

### 13.2 Score Formula

Risk score range: 0 to 100.

```
score =
  18 * norm(reconnect_burst_1m, 4, 30) +
  16 * norm(worker_churn_5m, 2, 20) +
  26 * norm(reject_ratio_5m, 0.05, 0.90) +
  16 * norm(low_quality_shares_5m, 0.03, 0.70) +
  14 * norm(ip_fanout_10m, 2, 50) +
  10 * norm(difficulty_flip_rate_5m, 1, 25)
```

Where `norm(x, lo, hi)` clamps to [0, 1].

### 13.3 Action Bands

- 0-34: allow
- 35-54: watchlist (yellow)
- 55-74: soft mitigation
  - tighten vardiff bounds
  - reduce accepted connection concurrency
- 75-89: redistribution mode for suspicious worker (if enabled)
  - shares attributed using configured redistribution policy
- 90-100: temporary ban
  - initial 10m ban, exponential up to 12h for repeats

### 13.4 Decay And Hysteresis

- score decays by 15% every 2 minutes without new events
- action downgrade requires score below threshold minus 8 points
- ban lift does not restore trust immediately: restart at minimum score 40 for 10m

### 13.5 Safety Constraints

- do not auto-ban if total active workers < 3 (small pool safety)
- cap auto-actions per 10m window to avoid mass false positives
- always allow manual override in UI
- every action must include reason codes and raw metrics snapshot

### 13.6 UI Requirements (Security/Abuse Page)

- live table: address, score, current band, active penalties, last reason
- details drawer: all signal values and 1h timeline
- policy controls:
  - mode for high-risk workers: reject / redistribute / limited-allow
  - auto-action enable toggle
  - threshold sliders
- actions:
  - force allow for N minutes
  - force ban for N minutes
  - clear penalties

### 13.7 Audit Log Schema

For each enforcement decision:

- timestamp
- subject (address, worker, ip)
- score and band
- trigger metrics snapshot
- action applied
- operator/manual flag
- expiry time (if temporary)

### 13.8 DDoS Management (Panel-Controlled)

The Qt panel should expose explicit DDoS controls, not only passive metrics.

Detection signals:

- new_connections_per_sec (global and per-IP)
- handshake_fail_ratio_1m
- auth_fail_ratio_1m
- submit_rate_per_ip_10s
- malformed_request_rate_1m
- concurrent_sessions_per_ip
- banned_ips_growth_rate

Mitigation levels:

- Level 0 (Normal)
  - standard limits
- Level 1 (Elevated)
  - tighten per-IP connection burst limit
  - enable stricter request parsing and early drop
- Level 2 (High)
  - per-IP token-bucket rate limiting for submit/auth calls
  - temporary cooldown on repeated auth failures
  - lower max concurrent sessions per IP
- Level 3 (Critical)
  - challenge/allowlist mode for new connections
  - aggressive temporary bans on abusive IPs/subnets
  - prioritize existing long-lived healthy miners

Panel controls (Security/Abuse page):

- DDoS mode selector: auto / manual
- Active mitigation level selector (manual mode)
- Per-IP burst and sustained rate sliders
- Temporary ban TTL controls
- Trusted source allowlist editor (localhost/LAN/admin hosts)
- Emergency button: "shield mode" for immediate Level 3

Operational safeguards:

- Dry-run preview: show expected impact before applying stricter policy
- Rollback timer: auto-revert emergency settings after N minutes unless confirmed
- Minimum service guarantee: never block localhost admin channel
- Change journal entry for each DDoS policy change

Recommended backend additions for full control support:

- GET /ddos/status
- POST /ddos/mode              (auto|manual)
- POST /ddos/level             (0..3)
- POST /ddos/limits            (burst/sustained/session caps)
- POST /ddos/allowlist         (add/remove host or cidr)
- POST /ddos/shield            (enable/disable with ttl)

If these endpoints are not available initially, the panel should still provide
read-only DDoS telemetry from existing security stats and expose controls as
"planned/disabled" until server support lands.

## 14. Immediate Next Steps (Mining MVP)

1. Freeze MVP-1 endpoint contract only (/stratum_stats, /connected_miners, /miner_stats, /global_stats, /local_stats, /uptime, /ban_stats).
2. Scaffold Qt project under a new directory (for example ui/qt-control-panel).
3. Build Mining + Overview + minimal Logs first, with process controls.
4. Demo mining-start workflow before implementing payout/settings/console features.
