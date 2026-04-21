# @c2pool/sharechain-explorer

Pluggable sharechain explorer + PPLNS view modules on a shared plugin
SDK. Phase-1 monolith inside `c2pool/web-static/` per the design
baseline in `frstrtr/the/docs/c2pool-explorer-repo-strategy.md`.

## Directory

```
sharechain-explorer/
├── src/                           TypeScript source
│   ├── shared-core (top-level)    plugin SDK: registry, slots,
│   │                              capabilities, events, middleware
│   │                              chain, host lifecycle, transport
│   │                              interface, HttpTransport, error
│   │                              taxonomy, hand-rolled schema
│   │                              validator. Plus baseline:
│   │                              6 transport middleware + 10 plugins.
│   └── explorer/                  Explorer-specific:
│                                  grid layout, colours, canvas
│                                  renderer, delta merger, animator,
│                                  colour utils, Realtime orchestrator.
├── tests/unit/                    Node-native tests (node --test)
├── dist/                          built bundles (committed at phase 1)
│   ├── shared-core.js             40 KB budget (currently ~25 KB)
│   └── sharechain-explorer.js     120 KB budget (currently ~42 KB)
├── schemas/                       JSON-Schemas per M1 D6
├── demo/                          synthetic-data demo
│   ├── demo.html                  deterministic RNG, no server
│   └── demo.mjs
├── dashboard-bundled.html         live test surface against a real
│                                  c2pool server (see below)
├── dashboard-bundled.mjs
├── resources-manifest.json        bundle file list + SRI (M1 D11)
├── size.config.json               bundle-size budgets
└── scripts/
    ├── emit-manifest.mjs
    └── check-bundle-size.mjs
```

## Scripts

```bash
npm run typecheck    # strict TS, exactOptionalPropertyTypes, etc.
npm run build        # esbuild → dist/*.js (production, minified)
npm run build:dev    # esbuild → dist/*.js with inline sourcemaps
npm test             # Node --test (no jest, no vitest)
npm run manifest     # regenerate resources-manifest.json
npm run size         # bundle-size gate
npm run verify       # typecheck + build + test + manifest + size
```

## Three surfaces for visual verification

The bundle ships three HTML entry points, each serving a different
stage of the M2 extraction discipline.

### 1. Synthetic demo — `demo/demo.html`

Deterministic synthetic share generator (seeded mulberry32 RNG).
No c2pool server required. Proves plugins compose end-to-end and
gives a stable target for future visual regression.

```bash
npm run build
python3 -m http.server 8080
# open http://localhost:8080/demo/demo.html
```

### 2. Live bundled — `dashboard-bundled.html`

Parallel A/B surface wired against a real c2pool server via
`HttpTransport`. Operators run it in a separate browser tab
alongside the production `dashboard.html` to visually compare
the bundled pipeline against the inline renderer. **Production
`dashboard.html` stays untouched** until parity is verified —
spec §11 migration discipline.

```bash
# serve web-static/ through c2pool itself, or:
python3 -m http.server 8080
# open http://localhost:8080/sharechain-explorer/dashboard-bundled.html
```

URL parameters:
- `?base=http://127.0.0.1:8080` — set c2pool base URL.
- `?addr=XMyAddress` — set "mine" address so mine-variant colours
  show.
- `?autoconnect=0` — don't auto-connect on load (for debugging).
- `?fast=1` — enable fast animation mode.

Persists base URL + my-address in `localStorage` under
`c2p-bundled-prefs` so operators don't retype on reload.

Exposes `window.__explorer` (the `RealtimeController`) for devtools
poking: `__explorer.getState()`, `__explorer.refresh()`, etc.

### 3. Production dashboard — `web-static/dashboard.html`

Untouched. Current inline-renderer flow. Remains the reference
implementation until pixel-diff parity is confirmed against (2).

The M2 swap-in — replacing the inline renderer with a
`<script type="module">` import of the bundle — is a later commit
and runs behind a query-string feature flag for safe rollout.

## Contract + specs

Authoritative documents live in `frstrtr/the/docs/`:

- `c2pool-sharechain-explorer-module-task.md` — Explorer spec
- `c2pool-pplns-view-module-task.md` — PPLNS View spec
- `c2pool-explorer-plugin-architecture.md` — plugin SDK
- `c2pool-sharechain-explorer-spec-delta-v1.md` — hardening
- `c2pool-explorer-repo-strategy.md` — phased distribution
- `c2pool-qt-hybrid-architecture.md` — Qt desktop decision
- `c2pool-qt-desktop-settings-module.md` — Qt native-shell
- `c2pool-explorer-m1-signoff.md` — M1 architecture decisions

## Status

Phase A + Phase B through #7 shipped. Remaining Phase B: particles +
card overlays (cosmetic polish). Phase B #7 (Realtime) was the
critical path — after this commit, the bundle is operationally
equivalent to `dashboard.html`'s Explorer pipeline modulo the
polish items.
