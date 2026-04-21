# Explorer demo

Synthetic sharechain running against the real bundle — proof that
Explorer plugins compose end-to-end without a c2pool server.

## Run

```bash
cd web-static/sharechain-explorer
npm run build              # produces dist/
python3 -m http.server 8080
# open http://localhost:8080/demo/demo.html
```

A plain `file://` open won't work — ES module imports require a real
HTTP origin. Any static server (python, `npx serve`, nginx) is fine.

## What it exercises

- `Host` lifecycle (init + destroy)
- `registerExplorerBaseline` — 15 plugins registered in one call
- `computeGridLayout` — cols/rows math against live containerWidth
- `createGridRenderer` — canvas DPR handling + paint program
- `getColor` — every LTC palette branch (dead, stale, unverified,
  fee, native, signaling, legacy, plus "mine" variants)
- `cellAtPoint` — live hover hit-testing on mousemove

## Deterministic seed

The synthetic RNG is seeded at `42`. Reloading the page shows the
same grid every time — suitable for pixel-regression baseline
capture once Phase B lands visual CI.

## Exposed globals

`window.__demo` exposes the Host, renderer, current share array, and
a paint() reference for devtools poking.

## Phase status

Demo at this stage renders only the static grid + hover highlight.
Real-time updates (delta + SSE) land in Phase B #3; animations
(death/wave/birth) land in Phase B #4. See
`frstrtr/the/docs/c2pool-sharechain-explorer-module-task.md` for the
full milestone map.
