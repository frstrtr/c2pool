# Visual regression — dashboard.html pixel-diff harness

Compares the **inline** Explorer in `dashboard.html` with the **bundled**
version (the `?new-explorer=1` flag path) rendering against identical
mock c2pool endpoints. Implements the Explorer spec §11 / Plugin SDK
§16.1 pixel-diff gate anchored by the `explorer-baseline-v0` tag.

## Design

1. **Fixtures** (`fixtures/generate.mjs`): seeded mulberry32 RNG emits
   deterministic JSON for `/sharechain/window`, `/sharechain/tip`,
   `/sharechain/stats`, `/current_merged_payouts`. 200 shares across
   the full V36-native / V35→V36 / V35-legacy / stale / dead / fee /
   block mix; one miner is `XMINEADDRESS` so "mine" colours appear.

2. **Mock server** (`mock-server.mjs`): serves the fixtures + the
   `web-static/` tree on localhost. Implements the minimum dashboard-
   consumed endpoints (empty replies for non-Explorer endpoints so
   dashboard.html doesn't error-cascade). `/sharechain/stream` is a
   keep-alive-only SSE — no tips fired during the capture window so
   animations don't distort the screenshot.

3. **Capture** (`capture.mjs`): puppeteer-core against system Chrome
   (`/usr/bin/google-chrome` by default; override via `CHROME_BIN`).
   Launches headless, loads `dashboard.html` twice:
   - without the flag → `out/inline.png`
   - with `?new-explorer=1` → `out/bundled.png`
   Both screenshots clip to `#sharechain-section`. Viewport fixed at
   1280×900, `deviceScaleFactor=1`, font-hinting off.

4. **Diff** (`diff.mjs`): pixelmatch between the two screenshots,
   writes `out/diff.png`, reports delta fraction, exits non-zero when
   over threshold (default 0.02 = 2%).

## Run

```bash
npm run visual                  # fixtures + server + capture + diff
npm run visual -- THRESHOLD=0.05   # looser cutoff
CHROME_BIN=/snap/bin/chromium npm run visual
```

Outputs land in `tests/visual/out/`:

```
inline.png        inline-mode screenshot
bundled.png       ?new-explorer=1 screenshot
diff.png          red-highlighted pixel diff
mock-server.log   server stdout/stderr
```

## Measured state (2026-04-20, explorer-module HEAD)

Current inline-vs-bundled delta on the 200-share fixture screenshot
of `#defrag-canvas`:

```
diff pixels: 0 / 34960 (0.000%)
threshold:   0.50%   (default — set via env THRESHOLD)
→ PASS
```

Pixel-byte-identical. All earlier "tighten later" items landed:

1. ✓ **my_address auto-adoption** — RealtimeOrchestrator reads
   `my_address` from `/sharechain/window` when the caller didn't
   supply one, matching inline dashboard.html:4624
   (`_effectiveUserContext` in `src/explorer/realtime.ts`).
2. ✓ **Block-cell borders** — CellFrame.stroke carries a
   `{color, lineWidth}` overlay; buildStaticFrame + the animator
   wave track emit LTC gold, DOGE cyan, twin orange per
   dashboard.html:4759-4775. Twin also overrides the fill to
   `#ff8000`.
3. ✓ **Tip-marker triangle** — CellFrame.tipMark drives a
   `fillTriangle` paint command on the tip share's top-left
   corner, suppressed when the tip is also a block
   (dashboard.html:4778-4787).
4. ✓ **Hour-axis labels + tick lines** — `buildHourAxis` in
   realtime.ts walks each row, labels hour-boundary transitions
   with `Xh` (right-aligned in the left margin) and draws
   0.5-px rgba(140,140,180,0.2) strokes across the grid
   (dashboard.html:4705-4740). Requires shares to carry `t`
   (unix seconds).

Threshold default is **0.5%** — comfortable margin for OS /
anti-aliasing / font-rendering noise when CI runs on different
hardware. Tighten to **0.1%** if stricter parity becomes
necessary.

## CI

Not wired to CI yet. Phase 2 of the repo strategy (sibling
`explorer-modules` repo) is where this becomes a blocking gate — per
`frstrtr/the/docs/c2pool-explorer-repo-strategy.md` §5.2. In phase 1
(monolithic inside c2pool), `npm run visual` is an opt-in contributor
tool.

## Baseline tag

`explorer-baseline-v0` on c2pool `master` @ `d95779af` (2026-04-19)
anchors the pre-extraction reference implementation. Extraction work
on branch `explorer-module` must not regress measurable pixels against
that anchor in **inline-mode** (flag off). Bundled-mode (flag on) is
the diff target against *inline at the same fixture* — it's a parity
measurement, not an anchor.
