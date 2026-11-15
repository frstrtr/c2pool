# Scene engine (`dist/scene.js`)

One layout-agnostic engine for every animated tile view in c2pool's web
UI and its Qt embeds:
- the PPLNS treemap;
- the share-chain grid;
- a transaction treemap;
- the v37 roundabout map.

Layouts are plug-ins. The renderer sits behind a fixed instance-buffer
contract: Canvas2D now, with a GPU backend able to slot in later without
any change to the layouts or views.

```
view: data adapter ──items──▶ engine ──layout(items, viewport)──▶ tiles
                                │        style(tile) → colour+flags
                                ▼
                     instance buffer (56 B / tile, dirty ranges)
                                │
                  renderer.draw(now)  then  overlay.draw(labels)
```

A **view** is three parts:
- a data adapter (endpoint → `SceneItem[]`);
- a **layout**;
- a **style** function (colour and flags per tile, from the view's state).

Views on different engines link through a `SelectionBus` (hover, pin and search on a shared subject key such as a payout address).

## Engine behaviour

| | |
|---|---|
| Keyed tweens | A tile keeps its `key` across updates and layouts. It moves from where it is drawn *now* to its new rect and colour over `duration` (default 500 ms), eased with smootherstep. New keys grow and fade in from their centre. Vanished keys shrink, fade out, and then free their slot. |
| Retarget | A new target mid-flight starts from the interpolated current state, so there is never a jump. |
| Merged updates | `setItems()` during a tween is held (the latest wins) and applied when the tween ends: at most one data update per animation. `{immediate: true}` retargets at once. |
| Idle-stop | `requestAnimationFrame` runs only while something moves or a redraw was requested. |
| Resize | Snaps: no tween, and leaving tiles are dropped. |
| `setLayout()` | A keyed transition: the same keys tween from the old layout to the new one. LOD changes are layout swaps. |
| Time base | Records store `t0` as f32 milliseconds from an engine epoch. The epoch is rebased after an idle hour, so pages left open for days keep millisecond precision. |
| Hit-testing | Uses the placement of the **last drawn frame** while a tween runs (what is on screen, not a frame ahead). While idle it uses a cached placement, invalidated by any update, restyle or resize, so mousemove does not allocate. |

## Surfaces

The engine draws into a **container** element (`position: relative`, sized by the host) and adds its own canvases to it:
- **One canvas per renderer, always fresh.** A canvas that ever held a WebGL or WebGPU context returns `null` for `getContext('2d')`, so a fallback can never reuse it.
- **The text overlay** has its own canvas stacked on top (`pointer-events: none`). It never shares a surface with a GPU context and does not move when the renderer is swapped.
- **Pointer events.** Hosts bind them to the container, so handlers survive a renderer swap.

**Boot and swap:**
- The engine **always boots on Canvas2D** (synchronous, always available), so the page is never blank.
- A requested `renderer` (e.g. a GPU backend) is initialised on a new surface in the background. It replaces Canvas2D only if its `init` resolves. If `init` throws or rejects, the failure goes to `onError` and the scene stays on Canvas2D.
- On context loss, the engine initialises `fallbackRenderer()` (default Canvas2D) on a **new** surface, swaps it in, removes the lost surface and re-uploads every record.
- `swapRenderer(next)` does the same on request and rejects, keeping the current renderer, if `next` fails.
- **For a GPU backend author.** The engine registers `onContextLost` only after `init` resolves, when it installs the renderer. The backend must therefore own its `webglcontextlost` / `device.lost` listener from `init` onward, and fire the engine's callback even if the loss happened between `init` and install. It must also remove that listener in `dispose()`, so a disposed backend never triggers a fallback.

## Layout plug-in contract

```ts
interface Layout<D> {
  readonly id: string;
  layout(items: readonly SceneItem<D>[], viewport: Rect): Tile<D>[];
  hitTest?(tiles: readonly PlacedTile<D>[], x: number, y: number): PlacedTile<D> | null;
}
```

- **Pure.** No DOM, no clock, no state between calls. The same input gives the same output, and the input is never mutated.
- **Keys.** Output keys are unique. A key that is not an input key is a synthetic tile (an aggregate, e.g. "N others"), and it lists the items it stands for in `tile.items` with their summed `weight`.
- **Units.** Rects are in CSS px inside `viewport`.
- **Hit-testing** runs on the CPU over tiles *placed at the current instant* (interpolated with the renderer's easing), so a pointer hits what is drawn. The default is a reverse scan; a layout may supply a faster `hitTest`.
- **Tests.** Every layout ships `tests/unit/scene-layout-<id>.test.ts`, which proves this contract plus its own geometry.

| Layout | id | Status |
|---|---|---|
| `createTreemapLayout()` | `treemap` | Squarified (`src/pplns/squarify.ts`, minStrip 0), so each **cell** (the rect before the `gap` inset) has area ∝ weight. That is the weights gate. The drawn tile is the cell inset by `gap/2` per side, so a 4×4 cell draws 3×3. Small tiles therefore *look* smaller than their weight; hovers state the true %. Also "N others" aggregation (`othersFraction`, `minTileArea`), `expandOthers`, and an optional `scale: 'log'` (non-proportional, must be labelled). |
| grid | `grid` | P2 ("Fluid", replaces the inline defrag renderer). |
| roundabout | `roundabout` | P2 prototype, on the agreed v37 data model only. |

## Renderer contract

```ts
interface Renderer {
  readonly kind: string;                                   // 'canvas2d' | 'webgl2' | 'webgpu'
  init(canvas: HTMLCanvasElement): void | Promise<void>;   // may resolve later
  resize(cssWidth: number, cssHeight: number, dpr: number): void;
  upload(buffer: InstanceBuffer, dirty: readonly DirtyRange[]): void;
  draw(now: number): void;                                 // engine ms, same clock as t0
  onContextLost(cb: () => void): void;
  dispose(): void;
}
```

**Lifecycle:** `init(freshCanvas) → resize → (upload | draw)* → [contextLost] → dispose`.
- **init.** `init` receives a canvas created for this renderer alone; see Surfaces. It may be asynchronous: a GPU backend compiles shaders without blocking the page, and Canvas2D keeps drawing until init resolves.
- **Context loss.** On `webglcontextlost` or WebGPU `device.lost`, the backend calls the engine's callback. The engine moves to a fallback renderer on a fresh surface. Nothing on the page breaks.
- **dispose.** Releases GPU resources; the engine removes the surface.

**Instance record.** Fixed at 56 B: 14 × 4-byte words, little-endian, and the *same* layout for every backend:

| Word | Field | Type |
|---|---|---|
| 0–3 | from rect x, y, w, h | f32 |
| 4–7 | to rect x, y, w, h | f32 |
| 8 | from colour RGBA8 (memory bytes R, G, B, A) | u32 |
| 9 | to colour RGBA8 | u32 |
| 10 | t0 (ms, engine clock) | f32 |
| 11 | dur (ms; ≤ 0 = settled) | f32 |
| 12 | flags | u32 |
| 13 | pad (0) | u32 |

**Uploads and drawing:**
- The engine writes only records whose state changed. `upload()` receives those as half-open dirty ranges.
- When `buffer.generation` changes, the backing store was replaced (it grew), and a GPU backend must reallocate and re-upload everything.
- Records `[0, buffer.count)` are drawn in order. A record whose two colours both have alpha 0 is a free slot and is skipped.
- **The renderer evaluates motion itself.** Per record and per frame it computes `p = smootherstep(clamp((now − t0) / dur, 0, 1))`, with `dur ≤ 0` meaning `p = 1` (`easing.ts`). It then lerps the rect and each colour channel by `p`. The engine never pushes per-frame positions. A GPU backend does this in its vertex shader with exactly this formula, because CPU hit-testing uses it too.

**Flags (word 12).** Applied instantly, never tweened, and with the same meaning in every backend:

| Bit | Name | Drawn as |
|---|---|---|
| 0 | `FLAG_DIM` | alpha × `DIM_ALPHA` (0.25) |
| 1 | `FLAG_SELECTED` | thin light outline (hover here or in a linked view) |
| 2 | `FLAG_PINNED` | thick light outline |
| 3 | `FLAG_MATCH` | amber outline (search match) |
| 8–15 | kind | `TileKind`: 0 plain, 1 ★ this node, 2 ⚑ owner fee, 3 ◇ donation, 4 ▣ off-chain block share, 5 "N others". Renderers may ignore it; the text overlay draws the marks. |

## Text overlay contract

```ts
interface TextOverlay {
  resize(cssWidth: number, cssHeight: number, dpr: number): void;
  draw(labels: readonly Label[]): void;    // replaces the previous labels
  dispose(): void;
}
```

Labels, axes and marks are a separate 2D pass drawn *after* the tiles, never by the quad renderer.
- With the Canvas2D renderer, the overlay shares the scene canvas.
- With a GPU renderer, it draws on a 2D canvas stacked above.

Each frame the engine passes the view's `labels(placedTiles)` for the tiles as placed at that instant, so labels follow moving tiles.

## Views

| View | Mount | Notes |
|---|---|---|
| PPLNS treemap (`views/pplns-treemap.ts` + pure `views/pplns-model.ts`) | `mountPplnsTreemap({ container, symbol, mergedSymbol?, bus?, special?, facts?, addressUrl? })`, then `view.update({ payouts, merged }, special?)` | See below. |

**PPLNS treemap.**
- **Data.** Tile weight = `/current_payouts`, i.e. what the payout code pays. Merged children come from `/current_merged_payouts`. In merged mode the same keys (parent addresses) are re-weighted by their child amount, so the toggle tweens each miner in place.
- **"% of miner payouts"** divides by the sum of `/current_payouts`. It never uses `/local_stats` `block_value_miner`, which on a relay is a projection without fees.
- **Special tiles.** ★ = addresses this node's stratum serves (`/stratum_stats` workers, the key up to the first `.`). ⚑ = an explicit owner address, or a tile whose hash160 equals the window's `fee_hash160`. ◇ = an explicit donation address only. Nothing is inferred from address prefixes.
- **Interaction.** Hover shows the tooltip and lights the miner in linked views. Click pins and Esc unpins. Clicking "N others" lays the small miners out. Ctrl/⌘-click opens the address explorer. Search dims non-matching tiles. The opt-in log scale carries a "not proportional" badge.
- **dashboard.html** mounts it in `#pplns-main-grid` behind `?pplns-view=1` (or `localStorage c2p_pplns_view=1`), and links it to the share-chain grid through one `SelectionBus`. A pinned miner, or one hovered in the treemap, keeps full colour in the grid; the rest dim.

## Budgets and hosts

- `dist/scene.js` is the base bundle, an ESM entry built by `esbuild.config.mjs`. Its budget is 120 KB in `size.config.json`, enforced by `npm run size` in Web-static verify.
- A GPU backend ships as its own lazily loaded chunk with its own budget (≤ 24 KB minified / ≤ 9 KB gzip). The Qt embeds never fetch it: Qt WebEngine has neither WebGPU nor a software GL, so Canvas2D is mandatory there.
- The inline pages load `dist/scene.js` with a content-hash stamp (`npm run stamp`). The Qt embeds load it from `qrc:/`.
- The engine is our own implementation. Third-party libraries, if any are ever added, must be MIT, ISC or BSD.
