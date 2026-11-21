// dist/scene.js — the universal scene engine (see README.md here).
// One layout-agnostic engine; layouts are plug-ins; the renderer is
// replaceable (Canvas2D now, a GPU backend later) behind a fixed
// instance-buffer contract.

export { createScene } from './engine.js';
export type { Scene, SceneOptions, FrameScheduler } from './engine.js';

export { createTreemapLayout, DEFAULT_OTHERS_KEY } from './layouts/treemap.js';
export type { TreemapOptions } from './layouts/treemap.js';

export { createCanvas2DRenderer, createCanvas2DTextOverlay } from './canvas2d.js';
export type { Canvas2DOptions, Ctx2D } from './canvas2d.js';

export {
  FLAG_DIM, FLAG_SELECTED, FLAG_PINNED, FLAG_MATCH, DIM_ALPHA,
  KIND_SHIFT, KIND_MASK, TileKind, withKind, kindOf,
} from './renderer.js';
export type { Renderer, TextOverlay, TileKindValue } from './renderer.js';

export {
  InstanceBuffer, RECORD_BYTES, RECORD_WORDS,
  W_FROM_X, W_FROM_Y, W_FROM_W, W_FROM_H, W_TO_X, W_TO_Y, W_TO_W, W_TO_H,
  W_FROM_RGBA, W_TO_RGBA, W_T0, W_DUR, W_FLAGS, W_PAD,
} from './instance-buffer.js';
export type { DirtyRange, RecordState } from './instance-buffer.js';

export { smootherstep, progress, lerp } from './easing.js';
export { rgba, hsl, withAlpha, lerpRgba, toCss, red, green, blue, alpha } from './colour.js';
export { createSelectionBus, matchesQuery } from './selection.js';
export type { SelectionBus, SelectionState } from './selection.js';

export type { Rect, SceneItem, Tile, PlacedTile, Layout, TileStyle, Label } from './types.js';

// Views on the engine.
export { mountPplnsTreemap, tooltipHtml } from './views/pplns-treemap.js';
export type { PplnsTreemap, PplnsTreemapOptions } from './views/pplns-treemap.js';
export {
  buildPplnsItems, classifyAddress, addressesFromWorkers, parentAmountMismatches,
  pplnsStyle, pplnsLabels, tooltipLines, addrHue, shortAddress, formatAge,
} from './views/pplns-model.js';
export type {
  PplnsSnapshot, PplnsMode, CurrentPayouts, CurrentMergedPayouts, MergedChild,
  SpecialAddresses, MinerDatum, MinerFacts, TooltipLine,
} from './views/pplns-model.js';
export { hash160OfAddress } from './views/address-hash.js';
export { loadPplnsSnapshot, mergedSymbolOf, coalesce } from './views/pplns-feed.js';
export type { PayoutSource, LoadedSnapshot } from './views/pplns-feed.js';
export { createGridLayout } from './layouts/grid.js';
export type { GridOptions, GridLayoutPlugin } from './layouts/grid.js';
export { mountSharechainGrid, parseCssColor, hourAxisLabels, keyOfShare, BLOCK_MARK } from './views/sharechain-grid.js';
export type { SharechainGrid, SharechainGridOptions, GridShare, BlockKind } from './views/sharechain-grid.js';
export { OFF_CHAIN_FILL, OFF_CHAIN_MARK } from './views/sharechain-grid.js';
export { offChainBlocks, withOffChainCells, offChainLines, isOffChainCell, safeExplorerUrl } from './views/offchain.js';
export type { BlockRow, OffChainCell } from './views/offchain.js';
