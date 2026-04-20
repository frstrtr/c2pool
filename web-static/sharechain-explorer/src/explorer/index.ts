// Public API for the Sharechain Explorer bundle (@c2pool/sharechain-explorer).
// Re-exports SharedCore so a single <script src="sharechain-explorer.js">
// is self-sufficient — browsers with no module loader only load one file.
// Future externalization (separate shared-core.js load) is a build-time
// toggle in esbuild.config.mjs.

export * from '../index.js';

// Explorer-specific plugins + primitives
export {
  GridLayoutPlugin,
  computeGridLayout,
  cellPosition,
  cellAtPoint,
  iterCells,
  type GridLayoutOptions,
  type GridLayout,
  type CellPosition,
} from './grid-layout.js';
export {
  ColorsPlugin,
  classifyShare,
  getColor,
  LTC_COLOR_PALETTE,
  type ColorPalette,
  type ShareForClassify,
  type ShareClass,
  type UserContext,
  type StaleInfo,
} from './colors.js';
export {
  GridCanvasPlugin,
  buildPaintProgram,
  buildAnimatedPaintProgram,
  executePaintProgram,
  createGridRenderer,
  type PaintCommand,
  type BuildPaintOptions,
  type GridRenderer,
  type CanvasLike,
} from './grid-paint.js';
export {
  ColorUtilsPlugin,
  parseHexColor,
  lerpColor,
  applyAlpha,
  lerpColorWithAlpha,
  type Rgb,
} from './color-utils.js';
export {
  RealtimePlugin,
  RealtimeOrchestrator,
  createRealtime,
  type RealtimeConfig,
  type RealtimeDOMOptions,
  type RealtimeController,
  type RealtimeState,
  type RealtimeStats,
  type LayoutParams,
} from './realtime.js';
export {
  PPLNSPlugin,
  parsePPLNS,
  type PPLNSEntry,
} from './pplns.js';
export {
  HoverZoomPlugin,
  buildHoverZoomProgram,
  createHoverZoomPanel,
  type HoverZoomBuildOptions,
  type HoverZoomPanel,
  type HoverZoomPanelOptions,
  type HoverZoomShare,
} from './hover-zoom.js';
export {
  DeltaMergerPlugin,
  mergeDelta,
  type DeltaShare,
  type WindowSnapshot,
  type DeltaPayload,
  type MergeOptions,
  type MergeResult,
} from './delta.js';
export {
  AnimatorPlugin,
  buildAnimationPlan,
  createAnimationController,
  computePhaseTiming,
  easeInOut,
  lerp,
  clamp01,
  SKIP_ANIMATION_NEW_COUNT_THRESHOLD,
  type AnimationInput,
  type AnimationPlan,
  type AnimationController,
  type AnimTrack,
  type CellFrame,
  type FrameSpec,
  type PhaseTiming,
} from './animator.js';

// Convenience: register every Explorer baseline plugin on a host.
import type { Host } from '../host.js';
import { registerBaseline as registerSharedBaseline } from '../index.js';
import { GridLayoutPlugin as _grid } from './grid-layout.js';
import { ColorsPlugin as _colors } from './colors.js';
import { GridCanvasPlugin as _canvas } from './grid-paint.js';
import { DeltaMergerPlugin as _delta } from './delta.js';
import { AnimatorPlugin as _anim } from './animator.js';
import { ColorUtilsPlugin as _cu } from './color-utils.js';
import { RealtimePlugin as _rt } from './realtime.js';
import { PPLNSPlugin as _pplns } from './pplns.js';
import { HoverZoomPlugin as _hover } from './hover-zoom.js';

/** Register SharedCore baseline plus Explorer-specific plugins. */
export function registerExplorerBaseline(host: Host): void {
  registerSharedBaseline(host);
  host.registry.register(_grid);
  host.registry.register(_colors);
  host.registry.register(_canvas);
  host.registry.register(_delta);
  host.registry.register(_anim);
  host.registry.register(_cu);
  host.registry.register(_rt);
  host.registry.register(_pplns);
  host.registry.register(_hover);
}
