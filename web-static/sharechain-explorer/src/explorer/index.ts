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
  executePaintProgram,
  createGridRenderer,
  type PaintCommand,
  type BuildPaintOptions,
  type GridRenderer,
  type CanvasLike,
} from './grid-paint.js';

// Convenience: register every Explorer baseline plugin on a host.
import type { Host } from '../host.js';
import { registerBaseline as registerSharedBaseline } from '../index.js';
import { GridLayoutPlugin as _grid } from './grid-layout.js';
import { ColorsPlugin as _colors } from './colors.js';
import { GridCanvasPlugin as _canvas } from './grid-paint.js';

/** Register SharedCore baseline plus Explorer-specific plugins. */
export function registerExplorerBaseline(host: Host): void {
  registerSharedBaseline(host);
  host.registry.register(_grid);
  host.registry.register(_colors);
  host.registry.register(_canvas);
}
