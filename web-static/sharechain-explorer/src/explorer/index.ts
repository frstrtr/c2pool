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

// Convenience: register every Explorer baseline plugin on a host.
import type { Host } from '../host.js';
import { registerBaseline as registerSharedBaseline } from '../index.js';
import { GridLayoutPlugin as _grid } from './grid-layout.js';

/** Register SharedCore baseline plus Explorer-specific plugins. */
export function registerExplorerBaseline(host: Host): void {
  registerSharedBaseline(host);
  host.registry.register(_grid);
}
