// Public API surface for the SharedCore / @c2pool/shared-core bundle.
// Everything exported here is part of the stable SDK (D1, D4, D12).
// Breaking changes require a major SDK version bump.

export { Host, type HostKind, type HostInitOptions } from './host.js';
export {
  PluginRegistry,
  SDK_VERSION,
  satisfiesSdk,
  resolveOrder,
  type PluginDescriptor,
  type PluginKind,
  type Permission,
  type SlotSpec,
  type ActivationContext,
  type HostFacade,
  type Logger,
} from './registry.js';
export {
  EventBus,
  type Handler,
  type Unsubscribe,
} from './events.js';
export {
  applyMiddleware,
  buildChain,
  type MiddlewareRequest,
  type Next,
  type TransportMiddleware,
} from './middleware.js';
export {
  type Transport,
  type TransportKind,
  type TransportOp,
  TRANSPORT_OPS,
  type RequestOptions,
  type TipEvent,
  type NegotiateResult,
  type StreamSubscription,
} from './transport/types.js';
export {
  createHttpTransport,
  type HttpTransportOptions,
} from './transport/http.js';
export {
  type ExplorerError,
  isExplorerError,
  internal,
  schemaError,
} from './errors.js';
export {
  validate,
  type Schema,
  type JsonType,
  type ValidationResult,
} from './schema.js';
export {
  PendingTracker,
  type Disposable,
} from './abort.js';

// ── Baseline middleware (plugin-arch §7.1) ─────────────────────────
export { LoggingMiddleware, type LoggingConfig } from './middleware/logging.js';
export { AuthMiddleware, type AuthConfig } from './middleware/auth.js';
export { RetryMiddleware, type RetryConfig } from './middleware/retry.js';
export { CacheMiddleware, type CacheConfig } from './middleware/cache.js';
export { TimeoutMiddleware, type TimeoutConfig } from './middleware/timeout.js';
export { ErrorTaxonomyMiddleware } from './middleware/error-taxonomy.js';

// ── Baseline SharedCore plugins (plugin-arch §12.1) ────────────────
export { ThemeDarkPlugin, DARK_THEME, type ThemeDescriptor } from './plugins/theme-dark.js';
export {
  TreemapSquarifiedPlugin,
  squarify,
  type TreemapItem,
  type TreemapRect,
  type SquarifyFn,
} from './plugins/treemap-squarified.js';
export {
  AddrHuePlugin,
  addrHue,
  addrHsl,
  type AddrHueFn,
  type HslTriple,
} from './plugins/addr-hue.js';
export {
  ShortHashPlugin,
  shortHash,
  type ShortHashFn,
} from './plugins/short-hash.js';
export {
  HashrateSiPlugin,
  formatHashrate,
  type HashrateFormatter,
} from './plugins/hashrate-si.js';
export {
  SparklineSvgPlugin,
  renderSparkline,
  type SparklineOptions,
} from './plugins/sparkline-svg.js';
export {
  TooltipDefaultPlugin,
  createTooltip,
  type Tooltip,
  type TooltipOptions,
} from './plugins/tooltip-default.js';
export {
  AriaLiveLogPlugin,
  createAnnouncer,
  type Announcer,
  type AnnouncerOptions,
} from './plugins/aria-live-log.js';
export {
  I18nEnPlugin,
  EN_CATALOG,
  translate,
  type I18nCatalog,
} from './plugins/i18n-en.js';
export {
  HttpTransportPlugin,
  type TransportFactory,
} from './plugins/http-transport.js';

// ── Baseline registration ──────────────────────────────────────────
import type { Host } from './host.js';
import { LoggingMiddleware as _log } from './middleware/logging.js';
import { AuthMiddleware as _auth } from './middleware/auth.js';
import { RetryMiddleware as _retry } from './middleware/retry.js';
import { CacheMiddleware as _cache } from './middleware/cache.js';
import { TimeoutMiddleware as _timeout } from './middleware/timeout.js';
import { ErrorTaxonomyMiddleware as _et } from './middleware/error-taxonomy.js';
import { ThemeDarkPlugin as _theme } from './plugins/theme-dark.js';
import { TreemapSquarifiedPlugin as _tree } from './plugins/treemap-squarified.js';
import { AddrHuePlugin as _hue } from './plugins/addr-hue.js';
import { ShortHashPlugin as _sh } from './plugins/short-hash.js';
import { HashrateSiPlugin as _hr } from './plugins/hashrate-si.js';
import { SparklineSvgPlugin as _sp } from './plugins/sparkline-svg.js';
import { TooltipDefaultPlugin as _tt } from './plugins/tooltip-default.js';
import { AriaLiveLogPlugin as _aria } from './plugins/aria-live-log.js';
import { I18nEnPlugin as _i18n } from './plugins/i18n-en.js';
import { HttpTransportPlugin as _http } from './plugins/http-transport.js';

/** Convenience: register every baseline middleware + plugin on a Host.
 *  Individual items can be disabled via `init({ disabled: ['id'] })`. */
export function registerBaseline(host: Host): void {
  // Middleware (order determines chain position; priority on each plugin)
  host.registry.register(_log);
  host.registry.register(_auth);
  host.registry.register(_retry);
  host.registry.register(_cache);
  host.registry.register(_timeout);
  host.registry.register(_et);
  // Plugins
  host.registry.register(_theme);
  host.registry.register(_tree);
  host.registry.register(_hue);
  host.registry.register(_sh);
  host.registry.register(_hr);
  host.registry.register(_sp);
  host.registry.register(_tt);
  host.registry.register(_aria);
  host.registry.register(_i18n);
  host.registry.register(_http);
}
