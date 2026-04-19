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

// Baseline middleware + plugins shipped with SharedCore.
export { ErrorTaxonomyMiddleware } from './middleware/error-taxonomy.js';
export { ThemeDarkPlugin, DARK_THEME, type ThemeDescriptor } from './plugins/theme-dark.js';

/** Convenience: attach the default-shipped baseline to a Host's registry. */
import type { Host } from './host.js';
import { ErrorTaxonomyMiddleware as _etm } from './middleware/error-taxonomy.js';
import { ThemeDarkPlugin as _tdp } from './plugins/theme-dark.js';

export function registerBaseline(host: Host): void {
  host.registry.register(_etm);
  host.registry.register(_tdp);
}
