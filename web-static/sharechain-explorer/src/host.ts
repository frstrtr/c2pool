// Host runtime (plugin-arch §2, §8).
// Owns lifecycle, registry, events, middleware chain, logger.
// destroy() is async (M1 D3): synchronous DOM/handler/timer cleanup
// runs before the first await; returned promise tracks pending Transport
// work so tests can fence "no activity after destroy".

import { EventBus } from './events.js';
import { internal, isExplorerError, type ExplorerError } from './errors.js';
import { PendingTracker } from './abort.js';
import {
  PluginRegistry,
  SDK_VERSION,
  resolveOrder,
  type HostFacade,
  type Logger,
  type PluginDescriptor,
  type SlotSpec,
} from './registry.js';
import { applyMiddleware, type TransportMiddleware } from './middleware.js';
import type { Transport } from './transport/types.js';

export type HostKind = 'explorer' | 'pplns-view' | 'shared-core';

export interface HostInitOptions {
  kind: HostKind;
  transport?: Transport;
  logger?: Logger;
  /** Per-plugin config, keyed by plugin id. `false` disables the plugin. */
  plugins?: Record<string, Record<string, unknown> | false>;
  /** Force-enable even if a plugin's `disabled` default was true. */
  enabled?: readonly string[];
  /** Force-disable. Critical slots will fail init if unfilled. */
  disabled?: readonly string[];
  /** Explicit capability providers. Overrides priority. */
  capabilities?: Record<string, string>;
  /** Activation timeout per plugin in ms (default 5000). */
  activateTimeoutMs?: number;
}

export class Host implements HostFacade {
  readonly kind: HostKind;
  readonly sdkVersion = SDK_VERSION;
  readonly registry = new PluginRegistry();
  readonly events = new EventBus();
  readonly logger: Logger;

  private wrappedTransport?: Transport;
  private capabilityConfig: Record<string, string> = {};
  private disabledSet = new Set<string>();
  private active: PluginDescriptor[] = [];
  private readonly pending = new PendingTracker();
  private readonly destroyController = new AbortController();
  private _destroyed = false;
  private _initialized = false;

  constructor(kind: HostKind, logger?: Logger) {
    this.kind = kind;
    this.logger = logger ?? consoleLogger();
  }

  get transport(): Transport | undefined {
    return this.wrappedTransport;
  }

  get destroyed(): boolean {
    return this._destroyed;
  }

  get signal(): AbortSignal {
    return this.destroyController.signal;
  }

  async init(options: HostInitOptions): Promise<void> {
    if (this._initialized) throw new Error('Host.init called twice');
    if (this._destroyed) throw new Error('Host.init on a destroyed host');
    this._initialized = true;

    this.capabilityConfig = options.capabilities ?? {};
    this.disabledSet = new Set(options.disabled ?? []);

    // ── Resolve active plugin set ─────────────────────────────────
    const all = this.registry.list();
    const enabledSet = new Set(options.enabled ?? []);
    const pluginConfig: Record<string, Record<string, unknown> | false> =
      options.plugins ?? {};
    const active = all.filter((p) => {
      if (this.disabledSet.has(p.id)) return false;
      if (pluginConfig[p.id] === false && !enabledSet.has(p.id)) return false;
      return true;
    });

    const ordered = resolveOrder(active);
    this.active = ordered;

    // ── Wrap transport with registered middleware chain ───────────
    if (options.transport !== undefined) {
      const mwPlugins = this.registry.transportMiddleware().filter((p) =>
        !this.disabledSet.has(p.id) && pluginConfig[p.id] !== false,
      );
      const middlewares: TransportMiddleware[] = mwPlugins
        .map((p) => (p.request ? { id: p.id, request: p.request.bind(p) } : null))
        .filter((x): x is TransportMiddleware => x !== null);
      this.wrappedTransport = applyMiddleware(options.transport, middlewares);
    }

    // ── Check required slots have fillers (after disable filtering) ───
    for (const [slotName, spec] of this.registry.slotsDefined()) {
      if (!spec.required) continue;
      const fillers = this.registry.slotFillers(slotName)
        .filter((p) => !this.disabledSet.has(p.id) && pluginConfig[p.id] !== false);
      if (fillers.length === 0) {
        throw internal(`required slot unfilled: ${slotName}`);
      }
      if (!spec.multiple && fillers.length > 1) {
        throw internal(`slot ${slotName} allows only one filler; got ${fillers.length}`);
      }
    }

    const timeoutMs = options.activateTimeoutMs ?? 5000;

    // ── init phase ────────────────────────────────────────────────
    for (const p of ordered) {
      if (!p.init) continue;
      const cfgRaw = pluginConfig[p.id];
      const cfg = cfgRaw ? { ...p.defaultConfig, ...cfgRaw } : p.defaultConfig;
      await this.runWithTimeout(
        Promise.resolve(p.init(this, cfg)),
        timeoutMs,
        `plugin.init ${p.id}`,
      );
    }

    // ── activate phase ────────────────────────────────────────────
    for (const p of ordered) {
      if (!p.activate) continue;
      const ctx = {
        host: this as HostFacade,
        signal: this.destroyController.signal,
        ...(p.slots?.[0] !== undefined ? { slot: p.slots[0] } : {}),
      };
      try {
        await this.runWithTimeout(
          Promise.resolve(p.activate(ctx)),
          timeoutMs,
          `plugin.activate ${p.id}`,
        );
      } catch (err) {
        this.logger.error('plugin activate failed', { id: p.id, err });
        this.events.emit('plugin:error', { id: p.id, phase: 'activate', err });
      }
    }

    this.events.emit('host:init:complete', { kind: this.kind });
  }

  /** Capability resolution honouring explicit config (M1 D4). */
  resolveCapability(name: string): PluginDescriptor | undefined {
    const explicit = this.capabilityConfig[name];
    return this.registry.capabilities(name, explicit)[0];
  }

  /** Tracks an async operation so destroy() can await it. */
  track<T>(p: Promise<T>): Promise<T> {
    return this.pending.track(p);
  }

  async destroy(): Promise<void> {
    if (this._destroyed) return;
    this._destroyed = true;
    this.events.emit('host:destroy:start', {});

    // Synchronous cleanup BEFORE any await (M1 D3).
    this.destroyController.abort();

    // Reverse-order deactivate + destroy hooks.
    for (let i = this.active.length - 1; i >= 0; i--) {
      const p = this.active[i];
      if (!p?.deactivate) continue;
      try {
        await Promise.resolve(p.deactivate());
      } catch (err) {
        this.logger.error('plugin deactivate failed', { id: p.id, err });
      }
    }
    for (let i = this.active.length - 1; i >= 0; i--) {
      const p = this.active[i];
      if (!p?.destroy) continue;
      try {
        await Promise.resolve(p.destroy());
      } catch (err) {
        this.logger.error('plugin destroy failed', { id: p.id, err });
      }
    }

    // Wait for in-flight Transport requests to settle.
    await this.pending.settled();

    this.events.emit('host:destroy:complete', {});
    this.events.dispose();
  }

  private async runWithTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(internal(`${label} timed out after ${ms}ms`)),
        ms,
      );
    });
    try {
      return await Promise.race([p, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /** Emit a structured error on the bus without throwing. */
  emitError(err: ExplorerError | unknown): void {
    const e = isExplorerError(err) ? err : internal('unknown error', err);
    this.events.emit('error', e);
  }
}

function consoleLogger(): Logger {
  /* eslint-disable no-console */
  const fmt = (level: string, msg: string, ctx?: Record<string, unknown>) =>
    ctx ? console.log(`[${level}] ${msg}`, ctx) : console.log(`[${level}] ${msg}`);
  return {
    debug: (m, c) => fmt('debug', m, c),
    info:  (m, c) => fmt('info',  m, c),
    warn:  (m, c) => fmt('warn',  m, c),
    error: (m, c) => fmt('error', m, c),
  };
  /* eslint-enable no-console */
}
