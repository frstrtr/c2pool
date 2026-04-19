// Plugin registry, slot + capability system (plugin-arch §§3–5, M1 D4).
// - Slots with `multiple` cardinality sort by priority desc, id asc.
// - Capability resolution: explicit config wins, else highest priority.
// - SDK semver range enforced at register.

import type { Transport } from './transport/types.js';
import type { TransportMiddleware } from './middleware.js';

export const SDK_VERSION = '1.0.0';

export type PluginKind =
  | 'renderer'
  | 'loader'
  | 'animator'
  | 'interaction'
  | 'middleware'
  | 'theme'
  | 'descriptor'
  | 'capability'
  | 'util';

export type Permission = 'clipboard-read' | 'clipboard-write';

export interface ActivationContext {
  host: HostFacade;
  slot?: string;
  signal: AbortSignal;
}

export interface PluginDescriptor {
  id: string;
  version: string;                      // plugin semver
  sdk: string;                          // SDK semver range, e.g. "^1.0"
  kind: PluginKind;
  dependencies?: readonly string[];
  softDependencies?: readonly string[];
  provides?: readonly string[];
  slots?: readonly string[];
  middlewareOf?: 'transport' | 'events';
  priority?: number;
  permissions?: readonly Permission[];
  defaultConfig?: Readonly<Record<string, unknown>>;

  init?(host: HostFacade, config: unknown): Promise<void> | void;
  activate?(ctx: ActivationContext): Promise<void> | void;
  deactivate?(): Promise<void> | void;
  destroy?(): Promise<void> | void;

  // Middleware-only:
  request?: TransportMiddleware['request'];
}

export interface SlotSpec {
  multiple: boolean;
  contract?: string;        // capability name a filler must provide
  required?: boolean;
  zIndex?: 'auto' | number;
}

export interface HostFacade {
  readonly kind: 'explorer' | 'pplns-view' | 'shared-core';
  readonly sdkVersion: string;
  readonly logger: Logger;
  readonly transport?: Transport | undefined;
}

export interface Logger {
  debug(msg: string, ctx?: Record<string, unknown>): void;
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
}

export class PluginRegistry {
  private readonly plugins = new Map<string, PluginDescriptor>();
  private readonly slots = new Map<string, SlotSpec>();
  // capability name -> set of plugin ids
  private readonly capabilityIndex = new Map<string, Set<string>>();

  register(p: PluginDescriptor): void {
    if (this.plugins.has(p.id)) {
      throw new Error(`plugin already registered: ${p.id}`);
    }
    if (!satisfiesSdk(p.sdk, SDK_VERSION)) {
      throw new Error(
        `plugin ${p.id} requires SDK ${p.sdk} but host is ${SDK_VERSION}`,
      );
    }
    this.plugins.set(p.id, p);
    for (const cap of p.provides ?? []) {
      let set = this.capabilityIndex.get(cap);
      if (!set) {
        set = new Set();
        this.capabilityIndex.set(cap, set);
      }
      set.add(p.id);
    }
  }

  defineSlot(name: string, spec: SlotSpec): void {
    if (this.slots.has(name)) {
      throw new Error(`slot already defined: ${name}`);
    }
    this.slots.set(name, spec);
  }

  get(id: string): PluginDescriptor | undefined {
    return this.plugins.get(id);
  }

  has(id: string): boolean {
    return this.plugins.has(id);
  }

  list(): PluginDescriptor[] {
    return Array.from(this.plugins.values());
  }

  slotsDefined(): ReadonlyMap<string, SlotSpec> {
    return this.slots;
  }

  slotFillers(name: string): PluginDescriptor[] {
    const fillers = this.plugins.values();
    const out: PluginDescriptor[] = [];
    for (const p of fillers) {
      if (p.slots?.includes(name)) out.push(p);
    }
    return sortBySlotOrder(out);
  }

  capabilities(name: string, explicit?: string): PluginDescriptor[] {
    const ids = this.capabilityIndex.get(name);
    if (!ids || ids.size === 0) return [];
    if (explicit !== undefined) {
      const p = this.plugins.get(explicit);
      if (p && ids.has(explicit)) return [p];
      return [];
    }
    const list: PluginDescriptor[] = [];
    for (const id of ids) {
      const p = this.plugins.get(id);
      if (p) list.push(p);
    }
    return sortByCapabilityOrder(list);
  }

  transportMiddleware(): PluginDescriptor[] {
    const out: PluginDescriptor[] = [];
    for (const p of this.plugins.values()) {
      if (p.kind === 'middleware' && p.middlewareOf === 'transport') out.push(p);
    }
    // Declared priority orders the chain: outer = highest priority first.
    return sortByCapabilityOrder(out);
  }
}

// ── Ordering (M1 D4) ───────────────────────────────────────────────
function sortBySlotOrder(list: PluginDescriptor[]): PluginDescriptor[] {
  // priority desc, id asc
  return list.slice().sort((a, b) => {
    const pa = a.priority ?? 0;
    const pb = b.priority ?? 0;
    if (pa !== pb) return pb - pa;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

function sortByCapabilityOrder(list: PluginDescriptor[]): PluginDescriptor[] {
  return sortBySlotOrder(list);  // same rule
}

// ── SDK semver range check ─────────────────────────────────────────
/** Minimal semver range parser for plugin `sdk` strings. Supports
 *  "^X.Y", "^X.Y.Z", "~X.Y", "X.Y", "X.Y.Z". */
export function satisfiesSdk(range: string, actual: string): boolean {
  const [amajor, aminor, apatch] = parseSemver(actual);
  if (range.startsWith('^')) {
    const [rmajor, rminor, rpatch] = parseSemver(range.slice(1));
    if (amajor !== rmajor) return false;
    if (aminor < rminor) return false;
    if (aminor === rminor && apatch < rpatch) return false;
    return true;
  }
  if (range.startsWith('~')) {
    const [rmajor, rminor, rpatch] = parseSemver(range.slice(1));
    if (amajor !== rmajor) return false;
    if (aminor !== rminor) return false;
    return apatch >= rpatch;
  }
  const [rmajor, rminor, rpatch] = parseSemver(range);
  return amajor === rmajor && aminor === rminor && apatch === rpatch;
}

function parseSemver(s: string): [number, number, number] {
  const parts = s.split('.').map((x) => parseInt(x, 10));
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

// ── Dependency resolution (plugin-arch §8) ─────────────────────────
/** Topologically sort plugins by `dependencies` + `softDependencies`.
 *  Missing hard deps throw; missing soft deps are silently dropped. */
export function resolveOrder(plugins: PluginDescriptor[]): PluginDescriptor[] {
  const ids = new Set(plugins.map((p) => p.id));
  const byId = new Map(plugins.map((p) => [p.id, p]));
  const visited = new Set<string>();
  const visiting = new Set<string>();
  const out: PluginDescriptor[] = [];

  const visit = (id: string): void => {
    if (visited.has(id)) return;
    if (visiting.has(id)) {
      throw new Error(`circular plugin dependency at ${id}`);
    }
    const p = byId.get(id);
    if (!p) return;
    visiting.add(id);
    for (const dep of p.dependencies ?? []) {
      if (!ids.has(dep)) {
        throw new Error(`plugin ${id} requires missing dep: ${dep}`);
      }
      visit(dep);
    }
    for (const dep of p.softDependencies ?? []) {
      if (ids.has(dep)) visit(dep);
    }
    visiting.delete(id);
    visited.add(id);
    out.push(p);
  };

  for (const p of plugins) visit(p.id);
  return out;
}
