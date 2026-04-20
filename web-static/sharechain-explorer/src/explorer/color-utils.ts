// Small, strict helpers for the animator's colour + alpha work.
// Output format is Canvas-2D-friendly: `rgba(r,g,b,a)` so downstream
// paint commands don't need a dedicated alpha channel.
//
// Provides capability `color-utils` (so Qt bridges / tests can reuse).

import type { PluginDescriptor } from '../registry.js';

export interface Rgb {
  r: number;
  g: number;
  b: number;
}

const HEX6 = /^#([0-9a-fA-F]{6})$/;
const HEX3 = /^#([0-9a-fA-F]{3})$/;
const HEX8 = /^#([0-9a-fA-F]{8})$/;

/** Parse "#rrggbb", "#rgb", or "#rrggbbaa" into {r,g,b}; null on
 *  mismatch. Alpha in `#rrggbbaa` is ignored — use applyAlpha() to
 *  set it explicitly. */
export function parseHexColor(hex: string): Rgb | null {
  if (typeof hex !== 'string') return null;
  let m = HEX6.exec(hex);
  if (m) {
    const h = m[1]!;
    return {
      r: parseInt(h.slice(0, 2), 16),
      g: parseInt(h.slice(2, 4), 16),
      b: parseInt(h.slice(4, 6), 16),
    };
  }
  m = HEX3.exec(hex);
  if (m) {
    const h = m[1]!;
    return {
      r: parseInt(h[0]! + h[0]!, 16),
      g: parseInt(h[1]! + h[1]!, 16),
      b: parseInt(h[2]! + h[2]!, 16),
    };
  }
  m = HEX8.exec(hex);
  if (m) {
    const h = m[1]!;
    return {
      r: parseInt(h.slice(0, 2), 16),
      g: parseInt(h.slice(2, 4), 16),
      b: parseInt(h.slice(4, 6), 16),
    };
  }
  return null;
}

function byteClamp(x: number): number {
  return Math.max(0, Math.min(255, Math.round(x)));
}

function alphaClamp(a: number): number {
  return Math.max(0, Math.min(1, a));
}

/** Interpolate two colours in sRGB space. `t` is clamped to [0,1].
 *  Falls back to `from` when either colour fails to parse — callers
 *  generally rely on the guaranteed-valid palette colours. */
export function lerpColor(from: string, to: string, t: number): string {
  const a = parseHexColor(from);
  const b = parseHexColor(to);
  const clamped = Math.max(0, Math.min(1, t));
  if (a === null || b === null) return from;
  const r = byteClamp(a.r + (b.r - a.r) * clamped);
  const g = byteClamp(a.g + (b.g - a.g) * clamped);
  const bl = byteClamp(a.b + (b.b - a.b) * clamped);
  return `rgb(${r},${g},${bl})`;
}

/** Apply alpha to a colour, returning an `rgba(...)` string Canvas 2D
 *  understands. Accepts hex (#rgb/#rrggbb/#rrggbbaa) or an rgb()
 *  return from lerpColor. */
export function applyAlpha(color: string, alpha: number): string {
  const a = alphaClamp(alpha);
  const parsed = parseHexColor(color);
  if (parsed !== null) {
    return `rgba(${parsed.r},${parsed.g},${parsed.b},${a})`;
  }
  // rgb(r,g,b) → rgba(r,g,b,a)
  const m = /^rgb\(([^)]+)\)$/.exec(color);
  if (m) return `rgba(${m[1]!},${a})`;
  // rgba(r,g,b,*) — replace the alpha channel
  const ma = /^rgba\(([^)]+)\)$/.exec(color);
  if (ma) {
    const parts = ma[1]!.split(',').map((s) => s.trim());
    if (parts.length >= 3) {
      return `rgba(${parts[0]},${parts[1]},${parts[2]},${a})`;
    }
  }
  return color;
}

/** One-shot: lerp two hex colours then apply alpha. */
export function lerpColorWithAlpha(
  from: string,
  to: string,
  t: number,
  alpha: number,
): string {
  return applyAlpha(lerpColor(from, to, t), alpha);
}

export const ColorUtilsPlugin: PluginDescriptor = {
  id: 'explorer.color-utils',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'util',
  provides: ['color-utils'],
  priority: 0,
  capabilities: {
    'color-utils': { parseHexColor, lerpColor, applyAlpha, lerpColorWithAlpha },
  },
};
