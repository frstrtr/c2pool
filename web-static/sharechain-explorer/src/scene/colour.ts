// Packed RGBA8 colour, as stored in the instance buffer: one u32 whose
// bytes in memory are R, G, B, A (little-endian value A<<24|B<<16|G<<8|R),
// so a GPU can read it as a normalised UNSIGNED_BYTE vec4 unchanged.

export function rgba(r: number, g: number, b: number, a = 255): number {
  return (((a & 255) << 24) | ((b & 255) << 16) | ((g & 255) << 8) | (r & 255)) >>> 0;
}

export function red(c: number): number { return c & 255; }
export function green(c: number): number { return (c >>> 8) & 255; }
export function blue(c: number): number { return (c >>> 16) & 255; }
export function alpha(c: number): number { return c >>> 24; }

/** Same colour, different alpha (0..255). */
export function withAlpha(c: number, a: number): number {
  return ((c & 0x00ffffff) | ((a & 255) << 24)) >>> 0;
}

/** Per-channel linear interpolation. */
export function lerpRgba(c0: number, c1: number, t: number): number {
  if (c0 === c1 || t <= 0) return c0 >>> 0;
  if (t >= 1) return c1 >>> 0;
  const l = (a: number, b: number): number => Math.round(a + (b - a) * t);
  return rgba(l(red(c0), red(c1)), l(green(c0), green(c1)), l(blue(c0), blue(c1)), l(alpha(c0), alpha(c1)));
}

/** HSL (h in degrees, s and l in percent) to packed RGBA8. */
export function hsl(h: number, s: number, l: number, a = 255): number {
  const sat = Math.max(0, Math.min(100, s)) / 100;
  const lig = Math.max(0, Math.min(100, l)) / 100;
  const hue = ((h % 360) + 360) % 360;
  const k = (n: number): number => (n + hue / 30) % 12;
  const m = sat * Math.min(lig, 1 - lig);
  const f = (n: number): number => lig - m * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return rgba(Math.round(f(0) * 255), Math.round(f(8) * 255), Math.round(f(4) * 255), a);
}

/** CSS rgba() string, with the alpha multiplied by `alphaScale`. */
export function toCss(c: number, alphaScale = 1): string {
  const a = Math.max(0, Math.min(1, (alpha(c) / 255) * alphaScale));
  return `rgba(${red(c)},${green(c)},${blue(c)},${+a.toFixed(3)})`;
}
