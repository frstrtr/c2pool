// Deterministic address → HSL hue hash. Shared with the Explorer hover
// zoom via web-static/sharechain-explorer/src/plugins/addr-hue.ts; the
// same formula keeps miner colours stable across Explorer + PPLNS
// View. Lightness/saturation are modulated per badge severity so
// degraded badges (warn/muted) render less vibrantly.

export type BadgeSeverity = 'ok' | 'signaling' | 'warn' | 'muted';

/** djb2-style hash of an address string. Positive 31-bit integer. */
export function addrHash(address: string): number {
  let h = 5381;
  for (let i = 0; i < address.length; i++) {
    h = (((h << 5) + h) ^ address.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

/** Map a hashed address to an HSL colour string. Lightness + saturation
 *  vary with severity so ops can visually distinguish healthy vs
 *  degraded miners at a glance. */
export function addrColor(address: string, severity: BadgeSeverity = 'ok'): string {
  const hue = addrHash(address) % 360;
  const [s, l] = satLight(severity);
  return `hsl(${hue}, ${s}%, ${l}%)`;
}

function satLight(severity: BadgeSeverity): [number, number] {
  switch (severity) {
    case 'ok':        return [58, 40];
    case 'signaling': return [50, 38];
    case 'warn':      return [42, 32];
    case 'muted':     return [15, 28];
  }
}
