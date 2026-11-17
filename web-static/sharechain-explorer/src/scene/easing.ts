// Easing shared by every renderer AND by CPU hit-testing, so a tile is
// hit where it is drawn. A GPU backend must implement exactly this in
// its vertex shader (README "Renderer contract").

/** Ken Perlin's smootherstep on [0, 1]: 6t⁵ − 15t⁴ + 10t³. */
export function smootherstep(t: number): number {
  if (!(t > 0)) return 0;
  if (t >= 1) return 1;
  return t * t * t * (t * (t * 6 - 15) + 10);
}

/** Eased progress of a tween that started at `t0` and lasts `dur`
 *  (same clock as `now`). A zero or negative duration is already done. */
export function progress(now: number, t0: number, dur: number): number {
  if (!(dur > 0)) return 1;
  return smootherstep((now - t0) / dur);
}

export function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}
