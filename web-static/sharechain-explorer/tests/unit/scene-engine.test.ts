// Scene engine: keyed tweens (enter / move / exit), in-flight retarget,
// merged updates, idle-stop, CPU hit-testing that matches what the
// Canvas2D renderer draws, keyed layout swaps, renderer swap on context
// loss, and the idle f32 epoch rebase. Runs against a manual clock, a
// manual frame scheduler and a recording 2D context.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createScene, createTreemapLayout, rgba, withAlpha, FLAG_SELECTED,
  type Ctx2D, type Layout, type Renderer, type SceneItem, type Scene, type InstanceBuffer,
} from '../../src/scene/index.js';

interface Call { op: string; args: unknown[] }

function recordingCtx(): Ctx2D & { calls: Call[]; reset(): void } {
  const calls: Call[] = [];
  const rec = (op: string) => (...args: unknown[]): void => { calls.push({ op, args }); };
  return {
    calls,
    reset() { calls.length = 0; },
    fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', textBaseline: '',
    setTransform: rec('setTransform'), fillRect: rec('fillRect'), clearRect: rec('clearRect'),
    strokeRect: rec('strokeRect'), fillText: rec('fillText'), save: rec('save'), restore: rec('restore'),
    beginPath: rec('beginPath'), rect: rec('rect'), clip: rec('clip'),
  };
}

function harness(opts: { layout?: Layout; duration?: number } = {}) {
  let t = 1_000;
  const queue: Array<() => void> = [];
  const ctx = recordingCtx();
  const canvas = {
    width: 0, height: 0, style: { width: '', height: '' }, clientWidth: 0, clientHeight: 0,
    getContext: () => ctx,
  } as unknown as HTMLCanvasElement;
  let hovered: string | null = null;
  const scene: Scene = createScene({
    canvas,
    layout: opts.layout ?? createTreemapLayout({ gap: 0, othersFraction: 0 }),
    style: (tile) => ({ color: rgba(100, 150, 200), flags: tile.key === hovered ? FLAG_SELECTED : 0 }),
    labels: (tiles) => tiles.map((p) => ({ text: p.key, x: p.x + p.w / 2, y: p.y + p.h / 2, color: '#fff', font: '10px sans-serif' })),
    duration: opts.duration ?? 500,
    background: rgba(13, 13, 26),
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return queue.length; }, cancel: () => { queue.length = 0; } },
    devicePixelRatio: () => 1,
  });
  scene.resize(400, 200);
  return {
    scene, ctx,
    advance(ms: number) { t += ms; },
    /** Run queued frames at the current time (one pass). */
    frame(): number { const q = queue.splice(0); q.forEach((cb) => cb()); return q.length; },
    /** Step time by `step` running frames until the loop idles. */
    runToIdle(step = 16, max = 10_000): number {
      let n = 0;
      while (queue.length > 0 && n < max) { t += step; this.frame(); n++; }
      return n;
    },
    pending: () => queue.length,
    setHovered(k: string | null) { hovered = k; },
  };
}

const items = (ws: Record<string, number>): SceneItem[] => Object.entries(ws).map(([key, weight]) => ({ key, weight }));
const rectsOf = (s: Scene) => Object.fromEntries(s.placed().map((p) => [p.key, [p.x, p.y, p.w, p.h].map((v) => +v.toFixed(3))]));
const target = (ws: Record<string, number>) => Object.fromEntries(
  createTreemapLayout({ gap: 0, othersFraction: 0 }).layout(items(ws), { x: 0, y: 0, w: 400, h: 200 })
    .map((tl) => [tl.key, [tl.x, tl.y, tl.w, tl.h].map((v) => +v.toFixed(3))]));

test('enter: tiles grow from their centre and fade in, then settle on the layout', () => {
  const h = harness();
  h.scene.setItems(items({ a: 3, b: 1 }));
  const start = h.scene.placed();
  for (const p of start) {
    assert.equal(p.w, 0);
    assert.equal(p.h, 0);
    assert.equal(p.color >>> 24, 0, 'transparent at t0');
  }
  h.advance(250);
  const mid = h.scene.placed().find((p) => p.key === 'a')!;
  assert.ok(mid.w > 0 && (mid.color >>> 24) > 0 && (mid.color >>> 24) < 255);
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), target({ a: 3, b: 1 }));
  assert.equal(h.scene.isAnimating(), false);
});

test('idle-stop: no frames are scheduled once tweens settle; restyle draws once', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  const ran = h.runToIdle();
  assert.ok(ran > 0 && ran < 100, `ran ${ran}`);
  assert.equal(h.pending(), 0);
  h.ctx.reset();
  h.setHovered('a');
  h.scene.restyle();
  assert.equal(h.pending(), 1);
  h.frame();
  assert.equal(h.pending(), 0, 'one frame, then idle again');
  assert.ok(h.ctx.calls.some((c) => c.op === 'strokeRect'), 'selected outline drawn');
});

test('retarget: a new target mid-flight starts from where the tile is drawn (no jump)', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  h.scene.setItems(items({ a: 9, b: 1 }), { immediate: true });
  h.advance(200);
  const before = rectsOf(h.scene);
  h.scene.setItems(items({ a: 1, b: 9 }), { immediate: true });
  assert.deepEqual(rectsOf(h.scene), before, 'continuous at the retarget instant');
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), target({ a: 1, b: 9 }));
});

test('merge: updates during a tween are held; only the latest is applied after it', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.advance(100);
  h.scene.setItems(items({ a: 5, b: 1 }));
  h.scene.setItems(items({ a: 1, b: 5 }));
  h.advance(100);
  h.frame();
  // Still heading for the first layout.
  h.advance(400);
  h.frame();
  // The first tween ended; the held update starts now.
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), target({ a: 1, b: 5 }));
});

test('exit: a vanished key shrinks, fades out and frees its slot', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1, c: 1 }));
  h.runToIdle();
  const count = h.scene.buffer.count;
  h.scene.setItems(items({ a: 1, b: 1 }));
  assert.deepEqual(h.scene.placed().map((p) => p.key).sort(), ['a', 'b'], 'leaving tile is not hit-testable');
  h.runToIdle();
  assert.ok(h.scene.buffer.count < count || h.scene.buffer.holes > 0, 'slot released');
  assert.deepEqual(Object.keys(rectsOf(h.scene)).sort(), ['a', 'b']);
});

test('a key that comes back while leaving is retargeted, not duplicated', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  h.scene.setItems(items({ a: 1 }));
  h.advance(100);
  h.scene.setItems(items({ a: 1, b: 1 }), { immediate: true });
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), target({ a: 1, b: 1 }));
  assert.equal(h.scene.placed().length, 2);
});

test('hit-test matches the drawn frame mid-tween (same easing as the renderer)', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  h.scene.setItems(items({ a: 7, b: 1 }), { immediate: true });
  h.advance(180);
  h.ctx.reset();
  h.frame();
  const fills = h.ctx.calls.filter((c) => c.op === 'fillRect').slice(1);  // [0] is the background
  const placed = h.scene.placed();
  assert.equal(fills.length, placed.length);
  for (const p of placed) {
    const drawn = fills.find((f) => Math.abs((f.args[0] as number) - p.x) < 1e-3 && Math.abs((f.args[1] as number) - p.y) < 1e-3);
    assert.ok(drawn, `${p.key} drawn where hit-testing places it`);
    assert.ok(Math.abs((drawn!.args[2] as number) - p.w) < 1e-3 && Math.abs((drawn!.args[3] as number) - p.h) < 1e-3);
    assert.equal(h.scene.hitTest(p.x + p.w / 2, p.y + p.h / 2)?.key, p.key);
  }
  assert.equal(h.scene.hitTest(-5, -5), null);
});

test('labels are drawn by the overlay pass after the tiles', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1 }));
  h.runToIdle();
  h.ctx.reset();
  h.scene.invalidate();
  h.frame();
  const ops = h.ctx.calls.map((c) => c.op);
  assert.ok(ops.lastIndexOf('fillRect') < ops.indexOf('fillText'), 'text after quads');
  assert.equal(h.ctx.calls.find((c) => c.op === 'fillText')?.args[0], 'a');
});

test('resize snaps tiles to the new viewport (no tween)', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  h.scene.resize(200, 200);
  const r = rectsOf(h.scene);
  const want = Object.fromEntries(createTreemapLayout({ gap: 0, othersFraction: 0 })
    .layout(items({ a: 1, b: 1 }), { x: 0, y: 0, w: 200, h: 200 })
    .map((tl) => [tl.key, [tl.x, tl.y, tl.w, tl.h].map((v) => +v.toFixed(3))]));
  assert.deepEqual(r, want);
});

test('setLayout: same keys tween from the old layout to the new one', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  const before = rectsOf(h.scene);
  const column: Layout = {
    id: 'column',
    layout: (its, vp) => its.map((it, i) => ({
      key: it.key, x: vp.x, y: vp.y + (i * vp.h) / its.length, w: vp.w, h: vp.h / its.length,
      weight: it.weight, items: [it], aggregate: false,
    })),
  };
  h.scene.setLayout(column);
  assert.deepEqual(rectsOf(h.scene), before, 'starts where it was');
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), { a: [0, 0, 400, 100], b: [0, 100, 400, 100] });
});

test('context loss swaps in the fallback renderer and re-uploads every record', async () => {
  let lost: (() => void) | null = null;
  const uploads: Array<{ kind: string; ranges: number }> = [];
  const fake = (kind: string): Renderer => ({
    kind,
    init() {},
    resize() {},
    upload(_b: InstanceBuffer, dirty) { uploads.push({ kind, ranges: dirty.reduce((s, d) => s + d.end - d.start, 0) }); },
    draw() {},
    onContextLost(cb) { if (kind === 'gpu') lost = cb; },
    dispose() {},
  });
  let t = 0;
  const queue: Array<() => void> = [];
  const canvas = { width: 0, height: 0, style: { width: '', height: '' }, getContext: () => recordingCtx() } as unknown as HTMLCanvasElement;
  const scene = createScene({
    canvas,
    layout: createTreemapLayout({ gap: 0 }),
    style: () => ({ color: rgba(1, 2, 3), flags: 0 }),
    renderer: fake('gpu'),
    fallbackRenderer: () => fake('cpu'),
    overlay: null,
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    devicePixelRatio: () => 1,
  });
  scene.resize(100, 100);
  scene.setItems(items({ a: 1, b: 2, c: 3 }));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(scene.renderer.kind, 'gpu');
  assert.ok(lost !== null);
  lost!();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(scene.renderer.kind, 'cpu');
  t += 10;
  queue.splice(0).forEach((cb) => cb());
  const last = uploads[uploads.length - 1]!;
  assert.equal(last.kind, 'cpu');
  assert.equal(last.ranges, scene.buffer.count, 'the fallback gets every record');
});

test('async renderer init does not block: drawing starts when it resolves', async () => {
  let resolve!: () => void;
  const draws: number[] = [];
  const slow: Renderer = {
    kind: 'slow',
    init: () => new Promise<void>((r) => { resolve = r; }),
    resize() {}, upload() {}, draw(now) { draws.push(now); }, onContextLost() {}, dispose() {},
  };
  const queue: Array<() => void> = [];
  const canvas = { width: 0, height: 0, style: { width: '', height: '' }, getContext: () => recordingCtx() } as unknown as HTMLCanvasElement;
  const scene = createScene({
    canvas, layout: createTreemapLayout(), style: () => ({ color: rgba(1, 1, 1), flags: 0 }),
    renderer: slow, overlay: null, clock: () => 0,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
  });
  scene.resize(10, 10);
  scene.setItems(items({ a: 1 }));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(draws.length, 0, 'nothing drawn before init resolves');
  resolve();
  await new Promise((r) => setTimeout(r, 0));
  queue.splice(0).forEach((cb) => cb());
  assert.ok(draws.length >= 1, 'drawing starts once it resolves');
});

test('epoch rebase: after an idle hour, new tweens use small f32-safe times', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  h.advance(5 * 3_600_000);  // five idle hours
  h.scene.setItems(items({ a: 3, b: 1 }));
  const t0s: number[] = [];
  for (let s = 0; s < h.scene.buffer.count; s++) t0s.push(h.scene.buffer.read(s).t0);
  assert.ok(t0s.every((v) => Math.abs(v) < 1_000), `t0 rebased (${t0s})`);
  h.runToIdle();
  assert.deepEqual(rectsOf(h.scene), target({ a: 3, b: 1 }));
});

test('restyle keeps an entering tile fading in', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1 }));
  h.advance(50);
  h.setHovered('a');
  h.scene.restyle();
  const rec = h.scene.buffer.read(0);
  assert.equal(rec.fromRgba >>> 24, 0, 'still fading from transparent');
  assert.equal(rec.toRgba, withAlpha(rgba(100, 150, 200), 255));
});
