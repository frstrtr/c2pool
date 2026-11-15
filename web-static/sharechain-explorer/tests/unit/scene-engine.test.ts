// Scene engine: keyed tweens (enter / move / exit), in-flight retarget,
// merged updates, idle-stop, CPU hit-testing that matches what the
// Canvas2D renderer draws, keyed layout swaps, renderer swap on context
// loss, and the idle f32 epoch rebase. Runs against a manual clock, a
// manual frame scheduler and a recording 2D context.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createScene, createTreemapLayout, createCanvas2DRenderer, rgba, withAlpha, FLAG_SELECTED,
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

/** A canvas that, like a real one, keeps the first context id it was
 *  asked for: after 'webgl2' it returns null for '2d'. */
interface FakeCanvas {
  role: string; width: number; height: number; style: Record<string, string>;
  ctx2d: ReturnType<typeof recordingCtx>;
  getContext(id: string): unknown;
}
function fakeCanvas(role: string): FakeCanvas {
  let locked: string | null = null;
  const ctx2d = recordingCtx();
  return {
    role, width: 0, height: 0, style: { width: '', height: '' }, ctx2d,
    getContext(id: string) {
      if (locked !== null && locked !== id) return null;
      locked = id;
      return id === '2d' ? ctx2d : { kind: id };
    },
  };
}

function fakeContainer(): { el: HTMLElement; children: FakeCanvas[] } {
  const children: FakeCanvas[] = [];
  const el = {
    clientWidth: 0, clientHeight: 0,
    appendChild(n: FakeCanvas) { children.push(n); return n; },
    insertBefore(n: FakeCanvas, ref: FakeCanvas | null) {
      const i = ref === null ? -1 : children.indexOf(ref);
      if (i < 0) children.push(n); else children.splice(i, 0, n);
      return n;
    },
    removeChild(n: FakeCanvas) { const i = children.indexOf(n); if (i >= 0) children.splice(i, 1); return n; },
  };
  return { el: el as unknown as HTMLElement, children };
}

const surfaces = (role: string) => fakeCanvas(role) as unknown as HTMLCanvasElement;

function harness(opts: { layout?: Layout; duration?: number } = {}) {
  let t = 1_000;
  const queue: Array<() => void> = [];
  const box = fakeContainer();
  let hovered: string | null = null;
  const scene: Scene = createScene({
    container: box.el,
    layout: opts.layout ?? createTreemapLayout({ gap: 0, othersFraction: 0 }),
    style: (tile) => ({ color: rgba(100, 150, 200), flags: tile.key === hovered ? FLAG_SELECTED : 0 }),
    labels: (tiles) => tiles.map((p) => ({ text: p.key, x: p.x + p.w / 2, y: p.y + p.h / 2, color: '#fff', font: '10px sans-serif' })),
    duration: opts.duration ?? 500,
    background: rgba(13, 13, 26),
    createSurface: surfaces,
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return queue.length; }, cancel: () => { queue.length = 0; } },
    devicePixelRatio: () => 1,
  });
  scene.resize(400, 200);
  const surfaceOf = (role: string): FakeCanvas => box.children.find((c) => c.role === role)!;
  return {
    scene, box,
    /** 2D context of the renderer's surface (quads). */
    get ctx() { return surfaceOf('renderer').ctx2d; },
    /** 2D context of the overlay's surface (labels). */
    get overlayCtx() { return surfaceOf('overlay').ctx2d; },
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
  h.frame();  // what is on screen mid-flight
  const before = rectsOf(h.scene);
  h.scene.setItems(items({ a: 1, b: 9 }), { immediate: true });
  h.frame();  // draw the retarget instant
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

test('labels are drawn by the overlay pass on its own stacked canvas', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1 }));
  h.runToIdle();
  h.overlayCtx.reset();
  h.ctx.reset();
  h.scene.invalidate();
  h.frame();
  assert.deepEqual(h.box.children.map((c) => c.role), ['renderer', 'overlay'], 'overlay stacked above');
  assert.ok(!h.ctx.calls.some((c) => c.op === 'fillText'), 'the quad renderer never draws text');
  const ops = h.overlayCtx.calls.map((c) => c.op);
  assert.ok(ops.indexOf('clearRect') >= 0 && ops.indexOf('clearRect') < ops.indexOf('fillText'), 'overlay clears, then draws');
  assert.equal(h.overlayCtx.calls.find((c) => c.op === 'fillText')?.args[0], 'a');
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

test('context loss: a fresh surface gets the real Canvas2D fallback and every record', async () => {
  let lost: (() => void) | null = null;
  let gpuSurface: FakeCanvas | null = null;
  const gpu: Renderer = {
    kind: 'gpu',
    init(c) { gpuSurface = c as unknown as FakeCanvas; assert.ok(gpuSurface.getContext('webgl2')); },
    resize() {}, upload() {}, draw() {},
    onContextLost(cb) { lost = cb; },
    dispose() {},
  };
  let t = 0;
  const queue: Array<() => void> = [];
  const box = fakeContainer();
  const errors: unknown[] = [];
  const scene = createScene({
    container: box.el,
    layout: createTreemapLayout({ gap: 0 }),
    style: () => ({ color: rgba(1, 2, 3), flags: 0 }),
    renderer: gpu,
    background: rgba(13, 13, 26),
    createSurface: surfaces,
    clock: () => t,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
    devicePixelRatio: () => 1,
    onError: (e) => errors.push(e),
  });
  scene.resize(100, 100);
  scene.setItems(items({ a: 1, b: 2, c: 3 }));
  await new Promise((r) => setTimeout(r, 0));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(scene.renderer.kind, 'gpu', 'upgraded once init resolved');
  // The hole this guards against: a GPU canvas never yields a 2D context.
  assert.throws(() => createCanvas2DRenderer().init(gpuSurface as unknown as HTMLCanvasElement));
  lost!();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(scene.renderer.kind, 'canvas2d');
  assert.ok(!box.children.includes(gpuSurface!), 'the lost GPU surface is removed');
  const r = box.children.find((c) => c.role === 'renderer')!;
  t += 10;
  queue.splice(0).forEach((cb) => cb());
  const fills = r.ctx2d.calls.filter((c) => c.op === 'fillRect');
  assert.equal(fills.length, 1 + scene.buffer.count, 'background + every record drawn on the fresh surface');
  assert.deepEqual(errors, []);
});

test('a requested renderer whose init rejects leaves the scene on Canvas2D, drawing', async () => {
  const errors: unknown[] = [];
  const bad: Renderer = {
    kind: 'gpu', init: () => Promise.reject(new Error('no adapter')),
    resize() {}, upload() {}, draw() {}, onContextLost() {}, dispose() {},
  };
  const queue: Array<() => void> = [];
  const box = fakeContainer();
  const scene = createScene({
    container: box.el, layout: createTreemapLayout(), style: () => ({ color: rgba(1, 1, 1), flags: 0 }),
    renderer: bad, background: rgba(0, 0, 0), createSurface: surfaces,
    clock: () => 0, onError: (e) => errors.push(e),
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
  });
  scene.resize(10, 10);
  scene.setItems(items({ a: 1 }));
  await new Promise((r) => setTimeout(r, 0));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(scene.renderer.kind, 'canvas2d');
  assert.equal((errors[0] as Error | undefined)?.message, 'no adapter', 'the failure is reported');
  const r = box.children.find((c) => c.role === 'renderer')!;
  assert.ok(r.ctx2d.calls.some((c) => c.op === 'fillRect'), 'still drawing');
  assert.equal(box.children.filter((c) => c.role === 'renderer').length, 1, 'no orphan surface');
});

test('async renderer init does not block: Canvas2D draws until it resolves', async () => {
  let resolve!: () => void;
  const draws: number[] = [];
  const slow: Renderer = {
    kind: 'slow',
    init: () => new Promise<void>((r) => { resolve = r; }),
    resize() {}, upload() {}, draw(now) { draws.push(now); }, onContextLost() {}, dispose() {},
  };
  const queue: Array<() => void> = [];
  const box = fakeContainer();
  const scene = createScene({
    container: box.el, layout: createTreemapLayout(), style: () => ({ color: rgba(1, 1, 1), flags: 0 }),
    renderer: slow, background: rgba(0, 0, 0), createSurface: surfaces, clock: () => 0,
    scheduler: { request: (cb) => { queue.push(cb); return 1; }, cancel: () => {} },
  });
  scene.resize(10, 10);
  scene.setItems(items({ a: 1 }));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(scene.renderer.kind, 'canvas2d', 'boots on Canvas2D');
  assert.equal(draws.length, 0);
  const boot = box.children.find((c) => c.role === 'renderer')!;
  assert.ok(boot.ctx2d.calls.some((c) => c.op === 'fillRect'), 'the page is never blank meanwhile');
  resolve();
  await new Promise((r) => setTimeout(r, 0));
  queue.splice(0).forEach((cb) => cb());
  assert.equal(scene.renderer.kind, 'slow');
  assert.ok(draws.length >= 1, 'the upgrade draws once it resolves');
  assert.equal(box.children.filter((c) => c.role === 'renderer').length, 1, 'old surface replaced');
});

test('hit-test uses the last drawn frame while animating, and a cached placement when idle', () => {
  const h = harness();
  h.scene.setItems(items({ a: 1, b: 1 }));
  h.runToIdle();
  const idle1 = h.scene.placed();
  assert.equal(h.scene.placed(), idle1, 'idle placement is cached (no per-call allocation)');
  h.scene.setItems(items({ a: 7, b: 1 }), { immediate: true });
  h.advance(150);
  h.frame();
  const drawn = h.scene.placed().map((p) => [p.key, p.x, p.w]);
  h.advance(10);  // the clock moved, no frame drawn yet
  assert.deepEqual(h.scene.placed().map((p) => [p.key, p.x, p.w]), drawn, 'what is on screen, not a frame ahead');
  h.runToIdle();
  const idle2 = h.scene.placed();
  assert.notEqual(idle2, idle1, 'cache invalidated by the update');
  h.setHovered('a');
  h.scene.restyle();
  assert.notEqual(h.scene.placed(), idle2, 'cache invalidated by restyle');
});

test('duplicate layout keys are dropped with one warning', () => {
  const warnings: string[] = [];
  const box = fakeContainer();
  const dup: Layout = {
    id: 'dup',
    layout: (its, vp) => [...its, ...its].map((it) => ({ key: it.key, x: vp.x, y: vp.y, w: vp.w, h: vp.h, weight: it.weight, items: [it], aggregate: false })),
  };
  const scene = createScene({
    container: box.el, layout: dup, style: () => ({ color: rgba(1, 1, 1), flags: 0 }),
    createSurface: surfaces, clock: () => 0,
    scheduler: { request: () => 1, cancel: () => {} }, onWarn: (m) => warnings.push(m),
  });
  scene.resize(10, 10);
  scene.setItems(items({ a: 1, b: 1 }));
  scene.setItems(items({ a: 1, b: 1 }), { immediate: true });
  assert.equal(scene.placed().length, 2);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /duplicate key 'a'/);
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
