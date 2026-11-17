// Tests for the createRealtime DOM adapter: the render loop must stop
// when nothing changes (no idle repaint), wake on data / resize /
// invalidate, and hit-test against the layout it actually painted.
// Runs in Node against a fake window (manual rAF queue) and a
// recording 2D context.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  RealtimeOrchestrator,
  cellAtPoint,
  computeGridLayout,
  createRealtime,
  type ShareForClassify,
  type TipEvent,
  type Transport,
} from '../../src/explorer/index.js';

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'Xother', ...over, h } as unknown as ShareForClassify;
}

function shares(n: number, prefix = 's'): ShareForClassify[] {
  return Array.from({ length: n }, (_, i) => sh(`${prefix}${i.toString(16).padStart(15, '0')}`));
}

interface MockTransport extends Transport {
  fireTip(ev: TipEvent): void;
}

function makeTransport(opts: {
  window: { shares: ShareForClassify[] };
  delta?: () => { shares: ShareForClassify[]; tip?: string; fork_switch?: boolean };
}): MockTransport {
  const subs: Array<(ev: TipEvent) => void> = [];
  return {
    kind: 'demo',
    fetchWindow: async () => opts.window,
    fetchTip:    async () => ({ hash: 'aaaaaaaaaaaaaaaa', height: 1 }),
    fetchDelta:  async () => opts.delta?.() ?? { shares: [] },
    fetchStats:  async () => ({ chain_height: 1 }),
    fetchShareDetail: async () => ({}),
    negotiate:   async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail:    async () => ({}),
    subscribeStream(onTip) {
      subs.push(onTip);
      return { unsubscribe() { const i = subs.indexOf(onTip); if (i >= 0) subs.splice(i, 1); } };
    },
    fireTip(ev) { for (const s of subs) s(ev); },
  };
}

/** Fake browser: a manual rAF queue plus window resize listeners. */
function installFakeWindow(): {
  pending(): number;
  /** Run queued frames (each may queue the next) until the queue is
   *  empty or `maxFrames` ran. Returns the number of frames run. */
  flush(maxFrames?: number, stepMs?: number): number;
  fireResize(): void;
  restore(): void;
} {
  const g = globalThis as unknown as Record<string, unknown>;
  const prev = g.window;
  let nextId = 1;
  const queue = new Map<number, (t: number) => void>();
  const resizeListeners = new Set<() => void>();
  let clock = performance.now();
  g.window = {
    devicePixelRatio: 1,
    requestAnimationFrame(cb: (t: number) => void): number {
      const id = nextId++;
      queue.set(id, cb);
      return id;
    },
    cancelAnimationFrame(id: number): void { queue.delete(id); },
    addEventListener(type: string, fn: () => void): void {
      if (type === 'resize') resizeListeners.add(fn);
    },
    removeEventListener(type: string, fn: () => void): void {
      if (type === 'resize') resizeListeners.delete(fn);
    },
  };
  return {
    pending: () => queue.size,
    flush(maxFrames = 10_000, stepMs = 16) {
      let ran = 0;
      clock = Math.max(clock, performance.now());
      while (queue.size > 0 && ran < maxFrames) {
        const [id, cb] = queue.entries().next().value as [number, (t: number) => void];
        queue.delete(id);
        clock += stepMs;
        cb(clock);
        ran++;
      }
      return ran;
    },
    fireResize() { for (const fn of resizeListeners) fn(); },
    restore() { g.window = prev; },
  };
}

/** Canvas whose 2D context counts paints (one setTransform per frame)
 *  and whose backing-store size assignments are counted. */
function makeCanvas(): {
  canvas: HTMLCanvasElement;
  paints(): number;
  backingAssignments(): number;
} {
  let paints = 0;
  let assigns = 0;
  let w = 0, h = 0;
  const noop = (): void => {};
  const ctx = {
    fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', textBaseline: '',
    setTransform: () => { paints++; },
    fillRect: noop, strokeRect: noop, fillText: noop, beginPath: noop,
    moveTo: noop, lineTo: noop, stroke: noop, closePath: noop, fill: noop,
  };
  const canvas = {
    style: {} as Record<string, string>,
    parentElement: null,
    getContext: () => ctx,
    get width() { return w; },
    set width(v: number) { w = v; assigns++; },
    get height() { return h; },
    set height(v: number) { h = v; assigns++; },
  };
  return {
    canvas: canvas as unknown as HTMLCanvasElement,
    paints: () => paints,
    backingAssignments: () => assigns,
  };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 0));
const CONTEXT = { myAddress: 'Xme', shareVersion: 36 };

test('idle-stop: after the first paint an idle canvas schedules no frames', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const rt = createRealtime({
      canvas: c.canvas,
      transport: makeTransport({ window: { shares: shares(50) } }),
      userContext: CONTEXT,
      containerWidth: () => 800,
    });
    await rt.start();
    const ran = fw.flush();
    assert.ok(ran < 10, `loop must stop on its own (ran ${ran} frames)`);
    assert.equal(fw.pending(), 0, 'no rAF stays queued while idle');
    assert.equal(c.paints(), 1, 'exactly one static paint');
    // Time passing with no change paints nothing more.
    fw.flush();
    assert.equal(c.paints(), 1);
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('idle-stop: a new tip wakes the loop, animates, settles and stops', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const base = shares(50);
    const fresh = sh('ffffffffffffffff');
    const transport = makeTransport({
      window: { shares: base },
      delta: () => ({ shares: [fresh], tip: 'ffffffffffffffff' }),
    });
    const rt = createRealtime({
      canvas: c.canvas,
      transport,
      userContext: CONTEXT,
      containerWidth: () => 800,
      fastAnimation: true,
    });
    await rt.start();
    fw.flush();
    const before = c.paints();
    transport.fireTip({ hash: 'ffffffffffffffff', height: 2 } as TipEvent);
    await settle();
    assert.ok(fw.pending() > 0, 'the delta woke the idle loop');
    const ran = fw.flush(20_000, 16);
    assert.equal(fw.pending(), 0, 'the loop stops once the animation settles');
    assert.ok(ran < 20_000, 'animation terminates');
    assert.ok(c.paints() > before + 1, 'animation frames were painted');
    assert.equal(rt.getState().shareCount, 51);
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('idle-stop: resize and invalidate() each repaint exactly once', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    let width = 800;
    const rt = createRealtime({
      canvas: c.canvas,
      transport: makeTransport({ window: { shares: shares(50) } }),
      userContext: CONTEXT,
      containerWidth: () => width,
    });
    await rt.start();
    fw.flush();
    assert.equal(c.paints(), 1);

    // A resize event with an unchanged container paints nothing.
    fw.fireResize();
    fw.flush();
    assert.equal(c.paints(), 1);

    width = 500;
    fw.fireResize();
    fw.flush();
    assert.equal(c.paints(), 2, 'container change repaints');
    assert.equal(fw.pending(), 0);

    rt.invalidate();
    fw.flush();
    assert.equal(c.paints(), 3, 'invalidate repaints');
    assert.equal(fw.pending(), 0);
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('backing store is reallocated only when its size changes', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const rt = createRealtime({
      canvas: c.canvas,
      transport: makeTransport({ window: { shares: shares(50) } }),
      userContext: CONTEXT,
      containerWidth: () => 800,
    });
    await rt.start();
    fw.flush();
    const assigns = c.backingAssignments();
    assert.equal(assigns, 2, 'width + height set once for the first paint');
    rt.invalidate();
    fw.flush();
    rt.invalidate();
    fw.flush();
    assert.equal(c.paints(), 3);
    assert.equal(c.backingAssignments(), assigns, 'same size: no reallocation');
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('stop(): no frames run after stop, and start() resumes painting', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const rt = createRealtime({
      canvas: c.canvas,
      transport: makeTransport({ window: { shares: shares(10) } }),
      userContext: CONTEXT,
      containerWidth: () => 800,
    });
    await rt.start();
    await rt.stop();
    fw.flush();
    assert.equal(c.paints(), 0);
    rt.invalidate();
    assert.equal(fw.pending(), 0, 'invalidate is inert while stopped');
    await rt.start();
    fw.flush();
    assert.equal(c.paints(), 1);
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('cellAtPoint hit-tests the painted auto-fit layout, not a fixed 10 px grid', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const n = 300;
    const rt = createRealtime({
      canvas: c.canvas,
      transport: makeTransport({ window: { shares: shares(n) } }),
      userContext: CONTEXT,
      containerWidth: () => 600,
      containerHeight: () => 400,
      minCellSize: 4,
    });
    assert.equal(rt.cellAtPoint(50, 5), null, 'nothing painted yet');
    await rt.start();
    fw.flush();
    const layout = rt.getLayout();
    assert.ok(layout !== null);
    assert.notEqual(layout!.cellSize, 10, 'fixture must exercise a non-default cell size');

    const fixed = computeGridLayout({
      shareCount: n, containerWidth: 600, cellSize: 10, gap: 1, marginLeft: 38, minHeight: 40,
    });
    let disagreements = 0;
    for (const i of [0, 1, 17, 42, 150, n - 1]) {
      const col = i % layout!.cols;
      const row = Math.floor(i / layout!.cols);
      const x = layout!.marginLeft + col * layout!.step + layout!.cellSize / 2;
      const y = row * layout!.step + layout!.cellSize / 2;
      assert.equal(rt.cellAtPoint(x, y), i, `centre of painted cell ${i}`);
      if (cellAtPoint(fixed, x, y) !== i) disagreements++;
    }
    assert.ok(disagreements > 0, 'the old fixed-cellSize hit-test picks wrong shares here');
    await rt.stop();
  } finally {
    fw.restore();
  }
});

test('orchestrator: revision bumps and the listener fires on data changes', async () => {
  const fresh = sh('ffffffffffffffff');
  const transport = makeTransport({
    window: { shares: shares(5) },
    delta: () => ({ shares: [fresh], tip: 'ffffffffffffffff' }),
  });
  const o = new RealtimeOrchestrator({ transport, userContext: CONTEXT, containerWidth: () => 800 });
  let calls = 0;
  o.setChangeListener(() => { calls++; });
  const r0 = o.revision;
  await o.start();
  assert.ok(o.revision > r0, 'window load bumps the revision');
  const r1 = o.revision;
  transport.fireTip({ hash: 'ffffffffffffffff', height: 2 } as TipEvent);
  await settle();
  assert.ok(o.revision > r1, 'delta bumps the revision');
  assert.ok(calls >= 2);
  assert.equal(o.animationFrame(performance.now()) !== null, true, 'small delta animates');
  await o.stop();
});

test('dashboard.html: bundled hover hit-test uses the painted layout', () => {
  const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');
  // The import may carry a ?v=<hash> cache-bust stamp.
  const start = html.indexOf("import('./sharechain-explorer/dist/sharechain-explorer.js");
  assert.ok(start > 0, 'bundled bootstrap present');
  const boot = html.slice(start);
  assert.ok(boot.includes('__explorerBundled.cellAtPoint('), 'hover asks the controller');
  assert.ok(!/computeGridLayout\(/.test(boot), 'no private re-layout for hit-testing');
  assert.ok(!/cellSize:\s*10\b/.test(boot), 'no fixed cell size in the hover path');
  assert.ok(!html.includes('Hover-zoom + per-share PPLNS treemap not yet ported'),
    'stale limitation comment removed');
});

test('dashboard-bundled.mjs: hover hit-test uses the painted layout, guarded for an old cached bundle', () => {
  const src = readFileSync(new URL('../../dashboard-bundled.mjs', import.meta.url), 'utf8');
  assert.ok(src.includes('rt.cellAtPoint('));
  assert.ok(src.includes("typeof rt.cellAtPoint !== 'function'"));
  assert.ok(!/computeGridLayout\(/.test(src));
});

test('a failed start() leaves no resize listener, timer, frame or change listener behind', async () => {
  const fw = installFakeWindow();
  try {
    const c = makeCanvas();
    const transport = makeTransport({ window: { shares: shares(5) } });
    transport.subscribeStream = () => { throw new Error('stream down'); };
    const rt = createRealtime({ canvas: c.canvas, transport, userContext: CONTEXT, containerWidth: () => 800 });
    await assert.rejects(rt.start(), /stream down/);
    assert.equal(fw.pending(), 0, 'the frame queued during start was cancelled');
    fw.fireResize();
    rt.invalidate();
    assert.equal(fw.pending(), 0, 'no resize listener, and the loop is stopped');
    assert.equal(c.paints(), 0);
  } finally {
    fw.restore();
  }
});

// ── hasQueued is derived from the animator, not a mirror flag ─────

function deltaFeed(): { delta: () => { shares: ShareForClassify[]; tip: string }; next: () => string } {
  let n = 0;
  let last = '';
  return {
    next() { n++; last = `d${n.toString(16).padStart(15, '0')}`; return last; },
    delta: () => ({ shares: [sh(last)], tip: last }),
  };
}

test('hasQueued: true while a plan waits, false once the animator starts it on its own', async () => {
  const feed = deltaFeed();
  const transport = makeTransport({ window: { shares: shares(20) }, delta: feed.delta });
  const o = new RealtimeOrchestrator({ transport, userContext: CONTEXT, containerWidth: () => 800 });
  await o.start();
  transport.fireTip({ hash: feed.next(), height: 2 } as TipEvent);
  await settle();
  assert.equal(o.getState().animating, true);
  assert.equal(o.getState().hasQueued, false);
  transport.fireTip({ hash: feed.next(), height: 3 } as TipEvent);
  await settle();
  assert.equal(o.getState().hasQueued, true, 'second delta queued behind the first');
  // Far past the first plan's end: tick() itself dequeues the second plan.
  o.animationFrame(performance.now() + 120_000);
  assert.equal(o.getState().hasQueued, false, 'no stale flag after the animator dequeues');
  o.animationFrame(performance.now() + 240_000);
  assert.equal(o.getState().animating, false);
  assert.equal(o.getState().hasQueued, false);
  await o.stop();
});

test('a full rebuild (fork switch) drops a plan queued against the old window', async () => {
  const feed = deltaFeed();
  let forkNext = false;
  const transport = makeTransport({
    window: { shares: shares(20) },
    delta: () => (forkNext ? { ...feed.delta(), fork_switch: true } : feed.delta()),
  });
  const o = new RealtimeOrchestrator({ transport, userContext: CONTEXT, containerWidth: () => 800 });
  await o.start();
  transport.fireTip({ hash: feed.next(), height: 2 } as TipEvent);
  await settle();
  transport.fireTip({ hash: feed.next(), height: 3 } as TipEvent);
  await settle();
  assert.equal(o.getState().hasQueued, true);
  // Reorg: the node now serves a different window (a few shares replaced).
  const reorged = [sh('ffffffffffffff01'), sh('ffffffffffffff02'), ...shares(18)];
  transport.fetchWindow = async () => ({ shares: reorged });
  forkNext = true;
  transport.fireTip({ hash: feed.next(), height: 4 } as TipEvent);
  await settle();
  await settle();
  assert.equal(o.getState().hasQueued, false, 'the stale queued plan is dropped');
  o.animationFrame(performance.now() + 120_000);  // finish the rebuild animation
  assert.equal(o.getState().animating, false, 'nothing stale plays after the rebuild');
  await o.stop();
});
