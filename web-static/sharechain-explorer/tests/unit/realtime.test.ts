// Tests for the Realtime orchestrator — pure state machine exercised
// against a fully-synchronous mock Transport. No DOM / no RAF.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RealtimeOrchestrator,
  type ShareForClassify,
  type Transport,
  type TipEvent,
  type ExplorerError,
} from '../../src/explorer/index.js';

interface MockTransport extends Transport {
  /** Fires the next tip into every subscriber. */
  fireTip(ev: TipEvent): void;
  /** Triggers onReconnect in every subscriber. */
  fireReconnect(): void;
}

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'Xother', ...over, h } as unknown as ShareForClassify;
}

function makeTransport(opts: {
  window?: { shares: ShareForClassify[] };
  tipResponse?: () => { hash: string };
  deltaForSince?: (since: string) => { shares: ShareForClassify[]; fork_switch?: boolean };
} = {}): MockTransport {
  const subs: Array<{
    onTip: (ev: TipEvent) => void;
    onErr?: (err: ExplorerError) => void;
    onRec?: () => void;
  }> = [];

  return {
    kind: 'demo',
    fetchWindow: async () => opts.window ?? { shares: [] },
    fetchTip:    async () => opts.tipResponse?.() ?? { hash: 'aaaaaaaaaaaaaaaa', height: 1 },
    fetchDelta:  async (since: string) =>
      opts.deltaForSince?.(since) ?? { shares: [] },
    fetchStats:  async () => ({ chain_height: 1 }),
    fetchShareDetail: async () => ({}),
    negotiate:   async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail:    async () => ({}),
    subscribeStream(onTip, onErr, onRec) {
      const entry: typeof subs[number] = { onTip };
      if (onErr !== undefined) entry.onErr = onErr;
      if (onRec !== undefined) entry.onRec = onRec;
      subs.push(entry);
      return {
        unsubscribe() {
          const i = subs.indexOf(entry);
          if (i >= 0) subs.splice(i, 1);
        },
      };
    },
    fireTip(ev) { for (const s of subs) s.onTip(ev); },
    fireReconnect() { for (const s of subs) s.onRec?.(); },
  };
}

const CONTEXT = { myAddress: 'Xme', shareVersion: 36 };
const CONTAINER_WIDTH = () => 1000;

// ── start() / initial window ──────────────────────────────────────

test('start: fetches window + sets tip', async () => {
  const transport = makeTransport({
    window: { shares: [sh('tip0001'), sh('tip0002'), sh('tip0003')] },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  const state = o.getState();
  assert.equal(state.shareCount, 3);
  assert.equal(state.window.tip, 'tip0001');
  assert.equal(state.started, true);
  await o.stop();
});

test('start: empty window is valid', async () => {
  const transport = makeTransport({ window: { shares: [] } });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  assert.equal(o.getState().shareCount, 0);
  await o.stop();
});

// ── tip → delta → merge ───────────────────────────────────────────

test('tip: triggers delta fetch and appends new shares', async () => {
  let deltaArg: string | null = null;
  const transport = makeTransport({
    window: { shares: [sh('a'), sh('b')] },
    deltaForSince: (since) => {
      deltaArg = since;
      return { shares: [sh('newtip')] };
    },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  transport.fireTip({ hash: 'newtip', height: 2 });
  // Let the in-flight promise resolve.
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  const state = o.getState();
  assert.equal(deltaArg, 'a');
  assert.equal(state.window.tip, 'newtip');
  assert.equal(state.shareCount, 3);
  await o.stop();
});

test('tip: dedup — same hash twice does only one delta fetch', async () => {
  let calls = 0;
  const transport = makeTransport({
    window: { shares: [sh('a')] },
    deltaForSince: () => {
      calls++;
      return { shares: [sh('b')] };
    },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  transport.fireTip({ hash: 'b', height: 2 });
  transport.fireTip({ hash: 'b', height: 2 });
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 1);
  await o.stop();
});

test('tip: coalesces — rapid tips only run one delta at a time', async () => {
  let delivered = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const transport = makeTransport({
    window: { shares: [sh('a')] },
    deltaForSince: () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      const out = { shares: [sh(`new${delivered++}`)] };
      inFlight--;
      return out;
    },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  transport.fireTip({ hash: 'new0', height: 2 });
  transport.fireTip({ hash: 'new1', height: 3 });
  transport.fireTip({ hash: 'new2', height: 4 });
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
  assert.ok(maxInFlight <= 1, `maxInFlight was ${maxInFlight}`);
  await o.stop();
});

// ── fork_switch: full refresh ──────────────────────────────────────

test('fork_switch: triggers full window rebuild', async () => {
  let windowCalls = 0;
  const transport = makeTransport({
    window: { shares: [sh('a'), sh('b')] },
    deltaForSince: () => ({
      shares: [sh('fork1')],
      fork_switch: true,
    }),
  });
  const origFetch = transport.fetchWindow;
  transport.fetchWindow = async () => {
    windowCalls++;
    return origFetch.call(transport);
  };
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  assert.equal(windowCalls, 1);
  transport.fireTip({ hash: 'fork1', height: 2 });
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  // fork_switch triggers a second fetchWindow.
  assert.ok(windowCalls >= 2, `expected ≥ 2 window fetches, got ${windowCalls}`);
  await o.stop();
});

// ── animation skipped at threshold ────────────────────────────────

test('skipAnimationThreshold: bulk updates skip animation', async () => {
  const transport = makeTransport({
    window: { shares: [sh('a')] },
    deltaForSince: () => ({
      shares: Array.from({ length: 5 }, (_, i) => sh(`new${i}`)),
    }),
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
    skipAnimationThreshold: 3,  // 5 >= 3 → skip
  });
  await o.start();
  transport.fireTip({ hash: 'new0', height: 2 });
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(o.getState().animating, false);
  assert.equal(o.getState().shareCount, 6);
  await o.stop();
});

test('below threshold: animation starts', async () => {
  const transport = makeTransport({
    window: { shares: [sh('a'), sh('b')] },
    deltaForSince: () => ({ shares: [sh('c')] }),
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  transport.fireTip({ hash: 'c', height: 3 });
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(o.getState().animating, true);
  // Tick past tEnd — animation completes.
  const longLater = 100_000;
  o.currentFrame(longLater);
  assert.equal(o.getState().animating, false);
  await o.stop();
});

// ── stop() cleans up ──────────────────────────────────────────────

test('stop: unsubscribes and stops processing tips', async () => {
  let calls = 0;
  const transport = makeTransport({
    window: { shares: [sh('a')] },
    deltaForSince: () => {
      calls++;
      return { shares: [sh('x')] };
    },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  await o.stop();
  transport.fireTip({ hash: 'x', height: 2 });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 0);
});

// ── reconnect catch-up ────────────────────────────────────────────

test('reconnect: fetches tip, applies delta if changed', async () => {
  let deltaCalls = 0;
  const transport = makeTransport({
    window: { shares: [sh('a')] },
    tipResponse: () => ({ hash: 'newertip' }),
    deltaForSince: () => {
      deltaCalls++;
      return { shares: [sh('newertip')] };
    },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  transport.fireReconnect();
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(deltaCalls, 1);
  assert.equal(o.getState().window.tip, 'newertip');
  await o.stop();
});

// ── error path ────────────────────────────────────────────────────

test('fetchWindow error surfaces via onError', async () => {
  const transport = makeTransport();
  transport.fetchWindow = async () => {
    throw { type: 'transport', message: 'boom' };
  };
  const errs: ExplorerError[] = [];
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
    onError: (e) => errs.push(e),
  });
  await o.start();
  assert.equal(errs.length, 1);
  assert.equal(errs[0]?.type, 'transport');
  await o.stop();
});

// ── static frame output ───────────────────────────────────────────

test('currentFrame: static frame reflects window after idle', async () => {
  const transport = makeTransport({
    window: { shares: [sh('a'), sh('b'), sh('c')] },
  });
  const o = new RealtimeOrchestrator({
    transport,
    userContext: CONTEXT,
    containerWidth: CONTAINER_WIDTH,
  });
  await o.start();
  const frame = o.currentFrame(0);
  assert.ok(frame);
  assert.equal(frame!.cells.length, 3);
  assert.equal(frame!.cells[0]?.shareHash, 'a');
  await o.stop();
});
