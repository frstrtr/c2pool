// HttpTransport — default Transport implementation over fetch + EventSource.
// Six Explorer ops + three PPLNS ops + subscribeStream.
// AbortSignal wired through every read op (M1 D3, delta v1 §A.1).
// SSE reconnect / backoff / jitter live in the core.transport.retry
// middleware plugin (D7), NOT here.

import type {
  NegotiateResult,
  RequestOptions,
  StreamSubscription,
  TipEvent,
  Transport,
} from './types.js';
import type { ExplorerError } from '../errors.js';

export interface HttpTransportOptions {
  /** Base URL, e.g. "..", "", "https://pool.example". */
  baseUrl: string;
  /** Optional auth header (string or async factory). */
  authHeader?: string | (() => Promise<string>);
  /** Default apiVersion if server /negotiate is absent. */
  clientApiVersion?: string;
}

export function createHttpTransport(opts: HttpTransportOptions): Transport {
  const base = opts.baseUrl.replace(/\/+$/, '');
  const url = (path: string) => `${base}${path}`;

  const doGet = async (path: string, signal?: AbortSignal): Promise<unknown> => {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (opts.authHeader !== undefined) {
      const h = typeof opts.authHeader === 'string' ? opts.authHeader : await opts.authHeader();
      if (h) headers.Authorization = h;
    }
    const fetchInit: RequestInit = { method: 'GET', headers };
    if (signal !== undefined) fetchInit.signal = signal;
    const resp = await fetch(url(path), fetchInit);
    if (!resp.ok) {
      const retryAfterHeader = resp.headers.get('Retry-After');
      const retryAfterMs = retryAfterHeader !== null ? parseRetryAfter(retryAfterHeader) : undefined;
      const err: { status: number; message: string; retryAfter?: number } = {
        status: resp.status,
        message: `HTTP ${resp.status} ${resp.statusText}`,
      };
      if (retryAfterMs !== undefined) err.retryAfter = retryAfterMs;
      throw err;
    }
    return resp.json();
  };

  return {
    kind: 'http',
    fetchWindow:        (o) => doGet('/sharechain/window', o?.signal),
    fetchTip:           (o) => doGet('/sharechain/tip', o?.signal),
    fetchDelta:         (since, o) =>
      doGet(`/sharechain/delta?since=${encodeURIComponent(since)}`, o?.signal),
    fetchStats:         (o) => doGet('/sharechain/stats', o?.signal),
    fetchShareDetail:   (h, o) =>
      doGet(`/web/share/${encodeURIComponent(h)}`, o?.signal),
    negotiate:          async (o) => {
      try {
        const r = (await doGet('/api/negotiate', o?.signal)) as { apiVersion?: unknown };
        if (typeof r?.apiVersion === 'string') return { apiVersion: r.apiVersion };
      } catch {
        // negotiate endpoint not mandatory; fall through to default
      }
      return { apiVersion: opts.clientApiVersion ?? '1.0' } satisfies NegotiateResult;
    },
    fetchCurrentPayouts: (o) => doGet('/pplns/current', o?.signal),
    fetchMinerDetail:    (addr, o) =>
      doGet(`/pplns/miner/${encodeURIComponent(addr)}`, o?.signal),

    subscribeStream(onTip, onError, onReconnect): StreamSubscription {
      const EventSourceCtor =
        (globalThis as { EventSource?: typeof EventSource }).EventSource;
      if (EventSourceCtor === undefined) {
        const err: ExplorerError = {
          type: 'internal',
          message: 'EventSource unavailable; cannot subscribe to stream',
        };
        onError?.(err);
        return { unsubscribe: () => {} };
      }
      let es: EventSource | null = new EventSourceCtor(url('/sharechain/stream'));
      let connectedOnce = false;

      const onOpen = () => {
        if (connectedOnce) onReconnect?.();
        else connectedOnce = true;
      };
      const onMessage = (evt: MessageEvent) => {
        try {
          const data = JSON.parse(evt.data as string) as
            | { connected: true }
            | TipEvent;
          if ('connected' in data) return; // skip the hello event
          if ('hash' in data && 'height' in data) onTip(data);
        } catch (err) {
          onError?.({ type: 'schema', message: 'malformed SSE payload', path: '$', got: evt.data });
        }
      };
      const onErr = (_evt: Event) => {
        onError?.({ type: 'transport', message: 'SSE error', url: url('/sharechain/stream') });
      };

      es.addEventListener('open', onOpen);
      es.addEventListener('message', onMessage);
      es.addEventListener('error', onErr);

      return {
        unsubscribe(): void {
          if (!es) return;
          es.removeEventListener('open', onOpen);
          es.removeEventListener('message', onMessage);
          es.removeEventListener('error', onErr);
          es.close();
          es = null;
        },
      };
    },
  };
}

function parseRetryAfter(v: string): number | undefined {
  const seconds = Number(v);
  if (!Number.isNaN(seconds)) return Math.floor(seconds * 1000);
  const date = Date.parse(v);
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return undefined;
}
