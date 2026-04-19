// Transport interface (Explorer spec §4.2, delta v1 §A, M1 D3/D7).
// Six Explorer ops + three PPLNS ops + stream + reconnect + negotiate.
// Every read op takes an optional AbortSignal; middleware wraps.

import type { ExplorerError } from '../errors.js';

export type TransportKind = 'http' | 'qt' | 'demo';

export interface TipEvent {
  hash: string;   // short-hash (16 hex)
  height: number;
}

export interface NegotiateResult {
  apiVersion: string;  // semver per M1 D12 / delta v1 §F
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface StreamSubscription {
  unsubscribe(): void;
}

export interface Transport {
  readonly kind: TransportKind;

  // Explorer ops (6)
  fetchWindow(opts?: RequestOptions): Promise<unknown>;
  fetchTip(opts?: RequestOptions): Promise<unknown>;
  fetchDelta(since: string, opts?: RequestOptions): Promise<unknown>;
  fetchStats(opts?: RequestOptions): Promise<unknown>;
  fetchShareDetail(fullHash: string, opts?: RequestOptions): Promise<unknown>;
  negotiate(opts?: RequestOptions): Promise<NegotiateResult>;

  // PPLNS ops (3)
  fetchCurrentPayouts(opts?: RequestOptions): Promise<unknown>;
  fetchMinerDetail(address: string, opts?: RequestOptions): Promise<unknown>;

  // Streaming
  subscribeStream(
    onTip: (ev: TipEvent) => void,
    onError?: (err: ExplorerError) => void,
    onReconnect?: () => void,
  ): StreamSubscription;
}

/** Canonical list of Transport operation names; used by middleware. */
export const TRANSPORT_OPS = [
  'fetchWindow',
  'fetchTip',
  'fetchDelta',
  'fetchStats',
  'fetchShareDetail',
  'negotiate',
  'fetchCurrentPayouts',
  'fetchMinerDetail',
] as const;
export type TransportOp = (typeof TRANSPORT_OPS)[number];
