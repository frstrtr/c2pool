// AbortController helpers (M1 D3, delta v1 §A.1).

export type Disposable = () => void;

/**
 * Tracks async work so host.destroy() can await settlement.
 * Returned disposer removes a promise once it settles; AbortController
 * is the mechanism that propagates cancellation through Transport calls.
 */
export class PendingTracker {
  private readonly pending = new Set<Promise<unknown>>();

  track<T>(p: Promise<T>): Promise<T> {
    this.pending.add(p);
    p.finally(() => this.pending.delete(p)).catch(() => {});
    return p;
  }

  size(): number {
    return this.pending.size;
  }

  async settled(): Promise<void> {
    if (this.pending.size === 0) return;
    await Promise.allSettled(Array.from(this.pending));
  }
}
