// Event bus (plugin-arch §6).
// Sync emit by default; emitAsync awaits all handlers.
// Handlers run in registration order. Middleware (event kind) wraps emit.

export type Handler<P> = (payload: P) => void | Promise<void>;
export type Unsubscribe = () => void;

export class EventBus {
  private readonly subs = new Map<string, Set<Handler<unknown>>>();
  private disposed = false;

  on<P = unknown>(name: string, handler: Handler<P>): Unsubscribe {
    if (this.disposed) return () => {};
    let set = this.subs.get(name);
    if (!set) {
      set = new Set();
      this.subs.set(name, set);
    }
    set.add(handler as Handler<unknown>);
    return () => {
      this.subs.get(name)?.delete(handler as Handler<unknown>);
    };
  }

  once<P = unknown>(name: string, handler: Handler<P>): Unsubscribe {
    const off = this.on<P>(name, (p) => {
      off();
      void handler(p);
    });
    return off;
  }

  off<P = unknown>(name: string, handler: Handler<P>): void {
    this.subs.get(name)?.delete(handler as Handler<unknown>);
  }

  emit<P = unknown>(name: string, payload: P): void {
    if (this.disposed) return;
    const set = this.subs.get(name);
    if (!set) return;
    // Snapshot to survive mutation during dispatch.
    for (const handler of Array.from(set)) {
      try {
        const r = handler(payload);
        if (r && typeof (r as Promise<void>).then === 'function') {
          // Fire-and-forget; surface errors as a separate 'error' emission.
          (r as Promise<void>).catch((err: unknown) => {
            this.emitError(name, err);
          });
        }
      } catch (err) {
        this.emitError(name, err);
      }
    }
  }

  async emitAsync<P = unknown>(name: string, payload: P): Promise<void> {
    if (this.disposed) return;
    const set = this.subs.get(name);
    if (!set) return;
    const snapshot = Array.from(set);
    await Promise.allSettled(snapshot.map((h) => Promise.resolve(h(payload))));
  }

  clear(): void {
    this.subs.clear();
  }

  dispose(): void {
    this.disposed = true;
    this.subs.clear();
  }

  private emitError(sourceEvent: string, err: unknown): void {
    if (sourceEvent === 'error') return; // avoid loops
    const set = this.subs.get('error');
    if (!set) return;
    for (const h of Array.from(set)) {
      try {
        h({ sourceEvent, err });
      } catch {
        // swallow — we're in the error path already
      }
    }
  }
}
