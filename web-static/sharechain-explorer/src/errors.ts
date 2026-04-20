// Structured error taxonomy (M1 D3/D7, delta v1 §A.5).
// Every bridge, transport call, schema validation, and host-lifecycle
// path rejects/emits with one of these discriminated variants. Plugins
// type-check against `type` only; new types append, never remove.

export type ExplorerError =
  | { type: 'transport'; message: string; cause?: unknown; status?: number; url?: string }
  | { type: 'schema'; message: string; path: string; got?: unknown }
  | { type: 'contract'; message: string; detail: unknown }
  | { type: 'version_mismatch'; message: string; client: string; server: string }
  | { type: 'rate_limited'; message: string; retryAfterMs?: number }
  | { type: 'fork_switch'; message: string; since: string }
  | { type: 'internal'; message: string; cause?: unknown };

export function isExplorerError(x: unknown): x is ExplorerError {
  return (
    typeof x === 'object' &&
    x !== null &&
    'type' in x &&
    typeof (x as { type: unknown }).type === 'string'
  );
}

export function internal(message: string, cause?: unknown): ExplorerError {
  return cause !== undefined
    ? { type: 'internal', message, cause }
    : { type: 'internal', message };
}

export function schemaError(path: string, message: string, got?: unknown): ExplorerError {
  return got !== undefined
    ? { type: 'schema', message, path, got }
    : { type: 'schema', message, path };
}
