// Linked selection across views. Views on different engines (the PPLNS
// treemap, the share-chain grid, a later roundabout map) share one bus
// and agree on a subject key: a miner's payout address. Hovering a tile
// in one view highlights the same subject in the others; pinning keeps
// it highlighted and filters; the search query dims non-matching tiles.

export interface SelectionState {
  /** Subject under the pointer in some view, or null. */
  hover: string | null;
  /** Pinned subject (click), or null. Esc clears it. */
  pinned: string | null;
  /** Lower-cased search text; '' when none. */
  query: string;
  /** Which view caused the last change (views ignore their own echo). */
  source: string | null;
}

export interface SelectionBus {
  get(): Readonly<SelectionState>;
  hover(subject: string | null, source?: string): void;
  pin(subject: string | null, source?: string): void;
  /** Pin `subject`, or unpin it if it is already pinned. */
  togglePin(subject: string, source?: string): void;
  search(query: string, source?: string): void;
  /** Called after every change. Returns an unsubscribe function. */
  subscribe(fn: (s: Readonly<SelectionState>) => void): () => void;
}

export function createSelectionBus(): SelectionBus {
  let state: SelectionState = { hover: null, pinned: null, query: '', source: null };
  const subs = new Set<(s: Readonly<SelectionState>) => void>();
  const set = (patch: Partial<SelectionState>, source: string | undefined): void => {
    const next = { ...state, ...patch, source: source ?? null };
    if (next.hover === state.hover && next.pinned === state.pinned && next.query === state.query) return;
    state = next;
    for (const fn of [...subs]) fn(state);
  };
  return {
    get: () => state,
    hover: (subject, source) => set({ hover: subject }, source),
    pin: (subject, source) => set({ pinned: subject }, source),
    togglePin: (subject, source) => set({ pinned: state.pinned === subject ? null : subject }, source),
    search: (query, source) => set({ query: query.trim().toLowerCase() }, source),
    subscribe(fn) {
      subs.add(fn);
      return () => { subs.delete(fn); };
    },
  };
}

/** True when `subject` matches a lower-cased query (substring). */
export function matchesQuery(subject: string, query: string): boolean {
  return query.length > 0 && subject.toLowerCase().includes(query);
}
