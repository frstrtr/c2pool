// Sort / filter / search toolbar for the PPLNS View.
//
// The PplnsController already has the three entry points
// (setSort, setFilter, setSearch) per spec §6; this module
// supplies the corresponding UI so callers don't have to build
// their own. Toolbar lives above the treemap grid and is rebuilt
// on every paint — it's cheap and keeps version-chip counts in
// sync with the current snapshot.
//
// Version filtering is implemented as a predicate composed from
// the active chip set; empty set = all miners.
//
// Security: every piece of rendered text uses textContent; the
// search input is an HTMLInputElement whose value is read via
// .value (string), never interpolated into DOM.

import type {
  CoinPplnsDescriptor,
  PplnsMiner,
  PplnsSnapshot,
  SortKey,
} from './types.js';

export interface ToolbarState {
  sort: SortKey;
  search: string;
  /** Set of version-badge keys currently active. Empty = all. */
  activeVersionKeys: ReadonlySet<string>;
}

export interface ToolbarCallbacks {
  onSortChange: (key: SortKey) => void;
  onSearchChange: (prefix: string) => void;
  onVersionKeysChange: (keys: ReadonlySet<string>) => void;
}

export interface ToolbarRenderArgs {
  host: HTMLElement;
  state: ToolbarState;
  snapshot: PplnsSnapshot | null;
  coin: CoinPplnsDescriptor;
  callbacks: ToolbarCallbacks;
}

/** Classify a miner into a version-badge key using the coin
 *  descriptor. Exposed so the controller can build the active
 *  filter predicate from the toolbar's key set. */
export function minerVersionKey(
  miner: Pick<PplnsMiner, 'version' | 'desiredVersion'>,
  coin: CoinPplnsDescriptor,
): string {
  const arg: Pick<PplnsMiner, 'version' | 'desiredVersion'> = {};
  if (miner.version !== undefined)        arg.version        = miner.version;
  if (miner.desiredVersion !== undefined) arg.desiredVersion = miner.desiredVersion;
  return coin.versionBadges.classify(arg);
}

export function renderToolbar(args: ToolbarRenderArgs): void {
  const { host, state, snapshot, coin, callbacks } = args;
  clearChildren(host);
  host.className = 'pplns-toolbar';
  applyStyle(host, {
    display: 'flex',
    flexWrap: 'wrap',
    alignItems: 'center',
    gap: '10px',
    padding: '8px 10px',
    borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
    background: 'rgba(30, 31, 34, 0.85)',
    color: '#d0d4d8',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    fontSize: '12px',
  });

  // ── Sort ──────────────────────────────────────────────────────────
  host.appendChild(label('Sort'));
  const sortSelect = document.createElement('select');
  applyStyle(sortSelect, CONTROL_STYLE);
  for (const opt of SORT_OPTIONS) {
    const o = document.createElement('option');
    o.value = opt.key;
    o.textContent = opt.label;
    if (state.sort === opt.key) o.selected = true;
    sortSelect.appendChild(o);
  }
  sortSelect.addEventListener('change', () => {
    callbacks.onSortChange(sortSelect.value as SortKey);
  });
  host.appendChild(sortSelect);

  // ── Version chips ─────────────────────────────────────────────────
  const versionCounts = countVersions(snapshot, coin);
  if (versionCounts.size > 0) {
    host.appendChild(divider());
    host.appendChild(label('Version'));
    for (const [key, count] of versionCounts) {
      const badge = coin.versionBadges.palette[key];
      if (badge === undefined) continue;
      const chip = makeChip({
        label: badge.label,
        count,
        color: badge.color,
        active: state.activeVersionKeys.has(key),
        onToggle: () => {
          const next = new Set(state.activeVersionKeys);
          if (next.has(key)) next.delete(key);
          else next.add(key);
          callbacks.onVersionKeysChange(next);
        },
      });
      host.appendChild(chip);
    }
    if (state.activeVersionKeys.size > 0) {
      const clear = makeTextButton('Clear', () => {
        callbacks.onVersionKeysChange(new Set());
      });
      host.appendChild(clear);
    }
  }

  // ── Search ────────────────────────────────────────────────────────
  host.appendChild(flexSpacer());
  const searchInput = document.createElement('input');
  searchInput.type = 'search';
  searchInput.placeholder = 'Search address prefix\u2026';
  searchInput.spellcheck = false;
  searchInput.autocomplete = 'off';
  searchInput.value = state.search;
  applyStyle(searchInput, {
    ...CONTROL_STYLE,
    minWidth: '180px',
    fontFamily: 'ui-monospace, Menlo, Consolas, monospace',
  } as Partial<CSSStyleDeclaration>);
  // Input events coalesced at the controller level (paintFromState
  // is cheap but not free). Keep it immediate here.
  searchInput.addEventListener('input', () => {
    callbacks.onSearchChange(searchInput.value);
  });
  // Ctrl/Cmd-F focuses the search field per spec §2.
  const onGlobalKey = (ev: KeyboardEvent): void => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'f') {
      // Only claim Ctrl-F if the toolbar is still mounted.
      if (!host.isConnected) {
        document.removeEventListener('keydown', onGlobalKey);
        return;
      }
      ev.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  };
  document.addEventListener('keydown', onGlobalKey);
  host.appendChild(searchInput);
}

// ── helpers ──────────────────────────────────────────────────────────

const SORT_OPTIONS: readonly { key: SortKey; label: string }[] = [
  { key: 'amount',   label: 'Amount' },
  { key: 'hashrate', label: 'Hashrate' },
  { key: 'address',  label: 'Address' },
  { key: 'version',  label: 'Version' },
];

const CONTROL_STYLE: Partial<CSSStyleDeclaration> = {
  background: '#2a2c30',
  color: '#d0d4d8',
  border: '1px solid #3a3d44',
  borderRadius: '4px',
  padding: '4px 8px',
  fontSize: '12px',
};

function countVersions(
  snap: PplnsSnapshot | null,
  coin: CoinPplnsDescriptor,
): Map<string, number> {
  const counts = new Map<string, number>();
  if (snap === null) return counts;
  // Preserve palette order so chips appear in a stable sequence.
  const order = Object.keys(coin.versionBadges.palette);
  for (const m of snap.miners) {
    const key = minerVersionKey(m, coin);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const ordered = new Map<string, number>();
  for (const k of order) {
    const c = counts.get(k);
    if (c !== undefined && c > 0) ordered.set(k, c);
  }
  // Append any non-palette keys (shouldn't happen, but defensive).
  for (const [k, c] of counts) {
    if (!ordered.has(k)) ordered.set(k, c);
  }
  return ordered;
}

interface ChipOpts {
  label: string;
  count: number;
  color: string;
  active: boolean;
  onToggle: () => void;
}

function makeChip(opts: ChipOpts): HTMLElement {
  const btn = document.createElement('button');
  btn.type = 'button';
  applyStyle(btn, {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '2px 8px',
    borderRadius: '12px',
    border: `1px solid ${opts.active ? opts.color : '#3a3d44'}`,
    background: opts.active ? `${opts.color}22` : 'transparent',
    color: opts.active ? opts.color : '#d0d4d8',
    fontSize: '11px',
    fontWeight: '500',
    cursor: 'pointer',
  });
  const dot = document.createElement('span');
  applyStyle(dot, {
    display: 'inline-block',
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: opts.color,
  });
  btn.appendChild(dot);
  const labelEl = document.createElement('span');
  labelEl.textContent = opts.label;
  btn.appendChild(labelEl);
  const countEl = document.createElement('span');
  countEl.textContent = String(opts.count);
  applyStyle(countEl, {
    color: '#8a8c90',
    fontVariantNumeric: 'tabular-nums',
  });
  btn.appendChild(countEl);
  btn.addEventListener('click', opts.onToggle);
  return btn;
}

function makeTextButton(label: string, onClick: () => void): HTMLElement {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = label;
  applyStyle(btn, {
    background: 'transparent',
    color: '#8a8c90',
    border: 'none',
    cursor: 'pointer',
    fontSize: '11px',
    padding: '2px 4px',
  });
  btn.addEventListener('click', onClick);
  return btn;
}

function label(text: string): HTMLElement {
  const l = document.createElement('span');
  l.textContent = text;
  applyStyle(l, {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: '#8a8c90',
  });
  return l;
}

function divider(): HTMLElement {
  const d = document.createElement('span');
  applyStyle(d, {
    width: '1px',
    alignSelf: 'stretch',
    background: 'rgba(255, 255, 255, 0.08)',
    margin: '0 2px',
  });
  return d;
}

function flexSpacer(): HTMLElement {
  const s = document.createElement('span');
  s.style.flex = '1 1 auto';
  return s;
}

function applyStyle(
  el: HTMLElement,
  style: Partial<CSSStyleDeclaration>,
): void {
  for (const [k, v] of Object.entries(style)) {
    if (v === undefined) continue;
    (el.style as unknown as Record<string, string>)[k] = v as string;
  }
}

function clearChildren(el: HTMLElement): void {
  while (el.firstChild !== null) el.removeChild(el.firstChild);
}
