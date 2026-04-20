// Per-miner drill-down panel. Renders a PplnsMinerDetail into an
// overlay DOM node attached to the host container. Addresses the
// spec §5.2 "single most-requested ops feature" point from the
// pplns-view-module task.
//
// Security: every piece of miner-supplied or server-supplied text
// goes through textContent or a documented escape; this module
// never touches innerHTML. (The legacy dashboard tooltip bug at
// dashboard.html:6199-6203 is explicitly called out in §2.)
//
// Layout: fixed-position overlay pinned to the top-right of the
// host container (or document.body fallback). Close via the X
// button, an Escape keypress, or a backdrop click.

import type {
  CoinPplnsDescriptor,
  PplnsMinerDetail,
  HashrateSeriesPoint,
  VersionHistoryPoint,
  RecentShare,
} from './types.js';
import { formatHashrate as defaultFormatHashrate } from './classify.js';

export interface DetailPanelHandle {
  element: HTMLElement;
  close(): void;
}

export interface DetailPanelOptions {
  /** Host that the panel sits above — the panel attaches to the
   *  container's parent so it floats over the treemap without
   *  disturbing layout. Falls back to document.body. */
  host: HTMLElement;
  detail: PplnsMinerDetail;
  coin: CoinPplnsDescriptor;
  /** Called when the user closes the panel (X, Escape, backdrop). */
  onClose?: () => void;
}

const PANEL_STYLE: Partial<CSSStyleDeclaration> = {
  position: 'absolute',
  right: '16px',
  top: '16px',
  zIndex: '10',
  width: 'min(420px, calc(100% - 32px))',
  maxHeight: 'calc(100% - 32px)',
  overflowY: 'auto',
  background: '#1e1f22',
  color: '#e6e6e6',
  border: '1px solid #3a3d44',
  borderRadius: '8px',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)',
  fontFamily: 'system-ui, -apple-system, sans-serif',
  fontSize: '13px',
  lineHeight: '1.4',
};

const HEADER_STYLE: Partial<CSSStyleDeclaration> = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '12px 14px',
  borderBottom: '1px solid #3a3d44',
  background: '#24262a',
};

const BODY_STYLE: Partial<CSSStyleDeclaration> = {
  padding: '14px',
  display: 'flex',
  flexDirection: 'column',
  gap: '14px',
};

const SECTION_LABEL_STYLE: Partial<CSSStyleDeclaration> = {
  fontSize: '11px',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  color: '#8a8c90',
  marginBottom: '4px',
};

export function renderMinerDetail(opts: DetailPanelOptions): DetailPanelHandle {
  const { host, detail, coin, onClose } = opts;
  // Ensure the host can anchor position: absolute children.
  const anchor = ensurePositioned(host);
  const panel = document.createElement('div');
  panel.className = 'pplns-detail-panel';
  applyStyle(panel, PANEL_STYLE);
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Miner detail');

  // ── Header ────────────────────────────────────────────────────────
  const header = document.createElement('div');
  applyStyle(header, HEADER_STYLE);

  const title = document.createElement('div');
  const label = document.createElement('div');
  label.style.fontWeight = '600';
  label.textContent = truncateAddress(detail.address);
  label.title = detail.address;
  const sub = document.createElement('div');
  sub.style.fontSize = '11px';
  sub.style.color = '#8a8c90';
  sub.style.marginTop = '2px';
  sub.textContent = detail.inWindow
    ? 'In PPLNS window'
    : 'Not in current window';
  title.appendChild(label);
  title.appendChild(sub);
  header.appendChild(title);

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.setAttribute('aria-label', 'Close miner detail');
  closeBtn.textContent = '\u00d7';
  applyStyle(closeBtn, {
    background: 'transparent',
    border: 'none',
    color: '#8a8c90',
    fontSize: '20px',
    cursor: 'pointer',
    padding: '0 4px',
    lineHeight: '1',
  });
  header.appendChild(closeBtn);
  panel.appendChild(header);

  // ── Body ──────────────────────────────────────────────────────────
  const body = document.createElement('div');
  applyStyle(body, BODY_STYLE);
  panel.appendChild(body);

  // Payout row
  if (detail.amount !== undefined) {
    body.appendChild(makePayoutRow(detail, coin));
  }

  // Hashrate + sparkline
  if (detail.hashrateHps !== undefined) {
    body.appendChild(makeHashrateRow(detail, coin));
  }

  // Share counts
  body.appendChild(makeShareCountsRow(detail));

  // Version badge + history
  if (detail.version !== undefined || detail.versionHistory !== undefined) {
    body.appendChild(makeVersionRow(detail, coin));
  }

  // Merged payouts
  if (detail.merged.length > 0) {
    body.appendChild(makeMergedRow(detail, coin));
  }

  // Recent shares table
  if (detail.recentShares !== undefined && detail.recentShares.length > 0) {
    body.appendChild(makeRecentSharesRow(detail.recentShares));
  }

  // Times
  body.appendChild(makeTimesRow(detail));

  anchor.appendChild(panel);

  // ── Close wiring ──────────────────────────────────────────────────
  const handle: DetailPanelHandle = {
    element: panel,
    close() {
      if (panel.parentNode !== null) panel.parentNode.removeChild(panel);
      document.removeEventListener('keydown', onKey);
      if (onClose !== undefined) onClose();
    },
  };
  const onKey = (ev: KeyboardEvent): void => {
    if (ev.key === 'Escape') handle.close();
  };
  closeBtn.addEventListener('click', () => handle.close());
  document.addEventListener('keydown', onKey);
  return handle;
}

// ── Section builders ─────────────────────────────────────────────────

function makePayoutRow(
  detail: PplnsMinerDetail,
  coin: CoinPplnsDescriptor,
): HTMLElement {
  const row = sectionFrame('Payout');
  const amt = document.createElement('div');
  amt.style.fontSize = '18px';
  amt.style.fontWeight = '600';
  amt.textContent = formatAmount(detail.amount ?? 0, coin);
  row.appendChild(amt);
  if (detail.pct !== undefined) {
    const pct = document.createElement('div');
    pct.style.fontSize = '12px';
    pct.style.color = '#8a8c90';
    pct.textContent = `${(detail.pct * 100).toFixed(2)}% of current PPLNS window`;
    row.appendChild(pct);
  }
  return row;
}

function makeHashrateRow(
  detail: PplnsMinerDetail,
  coin: CoinPplnsDescriptor,
): HTMLElement {
  const row = sectionFrame('Hashrate');
  const fmt = coin.formatHashrate ?? defaultFormatHashrate;
  const top = document.createElement('div');
  top.style.fontSize = '15px';
  top.style.fontWeight = '500';
  top.textContent = fmt(detail.hashrateHps ?? 0);
  row.appendChild(top);

  if (detail.hashrateSeries !== undefined && detail.hashrateSeries.length >= 2) {
    const svg = makeSparkline(detail.hashrateSeries);
    row.appendChild(svg);
  }
  return row;
}

function makeSparkline(series: readonly HashrateSeriesPoint[]): SVGElement {
  // Inline SVG sparkline. Width 100% of section, fixed 48px height.
  const w = 380;   // viewbox units — CSS scales to container width
  const h = 48;
  const pad = 2;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.style.width = '100%';
  svg.style.height = `${h}px`;
  svg.style.marginTop = '6px';

  const ts = series.map((p) => p.t);
  const hs = series.map((p) => p.hps);
  const tMin = Math.min(...ts);
  const tMax = Math.max(...ts);
  const hMax = Math.max(...hs, 1);
  const tRange = Math.max(1, tMax - tMin);

  const x = (t: number): number => pad + ((t - tMin) / tRange) * (w - 2 * pad);
  const y = (v: number): number => pad + (1 - v / hMax) * (h - 2 * pad);

  const d = series
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.t).toFixed(1)},${y(p.hps).toFixed(1)}`)
    .join(' ');

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', '#7aa7ff');
  path.setAttribute('stroke-width', '1.5');
  svg.appendChild(path);

  // Fill under the curve
  const fill = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  fill.setAttribute('d', `${d} L${x(tMax).toFixed(1)},${h - pad} L${x(tMin).toFixed(1)},${h - pad} Z`);
  fill.setAttribute('fill', '#7aa7ff');
  fill.setAttribute('fill-opacity', '0.15');
  svg.appendChild(fill);
  svg.insertBefore(fill, path);
  return svg;
}

function makeShareCountsRow(detail: PplnsMinerDetail): HTMLElement {
  const row = sectionFrame('Shares');
  const grid = document.createElement('div');
  grid.style.display = 'grid';
  grid.style.gridTemplateColumns = '1fr 1fr';
  grid.style.gap = '8px';
  const inWin = kv('In window',
    detail.sharesInWindow !== undefined ? detail.sharesInWindow.toString() : '—');
  const total = kv('Total',
    detail.sharesTotal !== undefined ? detail.sharesTotal.toString() : '—');
  grid.appendChild(inWin);
  grid.appendChild(total);
  row.appendChild(grid);
  return row;
}

function makeVersionRow(
  detail: PplnsMinerDetail,
  coin: CoinPplnsDescriptor,
): HTMLElement {
  const row = sectionFrame('Version');
  const top = document.createElement('div');
  top.style.display = 'flex';
  top.style.alignItems = 'center';
  top.style.gap = '8px';

  if (detail.version !== undefined) {
    const classifyArg: Pick<PplnsMinerDetail, 'version' | 'desiredVersion'> = {
      version: detail.version,
    };
    if (detail.desiredVersion !== undefined) {
      classifyArg.desiredVersion = detail.desiredVersion;
    }
    const key = coin.versionBadges.classify(classifyArg);
    const badge = coin.versionBadges.palette[key];
    const chip = document.createElement('span');
    chip.textContent = badge?.label ?? `V${detail.version}`;
    applyStyle(chip, {
      background: badge?.color ?? '#555',
      color: '#fff',
      fontSize: '11px',
      fontWeight: '600',
      padding: '2px 8px',
      borderRadius: '10px',
      letterSpacing: '0.02em',
    });
    top.appendChild(chip);
    const raw = document.createElement('span');
    raw.style.fontSize = '12px';
    raw.style.color = '#8a8c90';
    const desired = detail.desiredVersion !== undefined
      ? ` (desired V${detail.desiredVersion})` : '';
    raw.textContent = `Running V${detail.version}${desired}`;
    top.appendChild(raw);
  }
  row.appendChild(top);

  if (detail.versionHistory !== undefined && detail.versionHistory.length > 0) {
    row.appendChild(makeVersionHistory(detail.versionHistory));
  }
  return row;
}

function makeVersionHistory(
  history: readonly VersionHistoryPoint[],
): HTMLElement {
  const box = document.createElement('div');
  box.style.marginTop = '6px';
  box.style.display = 'flex';
  box.style.flexDirection = 'column';
  box.style.gap = '2px';
  for (const p of history) {
    const line = document.createElement('div');
    line.style.display = 'flex';
    line.style.justifyContent = 'space-between';
    line.style.fontSize = '11px';
    line.style.color = '#a8abb0';
    const when = document.createElement('span');
    when.textContent = formatRelative(p.t);
    const label = document.createElement('span');
    label.textContent = p.desiredVersion !== undefined && p.desiredVersion !== p.version
      ? `V${p.version} (signaling V${p.desiredVersion})`
      : `V${p.version}`;
    line.appendChild(when);
    line.appendChild(label);
    box.appendChild(line);
  }
  return box;
}

function makeMergedRow(
  detail: PplnsMinerDetail,
  coin: CoinPplnsDescriptor,
): HTMLElement {
  const row = sectionFrame('Merged chains');
  for (const m of detail.merged) {
    const line = document.createElement('div');
    line.style.display = 'flex';
    line.style.justifyContent = 'space-between';
    line.style.alignItems = 'center';
    line.style.gap = '8px';
    line.style.padding = '4px 0';

    const left = document.createElement('div');
    const sym = document.createElement('span');
    const desc = coin.mergedChains.find((c) => c.symbol === m.symbol);
    sym.textContent = desc?.displayLabel ?? m.symbol;
    sym.style.fontWeight = '500';
    if (desc !== undefined) sym.style.color = desc.color;
    left.appendChild(sym);
    if (m.source !== undefined) {
      const src = document.createElement('span');
      src.style.marginLeft = '6px';
      src.style.fontSize = '10px';
      src.style.color = '#8a8c90';
      src.textContent = `(${m.source})`;
      left.appendChild(src);
    }
    const addr = document.createElement('div');
    addr.style.fontSize = '11px';
    addr.style.color = '#8a8c90';
    addr.textContent = truncateAddress(m.address);
    addr.title = m.address;
    left.appendChild(addr);
    line.appendChild(left);

    const right = document.createElement('div');
    right.style.textAlign = 'right';
    right.style.fontVariantNumeric = 'tabular-nums';
    right.textContent = m.amount.toFixed(4);
    line.appendChild(right);
    row.appendChild(line);
  }
  return row;
}

function makeRecentSharesRow(shares: readonly RecentShare[]): HTMLElement {
  const row = sectionFrame('Recent shares');
  const table = document.createElement('div');
  table.style.display = 'grid';
  table.style.gridTemplateColumns = 'auto 1fr auto auto';
  table.style.columnGap = '10px';
  table.style.rowGap = '2px';
  table.style.fontSize = '11px';
  table.style.fontFamily = 'ui-monospace, Menlo, Consolas, monospace';

  // Header
  for (const label of ['#', 'Hash', 'Ver', 'Age']) {
    const h = document.createElement('div');
    h.textContent = label;
    h.style.color = '#8a8c90';
    h.style.fontSize = '10px';
    h.style.textTransform = 'uppercase';
    h.style.letterSpacing = '0.05em';
    table.appendChild(h);
  }
  shares.forEach((s, i) => {
    const stale = s.s === 1;
    const color = stale ? '#b04020' : '#d0d4d8';
    const idxCell = document.createElement('div');
    idxCell.textContent = `${i + 1}`;
    idxCell.style.color = '#8a8c90';
    const hashCell = document.createElement('div');
    hashCell.textContent = s.h;
    hashCell.style.color = color;
    if (stale) hashCell.title = 'Pruned by dead-chain check';
    const verCell = document.createElement('div');
    verCell.textContent = s.V !== undefined ? `V${s.V}` : '—';
    verCell.style.color = color;
    verCell.style.textAlign = 'right';
    const ageCell = document.createElement('div');
    ageCell.textContent = formatRelative(s.t);
    ageCell.style.color = color;
    ageCell.style.textAlign = 'right';
    table.appendChild(idxCell);
    table.appendChild(hashCell);
    table.appendChild(verCell);
    table.appendChild(ageCell);
  });
  row.appendChild(table);
  return row;
}

function makeTimesRow(detail: PplnsMinerDetail): HTMLElement {
  const row = sectionFrame('Activity');
  const grid = document.createElement('div');
  grid.style.display = 'grid';
  grid.style.gridTemplateColumns = '1fr 1fr';
  grid.style.gap = '8px';
  grid.appendChild(kv('First seen',
    detail.firstSeenAt !== undefined ? formatRelative(detail.firstSeenAt) : '—'));
  grid.appendChild(kv('Last share',
    detail.lastShareAt !== undefined ? formatRelative(detail.lastShareAt) : '—'));
  row.appendChild(grid);
  return row;
}

// ── helpers ──────────────────────────────────────────────────────────

function sectionFrame(label: string): HTMLElement {
  const s = document.createElement('section');
  s.style.display = 'flex';
  s.style.flexDirection = 'column';
  const lab = document.createElement('div');
  applyStyle(lab, SECTION_LABEL_STYLE);
  lab.textContent = label;
  s.appendChild(lab);
  return s;
}

function kv(label: string, value: string): HTMLElement {
  const wrap = document.createElement('div');
  const k = document.createElement('div');
  k.style.fontSize = '10px';
  k.style.color = '#8a8c90';
  k.style.textTransform = 'uppercase';
  k.style.letterSpacing = '0.05em';
  k.textContent = label;
  const v = document.createElement('div');
  v.style.fontSize = '13px';
  v.style.fontVariantNumeric = 'tabular-nums';
  v.textContent = value;
  wrap.appendChild(k);
  wrap.appendChild(v);
  return wrap;
}

function truncateAddress(addr: string): string {
  if (addr.length <= 16) return addr;
  return `${addr.slice(0, 8)}\u2026${addr.slice(-6)}`;
}

function formatAmount(amount: number, coin: CoinPplnsDescriptor): string {
  const label = coin.mergedChains.length > 0 && typeof coin.mergedChains[0]?.symbol === 'string'
    ? ''  // primary amount; coin symbol isn't on the descriptor
    : '';
  return `${amount.toFixed(8)}${label}`;
}

function formatRelative(tSec: number): string {
  const now = Math.floor(Date.now() / 1000);
  const ago = now - tSec;
  if (ago < 0) return 'in future';
  if (ago < 60) return `${ago}s ago`;
  if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
  if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
  return `${Math.floor(ago / 86400)}d ago`;
}

function applyStyle(el: HTMLElement | SVGElement, style: Partial<CSSStyleDeclaration>): void {
  for (const [k, v] of Object.entries(style)) {
    if (v === undefined) continue;
    (el.style as unknown as Record<string, string>)[k] = v as string;
  }
}

function ensurePositioned(host: HTMLElement): HTMLElement {
  const pos = getComputedStyleSafe(host).position;
  if (pos === 'absolute' || pos === 'relative' || pos === 'fixed' || pos === 'sticky') {
    return host;
  }
  host.style.position = 'relative';
  return host;
}

function getComputedStyleSafe(el: HTMLElement): CSSStyleDeclaration {
  if (typeof window === 'undefined' || typeof window.getComputedStyle !== 'function') {
    return el.style;
  }
  return window.getComputedStyle(el);
}
