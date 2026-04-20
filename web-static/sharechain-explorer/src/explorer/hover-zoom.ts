// Hover-zoom panel — on-hover 240×240 canvas showing the PPLNS
// distribution at a specific share's position (dashboard.html:5686-
// 5782 port). Pure build + thin DOM adapter, same split pattern as
// grid-paint.ts.
//
// Provides capabilities:
//   renderer.hover-zoom        — { buildHoverZoomProgram,
//                                  createHoverZoomPanel }

import type { PluginDescriptor } from '../registry.js';
import type { PaintCommand, CanvasLike } from './grid-paint.js';
import { executePaintProgram } from './grid-paint.js';
import { squarify } from '../plugins/treemap-squarified.js';
import { addrHue } from '../plugins/addr-hue.js';
import type { PPLNSEntry } from './pplns.js';

export interface HoverZoomBuildOptions {
  pplns: readonly PPLNSEntry[];
  size: number;          // pixel square, e.g. 240
  dpr: number;
  hoveredMinerAddr?: string | undefined;  // brightest colour
  myAddress?: string | undefined;         // mid colour for my own cells
  backgroundColor?: string;
  innerPadding?: number; // leave a margin inside the square
}

const DEFAULTS = {
  backgroundColor: '#0d0d1a',
  innerPadding: 2,
} as const;

/** Build the PaintCommand program for one hover-zoom frame. Pure. */
export function buildHoverZoomProgram(opts: HoverZoomBuildOptions): PaintCommand[] {
  const bg     = opts.backgroundColor ?? DEFAULTS.backgroundColor;
  const pad    = opts.innerPadding    ?? DEFAULTS.innerPadding;
  const sz     = opts.size;
  const hovMiner = opts.hoveredMinerAddr;
  const myAddr   = opts.myAddress;

  const cmds: PaintCommand[] = [];
  cmds.push({ op: 'setTransform', dpr: opts.dpr });
  cmds.push({ op: 'fillBackground', w: sz, h: sz, color: bg });

  if (opts.pplns.length === 0) return cmds;

  // Squarified treemap with padded interior (same (2,2,sz-4,sz-4) from
  // dashboard.html:5708).
  const items = opts.pplns.map((e) => ({
    area: e.pct,
    addr: e.addr,
    pct: e.pct,
  }));
  const rects = squarify(items, pad, pad, sz - 2 * pad, sz - 2 * pad);

  for (const r of rects) {
    const addr = r.addr as string;
    const pct  = r.pct as number;
    const isThisMiner = hovMiner !== undefined && addr === hovMiner;
    const isMe        = myAddr   !== undefined && myAddr !== '' && addr === myAddr;
    const hue = addrHue(addr);
    const fill = isThisMiner
      ? `hsl(${hue},85%,55%)`
      : isMe
      ? `hsl(${hue},60%,42%)`
      : `hsl(${hue},35%,30%)`;
    cmds.push({ op: 'fillCell', x: r.x, y: r.y, w: r.w, h: r.h, color: fill });
    // Cell border — dark, thin (dashboard.html:5729-5731).
    cmds.push({ op: 'strokeRect', x: r.x, y: r.y, w: r.w, h: r.h, color: bg, lineWidth: 1.5 });
    // Highlight ring for the hovered miner.
    if (isThisMiner) {
      cmds.push({
        op: 'strokeRect',
        x: r.x + 1, y: r.y + 1,
        w: r.w - 2, h: r.h - 2,
        color: '#ffffff', lineWidth: 2.5,
      });
    }
    // Percentage label + truncated address when cell is large enough.
    // Thresholds preserved verbatim from dashboard.html:5746-5761.
    if (r.w > 30 && r.h > 16) {
      const cx = r.x + r.w / 2;
      const cy = r.y + r.h / 2;
      const font = (isThisMiner ? 'bold 12px' : 'bold 10px') + ' -apple-system, sans-serif';
      const pctLabel = (pct * 100).toFixed(1) + '%';
      cmds.push({
        op: 'textCenter',
        text: pctLabel,
        x: cx,
        y: cy - (r.h > 28 ? 6 : 0),
        color: '#ffffff',
        font,
      });
      if (r.w > 44 && r.h > 28) {
        const maxChars = Math.max(4, Math.floor(r.w / 6));
        const addrLabel = addr.length > maxChars ? addr.slice(0, maxChars) + '\u2026' : addr.slice(0, maxChars);
        cmds.push({
          op: 'textCenter',
          text: addrLabel,
          x: cx,
          y: cy + 7,
          color: 'rgba(255,255,255,0.75)',
          font: (isThisMiner ? '9px' : '8px') + ' Monaco, Consolas, monospace',
        });
      }
    }
  }

  return cmds;
}

// ── DOM adapter ────────────────────────────────────────────────────

export interface HoverZoomPanelOptions {
  size?: number;          // default 240
  getDevicePixelRatio?: () => number;
  /** Nav-bar / tooltip width to avoid overlapping when flipping left. */
  flipLeftOffsetPx?: number;
  /** Optional container. Default: document.body. */
  parent?: HTMLElement;
}

export interface HoverZoomShare {
  h?: string;   // share short-hash (used as cache key upstream)
  m: string;    // miner address — highlighted in the panel
}

export interface HoverZoomPanel {
  /** Show the panel at cursor position for a specific share.
   *  `pplns` should come from orchestrator.getPPLNSForShare(share.h). */
  show(
    share: HoverZoomShare,
    pplns: readonly PPLNSEntry[],
    clientX: number,
    clientY: number,
    opts?: { myAddress?: string },
  ): void;
  hide(): void;
  destroy(): void;
}

export function createHoverZoomPanel(options: HoverZoomPanelOptions = {}): HoverZoomPanel {
  const size    = options.size ?? 240;
  const flipOff = options.flipLeftOffsetPx ?? 280;
  const getDpr  = options.getDevicePixelRatio ?? (() => window.devicePixelRatio || 1);
  const parent  = options.parent ?? document.body;

  const wrap = document.createElement('div');
  wrap.style.position = 'fixed';
  wrap.style.zIndex = '9999';
  wrap.style.pointerEvents = 'none';
  wrap.style.background = '#0d0d1a';
  wrap.style.border = '1px solid #3a3a5a';
  wrap.style.padding = '6px';
  wrap.style.display = 'none';
  wrap.style.borderRadius = '4px';

  const canvas = document.createElement('canvas');
  canvas.style.display = 'block';
  canvas.style.width = `${size}px`;
  canvas.style.height = `${size}px`;
  wrap.appendChild(canvas);

  const label = document.createElement('div');
  label.style.marginTop = '4px';
  label.style.fontSize = '11px';
  label.style.color = '#8888a0';
  label.style.fontFamily = '-apple-system, "Segoe UI", Roboto, sans-serif';
  label.style.textAlign = 'center';
  wrap.appendChild(label);

  parent.appendChild(wrap);

  const ctx2d = canvas.getContext('2d');
  if (ctx2d === null) {
    parent.removeChild(wrap);
    throw new Error('createHoverZoomPanel: no 2d context');
  }
  const ctx = ctx2d as unknown as CanvasLike;

  let destroyed = false;

  return {
    show(share, pplns, clientX, clientY, opts) {
      if (destroyed) return;
      if (pplns.length === 0) {
        wrap.style.display = 'none';
        return;
      }
      const dpr = getDpr();
      canvas.width = Math.round(size * dpr);
      canvas.height = Math.round(size * dpr);

      const program = buildHoverZoomProgram({
        pplns,
        size,
        dpr,
        hoveredMinerAddr: share.m,
        myAddress: opts?.myAddress,
      });
      executePaintProgram(ctx, program);

      label.textContent = `PPLNS Distribution \u2014 ${pplns.length} miners`;

      wrap.style.display = 'block';
      const rect = wrap.getBoundingClientRect();
      const totalH = rect.height || size + 20;
      let tx = clientX + 20;
      let ty = clientY - totalH / 2;
      if (tx + size > window.innerWidth - 8) tx = clientX - size - flipOff;
      if (ty < 8) ty = 8;
      if (ty + totalH > window.innerHeight - 8) ty = window.innerHeight - totalH - 8;
      wrap.style.left = `${tx}px`;
      wrap.style.top  = `${ty}px`;
    },
    hide() {
      if (destroyed) return;
      wrap.style.display = 'none';
    },
    destroy() {
      destroyed = true;
      if (wrap.parentNode) wrap.parentNode.removeChild(wrap);
    },
  };
}

// ── Plugin ────────────────────────────────────────────────────────

export const HoverZoomPlugin: PluginDescriptor = {
  id: 'explorer.hover-zoom.canvas',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'interaction',
  provides: ['renderer.hover-zoom'],
  slots: ['explorer.main.overlay'],
  priority: 0,
  capabilities: {
    'renderer.hover-zoom': { buildHoverZoomProgram, createHoverZoomPanel },
  },
};
