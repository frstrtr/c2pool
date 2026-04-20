// shared.tooltip.default — minimal pointer-following tooltip controller.
// Creates (lazily) a single position:fixed element; caller supplies
// content via setContent/showAt/hide. Auto-flips when near viewport
// edges (delta v1 / PPLNS spec tooltip behaviour).
// Provides capability `renderer.tooltip`.

import type { PluginDescriptor } from '../registry.js';

export interface Tooltip {
  /** Replace tooltip content with DOM (never innerHTML — XSS rule). */
  setContent(node: Node): void;
  showAt(clientX: number, clientY: number): void;
  hide(): void;
  destroy(): void;
}

export interface TooltipOptions {
  className: string;
  zIndex: number;
  offsetX: number;
  offsetY: number;
  edgePad: number;
}

const DEFAULTS: TooltipOptions = Object.freeze({
  className: 'c2p-tooltip',
  zIndex: 9999,
  offsetX: 14,
  offsetY: 14,
  edgePad: 8,
});

export function createTooltip(options: Partial<TooltipOptions> = {}): Tooltip {
  const opt: TooltipOptions = { ...DEFAULTS, ...options };
  let el: HTMLElement | null = null;

  const ensure = (): HTMLElement => {
    if (el) return el;
    const node = document.createElement('div');
    node.className = opt.className;
    node.style.position = 'fixed';
    node.style.display = 'none';
    node.style.pointerEvents = 'none';
    node.style.zIndex = String(opt.zIndex);
    document.body.appendChild(node);
    el = node;
    return node;
  };

  return {
    setContent(node) {
      const host = ensure();
      while (host.firstChild) host.removeChild(host.firstChild);
      host.appendChild(node);
    },
    showAt(cx, cy) {
      const host = ensure();
      host.style.display = 'block';
      // Measure first
      const rect = host.getBoundingClientRect();
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      let x = cx + opt.offsetX;
      let y = cy + opt.offsetY;
      if (x + rect.width > vw - opt.edgePad) x = cx - rect.width - opt.offsetX;
      if (y + rect.height > vh - opt.edgePad) y = cy - rect.height - opt.offsetY;
      if (x < opt.edgePad) x = opt.edgePad;
      if (y < opt.edgePad) y = opt.edgePad;
      host.style.left = `${x}px`;
      host.style.top = `${y}px`;
    },
    hide() {
      if (el) el.style.display = 'none';
    },
    destroy() {
      if (el && el.parentNode) el.parentNode.removeChild(el);
      el = null;
    },
  };
}

export const TooltipDefaultPlugin: PluginDescriptor = {
  id: 'shared.tooltip.default',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'renderer',
  provides: ['renderer.tooltip'],
  priority: 0,
  capabilities: {
    'renderer.tooltip': createTooltip,
  },
};
