// shared.aria.live-log — ARIA live region announcer (delta v1 §H.1).
// Creates a visually hidden role="log" aria-live="polite" element
// attached to document.body. Announces share/miner birth and death
// for screen-reader users. Rate-limited to avoid flooding.
// Provides capability `renderer.announcer`.

import type { PluginDescriptor } from '../registry.js';

export interface Announcer {
  announce(message: string): void;
  destroy(): void;
}

export interface AnnouncerOptions {
  className: string;
  /** Minimum ms between announcements; extras coalesced into a counter. */
  rateLimitMs: number;
}

const DEFAULTS: AnnouncerOptions = Object.freeze({
  className: 'c2p-sr-only',
  rateLimitMs: 500,
});

export function createAnnouncer(options: Partial<AnnouncerOptions> = {}): Announcer {
  const opt: AnnouncerOptions = { ...DEFAULTS, ...options };
  const el = document.createElement('div');
  el.setAttribute('role', 'log');
  el.setAttribute('aria-live', 'polite');
  el.setAttribute('aria-atomic', 'false');
  el.className = opt.className;
  // Visually hidden but read by SR. Inline style avoids CSS-load race.
  el.style.position = 'absolute';
  el.style.width = '1px';
  el.style.height = '1px';
  el.style.overflow = 'hidden';
  el.style.clip = 'rect(0 0 0 0)';
  el.style.clipPath = 'inset(50%)';
  el.style.whiteSpace = 'nowrap';
  el.style.left = '-9999px';
  document.body.appendChild(el);

  let lastAt = 0;
  let pending: string | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const flush = () => {
    timer = null;
    if (pending === null) return;
    const line = document.createElement('div');
    line.textContent = pending;
    el.appendChild(line);
    lastAt = Date.now();
    pending = null;
    // Trim to last ~50 lines so the log doesn't grow without bound.
    while (el.childNodes.length > 50) {
      el.removeChild(el.firstChild as Node);
    }
  };

  return {
    announce(message) {
      pending = message;
      const now = Date.now();
      const waitFor = Math.max(0, opt.rateLimitMs - (now - lastAt));
      if (timer !== null) return;
      timer = setTimeout(flush, waitFor);
    },
    destroy() {
      if (timer !== null) clearTimeout(timer);
      if (el.parentNode) el.parentNode.removeChild(el);
    },
  };
}

export const AriaLiveLogPlugin: PluginDescriptor = {
  id: 'shared.aria.live-log',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'renderer',
  provides: ['renderer.announcer'],
  priority: 0,
  capabilities: {
    'renderer.announcer': createAnnouncer,
  },
};
