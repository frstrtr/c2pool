// shared.theme.dark — default dark theme provider (proof-of-shape
// plugin for Phase A first commit). Theme values are what the existing
// dashboard.html uses today; extracted verbatim so M2 pixel-diff holds.

import type { PluginDescriptor } from '../registry.js';

export interface ThemeDescriptor {
  background: string;
  panel: string;
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  border: string;
  primary: string;
  success: string;
  warning: string;
  danger: string;
  gridLine: string;
  fontMono: string;
  fontUI: string;
}

export const DARK_THEME: Readonly<ThemeDescriptor> = Object.freeze({
  background:    '#0d0d1a',
  panel:         '#252540',
  textPrimary:   '#e0e0f0',
  textSecondary: '#a8a8c0',
  textMuted:     '#8888a0',
  border:        '#3a3a5a',
  primary:       '#008de4',
  success:       '#1d7f3b',
  warning:       '#ffc107',
  danger:        '#b04020',
  gridLine:      'rgba(140,140,180,0.2)',
  fontMono:      'Monaco, Consolas, monospace',
  fontUI:        '-apple-system, "Segoe UI", Roboto, sans-serif',
});

export const ThemeDarkPlugin: PluginDescriptor = {
  id: 'shared.theme.dark',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'theme',
  provides: ['theme.descriptor'],
  priority: 0,
};
