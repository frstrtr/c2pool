// shared.sparkline.svg — tiny inline SVG sparkline renderer.
// Returns a <svg> element populated with a polyline path; caller is
// responsible for DOM insertion + destruction. Scales data to [0, h].
// Provides capability `renderer.sparkline`.

import type { PluginDescriptor } from '../registry.js';

export interface SparklineOptions {
  width: number;
  height: number;
  strokeColor: string;
  strokeWidth: number;
  strokeLinecap: 'butt' | 'round' | 'square';
  fillColor: string | null;   // set to rgba for area-under-curve fill
  title?: string;             // SR-accessible <title> element
}

const DEFAULTS: SparklineOptions = Object.freeze({
  width: 120,
  height: 24,
  strokeColor: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round',
  fillColor: null,
});

const SVG_NS = 'http://www.w3.org/2000/svg';

export function renderSparkline(
  values: readonly number[],
  options: Partial<SparklineOptions> = {},
): SVGSVGElement {
  const opt: SparklineOptions = { ...DEFAULTS, ...options };
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('width', String(opt.width));
  svg.setAttribute('height', String(opt.height));
  svg.setAttribute('viewBox', `0 0 ${opt.width} ${opt.height}`);
  svg.setAttribute('role', 'img');
  if (opt.title) {
    const t = document.createElementNS(SVG_NS, 'title');
    t.textContent = opt.title;
    svg.appendChild(t);
  }

  if (values.length < 2) return svg;

  let min = Infinity;
  let max = -Infinity;
  for (const v of values) {
    if (!isFinite(v)) continue;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  if (!isFinite(min) || !isFinite(max)) return svg;
  const range = max - min || 1;
  const stepX = opt.width / (values.length - 1);
  const pad = opt.strokeWidth / 2;
  const drawH = opt.height - 2 * pad;

  const pts: string[] = [];
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (!isFinite(v as number)) continue;
    const x = i * stepX;
    const y = pad + drawH - ((v as number - min) / range) * drawH;
    pts.push(`${x.toFixed(2)},${y.toFixed(2)}`);
  }

  if (opt.fillColor) {
    const area = document.createElementNS(SVG_NS, 'path');
    const d = `M 0,${opt.height} L ${pts.join(' L ')} L ${opt.width},${opt.height} Z`;
    area.setAttribute('d', d);
    area.setAttribute('fill', opt.fillColor);
    area.setAttribute('stroke', 'none');
    svg.appendChild(area);
  }

  const polyline = document.createElementNS(SVG_NS, 'polyline');
  polyline.setAttribute('points', pts.join(' '));
  polyline.setAttribute('fill', 'none');
  polyline.setAttribute('stroke', opt.strokeColor);
  polyline.setAttribute('stroke-width', String(opt.strokeWidth));
  polyline.setAttribute('stroke-linecap', opt.strokeLinecap);
  polyline.setAttribute('stroke-linejoin', 'round');
  svg.appendChild(polyline);

  return svg;
}

export const SparklineSvgPlugin: PluginDescriptor = {
  id: 'shared.sparkline.svg',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'renderer',
  provides: ['renderer.sparkline'],
  priority: 0,
  capabilities: {
    'renderer.sparkline': renderSparkline,
  },
};
