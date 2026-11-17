// Classic-script entry → dist/layout.js (IIFE, global `C2PLayout`).
//
// dashboard.html and share.html are classic (non-module) pages, so they
// load this with a plain <script src="sharechain-explorer/dist/layout.js?v=…">
// before their inline code and call C2PLayout.squarify synchronously —
// no async import race. It exists so those pages share the ONE squarify
// (src/pplns/squarify.ts) with the bundles instead of carrying copies.
// The ?v= stamp is the file's content hash (scripts/stamp-html.mjs), so
// a deploy never pairs a fresh page with a cached older layout.js.

export { squarify } from './pplns/squarify.js';
export type { SquarifyItem, SquarifyOptions, SquarifyRect } from './pplns/squarify.js';
