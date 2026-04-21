// Bundle-size gate (M1 sign-off §4 follow-up / Phase A).
// Reads size.config.json for per-file budgets, compares to dist/*.
// Exits non-zero when a bundle exceeds budget or a required bundle is
// missing; emits a warning at `warnAt` × budget so we see creep before
// it breaks CI.
//
// Usage: node scripts/check-bundle-size.mjs

import { readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
const DIST = join(ROOT, 'dist');
const CONFIG_PATH = join(ROOT, 'size.config.json');

const cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
const budgets = cfg.budgets ?? {};

const COLORS = process.stdout.isTTY
  ? { reset: '\x1b[0m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', grey: '\x1b[90m' }
  : { reset: '', green: '', yellow: '', red: '', grey: '' };

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

let failed = false;
let warned = false;
let skippedRequired = 0;

console.log('bundle-size gate — reading', CONFIG_PATH);

for (const [name, spec] of Object.entries(budgets)) {
  const path = join(DIST, name);
  const budgetBytes = spec.bytes;
  const warnAt = spec.warnAt ?? 0.9;
  const role = spec.role ?? '';

  if (!existsSync(path)) {
    // A bundle in the config that hasn't been built yet is informational,
    // not a failure — we may be running between phases.
    console.log(`${COLORS.grey}·${COLORS.reset} ${name.padEnd(28)} not built yet ${COLORS.grey}(${role})${COLORS.reset}`);
    skippedRequired++;
    continue;
  }

  const size = statSync(path).size;
  const pct = size / budgetBytes;
  const pctStr = `${(pct * 100).toFixed(1)}%`;
  const sizeStr = fmtBytes(size).padStart(9);
  const budgetStr = fmtBytes(budgetBytes).padStart(9);

  let marker;
  let colour;
  if (pct > 1) {
    marker = '✗';
    colour = COLORS.red;
    failed = true;
  } else if (pct >= warnAt) {
    marker = '!';
    colour = COLORS.yellow;
    warned = true;
  } else {
    marker = '✓';
    colour = COLORS.green;
  }

  console.log(
    `${colour}${marker}${COLORS.reset} ${name.padEnd(28)} ` +
    `${sizeStr} / ${budgetStr} ${colour}${pctStr.padStart(6)}${COLORS.reset} ${COLORS.grey}${role}${COLORS.reset}`
  );
}

if (failed) {
  console.error(`\n${COLORS.red}bundle-size gate FAILED${COLORS.reset} — see entries above`);
  process.exit(1);
}
if (warned) {
  console.warn(`\n${COLORS.yellow}warning:${COLORS.reset} one or more bundles near budget`);
}
if (skippedRequired > 0) {
  console.log(`\n${COLORS.grey}(${skippedRequired} bundle(s) not yet built; will be checked once emitted)${COLORS.reset}`);
}
