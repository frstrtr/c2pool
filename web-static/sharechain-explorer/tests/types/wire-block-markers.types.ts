// Compile-time contract for the found-block marker lists (issue #946).
// Nothing here runs: `npm run typecheck` compiles this file through
// tsconfig.typetests.json, and a broken assertion is a tsc error.

import type { WireBlockMarkers } from '../../src/transport/types.js';
import type { DeltaPayload } from '../../src/explorer/delta.js';

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
function assertType<T extends true>(): void { /* compile-time only */ }

// Both lists are optional readonly arrays of short-hash strings.
assertType<Equal<WireBlockMarkers['doge_blocks'], readonly string[] | undefined>>();
assertType<Equal<WireBlockMarkers['blocks'], readonly string[] | undefined>>();

// The delta payload carries the same fields, from the same declaration.
assertType<Equal<DeltaPayload['doge_blocks'], WireBlockMarkers['doge_blocks']>>();
assertType<Equal<DeltaPayload['blocks'], WireBlockMarkers['blocks']>>();

// A window or delta with no markers is valid.
export const bare: DeltaPayload = { shares: [] };
export const withDoge: DeltaPayload = { shares: [], doge_blocks: ['0123456789abcdef'] };

// @ts-expect-error entries are short-hash strings, not numbers
export const numericEntry: WireBlockMarkers = { doge_blocks: [1] };

// @ts-expect-error exactOptionalPropertyTypes: omit the field, never set it to undefined
export const explicitUndefined: WireBlockMarkers = { doge_blocks: undefined };

// @ts-expect-error the list is readonly; consumers must not mutate the server copy
withDoge.doge_blocks?.push('fedcba9876543210');
