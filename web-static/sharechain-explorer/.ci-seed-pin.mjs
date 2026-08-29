// CI-only fast-check seed pin for the PPLNS parse property suite.
//
// Replays seed -1679627146 — the counterexample that surfaced the
// non-finite legacy bare-number regression (shrunk input [Infinity],
// totalPrimary -> Infinity). Fixed in PR #51 (parseLegacyShape now routes
// the bare-number branch through num()); this preload makes that exact
// path part of permanent CI, so a random-seeded run can never again pass
// while the pinned sequence still fails.
//
// Loaded via: node --import ./.ci-seed-pin.mjs  (see pplns-parse-seedpin.yml)
import fc from "fast-check";
fc.configureGlobal({ ...fc.readConfigureGlobal(), seed: -1679627146 });
