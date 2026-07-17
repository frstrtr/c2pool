# V37 Object-Lib Source Dissolution — Extracting web_server.cpp and its transitive dependency tangle out of `core` (follow-up to landed PR #63)

## 1. Executive summary

PR #63 landed the `core` OBJECT-library consolidation but left `web_server.cpp` (and its stratum sibling TUs) inside `core`, which forces every downstream target — `c2pool-btc`, all per-coin binaries, and ~15 gtest executables — to link `c2pool_payout`, `c2pool_hashrate`, `c2pool_merged_mining`, and LTC-specific objects purely to satisfy unresolved symbols in `web_server.o`. This proposal dissolves the SCC by extracting `web_server.cpp` (and the stratum runtime TUs it transitively pulls) into a new STATIC library `c2pool_pool_runtime` that only the actual pool daemons link. The result is a lean `core` that coin binaries and unit tests can consume without dragging the payout/hashrate/merged/LTC chain, and the removal of the `#22`/`#39` direct-naming workarounds in `src/c2pool/CMakeLists.txt` and `test/CMakeLists.txt`.

## 2. Current dependency topology

### Edge list (link-time, as forced by current OBJECT-lib semantics)

```
core (OBJECT) ──contains──> web_server.o
core (OBJECT) ──contains──> stratum_server.o
core (OBJECT) ──contains──> [all other core TUs: share.o, p2p_node.o, chain_tracker.o, merkletree.o, …]

web_server.o ──undef──> c2pool_payout::*
web_server.o ──undef──> c2pool_hashrate::*
web_server.o ──undef──> c2pool_merged_mining::*
web_server.o ──undef──> LTC-specific symbols (ltc::node_iface, ltc coin_node dispatch)
stratum_server.o ──undef──> web_server.o            (intra-core, free)
stratum_server.o ──undef──> c2pool_hashrate::*

c2pool-btc ──links──> core (OBJECT)
c2pool-btc ──FORCED links──> c2pool_payout          # only to satisfy web_server.o
c2pool-btc ──FORCED links──> c2pool_hashrate        # only to satisfy web_server.o / stratum_server.o
c2pool-btc ──FORCED links──> c2pool_merged_mining   # only to satisfy web_server.o
c2pool-btc ──FORCED links──> LTC objects            # only to satisfy web_server.o

c2pool-bch / c2pool-dgb ── (same forced edges as c2pool-btc)
c2pool-ltc ──links──> core ──FORCED links──> c2pool_payout c2pool_hashrate c2pool_merged_mining
                                                  (LTC objects are native here, not forced)

gtest_* (×15) ──links──> core (OBJECT)
gtest_* ──FORCED links──> c2pool_payout c2pool_hashrate c2pool_merged_mining   (#22 / #39)
```

### ASCII graph of the SCC

```
                         ┌──────────────────────────────────┐
                         │  core (OBJECT)                   │
                         │  ├─ web_server.o   ──────────────┼─┐
                         │  ├─ stratum_server.o ────────────┼─┼─┐
                         │  ├─ node_iface.hpp (hdr)         │ │ │
                         │  ├─ work_view.hpp (hdr)          │ │ │
                         │  ├─ hashrate_ring.hpp (hdr)      │ │ │
                         │  ├─ stratum_types.hpp (hdr)      │ │ │
                         │  └─ share.o, p2p_node.o, …       │ │ │
                         └──────────────┬───────────────────┘ │ │
                                        │ OBJECT-exposed      │ │
                                        │ .o to consumers     │ │ symbol refs
                                        ▼                     ▼ ▼
        ┌───────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  ┌────────────────┐
        │  c2pool-btc       │  │ c2pool_payout    │  │ c2pool_hashrate      │  │ c2pool_merged  │
        │  (and every       │  │                  │  │                      │  │ _mining        │
        │   coin binary,    │  │                  │  │                      │  │                │
        │   every gtest)    │  │                  │  │                      │  │                │
        └─────────┬─────────┘  └────────▲─────────┘  └─────────▲────────────┘  └───────▲────────┘
                  │                     │                      │                       │
                  └──── FORCED link ────┴──── FORCED link ─────┴─── FORCED link ───────┘
                        (workarounds at src/c2pool/CMakeLists.txt:165/194/201/204/217/226/
                         247/282/286/355/357; #22/#39 in test/CMakeLists.txt)
                                                  │
                                                  ▼
                                       ┌────────────────────┐
                                       │  LTC objects       │
                                       │  (forced into      │
                                       │   non-LTC daemons) │
                                       └────────────────────┘
```

The SCC: `{core, c2pool_payout, c2pool_hashrate, c2pool_merged_mining, LTC objects}` — not because of a true cycle in the source, but because OBJECT-lib semantics flatten the `web_server.o → {payout, hashrate, merged, LTC}` edge into a universal consumer-side requirement.

## 3. Root cause: OBJECT-lib semantics turn a soft dependency into a hard universal link edge

A CMake `OBJECT` library is not a link-time entity; it is a *bundle of `.o` files* that CMake injects verbatim into every target that consumes it. There is no `target_link_libraries(core …)` edge that can be deferred or made private — every consumer of `core` inherits `web_server.o` as one of its own translation units, and therefore inherits `web_server.o`'s undefined symbols as its own undefined symbols.

Concretely, when `c2pool-btc` writes `target_link_libraries(c2pool-btc PRIVATE core)`, the linker sees `web_server.o` directly on `c2pool-btc`'s link line, with unresolved references to `c2pool_payout::submit_share`, `c2pool_hashrate::record`, `c2pool_merged_mining::aux_block`, and `ltc::node_iface::*`. The linker has no idea those symbols came from a TU the consumer never asked for; it just sees undefined references and fails. The maintainer's workaround — direct-naming `c2pool_payout c2pool_hashrate c2pool_merged_mining` on every consumer — is the only way to make the link succeed under OBJECT semantics. The LTC self-link edge on `c2pool-btc` is the same phenomenon: `web_server.cpp` references LTC-specific symbols (coin_node dispatch, ltc-specific share validation paths) that are only defined in the LTC TU set, so even BTC binaries must link LTC objects.

A STATIC library, by contrast, is a link-time entity: its `.o`s are pulled in *lazily* by the linker, only when an upstream target has an unresolved symbol that the archive can satisfy. If `c2pool-btc` never references `web_server.o`'s symbols, the linker never opens `web_server.o` from the archive, and the payout/hashrate/merged/LTC chain is never transitively required. This is the property we exploit below.

The same flaw explains why the `#22`/`#39` direct-naming in `test/CMakeLists.txt` exists: every gtest that links `core` inherits `web_server.o` and therefore inherits its undefined symbols, even tests that exercise nothing in the stratum/payout path.

## 4. Proposed target decomposition

### New library: `c2pool_pool_runtime` (STATIC)

A STATIC library that owns the pool-daemon-only runtime TUs — the ones that actually need payout/hashrate/merged/LTC. Only the per-coin pool daemons (`c2pool-btc`, `c2pool-ltc`, `c2pool-bch`, `c2pool-dgb`) link it. Coin utilities, share-validation tools, and gtests do not.

### TUs that move from `core` → `c2pool_pool_runtime`

| File | Reason |
|---|---|
| `src/core/web_server.cpp` | Primary offender; references payout/hashrate/merged/LTC. |
| `src/core/stratum_server.cpp` | Sibling TU; pulls `web_server` symbols and shares the LTC dispatch path; also references `c2pool_hashrate`. |
| `src/core/work_view.cpp` (if present as a TU) | Consumed only by the pool daemon's work-push path. |
| `src/core/hashrate_ring.cpp` (if present as a TU) | Consumed only by the live pool daemon's hashrate aggregation. |

Headers (`web_server.hpp`, `stratum_server.hpp`, `node_iface.hpp`, `work_view.hpp`, `hashrate_ring.hpp`, `stratum_types.hpp`) **stay in `src/core/`** as pure declarations / include-only headers — they describe interfaces, they do not introduce link edges. The include path is unchanged; only the *implementation TU* moves. Consumers that `#include "core/web_server.hpp"` continue to compile unchanged.

### TUs that stay in `core`

Everything else: `share.cpp`, `p2p_node.cpp`, `chain_tracker.cpp`, `merkletree.cpp`, the coinbase/tx-out helpers, the pure-data `stratum_types.cpp` (if any), and all the header-only interface files. `core` becomes a lean OBJECT lib that coin binaries and tests can consume without dragging the runtime chain.

### New link edges

```
c2pool_pool_runtime (STATIC) ──links──> c2pool_payout
c2pool_pool_runtime (STATIC) ──links──> c2pool_hashrate
c2pool_pool_runtime (STATIC) ──links──> c2pool_merged_mining
c2pool_pool_runtime (STATIC) ──links──> core                # for shared types/headers' TUs
c2pool_pool_runtime (STATIC) ──does NOT link──> LTC objects # LTC dispatch resolved at daemon level

c2pool-btc ──links──> core
c2pool-btc ──links──> c2pool_pool_runtime
c2pool-btc ──links──> c2pool_payout?        NO — removed
c2pool-btc ──links──> c2pool_hashrate?      NO — removed
c2pool-btc ──links──> c2pool_merged_mining? NO — removed
c2pool-btc ──links──> LTC objects?          NO — removed

c2pool-ltc ──links──> core
c2pool-ltc ──links──> c2pool_pool_runtime
c2pool-ltc ──links──> LTC objects           # native, not forced

gtest_* ──links──> core
gtest_* ──links──> c2pool_pool_runtime?     only if the test actually exercises web_server/stratum
gtest_* ──links──> c2pool_payout?           NO — #22 workaround removed
gtest_* ──links──> c2pool_hashrate?         NO — #39 workaround removed
gtest_* ──links──> c2pool_merged_mining?    NO — removed
```

### Resulting acyclic graph

```
                       ┌──────────────────────────────────┐
                       │  core (OBJECT)                   │
                       │  lean: share, p2p, chain,        │
                       │  merkletree, headers-only        │
                       └──────────────┬───────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
        ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐
        │  c2pool-btc  │    │ c2pool_pool_     │    │   gtest_*    │
        │  (daemon)    │    │ runtime (STATIC) │    │  (no runtime)│
        └──────┬───────┘    └────────┬─────────┘    └──────────────┘
               │                     │
               │                     ├─→ c2pool_payout
               └────────────────────►├─→ c2pool_hashrate
                                     ├─→ c2pool_merged_mining
                                     └─→ (LTC objects linked by c2pool-ltc only)

        ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
        │ coin utils   │    │ share-val    │    │ per-coin     │
        │ (no runtime) │    │ tools        │    │ node.hpp     │
        └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
               │                   │                   │
               └────────► core ◄───┴───────────────────┘
                          (no payout/hashrate/merged edge)
```

No cycle. `core` has no edge to `c2pool_pool_runtime`, `c2pool_payout`, `c2pool_hashrate`, `c2pool_merged_mining`, or LTC. The runtime library is a leaf above `core` and the payout chain; only daemons pull it.

## 5. Migration plan (landable increments, each CI-green)

Each PR is independently buildable and passes the existing test matrix. No "hollow" intermediate states — every step removes a real workaround or moves a real TU.

### PR-A — Introduce `c2pool_pool_runtime` as an empty STATIC library

**CMakeLists edits:**
- `src/core/CMakeLists.txt`: no change.
- New file `src/core/pool_runtime/CMakeLists.txt` (or extend `src/core/CMakeLists.txt` with a second `add_library`):
  ```cmake
  add_library(c2pool_pool_runtime STATIC)
  target_link_libraries(c2pool_pool_runtime PUBLIC core)
  target_include_directories(c2pool_pool_runtime PUBLIC ${CMAKE_SOURCE_DIR}/src)
  ```
- `src/c2pool/CMakeLists.txt`: add `c2pool_pool_runtime` to the per-coin daemon link lists (lines 165, 194, 201, 204, 217, 226, 247, 282, 286, 355, 357) **in addition to** the existing `c2pool_payout c2pool_hashrate c2pool_merged_mining` direct-naming. No removals yet.

**Header changes:** none.

**Why CI-green:** `c2pool_pool_runtime` is empty; adding it to link lines is a no-op. The existing direct-naming workarounds still satisfy `web_server.o`'s symbols because `web_server.o` is still in `core`.

### PR-B — Move `web_server.cpp` from `core` to `c2pool_pool_runtime`

**CMakeLists edits:**
- `src/core/CMakeLists.txt:31`: remove `web_server.cpp` from the `core` OBJECT library source list.
- `src/core/pool_runtime/CMakeLists.txt`: add `web_server.cpp` to `c2pool_pool_runtime`.
- `src/core/pool_runtime/CMakeLists.txt`: add the link edges the TU needs:
  ```cmake
  target_link_libraries(c2pool_pool_runtime PUBLIC
      core
      c2pool_payout
      c2pool_hashrate
      c2pool_merged_mining)
  ```
- `src/c2pool/CMakeLists.txt`: **leave the direct-naming workarounds in place for now** — they are now redundant but harmless, and removing them in the same PR conflates two concerns.

**Header changes:**
- `src/core/web_server.hpp` stays in `src/core/`; no `#include` path changes anywhere because the include directory is the project root.
- Audit consumers of `web_server.hpp` (per the problem statement: `stratum_server.cpp`, `node_iface.hpp`, `work_view.hpp`, `hashrate_ring.hpp`, `stratum_types.hpp`, and each `btc/bch/ltc/dgb/node.hpp` + `coin_node`): they include the header, which is fine — headers don't introduce link edges. No source edits required.

**Why CI-green:** `web_server.o` now lives in `c2pool_pool_runtime`, which already links payout/hashrate/merged. The daemons already link `c2pool_pool_runtime` (from PR-A). The redundant direct-naming on the daemons is now a no-op (the linker resolves the symbols via `c2pool_pool_runtime`'s archive members, or via the direct-named libs — same result). gtests that don't link `c2pool_pool_runtime` no longer see `web_server.o` in their link line, so they no longer need the `#22`/`#39` direct-naming — but we don't remove those yet either, to keep this PR focused on the TU move.

### PR-C — Remove the LTC self-link edge from non-LTC daemons

**CMakeLists edits:**
- `src/c2pool/CMakeLists.txt`: audit the LTC-object direct-naming on `c2pool-btc`, `c2pool-bch`, `c2pool-dgb`. After PR-B, `web_server.o` is no longer in `core`, so non-LTC daemons no longer have unresolved LTC symbols *unless* `web_server.cpp` references them unconditionally. Remove the LTC-object entries from the non-LTC daemon link lists.
- `c2pool_pool_runtime` must NOT link LTC objects unconditionally; LTC dispatch is resolved at the daemon level. Concretely: keep LTC objects out of `c2pool_pool_runtime`'s `target_link_libraries`, and have `c2pool-ltc` link them directly. For non-LTC daemons, the LTC code paths in `web_server.cpp` must be guarded by `#ifdef COIN_LTC` (or the project's existing coin-dispatch macro, e.g. `WITH_LTC` / `COIN_LTC`) so the symbols are not referenced in non-LTC builds. If such guards do not yet exist, this PR adds them — they are a prerequisite for the LTC self-link edge to be removable.

**Source edits (only if guards are missing):**
- `src/core/web_server.cpp`: wrap the LTC-specific call sites (coin_node dispatch, ltc share-validation paths) in `#ifdef COIN_LTC … #endif`. The non-LTC path uses the generic coin-dispatch interface that `core` already exposes via `node_iface.hpp`.

**Header changes:** none.

**Why CI-green:** LTC daemon still links LTC objects directly; non-LTC daemons no longer reference LTC symbols because the `#ifdef COIN_LTC` guards suppress them. `nm -u c2pool-btc` will show zero `ltc::` undefined references.

### PR-D — Remove the `#22`/`#39` direct-naming workarounds in `test/CMakeLists.txt`

**CMakeLists edits:**
- `test/CMakeLists.txt`: for each gtest target that currently direct-names `c2pool_payout c2pool_hashrate c2pool_merged_mining` solely to satisfy `core`'s `web_server.o`, remove those entries. After PR-B, `core` no longer contains `web_server.o`, so gtests that link only `core` no longer need payout/hashrate/merged.
- For the small number of gtests that actually exercise `web_server`/`stratum_server` (e.g. `test_web_server.cpp`, `test_stratum.cpp` if present), add `c2pool_pool_runtime` to their link list — these tests genuinely need the runtime chain.

**Header changes:** none.

**Why CI-green:** Each removed direct-naming is verified by the gtest still linking. If a gtest fails to link after removal, that test was actually exercising a payout/hashrate/merged symbol directly (not via `core`'s `web_server.o`), and the fix is to add `c2pool_pool_runtime` (or the specific lib) to that test only — a per-test decision, not a blanket workaround.

### PR-E — Remove the daemon-side direct-naming workarounds in `src/c2pool/CMakeLists.txt`

**CMakeLists edits:**
- `src/c2pool/CMakeLists.txt` lines 165, 194, 201, 204, 217, 226, 247, 282, 286, 355, 357: remove the now-redundant `c2pool_payout c2pool_hashrate c2pool_merged_mining` direct-naming from each daemon. These symbols are now satisfied transitively via `c2pool_pool_runtime`'s `PUBLIC` link edges.
- Leave a comment at the top of the daemon link section: `# daemons link c2pool_pool_runtime, which transitively provides payout/hashrate/merged_mining; do not re-add direct-naming (see V37).`

**Header changes:** none.

**Why CI-green:** The `PUBLIC` link on `c2pool_pool_runtime` propagates to consumers. `c2pool-btc` links `c2pool_pool_runtime`, which links `c2pool_payout` etc.; the symbols resolve.

### PR-F — Documentation & `nm`/`ldd` regression gates

**Edits:**
- Add a CI step that runs `nm -u c2pool-btc | grep -E 'c2pool_payout|c2pool_hashrate|c2pool_merged_mining'` and fails on any match.
- Add a CI step that runs `ldd c2pool-btc` and asserts no LTC-only shared object appears (for static builds, the `nm` check above covers it).
- Update `docs/architecture.md` (if present) with the new topology diagram from §4.

## 6. Risk & rollback

### Symbol-resolution regressions
The highest-risk transition is PR-B: moving `web_server.o` out of `core` changes which archive the linker searches for `web_server`'s symbols. If any consumer was relying on `web_server.o`'s symbols *without* going through `c2pool_pool_runtime` (e.g. a gtest that calls `web_server::start` directly), that test will fail to link after PR-B. Mitigation: PR-B's CI run will surface every such test; the fix is to add `c2pool_pool_runtime` to that specific test's link list, which is the correct dependency declaration. Rollback: revert PR-B; `core` regains `web_server.o` and the old workarounds resurface — no data or API impact.

### LTC self-link edge
PR-C is the only step that touches source code (the `#ifdef COIN_LTC` guards in `web_server.cpp`). If the LTC dispatch in `web_server.cpp` is not cleanly separable by preprocessor (e.g. it uses a runtime coin-type switch rather than a compile-time macro), PR-C must introduce the macro guard or refactor the dispatch through a function pointer registered by the LTC daemon. Risk: a mis-guarded code path silently references an LTC symbol in a BTC build and the link fails. Mitigation: the `nm -u` gate added in PR-F catches this; in PR-C, run the same `nm -u` check manually before merge. Rollback: revert PR-C; non-LTC daemons regain the LTC-object direct-naming — no behavior change.

### gtest direct-naming cleanup
PR-D removes the `#22`/`#39` workarounds. Risk: a gtest that *transitively* needs a payout/hashrate/merged symbol (not via `web_server.o` but via some other `core` TU that we missed) will fail to link. Mitigation: PR-D is split from PR-B precisely so that any such failure is unambiguously attributable to the direct-naming removal (PR-B is already merged and green). Each failing test is fixed individually by adding the specific lib it needs — not by re-adding the blanket workaround. Rollback: revert PR-D; the `#22`/`#39` direct-naming returns.

### Non-hollow PRs
Every PR in the sequence either adds a real library with real TUs (PR-A/B), removes a real workaround (PR-D/E), removes a real cross-coin link edge (PR-C), or adds a real CI gate (PR-F). No PR is "preparation only" — each one changes the link graph observably.

## 7. Acceptance criteria

The tangle is gone when **all** of the following hold:

1. **`c2pool-btc` no longer links `c2pool_payout`, `c2pool_hashrate`, or `c2pool_merged_mining` directly.** Verified by:
   ```sh
   nm -u c2pool-btc | grep -E 'c2pool_payout|c2pool_hashrate|c2pool_merged_mining'
   # expected: no matches
   ```
   (If `c2pool-btc` legitimately calls into payout at runtime, those symbols will appear as *defined* references resolved via `c2pool_pool_runtime`'s archive — but the direct `target_link_libraries(c2pool-btc … c2pool_payout …)` line in `src/c2pool/CMakeLists.txt` must be gone.)

2. **`c2pool-btc` has no undefined `ltc::` symbols.** Verified by:
   ```sh
   nm -u c2pool-btc | grep -i ltc
   # expected: no matches
   ```

3. **`src/c2pool/CMakeLists.txt` lines 165/194/201/204/217/226/247/282/286/355/357 no longer contain `c2pool_payout c2pool_hashrate c2pool_merged_mining` direct-naming.** The workarounds documented in those comments are removed; the comments themselves are replaced with a pointer to V37.

4. **`test/CMakeLists.txt` no longer contains the `#22`/`#39` "OBJECT-lib SCC direct-naming" workarounds.** Gtests that genuinely need payout/hashrate/merged link `c2pool_pool_runtime` (or the specific lib) explicitly; gtests that don't, link only `core`.

5. **`core`'s source list in `src/core/CMakeLists.txt:31` no longer contains `web_server.cpp` (or `stratum_server.cpp` if moved).** `core` is an OBJECT lib containing only the lean TUs listed in §4.

6. **`c2pool_pool_runtime` is a STATIC library whose `target_link_libraries` includes `c2pool_payout c2pool_hashrate c2pool_merged_mining` and whose source list contains `web_server.cpp`.**

7. **A clean build of `c2pool-btc` from a fresh clone, with no `c2pool_payout`/`c2pool_hashrate`/`c2pool_merged_mining` direct-naming anywhere in the BTC daemon's link list, succeeds and produces a binary that passes the existing BTC daemon smoke tests.**

8. **The CI `nm`/`ldd` regression gate from PR-F is green on all per-coin daemons (btc/bch/ltc/dgb).**

When all eight hold, the SCC documented in §2 is dissolved: `core` is a leaf in the dependency graph with no edge to payout/hashrate/merged/LTC, and the runtime chain is reachable only through `c2pool_pool_runtime`, which only daemons link.

