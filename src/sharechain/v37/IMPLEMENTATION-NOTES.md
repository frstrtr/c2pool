# V37 MRR Roundabout Round-Buffer — implementation notes (WIP for review)

Branch: `v37/mrr-roundabout-buffer`. Spec: `c2pool-v37-mrr-roundabout-buffer.md` v1.0
(all OQ/S decisions resolved). Module: `src/sharechain/v37/`, header-only,
`namespace v37`, stdlib-only — compiles and tests standalone with
`g++ -std=c++20`, no conan/boost/btclibs dependency.

## Done (implemented + tested on this VM)

| Component (brief) | Where | Status |
|---|---|---|
| 1. Lane storage, bucket leaves (F-1 fields) | `v37_lane.hpp` | done |
| 2. MRR roll-up pyramid (OQ-5 geometry) | `v37_lane.hpp` (`fold_l0`, `cascade_folds`) | done; L=2 default fully tested, L≥3 see notes |
| 3. Epoch-scaled incremental decay + OQ-2 exact rebuild | `v37_lane.hpp` (`push`, `epoch_rebuild`) | done |
| 4. PayoutDescriptor v1 (OQ-3, S-1/S-2/S-3) | `v37_descriptor.hpp` | done |
| 5. Quantized window (OQ-1) + reorg journal D=64 (OQ-7) | `v37_lane.hpp` (`evict_oldest_bucket`, `rewind`) | done |
| 6. Lane digest (§8.5, OQ-4) | `v37_lane.hpp` (`digest`) | done |
| 7. Fixed-point model + slow reference + bit-exact gate | `v37_fixed.hpp` + `test/v37_test.cpp` (`ReferenceLane`) | done |
| Multichain container + miner intern | `v37_roundabout.hpp` | done |

Test run (g++ 13.3, -O2 and again under `-fsanitize=address,undefined`):
**100,338 checks, 0 failures.** The consensus gate is `ReferenceLane` — an
independent implementation whose per-miner weights are recomputed by full
scan of the durable records after EVERY push — compared bit-exact against the
incremental accumulators, across two geometries (small stress geometry, 5+
epochs; ratified OQ-5 default geometry across two epoch rebuilds, ~9.5k
pushes, full-u64-range weights). Also covered: digest determinism +
sensitivity, rewind bit-exact restoration, window quantization, raw-work
conservation (F-1), descriptor canon vectors for all five template kinds +
kind-255 fallback, S-1 identity distinctness, aux/attribution validity rules,
runtime lane add/remove, cross-lane identity intern.

## Range pinning + spec errata (flag for the spec's next revision)

1. **Q62, not Q64.** §8.2 says "widens to 64 fractional bits"; §8.1 delegates
   exact range pinning here. Pinned at FRAC_BITS = 62 so that: every table
   entry (decay ≤ 1.0, inverse ≤ 2^1.9) fits u64; w_raw keeps the FULL u64
   range; every w_raw × table product fits native unsigned __int128;
   accumulators fit 256 bits. Still 2^22 finer than V36's Q40. Suggest spec
   erratum: "62 fractional bits" with this rationale.
2. **Wider storage than the §3 struct sketch.** Spec sketches comp w_scaled
   as q64 and bucket scaled_sum as q128; with full-range u64 raw work those
   overflow. Implementation uses u128 (L0 scaled) and U256 (sums, comp
   scaled). Spec §5 footprint numbers shift accordingly; tightening back
   down requires capping w_raw (a consensus parameter decision — operator).
3. **Journal does not cross epoch rebuilds.** `rewind()` refuses if the span
   crosses a rebuild (journal is cleared there); caller takes the full lane
   rebuild path — the same escape hatch as the >D case (§6.2). Affects ~D/E
   ≈ 1.6% of max-depth reorgs at default geometry. Suggest folding this rule
   into §6.2 explicitly.
4. **Level sums for levels ≥ 1.** Buckets in one level can carry different
   epoch tags (immutability rule), so a single stored per-level scaled sum is
   frame-mixed; the per-band view weight is assembled per-bucket with the
   epoch shift (O(buckets/level) ≤ 568) instead of a maintained O(1) field.
   L0 sums are maintained O(1) as specced.
5. **No residual dust at L = 2 (stronger than spec).** §4.2 tolerates
   deterministic truncation residuals between rebuilds; with the
   rebuild-from-raw design and default L = 2 the incremental state equals the
   full-scan reference EXACTLY at every operation (proven by the gate). The
   only residual source is the L≥3 cascade fold (children re-framed at fold);
   at L≥3 the gate holds at rebuild points, per spec. L≥3 needs its own
   rebuild-point-gated test before any chain uses it.

## Stubbed / deferred (not blocking review)

- **L1 view projection** (`RingFrame`/`Level` serialization for
  `/pplns/rings`): not implemented — view-layer concern; all backing queries
  exist (`payout_map`, `raw_work_in_span`, `levels()` accessor, digest).
- **SoA / arena / power-of-two mask storage**: test-grade impl uses
  std::deque/std::vector with identical semantics; the §5 memory-layout
  optimizations (contiguous SoA rings, bump-allocated comps, SIMD renorm
  pass) are an integration-phase change that cannot alter results (same op
  sequence, same arithmetic).
- **THE state-root hookup**: `Lane::digest()` produces the leaf; committing
  it into the coinbase OP_RETURN root is wiring in the existing THE
  commitment path, out of scope for the standalone module.
- **Adaptive W (OQ-6)**: headroom only, per the resolution — W is a
  LaneParams constant; no formula.

## Needs CI / integrator attention

1. **Weight adapter**: V36 `att` is `uint288` (`target_to_average_attempts`).
   The lane takes `w_raw : u64`. For sharechain share targets this fits
   easily (att ≈ share_difficulty × 2^32), but the adapter MUST assert/clamp
   att ≤ u64::max — define the rule (reject share vs clamp) as a consensus
   parameter before wiring. Flagged rather than decided here.
2. **Hashers**: `v37_hash.hpp` is a self-contained FIPS-conformant SHA-256
   (known-vector tested, bit-equal to core's CSHA256). Integration may swap
   to `core/hash.hpp` for one less implementation; output identical.
3. **Full-tree build**: `src/sharechain/CMakeLists.txt` gained
   `add_subdirectory(v37/test)`; the test target is dependency-free and
   gated on BUILD_TESTING. Not exercised against the full conan build on
   this VM (by design) — ci-steward/btc-heap-opt to verify.
4. **gtest port**: the suite uses a standalone CHECK harness so it runs
   without GTest; trivially portable to the repo's gtest idiom if preferred.
5. **Caller migration**: `HeadPPLNS`/`think()` integration (replacing
   `DensePPLNSRing` per the spec's "subsumes" map) is intentionally not
   started — the module is per-coin-agnostic and caller-shaped for it
   (push/rewind/payout_map mirror slide/rebuild/compute_v36_weights).
