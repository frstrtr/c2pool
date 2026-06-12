# V37 MRR Roundabout Round-Buffer — implementation notes (WIP for review)

## Merkle digest (2026-06-12, OQ-M5 resolved) — lite-client proofs

The lane digest is now the root of a domain-separated Merkle tree over the
same canonical leaves (leaf = sha256d(0x00||payload), interior =
sha256d(0x01||L||R), odd promoted; fixed order: header leaf with geometry/
position/counts/L0 sums, acc leaves in canonical-identity order, bucket
leaves level-by-level oldest-first). `Lane::acc_proof()` produces a log-size
inclusion proof for one miner's accumulator; static `Lane::verify_proof()`
is the stateless lite-client verifier (kilobytes end-to-end via parent-chain
SPV -> OP_RETURN -> THE root -> lane root -> leaf). Same mechanism makes
per-band bucket raw_work individually provable for market settlement.
Tested: proof round-trip for every miner, tamper/index/root-freshness
rejection. Suite: 100,509 checks, 0 failures (-O2 and ASan/UBSan).

## Formal review pass (2026-06-12, fourth commit) — 7-angle review, 8 fixes

A structured multi-angle review (line-scan, replaced-behavior audit vs V36,
contract tracing, reuse/simplification/efficiency, altitude) confirmed the
three earlier fixes and surfaced new defects. Fixed in this commit:

1. **Rewind over a rebuild boundary** (consensus split, confirmed by
   experiment): rewinding onto the rebuild-triggering push succeeded without
   undoing the rebuild — restored state was in the new frame while honest
   peers that never saw the orphan stayed in the old frame. Fix: a
   RebuildBoundary sentinel journaled at every rebuild; rewind refuses to
   land on the rebuild-triggering push (caller takes the full-rebuild path);
   journal trim preserves an adjacent sentinel.
2. **kind-255 raw_script unbound to identity**: `valid()` now requires
   `canonicalize_script(raw_script) == pay` for RAW (enforces the hash
   binding AND the one-canon rule — template scripts smuggled under kind 255
   fail), rejects raw_script on template kinds, and validates payload widths
   (20/32) for every ScriptRef incl. attribution and aux.
3. **Geometry validation gaps**: constructor now refuses window < C0
   (previously: deterministic mid-push crash), empty level_caps, and inner
   level caps < R (previously: empty-deque UB on cascade).
4. **add_lane exception safety**: Lane constructed before directory insert —
   a geometry throw no longer bricks the chain id with a null entry.
5. **Public epoch_rebuild() misuse**: throws off the positional boundary
   (previously: B > next_pos, u64 underflow, OOB table reads).
6. **Zero-work shares rejected**: push(w_raw=0) created a zero acc entry the
   digest committed but undo_push erased — rewind was not bit-exact.
7. **aux count bound**: valid() caps aux at 0xffff so the canonical u16
   count field can never contradict the serialized entries.
8. **Lane geometry digest-committed**: W/C0/R/half_life/level_caps are now
   part of the digest preimage — parameter mismatch between nodes surfaces
   as an immediate attributable digest difference. Dead consensus surface
   removed (unused append_u32, free mul_q, U256::lo128).

Post-fix: **100,464 checks, 0 failures** (-O2 and ASan/UBSan), including
regressions for every fix above.

### Review findings deferred to integration (not fixed here)

- **Donation split (IMPORTANT)**: V36 splits each share's weight via the
  65535-donation scheme; v37 has no equivalent. The integration adapter MUST
  define donation handling — e.g. split w_raw at the adapter into a miner
  push and a donation-descriptor push (integer rule to be specified as
  consensus), or carry donation in the descriptor. Unresolved = donation
  outputs silently unpaid after migration.
- **Backward slide / multi-head**: V36 `slide_backward`/per-head `HeadPPLNS`
  have no direct v37 API. Multi-head = one Lane instance per competing head
  (~130 KiB each at default geometry); deep verification needs a
  rebuild-from-tracker constructor (O(W) push replay — same cost class as
  V36 `rebuild()`). Needs caller-shaped API at integration.
- **att (uint288) -> w_raw (u64) adapter** must assert/clamp (already
  flagged; review re-confirmed nothing in-module guards it).
- **Authority share messaging (V36 carry-forward, IMPORTANT)**: V36 embeds
  authority messages in shares' message_data — consensus-carried
  (ref_hash/PoW-protected), validated in share_check (bad envelope = share
  REJECTED), typed (incl. EMERGENCY and TRANSITION_SIGNAL — the channel a
  V37 activation itself would ride). See src/impl/<coin>/share_messages.hpp.
  This module reflects only PRESENCE at the lowest temporal level (L0 flag
  bit L0F_AUTHORITY_MSG, annotation-only, set by the adapter after
  share_check validation); payloads stay in the share store and join by
  pos. Open for operator/integrator: the V37 authority key set (V36 keys
  are baked-in donation-authority keys; new net needs an explicit decision
  + rotation policy) and FLAG_PERSISTENT semantics vs the roll-up pyramid
  (persistent messages lose L0 visibility at fold — re-broadcast, pin, or
  accept). Both filed as open questions in the design doc v1.2.
- **Efficiency backlog** (semantics-neutral): journal push-count counter
  instead of per-push O(|journal|) scans; drop dead Bucket copies in fold
  journal ops (only Evict undo reads op.bucket); payout_map emplace_hint or
  vector return (documented O(n) is currently O(n log n)); digest streaming
  into the incremental SHA ctx + per-call id_key memoization;
  raw_work_in_span lower_bound on ordered deques. Also consider deriving
  m_cover / m_acc_total / m_l0 sums instead of hand-maintaining (drift-proof
  by construction; the L0 sums are digest leaves, so derivation in digest()
  is the safer shape).
- **raw_work_in_span semantics**: buckets straddling the span edge are
  excluded (bucket-granular by design) and L0-vs-folded timing changes
  answers for unaligned bands — settlement bands MUST align to bucket/epoch
  boundaries (the market doc already assumes epoch-aligned bands); API doc
  updated, consider an aligned-band-only API at integration.
- **Reuse divergence risks for CI**: this module is the 3rd script-template
  classifier (vs core/address_utils.cpp x2), the 7th copy of the LN2_MICRO
  decay derivation, and a 2nd big-int (U256 vs base_uint). Integration
  should add cross-implementation agreement tests (same inputs -> same
  outputs) and a digest byte-layout golden test pinning the serialization
  independently of these helpers before any swap to core/pack.hpp idioms.

## Full reassessment pass 2 (2026-06-12, third commit) — C-1, consensus-critical

**C-1: lane digest keyed by node-local intern ids.** `MinerIntern` assigns
dense u32 ids at first *global* sighting; with multiple lanes the cross-lane
interleaving of first sightings is node-local (wall-clock dependent), so two
honest nodes assign different ids to the same miners. `digest()` serialized
acc in id order with raw id values (and `comp_hash` embedded ids), so two
honest nodes produced different digests for identical lane state — a chain
split under the consensus-committed digest (OQ-4). Payouts were never
affected (ids resolve to descriptors); only digest bytes.

Root cause is the SPEC: §8.5 says "acc in miner-id order". Erratum filed in
the design doc (v1.1): consensus serialization must be in **canonical
payout-descriptor identity order** with the 32-byte identity key (S-3) as
the serialized name — intern ids must never appear in consensus bytes.

Fix: `Lane::digest(resolver)` + `comp_hash(bucket, resolver)` sort and
serialize by `MinerIntern::key(id)` (identity_key, SHA256d of the identity
preimage); `Roundabout::lane_digest(chain)` is the production entry point.
Regression: two Roundabouts fed identical per-lane sequences under different
cross-lane interleavings — intern ids diverge, lane digests must not.
Post-fix: **100,448 checks, 0 failures** (-O2 and ASan/UBSan).

Docs re-verified in the same pass (geometry sums, half-life coverage, epoch
growth, tail-density claims all check out); doc errata E-1..E-5 listed in
the design doc v1.1 revision note.

## Reassessment pass (2026-06-12, second commit)

A full fresh-eyes re-audit of the consensus paths (re-deriving every range
bound rather than trusting comments) found and fixed two real defects that
the original 100k-check run could not see because both were self-consistent
between the fast path and the reference:

1. **Unguarded u64 wrap in `inv_decay` generation.** The inverse table
   requires `lambda^-(E-1) < 4.0` (roughly `E <= 2*half_life`); geometries
   violating it silently wrapped — lane and reference shared the wrapped
   table, so the bit-exact gate passed on a mathematically wrong curve. The
   generator now throws on any non-increase (wrap detection); two test
   geometries violated the ratio and were corrected; a regression test pins
   the throw. The ratified default geometry (E/HL = 1.896) was never
   affected.
2. **`rewind()` left the landing push's folds applied.** One push() call
   journals `[Folds][Push][Evicts]`; the undo loop stopped at the d-th Push
   without popping its own preceding folds, so a rewind landing exactly on a
   fold-triggering share restored "after the fold" instead of "before the
   share". The original digest test passed only by alignment luck. Fixed in
   `rewind()` and in the journal trim (which now keeps the kept-oldest
   push's folds); regression-tested by forcing a fold at the rewind boundary
   plus a 50-round randomized snapshot/push-k/rewind-k digest sweep.

Post-fix: **100,444 checks, 0 failures** (-O2 and ASan/UBSan). Lesson
folded into the suite: the reference-equality gate proves fast==reference,
not fast==intended-math — table generation and rewind now have their own
direct oracles (monotonicity/throw, digest-restore sweeps).

Branch: `fable/v37-mrr-buffer`. Spec: `c2pool-v37-mrr-roundabout-buffer.md` v1.0
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
