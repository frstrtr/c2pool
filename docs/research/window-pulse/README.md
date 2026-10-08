# Window deflation by pulsing hashrate

Research note, 2026-09-30. External review item "window: deflation by pulsing
hashrate" (review-criticals, planned for v37.1). Portable: the three
simulations here are self-contained and build against `src/`.

## Question

A large miner switches on for a short time. The XMR lane window is the last
8640 receipts, so the pulse pushes the older receipts of everyone else out of
the window. Does that take money from the small, steady miners, and can
someone profit by timing their mining around it?

## Short answer

- **The shipped window cannot be gamed.** Expected pay per unit of work is the
  same for the pulser, the miners it "deflates", and a hopper who knows the
  pulse schedule (within 0.05% in the model, 1.0000 on the real `v37::Lane`).
  Deflation changes **variance only**.
- **The V37.1 time-denominated window, as designed, can be gamed.** Work done
  just before a hashrate jump is overpaid, work just after it is underpaid. A
  schedule-aware hopper gets +23% (daily pulses) and up to +126% (weekly
  pulses, no width law). The pulser loses about 10%.
- **A defect in the V37.1 native-ridge width law** (gated off) is fixed. It
  ran the window to W_MAX instead of its fixed point.

## How the shipped XMR window works

The XMR lane runs `LaneParams{}` with every V37.1 gate OFF
(`xmr_node_config.hpp`: `node_lane_params_no_kind()`; XMR has no `LaneKind`).

- The window is 8640 **positions**, and the decay half-life is 2160 positions.
  One receipt is one position (`LaneRecord::push(..., 0)`, no origin bin).
- Every receipt is admitted at exactly the lane share difficulty (R-1,
  HELLO-pinned), and `kReceiptWeight = 1`.
- So every position is the same work and is equally likely to be a block.
  A receipt at position p earns `sum over later blocks b of λ^(P_b - p) / S`,
  where S = the total window weight, which is the same constant for every
  block. Its expected pay is `q · R` no matter when it was mined: a pulse
  shortens the window in wall-clock time, and blocks come just as much faster.

This is PPLNS with exponential weights, and PPLNS is hop-proof in expectation.
Withholding receipts and dumping them later is also a loss for the withholder:
the dumped positions sit in a jump that no block lands inside.

## Results

### Expected value (`fluid.cpp`)

Model:

- Steady pool: 12 receipts per bin (bin = one 120 s Monero block), so the
  window is about 24 h. The pool finds 2 blocks per day.
- B is a small steady miner (1%), C is the rest of the steady pool, A is the
  pulser, and D is a hopper at 0.1 of the steady rate.
- The time window is modelled as bin-age decay (half-life 2160 bins) with
  eviction by bin span. The width law is `W = C·D·W / raw_prev_window`, damped
  ×4 and floored to 8, with C chosen so the steady window is 720 bins.
- The first 14 days are excluded as warm-up.

Income per unit of work (1.00 = fair):

| scenario | positional (shipped) | time + width law | time, fixed 720 |
|---|---|---|---|
| A 10× for 2 h/day: A | 1.001 | **0.898** | 1.004 |
| same: B and C | 0.999 | **1.085** | 0.997 |
| D mines 2 h **before** each pulse | 0.998 | **1.233** | 1.037 |
| D mines 2 h **after** each pulse | 1.000 | **0.636** | 0.956 |
| A 10× for 1 day/week: A | 0.998 | 0.988 | **0.917** |
| same: B and C | 1.002 | 1.016 | **1.125** |
| D mines the day **before** the weekly pulse | 1.017 | **1.118** | **2.261** |

The positional residue is the model's time-step error. It shrinks toward zero
as the step shrinks (0.07% → 0.05% at 4 → 16 sub-steps per bin), and the exact
run on the real `Lane` (`v37_xmr_window_pulse_kat` P4, including the weekly
hopper at 1.017 here) gives 1.0000. The time-window distortion does
not shrink.

The mechanism: under a time window, the total weight at a block tracks the
hashrate of the recent past, while the block rate tracks the hashrate now.
Right after a jump, blocks come faster than the weight has grown, so work from
before the jump takes a larger cut. Right after a drop it is the other way
round.

### Variance (`mc.cpp`, real `v37::Lane`)

Setup: 200 runs of 30 days each. Pulse A is on for 2 h a day. The real lane
matches the double-precision reference within 2·10⁻⁵ (the gap is bucket
eviction in groups of 8).

| B | A | CV of B's 30-day income, positional / time | blocks where B has zero weight, positional / time |
|---|---|---|---|
| 1% | none | 0.143 / 0.142 | 0.03% / 0.03% |
| 1% | 10× | 0.118 / 0.100 | 0.2% / 0.2% |
| 1% | 30× | 0.108 / 0.074 | 2.9% / 0.2% |
| 0.1% | 10× | 0.124 / 0.108 | 5.7% / 1.3% |
| 0.1% | 30× | 0.128 / 0.094 | **40.5%** / 1.8% |

This is the real footprint of deflation. A 0.1% miner has no weight in 40% of
blocks while a 30× pulser runs, so its pay arrives in fewer, larger pieces.
Its monthly income has the same mean, and its variance is no worse than with
no pulser at all, because the pulser brings more blocks.

### The width-law defect (`nrlaw.cpp`, `v37_1_width_law_kat`)

`winlaw::retarget_width` computes `C·D·W_cur / raw` and assumes `raw` was
measured over the prior full window of width W_cur, so W_cur cancels.

The native ridge (`nr_maybe_retarget`) passed the raw work of **one 8-bin
period**. That leaves a stray factor of W_cur / 8, and W runs to W_MAX by the
damper:

```
fixed point wanted: 1000 bins (LTC table, C = 576)
positional divisor:            1000 1000 1000 ...
native ridge, before the fix:  2304 4608 4608 ...
native ridge, fixed:           1000 1000 1000 ...
```

The fix:

- `winlaw::retarget_width_over(d, W_cur, raw, span_bins, gate)` takes the
  measured span explicitly.
- `retarget_width` is its `span = W_cur` form and is unchanged bit for bit
  (WL-1).
- The ridge passes the period's span in bins: R_b, or the part of it since the
  flip.
- The code is gated off, and every existing ridge test drives `d_net = 0`, so
  no golden moves.

A separate issue: `coverage_blocks` is pinned to W_default (144 to 1440
"expected blocks in the window") and marked OWED. With that value, any pool
smaller than most of the network sits at W_MAX, so the value has to be ruled
before the law does anything.

## Recommendation

1. **Close the review item** for XMR as "not a fairness hole; variance only".
   It is pinned by `v37_xmr_window_pulse_kat`, which runs the real `Lane`: a
   pulser, the steady miners, and hoppers timed before, during, after and a
   day ahead of a weekly pulse all get 1.0000. A negative control (weight 2
   for the pulser) moves A to 1.24 and B to 0.80.
2. **Do not flip the time-denominated window for XMR** in its current form. It
   trades a variance effect for a real, exploitable bias. If the payout
   variance of very small miners matters, lengthen the window in receipts or
   lower the receipt difficulty. Both keep the hop-proof property.
3. **If V37.1 keeps a time window** for the other lanes, it needs either a
   work-denominated denominator (payout per unit of work at the block's own
   work rate, not the lagged window weight) or an argument that its bias is
   acceptable. The model here is the place to test candidates.
4. The native-ridge width law now measures its own span and is pinned by
   `v37_1_width_law_kat` (WL-1..3). WL-3 fails on the pre-fix code with 7
   checks.

## Files

| file | what |
|---|---|
| `fluid.cpp` | expected-value model, positional vs time window, with and without the width law |
| `mc.cpp` | Monte Carlo on the real `v37::Lane`: variance and zero-weight blocks |
| `nrlaw.cpp` | width-law fixed point, positional vs native ridge, before and after the fix |
| `src/c2pool/v37/test/v37_xmr_window_pulse_kat.cpp` | CI pin: the shipped window is fair under pulses and hoppers |
| `src/c2pool/v37/test/v37_1_width_law_kat.cpp` | CI pin: the width law settles at its fixed point |
