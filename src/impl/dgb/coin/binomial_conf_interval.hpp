// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::binomial_conf_interval -- FENCED, additive SSOT lift of the
// p2pool util/math.py:133 binomial_conf_interval (Wilson score interval) and
// its ierf/erf helpers. This is the stale-rate / dead-share CONFIDENCE-INTERVAL
// display arithmetic the status loop renders (main.py:406/425/426 via
// format_binomial_conf). DIAGNOSTICS ONLY -- it touches no PoW, share format,
// sharechain rule, PPLNS math, or block submission, so the p2pool-merged-v36
// surface is NONE. No call site is rewired by this slice (the byte-identity
// delegation, if ever wanted, is a separate follow-on); this header is the
// dormant SSOT + its KAT.
//
// FAITHFULNESS NOTE: the oracle does NOT use libm erf. It ships its own
// Abramowitz & Stegun 7.1.26 polynomial approximation (util/math.py:100) and
// ierf Newton-iterates ON THAT approximation (10 steps from 0, true-erf
// derivative). Porting std::erf instead would shift ierf and break byte-parity
// with the oracle, so erf_as7126 below reproduces the oracle polynomial exactly.
//
// Per-coin isolation: src/impl/dgb/ only. Pure header (<cmath>/<array>) -- no
// core/share/tracker translation unit pulled in.
// ---------------------------------------------------------------------------

#include <array>
#include <cmath>
#include <algorithm>

namespace dgb {
namespace coin {

// Oracle erf -- Abramowitz & Stegun formula 7.1.26 (util/math.py:100).
// erf(-x) = -erf(x) handled via sign capture, exactly as the oracle.
inline double erf_as7126(double x)
{
    int sign = 1;
    if (x < 0) sign = -1;
    x = std::fabs(x);

    const double a1 =  0.254829592;
    const double a2 = -0.284496736;
    const double a3 =  1.421413741;
    const double a4 = -1.453152027;
    const double a5 =  1.061405429;
    const double p  =  0.3275911;

    const double t = 1.0 / (1.0 + p * x);
    const double y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1)
                           * t * std::exp(-x * x);
    return sign * y;
}

// Oracle ierf (util/math.py:130) -- Newton root-find of erf(x) - z, 10 steps
// from guess 0, no bounds. find_root step: guess -= (erf(guess)-z)/erf'(guess),
// with erf'(x) = 2 e^{-x^2} / sqrt(pi) (the TRUE derivative, matching the
// oracle's analytic dy term even though erf itself is the approximation above).
inline double ierf(double z)
{
    double guess = 0.0;
    for (int i = 0; i < 10; ++i) {
        const double dy = 2.0 * std::exp(-guess * guess) / std::sqrt(M_PI);
        const double y_over_dy = (erf_as7126(guess) - z) / dy;
        const double prev = guess;
        guess = guess - y_over_dy;
        if (guess == prev) break;
    }
    return guess;
}

// Wilson score interval (util/math.py:133), n > 0 path. Returns {left, right},
// each clipped to [0,1], with the interval EXTENDED to include the point
// estimate p = x/n (oracle add_to_range, util/math.py:48). PRECONDITION n > 0:
// the oracle's n == 0 branch seeds a random.random() placeholder window of
// width `conf` -- a non-deterministic display sentinel handled by the caller,
// deliberately NOT reproduced here (a pure function cannot mirror it).
inline std::array<double, 2> binomial_conf_interval(double x, double n,
                                                    double conf = 0.95)
{
    const double z      = std::sqrt(2.0) * ierf(conf);
    const double p      = x / n;
    const double topa   = p + z * z / 2.0 / n;
    const double topb   = z * std::sqrt(p * (1.0 - p) / n + z * z / 4.0 / (n * n));
    const double bottom = 1.0 + z * z / n;

    double lo = (topa - topb) / bottom;
    double hi = (topa + topb) / bottom;

    // add_to_range(p, [lo, hi]) = (min(lo, p), max(hi, p)): pull the endpoints
    // out to always bracket the point estimate before clipping.
    lo = std::min(lo, p);
    hi = std::max(hi, p);

    const auto clip01 = [](double v) { return std::max(0.0, std::min(1.0, v)); };
    return { clip01(lo), clip01(hi) };
}

} // namespace coin
} // namespace dgb