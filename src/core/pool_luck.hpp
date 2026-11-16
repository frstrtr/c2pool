// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// pool_luck.hpp -- pool luck as EFFORT. Display only: nothing here reaches a
// share target, a payout or a block.
//
// THE MODEL (p2pool.info 2012 "pooled luck", the pool standard).
//
//   A pool hashing at H(t) against a network difficulty D(t) finds blocks as
//   a Poisson process of intensity  lambda(t) = H(t) / (D(t) * 2^32).  Over a
//   round [ts_prev, ts] the number of blocks it EXPECTS to find is
//
//       effort = integral of lambda(t) dt over the round,
//
//   exactly 1.0 on average. Per-block luck is 100 / effort and is never
//   averaged: E[1/effort] is infinite, the arithmetic mean of per-block luck
//   reads ~450 % on a perfectly fair pool with 30 blocks. A period's luck is
//
//       luck = blocks found / blocks expected = k / sum(effort),
//
//   with the exact Poisson 95 % interval
//       [ chi2(.025; 2k) / 2 , chi2(.975; 2k + 2) / 2 ] / blocks expected.
//
//   H is the GROSS pool rate: the sharechain estimator counts the work of the
//   shares that made the chain (the non-stale rate), so
//       H = nonstale / (1 - stale_prop)            (p2pool get_global_stats).
//
// WHAT IS MEASURED. The node samples (time, pool rate, stale proportion,
// network difficulty) once a minute (the graph stat log). RateHistory turns
// those samples into piecewise-constant segments and integrates them over a
// round. A round the history does not cover at all falls back to the one
// sample taken when the block was found (effort_method "single_sample").
//
// A round the history covers only IN PART (the node was down, or its history
// starts mid-round) is two different questions:
//   * the ROW's effort is the best estimate for that round: the covered
//     integral scaled up by the covered share (history_coverage says how
//     much was measured);
//   * a PERIOD's luck extrapolates nothing: it is the count of blocks found
//     while the history was watching over the integral of the time it
//     watched -- a Poisson count over the observed time, whatever happened
//     in the gaps. A block found in a gap is left out (with the gap).
//
// The round's predecessor is the previous MAIN-CHAIN pool block of the same
// chain BY TIME. An orphaned or stale block is never a predecessor and never
// ends a round: block 2561418 was timed from orphan 2561316 (15,515 s) when
// its round ran from 2561265 (23,835 s).

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace core {
namespace luck {

/// Hashes per unit of difficulty.
inline constexpr double kHashesPerDifficulty = 4294967296.0;   // 2^32

/// The gross pool rate behind a non-stale estimator reading. Same formula as
/// /global_stats' pool_hash_rate, so the rate luck is defined over is the
/// rate the dashboard shows.
inline double gross_rate(double nonstale_rate, double stale_prop)
{
    if (!(nonstale_rate > 0.0) || !std::isfinite(nonstale_rate))
        return 0.0;
    if (!(stale_prop > 0.0) || !(stale_prop < 1.0))
        return nonstale_rate;   // none measured, or a degenerate all-stale window
    return nonstale_rate / (1.0 - stale_prop);
}

/// A stretch of time over which the pool hashed at `rate` against `difficulty`.
struct RateSegment {
    double t0{0.0};
    double t1{0.0};
    double rate{0.0};         ///< gross pool rate, H/s (> 0)
    double difficulty{0.0};   ///< network difficulty; 0 = not sampled
    double weight{1.0};       ///< share of [t0, t1] the samples behind it cover
};

/// The pool's rate / difficulty history as non-overlapping segments in time
/// order.
class RateHistory
{
public:
    /// The longest stretch one sample speaks for. The estimator behind a
    /// sample is a trailing mean over the last hour of the sharechain, so a
    /// sample taken after a gap (a restart) still describes that hour.
    static constexpr double kMaxSampleSpan = 3600.0;

    /// The result of integrating a stretch [a, b].
    struct Integral {
        double effort{0.0};      ///< sum of rate / (D * 2^32) over the covered time
        double covered{0.0};     ///< seconds of [a, b] the history covers
        double hashes{0.0};      ///< sum of rate over the covered time
        double diff_time{0.0};   ///< sum of D over the covered time
        double last_end{0.0};    ///< where the last covered stretch of [a, b] ends
        uint32_t segments{0};    ///< segments that contributed
        double mean_rate() const { return covered > 0.0 ? hashes / covered : 0.0; }
        double mean_difficulty() const { return covered > 0.0 ? diff_time / covered : 0.0; }
    };

    void clear()
    {
        m_segments.clear();
        m_last_stale_prop = 0.0;
        m_last_rate = 0.0;
        m_last_difficulty = 0.0;
    }

    bool empty() const { return m_segments.empty(); }
    size_t size() const { return m_segments.size(); }
    const std::vector<RateSegment>& segments() const { return m_segments; }
    double first_time() const { return m_segments.empty() ? 0.0 : m_segments.front().t0; }
    double last_time() const { return m_segments.empty() ? 0.0 : m_segments.back().t1; }

    /// The stale proportion of the newest sample (0 before the first).
    double last_stale_prop() const { return m_last_stale_prop; }
    /// The gross rate and the difficulty of the newest usable sample.
    double last_rate() const { return m_last_rate; }
    double last_difficulty() const { return m_last_difficulty; }

    /// One periodic sample taken at `t`: the estimator's non-stale rate, the
    /// stale proportion and the network difficulty read at that moment. It
    /// covers the time back to the previous sample, at most kMaxSampleSpan. A
    /// sample with no rate (the estimator had none) covers nothing.
    void add_sample(double t, double nonstale_rate, double stale_prop, double difficulty)
    {
        if (!(t > 0.0) || !std::isfinite(t))
            return;
        if (std::isfinite(stale_prop) && stale_prop >= 0.0)
            m_last_stale_prop = stale_prop;
        const double rate = gross_rate(nonstale_rate, stale_prop);
        if (!(rate > 0.0))
            return;
        const double end = last_time();
        if (!m_segments.empty() && t <= end)
            return;   // not newer than what is held
        double t0 = t - kMaxSampleSpan;
        if (!m_segments.empty() && end > t0)
            t0 = end;
        RateSegment s;
        s.t0 = t0;
        s.t1 = t;
        s.rate = rate;
        s.difficulty = (difficulty > 0.0 && std::isfinite(difficulty)) ? difficulty : 0.0;
        m_segments.push_back(s);
        m_last_rate = rate;
        if (s.difficulty > 0.0)
            m_last_difficulty = s.difficulty;
    }

    /// Append a ready segment (time order; the part before the newest held
    /// time is clipped away).
    void add_segment(RateSegment s)
    {
        if (!(s.rate > 0.0) || !std::isfinite(s.rate) || !(s.t1 > s.t0))
            return;
        if (!m_segments.empty() && s.t0 < last_time())
            s.t0 = last_time();
        if (!(s.t1 > s.t0))
            return;
        if (!(s.weight > 0.0) || !std::isfinite(s.weight))
            return;
        if (s.weight > 1.0)
            s.weight = 1.0;
        if (!(s.difficulty > 0.0) || !std::isfinite(s.difficulty))
            s.difficulty = 0.0;
        m_segments.push_back(s);
        m_last_rate = s.rate;
        if (s.difficulty > 0.0)
            m_last_difficulty = s.difficulty;
    }

    /// Put OLDER segments (coarse bins from the year-scale graph store) in
    /// front of what is held. Whatever reaches into the held range is clipped:
    /// the fine samples win.
    void prepend_older(std::vector<RateSegment> older)
    {
        std::sort(older.begin(), older.end(),
                  [](const RateSegment& a, const RateSegment& b) { return a.t0 < b.t0; });
        const double limit = m_segments.empty()
            ? std::numeric_limits<double>::infinity() : m_segments.front().t0;
        std::vector<RateSegment> out;
        out.reserve(older.size() + m_segments.size());
        double end = -std::numeric_limits<double>::infinity();
        for (auto s : older) {
            if (!(s.rate > 0.0) || !std::isfinite(s.rate))
                continue;
            if (!(s.weight > 0.0) || !std::isfinite(s.weight))
                continue;
            if (s.weight > 1.0) s.weight = 1.0;
            if (!(s.difficulty > 0.0) || !std::isfinite(s.difficulty))
                s.difficulty = 0.0;
            if (s.t0 < end) s.t0 = end;
            if (s.t1 > limit) s.t1 = limit;
            if (!(s.t1 > s.t0))
                continue;
            end = s.t1;
            out.push_back(s);
        }
        out.insert(out.end(), m_segments.begin(), m_segments.end());
        m_segments = std::move(out);
    }

    /// Drop everything that ended before `t`.
    void trim_before(double t)
    {
        auto it = std::find_if(m_segments.begin(), m_segments.end(),
                               [t](const RateSegment& s) { return s.t1 > t; });
        m_segments.erase(m_segments.begin(), it);
    }

    /// The gross rate the history holds at `t` (0 = `t` is not covered).
    double rate_at(double t) const
    {
        auto it = first_ending_after(t);
        if (it == m_segments.end() || it->t0 > t)
            return 0.0;
        return it->rate;
    }

    /// Integrate rate / (D * 2^32) over [a, b].
    ///
    /// `difficulty_override` > 0: every segment is taken against that
    /// difficulty (a merged chain: the pool rate is the parent's, the
    /// difficulty the aux block's own). Otherwise each segment uses the
    /// difficulty sampled with it, and `difficulty_fallback` where it has
    /// none; a segment with neither is not covered.
    Integral integrate(double a, double b, double difficulty_override,
                       double difficulty_fallback) const
    {
        Integral out;
        if (!(b > a))
            return out;
        for (auto it = first_ending_after(a); it != m_segments.end() && it->t0 < b; ++it) {
            const double lo = std::max(a, it->t0);
            const double hi = std::min(b, it->t1);
            if (!(hi > lo))
                continue;
            double d = difficulty_override > 0.0 ? difficulty_override
                     : it->difficulty > 0.0      ? it->difficulty
                                                 : difficulty_fallback;
            if (!(d > 0.0))
                continue;
            const double w = (hi - lo) * it->weight;
            out.covered   += w;
            out.hashes    += w * it->rate;
            out.diff_time += w * d;
            out.effort    += w * it->rate / (d * kHashesPerDifficulty);
            out.last_end   = hi;
            ++out.segments;
        }
        return out;
    }

private:
    std::vector<RateSegment>::const_iterator first_ending_after(double t) const
    {
        return std::upper_bound(m_segments.begin(), m_segments.end(), t,
                                [](double v, const RateSegment& s) { return v < s.t1; });
    }

    std::vector<RateSegment> m_segments;
    double m_last_stale_prop{0.0};
    double m_last_rate{0.0};
    double m_last_difficulty{0.0};
};

// ---------------------------------------------------------------------------
// Rounds
// ---------------------------------------------------------------------------

enum class EffortMethod : uint8_t {
    none = 0,       ///< an input cannot be had: no effort, no luck
    first_block,    ///< no earlier main-chain block: effort 1.0 by definition
    integrated,     ///< integral of the rate / difficulty history over the round
    single_sample,  ///< the one rate / difficulty sample taken at find time
};

inline const char* effort_method_name(EffortMethod m)
{
    switch (m) {
    case EffortMethod::first_block:   return "first_block";
    case EffortMethod::integrated:    return "integrated";
    case EffortMethod::single_sample: return "single_sample";
    default:                          return "";
    }
}

/// Why a round has no effort.
enum class MissingInput : uint8_t { nothing = 0, difficulty, rate };

/// One found block of ONE chain, as luck sees it.
struct RoundInput {
    double   ts{0.0};           ///< block time, unix seconds
    uint64_t height{0};         ///< breaks a tie between equal times
    bool     main_chain{true};  ///< false: orphaned / stale
    double   difficulty{0.0};   ///< the block's own network difficulty; 0 = unknown
    double   rate_at_find{0.0}; ///< gross pool rate sampled at record time; 0 = unknown
};

struct RoundResult {
    EffortMethod method{EffortMethod::none};
    MissingInput missing{MissingInput::nothing};
    int      prev{-1};              ///< index of the predecessor row; -1 = none
    double   time_to_find{0.0};     ///< seconds since the predecessor; 0 = none
    double   effort{0.0};           ///< blocks expected over the round; 0 = unknown
    double   luck{0.0};             ///< 100 / effort; 0 = unknown
    double   expected_time{0.0};    ///< time_to_find / effort; 0 = unknown
    double   coverage{0.0};         ///< share of the round the history covers
    double   covered_effort{0.0};   ///< the integral over the covered time alone (not scaled up)
    bool     end_covered{false};    ///< the history was watching when the round ended
    double   rate_used{0.0};        ///< mean gross rate behind the effort
    double   difficulty_used{0.0};  ///< mean difficulty behind the effort
    uint32_t samples{0};            ///< history segments (or 1: the find sample)
};

struct RoundOptions {
    /// true: the difficulty sampled with the rate history (the node's own
    /// chain). false: each round runs against its block's own difficulty (a
    /// merged chain -- the history's difficulty is the parent's).
    bool history_difficulty{true};
};

/// A round is at least this long: block times have one-second resolution.
inline constexpr double kMinRoundSeconds = 1.0;

/// The history counts as watching at a round's end when its last covered
/// stretch ends within this of it: a block is recorded up to a sample period
/// (a minute) before the sample that covers its own time arrives.
inline constexpr double kEndGapTolerance = 300.0;

/// The effort of the stretch [a, b] of a round that ended in a block of
/// difficulty `difficulty` recorded at `rate_at_find`.
inline RoundResult effort_over(const RateHistory& hist, const RoundOptions& opt,
                               double a, double b, double difficulty, double rate_at_find)
{
    RoundResult r;
    const double span = b - a;
    const double t = std::max(span, kMinRoundSeconds);
    r.time_to_find = t;
    RateHistory::Integral in;
    if (opt.history_difficulty)
        in = hist.integrate(a, b, 0.0, difficulty);
    else if (difficulty > 0.0)
        in = hist.integrate(a, b, difficulty, 0.0);   // never the parent's difficulty
    if (in.covered > 0.0 && in.effort > 0.0) {
        r.method = EffortMethod::integrated;
        r.effort = in.effort / in.covered * t;
        r.coverage = span > 0.0 ? std::min(1.0, in.covered / span) : 0.0;
        r.covered_effort = in.effort;
        r.end_covered = b - in.last_end <= kEndGapTolerance;
        r.rate_used = in.mean_rate();
        r.difficulty_used = in.mean_difficulty();
        r.samples = in.segments;
    } else if (difficulty > 0.0 && rate_at_find > 0.0) {
        r.method = EffortMethod::single_sample;
        r.effort = t * rate_at_find / (difficulty * kHashesPerDifficulty);
        r.rate_used = rate_at_find;
        r.difficulty_used = difficulty;
        r.samples = 1;
    } else {
        r.method = EffortMethod::none;
        r.missing = difficulty > 0.0 ? MissingInput::rate : MissingInput::difficulty;
        return r;
    }
    r.luck = 100.0 / r.effort;
    r.expected_time = t / r.effort;
    return r;
}

/// Time order of the rows of one chain: by time, then height, then position.
inline std::vector<int> time_order(const std::vector<RoundInput>& rows)
{
    std::vector<int> order(rows.size());
    for (size_t i = 0; i < rows.size(); ++i) order[i] = static_cast<int>(i);
    std::stable_sort(order.begin(), order.end(), [&rows](int a, int b) {
        if (rows[a].ts != rows[b].ts) return rows[a].ts < rows[b].ts;
        return rows[a].height < rows[b].height;
    });
    return order;
}

/// Effort and luck of every row of one chain. The result is index-parallel to
/// `rows`.
inline std::vector<RoundResult> compute_rounds(const std::vector<RoundInput>& rows,
                                               const RateHistory& hist,
                                               const RoundOptions& opt = {})
{
    std::vector<RoundResult> out(rows.size());
    int last_main = -1;
    for (int i : time_order(rows)) {
        const RoundInput& row = rows[i];
        RoundResult& r = out[i];
        if (last_main < 0 && !row.main_chain) {
            // An orphan before the chain's first block: no round to time,
            // and it is not the first block either. No effort.
        } else if (last_main < 0) {
            // No earlier main-chain block: nothing to time the round from.
            // By the operator's ruling it is one block found for one expected.
            r.method = EffortMethod::first_block;
            r.effort = 1.0;
            r.luck = 100.0;
            if (row.difficulty > 0.0 && row.rate_at_find > 0.0) {
                r.expected_time = row.difficulty * kHashesPerDifficulty / row.rate_at_find;
                r.rate_used = row.rate_at_find;
                r.difficulty_used = row.difficulty;
                r.samples = 1;
            }
        } else {
            r = effort_over(hist, opt, rows[last_main].ts, row.ts, row.difficulty,
                            row.rate_at_find);
            r.prev = last_main;
        }
        if (row.main_chain)
            last_main = i;
    }
    return out;
}

// ---------------------------------------------------------------------------
// The open round and period luck
// ---------------------------------------------------------------------------

/// The round in progress: from the newest main-chain block to `now`.
struct OpenRound {
    int      since{-1};            ///< index of the block it runs from; -1 = no block yet
    double   elapsed{0.0};
    double   effort{0.0};          ///< 0 = unknown
    double   covered_effort{0.0};  ///< the integral over the covered time alone
    double   expected_time{0.0};   ///< at the live rate and difficulty; 0 = unknown
    double   coverage{0.0};
    double   difficulty{0.0};      ///< the live difficulty it ran against
    EffortMethod method{EffortMethod::none};
};

inline OpenRound open_round(const std::vector<RoundInput>& rows, const RateHistory& hist,
                            const RoundOptions& opt, double now, double live_rate,
                            double live_difficulty)
{
    OpenRound o;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (!rows[i].main_chain) continue;
        if (o.since < 0 || rows[i].ts > rows[o.since].ts
            || (rows[i].ts == rows[o.since].ts && rows[i].height > rows[o.since].height))
            o.since = static_cast<int>(i);
    }
    if (o.since < 0)
        return o;
    const double from = rows[o.since].ts;
    o.elapsed = std::max(0.0, now - from);
    o.difficulty = live_difficulty > 0.0 ? live_difficulty : 0.0;
    if (live_rate > 0.0 && live_difficulty > 0.0)
        o.expected_time = live_difficulty * kHashesPerDifficulty / live_rate;
    if (!(now > from))
        return o;
    const RoundResult r = effort_over(hist, opt, from, now, live_difficulty, live_rate);
    o.method = r.method;
    o.effort = r.effort;
    o.covered_effort = r.covered_effort;
    o.coverage = r.coverage;
    if (!(o.expected_time > 0.0) && r.effort > 0.0)
        o.expected_time = o.elapsed / r.effort;
    return o;
}

/// Lower regularized incomplete gamma P(a, x).
inline double regularized_gamma_p(double a, double x)
{
    if (!(a > 0.0) || !(x > 0.0))
        return 0.0;
    const double lead = std::exp(-x + a * std::log(x) - std::lgamma(a));
    if (x < a + 1.0) {
        // Series.
        double term = 1.0 / a, sum = term;
        for (int n = 1; n < 100000; ++n) {
            term *= x / (a + n);
            sum += term;
            if (std::fabs(term) < std::fabs(sum) * 1e-16) break;
        }
        return std::min(1.0, sum * lead);
    }
    // Continued fraction for Q(a, x) (modified Lentz).
    const double tiny = 1e-300;
    double b = x + 1.0 - a, c = 1.0 / tiny, d = 1.0 / b, h = d;
    for (int i = 1; i < 100000; ++i) {
        const double an = -static_cast<double>(i) * (static_cast<double>(i) - a);
        b += 2.0;
        d = an * d + b;
        if (std::fabs(d) < tiny) d = tiny;
        c = b + an / c;
        if (std::fabs(c) < tiny) c = tiny;
        d = 1.0 / d;
        const double delta = d * c;
        h *= delta;
        if (std::fabs(delta - 1.0) < 1e-16) break;
    }
    return std::max(0.0, 1.0 - lead * h);
}

/// x with P(a, x) = p: half the chi-square quantile of 2a degrees of freedom.
inline double inverse_gamma_p(double a, double p)
{
    if (!(a > 0.0) || !(p > 0.0))
        return 0.0;
    if (p >= 1.0)
        return std::numeric_limits<double>::infinity();
    if (a > 1.0e5) {
        // Wilson-Hilferty; the exact inverse costs O(a) per step up here and
        // the approximation is good to ~1e-7 relative.
        // Normal quantile by bisection on erfc.
        double zl = -40.0, zh = 40.0;
        for (int i = 0; i < 200; ++i) {
            const double zm = 0.5 * (zl + zh);
            if (0.5 * std::erfc(-zm / std::sqrt(2.0)) < p) zl = zm; else zh = zm;
        }
        const double z = 0.5 * (zl + zh);
        const double c = 1.0 - 1.0 / (9.0 * a) + z / (3.0 * std::sqrt(a));
        return a * c * c * c;
    }
    double lo = 0.0, hi = a + 10.0 * std::sqrt(a) + 50.0;
    while (regularized_gamma_p(a, hi) < p) hi *= 2.0;
    for (int i = 0; i < 200; ++i) {
        const double mid = 0.5 * (lo + hi);
        if (regularized_gamma_p(a, mid) < p) lo = mid; else hi = mid;
        if (hi - lo <= 1e-13 * hi) break;
    }
    return 0.5 * (lo + hi);
}

/// The exact (Garwood) 95 % interval for a Poisson mean given `k` events:
/// [ chi2(.025; 2k) / 2 , chi2(.975; 2k + 2) / 2 ].
inline std::pair<double, double> poisson_ci95(uint64_t k)
{
    const double lo = k == 0 ? 0.0 : inverse_gamma_p(static_cast<double>(k), 0.025);
    const double hi = inverse_gamma_p(static_cast<double>(k) + 1.0, 0.975);
    return {lo, hi};
}

/// Luck of a period: blocks found over blocks expected.
struct PeriodLuck {
    uint64_t k{0};              ///< main-chain blocks found in the period
    double   expected{0.0};     ///< blocks expected over it
    bool     has_luck{false};   ///< expected > 0
    double   luck{0.0};         ///< percent
    double   ci_low{0.0};       ///< percent
    double   ci_high{0.0};      ///< percent
    double   span{0.0};         ///< seconds the period covers
    uint64_t unmeasured{0};     ///< blocks in the period left out of k (see period_luck)
};

/// Period luck over [window_start, now] (window_start <= 0: all time).
///
/// blocks_expected is the effort of the period's rounds, each clipped to the
/// window, the open round included -- the expected number of blocks over
/// exactly that stretch of time. For a fully measured history that is
/// k / sum(effort). Where the history has gaps nothing is extrapolated:
///
///   * an integrated round adds the integral over the time the history
///     COVERS (not scaled up), and its block is counted only if the history
///     was watching when it was found -- a Poisson count over the observed
///     time. A block found in a gap is reported in `unmeasured`;
///   * a round with no history at all adds its single-sample effort (the
///     only measurement there is) and its block;
///   * a first block (no predecessor) is one found for one expected;
///   * a round whose effort cannot be had is left out of both the count and
///     the expectation, and reported in `unmeasured`.
inline PeriodLuck period_luck(const std::vector<RoundInput>& rows,
                              const std::vector<RoundResult>& res,
                              const RateHistory& hist, const RoundOptions& opt,
                              const OpenRound& open, double window_start, double now)
{
    PeriodLuck p;
    const bool all = !(window_start > 0.0);
    const double w0 = all ? -std::numeric_limits<double>::infinity() : window_start;
    double first_ts = 0.0;
    bool any = false;

    // What the part [a, b] of a round [from, to] adds to the expectation.
    // `whole` is the round's contribution when all of it is in the window.
    auto part = [&](EffortMethod method, double whole, double from, double to, double a,
                    double b, double difficulty) -> double {
        if (a <= from && b >= to) return whole;
        if (!(b > a)) return 0.0;
        if (method == EffortMethod::integrated) {
            // The covered integral over the clipped stretch, whatever it is.
            const RoundResult sub = effort_over(hist, opt, a, b, difficulty, 0.0);
            return sub.method == EffortMethod::integrated ? sub.covered_effort : 0.0;
        }
        // A single sample: linear in time.
        const double len = std::max(to - from, kMinRoundSeconds);
        return whole * (b - a) / len;
    };

    for (size_t i = 0; i < rows.size() && i < res.size(); ++i) {
        const RoundInput& row = rows[i];
        if (!row.main_chain) continue;
        if (!any || row.ts < first_ts) first_ts = row.ts;
        any = true;
        if (row.ts < w0) continue;
        const RoundResult& r = res[i];
        if (r.method == EffortMethod::first_block) {
            ++p.k;
            p.expected += 1.0;
        } else if (r.method == EffortMethod::none || r.prev < 0) {
            ++p.unmeasured;
        } else {
            const double from = rows[r.prev].ts;
            const bool integrated = r.method == EffortMethod::integrated;
            p.expected += part(r.method, integrated ? r.covered_effort : r.effort, from, row.ts,
                               std::max(from, w0), row.ts, row.difficulty);
            if (!integrated || r.end_covered) ++p.k;
            else ++p.unmeasured;   // found while the history was not watching
        }
    }
    if (open.since >= 0 && open.effort > 0.0 && open.since < static_cast<int>(rows.size())) {
        const double from = rows[open.since].ts;
        const bool integrated = open.method == EffortMethod::integrated;
        // The open round has no block: it runs against the live difficulty.
        p.expected += part(open.method, integrated ? open.covered_effort : open.effort, from,
                           now, std::max(from, w0), now, open.difficulty);
    }
    if (any)
        p.span = std::max(0.0, now - (all ? first_ts : std::max(first_ts, w0)));
    if (p.expected > 0.0) {
        p.has_luck = true;
        p.luck = 100.0 * static_cast<double>(p.k) / p.expected;
        const auto ci = poisson_ci95(p.k);
        p.ci_low = 100.0 * ci.first / p.expected;
        p.ci_high = 100.0 * ci.second / p.expected;
    }
    return p;
}

} // namespace luck
} // namespace core
