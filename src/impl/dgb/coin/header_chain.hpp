#pragma once
// DGB header-chain validation. Mirrors src/impl/btc/coin/header_chain.hpp,
// shares the Scrypt PoW path with src/impl/ltc (identical Scrypt to LTC).
//
// >>> SCRYPT-ONLY VALIDATION POINT (M1 §2, project_v36_dgb_scrypt_only) <<<
// DGB is a 5-algo chain (Scrypt, SHA256d, Skein, Qubit, Odocrypt). In V36
// c2pool-dgb validates the SCRYPT path ONLY:
//   - Scrypt block header        -> full PoW validate (this slice)
//   - non-Scrypt block header     -> accept-by-continuity (extend headers,
//                                    do NOT PoW-validate) OR ignore
//   - malformed / wrong-magic     -> reject
// Algo is selected from the DGB version field (multi-algo encoding). Full
// 5-algo validation is V37 scope — do NOT add Skein/Qubit/Odocrypt/SHA256d
// PoW here.
//
// >>> THIRD INVARIANT: ACCEPT-BY-CONTINUITY HEADERS ARE WORK-NEUTRAL <<<
// (PR #60, dash-consensus review)
// A non-Scrypt header accepted by continuity extends the header chain, but its
// un-validated PoW MUST NOT contribute to sharechain cumulative work or
// best-chain selection. Continuity headers carry zero weight in work
// accounting. Otherwise an attacker feeds cheap non-Scrypt headers to inflate
// cumulative work — a consensus divergence vs p2pool-merged-v36 AND a DoS
// surface. This is the multi-algo analogue of the DASH case where DGW fully
// overrides the base 2016-block retarget (the base path is never reached).
// M3 MUST honor this in BOTH HeaderChain::validate() (no work credited for
// continuity headers) and the DigiShield window (continuity headers excluded
// from the retarget walk — see below).
//
// >>> DIGISHIELD INSERTION POINT (M1 §2) <<<
// DGB uses DigiShield/MultiShield per-algo difficulty retarget, NOT BTC's
// 2016-block retarget. The Scrypt-only ancestor selection for that window is
// implemented + guarded in coin/dgb_digishield.hpp (scrypt_window_ancestors +
// header_credits_work). THIS header lands the validate() body that drives the
// chain: per-header disposition (Scrypt validate / continuity / reject),
// work-neutral accounting, and the Scrypt-only retarget-window ASSEMBLY
// (averaged target + actual timespan over the Scrypt samples). The damped
// DigiShield/MultiShield multiply (bnNew = avg * f(timespan)/target_timespan,
// arith_uint256, clamp + adjustment) layers on top of RetargetWindow in the
// following slice — its inputs are pinned here so the multiply cannot reach a
// continuity header.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include <impl/dgb/coin/dgb_block_algo.hpp>
#include <impl/dgb/coin/dgb_digishield.hpp>

namespace c2pool::dgb {

using ::dgb::coin::DgbAlgo;
using ::dgb::coin::HeaderDisposition;
using ::dgb::coin::dgb_header_disposition;
using ::dgb::coin::header_credits_work;
using ::dgb::coin::is_scrypt_header;
using ::dgb::coin::scrypt_window_ancestors;

// Minimal header sample the Scrypt-only retarget body consumes. The embedded
// DigiByte Core port (M3+) carries the full CBlockHeader; the validate() +
// retarget path needs only the algo bits (disposition + work-credit), the
// timestamp (timespan), and the expanded difficulty target (averaging).
// `target` is a fixed-width proxy for the standalone CI guard; the per-algo
// DigiShield slice swaps arith_uint256 in with the SAME field shape, so the
// averaging/timespan assembly below is unchanged when the real width lands.
struct HeaderSample {
    int32_t  n_version = 0;
    int64_t  n_time    = 0;
    uint64_t target    = 0;   // expanded PoW target (smaller == more work)
};

// Outcome of validating + ingesting one header.
enum class IngestResult {
    VALIDATED_SCRYPT,       // Scrypt header, PoW-validated, work credited
    ACCEPTED_CONTINUITY,    // known non-Scrypt, appended, ZERO work credited
    REJECTED,               // unknown algo bits, or malformed Scrypt header
};

// Inputs the DigiShield/MultiShield damped multiply consumes. Assembled over
// SCRYPT ancestors ONLY — a continuity header can never reach `avg_target` or
// `actual_timespan`, which is precisely the corruption the THIRD INVARIANT and
// the DIGISHIELD INSERTION POINT warn against.
struct RetargetWindow {
    std::size_t scrypt_samples  = 0;     // Scrypt headers folded in (<= window)
    uint64_t    avg_target      = 0;     // mean expanded target over samples
    int64_t     actual_timespan = 0;     // newest - oldest Scrypt sample time
    bool        sufficient      = false; // true iff the full window was found
};

// Work-neutral header chain with a Scrypt-only DigiShield retarget body.
// Append order is oldest..newest; the retarget walk reads nearest-first.
class HeaderChain {
public:
    // Validate one header and, unless rejected, append it to the chain.
    // Work-neutrality SSOT: cumulative work advances iff header_credits_work()
    // — the SAME predicate scrypt_window_ancestors() consults for the retarget
    // window (header_credits_work forwards to is_scrypt_header). The two paths
    // cannot drift: a header either credits work AND enters the window, or
    // does neither.
    IngestResult validate_and_append(const HeaderSample& h)
    {
        switch (dgb_header_disposition(h.n_version))
        {
        case HeaderDisposition::REJECT:
            return IngestResult::REJECTED;

        case HeaderDisposition::VALIDATE_SCRYPT:
            // PoW validate path. A zero target is not a validatable Scrypt
            // header (the embedded daemon's full scrypt(header) <= target
            // check lands with the daemon port; the structural guard here is
            // that a malformed target never credits work).
            if (h.target == 0)
                return IngestResult::REJECTED;
            m_chain.push_back(h);
            m_cumulative_work += work_from_target(h.target);  // credited
            return IngestResult::VALIDATED_SCRYPT;

        case HeaderDisposition::ACCEPT_BY_CONTINUITY:
        default:
            // Extends the header chain; work-neutral (NO m_cumulative_work
            // change) and excluded from the retarget window by construction.
            m_chain.push_back(h);
            return IngestResult::ACCEPTED_CONTINUITY;
        }
    }

    // Assemble the Scrypt-only retarget window for the next block. Walks the
    // SCRYPT ancestors of the tip (skipping continuity headers via the shared
    // helper) and returns the averaged target + actual timespan the DigiShield
    // multiply needs. `actual_timespan` spans the newest and oldest Scrypt
    // samples only — continuity headers between them never widen it.
    RetargetWindow next_retarget_window(std::size_t window) const
    {
        RetargetWindow rw;
        if (window == 0 || m_chain.empty())
            return rw;

        const std::size_t depth = m_chain.size();
        // nearest-first view: k == 0 is the tip.
        const auto version_at = [&](std::size_t k) {
            return m_chain[depth - 1 - k].n_version;
        };
        const std::vector<std::size_t> idx =
            scrypt_window_ancestors(version_at, depth, window);
        if (idx.empty())
            return rw;

        unsigned __int128 target_sum = 0;
        for (std::size_t k : idx)
            target_sum += m_chain[depth - 1 - k].target;

        rw.scrypt_samples  = idx.size();
        rw.avg_target      = static_cast<uint64_t>(target_sum / idx.size());
        // idx is nearest-first: front() == newest Scrypt sample (smallest k),
        // back() == oldest. Timespan is over Scrypt samples exclusively.
        rw.actual_timespan = m_chain[depth - 1 - idx.front()].n_time
                           - m_chain[depth - 1 - idx.back()].n_time;
        rw.sufficient      = (idx.size() == window);
        return rw;
    }

    uint64_t    cumulative_work() const { return m_cumulative_work; }
    std::size_t size()            const { return m_chain.size(); }

private:
    // Work proxy: inversely proportional to the target (smaller target == more
    // work), matching real PoW work accounting in shape. The per-algo slice
    // swaps the arith_uint256 work() in; only Scrypt headers ever reach here.
    static uint64_t work_from_target(uint64_t target)
    {
        return target == 0 ? 0 : (UINT64_MAX / target);
    }

    std::vector<HeaderSample> m_chain;          // oldest .. newest
    uint64_t                  m_cumulative_work = 0;
};

} // namespace c2pool::dgb
