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

#include <impl/dgb/coin/dgb_arith256.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>
#include <impl/dgb/coin/dgb_digishield.hpp>

namespace c2pool::dgb {

using ::dgb::coin::DgbAlgo;
using ::dgb::coin::HeaderDisposition;
using ::dgb::coin::dgb_header_disposition;
using ::dgb::coin::header_credits_work;
using ::dgb::coin::is_scrypt_header;
using ::dgb::coin::mul_div_u256;
using ::dgb::coin::scrypt_window_ancestors;
using ::dgb::coin::u256;

// Minimal header sample the Scrypt-only retarget body consumes. The embedded
// DigiByte Core port (M3+) carries the full CBlockHeader; the validate() +
// retarget path needs only the algo bits (disposition + work-credit), the
// timestamp (timespan), the expanded difficulty target (averaging), and the
// scrypt(header) PoW digest (`pow_hash`, the CheckProofOfWork hash <= target
// check). `target` and `pow_hash` are fixed-width proxies for the standalone CI
// guard; the per-algo DigiShield slice swaps arith_uint256 in with the SAME
// field shape, so the averaging/timespan assembly below is unchanged when the
// real width lands. pow_hash == 0 is the proxy default for "scrypt(header) not
// evaluated here" (trivially satisfies any target); the daemon port fills it.
struct HeaderSample {
    int32_t  n_version = 0;
    int64_t  n_time    = 0;
    uint64_t target    = 0;   // expanded PoW target (smaller == more work)
    uint64_t pow_hash  = 0;   // scrypt(header) digest; hash <= target == valid PoW
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

// DigiShield/MultiShield retarget parameters (per-algo). `target_timespan` is
// the nominal per-block Scrypt solve time the damped filter pulls toward;
// `pow_limit` is the easiest (largest) admissible target -- bnNew is capped to
// it so a long stall can never relax difficulty past the network minimum.
struct DigiShieldParams {
    int64_t  target_timespan = 0;   // nominal solve time the filter centers on
    uint64_t pow_limit       = 0;   // max (easiest) target; result never exceeds
};

// Per-algo DigiShield/MultiShield damped retarget multiply (M3 7b).
//
// Consumes the Scrypt-only RetargetWindow (averaged target + actual timespan,
// both assembled over SCRYPT ancestors EXCLUSIVELY in next_retarget_window) and
// produces the next block's expanded target. Pins DigiByte Core's DigiShield v3
// amplitude filter:
//
//   damped = target_timespan + (actual_timespan - target_timespan) / 8
//   clamp damped into [target_timespan*3/4, target_timespan*3/2]
//   bnNew  = avg_target * damped / target_timespan
//   bnNew  = min(bnNew, pow_limit)
//
// The /8 filter damps a single block's deviation; the clamp rails bound the
// per-step move so a manipulated (or non-monotonic) timestamp run cannot swing
// difficulty arbitrarily in one retarget. The lower rail is reachable only when
// actual_timespan goes sharply negative (out-of-order block times); the upper
// rail trips once actual_timespan exceeds ~5x nominal.
//
// The damped-multiply intermediate runs at TRUE 256-bit width via mul_div_u256
// (coin/dgb_arith256.hpp): arith_uint256 multiply-then-divide with 256-bit
// overflow truncation -- the consensus behaviour DigiByte Core exhibits near
// pow_limit, which an __int128 proxy could NOT reproduce (it would compute a
// wider, divergent next target). `target` here is still the uint64 field proxy
// the standalone CI guard uses; for any uint64-range avg_target the 256-bit path
// is bit-identical to the prior intermediate, so existing vectors are unchanged.
// The embedded-daemon port swaps real arith_uint256 into the field shape with
// this exact multiply/clamp ordering.
//
// Returns 0 when the window carries no Scrypt samples -- the caller MUST keep
// the prior target rather than retarget off an empty window (early/genesis).
inline uint64_t digishield_next_target(const RetargetWindow& rw,
                                       const DigiShieldParams& params)
{
    if (rw.scrypt_samples == 0 || params.target_timespan <= 0)
        return 0;

    const int64_t nominal = params.target_timespan;

    // Amplitude filter: pull the observed timespan 1/8 of the way off nominal.
    int64_t damped = nominal + (rw.actual_timespan - nominal) / 8;

    // Per-step clamp rails: [3/4 nominal, 3/2 nominal].
    const int64_t floor_ts = nominal - nominal / 4;
    const int64_t ceil_ts  = nominal + nominal / 2;
    if (damped < floor_ts) damped = floor_ts;
    if (damped > ceil_ts)  damped = ceil_ts;

    // bnNew = avg_target * damped / nominal at full 256-bit width. damped is
    // strictly positive after the clamp (floor_ts > 0 for nominal > 0). The
    // multiply truncates at 256 bits exactly as arith_uint256 does, so a target
    // near pow_limit retargets to the SAME value DigiByte Core computes.
    const u256 bn_new = mul_div_u256(u256::from_u64(rw.avg_target),
                                     static_cast<uint64_t>(damped),
                                     static_cast<uint64_t>(nominal));

    // Difficulty floor: never relax past the network's easiest target.
    if (params.pow_limit != 0 &&
        bn_new > u256::from_u64(params.pow_limit))
        return params.pow_limit;

    // uint64 field proxy: a uint64-range avg keeps bn_new within 64 bits, so
    // low64() is exact (the embedded port returns the full arith_uint256).
    return bn_new.low64();
}

// Work-neutral header chain with a Scrypt-only DigiShield retarget body.
// Append order is oldest..newest; the retarget walk reads nearest-first.
class HeaderChain {
public:
    HeaderChain() = default;

    // Configure the consensus retarget gate: the DigiShield params + the
    // Scrypt-only window depth validate_and_append enforces declared targets
    // against. Default-constructed chains leave target_timespan == 0, which
    // makes digishield_next_target() return 0 and the gate a no-op -- the
    // retarget-window/work-accounting tests run unconstrained, exactly as
    // before this slice.
    HeaderChain(DigiShieldParams ds, std::size_t retarget_window)
        : m_ds_params(ds), m_retarget_window(retarget_window) {}

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
        {
            // PoW validate path. A zero target is not a validatable Scrypt
            // header (the structural guard here is that a malformed target
            // never credits work).
            if (h.target == 0)
                return IngestResult::REJECTED;

            // Minimum-difficulty ceiling (DigiByte Core CheckProofOfWork
            // rejects when bnTarget > bnPowLimit). A declared Scrypt target
            // EASIER (numerically larger) than the network minimum is
            // consensus-invalid REGARDLESS of the retarget window -- this
            // guards the bootstrap/empty-window path (expected == 0) where
            // the nBits-style equality below cannot fire yet, so a stall
            // could not otherwise reject a sub-minimum-difficulty header.
            // pow_limit == 0 leaves the gate unconfigured (legacy
            // default-ctor chains stay unconstrained, exactly as before).
            if (m_ds_params.pow_limit != 0 && h.target > m_ds_params.pow_limit)
                return IngestResult::REJECTED;

            // PoW satisfaction (DigiByte Core CheckProofOfWork second half):
            // the header's scrypt(header) digest must SATISFY its declared
            // target -- hash <= target. A header claiming work it does not meet
            // is consensus-invalid. This is the CONTEXT-FREE PoW check (mirrors
            // `if (UintToArith256(hash) > bnTarget) return false`), run before
            // the contextual nBits-equality gate below. pow_hash == 0 is the
            // standalone proxy for "scrypt(header) not evaluated here" and
            // trivially satisfies any target, so the chain-helper tests stay
            // unconstrained; the embedded-daemon port fills pow_hash with the
            // real Scrypt digest and this gate goes live with the SAME shape.
            if (h.pow_hash > h.target)
                return IngestResult::REJECTED;

            // Consensus retarget gate: the declared target must equal the
            // DigiShield next-target computed over the Scrypt-only window
            // ending at the CURRENT tip (assembled BEFORE h is appended).
            // expected == 0 means no Scrypt ancestor is in range yet
            // (genesis/bootstrap) or the gate is unconfigured -- no retarget
            // constraint is enforceable, so the header passes on its
            // structural (non-zero) target alone. nBits-style exact match
            // mirrors Bitcoin/DigiByte consensus: the header carries the
            // required next-work value, not merely a target it satisfies.
            const RetargetWindow rw = next_retarget_window(m_retarget_window);
            const uint64_t expected = digishield_next_target(rw, m_ds_params);
            if (expected != 0 && h.target != expected)
                return IngestResult::REJECTED;

            m_chain.push_back(h);
            m_cumulative_work += work_from_target(h.target);  // credited
            return IngestResult::VALIDATED_SCRYPT;
        }

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

    DigiShieldParams          m_ds_params{};        // retarget gate params
    std::size_t               m_retarget_window = 0; // Scrypt window depth
    std::vector<HeaderSample> m_chain;          // oldest .. newest
    uint64_t                  m_cumulative_work = 0;
};

} // namespace c2pool::dgb
