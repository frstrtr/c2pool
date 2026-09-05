// SPDX-License-Identifier: AGPL-3.0-or-later
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <optional>
#include <vector>

#include <impl/dgb/coin/dgb_arith256.hpp>
#include <impl/dgb/coin/dgb_block_algo.hpp>
#include <impl/dgb/coin/dgb_digishield.hpp>
#include <impl/dgb/coin/dgb_multishield.hpp>

namespace c2pool::dgb {

using ::dgb::coin::DgbAlgo;
using ::dgb::coin::HeaderDisposition;
using ::dgb::coin::dgb_header_disposition;
using ::dgb::coin::header_credits_work;
using ::dgb::coin::is_scrypt_header;
using ::dgb::coin::mul_div_u256;
using ::dgb::coin::scrypt_window_ancestors;
using ::dgb::coin::u256;
using ::dgb::coin::MsHeader;
using ::dgb::coin::MsAccessor;
using ::dgb::coin::MultiShieldV4Params;
using ::dgb::coin::multishield_v4_next_bits;

// Minimal header sample the Scrypt-only retarget body consumes. The embedded
// DigiByte Core port (M3+) carries the full CBlockHeader; the validate() +
// retarget path needs only the algo bits (disposition + work-credit), the
// timestamp (timespan), the expanded difficulty target (averaging), and the
// scrypt(header) PoW digest (`pow_hash`, the CheckProofOfWork hash <= target
// check). `target` and `pow_hash` are full 256-bit (coin/dgb_arith256.hpp u256)
// as of the field-shape swap: the implicit uint64 widening keeps every
// uint64-range vector byte-identical while the ingest PoW/ceiling checks and the
// DigiShield averaging now run at true arith_uint256 width, so the embedded
// daemon port drops real digests into this SAME field with no reshape. pow_hash
// == 0 is the default for "scrypt(header) not evaluated here" (trivially
// satisfies any target); the daemon port fills it.
struct HeaderSample {
    int32_t  n_version  = 0;
    int64_t  n_time     = 0;
    u256     target     = 0;   // expanded PoW target (smaller == more work)
    u256     pow_hash    = 0;  // scrypt(header) digest; hash <= target == valid PoW
    u256     block_hash  = 0;  // sha256d(header) block id; 0 == not populated here
    // Raw compact nBits, carried verbatim for the MultiShield V4 next-target walk
    // (next_scrypt_bits() -> SetCompact(prevAlgo.nBits)). LAST field so the
    // 19-field positional brace-inits in the tests stay valid (each just omits
    // it, defaulting to 0). make_header_sample fills it from the wire header.
    uint32_t n_bits     = 0;
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
    u256        avg_target      = 0;     // mean expanded target over samples
    int64_t     actual_timespan = 0;     // newest - oldest Scrypt sample time
    bool        sufficient      = false; // true iff the full window was found
};

// DigiShield/MultiShield retarget parameters (per-algo). `target_timespan` is
// the nominal per-block Scrypt solve time the damped filter pulls toward;
// `pow_limit` is the easiest (largest) admissible target -- bnNew is capped to
// it so a long stall can never relax difficulty past the network minimum.
struct DigiShieldParams {
    int64_t  target_timespan = 0;   // nominal solve time the filter centers on
    u256     pow_limit       = 0;   // max (easiest) target; result never exceeds
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
// wider, divergent next target). With the field-shape swap the target/avg_target
// fields ARE arith_uint256 (u256); for any uint64-range avg_target the result is
// bit-identical to the prior __int128 proxy, so existing vectors are unchanged,
// while a >2^64 avg now retargets at full width. The embedded-daemon port reuses
// this exact multiply/clamp ordering with real arith_uint256.
//
// Returns 0 when the window carries no Scrypt samples -- the caller MUST keep
// the prior target rather than retarget off an empty window (early/genesis).
inline u256 digishield_next_target(const RetargetWindow& rw,
                                   const DigiShieldParams& params)
{
    if (rw.scrypt_samples == 0 || params.target_timespan <= 0)
        return u256{};

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
    const u256 bn_new = mul_div_u256(rw.avg_target,
                                     static_cast<uint64_t>(damped),
                                     static_cast<uint64_t>(nominal));

    // Difficulty floor: never relax past the network's easiest target. The cap
    // compare runs at full 256-bit width, so a pow_limit in the high limbs is
    // honoured exactly (a uint64 proxy would mis-decide near 2^64).
    if (!params.pow_limit.is_zero() && bn_new > params.pow_limit)
        return params.pow_limit;

    // Full-width next target (uint64-range inputs leave the high limbs zero, so
    // this is bit-identical to the prior low64() return for existing vectors).
    return bn_new;
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
            if (h.target.is_zero())
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
            if (!m_ds_params.pow_limit.is_zero() && h.target > m_ds_params.pow_limit)
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

            // Parent-difficulty retarget gate: DEMOTED to a no-op for V36
            // (integrator decision 2026-06-18, operator FYI'd). V36's defining
            // constraint is p2pool-merged-v36 compatibility, and that reference
            // NEVER re-derives parent difficulty -- it trusts the parent
            // header's declared nBits and checks PoW against it. The two
            // daemon-independent CheckProofOfWork halves above (pow_limit floor +
            // scrypt(header) <= target) ARE the correct, complete V36
            // parent-difficulty validation.
            //
            // NOTE (#179): the DEMOTED gate is about INGEST-time per-header
            // difficulty VALIDATION, which stays a no-op for p2pool-merged-v36
            // compat. It is NOT the same as computing the next block's target for
            // the SERVED template: the "Scrypt-only walk can't see the 5-algo
            // window" premise is FALSE here, because continuity (non-Scrypt)
            // headers ARE appended (work-neutral) with their target + timestamp +
            // nBits, so the GLOBAL MultiShield V4 averaging window is fully
            // present in m_chain. next_scrypt_bits() (below) reconstructs V4
            // byte-exact from it to stamp the template `bits` (replacing the
            // fabricated 0x1d00ffff). The OLD digishield_next_target() /
            // next_retarget_window() model the WRONG (DigiShield-v3, Scrypt-only-
            // avg) retarget and are retained only as test scaffolding -- the
            // ingest path deliberately does NOT call them, and neither does the
            // served path (which uses the V4 walk instead).

            // MTP monotonicity (DigiByte Core ContextualCheckBlockHeader
            // "time-too-old"): a Scrypt header's nTime must be STRICTLY GREATER
            // than the median timestamp of the tip and its (up to) 10 nearest
            // ancestors. This is the daemon-independent, Scrypt-only-walk-SAFE
            // half of header time validation -- it reads ONLY timestamps already
            // in the local header chain, with no difficulty re-derivation (the
            // demoted V4-MultiShield recompute). It is also the standard
            // anti-timewarp monotonicity floor the demoted nBits gate used to
            // imply. Genesis (empty chain) is unconstrained: median_time_past()
            // returns INT64_MIN, so the first header always passes. A rejection
            // never mutates the chain (checked before push_back).
            if (h.n_time <= median_time_past())
                return IngestResult::REJECTED;

            m_chain.push_back(h);
            m_cumulative_work += work_from_target(h.target);  // credited
            trim_to_window();
            return IngestResult::VALIDATED_SCRYPT;
        }

        case HeaderDisposition::ACCEPT_BY_CONTINUITY:
        default:
            // Extends the header chain; work-neutral (NO m_cumulative_work
            // change) and excluded from the retarget window by construction.
            m_chain.push_back(h);
            trim_to_window();
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

        u256 target_sum;
        for (std::size_t k : idx)
            target_sum += m_chain[depth - 1 - k].target;

        rw.scrypt_samples  = idx.size();
        rw.avg_target      = target_sum.div_u64(static_cast<uint64_t>(idx.size()));
        // idx is nearest-first: front() == newest Scrypt sample (smallest k),
        // back() == oldest. Timespan is over Scrypt samples exclusively.
        rw.actual_timespan = m_chain[depth - 1 - idx.front()].n_time
                           - m_chain[depth - 1 - idx.back()].n_time;
        rw.sufficient      = (idx.size() == window);
        return rw;
    }

    uint64_t    cumulative_work() const { return m_cumulative_work; }
    std::size_t size()            const { return m_chain.size(); }

    // ── Absolute block-height tracking (M3 §4c prerequisite) ────────────────
    // DGB block height counts EVERY block of EVERY algo: one block == one
    // height regardless of Scrypt / SHA256d / Skein / Qubit / Odocrypt. The
    // Scrypt-only HeaderChain still appends non-Scrypt headers via
    // accept-by-continuity (work-neutral but chain-extending), so block height
    // advances on BOTH VALIDATED_SCRYPT and ACCEPTED_CONTINUITY ingests and
    // ONLY those -- a REJECTED header never push_back()s and never advances
    // height (rejection is checked before every push_back above). Height is
    // therefore a pure function of the seed height + appended-header count:
    // index i holds absolute height (m_base_height + i), with no separate
    // mutable counter that could drift from m_chain.
    //
    // The embedded TemplateBuilder port (mirror of btc build_template) reads
    // next_block_height() for the coinbase BIP34 height push and the
    // subsidy_func(height) lookup that feeds embedded_coinbase_value (#207).
    // External-daemon GBT still carries its own authoritative "height"; this
    // accessor is the embedded-path source for the SAME field.

    // Absolute height assigned to m_chain[0] (the seed/genesis or checkpoint
    // header). Default 0 == sync-from-genesis; set_base_height() seeds a
    // fast-start checkpoint before the first append.
    uint32_t base_height() const { return m_base_height; }

    // Seed the absolute height of the FIRST appended header. Must be called
    // while the chain is still empty (a checkpoint fast-start); a no-op call
    // order otherwise would silently mis-number live headers.
    void set_base_height(uint32_t h) { m_base_height = h; }

    // Absolute height of the newest header, or nullopt for an empty chain.
    std::optional<uint32_t> tip_height() const
    {
        if (m_chain.empty())
            return std::nullopt;
        return static_cast<uint32_t>(m_base_height + (m_chain.size() - 1));
    }

    // Block hash of the newest header, or nullopt when the chain is empty OR
    // the tip carries no hash. DGB's block id is sha256d over the 80-byte
    // header (params.hpp block_hash_func == sha256d) -- distinct from pow_hash,
    // which is the scrypt(header) PoW digest. HeaderSample stores it as a u256
    // and the work-template emitter renders the GBT-conventional big-endian
    // display hex. block_hash == 0 is the "not populated here" sentinel (the
    // SAME convention pow_hash uses): the embedded-daemon header-ingest port
    // fills it at the validate_and_append boundary, so until that lands this
    // returns nullopt and get_current_work_template holds previousblockhash
    // back -- a truthful absence, never a fabricated hash.
    std::optional<u256> tip_hash() const
    {
        if (m_chain.empty() || m_chain.back().block_hash.is_zero())
            return std::nullopt;
        return m_chain.back().block_hash;
    }

    // Absolute height of the block the next template builds on top of the tip
    // == tip_height()+1, or m_base_height for an empty chain. This is the
    // template builder's `next_h` (btc template_builder.hpp: tip.height + 1).
    uint32_t next_block_height() const
    {
        return static_cast<uint32_t>(m_base_height + m_chain.size());
    }

    // Bitcoin/DigiByte median-time-past span (ContextualCheckBlockHeader uses
    // the tip + its 10 nearest ancestors == 11 timestamps).
    static constexpr std::size_t MEDIAN_TIME_SPAN = 11;

    // ── Rolling in-memory window bound (RSS plateau) ────────────────────────
    // DigiByte's ~15 s block time makes this the fastest-growing embedded
    // HeaderChain in the fleet: sync-from-genesis accumulates the ENTIRE ~24 M
    // header history in RAM (~112 B/HeaderSample × 24.1 M ≈ 2.7 GB resident,
    // the single largest memory consumer on the voidbind host and an OOM on a
    // no-swap box). Nothing in this class needs the full history: the only
    // consumers that index into m_chain read the TAIL —
    //   * median_time_past()      -> last MEDIAN_TIME_SPAN (11) headers,
    //   * next_retarget_window(w)  -> last `w` SCRYPT ancestors (retarget
    //                                 scaffolding; w == 0 / disabled on the live
    //                                 default-constructed chain),
    //   * tip_hash() / tip_height() / next_block_height() -> back()/size().
    // Absolute height is a pure function of base + index, and cumulative_work is
    // a running scalar, so the chain can drop headers OLDER than a bounded
    // window without changing ANY observable value: on eviction we pop_front()
    // and bump m_base_height by the same count, leaving tip_height(),
    // next_block_height() and cumulative_work() bit-identical while RAM
    // plateaus. This mirrors the BTC lane's bounded working set
    // (src/impl/btc/coin/header_chain.hpp HEADER_CACHE_CAP LRU) adapted to DGB's
    // positional, hash-keyless, reorg-free structure — a rolling tail window is
    // the DGB-appropriate form of the same "bounded RAM + trusted checkpoint of
    // older headers" bound.
    //
    // The cap must comfortably exceed every tail consumer AND any legal reorg
    // depth. 16384 headers ≈ 2.8 days of DGB blocks — vastly beyond the 11-wide
    // MTP window, beyond any DigiShield retarget window, and beyond the minutes-
    // scale finality a legal reorg could reach; the daemon-independent PoW/MTP
    // gates a header ingest runs are all context-free or tail-local, so a header
    // dropped below the window is never needed to validate the tip or a
    // fork the chain could switch to. At 16384 × 112 B ≈ 1.8 MB the header
    // subsystem's RSS is bounded regardless of chain height. Retained headers
    // never exceed CAP + 1 transiently (one push_back before one pop_front).
    static constexpr std::size_t HEADER_WINDOW_CAP = 16384;

    // MedianTimePast: median nTime over the tip and its (up to) MEDIAN_TIME_SPAN
    // nearest ancestors. Walks ALL appended headers regardless of algo --
    // DigiByte Core's GetMedianTimePast walks the block index, which interleaves
    // every algo, so continuity (non-Scrypt) headers DO contribute their
    // timestamps to the median even though their PoW is never validated. Sorts a
    // small fixed-size (<= 11) window and returns the upper-middle element
    // (sorted[n/2]), matching DGB Core. Returns INT64_MIN for an empty chain so
    // the genesis header is unconstrained.
    int64_t median_time_past() const
    {
        if (m_chain.empty())
            return std::numeric_limits<int64_t>::min();
        const std::size_t n = std::min(m_chain.size(), MEDIAN_TIME_SPAN);
        std::vector<int64_t> times;
        times.reserve(n);
        for (std::size_t i = 0; i < n; ++i)
            times.push_back(m_chain[m_chain.size() - 1 - i].n_time);
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

    // Next block's Scrypt nBits via DigiByte-Core MultiShield V4, derived from
    // the synced header window (coin/dgb_multishield.hpp). This is the SERVED
    // target the daemonless work source stamps into the block-template `bits`
    // field, replacing the fabricated diff-1 (0x1d00ffff) that made every won
    // block INVALID (#179). It reconstructs the GLOBAL 5-algo V4 window the
    // header chain now carries in full -- continuity (non-Scrypt) headers are
    // appended with their target + timestamp + nBits, so the 50-block averaging
    // window and the nearest-Scrypt-ancestor base target are both present.
    //
    // Returns nullopt when the local window is too shallow (< 61 headers: the
    // 50-back pindexFirst plus its 10-ancestor MedianTimePast) or holds no Scrypt
    // ancestor -- a TRUTHFUL absence the caller turns into "hold work / wait for
    // sync", never a fabricated target. Distinct from the demoted parent-difficulty
    // INGEST gate above (which stays a no-op, per p2pool-merged-v36 compat): this
    // is the forward, template-emit direction, not a per-header validation.
    std::optional<uint32_t> next_scrypt_bits() const
    {
        const std::size_t depth = m_chain.size();
        if (depth == 0)
            return std::nullopt;
        // Nearest-first accessor into the rolling window: k == 0 is the tip.
        const MsAccessor at = [this, depth](std::size_t k) -> MsHeader {
            const HeaderSample& s = m_chain[depth - 1 - k];
            return MsHeader{ s.n_version, s.n_bits, s.n_time };
        };
        return multishield_v4_next_bits(at, depth, MultiShieldV4Params{},
                                        ::dgb::coin::DgbAlgo::SCRYPT);
    }

private:
    // Drop headers older than HEADER_WINDOW_CAP so RAM plateaus regardless of
    // chain height. Popping the front and advancing m_base_height by the same
    // count is height-neutral: tip_height() == m_base_height + size() - 1 and
    // next_block_height() == m_base_height + size() are both invariant across a
    // pop_front()+(++m_base_height). cumulative_work is a monotone running
    // scalar (total work ever credited, never consumed by a V36 consensus
    // path), so it is deliberately NOT decremented for an evicted header. Called
    // after every push_back, so at most one eviction fires per append; the while
    // loop is defensive should the cap ever be lowered at runtime.
    void trim_to_window()
    {
        while (m_chain.size() > HEADER_WINDOW_CAP) {
            m_chain.pop_front();
            ++m_base_height;
        }
    }

    // Work proxy: inversely proportional to the target. The full-width field
    // narrows to low64() for the proxy, keeping cumulative_work byte-identical
    // for every uint64-range vector; the embedded port swaps in arith_uint256
    // work() (2^256 / (target+1)) over the same Scrypt-only credit path.
    static uint64_t work_from_target(const u256& target)
    {
        // Crude uint64 work proxy: UINT64_MAX / low64(target). DELIBERATELY a
        // proxy -- cumulative_work is internal bookkeeping NOT consumed by any
        // V36 consensus path (the parent-difficulty retarget gate is demoted to
        // a no-op; PPLNS scores shares, not header work). A REAL difficulty
        // header has its significant bits high in the 256-bit word, so its low
        // 64 bits are ZERO (e.g. genesis target ~2^224, low64()==0) -- dividing
        // by that is an integer div-by-zero (SIGFPE). Guard it: an
        // unrepresentable-in-uint64 target credits 0 proxy work rather than
        // crashing the live ingest path. The true 2^256/(target+1) work
        // computation lands at the embedded-daemon work-accounting boundary
        // alongside the scrypt(header)->pow_hash fill (same V37 deferral).
        if (target.is_zero() || target.low64() == 0)
            return 0;
        return UINT64_MAX / target.low64();
    }

    DigiShieldParams          m_ds_params{};        // retarget gate params
    uint32_t                  m_base_height = 0;   // abs height of m_chain[0]
    std::size_t               m_retarget_window = 0; // Scrypt window depth
    // Bounded rolling window, oldest .. newest (front == m_base_height). A
    // std::deque gives O(1) pop_front() for eviction (trim_to_window); every
    // access here is positional / back() / size(), all O(1) on a deque, so the
    // container swap from std::vector is behaviour-preserving for consumers.
    std::deque<HeaderSample>  m_chain;          // oldest .. newest (<= CAP)
    uint64_t                  m_cumulative_work = 0;
};

} // namespace c2pool::dgb