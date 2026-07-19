// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// mint_runloop.hpp — DASH run-loop share minting (mint campaign slice 3/3).
//
// The wiring layer between the producer machinery (share_producer.hpp, slice 1;
// share_producer_bind.hpp, slice 2) and the live --run pool: everything the
// main_dash run-loop closures need to
//   (a) serve a stratum coinbase whose bytes ARE the producer share gentx
//       (build_producer_job -> DASHWorkSource::ProducerJob), so a solved header
//       reproduces the exact bytes build_mint_share rebuilds at mint time —
//       byte-parity by construction, not by parallel-implementation parity;
//   (b) freeze the per-job producer context keyed by the ref_hash committed in
//       the coinbase OP_RETURN (FrozenJobRegistry) and look it up at mint time
//       (MintShareInputs.ref_hash, recovered from the coinb1 tail);
//   (c) mint fail-closed: build_mint_share (slice 2, X11 identity gate) PLUS
//       the explicit pow<=share-target guard (mint_from_inputs) so a share
//       whose PoW does not meet its own committed m_bits target can NEVER be
//       inserted/broadcast — the ban-safety line;
//   (d) elect the best share (elect_best_share — the btc::NodeImpl policy,
//       verified-work-first, ported as a pure function so it is KAT-able);
//   (e) walk the tracker for the PPLNS fallback-coinbase weights
//       (pplns_weights_for — ORACLE window: grandparent start, data.py:181).
//
// ORACLE: github.com/frstrtr/p2pool-dash (pre-v35 v16 lineage, min-proto 1700).
// Everything minted here is the LEGACY v16 DashShare the live network speaks —
// the v36 crossing is a SEPARATE later step and is deliberately absent.
//
// Header-only, fenced to src/impl/dash/. Nothing in src/core is touched; the
// dashd-RPC fallback path is untouched.
// ============================================================================

#include "share_producer.hpp"
#include "share_producer_bind.hpp"     // FrozenMintJob, build_mint_share
#include "coinbase_builder.hpp"        // push_bip34_height (BIP34 scriptSig SSOT)
#include "coin/rpc_data.hpp"           // dash::coin::DashWorkData
#include "stratum/work_source.hpp"     // DASHWorkSource::{MintShareInputs, ProducerJob, PplnsWeights}

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace dash::mint {

// ── build_producer_job ───────────────────────────────────────────────────────
//
// Job-time producer pass: assemble the prospective share_info off the live
// chain, compute its ref_hash, and serialize the FULL share gentx (nonce64
// slot zeroed — the stratum extranonce1||extranonce2 slot). The returned
// bytes/offset are what build_connection_coinbase splits into coinb1/coinb2,
// so the coinbase a miner hashes is byte-identical to the gentx the mint-time
// build_mint_share reproduces (same chain anchors, same frozen inputs — all
// producer walks are backward from prev_share_hash and therefore deterministic
// even if the chain has since grown).
//
// desired_target policy: params.max_target. The oracle clips desired into
// [pre_target3/30, pre_target3] (data.py:141-145), so max_target clips to
// pre_target3 — the pool's ACTUAL current share target. Per-miner pseudoshare
// difficulty stays a session/vardiff concern; the share target the mint gate
// enforces is the network one.
struct ProducerJobBuild
{
    dash::stratum::DASHWorkSource::ProducerJob job;   // gentx bytes + split point + ref_hash + bits
    dash::stratum::FrozenMintJob               frozen; // per-job mint context (registry payload)
};

template <typename ChainT>
inline std::optional<ProducerJobBuild> build_producer_job(
    ChainT& chain,
    const core::CoinParams& params,
    const uint256& prev_share_hash,
    const std::vector<unsigned char>& payout_script,
    const dash::coin::DashWorkData& wd,
    uint32_t desired_timestamp,
    uint32_t share_nonce,
    uint16_t donation,
    const std::string& pool_tag)
{
    // Miner identity: DASH sharechain payouts are P2PKH-keyed (share_data
    // pubkey_hash). Non-P2PKH -> no producer job (the caller's non-producer
    // coinbase path still serves work; it just cannot mint).
    auto pubkey_hash = dash::stratum::pubkey_hash_from_p2pkh(payout_script);
    if (!pubkey_hash)
        return std::nullopt;
    if (wd.m_bits == 0 || wd.m_height == 0)
        return std::nullopt;   // no real template -> nothing to commit to

    // share_data['coinbase'] — BIP34 height push + pool tag, capped at the
    // verifier's 100-byte scriptSig bound (oracle work.py packs height+flags
    // and slices [:100]). push_bip34_height is the same SSOT coinbase::build
    // uses, so the share-gentx scriptSig matches dashd's bad-cb-height check.
    std::vector<unsigned char> script_sig = dash::coinbase::push_bip34_height(wd.m_height);
    for (char c : pool_tag) {
        if (script_sig.size() >= 100) break;
        script_sig.push_back(static_cast<unsigned char>(c));
    }
    if (script_sig.size() < 2 || script_sig.size() > 100)
        return std::nullopt;   // verifier bound (share_check) — fail-closed

    dash::producer::ProducerJobInputs pin;
    pin.prev_share_hash    = prev_share_hash;
    pin.coinbase_scriptSig = script_sig;
    pin.coinbase_payload.assign(wd.m_coinbase_payload.begin(), wd.m_coinbase_payload.end());
    pin.share_nonce        = share_nonce;
    pin.pubkey_hash        = *pubkey_hash;
    pin.subsidy            = wd.m_coinbase_value;
    pin.donation           = donation;
    pin.stale_info         = dash::StaleInfo::none;
    pin.desired_version    = 16;                     // LEGACY v16 — the live lineage
    pin.payment_amount     = wd.m_payment_amount;
    for (const auto& p : wd.m_packed_payments) {
        dash::PackedPayment pp;
        pp.m_payee  = p.payee;
        pp.m_amount = p.amount;
        pin.packed_payments.push_back(std::move(pp));
    }
    pin.desired_tx_hashes  = wd.m_tx_hashes;
    pin.desired_timestamp  = desired_timestamp;
    pin.desired_target     = params.max_target;

    auto info = dash::producer::generate_prospective_share_info(chain, params, pin);

    // Cumulative PPLNS weights — the EXACT interior of producer::build_share
    // (oracle window: start at the grandparent, max(0, min(height, RCL)-1)
    // shares, capped at 65535*SPREAD*ata(block_target); data.py:181-184).
    // build_mint_share re-runs this identically at mint time.
    dash::producer::CumulativeWeights weights;
    if (!info.prev_hash.IsNull() && chain.contains(info.prev_hash))
    {
        uint256 grandparent;
        chain.get_share(info.prev_hash).invoke([&](auto* obj) {
            grandparent = obj->m_prev_hash;
        });
        const int32_t height = chain.get_acc_height(info.prev_hash);
        const int32_t max_shares = std::max<int32_t>(
            0, std::min<int32_t>(height, static_cast<int32_t>(params.real_chain_length)) - 1);
        const uint256 block_target = chain::bits_to_target(wd.m_bits);
        const uint288 desired_weight =
            chain::target_to_average_attempts(block_target) * params.spread * 65535u;
        weights = dash::producer::get_cumulative_weights(
            chain, grandparent, max_shares, desired_weight);
    }

    const uint256 ref_hash = dash::producer::compute_ref_hash(params, info);
    dash::producer::GentxResult gentx =
        dash::producer::build_gentx(info, weights, ref_hash, /*last_txout_nonce=*/0, params);

    // nonce64 slot: the OP_RETURN tail is [0x6a 0x28 ref(32) nonce(8)] followed
    // by locktime(4) + optional payload VarStr; build_gentx's prefix_len cuts
    // exactly before the ref_hash, so the nonce slot is prefix_len + 32.
    const size_t nonce_off = gentx.prefix_len + 32;
    if (nonce_off + 8 > gentx.bytes.size())
        return std::nullopt;                             // producer invariant broke
    if (std::memcmp(gentx.bytes.data() + gentx.prefix_len, ref_hash.data(), 32) != 0)
        return std::nullopt;                             // ref not where expected
    for (size_t i = 0; i < 8; ++i)
        if (gentx.bytes[nonce_off + i] != 0x00)
            return std::nullopt;                         // slot must be zeroed

    ProducerJobBuild out;
    out.job.gentx_bytes    = std::move(gentx.bytes);
    out.job.nonce64_offset = nonce_off;
    out.job.ref_hash       = ref_hash;
    out.job.share_bits     = info.bits;
    out.job.share_max_bits = info.max_bits;

    out.frozen.coinbase_scriptSig = std::move(script_sig);
    out.frozen.coinbase_payload   = pin.coinbase_payload;
    out.frozen.share_nonce        = share_nonce;
    out.frozen.donation           = donation;
    out.frozen.desired_version    = 16;
    out.frozen.payment_amount     = pin.payment_amount;
    out.frozen.packed_payments    = pin.packed_payments;
    out.frozen.desired_tx_hashes  = pin.desired_tx_hashes;
    out.frozen.desired_timestamp  = desired_timestamp;
    out.frozen.desired_target     = pin.desired_target;
    out.frozen.last_txout_nonce   = 0;                   // filled at mint from en1||en2
    out.frozen.stale_info         = dash::StaleInfo::none;
    // Freeze the job's share identity: the mint-time rebuild MUST use the
    // exact identity this gentx committed to (see FrozenMintJob note) — with
    // --fee substitution the submit-time username script differs from it.
    out.frozen.payout_script_override = payout_script;
    return out;
}

// ── Node-owner fee + dev fee + redistribute (README flag port) ───────────────
//
// Port of the LTC sharechain-lane semantics (main_ltc.cpp / web_server
// set_node_fee_from_address):
//   --give-author PCT  -> share_data['donation'] = round(65535*PCT/100) — the
//       ORACLE dev-fee channel (p2pool work.py math.perfect_round). PPLNS
//       weights already decay by it (att*(65535-donation)); the donation
//       output is ALWAYS emitted by build_gentx (even at 0 — the dust
//       marker), so --give-author 0 keeps the output present at the
//       remainder-only value. NOTHING here changes the gentx layout.
//   --fee PCT + --node-owner-address -> V36-compatible PROBABILISTIC identity
//       substitution at share-creation: ~PCT% of minted shares carry the node
//       owner's pubkey_hash instead of the miner's, so the owner accumulates
//       PPLNS weight while every peer still computes identical coinbase
//       outputs (consensus-safe — no new output, no format change).
//   --redistribute MODE -> policy for miners whose stratum credentials do not
//       decode to a P2PKH script (DASH shares are pubkey_hash-keyed):
//       fee    -> mint under the node owner's identity;
//       donate -> mint under the node owner's identity with donation=65535
//                 (100% of the share's PPLNS weight decays to the donation
//                 script — the DASH-conform expression of "100% to donation",
//                 since a v16 share MUST carry some pubkey_hash);
//       pplns/boost -> the LTC weighted-redistribution engine is NOT yet
//                 ported to DASH; these decline the producer job (the
//                 pre-existing fail-closed behavior, loudly logged).
struct MintFeePolicy
{
    enum class Redistribute { PPLNS, FEE, BOOST, DONATE };

    uint16_t donation_u16{66};                     // --give-author (default 0.1% -> 66)
    double   node_owner_fee_pct{0.0};              // --fee (0 = off)
    std::vector<unsigned char> node_owner_script;  // --node-owner-address (P2PKH), may be empty
    Redistribute redistribute{Redistribute::PPLNS};

    static Redistribute parse_redistribute(const std::string& s)
    {
        if (s == "fee")    return Redistribute::FEE;
        if (s == "boost")  return Redistribute::BOOST;
        if (s == "donate") return Redistribute::DONATE;
        return Redistribute::PPLNS;
    }
};

// round(65535 * pct / 100), clamped to the u16 field — the oracle's
// math.perfect_round(65535*donation_percentage/100) (p2pool work.py).
inline uint16_t donation_percent_to_u16(double pct)
{
    if (pct <= 0.0)   return 0;
    if (pct >= 100.0) return 65535;
    const double v = 65535.0 * pct / 100.0;
    const uint64_t r = static_cast<uint64_t>(v + 0.5);
    return r > 65535 ? 65535 : static_cast<uint16_t>(r);
}

// The share identity + donation a producer job freezes, after fee policy.
struct ResolvedIdentity
{
    std::vector<unsigned char> payout_script;  // P2PKH the share is keyed on
    uint16_t donation_u16{0};
    bool substituted{false};                   // true when NOT the miner's own
};

// Deterministic core (KAT-able): the caller supplies the fee roll as
// roll_x100 in [0, 10000) — one roll per job build, matching p2pool's
// per-get_work fee roll. Substitution triggers when roll_x100 <
// node_owner_fee_pct*100. Returns nullopt when no P2PKH identity is
// available for this job (mint declines fail-closed).
inline std::optional<ResolvedIdentity> resolve_mint_identity(
    const MintFeePolicy& policy,
    const std::vector<unsigned char>& miner_script,
    uint32_t roll_x100)
{
    const bool miner_ok =
        dash::stratum::pubkey_hash_from_p2pkh(miner_script).has_value();
    const bool owner_ok =
        dash::stratum::pubkey_hash_from_p2pkh(policy.node_owner_script).has_value();

    if (miner_ok) {
        if (policy.node_owner_fee_pct > 0.0 && owner_ok &&
            static_cast<double>(roll_x100) < policy.node_owner_fee_pct * 100.0)
            return ResolvedIdentity{policy.node_owner_script, policy.donation_u16, true};
        return ResolvedIdentity{miner_script, policy.donation_u16, false};
    }

    // Broken/undecodable miner credentials -> redistribute policy.
    switch (policy.redistribute) {
    case MintFeePolicy::Redistribute::FEE:
        if (owner_ok)
            return ResolvedIdentity{policy.node_owner_script, policy.donation_u16, true};
        return std::nullopt;
    case MintFeePolicy::Redistribute::DONATE:
        // 100%-donation share: weight fully decays to the donation script.
        if (owner_ok)
            return ResolvedIdentity{policy.node_owner_script, 65535, true};
        return std::nullopt;
    case MintFeePolicy::Redistribute::PPLNS:
    case MintFeePolicy::Redistribute::BOOST:
    default:
        return std::nullopt;   // weighted redistribution engine: later port
    }
}

// ── FrozenJobRegistry ────────────────────────────────────────────────────────
//
// Bounded ref_hash -> FrozenMintJob store. The ref_hash commits to the ENTIRE
// prospective share_info (miner pubkey_hash included), so it uniquely names
// the job context a solved coinbase belongs to. FIFO-evicted at `capacity`
// (default 512 — comfortably above MAX_ACTIVE_JOBS * sessions on one node);
// a miss at mint time is a fail-closed decline, never a guess.
class FrozenJobRegistry
{
public:
    explicit FrozenJobRegistry(size_t capacity = 512) : m_capacity(capacity) {}

    void put(const uint256& ref_hash, dash::stratum::FrozenMintJob job)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_jobs.find(ref_hash);
        if (it != m_jobs.end()) {
            it->second = std::move(job);   // same ref = same context; refresh
            return;
        }
        m_jobs[ref_hash] = std::move(job);
        m_order.push_back(ref_hash);
        while (m_order.size() > m_capacity) {
            m_jobs.erase(m_order.front());
            m_order.pop_front();
        }
    }

    std::optional<dash::stratum::FrozenMintJob> get(const uint256& ref_hash) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_jobs.find(ref_hash);
        if (it == m_jobs.end())
            return std::nullopt;
        return it->second;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_jobs.size();
    }

private:
    mutable std::mutex m_mutex;
    size_t m_capacity;
    std::map<uint256, dash::stratum::FrozenMintJob> m_jobs;
    std::deque<uint256> m_order;
};

// ── mint_from_inputs ─────────────────────────────────────────────────────────
//
// The mint-time transform: MintShareInputs + the registry-frozen job (with the
// live extranonce nonce64 filled in) -> a fully-built, self-verified BuiltShare.
// TWO fail-closed gates on top of slice 2's X11 identity gate:
//   * build_mint_share declines unless the rebuilt share's m_hash reproduces
//     the miner-solved header PoW exactly (byte-identity);
//   * the pow<=target guard declines a share whose PoW does not meet its OWN
//     committed m_bits target. Without it, a stratum share-bits race (job
//     classified against a stale/easier share target) could mint a share that
//     verifies structurally but fails the oracle's PoW check on peers — a
//     PeerMisbehavingError BAN. This guard is the ban-safety line.
template <typename ChainT>
inline std::optional<dash::producer::BuiltShare> mint_from_inputs(
    ChainT& chain,
    const core::CoinParams& params,
    const dash::stratum::DASHWorkSource::MintShareInputs& in,
    dash::stratum::FrozenMintJob job)
{
    job.last_txout_nonce = in.last_txout_nonce;
    auto built = dash::stratum::build_mint_share(chain, params, in, job);
    if (!built)
        return std::nullopt;

    // Ban-safety: m_hash (== in.pow_hash, X11 of the solved header) must meet
    // the share's own committed target.
    const uint256 share_target = chain::bits_to_target(built->share.m_bits);
    if (share_target.IsNull() || built->share.m_hash > share_target)
        return std::nullopt;

    return built;
}

// ── elect_best_share ─────────────────────────────────────────────────────────
//
// Best-share election policy — the btc::NodeImpl::best_share_hash() body
// (src/impl/btc/node.cpp) ported as a pure function over the tracker so the
// policy is KAT-able and the dash node method is a thin delegate. Mirrors
// p2pool: think()'s best is authoritative WHEN it sits on the verified chain;
// otherwise the heaviest verified head; with peers but no verified chain the
// answer is ZERO (never build work on an unverifiable head — p2pool's
// best_share_var None); a true genesis node (no peers) bootstraps from the
// tallest raw head.
template <typename TrackerT>
inline uint256 elect_best_share(TrackerT& tracker,
                                const uint256& think_best,
                                bool has_peers)
{
    if (!think_best.IsNull() && tracker.verified.contains(think_best))
        return think_best;

    // Heaviest verified head by ACCUMULATED work (tracker view get_work =
    // p2pool get_delta_to_last().work — cumulative from the chain tail; the
    // per-share index.work would mis-elect a short heavy fork).
    if (tracker.verified.size() > 0) {
        uint256 best;
        uint288 best_work;
        bool first = true;
        for (const auto& [head_hash, tail_hash] : tracker.verified.get_heads()) {
            if (!tracker.verified.contains(head_hash))
                continue;
            const uint288 w = tracker.verified.get_work(head_hash);
            if (first || w > best_work) {
                best = head_hash;
                best_work = w;
                first = false;
            }
        }
        if (!best.IsNull())
            return best;
    }

    // Verified chain empty. With peers: refuse (ZERO) — never mint on an
    // unverified foreign chain. Without peers: genesis bootstrap off the
    // tallest raw head.
    if (has_peers)
        return uint256::ZERO;

    if (tracker.chain.size() == 0)
        return uint256::ZERO;

    uint256 best;
    int32_t best_height = -1;
    for (const auto& [head_hash, tail_hash] : tracker.chain.get_heads()) {
        auto h = tracker.chain.get_height(head_hash);
        if (static_cast<int32_t>(h) > best_height) {
            best = head_hash;
            best_height = static_cast<int32_t>(h);
        }
    }
    return best;
}

// ── pplns_weights_for ────────────────────────────────────────────────────────
//
// Tracker walk for the DASHWorkSource PplnsWeights seam — the NON-producer
// (fallback) coinbase path, so a template built while the producer seam is
// busy still pays the live PPLNS window. ORACLE window semantics
// (data.py:181-184): the walk starts at prev's GRANDPARENT with
// max(0, min(height, REAL_CHAIN_LENGTH)-1) shares, capped at
// 65535*SPREAD*ata(block_target).
//
// The seam's weights are uint64; the oracle's are unbounded. A uniform
// right-shift normalizes everything into range when the 288-bit totals exceed
// 63 bits — proportions (and therefore payouts, which divide by total) are
// preserved to within the shift truncation.
//
// ref_hash is ZERO by contract here: the fallback coinbase carries no
// producer commitment, so a solve on it can never look up a frozen job and
// the mint declines — fail-closed by construction (payouts stay correct; only
// the sharechain credit needs the producer path).
template <typename ChainT>
inline std::optional<dash::stratum::DASHWorkSource::PplnsWeights>
pplns_weights_for(ChainT& chain,
                  const core::CoinParams& params,
                  const uint256& prev_share_hash,
                  uint32_t block_bits)
{
    if (prev_share_hash.IsNull() || !chain.contains(prev_share_hash) || block_bits == 0)
        return std::nullopt;

    uint256 grandparent;
    chain.get_share(prev_share_hash).invoke([&](auto* obj) {
        grandparent = obj->m_prev_hash;
    });
    const int32_t height = chain.get_acc_height(prev_share_hash);
    const int32_t max_shares = std::max<int32_t>(
        0, std::min<int32_t>(height, static_cast<int32_t>(params.real_chain_length)) - 1);
    const uint256 block_target = chain::bits_to_target(block_bits);
    const uint288 desired_weight =
        chain::target_to_average_attempts(block_target) * params.spread * 65535u;

    auto w = dash::producer::get_cumulative_weights(
        chain, grandparent, max_shares, desired_weight);
    if (w.total_weight.IsNull())
        return std::nullopt;

    // Normalize 288-bit weights into the seam's uint64 space: uniform shift
    // until the grand total fits in 63 bits.
    unsigned shift = 0;
    {
        uint288 t = w.total_weight;
        uint288 limit;
        limit.SetHex("7fffffffffffffff");   // 2^63 - 1
        while (t > limit) { t = t >> 1; ++shift; }
    }

    dash::stratum::DASHWorkSource::PplnsWeights out;
    out.total_weight = (w.total_weight >> shift).GetLow64();
    if (out.total_weight == 0)
        return std::nullopt;
    for (const auto& [script, weight] : w.weights) {
        const uint64_t v = (weight >> shift).GetLow64();
        if (v > 0)
            out.weights[script] = v;
    }
    out.ref_hash = uint256::ZERO;   // fallback path: no producer commitment
    if (out.weights.empty())
        return std::nullopt;
    return out;
}

} // namespace dash::mint
