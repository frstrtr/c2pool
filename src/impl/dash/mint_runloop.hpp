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
// The public network mints the LEGACY v16 DashShare the live network speaks.
// The private/isolated DASH v36 sharechain (custom --network-id; CoinParams::
// current_share_version == 36) mints DashV36Share through the v36 arm of the
// same functions (build_producer_job, mint_from_inputs_any). A v36 share
// commits the template's transactions through the coinbase merkle_link (the
// branch from the coinbase to the header merkle root); the finder assembles the
// full block from its frozen job (FrozenMintJob::tx_data_hex).
//
// Header-only, fenced to src/impl/dash/. Nothing in src/core is touched; the
// dashd-RPC fallback path is untouched.
// ============================================================================

#include "share_producer.hpp"
#include "share_producer_bind.hpp"     // FrozenMintJob, build_mint_share
#include "coinbase_builder.hpp"        // build_coinbase_scriptsig (BIP34 + coinbase-text SSOT)
#include "coin/rpc_data.hpp"           // dash::coin::DashWorkData
#include "stratum/work_source.hpp"     // DASHWorkSource::{MintShareInputs, ProducerJob, PplnsWeights}
#include "stratum/work_target.hpp"     // dash::stratum::modulate_desired_share_target (Cap 1)

#include <core/author_fee.hpp>
#include <core/coin_params.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <core/log.hpp>
#include <core/version_gate.hpp>

#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
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
// desired_target policy: the ORACLE per-miner modulation (work.py:308-312),
// Cap 1 only — the 1.67% pool-share cap:
//
//   desired = 2**256-1
//   desired = min(desired, average_attempts_to_target(
//                              local_hash_rate * SHARE_PERIOD / 0.0167))
//   desired = min(desired, params.max_target)      <- c2pool ceiling, unchanged
//
// and then generate_prospective_share_info -> compute_share_target clips it
// into the chain band [pre_target3//30, pre_target3] (data.py:141-145). The
// band clip is applied LAST and is the ONLY thing that reaches the share's
// committed m_bits, so a modulated desired can never leave the range canonical
// peers' check() accepts: too easy -> pre_target3, too hard -> pre_target3//30.
//
// local_hash_rate == 0 (fresh start, no measured pseudoshares, non-P2PKH
// credentials, stratum server down) degrades to "no meaningful cap": Cap 1 is
// a no-op, desired == params.max_target, i.e. BIT-IDENTICAL to the pre-cap
// behaviour (max_target >= pre_target3 always clips to pre_target3 -- the
// pool's current share target).
//
// Cap 2 (the dust-threshold EASE, work.py:317-326) is deliberately NOT wired
// here: it needs a pool-attempts-per-second estimate at job time and only ever
// makes the target EASIER, i.e. it cannot mitigate the over-minting this cap
// addresses. work_target.hpp carries it for the later port.
//
// Per-miner pseudoshare (vardiff) difficulty stays a session concern and is
// untouched; the share target the mint gate enforces is the modulated one.
struct ProducerJobBuild
{
    dash::stratum::DASHWorkSource::ProducerJob job;   // gentx bytes + split point + ref_hash + bits
    dash::stratum::FrozenMintJob               frozen; // per-job mint context (registry payload)
};

// desired_share_target — the pre-clip desired target a producer job commits to.
// Pure (KAT-able): oracle Cap 1 over the coin's SHARE_PERIOD, then floored by
// the c2pool max_target ceiling so the local_hash_rate == 0 path reproduces the
// pre-cap value EXACTLY. compute_share_target applies the [pre_target3//30,
// pre_target3] band afterwards; nothing here can escape it.
inline uint256 desired_share_target(const core::CoinParams& params,
                                    double local_hash_rate)
{
    dash::stratum::WorkTargetInputs wt;
    wt.local_hash_rate = local_hash_rate;
    wt.share_period    = static_cast<uint32_t>(params.share_period);
    wt.dust_gate       = false;   // Cap 2 not wired (see the note above)

    uint256 desired = dash::stratum::modulate_desired_share_target(wt);
    if (params.max_target < desired)
        desired = params.max_target;
    return desired;
}

// shared_template_bodies — ONE body vector per template, shared by every frozen
// job built over it. build_producer_job runs once per (payout, template); the
// FrozenJobRegistry keeps up to 512 jobs, so a per-job copy of a full template's
// hex would pin 512 copies of the same bodies. The memo keys on the template's
// complete tx hash list (a txid is the hash of its body, so equal lists mean
// equal bodies) and holds only weak_ptrs: it never extends a body vector's life
// past the last frozen job that references it. Thread-safe (stratum sessions
// build producer jobs concurrently).
class TemplateBodiesMemo
{
public:
    std::shared_ptr<const std::vector<std::string>>
    get(const dash::coin::DashWorkData& wd)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        for (auto it = m_slots.begin(); it != m_slots.end();) {
            auto sp = it->bodies.lock();
            if (!sp) { it = m_slots.erase(it); continue; }
            if (it->tx_hashes == wd.m_tx_hashes && sp->size() == wd.m_tx_data_hex.size())
                return sp;
            ++it;
        }
        auto sp = std::make_shared<const std::vector<std::string>>(wd.m_tx_data_hex);
        m_slots.push_back(Slot{wd.m_tx_hashes, sp});
        while (m_slots.size() > kSlots) m_slots.pop_front();
        return sp;
    }

    std::size_t live_slots()
    {
        std::lock_guard<std::mutex> lk(m_mu);
        std::size_t n = 0;
        for (const auto& s : m_slots) n += s.bodies.expired() ? 0 : 1;
        return n;
    }

    static TemplateBodiesMemo& instance()
    {
        static TemplateBodiesMemo m;
        return m;
    }

private:
    static constexpr std::size_t kSlots = 8;   // a few templates overlap at a tip change
    struct Slot
    {
        std::vector<uint256>                          tx_hashes;
        std::weak_ptr<const std::vector<std::string>> bodies;
    };
    std::mutex       m_mu;
    std::deque<Slot> m_slots;
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
    const std::string& coinbase_text,
    double local_hash_rate = 0.0,
    const std::vector<unsigned char>& message_data = {},
    dash::StaleInfo stale_info = dash::StaleInfo::none)
{
    const bool v36 = core::version_gate::is_v36_active(params.current_share_version);
    if (v36 && wd.m_tx_data_hex.size() != wd.m_tx_hashes.size()) {
        // The DASH v36 network commits the template's transactions through the
        // coinbase merkle_link and the finder assembles the won block from the
        // bodies frozen with this job. A template whose bodies do not match its
        // tx hash list could never be assembled: decline the producer job
        // (fail-closed); the non-producer coinbase still serves work.
        static int v36_tx_log = 0;
        if (v36_tx_log++ % 50 == 0)
            LOG_ERROR << "[MINT] v36 producer job declined: the work template carries "
                      << wd.m_tx_hashes.size() << " transaction hash(es) but "
                      << wd.m_tx_data_hex.size()
                      << " body(ies) -- the won block could not be assembled";
        return std::nullopt;
    }

    // Miner identity: DASH sharechain payouts are P2PKH-keyed (share_data
    // pubkey_hash). Non-P2PKH -> no producer job (the caller's non-producer
    // coinbase path still serves work; it just cannot mint).
    auto pubkey_hash = dash::stratum::pubkey_hash_from_p2pkh(payout_script);
    if (!pubkey_hash)
        return std::nullopt;
    if (wd.m_bits == 0 || wd.m_height == 0)
        return std::nullopt;   // no real template -> nothing to commit to

    // share_data['coinbase'] — BIP34 height push + the pool's coinbase text
    // (default "/P2Pool-DASH/c2pool/"), capped at the verifier's 100-byte
    // scriptSig bound (oracle work.py packs height+flags+COINBASEEXT and slices
    // [:100]). build_coinbase_scriptsig is the SHARED SSOT coinbase::build uses, so
    // this share-gentx scriptSig is byte-identical to the block coinbase served
    // over stratum (a divergence here would make the node self-reject its own
    // shares) and still carries dashd's bad-cb-height BIP34 prefix first.
    std::vector<unsigned char> script_sig =
        dash::coinbase::build_coinbase_scriptsig(wd.m_height, coinbase_text, params.is_testnet);
    if (script_sig.size() < 2 ||
        script_sig.size() > dash::coinbase::MAX_SCRIPTSIG_LEN)
        return std::nullopt;   // verifier bound (share_check) — fail-closed

    dash::producer::ProducerJobInputs pin;
    pin.prev_share_hash    = prev_share_hash;
    pin.coinbase_scriptSig = script_sig;
    pin.coinbase_payload.assign(wd.m_coinbase_payload.begin(), wd.m_coinbase_payload.end());
    pin.share_nonce        = share_nonce;
    pin.pubkey_hash        = *pubkey_hash;
    pin.subsidy            = wd.m_coinbase_value;
    pin.donation           = donation;
    // The node's own orphan/DOA report (stale_report.hpp next_stale_info),
    // decided at job time and committed in this job's ref_hash, as the
    // oracle's get_work does (p2pool-dash work.py:345-349). Default none.
    pin.stale_info         = stale_info;
    pin.desired_version    = params.current_share_version;   // 16 public; 36 isolated
    pin.payment_amount     = wd.m_payment_amount;
    for (const auto& p : wd.m_packed_payments) {
        dash::PackedPayment pp;
        pp.m_payee  = p.payee;
        pp.m_amount = p.amount;
        pin.packed_payments.push_back(std::move(pp));
    }
    pin.desired_tx_hashes  = wd.m_tx_hashes;
    pin.desired_timestamp  = desired_timestamp;
    pin.desired_target     = desired_share_target(params, local_hash_rate);
    if (v36)
        pin.message_data   = message_data;           // v16 has no message_data field

    auto info = dash::producer::generate_prospective_share_info(chain, params, pin);

    // Gentx bytes, split point and ref_hash for the share type this chain mints.
    std::vector<unsigned char> gentx_bytes;
    size_t prefix_len = 0;
    uint256 ref_hash;
    if (v36) {
        // v36 arm: the ref_hash over the populated share fields (the verifier's
        // one v36 ref builder), then the coinbase over the v36 window from the
        // parent — exactly what build_share_v36 reproduces at mint time.
        DashV36Share carrier;
        dash::producer::populate_v36_share(carrier, info, /*last_txout_nonce=*/0);
        ref_hash = dash::producer::compute_ref_hash(params, carrier);
        dash::CumulativeWeights w;
        try {
            w = dash::v36_pplns_window(chain, info.prev_hash);
        } catch (const std::exception&) {
            return std::nullopt;   // unrooted short chain: fail-closed until it roots
        }
        auto gentx = dash::producer::build_gentx_v36(info, w, ref_hash,
                                                     /*last_txout_nonce=*/0, params);
        gentx_bytes = std::move(gentx.bytes);
        prefix_len  = gentx.prefix_len;
    } else {
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

        ref_hash = dash::producer::compute_ref_hash(params, info);
        dash::producer::GentxResult gentx =
            dash::producer::build_gentx(info, weights, ref_hash, /*last_txout_nonce=*/0, params);
        gentx_bytes = std::move(gentx.bytes);
        prefix_len  = gentx.prefix_len;
    }

    // nonce64 slot: the OP_RETURN tail is [0x6a 0x28 ref(32) nonce(8)] followed
    // by locktime(4) + optional payload VarStr; build_gentx's (and
    // build_gentx_v36's, same contract) prefix_len cuts exactly before the
    // ref_hash, so the nonce slot is prefix_len + 32.
    const size_t nonce_off = prefix_len + 32;
    if (nonce_off + 8 > gentx_bytes.size())
        return std::nullopt;                             // producer invariant broke
    if (std::memcmp(gentx_bytes.data() + prefix_len, ref_hash.data(), 32) != 0)
        return std::nullopt;                             // ref not where expected
    for (size_t i = 0; i < 8; ++i)
        if (gentx_bytes[nonce_off + i] != 0x00)
            return std::nullopt;                         // slot must be zeroed

    ProducerJobBuild out;
    out.job.gentx_bytes    = std::move(gentx_bytes);
    out.job.nonce64_offset = nonce_off;
    out.job.ref_hash       = ref_hash;
    out.job.share_bits     = info.bits;
    out.job.share_max_bits = info.max_bits;

    out.frozen.coinbase_scriptSig = std::move(script_sig);
    out.frozen.coinbase_payload   = pin.coinbase_payload;
    out.frozen.share_nonce        = share_nonce;
    out.frozen.donation           = donation;
    out.frozen.desired_version    = params.current_share_version;
    out.frozen.payment_amount     = pin.payment_amount;
    out.frozen.packed_payments    = pin.packed_payments;
    out.frozen.desired_tx_hashes  = pin.desired_tx_hashes;
    out.frozen.desired_timestamp  = desired_timestamp;
    out.frozen.desired_target     = pin.desired_target;
    out.frozen.last_txout_nonce   = 0;                   // filled at mint from en1||en2
    out.frozen.stale_info         = stale_info;         // the rebuild reuses the committed byte
    // Freeze the job's share identity: the mint-time rebuild MUST use the
    // exact identity this gentx committed to (see FrozenMintJob note) — with
    // --fee substitution the submit-time username script differs from it.
    out.frozen.payout_script_override = payout_script;
    out.frozen.message_data       = pin.message_data;    // committed in ref_hash (v36)
    // v36: the template's tx bodies (template order, parallel to
    // desired_tx_hashes) -- the finder assembles the won block from them
    // (coin/reconstruct_won_block.hpp). Null on v16 and on coinbase-only jobs.
    if (v36 && !wd.m_tx_hashes.empty())
        out.frozen.tx_data_hex = TemplateBodiesMemo::instance().get(wd);
    return out;
}

// ── select_embed_blob ────────────────────────────────────────────────────────
//
// The operator message blob (--message-blob-hex) goes into the message_data of
// locally minted shares ONLY where the chain's share type carries the field
// (v36: the private/isolated DASH v36 sharechain) AND the blob validates
// against THAT chain's message authority (share_check.hpp
// active_message_authority(): the maintainer key alone on the isolated chain).
// The startup check in main_dash.cpp validates against the public 2-key set,
// which a blob keyed to the other authority key passes; embedding such a blob
// would make every minted share fail its own v36 verifier (message_data is
// validated in share_init_verify), i.e. the node would orphan its own shares.
// Here it is not embedded: the result is empty (and `why` says why), shares
// mint with empty message_data. On the public profile the result is always
// empty (v16 has no message_data field).
inline std::vector<unsigned char> select_embed_blob(
    const std::vector<unsigned char>& blob,
    const SharechainConfig::ShareProfile& prof,
    std::span<const AuthorityPubkey* const> keys,
    std::string* why = nullptr)
{
    auto reject = [&](std::string reason) {
        if (why) *why = std::move(reason);
        return std::vector<unsigned char>{};
    };
    if (blob.empty())
        return reject("no operator message blob");
    if (!core::version_gate::is_v36_active(prof.target_share_version))
        return reject("this sharechain mints v" + std::to_string(prof.target_share_version) +
                      " shares, which carry no message_data");
    if (blob.size() > MAX_MESSAGE_DATA_WIRE_BYTES)
        return reject("blob exceeds MAX_MESSAGE_DATA_WIRE_BYTES ("
                      + std::to_string(blob.size()) + " > "
                      + std::to_string(MAX_MESSAGE_DATA_WIRE_BYTES) + ")");
    const std::string err = validate_message_data(blob, keys);
    if (!err.empty())
        return reject("blob does not validate against this sharechain's message authority: " + err);
    if (why) why->clear();
    return blob;
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
// SSOT hoisted to core::donation_percent_to_u16 (src/core/author_fee.hpp) so
// all lanes share one formula; this thin forwarder keeps existing
// dash::mint::donation_percent_to_u16 callers working.
inline uint16_t donation_percent_to_u16(double pct)
{
    return core::donation_percent_to_u16(pct);
}

// The share identity + donation a producer job freezes, after fee policy.
struct ResolvedIdentity
{
    std::vector<unsigned char> payout_script;  // P2PKH the share is keyed on
    uint16_t donation_u16{0};
    bool substituted{false};                   // true when NOT the miner's own
};

// ── weighted redistribution engine (pplns / boost) ───────────────────────────
//
// Port of the LTC Redistributor selection semantics (src/impl/ltc/
// redistribute.hpp: pick_pplns :416-438, pick_boost :306-414) into the DASH
// mint path. This is a LOCAL, consensus-NEUTRAL choice of which payout script a
// broken-credential share is minted under — the DASH analogue of p2pool's
// address fallback ("-f"): it only decides whose PPLNS weight THIS node's share
// carries. Every peer still recomputes identical coinbase outputs from each
// share's recorded m_pubkey_hash (dash::pplns::compute_payouts), so nothing
// here touches DIP4 CbTx / merkleRootMNList / quorum commitments / block
// validity. It is the same share-identity field the --fee path substitutes.
//
// The candidate weights are gathered from the SAME oracle window the DASH
// payout uses (get_cumulative_weights via pplns_weights_for below), keyed by
// scriptPubKey, so redistribution is proportional to real accrued PPLNS weight.
struct WeightedCandidate
{
    std::vector<unsigned char> payout_script;  // P2PKH scriptPubKey
    uint64_t                   weight{0};      // accrued PPLNS weight (oracle window)
};

// Bundle of the impure inputs the pplns/boost arms need. Default-constructed
// (all empty) preserves the pre-port fail-closed decline: an empty candidate
// set (cold chain) yields nullopt, exactly the historical genesis behaviour.
struct RedistributeInputs
{
    std::vector<WeightedCandidate>              candidates;  // pplns weights, oracle window
    std::vector<std::vector<unsigned char>>     connected;   // boost: live-rate miner scripts
    uint64_t                                    pplns_roll{0};      // weighted-random draw
    uint64_t                                    boost_zero_roll{0}; // zero-share pick draw
};

// Pure deterministic selector (KAT surface) — the cumulative weighted-random
// walk of ltc::Redistributor::pick_pplns (redistribute.hpp:428-437). `roll` is
// reduced modulo the grand total, then the entry whose cumulative band it lands
// in is returned. Empty or all-zero-weight -> nullopt (caller fails closed).
inline std::optional<std::vector<unsigned char>> select_weighted(
    const std::vector<WeightedCandidate>& cands, uint64_t roll)
{
    uint64_t total = 0;
    for (const auto& c : cands) total += c.weight;
    if (total == 0)
        return std::nullopt;
    const uint64_t r = roll % total;
    uint64_t cumulative = 0;
    for (const auto& c : cands) {
        cumulative += c.weight;
        if (r < cumulative)
            return c.payout_script;
    }
    return cands.back().payout_script;
}

// Pure boost selector — mirrors ltc::Redistributor::pick_boost's V1 zero-share
// arm + pplns final fallback (redistribute.hpp:393-414). A currently-connected
// miner (live pseudoshare rate this window) that carries ZERO pplns weight is
// "boosted": picked uniformly so it starts accruing. When every connected miner
// already has weight (or none are connected), fall through to the weighted
// pplns selector — i.e. boost degrades to pplns exactly as LTC does at runtime
// (its V2 graduated path is never wired). Consensus-neutral, like select_weighted.
inline std::optional<std::vector<unsigned char>> select_boost(
    const std::vector<WeightedCandidate>& pplns_cands,
    const std::vector<std::vector<unsigned char>>& connected_scripts,
    uint64_t zero_roll,
    uint64_t pplns_roll)
{
    if (!connected_scripts.empty()) {
        std::set<std::vector<unsigned char>> have;
        for (const auto& c : pplns_cands)
            if (c.weight > 0)
                have.insert(c.payout_script);
        std::vector<std::vector<unsigned char>> zero_miners;
        for (const auto& s : connected_scripts)
            if (!s.empty() && have.find(s) == have.end())
                zero_miners.push_back(s);
        if (!zero_miners.empty())
            return zero_miners[zero_roll % zero_miners.size()];
    }
    return select_weighted(pplns_cands, pplns_roll);
}

// Deterministic core (KAT-able): the caller supplies the fee roll as
// roll_x100 in [0, 10000) — one roll per job build, matching p2pool's
// per-get_work fee roll. Substitution triggers when roll_x100 <
// node_owner_fee_pct*100. Returns nullopt when no P2PKH identity is
// available for this job (mint declines fail-closed).
inline std::optional<ResolvedIdentity> resolve_mint_identity(
    const MintFeePolicy& policy,
    const std::vector<unsigned char>& miner_script,
    uint32_t roll_x100,
    const RedistributeInputs& redistribute = {})
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
    default: {
        // Weighted-random over the accrued PPLNS window (ltc pick_pplns). Empty
        // window (cold chain) -> decline, preserving the fail-closed genesis
        // behaviour. donation_u16 is the normal dev-fee decay, as the fee arm.
        auto script = select_weighted(redistribute.candidates,
                                      redistribute.pplns_roll);
        if (script)
            return ResolvedIdentity{*script, policy.donation_u16, true};
        return std::nullopt;
    }
    case MintFeePolicy::Redistribute::BOOST: {
        // Zero-share boost, else pplns fallback (ltc pick_boost V1 + final).
        auto script = select_boost(redistribute.candidates,
                                   redistribute.connected,
                                   redistribute.boost_zero_roll,
                                   redistribute.pplns_roll);
        if (script)
            return ResolvedIdentity{*script, policy.donation_u16, true};
        return std::nullopt;
    }
    }
}

// ── FrozenJobRegistry ────────────────────────────────────────────────────────
//
// Bounded ref_hash -> FrozenMintJob store. The ref_hash commits to the ENTIRE
// prospective share_info (miner pubkey_hash included), so it uniquely names
// the job context a solved coinbase belongs to. FIFO-evicted at `capacity`
// (default 512 — comfortably above MAX_ACTIVE_JOBS * sessions on one node);
// a miss at mint time is a fail-closed decline, never a guess.
// On the DASH v36 network the ref_hash does not cover the template's tx set
// (the share carries no tx refs; the set is committed by the coinbase
// merkle_link instead). Every producer build draws a fresh random share nonce,
// so two tx sets never share a ref in practice, and both consumers re-check the
// set anyway: the mint's X11 identity gate (the rebuilt merkle_link must
// reproduce the solved header) and the finder's block assembly
// (v36_finder_block_bodies: the frozen hashes must fold to the share's link).
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

// ── mint_from_inputs_any ─────────────────────────────────────────────────────
//
// mint_from_inputs for the share type this chain mints (params.
// current_share_version: v16 public, v36 private/isolated): the same X11
// identity gate (build_mint_share_any) and the same pow<=committed-target
// ban-safety guard. `message_authority` defaults to the production set.
template <typename ChainT>
inline std::optional<dash::stratum::MintedShare> mint_from_inputs_any(
    ChainT& chain,
    const core::CoinParams& params,
    const dash::stratum::DASHWorkSource::MintShareInputs& in,
    dash::stratum::FrozenMintJob job,
    std::span<const AuthorityPubkey* const> message_authority = active_message_authority())
{
    job.last_txout_nonce = in.last_txout_nonce;
    auto built = dash::stratum::build_mint_share_any(chain, params, in, job, message_authority);
    if (!built)
        return std::nullopt;

    const uint256 share_target = chain::bits_to_target(built->bits());
    if (share_target.IsNull() || built->hash() > share_target)
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
//
// v36 (the private/isolated DASH v36 sharechain, params.current_share_version
// 36): the v36 window from the parent (pplns_v36.hpp v36_pplns_window, the
// rule the v36 stratum coinbase arm and every v36 share commit to), normalized
// the same way; an unrooted short chain (the window's depth guard throws)
// yields nullopt, like an empty window.
template <typename ChainT>
inline std::optional<dash::stratum::DASHWorkSource::PplnsWeights>
pplns_weights_for(ChainT& chain,
                  const core::CoinParams& params,
                  const uint256& prev_share_hash,
                  uint32_t block_bits)
{
    if (prev_share_hash.IsNull() || !chain.contains(prev_share_hash) || block_bits == 0)
        return std::nullopt;

    dash::producer::CumulativeWeights w;
    if (core::version_gate::is_v36_active(params.current_share_version)) {
        dash::CumulativeWeights v;
        try {
            v = dash::v36_pplns_window(chain, prev_share_hash);
        } catch (const std::exception&) {
            return std::nullopt;
        }
        w.weights      = std::move(v.weights);
        w.total_weight = v.total_weight;
    } else {
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

        w = dash::producer::get_cumulative_weights(
            chain, grandparent, max_shares, desired_weight);
    }
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

// ── gather_redistribute_candidates ───────────────────────────────────────────
//
// Impure gather feeding resolve_mint_identity's pplns/boost arms: walks the
// SAME oracle window the DASH payout uses (pplns_weights_for -> get_cumulative_
// weights) and returns the per-scriptPubKey accrued weight as a candidate list.
// Reusing pplns_weights_for guarantees the redistribution weights are bit-for-bit
// the payout weights (grandparent start, min(height,RCL)-1 window, 288->64
// normalization). Empty (cold chain / no window) -> empty vector -> the arm
// declines fail-closed, exactly the pre-port genesis behaviour.
template <typename ChainT>
inline std::vector<WeightedCandidate> gather_redistribute_candidates(
    ChainT& chain,
    const core::CoinParams& params,
    const uint256& prev_share_hash,
    uint32_t block_bits)
{
    std::vector<WeightedCandidate> cands;
    auto w = pplns_weights_for(chain, params, prev_share_hash, block_bits);
    if (!w)
        return cands;
    cands.reserve(w->weights.size());
    for (const auto& [script, weight] : w->weights)
        if (weight > 0)
            cands.push_back(WeightedCandidate{script, weight});
    return cands;
}

} // namespace dash::mint
