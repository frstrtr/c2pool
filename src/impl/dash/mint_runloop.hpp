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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
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
// FrozenJobRegistry keeps every job served in the last 420 s, so a per-job copy
// of a full template's hex would pin one copy of the same bodies per job (and
// the registry counts a vector once per pointer). The memo keys on the template's
// complete tx hash list (a txid is the hash of its body, so equal lists mean
// equal bodies) and holds only weak_ptrs: it never extends a body vector's life
// past the last frozen job that references it. Thread-safe (stratum sessions
// build producer jobs concurrently). A template stored by the work source
// brings its own encoded vector (DashWorkData::m_tx_hex_shared) and never
// reaches the memo; see build_producer_job.
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
    const std::vector<unsigned char>& message_data = {})
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
    pin.stale_info         = dash::StaleInfo::none;
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
    out.frozen.stale_info         = dash::StaleInfo::none;
    // Freeze the job's share identity: the mint-time rebuild MUST use the
    // exact identity this gentx committed to (see FrozenMintJob note) — with
    // --fee substitution the submit-time username script differs from it.
    out.frozen.payout_script_override = payout_script;
    out.frozen.message_data       = pin.message_data;    // committed in ref_hash (v36)
    // v36: the template's tx bodies (template order, parallel to
    // desired_tx_hashes) -- the finder assembles the won block from them
    // (coin/reconstruct_won_block.hpp). Null on v16 and on coinbase-only jobs.
    //
    // A stored template carries its own vector (m_tx_hex_shared: encoded for
    // it, or reused from the previous stored template with the same bodies):
    // the frozen job takes that very pointer, the one its stratum job froze, so
    // the two cannot hold different bodies. The memo serves only a template that
    // never went through the store (it carries no vector). Its match (the txid
    // list and the body count) is NOT byte-exact under Dash Core v24: a
    // version-2 asset unlock (type 9) keeps its txid when re-signed while its
    // bytes change. That is not reachable today, because template selection
    // never admits types 5/6/9 (Mempool::SpecialTxSelectMask::admits). Before
    // type 9 may enter templates, the memo must byte-check such bodies the way
    // coin::template_tx_hex_reusable does, or be retired.
    if (v36 && !wd.m_tx_hashes.empty())
        out.frozen.tx_data_hex = wd.m_tx_hex_shared
                                     ? wd.m_tx_hex_shared.hex()
                                     : TemplateBodiesMemo::instance().get(wd);
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
//       split  -> (default) mint under the node owner's identity with
//                 donation=core::kSplitShareDonation (32768 of 65535): the
//                 owner and the donation script each get half of the share's
//                 PPLNS weight. Deterministic, every such share. Without a
//                 usable owner address the owner half cannot be paid:
//                 main_dash.cpp runs pplns instead (logged at startup), and
//                 resolve_mint_identity takes the pplns arm;
//       pplns/boost -> the LTC weighted-redistribution engine is NOT yet
//                 ported to DASH; these decline the producer job (the
//                 pre-existing fail-closed behavior, loudly logged).
struct MintFeePolicy
{
    enum class Redistribute { PPLNS, FEE, BOOST, DONATE, SPLIT };

    // The --redistribute default (main_dash.cpp, the param catalog's
    // money.redistribute).
    static constexpr const char* kDefaultRedistribute = "split";

    uint16_t donation_u16{66};                     // --give-author (default 0.1% -> 66)
    double   node_owner_fee_pct{0.0};              // --fee (0 = off)
    std::vector<unsigned char> node_owner_script;  // --node-owner-address (P2PKH), may be empty
    Redistribute redistribute{Redistribute::SPLIT};

    static Redistribute parse_redistribute(const std::string& s)
    {
        if (s == "split")  return Redistribute::SPLIT;
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
    case MintFeePolicy::Redistribute::SPLIT:
        // Half the share's weight to the owner, half to the donation: the
        // split donation replaces --give-author's, it is not added to it.
        if (owner_ok)
            return ResolvedIdentity{policy.node_owner_script, core::kSplitShareDonation, true};
        // No usable owner: the owner half cannot be paid -> pplns.
        [[fallthrough]];
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
// the job context a solved coinbase belongs to. A miss at mint time is a
// fail-closed decline, never a guess.
// On the DASH v36 network the ref_hash does not cover the template's tx set
// (the share carries no tx refs; the set is committed by the coinbase
// merkle_link instead). Every producer build draws a fresh random share nonce,
// so two tx sets never share a ref in practice, and both consumers re-check the
// set anyway: the mint's X11 identity gate (the rebuilt merkle_link must
// reproduce the solved header) and the finder's block assembly
// (v36_finder_block_bodies: the frozen hashes must fold to the share's link).
//
// BOUNDS. A v36 entry holds the template's tx-hex vector (the stored
// template's TemplateTxHex, shared by pointer) and its own copy of the tx hash
// list. A 512-entry FIFO with no byte bound could pin 512 full templates
// (about 2 GiB). The registry is now bounded by age, by bytes and by count:
//
//   * AGE. An entry is evicted more than kFrozenJobAge (420 s) after its last
//     put. Past that no stratum session can still hold a job carrying its ref
//     (derivation at kFrozenJobAge).
//   * BYTES. registry bytes = every hex vector ONCE per pointer (however many
//     entries and payouts share it) + every entry's own bytes (its tx hash
//     list, its payment list, scripts and payload, and a fixed overhead).
//     The cap comes from the cgroup (frozen_registry_cap_from_cgroup).
//   * COUNT. A backstop of 16,384 entries. It is SOFT: it evicts in the same
//     tier order and never takes an entry the rules keep, so a count above it
//     is admitted, with a WARNING once per episode (over_backstop_puts counts
//     the puts that left it over). The age still bounds every entry.
//
// EVICTION RUNS ONLY INSIDE put(). A session sweeps its own jobs only when it
// inserts one, so with no work served nothing ages on either side; get() and
// lookup_for_mint() never evict. Order, oldest last put first within a tier:
//   1. expired (more than `age` since the last put), cap or not;
//   2. over the byte cap, or over the count backstop:
//      T1, an entry on an older coin tip, then
//      T2, an entry on the current coin tip but an older best share;
//      each only when its own (tip, best share) context was superseded (the
//      first put on another context after its last put: the clean notify that
//      moved the sessions off it) more than `grace` (45 s) ago.
// Entries on the current tip AND the current best share are never evicted
// before their age, nor is a just-superseded entry inside the grace.
// Each context keeps its own last-put list, and superseded contexts sit in a
// list in supersession order, so an eviction pass visits only the contexts
// past the grace (a prefix of that list), never the whole registry.
//
// SAFETY BRAKE. When the entries the rules keep exceed the cap on their own,
// put() still admits (refusing would serve a ref whose solve then declines)
// and raises brake_on(); the work source's template store then pauses
// same-tip refreshes that change only the tx set (tip changes always store).
// While the brake is on, the tiers trim to below 80% of the cap (not just to
// the cap), so it is released as soon as the kept entries fit in 80% again;
// trimming only to the cap would park the bytes just under it and keep the
// brake on for as long as the load lasts. One WARNING line on entry, one INFO
// line on exit, a counter of episodes.
//
// LOUD MISSES. Every eviction is remembered (ref, cause, time; ids only, never
// the job) in a ring, so a submit whose job is gone names its cause:
// lookup_for_mint counts the miss per cause and frozen_job_for_mint logs it.

// ── How long a submit can still need a frozen job ──────────────────────────
// A solve reaches the mint seam only through a job its stratum session still
// holds, and the put of that job's ref happens inside build_connection_coinbase,
// before send_notify_work stamps the job, so the time since a ref's last put
// is never less than the age of any job carrying it. A ref is needed up to:
//     300   s  session job TTL (core StratumSession::JOB_TTL)
//   +  37.5 s  session sweep lag: the TTL sweep runs only when the session
//              inserts a job; DASH feeds every session at least every
//              keepalive_notify_sec (DASHWorkSource::kKeepaliveNotifySec,
//              25 s) and the half-interval guard bounds the gap at 1.5 x 25 s
//   +  20   s  queued mint: a solve the busy tracker cannot take waits up to
//              the deferred-mint TTL (core::DeferredMinter, 20 s). The mint
//              copies the job at arrival and a won block carries that copy
//              (WonBlockBodies), so this term is now conservative
//   +  20   s  per-session hold (StratumConfig::job_hold_limit_sec), should
//              DASH ever set `held`
//   = 377.5 s; 420 s leaves 42.5 s of slack.
//
// The GRACE after a supersession: a session not yet served on the new
// context keeps hashing, and submitting, the superseded job until its next
// notify, at most the session lag (37.5 s) later; the stratum path accepts any
// job still in the session's active_jobs_ and mints it (a DOA or sibling
// share). 45 s = that lag + 7.5 s for results in flight.
inline constexpr double kFrozenJobSessionLagSec =
    1.5 * static_cast<double>(dash::stratum::DASHWorkSource::kKeepaliveNotifySec);
inline constexpr double kFrozenJobLiveBoundSec = 300.0 + kFrozenJobSessionLagSec + 20.0 + 20.0;
inline constexpr std::chrono::seconds kFrozenJobAge{420};
static_assert(kFrozenJobLiveBoundSec < static_cast<double>(kFrozenJobAge.count()),
              "the frozen-job age must outlive every stratum job that can carry its ref");
inline constexpr std::chrono::seconds kFrozenJobGrace{45};
static_assert(static_cast<double>(kFrozenJobGrace.count()) >= kFrozenJobSessionLagSec + 5.0,
              "the grace must cover the session lag plus results in flight");
inline constexpr size_t kFrozenJobBackstop = 16384;

inline constexpr uint64_t kMiB = 1024ull * 1024ull;
inline constexpr uint64_t kFrozenRegistryCapMax     = 256 * kMiB;
inline constexpr uint64_t kFrozenRegistryCapFloor   = 64 * kMiB;
inline constexpr uint64_t kFrozenRegistryCapDivisor = 8;

struct FrozenRegistryConfig
{
    uint64_t cap_bytes = kFrozenRegistryCapMax;
    size_t   backstop  = kFrozenJobBackstop;
    std::chrono::steady_clock::duration age   = kFrozenJobAge;
    std::chrono::steady_clock::duration grace = kFrozenJobGrace;
    size_t   evicted_ring = 4096;   ///< evictions remembered for a miss's cause
};

// ── The byte cap from the process's cgroup ──────────────────────────────────
// cap = min(256 MiB, memory.max / 8), at least 64 MiB; 256 MiB when no cgroup
// memory limit applies. memory.max is read for the process's own cgroup and
// every ancestor (the smallest limit applies): cgroup v2 first
// (/sys/fs/cgroup/<path>/memory.max, "max" = no limit), then the v1 memory
// controller (memory.limit_in_bytes; a value of 2^62 or more = no limit).
inline uint64_t frozen_registry_cap_for(std::optional<uint64_t> memory_max)
{
    if (!memory_max) return kFrozenRegistryCapMax;
    return std::clamp<uint64_t>(*memory_max / kFrozenRegistryCapDivisor,
                                kFrozenRegistryCapFloor, kFrozenRegistryCapMax);
}

struct FrozenRegistryCapChoice
{
    uint64_t cap_bytes{kFrozenRegistryCapMax};
    std::string source{"no-limit"};          ///< cgroup2 | cgroup1 | no-limit | flag
    std::string cgroup{"-"};                 ///< the cgroup whose limit applied ("-": none read)
    std::optional<uint64_t> memory_max;      ///< bytes; nullopt = no limit found
};

/// Reads a whole small text file; nullopt when it cannot be opened.
using TextFileReader = std::function<std::optional<std::string>(const std::string& path)>;

inline std::optional<std::string> read_text_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::ostringstream o;
    o << f.rdbuf();
    return o.str();
}

namespace detail {
// "/a/b" -> {"/a/b", "/a", "/"}
inline std::vector<std::string> cgroup_and_ancestors(std::string path)
{
    std::vector<std::string> out;
    if (path.empty() || path[0] != '/') path = "/" + path;
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    for (;;) {
        out.push_back(path);
        if (path == "/") break;
        const auto slash = path.find_last_of('/');
        path = slash == 0 ? std::string("/") : path.substr(0, slash);
    }
    return out;
}

inline std::string trim_ws(const std::string& s)
{
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

inline std::optional<uint64_t> parse_u64(const std::string& s)
{
    if (s.empty() || s.size() > 20) return std::nullopt;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}
} // namespace detail

inline FrozenRegistryCapChoice frozen_registry_cap_from_cgroup(
    const TextFileReader& read = read_text_file)
{
    FrozenRegistryCapChoice out;
    const auto self = read("/proc/self/cgroup");
    if (!self) return out;

    std::string v2_path, v1_path;
    bool have_v2 = false, have_v1 = false;
    std::istringstream lines(*self);
    for (std::string line; std::getline(lines, line);) {
        const auto c1 = line.find(':');
        if (c1 == std::string::npos) continue;
        const auto c2 = line.find(':', c1 + 1);
        if (c2 == std::string::npos) continue;
        const std::string id    = line.substr(0, c1);
        const std::string ctrls = line.substr(c1 + 1, c2 - c1 - 1);
        const std::string path  = detail::trim_ws(line.substr(c2 + 1));
        if (id == "0" && ctrls.empty()) { v2_path = path; have_v2 = true; continue; }
        std::istringstream cs(ctrls);
        for (std::string c; std::getline(cs, c, ',');)
            if (c == "memory") { v1_path = path; have_v1 = true; }
    }

    // One hierarchy: the smallest numeric limit over the cgroup and its
    // ancestors. Returns false when no limit file could be read at all.
    auto walk = [&](const std::string& path, const std::string& root, const char* file,
                    bool v1, std::optional<uint64_t>& limit, std::string& where) {
        bool any = false;
        for (const auto& dir : detail::cgroup_and_ancestors(path)) {
            const auto text = read(root + (dir == "/" ? std::string() : dir) + "/" + file);
            if (!text) continue;
            any = true;
            const std::string t = detail::trim_ws(*text);
            if (t == "max") continue;
            auto n = detail::parse_u64(t);
            if (!n) continue;
            if (v1 && *n >= (1ull << 62)) continue;   // the v1 "unlimited" value
            if (!limit || *n < *limit) { limit = *n; where = dir; }
        }
        return any;
    };

    if (have_v2) {
        std::optional<uint64_t> limit;
        std::string where;
        if (walk(v2_path, "/sys/fs/cgroup", "memory.max", false, limit, where)) {
            out.source     = "cgroup2";
            out.cgroup     = limit ? where : detail::cgroup_and_ancestors(v2_path).front();
            out.memory_max = limit;
            out.cap_bytes  = frozen_registry_cap_for(limit);
            return out;
        }
    }
    if (have_v1) {
        std::optional<uint64_t> limit;
        std::string where;
        if (walk(v1_path, "/sys/fs/cgroup/memory", "memory.limit_in_bytes", true, limit, where)) {
            out.source     = "cgroup1";
            out.cgroup     = limit ? where : detail::cgroup_and_ancestors(v1_path).front();
            out.memory_max = limit;
            out.cap_bytes  = frozen_registry_cap_for(limit);
            return out;
        }
    }
    return out;
}

inline std::string format_mib(uint64_t bytes)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f", static_cast<double>(bytes) / static_cast<double>(kMiB));
    return buf;
}

/// The start-up line: the cap, where it came from, and the other bounds.
inline std::string format_frozen_registry_config_line(const FrozenRegistryCapChoice& c,
                                                      const FrozenRegistryConfig& cfg)
{
    std::ostringstream o;
    o << "[MINT-REG] config cap_mib=" << format_mib(c.cap_bytes) << " cap_bytes=" << c.cap_bytes
      << " source=" << c.source << " cgroup=" << c.cgroup << " memory_max="
      << (c.memory_max ? std::to_string(*c.memory_max) : std::string(c.cgroup == "-" ? "none" : "max"))
      << " rule=min(256MiB,memory.max/8),floor=64MiB"
      << " age_s=" << std::chrono::duration_cast<std::chrono::seconds>(cfg.age).count()
      << " grace_s=" << std::chrono::duration_cast<std::chrono::seconds>(cfg.grace).count()
      << " backstop=" << cfg.backstop << " evicted_ring=" << cfg.evicted_ring;
    return o.str();
}

// ── Byte accounting ─────────────────────────────────────────────────────────
// Hex vector: the strings' characters plus one std::string object per tx,
// plus the vector and its control block. Counted once per pointer.
inline uint64_t frozen_vector_bytes(const std::vector<std::string>& v)
{
    uint64_t b = sizeof(std::vector<std::string>) + 32;
    for (const auto& s : v) b += sizeof(std::string) + s.size();
    return b;
}

// Entry: its own copy of the tx hash list (32 B per tx), payments, scripts and
// payload, plus a fixed overhead (the job struct, map and list nodes, and the
// registry's own fields). Counted per entry.
inline constexpr uint64_t kFrozenEntryFixedBytes = sizeof(dash::stratum::FrozenMintJob) + 256;
inline uint64_t frozen_entry_bytes(const dash::stratum::FrozenMintJob& j)
{
    uint64_t b = kFrozenEntryFixedBytes;
    b += j.desired_tx_hashes.size() * sizeof(uint256);
    for (const auto& p : j.packed_payments) b += sizeof(dash::PackedPayment) + p.m_payee.size();
    b += j.coinbase_scriptSig.size() + j.coinbase_payload.size()
       + j.payout_script_override.size() + j.message_data.size();
    return b;
}

enum class FrozenEvictCause : uint8_t { age, cap_oldtip, cap_oldshare, backstop };

inline const char* frozen_evict_cause_name(FrozenEvictCause c)
{
    switch (c) {
    case FrozenEvictCause::age:          return "age";
    case FrozenEvictCause::cap_oldtip:   return "cap_oldtip";
    case FrozenEvictCause::cap_oldshare: return "cap_oldshare";
    case FrozenEvictCause::backstop:     return "backstop";
    }
    return "?";
}

struct FrozenRegistryStats
{
    uint64_t cap_bytes{0};
    uint64_t backstop{0};
    uint64_t entries{0};
    uint64_t vectors{0};
    uint64_t contexts{0};      ///< (tip, best share) contexts holding entries
    uint64_t hex_bytes{0};     ///< every vector once
    uint64_t entry_bytes{0};   ///< every entry's own bytes
    uint64_t bytes{0};         ///< hex_bytes + entry_bytes
    uint64_t peak_bytes{0};
    uint64_t puts{0};          ///< puts of a new ref
    uint64_t reputs{0};        ///< puts of a ref already held
    uint64_t evict_age{0}, evict_cap_oldtip{0}, evict_cap_oldshare{0}, evict_backstop{0};
    uint64_t mint_hits{0};
    uint64_t mint_miss_age{0}, mint_miss_cap_oldtip{0}, mint_miss_cap_oldshare{0},
             mint_miss_backstop{0}, mint_miss_unknown{0};
    bool     brake_on{false};
    uint64_t brake_episodes{0};
    uint64_t over_cap_puts{0};       ///< puts that left the registry over its cap
    uint64_t over_backstop_puts{0};  ///< puts that left the count over the backstop
    uint64_t backstop_episodes{0};   ///< times the count went over the backstop
    uint64_t scan_steps{0};          ///< contexts an eviction pass examined
};

/// A mint-time lookup. On a miss, `evicted` says whether the ref is one this
/// registry evicted (and still remembers); then `cause` and the times name it.
struct FrozenMintLookup
{
    std::optional<dash::stratum::FrozenMintJob> job;
    bool             evicted{false};
    FrozenEvictCause cause{FrozenEvictCause::age};
    double           since_evict_s{0};    ///< from the eviction to this lookup
    double           idle_at_evict_s{0};  ///< from the ref's last put to its eviction
    uint64_t         miss_count{0};       ///< this cause's miss counter, this miss included
};

class FrozenJobRegistry
{
public:
    using TimePoint = std::chrono::steady_clock::time_point;
    using Clock     = std::function<TimePoint()>;

    // At most this many evictions per put: a put after a long idle period
    // (everything expired at once) or a trim to the brake level spreads the
    // work over the next puts instead of holding the lock for all of it. A put
    // that runs out of budget skips the later steps and the brake and backstop
    // updates; the next put goes on where it stopped, so the order holds.
    static constexpr size_t kEvictBudget = 1024;

    explicit FrozenJobRegistry(FrozenRegistryConfig cfg = {}, Clock clock = {})
        : m_cfg(cfg),
          m_now(clock ? std::move(clock) : Clock([] { return std::chrono::steady_clock::now(); }))
    {
    }

    /// Register (or refresh) the job a served coinbase committed to, with the
    /// context it was served on: the template's coin tip and the prev share.
    /// A re-put refreshes the entry's last put; eviction runs here and only
    /// here.
    void put(const uint256& ref_hash, const dash::stratum::FrozenMintJob& job,
             const uint256& coin_tip = uint256(), const uint256& prev_share = uint256())
    {
        std::vector<dash::stratum::FrozenMintJob> dead;    // evicted jobs, freed after the lock
        std::vector<std::pair<bool, std::string>> lines;   // (warning, text)
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            const TimePoint now = m_now();
            note_context_locked(coin_tip, prev_share, now);
            auto it = m_jobs.find(ref_hash);
            if (it != m_jobs.end()) {
                ++m_stats.reputs;
                Entry& e = it->second;
                // Same ref = same share context. Keep the held value unless the
                // bodies differ (a different vector or tx list), which only a
                // ref collision could produce.
                if (e.job.tx_data_hex != job.tx_data_hex ||
                    e.job.desired_tx_hashes != job.desired_tx_hashes) {
                    unaccount_locked(e);
                    e.job = job;
                    account_locked(e);
                }
                e.last_put = now;
                m_lru.splice(m_lru.end(), m_lru, e.lru);
                if (e.tip != coin_tip || e.share != prev_share) {
                    ctx_remove_locked(e);
                    e.tip   = coin_tip;
                    e.share = prev_share;
                    ctx_add_locked(e, ref_hash);
                } else {
                    ctx_touch_locked(e);
                }
            } else {
                ++m_stats.puts;
                auto [ins, ok] = m_jobs.emplace(ref_hash, Entry{});
                (void)ok;
                Entry& e   = ins->second;
                e.job      = job;
                e.tip      = coin_tip;
                e.share    = prev_share;
                e.last_put = now;
                e.lru      = m_lru.insert(m_lru.end(), ref_hash);
                account_locked(e);
                ctx_add_locked(e, ref_hash);
            }
            const bool complete = evict_locked(now);
            brake_locked(now, lines, complete);
            if (complete) backstop_locked(lines);
            periodic_locked(now, lines);
            dead.swap(m_graveyard);
        }
        for (const auto& [warn, text] : lines) {
            if (warn) LOG_WARNING << text;
            else      LOG_INFO << text;
        }
    }

    /// The held job for `ref_hash`. Never evicts and counts nothing.
    std::optional<dash::stratum::FrozenMintJob> get(const uint256& ref_hash) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_jobs.find(ref_hash);
        if (it == m_jobs.end())
            return std::nullopt;
        return it->second.job;
    }

    /// The mint seam's read: the held job, or the cause of the miss, counted.
    /// Never evicts.
    FrozenMintLookup lookup_for_mint(const uint256& ref_hash)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        FrozenMintLookup r;
        auto it = m_jobs.find(ref_hash);
        if (it != m_jobs.end()) {
            ++m_stats.mint_hits;
            r.job = it->second.job;
            return r;
        }
        const TimePoint now = m_now();
        for (auto e = m_ring.rbegin(); e != m_ring.rend(); ++e) {
            if (e->ref != ref_hash) continue;
            r.evicted         = true;
            r.cause           = e->cause;
            r.since_evict_s   = seconds_between(e->at, now);
            r.idle_at_evict_s = seconds_between(e->last_put, e->at);
            break;
        }
        if (!r.evicted) {
            r.miss_count = ++m_stats.mint_miss_unknown;
            return r;
        }
        switch (r.cause) {
        case FrozenEvictCause::age:          r.miss_count = ++m_stats.mint_miss_age; break;
        case FrozenEvictCause::cap_oldtip:   r.miss_count = ++m_stats.mint_miss_cap_oldtip; break;
        case FrozenEvictCause::cap_oldshare: r.miss_count = ++m_stats.mint_miss_cap_oldshare; break;
        case FrozenEvictCause::backstop:     r.miss_count = ++m_stats.mint_miss_backstop; break;
        }
        return r;
    }

    /// Whether `ref_hash` is held (no copy; counts nothing).
    bool contains(const uint256& ref_hash) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_jobs.count(ref_hash) != 0;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_jobs.size();
    }

    uint64_t bytes() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_hex_bytes + m_entry_bytes;
    }

    /// The safety brake (lock-free: the work source's template store reads it
    /// from its own thread).
    bool brake_on() const noexcept { return m_brake.load(std::memory_order_relaxed); }

    FrozenRegistryStats stats() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return stats_locked();
    }

    const FrozenRegistryConfig& config() const noexcept { return m_cfg; }

    static std::string format_stats_line(const FrozenRegistryStats& s)
    {
        std::ostringstream o;
        o << "[MINT-REG] 60s puts=" << s.puts << " reputs=" << s.reputs
          << " entries=" << s.entries << " vectors=" << s.vectors << " contexts=" << s.contexts
          << " hex_mib=" << format_mib(s.hex_bytes) << " entry_mib=" << format_mib(s.entry_bytes)
          << " bytes_mib=" << format_mib(s.bytes) << " peak_mib=" << format_mib(s.peak_bytes)
          << " cap_mib=" << format_mib(s.cap_bytes)
          << " evict age=" << s.evict_age << " cap_oldtip=" << s.evict_cap_oldtip
          << " cap_oldshare=" << s.evict_cap_oldshare << " backstop=" << s.evict_backstop
          << " mint_miss age=" << s.mint_miss_age << " cap_oldtip=" << s.mint_miss_cap_oldtip
          << " cap_oldshare=" << s.mint_miss_cap_oldshare << " backstop=" << s.mint_miss_backstop
          << " unknown=" << s.mint_miss_unknown << " mint_hits=" << s.mint_hits
          << " brake=" << (s.brake_on ? "on" : "off") << " brake_episodes=" << s.brake_episodes
          << " over_cap_puts=" << s.over_cap_puts
          << " over_backstop_puts=" << s.over_backstop_puts
          << " backstop_episodes=" << s.backstop_episodes;
        return o.str();
    }

    /// The WARNING when the count goes over the soft backstop.
    static std::string format_backstop_line(const FrozenRegistryStats& s)
    {
        std::ostringstream o;
        o << "[MINT-REG] COUNT BACKSTOP exceeded with no evictable entry left: entries="
          << s.entries << " backstop=" << s.backstop << " contexts=" << s.contexts
          << " backstop_episodes=" << s.backstop_episodes
          << " -- admitted: the backstop never evicts the current tip and best share, nor an"
             " entry inside the grace; the age bound still applies";
        return o.str();
    }

private:
    using Pair = std::pair<uint256, uint256>;   // (coin tip, best share)

    struct CtxNode { uint256 ref; TimePoint put; };   // an entry in its context's list
    struct Entry
    {
        dash::stratum::FrozenMintJob job;
        uint256   tip;
        uint256   share;
        TimePoint last_put{};
        uint64_t  entry_bytes{0};
        const void* vec{nullptr};
        std::list<uint256>::iterator lru;       // in m_lru (every entry, last-put order)
        std::list<CtxNode>::iterator ctx_lru;   // in its context's own list
    };
    struct VecInfo { uint64_t bytes{0}; uint64_t refs{0}; };
    // A context: its entries in last-put order (each with its last put, so an
    // eviction pass needs no lookup), and when it was superseded (unset while
    // it is the current one; set for every other context, because each one
    // stopped being current at a put). A superseded context also sits in
    // m_superseded, in supersession order, by pointer (map nodes do not move).
    struct Ctx;
    struct SupItem { Pair key; Ctx* ctx; };
    struct Ctx
    {
        std::list<CtxNode>           lru;
        std::optional<TimePoint>     superseded_at;
        std::list<SupItem>::iterator sup;
    };

    struct Evicted { uint256 ref; FrozenEvictCause cause; TimePoint at; TimePoint last_put; };

    static double seconds_between(TimePoint a, TimePoint b)
    {
        return std::chrono::duration<double>(b - a).count();
    }

    uint64_t bytes_locked() const { return m_hex_bytes + m_entry_bytes; }

    void supersede_locked(Ctx& c, const Pair& key, TimePoint now)
    {
        if (c.superseded_at) return;
        c.superseded_at = now;
        c.sup = m_superseded.insert(m_superseded.end(), SupItem{key, &c});
    }

    void revive_locked(Ctx& c)
    {
        if (!c.superseded_at) return;
        m_superseded.erase(c.sup);
        c.superseded_at.reset();
    }

    // The context of this put becomes the current one. The previous current
    // context, when it differs, is superseded now (a clean notify moved the
    // sessions off it); the context put now is live again, which also covers a
    // reorg back to a tip seen before and two producers interleaving their
    // puts. An entry's grace runs from ITS context's supersession, so an entry
    // an earlier best-share change already superseded stays evictable when the
    // tip then changes.
    void note_context_locked(const uint256& tip, const uint256& share, TimePoint now)
    {
        if (m_have_current && tip == m_cur_tip && share == m_cur_share) return;
        if (m_have_current)
            if (auto p = m_ctx.find(Pair{m_cur_tip, m_cur_share}); p != m_ctx.end())
                supersede_locked(p->second, p->first, now);
        if (auto p = m_ctx.find(Pair{tip, share}); p != m_ctx.end()) revive_locked(p->second);
        m_cur_tip      = tip;
        m_cur_share    = share;
        m_have_current = true;
    }

    void ctx_add_locked(Entry& e, const uint256& ref)
    {
        Ctx& c = m_ctx[Pair{e.tip, e.share}];
        e.ctx_lru = c.lru.insert(c.lru.end(), CtxNode{ref, e.last_put});
    }

    void ctx_touch_locked(Entry& e)
    {
        Ctx& c = m_ctx[Pair{e.tip, e.share}];
        c.lru.splice(c.lru.end(), c.lru, e.ctx_lru);
        e.ctx_lru->put = e.last_put;
    }

    void ctx_remove_locked(Entry& e)
    {
        auto p = m_ctx.find(Pair{e.tip, e.share});
        if (p == m_ctx.end()) return;
        p->second.lru.erase(e.ctx_lru);
        if (!p->second.lru.empty()) return;
        if (p->second.superseded_at) m_superseded.erase(p->second.sup);
        m_ctx.erase(p);
    }

    void account_locked(Entry& e)
    {
        e.entry_bytes = frozen_entry_bytes(e.job);
        m_entry_bytes += e.entry_bytes;
        e.vec = e.job.tx_data_hex ? static_cast<const void*>(e.job.tx_data_hex.get()) : nullptr;
        if (!e.vec) return;
        VecInfo& v = m_vectors[e.vec];
        if (v.refs++ == 0) {
            v.bytes = frozen_vector_bytes(*e.job.tx_data_hex);
            m_hex_bytes += v.bytes;
        }
    }

    void unaccount_locked(Entry& e)
    {
        m_entry_bytes -= e.entry_bytes;
        e.entry_bytes = 0;
        if (!e.vec) return;
        if (auto v = m_vectors.find(e.vec); v != m_vectors.end() && --v->second.refs == 0) {
            m_hex_bytes -= v->second.bytes;
            m_vectors.erase(v);
        }
        e.vec = nullptr;
    }

    void erase_locked(std::map<uint256, Entry>::iterator it, FrozenEvictCause cause, TimePoint now)
    {
        Entry& e = it->second;
        unaccount_locked(e);
        ctx_remove_locked(e);
        m_lru.erase(e.lru);
        m_ring.push_back(Evicted{it->first, cause, now, e.last_put});
        while (m_ring.size() > m_cfg.evicted_ring) m_ring.pop_front();
        m_graveyard.push_back(std::move(e.job));   // freed by put() after the lock
        switch (cause) {
        case FrozenEvictCause::age:          ++m_stats.evict_age; break;
        case FrozenEvictCause::cap_oldtip:   ++m_stats.evict_cap_oldtip; break;
        case FrozenEvictCause::cap_oldshare: ++m_stats.evict_cap_oldshare; break;
        case FrozenEvictCause::backstop:     ++m_stats.evict_backstop; break;
        }
        m_jobs.erase(it);
    }

    // T1 (contexts on an older coin tip) oldest last put first, then T2
    // (older best share on the current tip), while `over()` holds and the
    // budget lasts (false: it ran out, more is owed). Only the contexts
    // superseded more than `grace` ago are candidates; they are the front of
    // m_superseded, so ONE walk stops at the first one inside the grace and
    // never visits the current context or the entries one by one. Across the
    // candidate contexts of a tier a min-heap on each context's oldest entry
    // keeps the global oldest-first order.
    struct Cand { TimePoint front; Ctx* ctx; };
    template <typename Over>
    bool evict_tiers_locked(TimePoint now, bool backstop, Over over, size_t& budget)
    {
        const auto later = [](const Cand& a, const Cand& b) { return a.front > b.front; };
        std::vector<Cand> t1, t2;
        for (const SupItem& si : m_superseded) {
            ++m_stats.scan_steps;
            if (now - *si.ctx->superseded_at <= m_cfg.grace) break;   // the rest are younger
            if (si.key.first == m_cur_tip && si.key.second == m_cur_share) continue;
            (si.key.first != m_cur_tip ? t1 : t2).push_back(Cand{si.ctx->lru.front().put, si.ctx});
        }
        for (const bool old_tip : {true, false}) {
            std::vector<Cand>& heap = old_tip ? t1 : t2;
            std::make_heap(heap.begin(), heap.end(), later);
            const FrozenEvictCause cause =
                backstop ? FrozenEvictCause::backstop
                         : (old_tip ? FrozenEvictCause::cap_oldtip : FrozenEvictCause::cap_oldshare);
            while (!heap.empty() && over()) {
                if (budget == 0) return false;
                std::pop_heap(heap.begin(), heap.end(), later);
                Ctx* c = heap.back().ctx;
                heap.pop_back();
                const bool last = c->lru.size() == 1;
                erase_locked(m_jobs.find(c->lru.front().ref), cause, now);
                --budget;
                if (last) continue;   // the context went with its last entry
                heap.push_back(Cand{c->lru.front().put, c});
                std::push_heap(heap.begin(), heap.end(), later);
            }
            if (!over()) break;
        }
        return true;
    }

    // Over the byte cap: above the cap, or, while the brake is on, at or above
    // 80% of it (so the brake can be released under a steady load).
    bool over_cap_locked(bool braking) const
    {
        const uint64_t b = bytes_locked();
        return braking ? b * 5 >= m_cfg.cap_bytes * 4 : b > m_cfg.cap_bytes;
    }

    // false: the eviction budget ran out with evictions still owed.
    bool evict_locked(TimePoint now)
    {
        size_t budget = kEvictBudget;
        // 1. Expired, oldest first: m_lru is in last-put order.
        while (!m_lru.empty()) {
            auto it = m_jobs.find(m_lru.front());
            if (now - it->second.last_put <= m_cfg.age) break;
            if (budget == 0) return false;
            erase_locked(it, FrozenEvictCause::age, now);
            --budget;
        }
        // 2. Over the byte cap (trimmed to below 80% while the brake is on).
        const bool braking = m_brake.load(std::memory_order_relaxed);
        if (over_cap_locked(braking) &&
            !evict_tiers_locked(now, false, [this, braking] { return over_cap_locked(braking); }, budget))
            return false;
        // 3. Over the count backstop.
        if (m_jobs.size() > m_cfg.backstop &&
            !evict_tiers_locked(now, true, [this] { return m_jobs.size() > m_cfg.backstop; }, budget))
            return false;
        return true;
    }

    // `complete`: this put's evictions all ran. When the budget cut them short,
    // the bytes may still hold evictable entries, so the brake is not raised.
    void brake_locked(TimePoint now, std::vector<std::pair<bool, std::string>>& lines, bool complete)
    {
        const uint64_t b = bytes_locked();
        m_peak_bytes = std::max(m_peak_bytes, b);
        const bool on = m_brake.load(std::memory_order_relaxed);
        if (b > m_cfg.cap_bytes) {
            if (!complete) return;
            ++m_stats.over_cap_puts;
            if (on) return;
            m_brake.store(true, std::memory_order_relaxed);
            ++m_stats.brake_episodes;
            m_brake_since = now;
            std::ostringstream o;
            o << "[MINT-REG] SAFETY BRAKE ON: frozen-job registry over its byte cap with no"
                 " evictable entry left (current tip and best share, or superseded less than "
              << std::chrono::duration_cast<std::chrono::seconds>(m_cfg.grace).count()
              << " s ago) bytes_mib=" << format_mib(b) << " cap_mib=" << format_mib(m_cfg.cap_bytes)
              << " entries=" << m_jobs.size() << " vectors=" << m_vectors.size()
              << " brake_episodes=" << m_stats.brake_episodes
              << " -- the template store pauses same-tip refreshes that change only the tx set"
                 " until bytes < 80% of the cap; tip changes still store";
            lines.emplace_back(true, o.str());
        } else if (on && b * 5 < m_cfg.cap_bytes * 4) {
            m_brake.store(false, std::memory_order_relaxed);
            std::ostringstream o;
            o << "[MINT-REG] SAFETY BRAKE OFF after "
              << static_cast<int64_t>(seconds_between(m_brake_since, now))
              << " s: bytes_mib=" << format_mib(b) << " below 80% of cap_mib="
              << format_mib(m_cfg.cap_bytes) << " entries=" << m_jobs.size()
              << " vectors=" << m_vectors.size() << " brake_episodes=" << m_stats.brake_episodes;
            lines.emplace_back(false, o.str());
        }
    }

    // The soft backstop: a WARNING once per episode of a count above it.
    void backstop_locked(std::vector<std::pair<bool, std::string>>& lines)
    {
        if (m_jobs.size() > m_cfg.backstop) {
            ++m_stats.over_backstop_puts;
            if (m_over_backstop) return;
            m_over_backstop = true;
            ++m_stats.backstop_episodes;
            lines.emplace_back(true, format_backstop_line(stats_locked()));
        } else if (m_over_backstop) {
            m_over_backstop = false;
            lines.emplace_back(false, "[MINT-REG] count back within the backstop: entries=" +
                                          std::to_string(m_jobs.size()) +
                                          " backstop=" + std::to_string(m_cfg.backstop));
        }
    }

    // One stats line per 60 s of puts, when a counter moved since the last.
    void periodic_locked(TimePoint now, std::vector<std::pair<bool, std::string>>& lines)
    {
        if (!m_have_line) { m_have_line = true; m_line_at = now; return; }
        if (now - m_line_at < std::chrono::seconds(60)) return;
        const FrozenRegistryStats s = stats_locked();
        const auto key = std::make_tuple(s.puts, s.reputs, s.evict_age + s.evict_cap_oldtip +
                                         s.evict_cap_oldshare + s.evict_backstop,
                                         s.mint_hits + s.mint_miss_age + s.mint_miss_cap_oldtip +
                                         s.mint_miss_cap_oldshare + s.mint_miss_backstop +
                                         s.mint_miss_unknown, s.brake_episodes);
        m_line_at = now;
        if (key == m_line_key) return;
        m_line_key = key;
        lines.emplace_back(false, format_stats_line(s));
    }

    FrozenRegistryStats stats_locked() const
    {
        FrozenRegistryStats s = m_stats;
        s.cap_bytes   = m_cfg.cap_bytes;
        s.backstop    = m_cfg.backstop;
        s.entries     = m_jobs.size();
        s.vectors     = m_vectors.size();
        s.contexts    = m_ctx.size();
        s.hex_bytes   = m_hex_bytes;
        s.entry_bytes = m_entry_bytes;
        s.bytes       = m_hex_bytes + m_entry_bytes;
        s.peak_bytes  = m_peak_bytes;
        s.brake_on    = m_brake.load(std::memory_order_relaxed);
        return s;
    }

    const FrozenRegistryConfig m_cfg;
    const Clock                m_now;
    mutable std::mutex         m_mutex;
    std::map<uint256, Entry>   m_jobs;
    std::list<uint256>         m_lru;         // every entry, last-put order, oldest first
    std::unordered_map<const void*, VecInfo> m_vectors;
    std::map<Pair, Ctx>        m_ctx;         // contexts holding entries
    std::list<SupItem>         m_superseded;  // superseded contexts, oldest supersession first
    std::vector<dash::stratum::FrozenMintJob> m_graveyard;   // evicted this put, freed outside the lock
    bool                       m_have_current{false};
    uint256                    m_cur_tip;
    uint256                    m_cur_share;
    std::deque<Evicted>        m_ring;
    uint64_t                   m_hex_bytes{0};
    uint64_t                   m_entry_bytes{0};
    uint64_t                   m_peak_bytes{0};
    FrozenRegistryStats        m_stats;       // counters only; sizes are filled by stats_locked
    std::atomic<bool>          m_brake{false};
    TimePoint                  m_brake_since{};
    bool                       m_over_backstop{false};
    bool                       m_have_line{false};
    TimePoint                  m_line_at{};
    std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t> m_line_key{};
};

// ── WonBlockBodies ──────────────────────────────────────────────────────────
//
// The tx bodies of a WON BLOCK's job, carried from the mint seam's copy to the
// won-block rebuild. The mint copies the frozen job when the solve arrives;
// the finder's rebuild (reconstruct_won_block, the p2p relay leg) runs later,
// after the win has moved the tip, when the registry may already have
// evicted the entry. The seam records the won job's tx hashes and its shared
// hex vector here, and the rebuild reads them here first. At most kCapacity
// wins are kept (each one template's vector, by pointer), oldest dropped.
// Thread-safe: the seam runs on the io thread, the rebuild on the compute
// thread.
struct WonTemplateBodies
{
    std::vector<uint256> tx_hashes;
    std::shared_ptr<const std::vector<std::string>> tx_data_hex;
};

class WonBlockBodies
{
public:
    static constexpr size_t kCapacity = 4;

    void record(const uint256& ref_hash, const dash::stratum::FrozenMintJob& job)
    {
        if (!job.tx_data_hex) return;   // v16 or coinbase-only: nothing to carry
        std::lock_guard<std::mutex> lk(m_mu);
        for (auto& e : m_entries)
            if (e.first == ref_hash) {
                e.second = WonTemplateBodies{job.desired_tx_hashes, job.tx_data_hex};
                return;
            }
        m_entries.emplace_back(ref_hash, WonTemplateBodies{job.desired_tx_hashes, job.tx_data_hex});
        while (m_entries.size() > kCapacity) m_entries.pop_front();
    }

    std::optional<WonTemplateBodies> find(const uint256& ref_hash) const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        for (const auto& e : m_entries)
            if (e.first == ref_hash) return e.second;
        return std::nullopt;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_entries.size();
    }

private:
    mutable std::mutex m_mu;
    std::deque<std::pair<uint256, WonTemplateBodies>> m_entries;
};

/// The finder's bodies for a won block's ref: the copy the mint carried, else
/// the registry's entry (still held when the rebuild runs early).
inline std::optional<WonTemplateBodies>
won_block_bodies_for(const WonBlockBodies& won, const FrozenJobRegistry& registry,
                     const uint256& ref_hash)
{
    if (auto w = won.find(ref_hash)) return w;
    auto job = registry.get(ref_hash);
    if (!job || !job->tx_data_hex) return std::nullopt;
    return WonTemplateBodies{std::move(job->desired_tx_hashes), job->tx_data_hex};
}

// ── frozen_job_for_mint ─────────────────────────────────────────────────────
//
// The mint seam's registry read. A miss loses the share (the miner is still
// told "accepted": work_source's "accepted (mint deferred/declined)" line), so
// it must never be silent: the WARNING names the cause (an eviction by age,
// by the cap from an old tip or an old share, by the count backstop, or
// unknown: never registered here, or evicted before the remembered ring) and
// carries that cause's counter. On a hit for a WON BLOCK (`won` set), the
// job's bodies are recorded for the won-block rebuild (WonBlockBodies).
inline std::string format_mint_miss_line(const uint256& ref_hash, const FrozenMintLookup& r)
{
    std::ostringstream o;
    o << "[MINT] no frozen job for ref=" << ref_hash.GetHex().substr(0, 16);
    if (r.evicted) {
        o << " cause=" << frozen_evict_cause_name(r.cause) << " (evicted "
          << static_cast<int64_t>(r.since_evict_s) << " s ago, "
          << static_cast<int64_t>(r.idle_at_evict_s) << " s after its last put)";
        o << " -- share declined, no sharechain credit; mint_miss_" << frozen_evict_cause_name(r.cause)
          << "=" << r.miss_count;
    } else {
        o << " cause=unknown (never registered here, or evicted before the remembered evictions)"
             " -- share declined, no sharechain credit; mint_miss_unknown=" << r.miss_count;
    }
    return o.str();
}

inline std::optional<dash::stratum::FrozenMintJob>
frozen_job_for_mint(FrozenJobRegistry& registry, const uint256& ref_hash,
                    std::string* miss_line = nullptr, WonBlockBodies* won = nullptr)
{
    FrozenMintLookup r = registry.lookup_for_mint(ref_hash);
    if (r.job) {
        if (won) won->record(ref_hash, *r.job);
        return std::move(r.job);
    }
    const std::string line = format_mint_miss_line(ref_hash, r);
    LOG_WARNING << line;
    if (miss_line) *miss_line = line;
    return std::nullopt;
}

// ── ProducerJobCache ────────────────────────────────────────────────────────
//
// The run-loop's per-(prev share, payout) producer job cache: sessions
// re-notify often, and a fresh random share nonce per notify would make every
// job's bytes unique, defeating the session's payload reuse and churning the
// registry. A hit serves the SAME job (and re-puts its ref).
//
// A hit needs the same coin tip, height, payment amount and TX SET, and an
// entry younger than 30 s. "Same coin template" MUST mean the same tx set, not
// merely the same tip+height: the masternode payout inside the cached gentx is
// fee-dependent, so a cached gentx over an older poll's fee total, frozen with
// the CURRENT template's tx set, is a merkle-consistent but consensus-INVALID
// block (bad-cb-payee; mainnet h2508929 and h2509044 were lost that way).
//
// Every call first sweeps the entries older than 60 s, at any size (it used to
// sweep only above 128 entries, so a small cache pinned its templates' hex
// vectors until it grew). Thread-safe.
class ProducerJobCache
{
public:
    using Key       = std::pair<uint256, std::vector<unsigned char>>;   // (prev share, payout script)
    using TimePoint = std::chrono::steady_clock::time_point;
    static constexpr std::chrono::seconds kHitTtl{30};
    static constexpr std::chrono::seconds kSweepAge{60};

    enum class Outcome { hit, drift, miss };
    struct Lookup
    {
        Outcome outcome{Outcome::miss};
        std::shared_ptr<const ProducerJobBuild> build;   ///< set on a hit
    };

    /// Sweep, then look `key` up for template `wd`. A drift is a fresh entry on
    /// the same tip and height whose tx set or payment amount moved; it is
    /// dropped, like any other non-hit.
    Lookup find(const Key& key, const dash::coin::DashWorkData& wd, TimePoint now)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        sweep_locked(now);
        Lookup r;
        auto it = m_entries.find(key);
        if (it == m_entries.end()) return r;
        const Entry& e = it->second;
        const bool same_tip = e.coin_tip == wd.m_previous_block && e.height == wd.m_height;
        const bool fresh    = now - e.at < kHitTtl;
        if (same_tip && fresh && e.build->frozen.payment_amount == wd.m_payment_amount &&
            e.build->frozen.desired_tx_hashes == wd.m_tx_hashes) {
            r.outcome = Outcome::hit;
            r.build   = e.build;
            return r;
        }
        r.outcome = (same_tip && fresh) ? Outcome::drift : Outcome::miss;
        m_entries.erase(it);
        return r;
    }

    void store(const Key& key, std::shared_ptr<const ProducerJobBuild> build,
               const uint256& coin_tip, uint32_t height, TimePoint now)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_entries[key] = Entry{std::move(build), coin_tip, height, now};
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_entries.size();
    }

private:
    struct Entry
    {
        std::shared_ptr<const ProducerJobBuild> build;
        uint256   coin_tip;
        uint32_t  height{0};
        TimePoint at{};
    };

    void sweep_locked(TimePoint now)
    {
        for (auto it = m_entries.begin(); it != m_entries.end();) {
            if (now - it->second.at > kSweepAge)
                it = m_entries.erase(it);
            else
                ++it;
        }
    }

    mutable std::mutex   m_mu;
    std::map<Key, Entry> m_entries;
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
