// share_producer_bind.hpp -- slice 2/3 of the DASH mint campaign.
//
// Adapter that binds the producer-side share construction in
// share_producer.hpp (generate_prospective_share_info + build_share) to the
// node work-source found-share seam DASHWorkSource::MintShareFn
// (stratum/work_source.hpp). This is the wire-in half of the campaign: it
// turns a stratum-found solution (MintShareInputs) plus the per-job context
// frozen at getblocktemplate/notify time (FrozenMintJob) into a fully-built,
// self-verified DashShare and returns its X11 share hash for the run-loop to
// add to the ShareTracker + broadcast.
//
// SCOPE / SAFETY (mirrors #734 posture, integrator-approved slice-2 shape):
//   - header-only, lives entirely inside src/impl/dash/ (single-coin smoke
//     gate preserved -- touches nothing shared / nothing in src/core);
//   - KAT-gated: exercised only by test/test_dash_share_producer_bind.cpp;
//     NOT wired into --run here. The run-loop set_mint_share_fn(...) call is
//     slice 3/3 (main_dash);
//   - dashd RPC fallback path is untouched and stays.
//
// WHY the frozen job carries the coinbase pieces (not a reverse-parse):
//   At mint time the producer already knows the canonical share_data
//   ['coinbase'] scriptSig + DIP4 payload it handed to the miner at job
//   assembly -- it does NOT reverse-parse the solved coinbase. MintShareInputs
//   .coinbase_bytes is the reassembled coinbase (for the miner merkle/PoW);
//   the canonical scriptSig/payload + payment/tx set + desired_target arrive
//   via FrozenMintJob, which slice 3/3 threads from the live DASHWorkSource
//   job and the KAT constructs directly.
//
// Mapping MintShareInputs (in) + FrozenMintJob (job) -> ProducerJobInputs:
//   in.header_bytes(80) -> min_header            [parse_min_header_80, slice]
//   in.prev_share_hash  -> prev_share_hash
//   in.subsidy          -> subsidy
//   in.payout_script    -> pubkey_hash           [P2PKH extract, fail-closed]
//   job.coinbase_scriptSig / coinbase_payload / share_nonce / donation /
//     desired_version / payment_amount / packed_payments / desired_tx_hashes /
//     desired_timestamp / desired_target / stale_info -> carried through
//   in.pow_hash         -> cross-check vs built.share.m_hash (X11), decline
//                          the mint (null) on mismatch -> fail-closed.

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <core/pack_types.hpp>                     // PackStream
#include <core/uint256.hpp>                        // uint160/uint256
#include <impl/bitcoin_family/coin/base_block.hpp> // BlockHeaderType / SmallBlockHeaderType
#include <impl/dash/share_producer.hpp>            // dash::producer::*
#include <impl/dash/stratum/work_source.hpp>       // dash::stratum::DASHWorkSource

namespace dash::stratum {

// -- parse_min_header_80 -----------------------------------------------------
// Parse a canonical 80-byte block header (fixed 4-byte version + merkle_root)
// into the SmallBlockHeaderType (version|prev|time|bits|nonce) the producer
// consumes. Slices off m_merkle_root. Returns nullopt on a short/malformed
// buffer (fail-closed). Pure.
inline std::optional<bitcoin_family::coin::SmallBlockHeaderType>
parse_min_header_80(const std::vector<unsigned char>& header_bytes)
{
    if (header_bytes.size() < 80)
        return std::nullopt;
    try {
        PackStream ps(header_bytes);
        bitcoin_family::coin::BlockHeaderType full;
        ps >> full;
        // SmallBlockHeaderType is the base subobject of BlockHeaderType; slicing
        // off m_merkle_root yields exactly the small-header fields.
        return static_cast<bitcoin_family::coin::SmallBlockHeaderType&>(full);
    } catch (const std::exception&) {
        return std::nullopt;  // truncated / unserialize failure -> fail-closed
    }
}

// -- pubkey_hash_from_p2pkh --------------------------------------------------
// Extract the 20-byte hash160 from a standard Dash P2PKH script
// (76 a9 14 <20> 88 ac). Exact inverse of share_check.hpp::pubkey_hash_to_script2.
// Returns nullopt on any non-canonical script (fail-closed: the mint declines
// rather than credit a malformed / non-P2PKH payout). Pure.
inline std::optional<uint160>
pubkey_hash_from_p2pkh(const std::vector<unsigned char>& script)
{
    if (script.size() != 25)
        return std::nullopt;
    if (script[0] != 0x76 || script[1] != 0xa9 || script[2] != 0x14 ||
        script[23] != 0x88 || script[24] != 0xac)
        return std::nullopt;
    return uint160(std::vector<unsigned char>(script.begin() + 3, script.begin() + 23));
}

// -- FrozenMintJob -----------------------------------------------------------
// The per-job context frozen at getblocktemplate/notify time and threaded into
// the mint. Carries the ProducerJobInputs fields the found-solution
// MintShareInputs does NOT itself carry. Slice 3/3 binds this from the live
// DASHWorkSource job; the KAT constructs it directly.
struct FrozenMintJob
{
    std::vector<unsigned char> coinbase_scriptSig;   // share_data['coinbase'], 2..100 bytes
    std::vector<unsigned char> coinbase_payload;     // RAW DIP4 CbTx extra payload ('' -> none)
    uint32_t share_nonce{0};                         // share_data['nonce']
    uint16_t donation{0};                            // share_data['donation'] (--give-author)
    // Default = the pre-v36 baseline for callers that fill the struct by hand;
    // mint_runloop.hpp build_producer_job always writes
    // params.current_share_version (36 on the private/isolated v36 chain).
    uint64_t desired_version{16};
    uint64_t payment_amount{0};                      // GBT masternode/superblock total
    std::vector<dash::PackedPayment> packed_payments;  // GBT payment list (template order)
    std::vector<uint256> desired_tx_hashes;          // GBT tx set (template order)
    uint32_t desired_timestamp{0};                   // job time
    uint256  desired_target;                         // vardiff target (pre-clip)
    uint64_t last_txout_nonce{0};                    // per-connection coinbase nonce
    dash::StaleInfo stale_info{dash::StaleInfo::none};
    // Share identity frozen at job time (slice 3/3 node-fee port). When
    // non-empty this P2PKH script REPLACES MintShareInputs.payout_script in
    // the rebuild -- the mechanism behind the consensus-safe --fee
    // (probabilistic node-owner substitution) and --redistribute: the job's
    // coinbase was built with THIS identity, so the mint must rebuild with
    // the same one or the X11 identity gate would decline every
    // fee-substituted solve. Empty -> identity from the submit's username.
    std::vector<unsigned char> payout_script_override;
    // v36 only: the message_data the job committed (its ref_hash — the registry
    // key — covers it), frozen so the mint-time rebuild uses the exact bytes
    // the served coinbase committed, never a live re-read. Empty on v16.
    std::vector<unsigned char> message_data;
    // v36 only: the template's tx bodies (hex, template order, parallel to
    // desired_tx_hashes) the job's coinbase merkle_link commits to. The finder
    // assembles the won block from them (coin/reconstruct_won_block.hpp); the
    // mint-time rebuild does not read them. Null on v16 and on coinbase-only
    // jobs.
    std::shared_ptr<const std::vector<std::string>> tx_data_hex;
};

// -- build_mint_share --------------------------------------------------------
// Pure transform: MintShareInputs + FrozenMintJob -> BuiltShare, or nullopt if
// the header is malformed, the payout script is non-P2PKH, or the rebuilt share
// X11 hash does not reproduce the solved header PoW hash (all fail-closed).
// Deterministic; KAT-exercised.
template <typename ChainT>
inline std::optional<dash::producer::BuiltShare>
build_mint_share(ChainT& chain,
                 const core::CoinParams& params,
                 const DASHWorkSource::MintShareInputs& in,
                 const FrozenMintJob& job)
{
    auto min_header = parse_min_header_80(in.header_bytes);
    if (!min_header)
        return std::nullopt;  // malformed 80-byte header

    const std::vector<unsigned char>& identity_script =
        job.payout_script_override.empty() ? in.payout_script
                                           : job.payout_script_override;
    auto pubkey_hash = pubkey_hash_from_p2pkh(identity_script);
    if (!pubkey_hash)
        return std::nullopt;  // non-canonical payout script

    dash::producer::ProducerJobInputs pin;
    pin.prev_share_hash    = in.prev_share_hash;
    pin.coinbase_scriptSig = job.coinbase_scriptSig;
    pin.coinbase_payload   = job.coinbase_payload;
    pin.share_nonce        = job.share_nonce;
    pin.pubkey_hash        = *pubkey_hash;
    pin.subsidy            = in.subsidy;
    pin.donation           = job.donation;
    pin.stale_info         = job.stale_info;
    pin.desired_version    = job.desired_version;
    pin.payment_amount     = job.payment_amount;
    pin.packed_payments    = job.packed_payments;
    pin.desired_tx_hashes  = job.desired_tx_hashes;
    pin.desired_timestamp  = job.desired_timestamp;
    pin.desired_target     = job.desired_target;

    auto info = dash::producer::generate_prospective_share_info(chain, params, pin);
    // check_pow=false: the stratum already vardiff-validated the solution; we do
    // our own exact X11 identity cross-check below instead of a target compare.
    auto built = dash::producer::build_share(
        chain, params, info, *min_header, job.last_txout_nonce, /*check_pow=*/false);

    // Integrity gate: the rebuilt share must reproduce the miner-solved header.
    // If the reassembled coinbase/merkle diverged, m_hash != pow_hash -> decline
    // rather than mint a share that would not verify on peers.
    if (built.share.m_hash != in.pow_hash)
        return std::nullopt;

    return built;
}

// -- MintedShare / build_mint_share_any --------------------------------------
// The mint-time rebuild for EITHER share type the chain mints: v16 DashShare
// (public network) or v36 DashV36Share (private/isolated DASH v36 sharechain),
// selected by params.current_share_version — the same knob that sets the
// admitted type (share_check.hpp check_share_type_admitted), so a node always
// mints the type it admits.
struct MintedShare
{
    std::variant<dash::producer::BuiltShare, dash::producer::BuiltV36Share> built;

    template <typename F>
    decltype(auto) share_visit(F&& f) const
    {
        return std::visit([&](const auto& b) -> decltype(auto) { return f(b.share); }, built);
    }
    bool is_v36() const { return std::holds_alternative<dash::producer::BuiltV36Share>(built); }
    uint256  hash() const { return share_visit([](const auto& s) { return s.m_hash; }); }
    uint32_t bits() const { return share_visit([](const auto& s) { return s.m_bits; }); }
    uint64_t last_txout_nonce() const
    {
        return share_visit([](const auto& s) { return s.m_last_txout_nonce; });
    }
    uint256 ref_hash() const
    {
        return std::visit([](const auto& b) { return b.ref_hash; }, built);
    }
    // A heap copy in the live share variant (the tracker owns it after
    // add_local_share; the caller deletes it on a declined insert).
    dash::ShareType to_share_type() const
    {
        dash::ShareType st;
        std::visit([&](const auto& b) {
            using S = std::decay_t<decltype(b.share)>;
            st = new S(b.share);
        }, built);
        return st;
    }
};

// Same header parse, identity resolution and X11 identity gate as
// build_mint_share; the rebuild is build_share_v36 (with the frozen
// message_data) when params.current_share_version is v36, else build_share.
// `message_authority` is the key set the v36 self-verify checks message_data
// against (production: active_message_authority()).
template <typename ChainT>
inline std::optional<MintedShare>
build_mint_share_any(ChainT& chain,
                     const core::CoinParams& params,
                     const DASHWorkSource::MintShareInputs& in,
                     const FrozenMintJob& job,
                     std::span<const AuthorityPubkey* const> message_authority)
{
    if (!core::version_gate::is_v36_active(params.current_share_version)) {
        auto v16 = build_mint_share(chain, params, in, job);
        if (!v16)
            return std::nullopt;
        return MintedShare{std::move(*v16)};
    }

    auto min_header = parse_min_header_80(in.header_bytes);
    if (!min_header)
        return std::nullopt;

    const std::vector<unsigned char>& identity_script =
        job.payout_script_override.empty() ? in.payout_script
                                           : job.payout_script_override;
    auto pubkey_hash = pubkey_hash_from_p2pkh(identity_script);
    if (!pubkey_hash)
        return std::nullopt;

    dash::producer::ProducerJobInputs pin;
    pin.prev_share_hash    = in.prev_share_hash;
    pin.coinbase_scriptSig = job.coinbase_scriptSig;
    pin.coinbase_payload   = job.coinbase_payload;
    pin.share_nonce        = job.share_nonce;
    pin.pubkey_hash        = *pubkey_hash;
    pin.subsidy            = in.subsidy;
    pin.donation           = job.donation;
    pin.stale_info         = job.stale_info;
    pin.desired_version    = job.desired_version;
    pin.payment_amount     = job.payment_amount;
    pin.packed_payments    = job.packed_payments;
    pin.desired_tx_hashes  = job.desired_tx_hashes;
    pin.desired_timestamp  = job.desired_timestamp;
    pin.desired_target     = job.desired_target;
    pin.message_data       = job.message_data;

    auto info = dash::producer::generate_prospective_share_info(chain, params, pin);
    auto built = dash::producer::build_share_v36(
        chain, params, info, *min_header, job.last_txout_nonce, /*check_pow=*/false,
        message_authority);
    if (built.share.m_hash != in.pow_hash)
        return std::nullopt;
    return MintedShare{std::move(built)};
}

template <typename ChainT>
inline std::optional<MintedShare>
build_mint_share_any(ChainT& chain,
                     const core::CoinParams& params,
                     const DASHWorkSource::MintShareInputs& in,
                     const FrozenMintJob& job)
{
    return build_mint_share_any(chain, params, in, job, active_message_authority());
}

// -- make_producer_mint_fn ---------------------------------------------------
// Bind build_mint_share into a DASHWorkSource::MintShareFn. The job-context
// provider yields the FrozenMintJob for the template the solution belongs to
// (slice 3/3 supplies it from the live work source; the KAT supplies a fixed
// closure). Returns the minted share hash, or NULL uint256 when the mint is
// declined (fail-closed branch; slice 3/3 logs the reason).
//
// NOTE: minting into the ShareTracker + peer broadcast is the run-loop job
// (slice 3/3); this adapter only produces the verified share + its hash.
template <typename ChainT>
inline DASHWorkSource::MintShareFn make_producer_mint_fn(
    ChainT& chain,
    const core::CoinParams& params,
    std::function<FrozenMintJob(const DASHWorkSource::MintShareInputs&)> job_provider)
{
    return [&chain, &params, job_provider = std::move(job_provider)](
               const DASHWorkSource::MintShareInputs& in) -> uint256 {
        FrozenMintJob job = job_provider(in);
        auto built = build_mint_share(chain, params, in, job);
        if (!built)
            return uint256();  // declined / deferred -- null share hash
        return built->share.m_hash;
    };
}

}  // namespace dash::stratum
