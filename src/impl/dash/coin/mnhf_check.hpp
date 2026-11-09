// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core's checks on a masternode hard-fork signal (special tx type 7,
/// MNHF) before it rides a template we build.
///
/// Dash Core v24.0.0 mines every valid signal its mempool holds: the mempool
/// prioritises each one by 0.1 DASH (txmempool.cpp addUnchecked, already
/// reproduced in mempool.hpp), so it sorts to the top of every template, and
/// the miner skips only a duplicate (node/miner.cpp:728-735). Ported here:
///
///   CheckMNHFTxImpl (src/evo/mnhftx.cpp:107-164), in Core's order and with
///   Core's reject codes:
///     bad-mnhf-type, bad-mnhf-payload, MNHFTxPayload::IsTriviallyValid
///     (bad-mnhf-version, bad-mnhf-nbit-out-of-bounds),
///     CChainParams::IsValidMNActivation at MTP(pindexPrev) (bad-mnhf-non-ehf),
///     the quorum block on the active chain (bad-mnhf-quorum-hash), the
///     quorum of type llmqTypeMnhf (bad-mnhf-missing-quorum), and the
///     recovered threshold signature over
///     SignHash(llmqType, quorumHash, GetRequestId(), msgHash) with msgHash
///     the txid of the tx with the signature zeroed (bad-mnhf-invalid);
///   CMNHFManager::ProcessBlock (mnhftx.cpp:210-260), the block-level rules:
///     a bit already in GetSignalsStage(pindexPrev) (bad-mnhf-duplicate),
///     a bit twice in one block (bad-mnhf-duplicates-in-block; the miner keeps
///     the first), IsValidMNActivation at the new block's MTP
///     (bad-mnhf-non-mn-fork).
///
/// FAIL CLOSED. A leg that cannot be decided refuses the signal (the caller
/// leaves it out of the template and logs it; a signal never pays a fee, so
/// nothing else changes):
///   * no environment wired, no chain lookup, no quorum key, no BLS verifier;
///   * the staged signals for the bit are not known exactly as of the parent
///     (the EHF tracker does not cover it). The tracker follows the bits of
///     the deployments Dash Core v24.0.0 knows (13 v24, 14 evo_shares); a
///     signal for any other bit is refused, because a signal for a retired
///     deployment's bit may already be staged below the tracker's anchor.
///     Dash Core v24.0.0 masternodes sign only for those two bits;
///   * the new block's MTP is not known before it is mined, so
///     bad-mnhf-non-mn-fork is evaluated for EVERY time from MTP(parent) on
///     (the new block's MTP is never below its parent's): a bit is refused if
///     any such time is outside Core's rule. For the v24.0.0 deployment table
///     this is exactly Core's verdict (the rule only refuses bit 28,
///     TESTDUMMY, at every time).

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/vendor/mnhftx.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dash {
namespace coin {

/// What the node wires once for the type-7 checks. Every function may be
/// called from the template builder and the emit gate.
struct MnhfCheckEnv
{
    DashNetwork net{DashNetwork::MAINNET};
    /// The height of block `hash` when it is on our active chain at or below
    /// `prev_height` (Core: LookupBlockIndex + pindexPrev->GetAncestor);
    /// nullopt when unknown or not an ancestor of the template's parent.
    std::function<std::optional<uint32_t>(const uint256& hash, uint32_t prev_height)> chain_height_of;
    /// CFinalCommitment::quorumPublicKey of the mined quorum
    /// (llmqType, quorumHash); nullopt when we do not hold it.
    std::function<std::optional<std::array<uint8_t, 48>>(uint8_t llmq_type, const uint256& quorum_hash)>
        quorum_public_key;
    /// CBLSSignature::VerifyInsecure under the basic scheme
    /// (vendor::verify_chainlock_sig in c2pool-dash).
    std::function<bool(const std::array<uint8_t, 48>& pubkey, const uint256& sign_hash,
                       const std::array<uint8_t, 96>& sig)>
        verify_sig;
    /// GetSignalsStage(pindexPrev) restricted to `bit`: true when an
    /// unexpired signal for the bit is mined at or below `prev_height`, false
    /// when none is; nullopt when that is not known exactly.
    std::function<std::optional<bool>(uint8_t bit, uint32_t prev_height)> bit_staged;
};

namespace mnhf_detail {

/// One entry of Core's vDeployments as IsValidMNActivation reads it.
struct ActivationRow
{
    int     bit;
    int64_t start;
    int64_t timeout;
    bool    ehf;
};

/// Core's vDeployments in DeploymentPos order: TESTDUMMY, V24, EVO_SHARES.
inline std::vector<ActivationRow> activation_rows(const DashDeploymentParams& p)
{
    std::vector<ActivationRow> rows;
    // DEPLOYMENT_TESTDUMMY: bit 28, never EHF; NEVER_ACTIVE start on every
    // network but regtest (start 0), no timeout (chainparams.cpp).
    rows.push_back({28, p.network == DashNetwork::REGTEST ? int64_t{0} : Bip9Deployment::NEVER_ACTIVE,
                    Bip9Deployment::NO_TIMEOUT, false});
    for (const auto& d : p.deployments) rows.push_back({d.bit, d.nStartTime, d.nTimeout, d.useEHF});
    return rows;
}

inline uint256 sha256d(::PackStream& s)
{
    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

} // namespace mnhf_detail

/// llmq::SignHash (src/llmq/signhash.cpp): SHA256d(u8 llmqType || quorumHash
/// || id || msgHash). The same preimage the ChainLock verifier builds
/// (chainlock_verify.hpp build_sign_hash).
inline uint256 mnhf_sign_hash(uint8_t llmq_type, const uint256& quorum_hash, const uint256& id,
                              const uint256& msg_hash)
{
    ::PackStream s;
    s << llmq_type;
    s << quorum_hash;
    s << id;
    s << msg_hash;
    return mnhf_detail::sha256d(s);
}

/// CChainParams::IsValidMNActivation(nBit, timePast) (chainparams.cpp:109-130):
/// the first deployment using the bit whose [start, timeout] holds timePast
/// decides (an EHF deployment is valid, any other is not); a bit no
/// deployment covers at that time is "unknown" and valid.
inline bool mnhf_is_valid_activation(const DashDeploymentParams& p, int bit, int64_t time_past)
{
    for (const auto& d : mnhf_detail::activation_rows(p)) {
        if (d.bit != bit) continue;
        if (time_past > d.timeout || time_past < d.start) continue;
        return d.ehf;
    }
    return true;
}

/// IsValidMNActivation(bit, t) for EVERY t >= from (piecewise constant, it
/// changes only at a deployment's start or just after its timeout).
inline bool mnhf_is_valid_activation_from(const DashDeploymentParams& p, int bit, int64_t from)
{
    if (!mnhf_is_valid_activation(p, bit, from)) return false;
    for (const auto& d : mnhf_detail::activation_rows(p)) {
        if (d.bit != bit) continue;
        if (d.start > from && !mnhf_is_valid_activation(p, bit, d.start)) return false;
        if (d.timeout != std::numeric_limits<int64_t>::max() && d.timeout + 1 > from
            && !mnhf_is_valid_activation(p, bit, d.timeout + 1))
            return false;
    }
    return true;
}

/// MNHFTxPayload::GetRequestId: SHA256d of the pair ("mnhf", int64 bit).
inline uint256 mnhf_request_id(uint8_t bit)
{
    static constexpr std::string_view kPrefix{"mnhf"};
    ::PackStream s;
    WriteCompactSize(s, kPrefix.size());
    s.write(std::as_bytes(std::span{kPrefix.data(), kPrefix.size()}));
    s << static_cast<int64_t>(bit);
    return mnhf_detail::sha256d(s);
}

/// The hash the quorum signs: the txid of the tx whose payload carries a null
/// signature (CheckMNHFTxImpl: tx_copy with payload_copy.signal.sig reset; a
/// null CBLSSignature serializes as 96 zero bytes).
inline uint256 mnhf_msg_hash(const MutableTransaction& tx, const vendor::MNHFTxPayload& p)
{
    MutableTransaction copy = tx;
    auto zeroed = p;
    zeroed.signal.sig.fill(0);
    ::PackStream s;
    s << zeroed;
    auto sp = s.get_span();
    copy.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                              reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return dash_txid(copy);
}

/// The first reason Dash Core refuses this type-7 tx in a block built on
/// the parent at `prev_height` (median time past `mtp_prev`), or nullopt
/// when it may ride. A non-MNHF tx passes. The in-body duplicate rule is
/// the caller's (mnhf_select below).
inline std::optional<std::string> mnhf_tx_refusal(const MutableTransaction& tx, const MnhfCheckEnv* env,
                                                  uint32_t prev_height, int64_t mtp_prev)
{
    if (tx.type != vendor::MNHFTxPayload::SPECIALTX_TYPE) return std::nullopt;
    if (!tx_is_special_version(tx.version)) return std::string("bad-mnhf-type");
    vendor::MNHFTxPayload p;
    if (!vendor::parse_mnhf_payload(tx.extra_payload, p)) return std::string("bad-mnhf-payload");
    if (p.nVersion == 0 || p.nVersion > vendor::MNHFTxPayload::CURRENT_VERSION)
        return std::string("bad-mnhf-version");
    if (p.signal.versionBit >= kVersionBitsNumBits) return std::string("bad-mnhf-nbit-out-of-bounds");
    if (env == nullptr) return std::string("mnhf signal not checkable (no MNHF check wired) - excluded");
    const auto& params = dash_deployment_params(env->net);
    if (!mnhf_is_valid_activation(params, p.signal.versionBit, mtp_prev)) return std::string("bad-mnhf-non-ehf");
    if (!env->chain_height_of) return std::string("bad-mnhf-quorum-hash (no chain lookup wired) - excluded");
    if (!env->chain_height_of(p.signal.quorumHash, prev_height))
        return std::string("bad-mnhf-quorum-hash (not a block of our active chain at or below the parent)");
    if (!env->quorum_public_key) return std::string("bad-mnhf-missing-quorum (no quorum lookup wired) - excluded");
    const auto qkey = env->quorum_public_key(params.llmq_type_mnhf, p.signal.quorumHash);
    if (!qkey) return std::string("bad-mnhf-missing-quorum (the quorum is not one we hold) - excluded");
    if (!env->verify_sig) return std::string("bad-mnhf-invalid (no BLS verifier wired) - excluded");
    const uint256 sign_hash = mnhf_sign_hash(params.llmq_type_mnhf, p.signal.quorumHash,
                                              mnhf_request_id(p.signal.versionBit), mnhf_msg_hash(tx, p));
    if (!env->verify_sig(*qkey, sign_hash, p.signal.sig)) return std::string("bad-mnhf-invalid");
    // ProcessBlock.
    bool tracked = false;
    for (const auto& d : params.deployments)
        if (d.useEHF && d.bit == p.signal.versionBit) tracked = true;
    if (!tracked)
        return "mnhf signal for bit " + std::to_string(p.signal.versionBit)
             + ": no staged-signal state for a bit outside the deployment table - excluded";
    if (!env->bit_staged) return std::string("mnhf staged signals unknown (no EHF tracker wired) - excluded");
    const auto staged = env->bit_staged(p.signal.versionBit, prev_height);
    if (!staged) return std::string("mnhf staged signals not known exactly at the parent (EHF scan) - excluded");
    if (*staged) return std::string("bad-mnhf-duplicate");
    if (!mnhf_is_valid_activation_from(params, p.signal.versionBit, mtp_prev))
        return std::string("bad-mnhf-non-mn-fork");
    return std::nullopt;
}

/// The miner's duplicate rule over a body in block order: each signal is
/// checked (mnhf_tx_refusal) and a second signal for a bit already in the
/// body is left out (node/miner.cpp:728-735). Returns, for every tx of the
/// body, the reason it must leave (empty: it stays).
inline std::vector<std::string> mnhf_select(const std::vector<MutableTransaction>& body,
                                            const MnhfCheckEnv* env, uint32_t prev_height, int64_t mtp_prev)
{
    std::vector<std::string> why(body.size());
    std::set<uint8_t> bits;
    for (size_t i = 0; i < body.size(); ++i) {
        if (body[i].type != vendor::MNHFTxPayload::SPECIALTX_TYPE) continue;
        if (auto r = mnhf_tx_refusal(body[i], env, prev_height, mtp_prev)) {
            why[i] = *r;
            continue;
        }
        const auto bit = extract_ehf_signal(body[i]);
        if (!bit || !bits.insert(*bit).second)
            why[i] = "bad-mnhf-duplicates-in-block (a signal for bit "
                   + std::to_string(bit ? *bit : 0) + " is already in this block)";
    }
    return why;
}

} // namespace coin
} // namespace dash
