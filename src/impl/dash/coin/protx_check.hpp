// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core's full provider-tx checks, for template selection.
///
/// Before a provider tx (types 1-4) rides a template we build, it must pass
/// what Dash Core v24 runs on it in TestPackageTransactions / ConnectBlock:
///
///   CheckProRegTx, CheckProUpServTx, CheckProUpRegTx, CheckProUpRevTx
///   (src/evo/specialtxman.cpp), with GetValidatedPayload, every
///   IsTriviallyValid, IsPayoutListTriviallyValid, IsPayoutListKeySafe,
///   CheckProviderNetworkFields / MnNetInfo::ValidateService
///   (src/evo/providertx.cpp, src/evo/netinfo.cpp), CheckInputsHash
///   (src/evo/providertx.h), and the three signature checks: the collateral
///   key's message signature over MakeSignString (ProRegTx with an external
///   collateral), the owner key's hash signature (ProUpRegTx), and the
///   operator's BLS signature (ProUpServTx / ProUpRevTx; that one stays in
///   the template fold, sml_special_fold.hpp, which already verifies it).
///
/// The duplicate-key / duplicate-address / platformNodeID uniqueness rules and
/// the "update names a listed masternode" rules also stay in the template
/// fold, which sees the in-body changes as well as the pre-block list.
///
/// Scope of this port: every payload version of types 2-4 (version 3 payloads
/// through the S2 payload rules of v24_rules.hpp, plus CheckProUpServTx's
/// ApplyProUpServTx dry run, CheckProUpRegTx's shared refusal, payout list
/// and SetStateVersion dry run); type 1 at every version: a version-3
/// ProRegTx (ExtAddr, every shared registration) with its payout-list sign
/// string (MakeSignString) or every share owner's consent signature over
/// MakeSharedRegConsentHash (proreg_v3_refusal). The
/// v24 provider types 10-12 are checked in full (CheckProDisTx,
/// CheckProUpShareTx, CheckProUpSharedRegTx, specialtxman.cpp:1625-1875):
/// the payload rules through v24_rules.hpp provider_payload_refusal
/// (GetValidatedPayload and the too-early gate), then the masternode-list
/// rules against the pre-block list, the inputs hash, and every share owner's
/// canonical ECDSA signature (CHashSigner::VerifyHashCanonical).
///
/// FAIL CLOSED. A check that cannot be decided refuses the tx: an external
/// collateral the UTXO view cannot prove, a missing signature verifier, a
/// BLS build without the backend (operator keys cannot be validated), a
/// network address whose emptiness Core and the fold would judge differently.
/// The caller excludes the tx; nothing else changes.

#include <impl/dash/coin/dash_deployments.hpp>      // DashNetwork
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>     // opkey_valid_canonical, opkey_to_basic
#include <impl/dash/coin/vendor/providertx.hpp>

#include <core/address_utils.hpp>                   // script_to_address (EncodeDestination)
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dash {
namespace coin {

/// SpecialTxRules for the block being built, plus the chain parameters the
/// network-field rules read.
struct ProTxCheckRules
{
    DashNetwork net{DashNetwork::MAINNET};
    bool v19_active{true};
    bool v24_active{false};
    /// The height of the block being built (pindexPrev->nHeight + 1): the
    /// ProDisTx early-exit period is measured to it. 0 = not known; a ProDisTx
    /// is then refused.
    uint32_t height{0};

    bool mainnet() const { return net == DashNetwork::MAINNET; }
    /// DEPLOYMENT_IPV4_OPTIONAL: height 0 on testnet and devnet, never on
    /// mainnet; regtest only through -testactivationheight.
    bool ipv4_optional() const { return net == DashNetwork::TESTNET || net == DashNetwork::DEVNET; }
    /// CChainParams::RequireRoutableExternalIP: all but regtest.
    bool require_routable() const { return net != DashNetwork::REGTEST; }
    uint8_t pkh_version() const
    {
        return (net == DashNetwork::MAINNET) ? 76 : 140;
    }
    uint8_t p2sh_version() const
    {
        return (net == DashNetwork::MAINNET) ? 16 : 19;
    }
};

/// What the chain UTXO set (at the tip) proves about a coin.
enum class ProTxCoinProof : uint8_t { Unknown, Unspent, Absent };
using ProTxCoinFn = std::function<ProTxCoinProof(const bitcoin_family::coin::TxPrevOut&,
                                                 int64_t& value, std::vector<uint8_t>& script)>;

/// CHashSigner::VerifyHash: recover the signer of a 65-byte compact ECDSA
/// signature over `hash` and compare its key ID.
using ProTxEcdsaVerifyFn = std::function<bool(const uint256& hash, const std::vector<uint8_t>& sig,
                                              const uint160& key_id)>;

/// What the node wires once (main_dash): the network and the ECDSA verifier.
/// Unset ecdsa => txs that need it (an external-collateral ProRegTx, every
/// ProUpRegTx) are refused.
struct ProTxCheckEnv
{
    DashNetwork        net{DashNetwork::MAINNET};
    ProTxEcdsaVerifyFn ecdsa;
    /// Replaces protx_core_refusal entirely. Only for unit tests of the
    /// fold's own rules (ordering, replacement) with synthetic provider txs;
    /// c2pool-dash never sets it.
    std::function<std::optional<std::string>(const MutableTransaction&)> check_override;
};

/// DEPLOYMENT_V19 buried heights (chainparams.cpp).
inline bool protx_v19_active_at(DashNetwork net, uint32_t height)
{
    switch (net) {
    case DashNetwork::MAINNET: return height >= 1'899'072;
    case DashNetwork::TESTNET: return height >= 850'100;
    case DashNetwork::DEVNET:  return height >= 2;
    case DashNetwork::REGTEST: return height >= 1;
    }
    return false;
}

inline ProTxCheckRules protx_rules_for(const ProTxCheckEnv& env, uint32_t height, bool v24_active)
{
    ProTxCheckRules r;
    r.net = env.net;
    r.v19_active = protx_v19_active_at(env.net, height);
    r.v24_active = v24_active;
    r.height = height;
    return r;
}

namespace protx_check_detail {

inline constexpr int64_t kCollateralRegular = 1000LL * 100'000'000LL;
inline constexpr int64_t kCollateralEvo     = 4000LL * 100'000'000LL;
inline constexpr uint16_t kMainnetPort      = 9999;
inline constexpr uint16_t kMainnetPlatformP2PPort  = 26656;
inline constexpr uint16_t kMainnetPlatformHTTPPort = 443;

using Refusal = std::optional<std::string>;
inline Refusal no(std::string why) { return Refusal{std::move(why)}; }

// ── scripts and destinations ────────────────────────────────────────────────

inline bool is_p2pkh(const std::vector<uint8_t>& s)
{
    return s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac;
}
inline bool is_p2sh(const std::vector<uint8_t>& s)
{
    return s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87;
}

/// CTxDestination for the script forms ExtractDestination answers and the
/// ProTx rules compare (PKHash / ScriptHash). P2PK yields PKHash of the key.
struct Dest
{
    enum Kind : uint8_t { PKH, SH } kind{PKH};
    uint160 hash;
    bool operator==(const Dest& o) const { return kind == o.kind && hash == o.hash; }
};

inline uint160 hash160(const uint8_t* p, size_t n)
{
    uint160 h;
    CHash160().Write(std::span<const unsigned char>(p, n)).Finalize(std::span<unsigned char>(h.data(), 20));
    return h;
}

inline std::optional<Dest> extract_dest(const std::vector<uint8_t>& s)
{
    Dest d;
    if (is_p2pkh(s)) {
        d.kind = Dest::PKH;
        std::copy(s.begin() + 3, s.begin() + 23, d.hash.data());
        return d;
    }
    if (is_p2sh(s)) {
        d.kind = Dest::SH;
        std::copy(s.begin() + 2, s.begin() + 22, d.hash.data());
        return d;
    }
    // P2PK: <33-byte compressed or 65-byte uncompressed key> OP_CHECKSIG.
    if (s.size() == 35 && s[0] == 33 && (s[1] == 0x02 || s[1] == 0x03) && s[34] == 0xac) {
        d.kind = Dest::PKH;
        d.hash = hash160(s.data() + 1, 33);
        return d;
    }
    if (s.size() == 67 && s[0] == 65 && s[1] == 0x04 && s[66] == 0xac) {
        d.kind = Dest::PKH;
        d.hash = hash160(s.data() + 1, 65);
        return d;
    }
    return std::nullopt;
}

inline Dest pkh(const uint160& k) { return Dest{Dest::PKH, k}; }

/// EncodeDestination for MakeSignString.
inline std::string encode_pkh(const uint160& k, uint8_t ver)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), k.data(), k.data() + 20);
    s.push_back(0x88);
    s.push_back(0xac);
    return core::script_to_address(s, "", ver, 0);
}

// ── hashes ──────────────────────────────────────────────────────────────────

inline uint256 sha256d(const uint8_t* p, size_t n)
{
    uint256 h;
    CHash256().Write(std::span<const unsigned char>(p, n)).Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

/// CalcTxInputsHash: SHA256d over every input's prevout (hash, n LE).
template <typename Tx>
inline uint256 inputs_hash(const Tx& tx)
{
    std::vector<uint8_t> buf;
    buf.reserve(tx.vin.size() * 36);
    for (const auto& in : tx.vin) {
        buf.insert(buf.end(), in.prevout.hash.data(), in.prevout.hash.data() + 32);
        const uint32_t n = in.prevout.index;
        for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>(n >> (8 * i)));
    }
    return sha256d(buf.data(), buf.size());
}

inline size_t compact_size_len(size_t n)
{
    return n < 253 ? 1 : n <= 0xffff ? 3 : n <= 0xffffffffu ? 5 : 9;
}

/// ::SerializeHash(proTx) for a payload whose LAST field is the vchSig byte
/// vector (ProRegTx, ProUpRegTx): SER_GETHASH drops that field.
inline std::optional<uint256> hash_without_trailing_vchsig(const std::vector<uint8_t>& payload,
                                                           size_t sig_len)
{
    const size_t tail = compact_size_len(sig_len) + sig_len;
    if (payload.size() < tail) return std::nullopt;
    return sha256d(payload.data(), payload.size() - tail);
}

inline void write_varstr(std::vector<uint8_t>& out, const std::string& s)
{
    const size_t n = s.size();
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(253);
        out.push_back(static_cast<uint8_t>(n & 0xff));
        out.push_back(static_cast<uint8_t>(n >> 8));
    } else {
        out.push_back(254);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    }
    out.insert(out.end(), s.begin(), s.end());
}

/// util/message.cpp MessageHash: SHA256d(varstr(MESSAGE_MAGIC) || varstr(msg)).
inline uint256 message_hash(const std::string& msg)
{
    std::vector<uint8_t> buf;
    write_varstr(buf, "DarkCoin Signed Message:\n");
    write_varstr(buf, msg);
    return sha256d(buf.data(), buf.size());
}

// ── network fields (MnNetInfo, the 18-byte legacy CService) ─────────────────

/// How Core reads a legacy service. Core's MnNetInfo::Unserialize keeps the
/// CService only when CNetAddr::IsValid, so a non-zero but invalid address is
/// an empty netInfo. The folds read it the same way since #2147
/// (LegacyNetService::IsEmpty). Selection still leaves such a provider tx out
/// (Ambiguous): stricter than Core, never an invalid block.
enum class ServiceKind : uint8_t { Empty, IPv4, Ambiguous };

struct Ipv4 { uint8_t a, b, c, d; };

inline ServiceKind classify_service(const vendor::LegacyNetService& n, Ipv4& out)
{
    bool all_zero = n.port_be == 0;
    for (uint8_t x : n.ip) if (x != 0) { all_zero = false; break; }
    if (all_zero) return ServiceKind::Empty;
    for (int i = 0; i < 10; ++i)
        if (n.ip[i] != 0) return ServiceKind::Ambiguous;   // not IPv4-mapped
    if (n.ip[10] != 0xff || n.ip[11] != 0xff) return ServiceKind::Ambiguous;
    out = Ipv4{n.ip[12], n.ip[13], n.ip[14], n.ip[15]};
    const bool any  = out.a == 0 && out.b == 0 && out.c == 0 && out.d == 0;
    const bool none = out.a == 255 && out.b == 255 && out.c == 255 && out.d == 255;
    if (any || none) return ServiceKind::Ambiguous;          // !IsValid: empty for Core only
    return ServiceKind::IPv4;
}

/// CNetAddr::IsRoutable for an IPv4 address (IsValid already holds).
inline bool ipv4_routable(const Ipv4& ip)
{
    if (ip.a == 10) return false;                                          // RFC1918
    if (ip.a == 192 && ip.b == 168) return false;                          // RFC1918
    if (ip.a == 172 && ip.b >= 16 && ip.b <= 31) return false;             // RFC1918
    if (ip.a == 198 && (ip.b == 18 || ip.b == 19)) return false;           // RFC2544
    if (ip.a == 169 && ip.b == 254) return false;                          // RFC3927
    if (ip.a == 100 && (ip.b & 0xc0) == 64) return false;                  // RFC6598
    if (ip.a == 192 && ip.b == 0 && ip.c == 2) return false;               // RFC5737
    if (ip.a == 198 && ip.b == 51 && ip.c == 100) return false;            // RFC5737
    if (ip.a == 203 && ip.b == 0 && ip.c == 113) return false;             // RFC5737
    if (ip.a == 127 || ip.a == 0) return false;                            // IsLocal
    return true;
}

/// CheckProviderNetworkFields for a version 1/2 payload (MnNetInfo).
inline Refusal network_fields_refusal(const vendor::LegacyNetService& net, uint8_t nType,
                                      const uint160& platform_node_id, uint16_t platform_p2p_port,
                                      uint16_t platform_http_port, bool allow_empty,
                                      const ProTxCheckRules& rules)
{
    Ipv4 ip{};
    const ServiceKind kind = classify_service(net, ip);
    if (kind == ServiceKind::Ambiguous)
        return no("bad-protx-netinfo-addr (invalid address the fold and Core would read differently)");
    if (kind == ServiceKind::Empty) {
        if (!allow_empty) return no("bad-protx-netinfo-empty");
    } else {
        // MnNetInfo::ValidateService: IsValid and IsIPv4 hold here.
        if (rules.require_routable() && !ipv4_routable(ip)) return no("bad-protx-netinfo-addr-unroutable");
        if (rules.mainnet() != (net.port_be == kMainnetPort)) return no("bad-protx-netinfo-port");
        // CheckIPv4Primaries: the primary is IPv4.
    }
    if (nType != vendor::MnType::EVO) return std::nullopt;
    if (platform_node_id.IsNull()) return no("bad-protx-platform-nodeid");
    if (rules.mainnet()) {
        if (platform_p2p_port != kMainnetPlatformP2PPort) return no("bad-protx-platform-p2p-port");
        if (platform_http_port != kMainnetPlatformHTTPPort) return no("bad-protx-platform-http-port");
    }
    if (platform_p2p_port == kMainnetPort) return no("bad-protx-platform-p2p-port");
    if (platform_http_port == kMainnetPort) return no("bad-protx-platform-http-port");
    const uint16_t core_port = kind == ServiceKind::Empty ? 0 : net.port_be;
    if (platform_p2p_port == platform_http_port || platform_p2p_port == core_port
        || platform_http_port == core_port)
        return no("bad-protx-platform-dup-ports");
    return std::nullopt;
}

/// IsPayoutListTriviallyValid for a v1/v2 payload's [scriptPayout, 10000].
inline Refusal payout_refusal(const std::vector<uint8_t>& script, const uint160& owner,
                              const uint160& voting)
{
    if (!is_p2pkh(script) && !is_p2sh(script)) return no("bad-protx-payee");
    const auto dest = extract_dest(script);
    if (!dest) return no("bad-protx-payee-dest");
    if ((!owner.IsNull() && *dest == pkh(owner)) || *dest == pkh(voting))
        return no("bad-protx-payee-reuse");
    return std::nullopt;
}

/// ProTxVersion::GetMax.
inline uint16_t max_version(const ProTxCheckRules& r)
{
    if (!r.v19_active) return vendor::ProTxVersion::LEGACY_BLS;
    return r.v24_active ? vendor::ProTxVersion::EXT_ADDR : vendor::ProTxVersion::BASIC_BLS;
}

/// The codec this check is defined over reads versions 1 and 2 only.
inline Refusal codec_version_refusal(uint16_t v)
{
    if (v == 0 || v > vendor::ProTxVersion::EXT_ADDR) return no("bad-protx-version");
    if (v >= vendor::ProTxVersion::EXT_ADDR)
        return no("bad-protx-version (ExtAddr payload: not checkable by this codec, excluded)");
    return std::nullopt;
}

/// IsVersionChangeValid (v24 only).
inline Refusal version_change_refusal(uint16_t state_version, uint16_t tx_version, const ProTxCheckRules& r)
{
    if (!r.v24_active) return std::nullopt;
    if (state_version >= vendor::ProTxVersion::BASIC_BLS && tx_version == vendor::ProTxVersion::LEGACY_BLS)
        return no("bad-protx-version-downgrade");
    return std::nullopt;
}

/// CDeterministicMNList::HasOperatorKeyUnderAnyScheme: the store keeps every
/// operator key canonically in the basic scheme, so one point is one byte
/// string here.
inline bool operator_key_held_by_other(const MnStateMachine& pre,
                                       const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& basic,
                                       const uint256& self)
{
    for (const auto& [pro, st] : pre.entries())
        if (pro != self && st.pubKeyOperator == basic) return true;
    return false;
}

template <typename T>
inline bool parse(const std::vector<uint8_t>& payload, T& out)
{
    return vendor::parse_protx_payload(payload, out);
}

inline const MNState* find_mn(const MnStateMachine& pre, const uint256& pro)
{
    auto it = pre.entries().find(pro);
    return it == pre.entries().end() ? nullptr : &it->second;
}

/// CHashSigner::VerifyHashCanonical (messagesigner.cpp:58-90): 65 bytes, a
/// recovery header SignCompact can produce (27..34), low S, then VerifyHash.
template <typename Sig>
inline bool verify_hash_canonical(const ProTxEcdsaVerifyFn& ecdsa, const uint256& hash, const Sig& sig,
                                  const uint160& key_id)
{
    static constexpr uint8_t kHalfOrder[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    };
    if (!ecdsa) return false;
    if (sig.size() != vendor::COMPACT_SIGNATURE_SIZE) return false;
    if (sig[0] < 27 || sig[0] > 34) return false;
    if (std::memcmp(sig.data() + 33, kHalfOrder, 32) > 0) return false;
    return ecdsa(hash, std::vector<uint8_t>(sig.begin(), sig.end()), key_id);
}

/// ::SerializeHash(proTx) of a CProUpSharedRegTx / CProDisTx-style payload
/// whose LAST field is `u8 count || 65-byte sig * count` (excluded under
/// SER_GETHASH).
inline std::optional<uint256> hash_without_trailing_sig_list(const std::vector<uint8_t>& payload,
                                                             size_t sig_count)
{
    const size_t tail = 1 + sig_count * vendor::COMPACT_SIGNATURE_SIZE;
    if (payload.size() < tail) return std::nullopt;
    return sha256d(payload.data(), payload.size() - tail);
}

/// CProDisTx::MakeSignHash (providertx.cpp:546-573): SHA256d over the
/// domain tag, the payload version, the tx's version, type and lock time, its
/// prevouts, its sequences, its outputs, then proTxHash, actorIndex and the
/// signature count.
template <typename Tx>
inline uint256 prodis_sign_hash(const Tx& tx, const vendor::CProDisTx& p, uint8_t sig_count)
{
    static constexpr std::string_view kTag{"DashSharedMNDissolve"};
    ::PackStream s;
    WriteCompactSize(s, kTag.size());
    s.write(std::as_bytes(std::span{kTag.data(), kTag.size()}));
    s << p.nVersion;
    s << static_cast<uint16_t>(tx.version & 0xFFFF);   // CTransaction::nVersion (int16)
    s << tx.type;
    s << tx.locktime;
    for (const auto& in : tx.vin) s << in.prevout;
    for (const auto& in : tx.vin) s << in.sequence;
    for (const auto& out : tx.vout) s << out;
    s << p.proTxHash;
    s << p.actorIndex;
    s << sig_count;
    auto sp = s.get_span();
    return sha256d(reinterpret_cast<const uint8_t*>(sp.data()), sp.size());
}

/// The provider payload rules (v24_rules.hpp) for the block being built,
/// with the header-only BLS encoding checks (this path is compiled into
/// every target that includes the embedded builder, not only those linking
/// dash_bls_verify). Aggregate-initialized in full: a default-constructed
/// BlsEncodingChecks would name the exported functions.
inline ProviderTxRules provider_rules_of(const ProTxCheckRules& r)
{
    return ProviderTxRules{r.v19_active, r.v24_active, /*evo_shares_active=*/false, r.ipv4_optional(),
                           netinfo_rules_for(r.net), vendor::bls_encoding_checks_inline()};
}

/// What CheckProDisTxForList reads from the masternode a ProDisTx names.
inline v24::ProDisTarget prodis_target_of(const MNState& st)
{
    v24::ProDisTarget t;
    t.exists = true;
    t.shared = st.v24.IsShared();
    t.collateral = st.collateralOutpoint;
    t.shares = &st.v24.shares;
    t.registered_height = st.nRegisteredHeight;
    t.early_period_blocks = st.v24.nEarlyPeriodBlocks;
    t.early_penalty = st.v24.nEarlyPenalty;
    return t;
}

/// CProRegTx::MakeSharedRegConsentHash (providertx.cpp:380-418): the digest
/// every share owner signs (vchJoinSigs) - the domain tag, the payload
/// version, the tx's version, type and lock time, its inputs hash and
/// sequences, its outputs hash, then the registrar configuration, the share
/// table and the penalty terms.
template <typename Tx>
inline uint256 shared_reg_consent_hash(const Tx& tx, const vendor::CProRegTx& p)
{
    static constexpr std::string_view kTag{"DashSharedMNReg"};
    ::PackStream s;
    WriteCompactSize(s, kTag.size());
    s.write(std::as_bytes(std::span{kTag.data(), kTag.size()}));
    s << p.nVersion;
    s << static_cast<uint16_t>(tx.version & 0xFFFF);   // CTransaction::nVersion (int16)
    s << tx.type;
    s << tx.locktime;
    s << inputs_hash(tx);
    for (const auto& in : tx.vin) s << in.sequence;
    {
        ::PackStream outs;   // CalcTxOutputsHash
        for (const auto& out : tx.vout) outs << out;
        auto sp = outs.get_span();
        s << sha256d(reinterpret_cast<const uint8_t*>(sp.data()), sp.size());
    }
    s << p.nType;
    s << p.nMode;
    if (p.nVersion >= vendor::ProTxVersion::EXT_ADDR) s << p.extNetInfo; else s << p.netInfo;
    if (p.nType == vendor::MnType::EVO) s << p.platformNodeID;
    s << p.keyIDVoting;
    s.write(std::as_bytes(std::span{p.pubKeyOperator.data(), p.pubKeyOperator.size()}));
    s << p.nOperatorReward;
    s << static_cast<uint8_t>(p.shares.size());
    for (const auto& sh : p.shares) s << sh;
    s << p.nEarlyPeriodBlocks;
    s << p.nEarlyPenalty;
    auto sp = s.get_span();
    return sha256d(reinterpret_cast<const uint8_t*>(sp.data()), sp.size());
}

/// EncodeDestination of a P2PKH / P2SH script, else HexStr (PayoutListToString).
inline std::string dest_or_hex(const std::vector<uint8_t>& script, const ProTxCheckRules& rules)
{
    if (is_p2pkh(script) || is_p2sh(script))
        return core::script_to_address(script, "", rules.pkh_version(), rules.p2sh_version());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : script) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 15]);
    }
    return out;
}

/// PayoutListToString(MasternodePayoutShares) (providertx_util.cpp:24-34).
inline std::string payout_list_to_string(const vendor::MasternodePayoutShares& payouts, const ProTxCheckRules& rules)
{
    std::string ret;
    for (const auto& p : payouts) {
        if (!ret.empty()) ret += ",";
        ret += dest_or_hex(p.scriptPayout.m_data, rules) + ":" + std::to_string(p.reward);
    }
    return ret;
}

/// CheckProRegTx for a version-3 payload (ExtAddr; every shared
/// registration), specialtxman.cpp:1208-1384, with the payload rules of
/// v24_rules.hpp (GetValidatedPayload, the v24 version rules, the EvoNode
/// share rules, CheckProviderNetworkFields over ExtNetInfo). The masternode
/// list uniqueness rules (netInfo entries, owner and share owner keys,
/// operator key, platformNodeID) are the template fold's, over the pre-block
/// list and the body.
template <typename Tx>
inline Refusal proreg_v3_refusal(const Tx& tx, const vendor::CProRegTx& p, const MnStateMachine& pre,
                                 const ProTxCheckRules& rules, const ProTxCoinFn& coin,
                                 const ProTxEcdsaVerifyFn& ecdsa)
{
    if (auto r = provider_payload_refusal(vendor::CProRegTx::SPECIALTX_TYPE, tx.extra_payload,
                                          provider_rules_of(rules)))
        return r;
    const int64_t want = p.nType == vendor::MnType::EVO ? kCollateralEvo : kCollateralRegular;
    std::optional<Dest> collateral_dest;
    const bool external = !p.collateralOutpoint.hash.IsNull();
    if (external) {
        if (!coin) return no("bad-protx-collateral (no UTXO view to prove the coin)");
        int64_t value = 0;
        std::vector<uint8_t> script;
        const auto proof = coin(p.collateralOutpoint, value, script);
        if (proof == ProTxCoinProof::Unknown) return no("bad-protx-collateral (the UTXO view cannot prove the coin)");
        if (proof == ProTxCoinProof::Absent || value != want) return no("bad-protx-collateral");
        collateral_dest = extract_dest(script);
        if (!collateral_dest) return no("bad-protx-collateral-dest");
        if (collateral_dest->kind != Dest::PKH) return no("bad-protx-collateral-pkh");
    } else {
        if (p.collateralOutpoint.index >= tx.vout.size()) return no("bad-protx-collateral-index");
        const auto& out = tx.vout[p.collateralOutpoint.index];
        if (out.value != want) return no("bad-protx-collateral");
        if (p.IsShared()) {
            if (!v24::is_shared_collateral_script(out.scriptPubKey.m_data))
                return no("bad-protx-shares-collateral-script");
        } else {
            collateral_dest = extract_dest(out.scriptPubKey.m_data);
            if (!collateral_dest) return no("bad-protx-collateral-dest");
        }
    }
    // IsPayoutListKeySafe (version 3: no payout may pay the collateral key).
    if (!p.IsShared()) {
        if (*collateral_dest == pkh(p.keyIDOwner) || *collateral_dest == pkh(p.keyIDVoting))
            return no("bad-protx-collateral-reuse");
        for (const auto& po : p.payouts) {
            const auto d = extract_dest(po.scriptPayout.m_data);
            if (d && *d == *collateral_dest) return no("bad-protx-payee-reuse");
        }
    }
    if (rules.v24_active
        && operator_key_held_by_other(pre, vendor::opkey_to_basic(p.pubKeyOperator, /*legacy=*/false), uint256{}))
        return no("bad-protx-dup-key (operator key under another scheme)");
    if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
    if (external) {
        // CheckStringSig over MakeSignString: the payout list, the operator
        // reward, the owner and voting addresses, the payload hash.
        if (!ecdsa) return no("bad-protx-sig (no ECDSA verifier wired)");
        const auto h = hash_without_trailing_vchsig(tx.extra_payload, p.vchSig.size());
        if (!h) return no("bad-protx-sig");
        const std::string sign_string = payout_list_to_string(p.payouts, rules)
                                      + "|" + std::to_string(p.nOperatorReward)
                                      + "|" + encode_pkh(p.keyIDOwner, rules.pkh_version())
                                      + "|" + encode_pkh(p.keyIDVoting, rules.pkh_version())
                                      + "|" + h->GetHex();
        if (!ecdsa(message_hash(sign_string), p.vchSig, collateral_dest->hash)) return no("bad-protx-sig");
        return std::nullopt;
    }
    if (!p.vchSig.empty()) return no("bad-protx-sig");
    if (p.IsShared()) {
        // Every share owner consents to the exact funding inputs, outputs,
        // share table, penalty terms and registrar configuration.
        if (p.vchJoinSigs.size() != p.shares.size()) return no("bad-protx-shares-sig");
        const uint256 consent = shared_reg_consent_hash(tx, p);
        for (size_t i = 0; i < p.shares.size(); ++i)
            if (!verify_hash_canonical(ecdsa, consent, p.vchJoinSigs[i], p.shares[i].keyIDOwner))
                return no("bad-protx-shares-sig");
    }
    return std::nullopt;
}

} // namespace protx_check_detail

/// The first reason Dash Core v24 refuses this provider tx for a block built
/// on `pre` (the masternode list at the tip), or nullopt when every rule this
/// file ports passes. Non-provider txs pass (nullopt).
template <typename Tx>
inline std::optional<std::string>
protx_core_refusal(const Tx& tx_in, const MnStateMachine& pre, const ProTxCheckRules& rules,
                   const ProTxCoinFn& coin, const ProTxEcdsaVerifyFn& ecdsa)
{
    using namespace protx_check_detail;
    namespace pv = vendor::ProTxVersion;
    const MutableTransaction tx(tx_in);
    if ((tx.type < 1 || tx.type > 4) && !tx_type_is_v24_provider(tx.type)) return std::nullopt;

    switch (tx.type) {
    case vendor::CProRegTx::SPECIALTX_TYPE: {
        vendor::CProRegTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        if (p.nVersion >= pv::EXT_ADDR || p.IsShared()) return proreg_v3_refusal(tx, p, pre, rules, coin, ecdsa);
        if (auto r = codec_version_refusal(p.nVersion)) return r;
        if (p.nVersion > max_version(rules)) return no("bad-protx-version");
        // CProRegTx::IsTriviallyValid
        if (p.nVersion < pv::BASIC_BLS && p.nType == vendor::MnType::EVO) return no("bad-protx-evo-version");
        if (p.nType != vendor::MnType::REGULAR && p.nType != vendor::MnType::EVO) return no("bad-protx-type");
        if (p.nMode != 0) return no("bad-protx-mode");
        if (p.keyIDOwner.IsNull()) return no("bad-protx-key-null");
        if (!vendor::opkey_valid_canonical(p.pubKeyOperator, p.nVersion == pv::LEGACY_BLS)
            || p.keyIDVoting.IsNull())
            return no("bad-protx-key-null");
        if (auto r = payout_refusal(p.scriptPayout.m_data, p.keyIDOwner, p.keyIDVoting)) return r;
        if (p.nOperatorReward > 10000) return no("bad-protx-operator-reward");
        // CheckProRegTx
        if (rules.v24_active && p.nVersion < pv::BASIC_BLS) return no("bad-protx-version-disallowed");
        if (auto r = network_fields_refusal(p.netInfo, p.nType, p.platformNodeID, p.platformP2PPort,
                                            p.platformHTTPPort, /*allow_empty=*/true, rules))
            return r;
        const int64_t want = p.nType == vendor::MnType::EVO ? kCollateralEvo : kCollateralRegular;
        std::optional<Dest> collateral_dest;
        bool external = !p.collateralOutpoint.hash.IsNull();
        if (external) {
            if (!coin) return no("bad-protx-collateral (no UTXO view to prove the coin)");
            int64_t value = 0;
            std::vector<uint8_t> script;
            const auto proof = coin(p.collateralOutpoint, value, script);
            if (proof == ProTxCoinProof::Unknown)
                return no("bad-protx-collateral (the UTXO view cannot prove the coin)");
            if (proof == ProTxCoinProof::Absent || value != want) return no("bad-protx-collateral");
            collateral_dest = extract_dest(script);
            if (!collateral_dest) return no("bad-protx-collateral-dest");
            if (collateral_dest->kind != Dest::PKH) return no("bad-protx-collateral-pkh");
        } else {
            if (p.collateralOutpoint.index >= tx.vout.size()) return no("bad-protx-collateral-index");
            const auto& out = tx.vout[p.collateralOutpoint.index];
            if (out.value != want) return no("bad-protx-collateral");
            collateral_dest = extract_dest(out.scriptPubKey.m_data);
            if (!collateral_dest) return no("bad-protx-collateral-dest");
        }
        // IsPayoutListKeySafe (payout reuse of the collateral is v3 only).
        if (*collateral_dest == pkh(p.keyIDOwner) || *collateral_dest == pkh(p.keyIDVoting))
            return no("bad-protx-collateral-reuse");
        if (rules.v24_active
            && operator_key_held_by_other(pre, vendor::opkey_to_basic(p.pubKeyOperator,
                                                                      p.nVersion == pv::LEGACY_BLS),
                                          uint256{}))
            return no("bad-protx-dup-key (operator key under another scheme)");
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        if (external) {
            if (!ecdsa) return no("bad-protx-sig (no ECDSA verifier wired)");
            const auto h = hash_without_trailing_vchsig(tx.extra_payload, p.vchSig.size());
            if (!h) return no("bad-protx-sig");
            const std::string sign_string =
                core::script_to_address(p.scriptPayout.m_data, "", rules.pkh_version(), rules.p2sh_version())
                + "|" + std::to_string(p.nOperatorReward)
                + "|" + encode_pkh(p.keyIDOwner, rules.pkh_version())
                + "|" + encode_pkh(p.keyIDVoting, rules.pkh_version())
                + "|" + h->GetHex();
            if (!ecdsa(message_hash(sign_string), p.vchSig, collateral_dest->hash))
                return no("bad-protx-sig");
        } else if (!p.vchSig.empty()) {
            return no("bad-protx-sig");
        }
        return std::nullopt;
    }

    case vendor::CProUpServTx::SPECIALTX_TYPE: {
        vendor::CProUpServTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        if (p.nVersion >= pv::EXT_ADDR) {
            // A version-3 (ExtNetInfo) payload: GetValidatedPayload and
            // CheckProviderNetworkFields through the S2 payload rules
            // (v24_rules.hpp), which read ExtNetInfo exactly as Core does.
            if (p.nVersion > max_version(rules)) return no("bad-protx-version");
            if (auto r = provider_payload_refusal(tx.type, tx.extra_payload, provider_rules_of(rules))) return r;
        } else {
            if (!vendor::blssig_parses_canonical(p.sig, p.nVersion == pv::LEGACY_BLS))
                return no("bad-protx-payload (malleable BLS signature)");
            if (auto r = codec_version_refusal(p.nVersion)) return r;
            if (p.nVersion > max_version(rules)) return no("bad-protx-version");
            // CProUpServTx::IsTriviallyValid
            if (p.nVersion < pv::BASIC_BLS && p.nType == vendor::MnType::EVO) return no("bad-protx-evo-version");
            if (p.nType != vendor::MnType::REGULAR && p.nType != vendor::MnType::EVO) return no("bad-protx-type");
            {
                Ipv4 ip{};
                if (classify_service(p.netInfo, ip) == ServiceKind::Empty) return no("bad-protx-netinfo-empty");
            }
            // CheckProUpServTx
            if (auto r = network_fields_refusal(p.netInfo, p.nType, p.platformNodeID, p.platformP2PPort,
                                                p.platformHTTPPort, /*allow_empty=*/false, rules))
                return r;
        }
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-protx-hash");
        if (p.nType != mn->nType) return no("bad-protx-type-mismatch");
        if (!rules.v24_active && mn->nVersion >= pv::EXT_ADDR)
            return no("bad-protx-version (ExtAddr state before DEPLOYMENT_V24)");
        if (auto r = version_change_refusal(mn->nVersion, p.nVersion, rules)) return r;
        if (rules.v24_active && p.nType == vendor::MnType::EVO && p.nVersion < pv::EXT_ADDR)
            return no("bad-protx-version-disallowed");
        // v24: ApplyProUpServTx on a copy of the pre-block state (the state
        // version raise and the netInfo conversion must succeed).
        if (rules.v24_active) {
            MNState copy = *mn;
            const auto t = v24::apply_proupserv(copy, p, mn->nType, netinfo_rules_for(rules.net));
            if (t.error) return no(*t.error);
        }
        // v24: a legacy -> basic migration re-keys the stored operator key.
        if (rules.v24_active && mn->nVersion == pv::LEGACY_BLS && p.nVersion >= pv::BASIC_BLS
            && operator_key_held_by_other(pre, mn->pubKeyOperator, p.proTxHash))
            return no("bad-protx-dup-key");
        if (!p.scriptOperatorPayout.m_data.empty()) {
            if (mn->nOperatorReward == 0) return no("bad-protx-operator-payee");
            if (!is_p2pkh(p.scriptOperatorPayout.m_data) && !is_p2sh(p.scriptOperatorPayout.m_data))
                return no("bad-protx-operator-payee");
        }
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        return std::nullopt;   // the BLS operator signature: the template fold
    }

    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        if (p.nVersion >= pv::EXT_ADDR) {
            // A version-3 payload (payout list): GetValidatedPayload through
            // the S2 payload rules (IsPayoutListTriviallyValid without the
            // owner key, the operator key under the basic scheme).
            if (p.nVersion > max_version(rules)) return no("bad-protx-version");
            if (auto r = provider_payload_refusal(tx.type, tx.extra_payload, provider_rules_of(rules))) return r;
        } else {
            if (auto r = codec_version_refusal(p.nVersion)) return r;
            if (p.nVersion > max_version(rules)) return no("bad-protx-version");
            // CProUpRegTx::IsTriviallyValid
            if (p.nMode != 0) return no("bad-protx-mode");
            if (!vendor::opkey_valid_canonical(p.pubKeyOperator, p.nVersion == pv::LEGACY_BLS)
                || p.keyIDVoting.IsNull())
                return no("bad-protx-key-null");
            if (auto r = payout_refusal(p.scriptPayout.m_data, uint160{}, p.keyIDVoting)) return r;
        }
        // CheckProUpRegTx
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-protx-hash");
        // Shared masternodes are updated by ProUpShareTx / ProUpSharedRegTx only.
        if (mn->v24.IsShared()) return no("bad-protx-shared-mn");
        if (!rules.v24_active && mn->nVersion >= pv::EXT_ADDR)
            return no("bad-protx-version (ExtAddr state before DEPLOYMENT_V24)");
        if (auto r = version_change_refusal(mn->nVersion, p.nVersion, rules)) return r;
        if (rules.v24_active) {
            const auto new_basic = vendor::opkey_to_basic(p.pubKeyOperator, p.nVersion == pv::LEGACY_BLS);
            const bool key_changed = new_basic != mn->pubKeyOperator;
            const bool migrating = mn->nVersion == pv::LEGACY_BLS && p.nVersion >= pv::BASIC_BLS;
            if ((key_changed || migrating) && operator_key_held_by_other(pre, new_basic, p.proTxHash))
                return no("bad-protx-dup-key");
            // Dash Core v24 CheckProUpRegTx: without a key change the stored
            // addresses are carried into max(state, tx) version
            // (SetStateVersion -> AddNetInfoEntries -> ValidateService). A
            // legacy -> basic migration re-validates the STORED core service
            // and refuses the tx if it no longer validates (an empty service
            // has no entry to add). Only a version-1 state migrates here: a
            // version-3 state is refused above.
            if (!key_changed && migrating) {
                if (auto r = network_fields_refusal(mn->netInfo, vendor::MnType::REGULAR, uint160{}, 0, 0,
                                                    /*allow_empty=*/true, rules))
                    return r;
            }
            // ... and into a version-3 target through SetStateVersion (the
            // legacy service becomes an ExtNetInfo entry; an EvoNode's
            // scalar Platform ports cannot be carried: bad-protx-netinfo-version).
            if (!key_changed) {
                MNState copy = *mn;
                if (auto e = v24::set_state_version(copy, std::max<uint16_t>(mn->nVersion, p.nVersion), mn->nType,
                                                    v24::state_has_ext(mn->nVersion), netinfo_rules_for(rules.net)))
                    return no(*e);
            }
        }
        const auto owner_payouts = p.owner_payouts();
        if (p.nVersion >= pv::EXT_ADDR) {
            if (auto r = payout_list_refusal(owner_payouts, mn->keyIDOwner, p.keyIDVoting)) return r;
        } else if (auto r = payout_refusal(p.scriptPayout.m_data, mn->keyIDOwner, p.keyIDVoting)) {
            return r;
        }
        // DEPLOYMENT_EVO_SHARES is not active under v24.0.0.
        if (mn->nType == vendor::MnType::EVO && owner_payouts.size() > 1) return no("bad-protx-payouts-evo");
        if (!coin) return no("bad-protx-collateral (no UTXO view to prove the coin)");
        int64_t value = 0;
        std::vector<uint8_t> script;
        const auto proof = coin(mn->collateralOutpoint, value, script);
        if (proof == ProTxCoinProof::Unknown)
            return no("bad-protx-collateral (the UTXO view cannot prove the coin)");
        if (proof == ProTxCoinProof::Absent) return no("bad-protx-collateral");
        const auto collateral_dest = extract_dest(script);
        if (!collateral_dest) return no("bad-protx-collateral-dest");
        if (*collateral_dest == pkh(mn->keyIDOwner) || *collateral_dest == pkh(p.keyIDVoting))
            return no("bad-protx-collateral-reuse");
        // IsPayoutListKeySafe: from a version-3 target no payout may pay the
        // collateral's destination.
        if (std::max<uint16_t>(mn->nVersion, p.nVersion) >= pv::EXT_ADDR)
            for (const auto& payout : owner_payouts)
                if (const auto d = extract_dest(payout.scriptPayout.m_data); d && *d == *collateral_dest)
                    return no("bad-protx-payee-reuse");
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        if (!ecdsa) return no("bad-protx-sig (no ECDSA verifier wired)");
        const auto h = hash_without_trailing_vchsig(tx.extra_payload, p.vchSig.size());
        if (!h || !ecdsa(*h, p.vchSig, mn->keyIDOwner)) return no("bad-protx-sig");
        return std::nullopt;
    }

    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        if (!vendor::blssig_parses_canonical(p.sig, p.nVersion == pv::LEGACY_BLS))
            return no("bad-protx-payload (malleable BLS signature)");
        // CheckProUpRevTx has no version-3 rule of its own (its payload layout
        // is the v2 one): a v3 payload, and a v3 state, are checked in full.
        if (p.nVersion == 0 || p.nVersion > pv::EXT_ADDR) return no("bad-protx-version");
        if (p.nVersion > max_version(rules)) return no("bad-protx-version");
        if (p.nReason > vendor::CProUpRevTx::REASON_CHANGE_OF_KEYS) return no("bad-protx-reason");
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-protx-hash");
        if (!rules.v24_active && mn->nVersion >= pv::EXT_ADDR)
            return no("bad-protx-version (ExtAddr state before DEPLOYMENT_V24)");
        if (auto r = version_change_refusal(mn->nVersion, p.nVersion, rules)) return r;
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        return std::nullopt;   // the BLS operator signature: the template fold
    }

    // ── Dash Core v24 shared masternodes (specialtxman.cpp:1625-1875) ────────
    case vendor::CProUpShareTx::SPECIALTX_TYPE: {
        // CheckProUpShareTx
        if (auto r = provider_payload_refusal(tx.type, tx.extra_payload, provider_rules_of(rules))) return r;
        vendor::CProUpShareTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-proupshare-hash");
        if (!mn->v24.IsShared()) return no("bad-proupshare-not-shared");
        if (p.shareIndex >= mn->v24.shares.size()) return no("bad-proupshare-index");
        const auto dest = extract_dest(p.scriptReward.m_data);
        if (!dest) return no("bad-proupshare-payee-dest");
        if (*dest == pkh(mn->keyIDVoting)) return no("bad-proupshare-payee-reuse");
        for (const auto& share : mn->v24.shares)
            if (*dest == pkh(share.keyIDOwner)) return no("bad-proupshare-payee-reuse");
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        if (!ecdsa) return no("bad-proupshare-sig (no ECDSA verifier wired)");
        const auto h = hash_without_trailing_vchsig(tx.extra_payload, p.vchSig.size());
        if (!h || !verify_hash_canonical(ecdsa, *h, p.vchSig, mn->v24.shares[p.shareIndex].keyIDOwner))
            return no("bad-proupshare-sig");
        return std::nullopt;
    }

    case vendor::CProUpSharedRegTx::SPECIALTX_TYPE: {
        // CheckProUpSharedRegTx
        if (auto r = provider_payload_refusal(tx.type, tx.extra_payload, provider_rules_of(rules))) return r;
        vendor::CProUpSharedRegTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-proupsharedreg-hash");
        if (!mn->v24.IsShared()) return no("bad-proupsharedreg-not-shared");
        if (p.vchSigs.size() != mn->v24.shares.size()) return no("bad-proupsharedreg-sig-count");
        // HasOperatorKeyUnderAnyScheme: the payload key is always basic, and
        // the store is canonical basic, so one point is one byte string.
        if (operator_key_held_by_other(pre, vendor::opkey_to_basic(p.pubKeyOperator, /*legacy=*/false),
                                       p.proTxHash))
            return no("bad-protx-dup-key");
        if (!v24::share_list_voting_key_safe(mn->v24.shares, p.keyIDVoting))
            return no("bad-proupsharedreg-payee-reuse");
        if (inputs_hash(tx) != p.inputsHash) return no("bad-protx-inputs-hash");
        if (!ecdsa) return no("bad-proupsharedreg-sig (no ECDSA verifier wired)");
        const auto h = hash_without_trailing_sig_list(tx.extra_payload, p.vchSigs.size());
        if (!h) return no("bad-proupsharedreg-sig");
        for (size_t i = 0; i < mn->v24.shares.size(); ++i)
            if (!verify_hash_canonical(ecdsa, *h, p.vchSigs[i], mn->v24.shares[i].keyIDOwner))
                return no("bad-proupsharedreg-sig");
        return std::nullopt;
    }

    case vendor::CProDisTx::SPECIALTX_TYPE: {
        // CheckProDisTx: the masternode must exist at the previous block
        // (registering and dissolving in one block is invalid), then
        // CheckProDisTxForList against that list at the new block's height.
        if (auto r = provider_payload_refusal(tx.type, tx.extra_payload, provider_rules_of(rules))) return r;
        vendor::CProDisTx p;
        if (!parse(tx.extra_payload, p)) return no("bad-protx-payload");
        const MNState* mn = find_mn(pre, p.proTxHash);
        if (!mn) return no("bad-prodis-hash");
        if (rules.height == 0) return no("bad-prodis (the height of the block being built is unknown) - excluded");
        if (auto r = v24::prodis_list_refusal(tx, p, prodis_target_of(*mn), rules.height)) return r;
        if (!ecdsa) return no("bad-prodis-sig (no ECDSA verifier wired)");
        const auto& shares = mn->v24.shares;
        const uint256 h = prodis_sign_hash(tx, p, static_cast<uint8_t>(p.vchSigs.size()));
        if (p.vchSigs.size() == shares.size()) {
            for (size_t i = 0; i < shares.size(); ++i)
                if (!verify_hash_canonical(ecdsa, h, p.vchSigs[i], shares[i].keyIDOwner))
                    return no("bad-prodis-sig");
        } else if (!verify_hash_canonical(ecdsa, h, p.vchSigs[0], shares[p.actorIndex].keyIDOwner)) {
            return no("bad-prodis-sig");
        }
        return std::nullopt;
    }
    }
    return std::nullopt;
}

} // namespace coin
} // namespace dash
