// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Provider special-transaction payloads, vendored from Dash Core
// src/evo/providertx.h. First vendored from develop cfad414 (v23.1-dev) for
// the four ProTx types; extended to Dash Core v24.0.0:
//
//   * ProTx version 3 (ProTxVersion::ExtAddr), valid once DEPLOYMENT_V24 is
//     active:
//       - netInfo is an ExtNetInfo (vendor/netinfo.hpp) instead of the
//         legacy 18-byte CService;
//       - CProRegTx / CProUpRegTx carry a payout list
//         (u8 count | {CScript scriptPayout, u16 reward}*) instead of a
//         single scriptPayout;
//       - CProRegTx also carries the share table of a shared masternode
//         (u8 count | {i64 amount, CScript scriptRefund, CScript scriptReward,
//         CKeyID keyIDOwner}*), one 65-byte join signature per share, and the
//         early-exit terms (u32 nEarlyPeriodBlocks, i64 nEarlyPenalty);
//       - EvoNode platform ports are no longer scalar fields (they live in
//         netInfo); platformNodeID stays.
//     CProUpRevTx v3 has the v2 layout.
//   * Three new special types: 10 CProDisTx, 11 CProUpShareTx and
//     12 CProUpSharedRegTx.
//
// Payload version handling. Core's ProTx SERIALIZE_METHODS stop after
// nVersion when it is 0 or above ProTxVersion::GetMax(true, true) (= 3);
// GetTxPayload then fails on the unread tail, and a payload that is only the
// version reaches IsTriviallyValid's bad-protx-version. The codecs below do
// the same, and the fold-facing parse_protx_payload() adds one rule on top:
// a version this code does not know is a FAILED parse, never a partial
// object (fail closed; a v4+ payload must refuse, not mis-parse). The
// earlier vendoring had dropped that branch and read every version with the
// v2 layout.
//
// Gating is NOT done here: decoding is purely version-driven. Whether a
// version-3 payload or a type 10-12 transaction is VALID at a height is the
// v24 rule in coin/v24_rules.hpp (ProTxVersion::GetMax and the *-too-early
// checks), which the folds apply.
//
// Adaptations from upstream:
//   1. MnType (uint16 on the wire) -> raw uint16 with REGULAR / EVO constants.
//   2. NetInfoSerWrapper -> two members: `netInfo` (LegacyNetService, read
//      and written for versions 1 and 2, byte for byte as before) and
//      `extNetInfo` (ExtNetInfo, version 3). Only the one the version selects
//      is on the wire.
//   3. CBLSLazyPublicKey -> 48 raw bytes, CBLSSignature -> 96 raw bytes,
//      CompactSignature -> 65 raw bytes. The legacy/basic BLS scheme only
//      changes how the bytes decode to a point, never their count.
//   4. CKeyID = uint160, COutPoint = TxPrevOut, CScript = OPScript (the same
//      CompactSize-prefixed bytes), CAmount = int64_t.
//   5. IsTriviallyValid() and the stateless parts of the Check*Tx functions
//      are ported separately (coin/v24_rules.hpp); ToString/ToJson and the
//      sign-string helpers are not vendored.
//   6. Signatures are carried, not verified, at this layer.

#include <impl/dash/coin/vendor/shim.hpp>
#include <impl/dash/coin/vendor/netinfo.hpp>
#include <impl/dash/coin/vendor/bls_canonical.hpp>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/opscript.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <ios>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// MnType from dashcore evo/dmn_types.h (uint16 on the wire)
namespace MnType {
    inline constexpr uint8_t REGULAR = 0;
    inline constexpr uint8_t EVO     = 1;
}

// ProTxVersion (dashcore evo/types.h)
namespace ProTxVersion {
    inline constexpr uint16_t LEGACY_BLS = 1;
    inline constexpr uint16_t BASIC_BLS  = 2;
    inline constexpr uint16_t EXT_ADDR   = 3;
    /// ProTxVersion::GetMax(is_basic_scheme_active=true, is_extended_addr=true):
    /// the highest version any ProTx codec reads past nVersion.
    inline constexpr uint16_t MAX_KNOWN  = EXT_ADDR;
    constexpr bool is_known(uint16_t v) { return v != 0 && v <= MAX_KNOWN; }
}

inline constexpr size_t BLS_PUBKEY_SIZE         = 48;
inline constexpr size_t BLS_SIG_SIZE            = 96;
inline constexpr size_t COMPACT_SIGNATURE_SIZE  = 65;   // CPubKey::COMPACT_SIGNATURE_SIZE

/// A 65-byte compact recoverable ECDSA signature, raw on the wire.
using CompactSignature = std::array<uint8_t, COMPACT_SIGNATURE_SIZE>;

namespace protx_detail {

template <typename Stream, size_t N>
inline void write_raw(Stream& s, const std::array<uint8_t, N>& a)
{
    s.write(std::as_bytes(std::span{a}));
}

template <typename Stream, size_t N>
inline void read_raw(Stream& s, std::array<uint8_t, N>& a)
{
    s.read(std::as_writable_bytes(std::span{a}));
}

template <typename Stream>
inline void write_u8(Stream& s, uint8_t v)
{
    s.write(std::as_bytes(std::span{&v, 1}));
}

template <typename Stream>
inline uint8_t read_u8(Stream& s)
{
    uint8_t v{0};
    s >> v;
    return v;
}

template <typename Stream, typename Vec>
inline void write_count_u8(Stream& s, const Vec& v)
{
    // The share, payout and signature counts travel in one byte.
    if (v.size() > 0xFF) throw std::ios_base::failure("ProTx list longer than 255 entries");
    write_u8(s, static_cast<uint8_t>(v.size()));
}

} // namespace protx_detail

// ── MasternodePayoutShare (v3 payout list entry) ──────────────────────────
struct MasternodePayoutShare
{
    static constexpr uint16_t MIN_REWARD = 100;
    static constexpr uint16_t MAX_REWARD = 10000;

    OPScript scriptPayout;
    uint16_t reward{MAX_REWARD};

    bool operator==(const MasternodePayoutShare& o) const
    {
        return scriptPayout == o.scriptPayout && reward == o.reward;
    }

    template <typename Stream>
    void Serialize(Stream& s) const { s << scriptPayout << reward; }
    template <typename Stream>
    void Unserialize(Stream& s) { s >> scriptPayout >> reward; }
};
using MasternodePayoutShares = std::vector<MasternodePayoutShare>;

/// LegacyPayoutAsList: a v1/v2 single payout script as a one-entry list.
inline MasternodePayoutShares legacy_payout_as_list(const OPScript& script)
{
    MasternodePayoutShare p;
    p.scriptPayout = script;
    p.reward = MasternodePayoutShare::MAX_REWARD;
    return {p};
}

// ── CCollateralShare (one participant of a shared masternode) ──────────────
struct CCollateralShare
{
    static constexpr int64_t COIN       = 100000000;
    static constexpr int64_t MIN_AMOUNT = 100 * COIN;

    int64_t  amount{0};
    OPScript scriptRefund;
    OPScript scriptReward;   ///< empty means "use scriptRefund"
    uint160  keyIDOwner;

    /// The script this share's portion of owner rewards is paid to.
    const OPScript& RewardScript() const
    {
        return scriptReward.m_data.empty() ? scriptRefund : scriptReward;
    }

    bool operator==(const CCollateralShare& o) const
    {
        return amount == o.amount && scriptRefund == o.scriptRefund
            && scriptReward == o.scriptReward && keyIDOwner == o.keyIDOwner;
    }

    template <typename Stream>
    void Serialize(Stream& s) const { s << amount << scriptRefund << scriptReward << keyIDOwner; }
    template <typename Stream>
    void Unserialize(Stream& s) { s >> amount >> scriptRefund >> scriptReward >> keyIDOwner; }
};
using CollateralShares = std::vector<CCollateralShare>;

// ── CProRegTx ─────────────────────────────────────────────────────────────
// Type 1. Registers a new masternode.
//
// Wire (v1/v2): nVersion u16 | nType u16 | nMode u16 | collateralOutpoint |
//   netInfo(18) | keyIDOwner | pubKeyOperator(48) | keyIDVoting |
//   nOperatorReward u16 | scriptPayout | inputsHash |
//   [Evo: platformNodeID | platformP2PPort u16 | platformHTTPPort u16] | vchSig
// Wire (v3): ... collateralOutpoint | ExtNetInfo | keyIDOwner |
//   pubKeyOperator | keyIDVoting | nOperatorReward | u8 n | payout * n |
//   u8 m | share * m | joinSig(65) * m | nEarlyPeriodBlocks u32 |
//   nEarlyPenalty i64 | inputsHash | [Evo: platformNodeID] | vchSig
struct CProRegTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 1;

    static constexpr uint8_t  MIN_SHARES = 2;
    static constexpr uint8_t  MAX_SHARES = 8;
    static constexpr uint32_t MAX_EARLY_PERIOD_BLOCKS = 420480;

    uint16_t                           nVersion{ProTxVersion::BASIC_BLS};
    // dashcore wire format has nType as uint16_t (LE), NOT uint8_t. The
    // narrower read silently shifted every subsequent field by 1 byte, which
    // garbled collateralOutpoint for both REGULAR and EVO registrations
    // (Bug 13 root cause together with the same fix on CProUpServTx).
    uint16_t                           nType{MnType::REGULAR};
    uint16_t                           nMode{0};
    bitcoin_family::coin::TxPrevOut    collateralOutpoint;   // null hash: this tx's own output
    LegacyNetService                   netInfo;              // v1/v2
    ExtNetInfo                         extNetInfo;           // v3
    uint160                            keyIDOwner;           // null for a shared registration
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                            keyIDVoting;
    uint16_t                           nOperatorReward{0};
    OPScript                           scriptPayout;         // v1/v2
    MasternodePayoutShares             payouts;              // v3
    CollateralShares                   shares;               // v3: non-empty = shared masternode
    std::vector<CompactSignature>      vchJoinSigs;          // v3: one per share, in share order
    uint32_t                           nEarlyPeriodBlocks{0};// v3
    int64_t                            nEarlyPenalty{0};     // v3
    uint256                            inputsHash;
    std::vector<uint8_t>               vchSig;
    // Evo-only (gated on nType == EVO); the ports only below v3:
    uint160                            platformNodeID;
    uint16_t                           platformP2PPort{0};
    uint16_t                           platformHTTPPort{0};

    bool version_known() const { return ProTxVersion::is_known(nVersion); }
    bool IsShared() const { return !shares.empty(); }
    NetInfoRef net_info() const
    {
        return nVersion >= ProTxVersion::EXT_ADDR ? NetInfoRef{nullptr, &extNetInfo}
                                                  : NetInfoRef{&netInfo, nullptr};
    }
    /// GetOwnerPayouts: the v3 list, or the single v1/v2 script at 10000.
    MasternodePayoutShares owner_payouts() const
    {
        return nVersion >= ProTxVersion::EXT_ADDR ? payouts : legacy_payout_as_list(scriptPayout);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        using namespace protx_detail;
        s << nVersion;
        if (!version_known()) return;   // Core: unknown version, nothing after nVersion
        s << nType << nMode << collateralOutpoint;
        if (nVersion >= ProTxVersion::EXT_ADDR) s << extNetInfo; else s << netInfo;
        s << keyIDOwner;
        write_raw(s, pubKeyOperator);
        s << keyIDVoting << nOperatorReward;
        if (nVersion >= ProTxVersion::EXT_ADDR) {
            write_count_u8(s, payouts);
            for (const auto& p : payouts) s << p;
            if (vchJoinSigs.size() != shares.size())
                throw std::ios_base::failure("join signature count mismatch");
            write_count_u8(s, shares);
            for (const auto& sh : shares) s << sh;
            for (const auto& sig : vchJoinSigs) write_raw(s, sig);
            s << nEarlyPeriodBlocks << nEarlyPenalty;
        } else {
            s << scriptPayout;
        }
        s << inputsHash;
        if (nType == MnType::EVO) {
            s << platformNodeID;
            // Plain uint16 members upstream => LE on the wire (they are NOT
            // CService ports; verified against real testnet entries).
            if (nVersion < ProTxVersion::EXT_ADDR) s << platformP2PPort << platformHTTPPort;
        }
        s << vchSig;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        using namespace protx_detail;
        s >> nVersion;
        if (!version_known()) return;
        s >> nType >> nMode >> collateralOutpoint;
        if (nVersion >= ProTxVersion::EXT_ADDR) s >> extNetInfo; else s >> netInfo;
        s >> keyIDOwner;
        read_raw(s, pubKeyOperator);
        s >> keyIDVoting >> nOperatorReward;
        if (nVersion >= ProTxVersion::EXT_ADDR) {
            payouts.assign(read_u8(s), {});
            for (auto& p : payouts) s >> p;
            const uint8_t n = read_u8(s);
            shares.assign(n, {});
            for (auto& sh : shares) s >> sh;
            vchJoinSigs.assign(n, {});
            for (auto& sig : vchJoinSigs) read_raw(s, sig);
            s >> nEarlyPeriodBlocks >> nEarlyPenalty;
        } else {
            s >> scriptPayout;
        }
        s >> inputsHash;
        if (nType == MnType::EVO) {
            s >> platformNodeID;
            if (nVersion < ProTxVersion::EXT_ADDR) s >> platformP2PPort >> platformHTTPPort;
        }
        s >> vchSig;
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProRegTx{v" << nVersion
           << " t" << int(nType)
           << " collat=" << collateralOutpoint.hash.GetHex().substr(0, 12)
           << ":" << collateralOutpoint.index;
        if (nVersion >= ProTxVersion::EXT_ADDR)
            os << " payouts=" << payouts.size() << " shares=" << shares.size();
        else
            os << " payout=" << scriptPayout.m_data.size() << "B";
        os << "}";
        return os.str();
    }
};

// ── CProUpServTx ──────────────────────────────────────────────────────────
// Type 2. Updates a MN's network info + operator-payout script.
//
// Wire: nVersion | [v>=2: nType u16] | proTxHash | netInfo (ExtNetInfo at
//   v3) | scriptOperatorPayout | inputsHash |
//   [Evo: platformNodeID | v<3: platformP2PPort u16, platformHTTPPort u16] |
//   sig(96)
struct CProUpServTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 2;

    uint16_t              nVersion{ProTxVersion::BASIC_BLS};
    // nType is uint16 on the wire (Bug 13: the narrower read garbled every
    // v2+ ProUpServTx; live-observed 2026-04-26..05-03).
    uint16_t              nType{MnType::REGULAR};
    uint256               proTxHash;
    LegacyNetService      netInfo;       // v1/v2
    ExtNetInfo            extNetInfo;    // v3
    OPScript              scriptOperatorPayout;
    uint256               inputsHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};
    // Evo-only:
    uint160               platformNodeID;
    uint16_t              platformP2PPort{0};
    uint16_t              platformHTTPPort{0};

    bool version_known() const { return ProTxVersion::is_known(nVersion); }
    NetInfoRef net_info() const
    {
        return nVersion >= ProTxVersion::EXT_ADDR ? NetInfoRef{nullptr, &extNetInfo}
                                                  : NetInfoRef{&netInfo, nullptr};
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        using namespace protx_detail;
        s << nVersion;
        if (!version_known()) return;
        if (nVersion >= ProTxVersion::BASIC_BLS) s << nType;
        s << proTxHash;
        if (nVersion >= ProTxVersion::EXT_ADDR) s << extNetInfo; else s << netInfo;
        s << scriptOperatorPayout << inputsHash;
        if (nType == MnType::EVO) {
            s << platformNodeID;
            if (nVersion < ProTxVersion::EXT_ADDR) s << platformP2PPort << platformHTTPPort;
        }
        write_raw(s, sig);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        using namespace protx_detail;
        s >> nVersion;
        if (!version_known()) return;
        if (nVersion >= ProTxVersion::BASIC_BLS) s >> nType;
        s >> proTxHash;
        if (nVersion >= ProTxVersion::EXT_ADDR) s >> extNetInfo; else s >> netInfo;
        s >> scriptOperatorPayout >> inputsHash;
        if (nType == MnType::EVO) {
            s >> platformNodeID;
            if (nVersion < ProTxVersion::EXT_ADDR) s >> platformP2PPort >> platformHTTPPort;
        }
        read_raw(s, sig);
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProUpServTx{v" << nVersion
           << " t" << int(nType)
           << " pro=" << proTxHash.GetHex().substr(0, 12)
           << "}";
        return os.str();
    }
};

// ── CProUpRegTx ───────────────────────────────────────────────────────────
// Type 3. Updates a MN's operator pubkey, voting keyID and payout(s).
//
// Wire: nVersion | proTxHash | nMode u16 | pubKeyOperator(48) | keyIDVoting |
//   v1/v2: scriptPayout   v3: u8 n | payout * n | inputsHash | vchSig
struct CProUpRegTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 3;

    uint16_t                             nVersion{ProTxVersion::BASIC_BLS};
    uint256                              proTxHash;
    uint16_t                             nMode{0};
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                              keyIDVoting;
    OPScript                             scriptPayout;   // v1/v2
    MasternodePayoutShares               payouts;        // v3
    uint256                              inputsHash;
    std::vector<uint8_t>                 vchSig;

    bool version_known() const { return ProTxVersion::is_known(nVersion); }
    MasternodePayoutShares owner_payouts() const
    {
        return nVersion >= ProTxVersion::EXT_ADDR ? payouts : legacy_payout_as_list(scriptPayout);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        using namespace protx_detail;
        s << nVersion;
        if (!version_known()) return;
        s << proTxHash << nMode;
        write_raw(s, pubKeyOperator);
        s << keyIDVoting;
        if (nVersion >= ProTxVersion::EXT_ADDR) {
            write_count_u8(s, payouts);
            for (const auto& p : payouts) s << p;
        } else {
            s << scriptPayout;
        }
        s << inputsHash << vchSig;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        using namespace protx_detail;
        s >> nVersion;
        if (!version_known()) return;
        s >> proTxHash >> nMode;
        read_raw(s, pubKeyOperator);
        s >> keyIDVoting;
        if (nVersion >= ProTxVersion::EXT_ADDR) {
            payouts.assign(read_u8(s), {});
            for (auto& p : payouts) s >> p;
        } else {
            s >> scriptPayout;
        }
        s >> inputsHash >> vchSig;
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProUpRegTx{v" << nVersion
           << " pro=" << proTxHash.GetHex().substr(0, 12);
        if (nVersion >= ProTxVersion::EXT_ADDR)
            os << " payouts=" << payouts.size();
        else
            os << " new_payout=" << scriptPayout.m_data.size() << "B";
        os << "}";
        return os.str();
    }
};

// ── CProUpRevTx ───────────────────────────────────────────────────────────
// Type 4. Revokes a MN's operator. v3 has the v2 layout:
// nVersion | proTxHash | nReason u16 | inputsHash | sig(96)
struct CProUpRevTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 4;

    static constexpr uint16_t REASON_NOT_SPECIFIED         = 0;
    static constexpr uint16_t REASON_TERMINATION_OF_SERVICE = 1;
    static constexpr uint16_t REASON_COMPROMISED_KEYS      = 2;
    static constexpr uint16_t REASON_CHANGE_OF_KEYS        = 3;
    static constexpr uint16_t REASON_LAST                  = REASON_CHANGE_OF_KEYS;

    uint16_t                          nVersion{ProTxVersion::BASIC_BLS};
    uint256                           proTxHash;
    uint16_t                          nReason{REASON_NOT_SPECIFIED};
    uint256                           inputsHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};

    bool version_known() const { return ProTxVersion::is_known(nVersion); }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << nVersion;
        if (!version_known()) return;
        s << proTxHash << nReason << inputsHash;
        protx_detail::write_raw(s, sig);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> nVersion;
        if (!version_known()) return;
        s >> proTxHash >> nReason >> inputsHash;
        protx_detail::read_raw(s, sig);
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProUpRevTx{v" << nVersion
           << " pro=" << proTxHash.GetHex().substr(0, 12)
           << " reason=" << nReason
           << "}";
        return os.str();
    }
};

// ── CProDisTx ─────────────────────────────────────────────────────────────
// Type 10 (v24). Dissolves a shared masternode by spending its internal
// collateral. Exactly one signature (unilateral, by shares[actorIndex]) or
// one per share in share order (unanimous): the count selects the mode.
// Wire: nVersion u16 | proTxHash | actorIndex u16 | u8 n | sig(65) * n
// (no version bail-out in Core: every field is read; IsTriviallyValid
// rejects versions other than 1).
struct CProDisTx
{
    static constexpr uint16_t SPECIALTX_TYPE  = 10;
    static constexpr uint16_t CURRENT_VERSION = 1;
    static constexpr int64_t  MAX_FEE         = 1000000;

    uint16_t                      nVersion{CURRENT_VERSION};
    uint256                       proTxHash;
    uint16_t                      actorIndex{0};
    std::vector<CompactSignature> vchSigs;

    bool version_known() const { return nVersion == CURRENT_VERSION; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        using namespace protx_detail;
        s << nVersion << proTxHash << actorIndex;
        write_count_u8(s, vchSigs);
        for (const auto& sig : vchSigs) write_raw(s, sig);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        using namespace protx_detail;
        s >> nVersion >> proTxHash >> actorIndex;
        vchSigs.assign(read_u8(s), {});
        for (auto& sig : vchSigs) read_raw(s, sig);
    }
};

// ── CProUpShareTx ─────────────────────────────────────────────────────────
// Type 11 (v24). One share owner changes the reward script of its share.
// Wire: nVersion u16 | proTxHash | shareIndex u16 | scriptReward |
//   inputsHash | vchSig (CompactSize-prefixed; excluded from the sign hash)
struct CProUpShareTx
{
    static constexpr uint16_t SPECIALTX_TYPE  = 11;
    static constexpr uint16_t CURRENT_VERSION = 1;

    uint16_t             nVersion{CURRENT_VERSION};
    uint256              proTxHash;
    uint16_t             shareIndex{0};
    OPScript             scriptReward;
    uint256              inputsHash;
    std::vector<uint8_t> vchSig;

    bool version_known() const { return nVersion == CURRENT_VERSION; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << nVersion << proTxHash << shareIndex << scriptReward << inputsHash << vchSig;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> nVersion >> proTxHash >> shareIndex >> scriptReward >> inputsHash >> vchSig;
    }
};

// ── CProUpSharedRegTx ─────────────────────────────────────────────────────
// Type 12 (v24). Unanimous registrar update of a shared masternode: new
// operator key (always the basic BLS scheme) and voting key.
// Wire: nVersion u16 | proTxHash | pubKeyOperator(48) | keyIDVoting |
//   inputsHash | u8 n | sig(65) * n   (count + sigs excluded from the sign hash)
struct CProUpSharedRegTx
{
    static constexpr uint16_t SPECIALTX_TYPE  = 12;
    static constexpr uint16_t CURRENT_VERSION = 1;

    uint16_t                             nVersion{CURRENT_VERSION};
    uint256                              proTxHash;
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                              keyIDVoting;
    uint256                              inputsHash;
    std::vector<CompactSignature>        vchSigs;

    bool version_known() const { return nVersion == CURRENT_VERSION; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        using namespace protx_detail;
        s << nVersion << proTxHash;
        write_raw(s, pubKeyOperator);
        s << keyIDVoting << inputsHash;
        write_count_u8(s, vchSigs);
        for (const auto& sig : vchSigs) write_raw(s, sig);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        using namespace protx_detail;
        s >> nVersion >> proTxHash;
        read_raw(s, pubKeyOperator);
        s >> keyIDVoting >> inputsHash;
        vchSigs.assign(read_u8(s), {});
        for (auto& sig : vchSigs) read_raw(s, sig);
    }
};

// ── Operator-signature preimage (B.9) ─────────────────────────────────────
// dashd CheckProUpServTx / CheckProUpRevTx verify `sig` against
// ::SerializeHash(proTx) (specialtxman.cpp CheckHashSig). Both payloads skip
// the trailing BLS `sig` under SER_GETHASH and `sig` is their last field in
// every version (v3 included), so for a payload that parse_protx_payload
// consumed completely the signed preimage is the payload minus its last
// BLS_SIG_SIZE bytes, hashed SHA256d. Returns nullopt when the payload is too
// short to carry a signature.
inline std::optional<uint256>
protx_operator_sign_hash(const std::vector<uint8_t>& payload)
{
    if (payload.size() < BLS_SIG_SIZE) return std::nullopt;
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(payload.data(),
                                              payload.size() - BLS_SIG_SIZE))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

// ── Payload decoding ──────────────────────────────────────────────────────

/// The payload's structure: decode and require it to be consumed exactly.
/// No version gate (a payload that is only an unknown nVersion decodes to an
/// object carrying just that version, as in Core) and no BLS math, so the
/// folds' reading of v1/v2 payloads stays exactly the pre-v24 one.
template <typename T>
inline bool decode_payload_structure(const std::vector<uint8_t>& payload, T& out)
{
    if (payload.empty()) return false;
    try {
        ::PackStream s(payload);
        s >> out;
        return s.empty();
    } catch (const std::exception&) {
        return false;
    }
}

/// The BLS signature a type-2 / type-4 payload carries is a plain
/// CBLSSignature in Core (not a lazy wrapper): its unserializer throws on an
/// encoding that is canonical under neither scheme, so GetTxPayload fails.
/// nullopt: no BLS backend, cannot decide. true for every other payload type.
template <typename T>
inline constexpr bool payload_has_bls_sig =
    std::is_same_v<T, CProUpServTx> || std::is_same_v<T, CProUpRevTx>;

template <typename T>
inline std::optional<bool> payload_bls_objects_decode(const T& p, const BlsEncodingChecks& bls)
{
    if constexpr (payload_has_bls_sig<T>) {
        if (!p.version_known()) return true;   // Core read nothing after nVersion
        return bls.sig_decodes(p.sig, p.nVersion == ProTxVersion::LEGACY_BLS);
    } else {
        (void)p; (void)bls;
        return true;
    }
}

/// Core's GetTxPayload<T>: the structure, plus the BLS signature encoding
/// rule of types 2 and 4 (an undecidable signature, without a BLS backend,
/// counts as a failure). The folds use parse_protx_payload instead. Only the
/// types 2 and 4 instantiations reference the BLS backend (dash_bls_verify).
template <typename T>
inline bool decode_special_payload(const std::vector<uint8_t>& payload, T& out)
{
    if (!decode_payload_structure(payload, out)) return false;
    if constexpr (payload_has_bls_sig<T>) {
        const auto sig_ok = payload_bls_objects_decode(out, BlsEncodingChecks{});
        return sig_ok.has_value() && *sig_ok;
    } else {
        return true;
    }
}

/// The fold-facing parse. True only when the payload decodes exactly AND
/// its version is one this codec knows (ProTx 1..3, types 10-12 version 1):
/// an unknown version FAILS here and never yields a partially read object.
/// Callers fail closed on false (refuse the block or the fold, never skip).
/// Whether the version is VALID at a given height is a separate rule
/// (coin/v24_rules.hpp). No BLS math: chainlocked blocks carry decodable
/// signatures, and the fold must work without a BLS backend.
template <typename T>
inline bool parse_protx_payload(const std::vector<uint8_t>& payload, T& out)
{
    if (!decode_payload_structure(payload, out)) return false;
    return out.version_known();
}

/// Re-serialize a payload (Core's SetTxPayload).
template <typename T>
inline std::vector<uint8_t> serialize_special_payload(const T& obj)
{
    ::PackStream s;
    s << obj;
    auto sp = s.get_span();
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

} // namespace vendor
} // namespace coin
} // namespace dash
