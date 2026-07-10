// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vendored from dashcore/src/evo/providertx.{h,cpp} @ develop cfad414
// (Dash Core v23.1-dev). Phase C-PAY step 1 (foundation).
//
// First credible step toward full Dash Core RPC independence: parse
// the four ProTx variants out of the special-tx extra_payload so we
// can build our own DMN state machine instead of querying dashd's
// `protx list`. The Simplified MN List we already sync (DIP-0004)
// is a SUBSET that omits scriptPayout / nLastPaidHeight / etc. —
// see the/docs/c2pool-dash-phase-c-pay-design.md.
//
// THIS COMMIT IS DATA-LAYER ONLY. No state-machine wiring yet; a
// follow-up commit will land mn_state_db + on_full_block scanning.
//
// Adaptations from upstream (mirroring simplifiedmns.hpp's pattern):
//
//   1. Wire-format mode is hard-coded to "current Dash mainnet at our
//      advertised proto version (70230)". Specifically: the upstream
//      "if nVersion unknown, bail out early" branch is dropped — we
//      assume a parseable nVersion in {1=LegacyBLS, 2=BasicBLS}. ProTx
//      records with nVersion >= 3 (ExtAddr / DIP-0028) need
//      DEPLOYMENT_V24 (EHF) which has not activated on mainnet; if
//      we ever see one we log+drop (the parse will fail at the
//      NetInfo step because we don't support MnNetInfo yet).
//
//   2. `MnType` (Consensus enum, uint8 underlying) → raw uint8 with
//      named constexpr TYPE_REGULAR / TYPE_EVO values.
//
//   3. `NetInfoInterface` / `NetInfoSerWrapper` is replaced by an
//      inline 18-byte legacy CService (16-byte raw IPv6 + 2-byte BE
//      port). MnNetInfo (multi-addr) NOT supported yet — same as
//      simplifiedmns.hpp's approach. Re-vendor with NetInfo support
//      once DEPLOYMENT_V24 activates.
//
//   4. `CBLSLazyPublicKey` → 48-byte std::array. `CBLSSignature` →
//      96-byte std::array. The legacy/basic curve-scheme flag
//      doesn't change wire byte count; it only affects how the impl
//      decompresses the curve point, which we never do at the parse
//      layer (Phase L's verifier handles that).
//
//   5. `CKeyID` = uint160. `COutPoint` = bitcoin_family::coin::TxPrevOut.
//      `CScript` = core::OPScript (vector<u8>-style with CompactSize
//      length prefix on the wire — bit-identical to dashcore's CScript).
//
//   6. `IsTriviallyValid()` / `ToString()` / `ToJson()` / `GetJsonHelp()`
//      methods NOT vendored — they need ChainstateManager, CBlockIndex,
//      and RPC infrastructure we don't have. The state-machine consumer
//      will do its own validity checks against our header chain.
//
//   7. `vchSig` (collateral key signature on CProRegTx, also on
//      CProUpRegTx) is preserved on the wire but not verified — that
//      verification needs the collateral output's pubkey from our
//      UTXO state. Phase C-PAY step 3 (state machine) decides whether
//      to gate state updates on signature verify; for the parse layer
//      we just round-trip the bytes.
//
//   8. The SER_GETHASH path (used by dashcore for txid computation
//      via inputsHash) skips the trailing signature. Our state machine
//      identifies ProTx by the *transaction's* hash (vendor txid), not
//      the payload hash, so this distinction doesn't matter to us.

#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/opscript.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// MnType from dashcore consensus/params.h (uint8_t underlying)
namespace MnType {
    inline constexpr uint8_t REGULAR = 0;
    inline constexpr uint8_t EVO     = 1;
}

// ProTxVersion (matches dashcore evo/providertx.h ProTxVersion namespace)
namespace ProTxVersion {
    inline constexpr uint16_t LEGACY_BLS = 1;
    inline constexpr uint16_t BASIC_BLS  = 2;
    inline constexpr uint16_t EXT_ADDR   = 3;
}

inline constexpr size_t BLS_PUBKEY_SIZE = 48;
inline constexpr size_t BLS_SIG_SIZE    = 96;
inline constexpr size_t NETADDR_SIZE    = 16;

// Legacy 18-byte CService inline-serializer. See landmine note in
// simplifiedmns.hpp for the same pattern.
struct LegacyNetService
{
    std::array<uint8_t, NETADDR_SIZE> ip{};
    uint16_t                          port_be{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(std::as_bytes(std::span{ip}));
        uint8_t pb[2] = {
            static_cast<uint8_t>((port_be >> 8) & 0xff),
            static_cast<uint8_t>(port_be & 0xff)
        };
        s.write(std::as_bytes(std::span{pb}));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::array<uint8_t, NETADDR_SIZE> raw{};
        s.read(std::as_writable_bytes(std::span{raw}));
        ip = raw;
        uint8_t pb[2];
        s.read(std::as_writable_bytes(std::span{pb}));
        port_be = (uint16_t(pb[0]) << 8) | uint16_t(pb[1]);
    }
};

// ── CProRegTx ─────────────────────────────────────────────────────────────
// Type 1. Registers a new masternode. Provides:
//   - scriptPayout (where MN reward goes — mutable later via ProUpRegTx)
//   - keyIDOwner / keyIDVoting / pubKeyOperator (governance + signing)
//   - collateralOutpoint (the 1000 / 4000 DASH lock)
//   - nType (Regular vs Evo)
//   - For Evo: platformNodeID + ports (HTTP for DAPI, P2P for masternode net)

struct CProRegTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 1;

    uint16_t                           nVersion{ProTxVersion::BASIC_BLS};
    // dashcore wire format has nType as uint16_t (LE), NOT uint8_t. The
    // narrower read silently shifted every subsequent field by 1 byte,
    // which:
    //   - For REGULAR (nType=0): coincidentally aligned because the 0x00
    //     high byte of nType and the 0x00 low byte of nMode both happen
    //     to be zero, so nType+nMode read the right values — BUT
    //     collateralOutpoint then started 1 byte early and was garbage.
    //     Effect: registered EVO MNs got wrong collateralOutpoint →
    //     m_collateral_index entries point at non-existent outpoints,
    //     so collateral-spend detection misses them.
    //   - For EVO (nType=1): same shift, garbage collateral.
    // Bug 13 root cause when paired with the same fix on CProUpServTx.
    uint16_t                           nType{MnType::REGULAR};
    uint16_t                           nMode{0};
    bitcoin_family::coin::TxPrevOut    collateralOutpoint;
    LegacyNetService                   netInfo;
    uint160                            keyIDOwner;
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                            keyIDVoting;
    uint16_t                           nOperatorReward{0};
    OPScript                           scriptPayout;
    uint256                            inputsHash;
    std::vector<uint8_t>               vchSig;
    // Evo-only (gated on nType == EVO):
    uint160                            platformNodeID;
    uint16_t                           platformP2PPort{0};
    uint16_t                           platformHTTPPort{0};

    C2POOL_SERIALIZE_METHODS(CProRegTx)
    {
        READWRITE(obj.nVersion);
        // We DROP dashcore's "if (nVersion == 0 || nVersion > GetMax())
        // bail out early" — see preamble adaptation #1.
        READWRITE(obj.nType,
                  obj.nMode,
                  obj.collateralOutpoint,
                  obj.netInfo,
                  obj.keyIDOwner,
                  Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(obj.pubKeyOperator),
                  obj.keyIDVoting,
                  obj.nOperatorReward,
                  obj.scriptPayout,
                  obj.inputsHash);
        if (obj.nType == MnType::EVO) {
            READWRITE(obj.platformNodeID);
            if (obj.nVersion < ProTxVersion::EXT_ADDR) {
                READWRITE(Using<BigEndianFormat<2>>(obj.platformP2PPort),
                          Using<BigEndianFormat<2>>(obj.platformHTTPPort));
            }
        }
        READWRITE(obj.vchSig);
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProRegTx{v" << nVersion
           << " t" << int(nType)
           << " collat=" << collateralOutpoint.hash.GetHex().substr(0, 12)
           << ":" << collateralOutpoint.index
           << " payout=" << scriptPayout.m_data.size() << "B"
           << "}";
        return os.str();
    }
};

// ── CProUpServTx ──────────────────────────────────────────────────────────
// Type 2. Updates a MN's network info + (Evo) operator-payout script.
// Service updates are how a MN signals "I moved to a new IP".

struct CProUpServTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 2;

    uint16_t              nVersion{ProTxVersion::BASIC_BLS};
    // dashcore wire format has nType as uint16_t (LE), NOT uint8_t.
    // The narrower read shifted proTxHash + every subsequent field by
    // 1 byte for v2+ (BASIC_BLS) ProUpServTxs. Effect: parse_protx_payload
    // failed (read past end of payload) for EVO updates AND parsed
    // garbage proTxHash for REGULAR updates. Live-observed via 6+
    // [MNS-SM] CProUpServTx parse failed warnings 2026-04-26..05-03,
    // including h=2462994 — the missed PoSe revival of MN
    // 788707b3...80f4 that produced 1858 [PAY] MISMATCH events
    // before Bug 12's SML sync masked the symptom. Bug 13 root cause.
    uint16_t              nType{MnType::REGULAR};
    uint256               proTxHash;
    LegacyNetService      netInfo;
    OPScript              scriptOperatorPayout;
    uint256               inputsHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};
    // Evo-only:
    uint160               platformNodeID;
    uint16_t              platformP2PPort{0};
    uint16_t              platformHTTPPort{0};

    C2POOL_SERIALIZE_METHODS(CProUpServTx)
    {
        READWRITE(obj.nVersion);
        if (obj.nVersion >= ProTxVersion::BASIC_BLS) {
            READWRITE(obj.nType);
        }
        READWRITE(obj.proTxHash,
                  obj.netInfo,
                  obj.scriptOperatorPayout,
                  obj.inputsHash);
        if (obj.nType == MnType::EVO) {
            READWRITE(obj.platformNodeID);
            if (obj.nVersion < ProTxVersion::EXT_ADDR) {
                READWRITE(Using<BigEndianFormat<2>>(obj.platformP2PPort),
                          Using<BigEndianFormat<2>>(obj.platformHTTPPort));
            }
        }
        READWRITE(Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.sig));
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
// Type 3. Updates a MN's operator pubkey, voting keyID, and/or payout
// script. This is how a MN can rotate its operator key without losing
// its registration (and thus its nLastPaidHeight history).

struct CProUpRegTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 3;

    uint16_t                             nVersion{ProTxVersion::BASIC_BLS};
    uint256                              proTxHash;
    uint16_t                             nMode{0};
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                              keyIDVoting;
    OPScript                             scriptPayout;
    uint256                              inputsHash;
    std::vector<uint8_t>                 vchSig;

    C2POOL_SERIALIZE_METHODS(CProUpRegTx)
    {
        READWRITE(obj.nVersion,
                  obj.proTxHash,
                  obj.nMode,
                  Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(obj.pubKeyOperator),
                  obj.keyIDVoting,
                  obj.scriptPayout,
                  obj.inputsHash,
                  obj.vchSig);
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "CProUpRegTx{v" << nVersion
           << " pro=" << proTxHash.GetHex().substr(0, 12)
           << " new_payout=" << scriptPayout.m_data.size() << "B"
           << "}";
        return os.str();
    }
};

// ── CProUpRevTx ───────────────────────────────────────────────────────────
// Type 4. Revokes a MN. The MN is removed from the active set + a new
// operator key is required for re-activation. Used by MN owners to
// signal compromised keys / change of service.

struct CProUpRevTx
{
    static constexpr uint16_t SPECIALTX_TYPE = 4;

    static constexpr uint16_t REASON_NOT_SPECIFIED         = 0;
    static constexpr uint16_t REASON_TERMINATION_OF_SERVICE = 1;
    static constexpr uint16_t REASON_COMPROMISED_KEYS      = 2;
    static constexpr uint16_t REASON_CHANGE_OF_KEYS        = 3;

    uint16_t                          nVersion{ProTxVersion::BASIC_BLS};
    uint256                           proTxHash;
    uint16_t                          nReason{REASON_NOT_SPECIFIED};
    uint256                           inputsHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};

    C2POOL_SERIALIZE_METHODS(CProUpRevTx)
    {
        READWRITE(obj.nVersion,
                  obj.proTxHash,
                  obj.nReason,
                  obj.inputsHash,
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.sig));
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

// ── Generic helper ────────────────────────────────────────────────────────
// Parse a ProTx payload. Returns true on success (payload fully consumed),
// false on any deserialization error or trailing garbage. Caller checks
// tx.type to know which variant to attempt.

template <typename T>
inline bool parse_protx_payload(const std::vector<uint8_t>& payload, T& out)
{
    if (payload.empty()) return false;
    try {
        ::PackStream s(payload);
        s >> out;
        // Successful parse must consume the entire payload — trailing
        // bytes indicate either malformed input or a wire-format change
        // we haven't caught up to.
        return s.empty();
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash