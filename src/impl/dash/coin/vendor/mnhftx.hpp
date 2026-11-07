// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// MNHF ("masternode hard fork") signal, special tx type 7.
///
/// Ported from Dash Core v24.0.0 src/evo/mnhftx.h / mnhftx.cpp:
///   MNHFTx         { uint8 versionBit; uint256 quorumHash; CBLSSignature sig }
///                  (the signature is always in the basic scheme, 96 bytes)
///   MNHFTxPayload  { uint8 nVersion (CURRENT_VERSION = 1); MNHFTx signal }
///   extractEHFSignal(tx): the signal's versionBit for a special-version tx of
///                  type 7 whose payload parses, else nothing.
///   MNHFTxPayload::IsTriviallyValid: nVersion in [1, CURRENT_VERSION] and
///                  versionBit < VERSIONBITS_NUM_BITS (29).
///
/// The quorum signature is carried as opaque bytes and never verified here:
/// the EHF tracker reads signals only from blocks Dash Core already accepted
/// (the design keeps type 7 out of our templates; others mine the signal).

#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/vendor/shim.hpp>      // RawBytesFormat

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <optional>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

struct MNHFTx
{
    static constexpr size_t BLS_SIG_SIZE = 96;

    uint8_t                           versionBit{0};
    uint256                           quorumHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};

    C2POOL_SERIALIZE_METHODS(MNHFTx)
    {
        READWRITE(obj.versionBit, obj.quorumHash,
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.sig));
    }
};

struct MNHFTxPayload
{
    static constexpr uint16_t SPECIALTX_TYPE  = 7;
    static constexpr uint16_t CURRENT_VERSION = 1;

    uint8_t nVersion{CURRENT_VERSION};
    MNHFTx  signal;

    C2POOL_SERIALIZE_METHODS(MNHFTxPayload)
    {
        READWRITE(obj.nVersion, obj.signal);
    }

    /// MNHFTxPayload::IsTriviallyValid.
    bool is_trivially_valid() const
    {
        return nVersion != 0 && nVersion <= CURRENT_VERSION && signal.versionBit < 29;
    }
};

/// GetTxPayload<MNHFTxPayload>: the payload must parse and be consumed whole.
inline bool parse_mnhf_payload(const std::vector<unsigned char>& payload, MNHFTxPayload& out)
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

} // namespace vendor

/// extractEHFSignal: the version bit a type-7 tx signals, or nullopt for any
/// other tx (or a type-7 whose payload does not parse).
template <typename Tx>
inline std::optional<uint8_t> extract_ehf_signal(const Tx& tx)
{
    if (!tx_is_special_version(tx.version) || tx.type != vendor::MNHFTxPayload::SPECIALTX_TYPE)
        return std::nullopt;
    vendor::MNHFTxPayload p;
    if (!vendor::parse_mnhf_payload(tx.extra_payload, p)) return std::nullopt;
    return p.signal.versionBit;
}

} // namespace coin
} // namespace dash
